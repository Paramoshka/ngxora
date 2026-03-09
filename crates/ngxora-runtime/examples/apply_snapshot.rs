use ngxora_runtime::grpc::proto::control_plane_client::ControlPlaneClient;
use ngxora_runtime::grpc::proto::{
    ApplyResult, ConfigSnapshot, HttpOptions, Listener, Match, Plugin, Route, RouteTimeouts,
    Upstream, VirtualHost,
};
use std::env;
use std::error::Error;
use std::io;
use std::path::PathBuf;
use tonic::transport::{Channel, Endpoint};

#[cfg(unix)]
use hyper_util::rt::TokioIo;
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(unix)]
use tower::service_fn;

enum Target {
    Tcp(String),
    Uds(PathBuf),
}

struct CliArgs {
    target: Target,
    version: String,
    listener_name: String,
    address: String,
    port: u32,
    server_name: String,
    path_prefix: String,
    upstream_scheme: String,
    upstream_host: String,
    upstream_port: u32,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let cli = parse_args(env::args())?;
    let mut client = connect(&cli.target).await?;
    let result = client
        .apply_snapshot(build_snapshot(&cli))
        .await?
        .into_inner();

    print_result(&result);
    Ok(())
}

async fn connect(target: &Target) -> Result<ControlPlaneClient<Channel>, Box<dyn Error>> {
    let channel = match target {
        Target::Tcp(addr) => Endpoint::from_shared(addr.clone())?.connect().await?,
        Target::Uds(path) => connect_uds(path.clone()).await?,
    };

    Ok(ControlPlaneClient::new(channel))
}

#[cfg(unix)]
async fn connect_uds(path: PathBuf) -> Result<Channel, Box<dyn Error>> {
    let endpoint = Endpoint::try_from("http://[::]:50051")?;
    let channel = endpoint
        .connect_with_connector(service_fn(move |_| {
            let path = path.clone();
            async move {
                let stream = UnixStream::connect(path).await?;
                Ok::<_, io::Error>(TokioIo::new(stream))
            }
        }))
        .await?;
    Ok(channel)
}

#[cfg(not(unix))]
async fn connect_uds(_path: PathBuf) -> Result<Channel, Box<dyn Error>> {
    Err("UDS client is only available on unix targets".into())
}

fn build_snapshot(cli: &CliArgs) -> ConfigSnapshot {
    ConfigSnapshot {
        version: cli.version.clone(),
        http: Some(HttpOptions {
            downstream_keepalive_timeout_seconds: 30,
            tcp_nodelay: true,
            keepalive_requests: 1000,
            allow_connect_method_proxying: false,
            h2c: false,
            client_max_body_size_bytes: 10 * 1024 * 1024,
        }),
        listeners: vec![Listener {
            name: cli.listener_name.clone(),
            address: cli.address.clone(),
            port: cli.port,
            tls: false,
            http2: false,
            http2_only: false,
            tls_options: None,
        }],
        virtual_hosts: vec![VirtualHost {
            listener: cli.listener_name.clone(),
            server_names: vec![cli.server_name.clone()],
            default_server: true,
            tls: None,
            routes: vec![Route {
                r#match: Some(Match {
                    kind: Some(ngxora_runtime::grpc::proto::r#match::Kind::Prefix(
                        cli.path_prefix.clone(),
                    )),
                }),
                upstream: Some(Upstream {
                    scheme: cli.upstream_scheme.clone(),
                    host: cli.upstream_host.clone(),
                    port: cli.upstream_port,
                }),
                timeouts: Some(RouteTimeouts {
                    connect_timeout_ms: 3_000,
                    read_timeout_ms: 15_000,
                    write_timeout_ms: 15_000,
                }),
                plugins: vec![Plugin {
                    name: "headers".into(),
                    json_config: r#"{"response":{"add":[["x-proxy","ngxora"]]}}"#.into(),
                }],
            }],
        }],
    }
}

fn print_result(result: &ApplyResult) {
    println!(
        "applied={} restart_required={} version={} generation={} message={}",
        result.applied,
        result.restart_required,
        result.active_version,
        result.active_generation,
        result.message
    );
}

fn parse_args<I>(args: I) -> Result<CliArgs, Box<dyn Error>>
where
    I: IntoIterator,
    I::Item: Into<String>,
{
    let mut args = args.into_iter().skip(1).map(Into::into);
    let mut tcp: Option<String> = None;
    let mut uds: Option<PathBuf> = None;
    let mut version = String::from("manual-v1");
    let mut listener_name = String::from("edge");
    let mut address = String::from("0.0.0.0");
    let mut port = 8080;
    let mut server_name = String::from("localhost");
    let mut path_prefix = String::from("/");
    let mut upstream_scheme = String::from("http");
    let mut upstream_host = String::from("example.com");
    let mut upstream_port = 80;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--addr" => {
                let value = args.next().ok_or_else(|| {
                    invalid_input("--addr requires a full URI like http://127.0.0.1:50051")
                })?;
                tcp = Some(value);
            }
            "--uds" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid_input("--uds requires a socket path"))?;
                uds = Some(PathBuf::from(value));
            }
            "--version" => version = required_value(&mut args, "--version")?,
            "--listener-name" => listener_name = required_value(&mut args, "--listener-name")?,
            "--listen-addr" => address = required_value(&mut args, "--listen-addr")?,
            "--listen-port" => port = required_value(&mut args, "--listen-port")?.parse()?,
            "--server-name" => server_name = required_value(&mut args, "--server-name")?,
            "--path-prefix" => path_prefix = required_value(&mut args, "--path-prefix")?,
            "--upstream-scheme" => {
                upstream_scheme = required_value(&mut args, "--upstream-scheme")?
            }
            "--upstream-host" => upstream_host = required_value(&mut args, "--upstream-host")?,
            "--upstream-port" => {
                upstream_port = required_value(&mut args, "--upstream-port")?.parse()?
            }
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            value => return Err(invalid_input(&format!("unknown argument: {value}")).into()),
        }
    }

    let target = match (tcp, uds) {
        (Some(_), Some(_)) => {
            return Err(invalid_input("use either --addr or --uds, not both").into());
        }
        (Some(addr), None) => Target::Tcp(addr),
        (None, Some(path)) => Target::Uds(path),
        (None, None) => Target::Tcp("http://127.0.0.1:50051".into()),
    };

    validate_scheme(&upstream_scheme)?;

    Ok(CliArgs {
        target,
        version,
        listener_name,
        address,
        port,
        server_name,
        path_prefix,
        upstream_scheme,
        upstream_host,
        upstream_port,
    })
}

fn required_value<I>(args: &mut I, flag: &str) -> Result<String, io::Error>
where
    I: Iterator<Item = String>,
{
    args.next()
        .ok_or_else(|| invalid_input(&format!("{flag} requires a value")))
}

fn validate_scheme(value: &str) -> Result<(), io::Error> {
    match value {
        "http" | "https" => Ok(()),
        _ => Err(invalid_input(
            "--upstream-scheme must be either `http` or `https`",
        )),
    }
}

fn print_usage() {
    eprintln!(
        "Usage: cargo run -p ngxora-runtime --example apply_snapshot -- [--addr <uri> | --uds <path>] [--version <v>] [--listener-name <name>] [--listen-addr <ip>] [--listen-port <port>] [--server-name <host>] [--path-prefix <path>] [--upstream-scheme http|https] [--upstream-host <host>] [--upstream-port <port>]"
    );
}

fn invalid_input(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_string())
}
