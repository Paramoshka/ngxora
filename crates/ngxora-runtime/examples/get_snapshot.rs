use ngxora_runtime::grpc::proto::GetSnapshotRequest;
use ngxora_runtime::grpc::proto::control_plane_client::ControlPlaneClient;
use std::env;
use std::error::Error;
use std::io;
use std::path::PathBuf;
use tonic::transport::{Certificate, Channel, ClientTlsConfig, Endpoint, Identity};
use url::Url;

#[cfg(unix)]
use hyper_util::rt::TokioIo;
#[cfg(unix)]
use tokio::net::UnixStream;
#[cfg(unix)]
use tower::service_fn;

enum Target {
    Tcp(TcpTarget),
    Uds(PathBuf),
}

struct TcpTarget {
    endpoint: String,
    ca: PathBuf,
    certificate: PathBuf,
    key: PathBuf,
    domain: Option<String>,
}

#[tokio::main(flavor = "multi_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let target = parse_args(env::args())?;
    let mut client = connect(target).await?;
    let snapshot = client
        .get_snapshot(GetSnapshotRequest {})
        .await?
        .into_inner();

    println!("{snapshot:#?}");
    Ok(())
}

async fn connect(target: Target) -> Result<ControlPlaneClient<Channel>, Box<dyn Error>> {
    let channel = match target {
        Target::Tcp(target) => connect_tcp(target).await?,
        Target::Uds(path) => connect_uds(path).await?,
    };

    Ok(ControlPlaneClient::new(channel))
}

async fn connect_tcp(target: TcpTarget) -> Result<Channel, Box<dyn Error>> {
    let ca = read_pem(&target.ca, "controller CA")?;
    let certificate = read_pem(&target.certificate, "controller certificate")?;
    let key = read_pem(&target.key, "controller key")?;

    let mut tls = ClientTlsConfig::new()
        .ca_certificate(Certificate::from_pem(ca))
        .identity(Identity::from_pem(certificate, key));
    if let Some(domain) = target.domain {
        tls = tls.domain_name(domain);
    }

    Ok(Endpoint::from_shared(target.endpoint)?
        .tls_config(tls)?
        .connect()
        .await?)
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

fn parse_args<I>(args: I) -> Result<Target, Box<dyn Error>>
where
    I: IntoIterator,
    I::Item: Into<String>,
{
    let mut args = args.into_iter().skip(1).map(Into::into);
    let mut tcp: Option<String> = None;
    let mut uds: Option<PathBuf> = None;
    let mut ca: Option<PathBuf> = None;
    let mut certificate: Option<PathBuf> = None;
    let mut key: Option<PathBuf> = None;
    let mut domain: Option<String> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--addr" => {
                let value = args.next().ok_or_else(|| {
                    invalid_input(
                        "--addr requires an HTTPS URI like https://controller.example:50051",
                    )
                })?;
                tcp = Some(value);
            }
            "--uds" => {
                let value = args
                    .next()
                    .ok_or_else(|| invalid_input("--uds requires a socket path"))?;
                uds = Some(PathBuf::from(value));
            }
            "--tls-ca" => ca = Some(PathBuf::from(required_value(&mut args, "--tls-ca")?)),
            "--tls-cert" => {
                certificate = Some(PathBuf::from(required_value(&mut args, "--tls-cert")?))
            }
            "--tls-key" => key = Some(PathBuf::from(required_value(&mut args, "--tls-key")?)),
            "--tls-domain" => domain = Some(required_value(&mut args, "--tls-domain")?),
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            value => return Err(invalid_input(&format!("unknown argument: {value}")).into()),
        }
    }

    match (tcp, uds) {
        (Some(_), Some(_)) => Err(invalid_input("use either --addr or --uds, not both").into()),
        (Some(endpoint), None) => {
            validate_https_endpoint(&endpoint)?;
            let (Some(ca), Some(certificate), Some(key)) = (ca, certificate, key) else {
                return Err(invalid_input(
                    "--addr requires --tls-ca, --tls-cert, and --tls-key for mTLS",
                )
                .into());
            };
            Ok(Target::Tcp(TcpTarget {
                endpoint,
                ca,
                certificate,
                key,
                domain,
            }))
        }
        (None, Some(path)) => Ok(Target::Uds(path)),
        (None, None) => Err(invalid_input("specify --addr or --uds").into()),
    }
}

fn print_usage() {
    eprintln!(
        "Usage: cargo run -p ngxora-runtime --example get_snapshot -- [--addr <https-uri> --tls-ca <pem> --tls-cert <pem> --tls-key <pem> [--tls-domain <dns-name>] | --uds <path>]"
    );
}

fn required_value<I>(args: &mut I, flag: &str) -> Result<String, io::Error>
where
    I: Iterator<Item = String>,
{
    args.next()
        .ok_or_else(|| invalid_input(&format!("{flag} requires a value")))
}

fn validate_https_endpoint(value: &str) -> Result<(), io::Error> {
    let endpoint =
        Url::parse(value).map_err(|err| invalid_input(&format!("invalid --addr: {err}")))?;
    if endpoint.scheme() != "https" || endpoint.host().is_none() {
        return Err(invalid_input("--addr must be an HTTPS URI with a host"));
    }
    Ok(())
}

fn read_pem(path: &PathBuf, name: &str) -> Result<Vec<u8>, io::Error> {
    std::fs::read(path)
        .map_err(|err| invalid_input(&format!("failed to read {name} {}: {err}", path.display())))
}

fn invalid_input(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_string())
}
