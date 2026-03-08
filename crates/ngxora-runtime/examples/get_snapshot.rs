use ngxora_runtime::grpc::proto::GetSnapshotRequest;
use ngxora_runtime::grpc::proto::control_plane_client::ControlPlaneClient;
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
        Target::Tcp(addr) => Endpoint::from_shared(addr)?.connect().await?,
        Target::Uds(path) => connect_uds(path).await?,
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

fn parse_args<I>(args: I) -> Result<Target, Box<dyn Error>>
where
    I: IntoIterator,
    I::Item: Into<String>,
{
    let mut args = args.into_iter().skip(1).map(Into::into);
    let mut tcp: Option<String> = None;
    let mut uds: Option<PathBuf> = None;

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
            "-h" | "--help" => {
                print_usage();
                std::process::exit(0);
            }
            value => return Err(invalid_input(&format!("unknown argument: {value}")).into()),
        }
    }

    match (tcp, uds) {
        (Some(_), Some(_)) => Err(invalid_input("use either --addr or --uds, not both").into()),
        (Some(addr), None) => Ok(Target::Tcp(addr)),
        (None, Some(path)) => Ok(Target::Uds(path)),
        (None, None) => Ok(Target::Tcp("http://127.0.0.1:50051".into())),
    }
}

fn print_usage() {
    eprintln!(
        "Usage: cargo run -p ngxora-runtime --example get_snapshot -- [--addr <uri> | --uds <path>]"
    );
}

fn invalid_input(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.to_string())
}
