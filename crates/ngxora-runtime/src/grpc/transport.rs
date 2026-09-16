use super::{
    GrpcControlPlane, GrpcTlsConfig, InProcessControlPlane,
    proto::control_plane_server::ControlPlaneServer,
};
use pingora::server::ExecutionPhase;
use std::{future::Future, io, net::SocketAddr, path::PathBuf, thread::JoinHandle, time::Duration};
use tokio::{net::TcpListener, sync::broadcast, time::Instant};
use tonic::transport::{Server as GrpcServer, ServerTlsConfig, server::TcpIncoming};

#[cfg(unix)]
#[path = "uds.rs"]
mod uds;
#[cfg(all(unix, test))]
pub(super) use uds::set_uds_permissions;

pub(super) fn grpc_server(tls: &GrpcTlsConfig) -> Result<GrpcServer, tonic::transport::Error> {
    GrpcServer::builder().tls_config(
        ServerTlsConfig::new()
            .identity(tls.identity.clone())
            .client_ca_root(tls.client_ca.clone()),
    )
}

pub(super) fn grpc_runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("ngxora-grpc")
        .build()
        .map_err(|err| format!("failed to create gRPC runtime: {err}"))
}

/// Runs an unmanaged TCP server on the caller's runtime.
pub async fn serve_control_plane(
    addr: SocketAddr,
    control: InProcessControlPlane,
    tls: GrpcTlsConfig,
) -> Result<(), tonic::transport::Error> {
    grpc_server(&tls)?
        .add_service(ControlPlaneServer::new(GrpcControlPlane::new(control)))
        .serve(addr)
        .await
}

/// Runs an unmanaged UDS server on the caller's runtime.
#[cfg(unix)]
pub async fn serve_control_plane_uds(
    path: PathBuf,
    control: InProcessControlPlane,
) -> Result<(), String> {
    let (listener, _ownership) = uds::bind(&path)
        .await
        .map_err(|err| format!("gRPC UDS bind failed: {err}"))?;
    GrpcServer::builder()
        .add_service(ControlPlaneServer::new(GrpcControlPlane::new(control)))
        .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener))
        .await
        .map_err(|err| format!("gRPC UDS server failed: {err}"))
}

#[cfg(not(unix))]
pub async fn serve_control_plane_uds(
    _path: PathBuf,
    _control: InProcessControlPlane,
) -> Result<(), String> {
    Err("UDS gRPC control plane is only available on unix targets".into())
}

/// Owns all Tonic connection tasks on a separate runtime, closed at Pingora shutdown.
pub fn spawn_control_plane(
    addr: SocketAddr,
    control: InProcessControlPlane,
    tls: GrpcTlsConfig,
    phases: broadcast::Receiver<ExecutionPhase>,
    retry_bind: bool,
) -> Result<JoinHandle<()>, String> {
    let mut server =
        grpc_server(&tls).map_err(|err| format!("invalid gRPC mTLS configuration: {err}"))?;
    let runtime = grpc_runtime()?;
    Ok(std::thread::spawn(move || {
        runtime.block_on(until_shutdown(phases, async move {
            let listener = bind_retry(&addr.to_string(), retry_bind, || TcpListener::bind(addr))
                .await
                .map_err(|err| format!("failed to bind gRPC TCP {addr}: {err}"))?;
            // Keep the TCP_NODELAY default used by Tonic's serve(addr).
            let incoming = TcpIncoming::from_listener(listener, true, None)
                .map_err(|err| format!("failed to prepare gRPC TCP listener: {err}"))?;
            eprintln!("gRPC control plane listening with mTLS on {addr}");
            server
                .add_service(ControlPlaneServer::new(GrpcControlPlane::new(control)))
                .serve_with_incoming(incoming)
                .await
                .map_err(|err| format!("gRPC TCP server failed: {err}"))
        }));
        // Dropping only the serve future leaves Tonic's spawned connections alive.
        drop(runtime);
        eprintln!("gRPC control plane stopped on {addr}");
    }))
}

/// Keeps socket ownership until every task on the dedicated runtime has stopped.
#[cfg(unix)]
pub fn spawn_control_plane_uds(
    path: PathBuf,
    control: InProcessControlPlane,
    phases: broadcast::Receiver<ExecutionPhase>,
    retry_bind: bool,
) -> Result<JoinHandle<()>, String> {
    let runtime = grpc_runtime()?;
    Ok(std::thread::spawn(move || {
        let mut ownership = None;
        runtime.block_on(until_shutdown(phases, async {
            let (listener, guard) =
                bind_retry(&path.display().to_string(), retry_bind, || uds::bind(&path))
                    .await
                    .map_err(|err| format!("failed to bind gRPC UDS {}: {err}", path.display()))?;
            ownership = Some(guard);
            eprintln!("gRPC control plane listening on unix://{}", path.display());
            GrpcServer::builder()
                .add_service(ControlPlaneServer::new(GrpcControlPlane::new(control)))
                .serve_with_incoming(tokio_stream::wrappers::UnixListenerStream::new(listener))
                .await
                .map_err(|err| format!("gRPC UDS server failed: {err}"))
        }));
        drop(runtime);
        drop(ownership);
        eprintln!("gRPC control plane stopped on unix://{}", path.display());
    }))
}

#[cfg(not(unix))]
pub fn spawn_control_plane_uds(
    _path: PathBuf,
    _control: InProcessControlPlane,
    _phases: broadcast::Receiver<ExecutionPhase>,
    _retry_bind: bool,
) -> Result<JoinHandle<()>, String> {
    Err("UDS gRPC control plane is only available on unix targets".into())
}

async fn until_shutdown(
    phases: broadcast::Receiver<ExecutionPhase>,
    serve: impl Future<Output = Result<(), String>>,
) {
    tokio::select! {
        biased;
        () = stopping(phases) => {},
        result = serve => if let Err(err) = result { eprintln!("gRPC control plane failed: {err}"); },
    }
}

async fn stopping(mut phases: broadcast::Receiver<ExecutionPhase>) {
    loop {
        match phases.recv().await {
            Ok(
                ExecutionPhase::Setup
                | ExecutionPhase::Bootstrap
                | ExecutionPhase::BootstrapComplete
                | ExecutionPhase::Running,
            ) => {}
            Ok(_) | Err(broadcast::error::RecvError::Closed) => return,
            Err(broadcast::error::RecvError::Lagged(n)) => {
                eprintln!("gRPC stopping after missing {n} Pingora lifecycle events");
                return;
            }
        }
    }
}

async fn bind_retry<T, F, Fut>(address: &str, retry: bool, mut bind: F) -> io::Result<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = io::Result<T>>,
{
    let mut last_warning = None;
    loop {
        match bind().await {
            Ok(listener) => return Ok(listener),
            Err(err) if retry && err.kind() == io::ErrorKind::AddrInUse => {
                if last_warning
                    .is_none_or(|last: Instant| last.elapsed() >= Duration::from_secs(30))
                {
                    eprintln!(
                        "gRPC waiting for address {address}: {err}; retrying bind every second"
                    );
                    last_warning = Some(Instant::now());
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            Err(err) => return Err(err),
        }
    }
}

#[cfg(test)]
mod tests;
