//! Authenticated gRPC/UDS transport for the runtime control plane.

use crate::control::{ApplyResult as RuntimeApplyResult, InProcessControlPlane};
use std::net::SocketAddr;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use tonic::transport::{Certificate, Identity, Server as GrpcServer, ServerTlsConfig};
use tonic::{Request, Response, Status};

#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(unix)]
use tokio_stream::wrappers::UnixListenerStream;

pub mod proto {
    tonic::include_proto!("ngxora.control.v1");
}

use decode::runtime_snapshot_from_proto;
#[cfg(test)]
use decode::upstreams_from_proto;
use encode::proto_snapshot_from_runtime;
use proto::control_plane_server::{ControlPlane, ControlPlaneServer};
use proto::{
    ApplyResult as ProtoApplyResult, ConfigSnapshot as ProtoConfigSnapshot,
    GetSnapshotRequest as ProtoGetSnapshotRequest,
};

mod client_policy;
mod decode;
mod encode;
mod http_routes;
mod tls;
mod values;

#[cfg(test)]
mod tests;

/// GrpcControlPlane exposes the in-process runtime state through the protobuf
/// ControlPlane service.
#[derive(Clone)]
pub struct GrpcControlPlane {
    control: InProcessControlPlane,
}

impl GrpcControlPlane {
    /// new wraps the in-process control-plane with the gRPC service adapter.
    pub fn new(control: InProcessControlPlane) -> Self {
        Self { control }
    }
}

/// TLS material for the TCP gRPC control plane.
///
/// Supplying a client CA makes client certificates mandatory. The local UDS
/// control plane intentionally does not use this configuration.
#[derive(Clone)]
pub struct GrpcTlsConfig {
    identity: Identity,
    client_ca: Certificate,
}

impl GrpcTlsConfig {
    /// Creates the server identity and the dedicated CA used for controller
    /// client certificates.
    pub fn from_pem(
        server_certificate: impl AsRef<[u8]>,
        server_key: impl AsRef<[u8]>,
        client_ca: impl AsRef<[u8]>,
    ) -> Self {
        Self {
            identity: Identity::from_pem(server_certificate, server_key),
            client_ca: Certificate::from_pem(client_ca),
        }
    }
}

#[tonic::async_trait]
impl ControlPlane for GrpcControlPlane {
    async fn apply_snapshot(
        &self,
        request: Request<ProtoConfigSnapshot>,
    ) -> Result<Response<ProtoApplyResult>, Status> {
        let snapshot =
            runtime_snapshot_from_proto(request.into_inner()).map_err(Status::invalid_argument)?;
        let result = self.control.apply_snapshot(snapshot);
        Ok(Response::new(proto_apply_result(result)))
    }

    async fn get_snapshot(
        &self,
        _request: Request<ProtoGetSnapshotRequest>,
    ) -> Result<Response<ProtoConfigSnapshot>, Status> {
        let snapshot = self.control.get_snapshot();
        let response =
            proto_snapshot_from_runtime(snapshot.as_ref()).map_err(Status::failed_precondition)?;
        Ok(Response::new(response))
    }
}

/// Runs the gRPC control plane on the provided socket address.
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

/// Spawns the gRPC control plane on its own Tokio runtime so Pingora can
/// continue to own the main thread.
pub fn spawn_control_plane(
    addr: SocketAddr,
    control: InProcessControlPlane,
    tls: GrpcTlsConfig,
) -> Result<JoinHandle<()>, String> {
    // Validate the PEM before the server is moved to its background runtime so
    // a bad Secret fails process startup instead of only logging in a thread.
    grpc_server(&tls).map_err(|err| format!("invalid gRPC mTLS configuration: {err}"))?;
    let runtime = grpc_runtime()?;

    Ok(std::thread::spawn(move || {
        runtime.block_on(async move {
            if let Err(err) = serve_control_plane(addr, control, tls).await {
                eprintln!("gRPC control plane stopped: {err}");
            }
        });
    }))
}

fn grpc_server(tls: &GrpcTlsConfig) -> Result<GrpcServer, tonic::transport::Error> {
    GrpcServer::builder().tls_config(
        ServerTlsConfig::new()
            .identity(tls.identity.clone())
            .client_ca_root(tls.client_ca.clone()),
    )
}

/// Runs the gRPC control plane over a Unix domain socket for local agent-sidecar use.
#[cfg(unix)]
pub async fn serve_control_plane_uds(
    path: PathBuf,
    control: InProcessControlPlane,
) -> Result<(), String> {
    prepare_uds_path(&path)?;
    let listener = UnixListener::bind(&path)
        .map_err(|err| format!("failed to bind gRPC UDS {}: {err}", path.display()))?;
    set_uds_permissions(&path)?;
    let incoming = UnixListenerStream::new(listener);

    GrpcServer::builder()
        .add_service(ControlPlaneServer::new(GrpcControlPlane::new(control)))
        .serve_with_incoming(incoming)
        .await
        .map_err(|err| format!("gRPC control plane stopped on {}: {err}", path.display()))
}

#[cfg(not(unix))]
pub async fn serve_control_plane_uds(
    _path: PathBuf,
    _control: InProcessControlPlane,
) -> Result<(), String> {
    Err("UDS gRPC control plane is only available on unix targets".into())
}

/// Spawns the UDS gRPC control plane on its own Tokio runtime.
pub fn spawn_control_plane_uds(
    path: PathBuf,
    control: InProcessControlPlane,
) -> Result<JoinHandle<()>, String> {
    let runtime = grpc_runtime()?;

    Ok(std::thread::spawn(move || {
        runtime.block_on(async move {
            if let Err(err) = serve_control_plane_uds(path.clone(), control).await {
                eprintln!("gRPC control plane stopped on {}: {err}", path.display());
            }
        });
    }))
}

fn grpc_runtime() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .thread_name("ngxora-grpc")
        .build()
        .map_err(|err| format!("failed to build gRPC runtime: {err}"))
}

#[cfg(unix)]
fn prepare_uds_path(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("failed to create directory {}: {err}", parent.display()))?;
    }

    match std::fs::metadata(path) {
        Ok(metadata) => {
            #[allow(clippy::useless_conversion)]
            let is_socket = std::os::unix::fs::FileTypeExt::is_socket(&metadata.file_type());
            if !is_socket {
                return Err(format!(
                    "gRPC UDS path {} already exists and is not a socket",
                    path.display()
                ));
            }
            std::fs::remove_file(path).map_err(|err| {
                format!(
                    "failed to remove stale gRPC socket {}: {err}",
                    path.display()
                )
            })?;
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(err) => {
            return Err(format!(
                "failed to inspect gRPC socket path {}: {err}",
                path.display()
            ));
        }
    }

    Ok(())
}

#[cfg(unix)]
fn set_uds_permissions(path: &Path) -> Result<(), String> {
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|err| {
        format!(
            "failed to set gRPC UDS permissions on {}: {err}",
            path.display()
        )
    })
}

fn proto_apply_result(result: RuntimeApplyResult) -> ProtoApplyResult {
    ProtoApplyResult {
        applied: result.applied,
        restart_required: result.restart_required,
        message: result.message,
        active_version: result.active_version,
        active_generation: result.active_generation,
    }
}
