//! Authenticated gRPC/UDS transport for the runtime control plane.

use crate::control::{ApplyResult as RuntimeApplyResult, InProcessControlPlane};
use tonic::transport::{Certificate, Identity};
use tonic::{Request, Response, Status};

pub use transport::{
    serve_control_plane, serve_control_plane_uds, spawn_control_plane, spawn_control_plane_uds,
};

pub mod proto {
    tonic::include_proto!("ngxora.control.v1");
}

use decode::runtime_snapshot_from_proto;
#[cfg(test)]
use decode::upstreams_from_proto;
use encode::proto_snapshot_from_runtime;
use proto::control_plane_server::ControlPlane;
use proto::{
    ApplyResult as ProtoApplyResult, ConfigSnapshot as ProtoConfigSnapshot,
    GetSnapshotRequest as ProtoGetSnapshotRequest,
};

mod client_policy;
mod decode;
mod encode;
mod http_routes;
mod tls;
mod transport;
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

fn proto_apply_result(result: RuntimeApplyResult) -> ProtoApplyResult {
    ProtoApplyResult {
        applied: result.applied,
        restart_required: result.restart_required,
        message: result.message,
        active_version: result.active_version,
        active_generation: result.active_generation,
    }
}
