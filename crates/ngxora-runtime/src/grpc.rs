use crate::control::{
    ApplyResult as RuntimeApplyResult, ConfigSnapshot as RuntimeConfigSnapshot,
    InProcessControlPlane, RuntimeSnapshot,
};
use crate::upstreams::{
    CompiledLocation, CompiledMatcher, CompiledRouter, HttpRuntimeOptions, ListenKey, RouteTarget,
    ServerRoutes, VirtualHostRoutes,
};
use ngxora_compile::ir::{
    DownstreamTlsOptions, Http, KeepaliveTimeout, Listen, Location, LocationDirective,
    LocationMatcher, PemSource, Server, Switch, TlsIdentity, TlsProtocolBounds, TlsProtocolVersion,
    TlsVerifyClient, UpstreamTimeouts,
};
use ngxora_plugin_api::PluginSpec;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::net::{IpAddr, SocketAddr};
use std::path::{Path, PathBuf};
use std::thread::JoinHandle;
use std::time::Duration;
#[cfg(unix)]
use tokio::net::UnixListener;
#[cfg(unix)]
use tokio_stream::wrappers::UnixListenerStream;
use tonic::transport::Server as GrpcServer;
use tonic::{Request, Response, Status};
use url::Url;

pub mod proto {
    tonic::include_proto!("ngxora.control.v1");
}

use proto::control_plane_server::{ControlPlane, ControlPlaneServer};
use proto::{
    ApplyResult as ProtoApplyResult, ConfigSnapshot as ProtoConfigSnapshot,
    GetSnapshotRequest as ProtoGetSnapshotRequest, HttpOptions as ProtoHttpOptions,
    Listener as ProtoListener, ListenerTlsOptions as ProtoListenerTlsOptions, Match as ProtoMatch,
    PemSource as ProtoPemSource, Plugin as ProtoPlugin, Regex as ProtoRegex, Route as ProtoRoute,
    RouteTimeouts as ProtoRouteTimeouts, TlsBinding as ProtoTlsBinding,
    TlsProtocolVersion as ProtoTlsProtocolVersion, TlsVerifyClient as ProtoTlsVerifyClient,
    Upstream as ProtoUpstream, VirtualHost as ProtoVirtualHost,
};

#[cfg(test)]
#[path = "grpc_tests.rs"]
mod tests;

#[derive(Clone)]
pub struct GrpcControlPlane {
    control: InProcessControlPlane,
}

impl GrpcControlPlane {
    pub fn new(control: InProcessControlPlane) -> Self {
        Self { control }
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
) -> Result<(), tonic::transport::Error> {
    GrpcServer::builder()
        .add_service(ControlPlaneServer::new(GrpcControlPlane::new(control)))
        .serve(addr)
        .await
}

/// Spawns the gRPC control plane on its own Tokio runtime so Pingora can
/// continue to own the main thread.
pub fn spawn_control_plane(
    addr: SocketAddr,
    control: InProcessControlPlane,
) -> Result<JoinHandle<()>, String> {
    let runtime = grpc_runtime()?;

    Ok(std::thread::spawn(move || {
        runtime.block_on(async move {
            if let Err(err) = serve_control_plane(addr, control).await {
                eprintln!("gRPC control plane stopped: {err}");
            }
        });
    }))
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

fn proto_apply_result(result: RuntimeApplyResult) -> ProtoApplyResult {
    ProtoApplyResult {
        applied: result.applied,
        restart_required: result.restart_required,
        message: result.message,
        active_version: result.active_version,
        active_generation: result.active_generation,
    }
}

// Converts the wire snapshot into the existing IR/CompiledRouter pipeline so
// config validation stays in one place.
fn runtime_snapshot_from_proto(
    snapshot: ProtoConfigSnapshot,
) -> Result<RuntimeConfigSnapshot, String> {
    let http = http_from_proto_snapshot(&snapshot)?;
    let router = CompiledRouter::from_http(&http)?;

    Ok(RuntimeConfigSnapshot::new(snapshot.version, router))
}

fn http_from_proto_snapshot(snapshot: &ProtoConfigSnapshot) -> Result<Http, String> {
    let options = snapshot.http.clone().unwrap_or_default();
    let listener_defs = listener_defs(&snapshot.listeners)?;
    let mut servers = Vec::with_capacity(snapshot.virtual_hosts.len());

    for virtual_host in &snapshot.virtual_hosts {
        let listener = listener_defs.get(&virtual_host.listener).ok_or_else(|| {
            format!(
                "virtual host references unknown listener `{}`",
                virtual_host.listener
            )
        })?;
        servers.push(server_from_proto_virtual_host(listener, virtual_host)?);
    }

    Ok(Http {
        servers,
        keepalive_timeout: keepalive_timeout_from_proto(
            options.downstream_keepalive_timeout_seconds,
        ),
        keepalive_requests: none_if_zero(options.keepalive_requests),
        tcp_nodelay: switch_from_bool(options.tcp_nodelay),
        allow_connect_method_proxying: switch_from_bool(options.allow_connect_method_proxying),
        h2c: switch_from_bool(options.h2c),
    })
}

fn listener_defs(listeners: &[ProtoListener]) -> Result<HashMap<String, ListenerDef>, String> {
    let mut defs = HashMap::with_capacity(listeners.len());

    for listener in listeners {
        let name = listener.name.trim();
        if name.is_empty() {
            return Err("listener name cannot be empty".into());
        }
        if defs.contains_key(name) {
            return Err(format!("listener `{name}` is duplicated"));
        }

        defs.insert(name.to_string(), ListenerDef::try_from(listener)?);
    }

    Ok(defs)
}

fn server_from_proto_virtual_host(
    listener: &ListenerDef,
    virtual_host: &ProtoVirtualHost,
) -> Result<Server, String> {
    if listener.listen.ssl && virtual_host.tls.is_none() {
        return Err(format!(
            "virtual host on listener `{}` requires a TLS binding",
            listener.name
        ));
    }
    if !listener.listen.ssl && virtual_host.tls.is_some() {
        return Err(format!(
            "virtual host on listener `{}` cannot define TLS binding on a plaintext listener",
            listener.name
        ));
    }

    Ok(Server {
        server_names: virtual_host.server_names.clone(),
        locations: virtual_host
            .routes
            .iter()
            .map(location_from_proto_route)
            .collect::<Result<Vec<_>, _>>()?,
        listens: vec![Listen {
            default_server: virtual_host.default_server,
            ..listener.listen.clone()
        }],
        tls: virtual_host
            .tls
            .as_ref()
            .map(tls_identity_from_proto)
            .transpose()?,
        tls_options: listener.tls_options.clone(),
    })
}

fn location_from_proto_route(route: &ProtoRoute) -> Result<Location, String> {
    let matcher = matcher_from_proto(route.r#match.as_ref())?;
    let upstream = route
        .upstream
        .as_ref()
        .ok_or_else(|| "route upstream is required".to_string())?;
    let mut directives = Vec::with_capacity(4);

    if let Some(timeouts) = route.timeouts.as_ref() {
        if let Some(duration) = duration_from_millis(timeouts.connect_timeout_ms) {
            directives.push(LocationDirective::ProxyConnectTimeout(duration));
        }
        if let Some(duration) = duration_from_millis(timeouts.read_timeout_ms) {
            directives.push(LocationDirective::ProxyReadTimeout(duration));
        }
        if let Some(duration) = duration_from_millis(timeouts.write_timeout_ms) {
            directives.push(LocationDirective::ProxyWriteTimeout(duration));
        }
    }

    directives.push(LocationDirective::ProxyPass(upstream_url_from_proto(
        upstream,
    )?));

    Ok(Location {
        matcher,
        directives,
        plugins: route
            .plugins
            .iter()
            .map(plugin_spec_from_proto)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn matcher_from_proto(value: Option<&ProtoMatch>) -> Result<LocationMatcher, String> {
    let matcher = value.ok_or_else(|| "route match is required".to_string())?;
    let kind = matcher
        .kind
        .as_ref()
        .ok_or_else(|| "route match kind is required".to_string())?;

    match kind {
        proto::r#match::Kind::Prefix(path) => Ok(LocationMatcher::Prefix(path.clone())),
        proto::r#match::Kind::Exact(path) => Ok(LocationMatcher::Exact(path.clone())),
        proto::r#match::Kind::PreferPrefix(path) => Ok(LocationMatcher::PreferPrefix(path.clone())),
        proto::r#match::Kind::Regex(regex) => Ok(LocationMatcher::Regex {
            case_insensitive: regex.case_insensitive,
            pattern: regex.pattern.clone(),
        }),
        proto::r#match::Kind::Named(name) => Ok(LocationMatcher::Named(name.clone())),
    }
}

fn upstream_url_from_proto(upstream: &ProtoUpstream) -> Result<Url, String> {
    if upstream.host.trim().is_empty() {
        return Err("upstream host cannot be empty".into());
    }
    if upstream.port == 0 {
        return Err("upstream port must be greater than zero".into());
    }

    let scheme = match upstream.scheme.as_str() {
        "http" | "https" => upstream.scheme.as_str(),
        _ => return Err(format!("unsupported upstream scheme `{}`", upstream.scheme)),
    };
    let raw = format!("{scheme}://{}:{}", upstream.host, upstream.port);
    Url::parse(&raw).map_err(|err| format!("invalid upstream URL `{raw}`: {err}"))
}

fn plugin_spec_from_proto(plugin: &ProtoPlugin) -> Result<PluginSpec, String> {
    if plugin.name.trim().is_empty() {
        return Err("plugin name cannot be empty".into());
    }

    let config = if plugin.json_config.trim().is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&plugin.json_config)
            .map_err(|err| format!("invalid plugin JSON for `{}`: {err}", plugin.name))?
    };

    Ok(PluginSpec {
        name: plugin.name.clone(),
        config,
    })
}

fn tls_identity_from_proto(value: &ProtoTlsBinding) -> Result<TlsIdentity, String> {
    Ok(TlsIdentity {
        cert: pem_source_from_proto(value.cert.as_ref(), "tls cert")?,
        key: pem_source_from_proto(value.key.as_ref(), "tls key")?,
    })
}

fn listener_tls_options_from_proto(
    value: Option<&ProtoListenerTlsOptions>,
) -> Result<DownstreamTlsOptions, String> {
    let Some(value) = value else {
        return Ok(DownstreamTlsOptions::default());
    };

    let min = tls_protocol_version_from_proto(value.min_protocol)?;
    let max = tls_protocol_version_from_proto(value.max_protocol)?;
    let protocols = match (min, max) {
        (None, None) => None,
        (Some(min), Some(max)) if min <= max => Some(TlsProtocolBounds { min, max }),
        (Some(_), Some(_)) => {
            return Err(
                "listener TLS protocol bounds are invalid: min_protocol > max_protocol".into(),
            );
        }
        _ => {
            return Err(
                "listener TLS protocol bounds must set both min_protocol and max_protocol".into(),
            );
        }
    };

    Ok(DownstreamTlsOptions {
        protocols,
        verify_client: tls_verify_client_from_proto(value.verify_client)?,
        client_certificate: value
            .client_certificate
            .as_ref()
            .map(|source| pem_source_from_proto(Some(source), "client certificate"))
            .transpose()?,
    })
}

fn pem_source_from_proto(value: Option<&ProtoPemSource>, field: &str) -> Result<PemSource, String> {
    let source = value.ok_or_else(|| format!("{field} is required"))?;
    let source = source
        .source
        .as_ref()
        .ok_or_else(|| format!("{field} source is required"))?;

    match source {
        proto::pem_source::Source::Path(path) => Ok(PemSource::Path(path.into())),
        proto::pem_source::Source::InlinePem(pem) => Ok(PemSource::InlinePem(pem.clone())),
    }
}

fn proto_snapshot_from_runtime(snapshot: &RuntimeSnapshot) -> Result<ProtoConfigSnapshot, String> {
    let mut listener_keys = snapshot
        .router
        .listeners
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    listener_keys.sort();

    let listener_names = listener_names(&listener_keys);
    let listeners = listener_keys
        .iter()
        .map(|key| proto_listener_from_runtime(snapshot, key, &listener_names))
        .collect::<Result<Vec<_>, _>>()?;

    let mut virtual_hosts = Vec::new();
    for key in &listener_keys {
        let routes = snapshot
            .router
            .listeners
            .get(key)
            .ok_or_else(|| "listener disappeared while building snapshot".to_string())?;
        let listener_name = listener_names
            .get(key)
            .cloned()
            .ok_or_else(|| "listener name mapping is incomplete".to_string())?;
        let tls = snapshot.router.listener_tls.get(key);
        virtual_hosts.extend(proto_virtual_hosts_from_runtime(
            &listener_name,
            routes,
            tls,
        )?);
    }

    Ok(ProtoConfigSnapshot {
        version: snapshot.version.clone(),
        http: Some(proto_http_options_from_runtime(
            &snapshot.router.http_options,
        )),
        listeners,
        virtual_hosts,
    })
}

fn listener_names(keys: &[ListenKey]) -> BTreeMap<ListenKey, String> {
    keys.iter()
        .enumerate()
        .map(|(index, key)| (key.clone(), format!("listener-{}", index + 1)))
        .collect()
}

fn proto_listener_from_runtime(
    snapshot: &RuntimeSnapshot,
    key: &ListenKey,
    names: &BTreeMap<ListenKey, String>,
) -> Result<ProtoListener, String> {
    let protocol = snapshot
        .router
        .listener_protocols
        .get(key)
        .cloned()
        .unwrap_or_default();
    let tls_options = snapshot
        .router
        .listener_tls
        .get(key)
        .map(|tls| proto_listener_tls_options_from_runtime(&tls.settings));

    Ok(ProtoListener {
        name: names
            .get(key)
            .cloned()
            .ok_or_else(|| "listener name mapping is incomplete".to_string())?,
        address: key.addr.to_string(),
        port: u32::from(key.port),
        tls: key.ssl,
        http2: protocol.http2,
        http2_only: protocol.http2_only,
        tls_options,
    })
}

fn proto_virtual_hosts_from_runtime(
    listener_name: &str,
    routes: &VirtualHostRoutes,
    tls: Option<&crate::upstreams::ListenerTlsConfig>,
) -> Result<Vec<ProtoVirtualHost>, String> {
    let mut virtual_hosts = Vec::new();

    for (host, server_routes) in sorted_named_routes(&routes.named) {
        let identity = tls
            .and_then(|cfg| cfg.named.get(host))
            .cloned()
            .or_else(|| tls.and_then(|cfg| cfg.default.clone()));

        merge_or_push_virtual_host(
            &mut virtual_hosts,
            listener_name,
            false,
            host.clone(),
            server_routes,
            identity,
        )?;
    }

    if let Some(default_routes) = routes.default.as_ref() {
        let default_tls = tls.and_then(|cfg| cfg.default.clone());
        let default_routes_proto = proto_routes_from_runtime(default_routes)?;
        let default_tls_proto = default_tls.as_ref().map(proto_tls_binding_from_runtime);

        if let Some(current) = virtual_hosts.iter_mut().find(|current| {
            current.listener == listener_name
                && current.routes == default_routes_proto
                && current.tls == default_tls_proto
        }) {
            current.default_server = true;
        } else {
            virtual_hosts.push(ProtoVirtualHost {
                listener: listener_name.to_string(),
                server_names: Vec::new(),
                default_server: true,
                tls: default_tls_proto,
                routes: default_routes_proto,
            });
        }
    }

    Ok(virtual_hosts)
}

fn merge_or_push_virtual_host(
    out: &mut Vec<ProtoVirtualHost>,
    listener_name: &str,
    default_server: bool,
    host: String,
    routes: &ServerRoutes,
    identity: Option<TlsIdentity>,
) -> Result<(), String> {
    let tls = identity.as_ref().map(proto_tls_binding_from_runtime);
    let routes = proto_routes_from_runtime(routes)?;

    if let Some(current) = out.iter_mut().find(|current| {
        current.listener == listener_name
            && current.default_server == default_server
            && current.tls == tls
            && current.routes == routes
    }) {
        current.server_names.push(host);
        current.server_names.sort();
        return Ok(());
    }

    out.push(ProtoVirtualHost {
        listener: listener_name.to_string(),
        server_names: vec![host],
        default_server,
        tls,
        routes,
    });
    Ok(())
}

fn proto_routes_from_runtime(routes: &ServerRoutes) -> Result<Vec<ProtoRoute>, String> {
    routes
        .locations
        .iter()
        .map(proto_route_from_runtime)
        .collect()
}

fn proto_route_from_runtime(route: &CompiledLocation) -> Result<ProtoRoute, String> {
    Ok(ProtoRoute {
        r#match: Some(proto_match_from_runtime(&route.matcher)),
        upstream: Some(proto_upstream_from_runtime(&route.target)),
        timeouts: Some(proto_timeouts_from_runtime(&route.upstream_timeouts)),
        plugins: route
            .plugins
            .iter()
            .map(proto_plugin_from_runtime)
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn proto_match_from_runtime(matcher: &CompiledMatcher) -> ProtoMatch {
    let kind = match matcher {
        CompiledMatcher::Prefix(path) => proto::r#match::Kind::Prefix(path.clone()),
        CompiledMatcher::Exact(path) => proto::r#match::Kind::Exact(path.clone()),
        CompiledMatcher::PreferPrefix(path) => proto::r#match::Kind::PreferPrefix(path.clone()),
        CompiledMatcher::Regex(regex) => proto::r#match::Kind::Regex(ProtoRegex {
            pattern: regex.pattern.clone(),
            case_insensitive: regex.case_insensitive,
        }),
        CompiledMatcher::Named(name) => proto::r#match::Kind::Named(name.clone()),
    };

    ProtoMatch { kind: Some(kind) }
}

fn proto_upstream_from_runtime(target: &RouteTarget) -> ProtoUpstream {
    match target {
        RouteTarget::ProxyPass {
            host, port, tls, ..
        } => ProtoUpstream {
            scheme: if *tls { "https" } else { "http" }.into(),
            host: host.clone(),
            port: u32::from(*port),
        },
    }
}

fn proto_timeouts_from_runtime(timeouts: &UpstreamTimeouts) -> ProtoRouteTimeouts {
    ProtoRouteTimeouts {
        connect_timeout_ms: duration_to_millis(timeouts.connect),
        read_timeout_ms: duration_to_millis(timeouts.read),
        write_timeout_ms: duration_to_millis(timeouts.write),
    }
}

fn proto_plugin_from_runtime(plugin: &PluginSpec) -> Result<ProtoPlugin, String> {
    Ok(ProtoPlugin {
        name: plugin.name.clone(),
        json_config: serde_json::to_string(&plugin.config)
            .map_err(|err| format!("failed to serialize plugin `{}` config: {err}", plugin.name))?,
    })
}

fn proto_http_options_from_runtime(options: &HttpRuntimeOptions) -> ProtoHttpOptions {
    ProtoHttpOptions {
        downstream_keepalive_timeout_seconds: options.downstream_keepalive_timeout.unwrap_or(0),
        tcp_nodelay: options.tcp_nodelay,
        keepalive_requests: options.keepalive_requests.unwrap_or(0),
        allow_connect_method_proxying: options.allow_connect_method_proxying,
        h2c: options.h2c,
    }
}

fn proto_listener_tls_options_from_runtime(
    value: &crate::upstreams::ListenerTlsSettings,
) -> ProtoListenerTlsOptions {
    let (min_protocol, max_protocol) = value
        .protocols
        .map(|bounds| {
            (
                proto_tls_protocol_version_from_runtime(bounds.min),
                proto_tls_protocol_version_from_runtime(bounds.max),
            )
        })
        .unwrap_or((
            ProtoTlsProtocolVersion::Unspecified as i32,
            ProtoTlsProtocolVersion::Unspecified as i32,
        ));

    ProtoListenerTlsOptions {
        min_protocol,
        max_protocol,
        verify_client: proto_tls_verify_client_from_runtime(value.verify_client) as i32,
        client_certificate: value
            .client_certificate
            .as_ref()
            .map(proto_pem_source_from_runtime),
    }
}

fn proto_tls_binding_from_runtime(value: &TlsIdentity) -> ProtoTlsBinding {
    ProtoTlsBinding {
        cert: Some(proto_pem_source_from_runtime(&value.cert)),
        key: Some(proto_pem_source_from_runtime(&value.key)),
    }
}

fn proto_pem_source_from_runtime(value: &PemSource) -> ProtoPemSource {
    let source = match value {
        PemSource::Path(path) => proto::pem_source::Source::Path(path.display().to_string()),
        PemSource::InlinePem(pem) => proto::pem_source::Source::InlinePem(pem.clone()),
    };

    ProtoPemSource {
        source: Some(source),
    }
}

fn proto_tls_protocol_version_from_runtime(value: TlsProtocolVersion) -> i32 {
    match value {
        TlsProtocolVersion::Tls1 => ProtoTlsProtocolVersion::Tls1 as i32,
        TlsProtocolVersion::Tls1_2 => ProtoTlsProtocolVersion::Tls12 as i32,
        TlsProtocolVersion::Tls1_3 => ProtoTlsProtocolVersion::Tls13 as i32,
    }
}

fn proto_tls_verify_client_from_runtime(value: TlsVerifyClient) -> ProtoTlsVerifyClient {
    match value {
        TlsVerifyClient::Off => ProtoTlsVerifyClient::Off,
        TlsVerifyClient::Optional => ProtoTlsVerifyClient::Optional,
        TlsVerifyClient::Required => ProtoTlsVerifyClient::Required,
    }
}

fn tls_protocol_version_from_proto(value: i32) -> Result<Option<TlsProtocolVersion>, String> {
    match ProtoTlsProtocolVersion::try_from(value).unwrap_or(ProtoTlsProtocolVersion::Unspecified) {
        ProtoTlsProtocolVersion::Unspecified => Ok(None),
        ProtoTlsProtocolVersion::Tls1 => Ok(Some(TlsProtocolVersion::Tls1)),
        ProtoTlsProtocolVersion::Tls12 => Ok(Some(TlsProtocolVersion::Tls1_2)),
        ProtoTlsProtocolVersion::Tls13 => Ok(Some(TlsProtocolVersion::Tls1_3)),
    }
}

fn tls_verify_client_from_proto(value: i32) -> Result<TlsVerifyClient, String> {
    match ProtoTlsVerifyClient::try_from(value).unwrap_or(ProtoTlsVerifyClient::Unspecified) {
        ProtoTlsVerifyClient::Unspecified | ProtoTlsVerifyClient::Off => Ok(TlsVerifyClient::Off),
        ProtoTlsVerifyClient::Optional => Ok(TlsVerifyClient::Optional),
        ProtoTlsVerifyClient::Required => Ok(TlsVerifyClient::Required),
    }
}

fn keepalive_timeout_from_proto(seconds: u64) -> KeepaliveTimeout {
    if seconds == 0 {
        KeepaliveTimeout::Off
    } else {
        KeepaliveTimeout::Timeout {
            idle: Duration::from_secs(seconds),
            header: None,
        }
    }
}

fn duration_from_millis(millis: u64) -> Option<Duration> {
    (millis > 0).then(|| Duration::from_millis(millis))
}

fn duration_to_millis(duration: Option<Duration>) -> u64 {
    duration
        .map(|value| u64::try_from(value.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

fn switch_from_bool(value: bool) -> Switch {
    if value { Switch::On } else { Switch::Off }
}

fn none_if_zero(value: u32) -> Option<u32> {
    (value > 0).then_some(value)
}

fn sorted_named_routes(routes: &HashMap<String, ServerRoutes>) -> Vec<(&String, &ServerRoutes)> {
    let mut entries = routes.iter().collect::<Vec<_>>();
    entries.sort_by(|(left, _), (right, _)| left.cmp(right));
    entries
}

#[derive(Clone)]
struct ListenerDef {
    name: String,
    listen: Listen,
    tls_options: DownstreamTlsOptions,
}

impl TryFrom<&ProtoListener> for ListenerDef {
    type Error = String;

    fn try_from(value: &ProtoListener) -> Result<Self, Self::Error> {
        let addr: IpAddr = value
            .address
            .parse()
            .map_err(|err| format!("invalid listener address `{}`: {err}", value.address))?;
        let port = u16::try_from(value.port)
            .map_err(|_| format!("invalid listener port `{}`", value.port))?;
        let tls_options = listener_tls_options_from_proto(value.tls_options.as_ref())?;

        if !value.tls && tls_options != DownstreamTlsOptions::default() {
            return Err(format!(
                "listener `{}` defines TLS options but tls=false",
                value.name
            ));
        }

        Ok(Self {
            name: value.name.clone(),
            listen: Listen {
                addr,
                port,
                ssl: value.tls,
                default_server: false,
                http2: value.http2,
                http2_only: value.http2_only,
            },
            tls_options,
        })
    }
}
