use super::compile::proxy_pass_sni;
use super::routing::{ResolvedLocation, listener_routes, resolve_route};
use super::types::{
    CompiledRouter, CompiledUpstreamGroup, CompiledUpstreamServer, ListenKey, RouteTarget,
    VirtualHostRoutes,
};
use crate::control::{ApplyResult, ConfigSnapshot, RuntimeSnapshot, RuntimeState};
use async_trait::async_trait;
use bytes::Bytes;
use futures::FutureExt;
use ngxora_compile::ir::{
    PemSource, Switch, UpstreamHttpProtocol, UpstreamSelectionPolicy, UpstreamSslOptions,
    UpstreamTimeouts,
};
use ngxora_plugin_api::{
    HeaderMapMut, LocalResponse, PluginError, PluginFlow, PluginState, RequestCtx, ResponseCtx,
    UpstreamRequestCtx,
};
use pingora::Result as PingoraResult;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::lb::{Backend, Backends, LoadBalancer, discovery, selection};
use pingora::protocols::l4::socket::SocketAddr as PingoraSocketAddr;
use pingora::protocols::tls::CaType;
#[cfg(feature = "openssl")]
use pingora::tls::x509::X509;
use pingora::upstreams::peer::HttpPeer;
use pingora_proxy::{ProxyHttp, Session};
use std::collections::{BTreeSet, HashMap};
use std::fmt::Display;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

pub(crate) type RuntimeTrustedCa = Arc<CaType>;

pub struct RuntimeUpstreamGroup {
    selector: RuntimeUpstreamSelector,
    max_iterations: usize,
    health_check: Option<RuntimeHealthCheckSchedule>,
}

enum RuntimeUpstreamSelector {
    RoundRobin(LoadBalancer<selection::RoundRobin>),
    Random(LoadBalancer<selection::Random>),
}

struct RuntimeHealthCheckSchedule {
    interval: Duration,
    next_run_at: Mutex<Instant>,
}

fn synthetic_backends(servers: &[CompiledUpstreamServer]) -> Result<BTreeSet<Backend>, String> {
    servers
        .iter()
        .enumerate()
        .map(|(index, server)| {
            let mut ext = http::Extensions::new();
            ext.insert(server.clone());

            Ok(Backend {
                addr: PingoraSocketAddr::Inet(synthetic_backend_addr(index)),
                weight: 1,
                ext,
            })
        })
        .collect()
}

fn synthetic_backend_addr(index: usize) -> SocketAddr {
    let index = u64::try_from(index).unwrap_or(u64::MAX);
    let ip = Ipv6Addr::new(
        0xfd00,
        0,
        0,
        0,
        ((index >> 32) & 0xffff) as u16,
        ((index >> 16) & 0xffff) as u16,
        (index & 0xffff) as u16,
        1,
    );

    SocketAddr::V6(SocketAddrV6::new(ip, 1, 0, 0))
}

fn build_load_balancer<S>(
    backends: BTreeSet<Backend>,
    health_check: Option<&super::CompiledHealthCheck>,
) -> Result<LoadBalancer<S>, String>
where
    S: selection::BackendSelection + 'static,
    S::Iter: selection::BackendIter,
{
    let discovery = discovery::Static::new(backends);
    let backends = Backends::new(discovery);
    let mut lb = LoadBalancer::from_backends(backends);
    if let Some(health_check) = health_check {
        lb.set_health_check(health_check.build()?);
    }
    lb.update()
        .now_or_never()
        .ok_or_else(|| "static upstream update unexpectedly blocked".to_string())?
        .map_err(|err| format!("failed to initialize upstream load balancer: {err}"))?;
    Ok(lb)
}

impl RuntimeUpstreamSelector {
    fn select(&self, key: &[u8], max_iterations: usize) -> Option<Backend> {
        match self {
            Self::RoundRobin(lb) => lb.select(key, max_iterations),
            Self::Random(lb) => lb.select(key, max_iterations),
        }
    }

    async fn run_health_check(&self) {
        match self {
            Self::RoundRobin(lb) => lb.backends().run_health_check(false).await,
            Self::Random(lb) => lb.backends().run_health_check(false).await,
        }
    }
}

impl RuntimeUpstreamGroup {
    pub(crate) fn from_compiled(group: &CompiledUpstreamGroup) -> Result<Self, String> {
        if group.servers.is_empty() {
            return Err(format!(
                "upstream `{}` must define at least one server",
                group.name
            ));
        }

        let backends = synthetic_backends(&group.servers)?;
        let selector = match group.policy {
            UpstreamSelectionPolicy::RoundRobin => RuntimeUpstreamSelector::RoundRobin(
                build_load_balancer(backends, group.health_check.as_ref())?,
            ),
            UpstreamSelectionPolicy::Random => RuntimeUpstreamSelector::Random(
                build_load_balancer(backends, group.health_check.as_ref())?,
            ),
        };

        Ok(Self {
            selector,
            max_iterations: group.servers.len(),
            health_check: group.health_check.as_ref().map(|health_check| {
                RuntimeHealthCheckSchedule {
                    interval: health_check.interval,
                    next_run_at: Mutex::new(Instant::now()),
                }
            }),
        })
    }

    pub(crate) fn select(&self, key: &[u8]) -> Option<CompiledUpstreamServer> {
        let backend = self.selector.select(key, self.max_iterations)?;
        backend.ext.get::<CompiledUpstreamServer>().cloned()
    }

    pub(crate) async fn run_due_health_check(&self, now: Instant) -> Option<Instant> {
        let schedule = self.health_check.as_ref()?;
        let next_run_at = {
            let mut next_run_at = schedule
                .next_run_at
                .lock()
                .expect("health check lock poisoned");
            if *next_run_at > now {
                return Some(*next_run_at);
            }
            *next_run_at = now + schedule.interval;
            *next_run_at
        };
        self.selector.run_health_check().await;
        Some(next_run_at)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct SelectedPeer {
    host: String,
    port: u16,
    tls: bool,
    sni: String,
}

#[derive(Clone)]
pub(crate) struct SelectedRoute {
    peer: SelectedPeer,
    upstream_timeouts: UpstreamTimeouts,
    upstream_protocol: Option<UpstreamHttpProtocol>,
    upstream_ssl_options: UpstreamSslOptions,
    upstream_trusted_ca: Option<RuntimeTrustedCa>,
    plugins: ngxora_plugin_api::PluginChain,
}

#[derive(Default)]
pub struct ProxyContext {
    pub(crate) selected: Option<SelectedRoute>,
    pub(crate) plugin_state: PluginState,
    pub(crate) client_max_body_size: Option<u64>,
    pub(crate) received_body_bytes: u64,
}

fn header_editor_error(action: &str, name: &http::HeaderName, err: impl Display) -> PluginError {
    PluginError::new(
        "header-editor",
        format!("failed to {action} header `{name}`: {err}"),
    )
}

struct RequestHeaderEditor<'a> {
    inner: &'a mut RequestHeader,
}

impl HeaderMapMut for RequestHeaderEditor<'_> {
    fn get(&self, name: &http::HeaderName) -> Option<&http::HeaderValue> {
        self.inner.headers.get(name)
    }

    fn add(
        &mut self,
        name: &http::HeaderName,
        value: http::HeaderValue,
    ) -> Result<(), PluginError> {
        self.inner
            .append_header(name, value)
            .map(|_| ())
            .map_err(|err| header_editor_error("append", name, err))
    }

    fn set(
        &mut self,
        name: &http::HeaderName,
        value: http::HeaderValue,
    ) -> Result<(), PluginError> {
        self.inner
            .insert_header(name, value)
            .map_err(|err| header_editor_error("insert", name, err))
    }

    fn remove(&mut self, name: &http::HeaderName) {
        self.inner.remove_header(name);
    }
}

struct ResponseHeaderEditor<'a> {
    inner: &'a mut ResponseHeader,
}

impl HeaderMapMut for ResponseHeaderEditor<'_> {
    fn get(&self, name: &http::HeaderName) -> Option<&http::HeaderValue> {
        self.inner.headers.get(name)
    }

    fn add(
        &mut self,
        name: &http::HeaderName,
        value: http::HeaderValue,
    ) -> Result<(), PluginError> {
        self.inner
            .append_header(name, value)
            .map(|_| ())
            .map_err(|err| header_editor_error("append", name, err))
    }

    fn set(
        &mut self,
        name: &http::HeaderName,
        value: http::HeaderValue,
    ) -> Result<(), PluginError> {
        self.inner
            .insert_header(name, value)
            .map_err(|err| header_editor_error("insert", name, err))
    }

    fn remove(&mut self, name: &http::HeaderName) {
        self.inner.remove_header(name);
    }
}

impl SelectedRoute {
    fn from_resolved(snapshot: &RuntimeSnapshot, resolved: &ResolvedLocation<'_>) -> PingoraResult<Self> {
        let peer = match &resolved.location.target {
            RouteTarget::ProxyPass {
                host,
                port,
                tls,
                sni,
            } => SelectedPeer {
                host: host.clone(),
                port: *port,
                tls: *tls,
                sni: sni.clone(),
            },
            RouteTarget::UpstreamGroup { name, tls } => {
                let group = snapshot.upstream_group(name).ok_or_else(|| {
                    pingora::Error::explain(
                        pingora::ErrorType::InternalError,
                        format!("compiled upstream group `{name}` is missing at runtime"),
                    )
                })?;
                let backend = group.select(b"").ok_or_else(|| {
                    pingora::Error::explain(
                        pingora::ErrorType::HTTPStatus(503),
                        format!("upstream `{name}` has no available backends"),
                    )
                })?;

                SelectedPeer {
                    sni: proxy_pass_sni(&backend.host, *tls),
                    host: backend.host,
                    port: backend.port,
                    tls: *tls,
                }
            }
        };

        Ok(Self {
            peer,
            upstream_timeouts: resolved.location.upstream_timeouts,
            upstream_protocol: resolved.location.upstream_protocol,
            upstream_ssl_options: resolved.location.upstream_ssl_options.clone(),
            upstream_trusted_ca: resolved
                .location
                .upstream_ssl_options
                .trusted_certificate
                .as_ref()
                .map(|source| {
                    snapshot.trusted_ca(source).ok_or_else(|| {
                        pingora::Error::explain(
                            pingora::ErrorType::InternalError,
                            "compiled trusted upstream CA is missing at runtime",
                        )
                    })
                })
                .transpose()?,
            plugins: snapshot.plugin_chain(resolved.location.route_id),
        })
    }
}

fn select_runtime_route(
    snapshot: &RuntimeSnapshot,
    session: &Session,
) -> PingoraResult<Option<(SelectedRoute, Option<String>)>> {
    let Some(resolved) = resolve_route(&snapshot.router, session)? else {
        return Ok(None);
    };

    Ok(Some((
        SelectedRoute::from_resolved(snapshot, &resolved)?,
        resolved.host,
    )))
}

fn respond_from_plugin_flow(flow: PluginFlow, stage: &str) -> PingoraResult<()> {
    match flow {
        PluginFlow::Continue => Ok(()),
        PluginFlow::Respond(_) => Err(pingora::Error::explain(
            pingora::ErrorType::InternalError,
            format!("plugin attempted local response during {stage}, which is not supported"),
        )),
    }
}

fn map_plugin_error(stage: &str, err: PluginError) -> Box<pingora::Error> {
    pingora::Error::explain(
        pingora::ErrorType::InternalError,
        format!("plugin hook failed during {stage}: {err}"),
    )
}

fn set_content_length(header: &mut ResponseHeader, value: impl ToString) -> PingoraResult<()> {
    let value = value.to_string();
    header
        .insert_header(http::header::CONTENT_LENGTH, value)
        .map_err(|err| {
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                format!("failed to finalize plugin response: {err}"),
            )
        })
}

fn normalized_peer_timeout(timeout: Option<Duration>) -> Option<Duration> {
    match timeout {
        Some(timeout) if timeout.is_zero() => None,
        other => other,
    }
}

fn body_too_large_error() -> Box<pingora::Error> {
    pingora::Error::explain(
        pingora::ErrorType::HTTPStatus(413),
        "request body exceeds client_max_body_size",
    )
}

pub(crate) fn content_length_limit_exceeded(
    header: Option<&http::HeaderValue>,
    limit: Option<u64>,
) -> Option<bool> {
    let limit = limit?;
    let header = header?;
    let size = header.to_str().ok()?.parse::<u64>().ok()?;
    Some(size > limit)
}

pub(crate) fn update_received_body_bytes(
    received: &mut u64,
    body: Option<&Bytes>,
    limit: Option<u64>,
) -> PingoraResult<()> {
    let Some(limit) = limit else {
        return Ok(());
    };
    let Some(body) = body else {
        return Ok(());
    };

    let chunk_len = u64::try_from(body.len()).map_err(|_| body_too_large_error())?;
    let next = received
        .checked_add(chunk_len)
        .ok_or_else(body_too_large_error)?;
    if next > limit {
        return Err(body_too_large_error());
    }

    *received = next;
    Ok(())
}

// Route-level timeout directives are mapped directly to Pingora upstream peer
// options, so they can change live with route snapshots.
pub(crate) fn apply_upstream_timeouts(peer: &mut HttpPeer, timeouts: UpstreamTimeouts) {
    peer.options.connection_timeout = normalized_peer_timeout(timeouts.connect);
    peer.options.read_timeout = normalized_peer_timeout(timeouts.read);
    peer.options.write_timeout = normalized_peer_timeout(timeouts.write);
}

pub(crate) fn apply_upstream_http_protocol(
    peer: &mut HttpPeer,
    protocol: Option<UpstreamHttpProtocol>,
) {
    match protocol {
        Some(UpstreamHttpProtocol::H1) => peer.options.set_http_version(1, 1),
        Some(UpstreamHttpProtocol::H2 | UpstreamHttpProtocol::H2c) => {
            peer.options.set_http_version(2, 2)
        }
        None => {}
    }
}

// Apply SSL options from location directives to Pingora peer options.
pub(crate) fn apply_upstream_ssl_options(
    peer: &mut HttpPeer,
    options: &UpstreamSslOptions,
    trusted_ca: Option<&RuntimeTrustedCa>,
) {
    match options.verify_cert {
        Switch::On => {
            peer.options.verify_cert = true;
            peer.options.verify_hostname = true;
        }
        Switch::Off => {
            peer.options.verify_cert = false;
            peer.options.verify_hostname = false;
        }
    }

    peer.options.ca = trusted_ca.cloned();
}

pub(crate) fn build_runtime_trusted_cas(
    router: &CompiledRouter,
) -> Result<HashMap<PemSource, RuntimeTrustedCa>, String> {
    let mut trusted_cas = HashMap::new();

    for routes in router.listeners.values() {
        collect_trusted_cas_from_vhosts(routes, &mut trusted_cas)?;
    }

    Ok(trusted_cas)
}

fn collect_trusted_cas_from_vhosts(
    routes: &VirtualHostRoutes,
    trusted_cas: &mut HashMap<PemSource, RuntimeTrustedCa>,
) -> Result<(), String> {
    for server_routes in routes.named.values().chain(routes.default.iter()) {
        collect_trusted_cas_from_server(server_routes, trusted_cas)?;
    }

    Ok(())
}

fn collect_trusted_cas_from_server(
    routes: &super::ServerRoutes,
    trusted_cas: &mut HashMap<PemSource, RuntimeTrustedCa>,
) -> Result<(), String> {
    for location in &routes.locations {
        let Some(source) = location.upstream_ssl_options.trusted_certificate.as_ref() else {
            continue;
        };
        if trusted_cas.contains_key(source) {
            continue;
        }

        trusted_cas.insert(source.clone(), load_runtime_trusted_ca(source)?);
    }

    Ok(())
}

fn read_pem_source(source: &PemSource, label: &str) -> Result<Vec<u8>, String> {
    match source {
        PemSource::Path(path) => std::fs::read(path)
            .map_err(|err| format!("failed to read {label} `{}`: {err}", path.display())),
        PemSource::InlinePem(pem) => Ok(pem.as_bytes().to_vec()),
    }
}

#[cfg(feature = "openssl")]
fn load_runtime_trusted_ca(source: &PemSource) -> Result<RuntimeTrustedCa, String> {
    let pem = read_pem_source(source, "proxy_ssl_trusted_certificate")?;
    let certs = X509::stack_from_pem(&pem)
        .map_err(|err| format!("failed to parse proxy_ssl_trusted_certificate: {err}"))?;
    if certs.is_empty() {
        return Err("proxy_ssl_trusted_certificate does not contain any certificates".into());
    }

    Ok(Arc::new(certs.into_boxed_slice()))
}

#[cfg(not(feature = "openssl"))]
fn load_runtime_trusted_ca(_source: &PemSource) -> Result<RuntimeTrustedCa, String> {
    Err("proxy_ssl_trusted_certificate requires build with feature `openssl`".into())
}

// Content-Length is only a fast path. Chunked and h2 bodies are enforced later
// in request_body_filter while the downstream body stream is consumed.
async fn restrict_client_max_body_size(
    session: &mut Session,
    ctx: &mut ProxyContext,
) -> PingoraResult<bool> {
    if content_length_limit_exceeded(
        session.get_header(http::header::CONTENT_LENGTH),
        ctx.client_max_body_size,
    ) == Some(true)
    {
        session.set_keepalive(None);
        session.respond_error(413).await?;
        return Ok(true);
    }

    Ok(false)
}

// Plugins can short-circuit the request path with a local response, but that
// response is still normalized through Pingora's typed response writer.
async fn write_local_response(session: &mut Session, response: LocalResponse) -> PingoraResult<()> {
    let mut header = ResponseHeader::build(response.status, None).map_err(|err| {
        pingora::Error::explain(
            pingora::ErrorType::InternalError,
            format!("failed to build plugin response: {err}"),
        )
    })?;
    for (name, value) in response.headers {
        header.insert_header(name, value).map_err(|err| {
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                format!("failed to insert plugin response header: {err}"),
            )
        })?;
    }

    if response.body.is_empty() {
        set_content_length(&mut header, 0)?;
        session.write_response_header(Box::new(header), true).await
    } else {
        set_content_length(&mut header, response.body.len().to_string())?;
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session.write_response_body(Some(response.body), true).await
    }
}

pub struct DynamicProxy {
    state: Arc<RuntimeState>,
}

impl DynamicProxy {
    pub fn new(state: Arc<RuntimeState>) -> Self {
        Self { state }
    }

    pub fn from_router(routing: CompiledRouter) -> Self {
        Self::new(Arc::new(RuntimeState::bootstrap(routing)))
    }

    pub fn runtime_state(&self) -> &Arc<RuntimeState> {
        &self.state
    }

    /// Retrieve routes for a specific key (lock-free).
    pub fn get_routes(&self, key: &ListenKey) -> Option<Arc<VirtualHostRoutes>> {
        let snapshot = self.state.snapshot();
        listener_routes(&snapshot.router, key)
            .cloned()
            .map(Arc::new)
    }

    /// Replace the entire routing table if listener topology stays compatible.
    pub fn update_routing(&self, new_router: CompiledRouter) -> ApplyResult {
        self.state
            .apply_snapshot(ConfigSnapshot::new("runtime-update", new_router))
    }
}

#[async_trait]
impl ProxyHttp for DynamicProxy {
    type CTX = ProxyContext;

    fn new_ctx(&self) -> Self::CTX {
        ProxyContext::default()
    }

    // Request plugins run in declaration order and may terminate the request
    // locally before any upstream peer is selected.
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<bool> {
        let snapshot = self.state.snapshot();
        session.set_keepalive(snapshot.router.http_options.downstream_keepalive_timeout);
        ctx.client_max_body_size = snapshot.router.http_options.client_max_body_size;
        ctx.received_body_bytes = 0;

        if restrict_client_max_body_size(session, ctx).await? {
            return Ok(true);
        }

        let Some((selected, host)) = select_runtime_route(&snapshot, session)? else {
            ctx.selected = None;
            return Ok(false);
        };

        let path = session.req_header().uri.path().to_string();
        let method = session.req_header().method.clone();
        let mut headers = RequestHeaderEditor {
            inner: session.downstream_session.req_header_mut(),
        };

        for plugin in selected.plugins.iter() {
            let flow = plugin
                .on_request(&mut RequestCtx {
                    state: &mut ctx.plugin_state,
                    path: &path,
                    host: host.as_deref(),
                    method: &method,
                    headers: &mut headers,
                })
                .await
                .map_err(|err| map_plugin_error("request_filter", err))?;
            if let PluginFlow::Respond(response) = flow {
                session.set_keepalive(None);
                write_local_response(session, response).await?;
                return Ok(true);
            }
        }

        ctx.selected = Some(selected);
        Ok(false)
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()> {
        // Classic WebSocket upgrades switch the downstream body stream into a
        // raw upgraded tunnel after the 101 response. That traffic must not be
        // counted against HTTP request body limits.
        if session.was_upgraded() {
            return Ok(());
        }

        update_received_body_bytes(
            &mut ctx.received_body_bytes,
            body.as_ref(),
            ctx.client_max_body_size,
        )
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()> {
        let Some(selected) = ctx.selected.as_ref() else {
            return Ok(());
        };

        let mut headers = RequestHeaderEditor {
            inner: upstream_request,
        };

        for plugin in selected.plugins.iter() {
            let flow = plugin
                .on_upstream_request(&mut UpstreamRequestCtx {
                    state: &mut ctx.plugin_state,
                    headers: &mut headers,
                })
                .await
                .map_err(|err| map_plugin_error("upstream_request_filter", err))?;
            respond_from_plugin_flow(flow, "upstream_request_filter")?;
        }

        Ok(())
    }

    // Response plugins run in reverse order so they behave like unwind-style
    // middleware around the upstream exchange.
    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()> {
        let Some(selected) = ctx.selected.as_ref() else {
            return Ok(());
        };

        let mut status = upstream_response.status;
        {
            let mut headers = ResponseHeaderEditor {
                inner: upstream_response,
            };

            for plugin in selected.plugins.iter().rev() {
                let flow = plugin
                    .on_response(&mut ResponseCtx {
                        state: &mut ctx.plugin_state,
                        status: &mut status,
                        headers: &mut headers,
                    })
                    .await
                    .map_err(|err| map_plugin_error("response_filter", err))?;
                respond_from_plugin_flow(flow, "response_filter")?;
            }
        }

        upstream_response.set_status(status).map_err(|err| {
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                format!("failed to update response status from plugin chain: {err}"),
            )
        })?;
        Ok(())
    }

    // Upstream selection is derived from the already resolved route; if the
    // request_filter path did not run, we resolve lazily here as a fallback.
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<Box<HttpPeer>> {
        let selected = if let Some(selected) = ctx.selected.as_ref().cloned() {
            selected
        } else {
            let snapshot = self.state.snapshot();
            let Some((selected, _host)) = select_runtime_route(&snapshot, session)? else {
                return Err(pingora::Error::explain(
                    pingora::ErrorType::HTTPStatus(404),
                    "no location matched",
                ));
            };
            ctx.selected = Some(selected.clone());
            selected
        };

        let mut peer = HttpPeer::new(
            (selected.peer.host.as_str(), selected.peer.port),
            selected.peer.tls,
            selected.peer.sni.clone(),
        );
        apply_upstream_timeouts(&mut peer, selected.upstream_timeouts);
        apply_upstream_http_protocol(&mut peer, selected.upstream_protocol);
        apply_upstream_ssl_options(
            &mut peer,
            &selected.upstream_ssl_options,
            selected.upstream_trusted_ca.as_ref(),
        );

        Ok(Box::new(peer))
    }
}
