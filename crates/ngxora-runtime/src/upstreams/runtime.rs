use super::compile::proxy_pass_sni;
use super::routing::{ResolvedLocation, listener_routes, resolve_route};
use super::types::{
    CompiledRouter, CompiledUpstreamGroup, CompiledUpstreamServer, ListenKey, RouteTarget,
    VirtualHostRoutes,
};
use crate::cache::{CacheBackend, CacheKey, build_cache_key, is_cacheable};
use crate::control::{ApplyResult, ConfigSnapshot, RuntimeSnapshot, RuntimeState};
use async_trait::async_trait;
use bytes::Bytes;
use futures::FutureExt;
use ngxora_compile::ir::{
    CacheConfig, PemSource, Switch, UpstreamHttpProtocol, UpstreamSelectionPolicy,
    UpstreamSslOptions, UpstreamTimeouts,
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

#[derive(Debug, Clone)]
enum SelectedTarget {
    Upstream(SelectedPeer),
    Return { status: u16, location: String },
}

#[derive(Clone)]
pub(crate) struct SelectedRoute {
    route_id: u64,
    target: SelectedTarget,
    upstream_timeouts: UpstreamTimeouts,
    upstream_protocol: Option<UpstreamHttpProtocol>,
    upstream_ssl_options: UpstreamSslOptions,
    upstream_trusted_ca: Option<RuntimeTrustedCa>,
    plugins: ngxora_plugin_api::PluginChain,
    cache: Option<CacheConfig>,
}

impl SelectedRoute {
    pub(crate) fn route_id(&self) -> u64 {
        self.route_id
    }
}

fn cache_store_allowed(cfg: &CacheConfig, threshold_reached: bool) -> bool {
    cfg.min_uses.unwrap_or(1) <= 1 || threshold_reached
}

#[derive(Default)]
pub struct ProxyContext {
    pub(crate) selected: Option<SelectedRoute>,
    pub(crate) plugin_state: PluginState,
    pub(crate) client_max_body_size: Option<u64>,
    pub(crate) received_body_bytes: u64,
    pub(crate) cache_key: Option<CacheKey>,
    pub(crate) cache_store_allowed: bool,
    pub(crate) cache_status: Option<http::StatusCode>,
    pub(crate) cache_headers: Option<http::HeaderMap>,
    pub(crate) response_body_buf: bytes::Bytes,
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
    fn from_resolved(
        snapshot: &RuntimeSnapshot,
        resolved: &ResolvedLocation<'_>,
    ) -> PingoraResult<Self> {
        let target = match &resolved.location.target {
            RouteTarget::Return { status, location } => {
                return Ok(Self {
                    route_id: resolved.location.route_id,
                    target: SelectedTarget::Return {
                        status: *status,
                        location: location.clone(),
                    },
                    upstream_timeouts: UpstreamTimeouts::default(),
                    upstream_protocol: None,
                    upstream_ssl_options: UpstreamSslOptions::default(),
                    upstream_trusted_ca: None,
                    plugins: snapshot.plugin_chain(resolved.location.route_id),
                    cache: resolved.location.cache.clone(),
                });
            }
            RouteTarget::ProxyPass {
                host,
                port,
                tls,
                sni,
            } => SelectedTarget::Upstream(SelectedPeer {
                host: host.clone(),
                port: *port,
                tls: *tls,
                sni: sni.clone(),
            }),
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

                SelectedTarget::Upstream(SelectedPeer {
                    sni: proxy_pass_sni(&backend.host, *tls),
                    host: backend.host,
                    port: backend.port,
                    tls: *tls,
                })
            }
        };

        Ok(Self {
            route_id: resolved.location.route_id,
            target,
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
            cache: resolved.location.cache.clone(),
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

fn request_client_ip(session: &Session) -> Option<std::net::IpAddr> {
    session
        .downstream_session
        .client_addr()
        .and_then(|addr| addr.as_inet())
        .map(|addr| addr.ip())
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

async fn write_cached_response(
    session: &mut Session,
    cached: &crate::cache::CachedResponse,
) -> PingoraResult<()> {
    let mut header = ResponseHeader::build(cached.status, None).map_err(|err| {
        pingora::Error::explain(
            pingora::ErrorType::InternalError,
            format!("failed to build cached response header: {err}"),
        )
    })?;
    for (name, value) in cached.headers.iter() {
        header
            .insert_header(name.clone(), value.clone())
            .map_err(|err| {
                pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    format!("failed to insert cached header `{name}`: {err}"),
                )
            })?;
    }
    if cached.body.is_empty() {
        session.write_response_header(Box::new(header), true).await
    } else {
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(cached.body.clone()), true)
            .await
    }
}

pub struct DynamicProxy {
    state: Arc<RuntimeState>,
    cache_backend: CacheBackend,
}

impl DynamicProxy {
    pub fn new(state: Arc<RuntimeState>) -> Self {
        Self {
            state,
            cache_backend: CacheBackend::new(50 * 1024 * 1024), // 50MB default
        }
    }

    pub fn new_with_cache(state: Arc<RuntimeState>, cache_backend: CacheBackend) -> Self {
        Self {
            state,
            cache_backend,
        }
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

        // Apply global proxy_cache_max_size from config (once per snapshot
        // change — set_default_max_size is a relaxed atomic store).
        if let Some(global_size) = snapshot.router.http_options.proxy_cache_max_size {
            self.cache_backend.set_default_max_size(global_size);
        }

        if restrict_client_max_body_size(session, ctx).await? {
            return Ok(true);
        }

        let Some((selected, host)) = select_runtime_route(&snapshot, session)? else {
            ctx.selected = None;
            return Ok(false);
        };

        // ── Cache lookup ──
        let full_uri = session.req_header().uri.to_string();
        if let Some(cache_cfg) = &selected.cache {
            let cache_key = build_cache_key(
                &session.req_header().method,
                &full_uri,
                selected.route_id(),
                cache_cfg,
            );
            if let Some(cached) = self.cache_backend.get(&cache_key, cache_cfg).await {
                write_cached_response(session, &cached).await?;
                return Ok(true);
            }
            ctx.cache_store_allowed = self.cache_backend.record_miss(&cache_key, cache_cfg);
            ctx.cache_key = Some(cache_key);
        }

        let path = session.req_header().uri.path().to_string();
        let method = session.req_header().method.clone();
        let client_ip = request_client_ip(session);
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
                    client_ip,
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

        // Handle return/redirect targets
        if let SelectedTarget::Return { status, location } = &selected.target {
            let status_code = http::StatusCode::from_u16(*status).map_err(|_| {
                pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    format!("invalid redirect status code: {status}"),
                )
            })?;

            let mut response = LocalResponse::new(status_code, "");
            response.headers.push((
                http::header::LOCATION,
                http::HeaderValue::from_str(location).map_err(|_| {
                    pingora::Error::explain(
                        pingora::ErrorType::InternalError,
                        format!("invalid redirect location: {location}"),
                    )
                })?,
            ));

            session.set_keepalive(None);
            write_local_response(session, response).await?;
            return Ok(true);
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

    /// Serve a stale cached response when upstream returns an error.
    ///
    /// Only activates when the location has `proxy_cache_stale_if_error`
    /// configured and a cached entry exists (TTL is ignored for stale).
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        _error: &pingora::Error,
        ctx: &mut Self::CTX,
    ) -> pingora_proxy::FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        let Some(selected) = ctx.selected.as_ref() else {
            return pingora_proxy::FailToProxy {
                can_reuse_downstream: false,
                error_code: 502,
            };
        };
        let Some(cache_cfg) = selected.cache.as_ref() else {
            return pingora_proxy::FailToProxy {
                can_reuse_downstream: false,
                error_code: 502,
            };
        };
        // stale_if_error must be explicitly configured
        if cache_cfg.stale_if_error.is_none() {
            return pingora_proxy::FailToProxy {
                can_reuse_downstream: false,
                error_code: 502,
            };
        }
        let Some(cache_key) = &ctx.cache_key else {
            return pingora_proxy::FailToProxy {
                can_reuse_downstream: false,
                error_code: 502,
            };
        };

        let Some(mut cached) = self.cache_backend.get_stale(cache_key, cache_cfg).await else {
            return pingora_proxy::FailToProxy {
                can_reuse_downstream: false,
                error_code: 502,
            };
        };

        cached.headers.insert(
            http::HeaderName::from_static("x-cache"),
            http::HeaderValue::from_static("STALE"),
        );

        if write_cached_response(session, &cached).await.is_err() {
            return pingora_proxy::FailToProxy {
                can_reuse_downstream: false,
                error_code: 502,
            };
        }

        pingora_proxy::FailToProxy {
            can_reuse_downstream: true,
            error_code: cached.status.as_u16(),
        }
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

        // Cacheability must be evaluated against the final response that the
        // client will actually receive after plugins mutate headers/status.
        if let (Some(_cache_key), Some(cache_cfg)) = (&ctx.cache_key, selected.cache.as_ref()) {
            if cache_store_allowed(cache_cfg, ctx.cache_store_allowed)
                && is_cacheable(status, &upstream_response.headers, cache_cfg)
            {
                ctx.cache_status = Some(status);
                ctx.cache_headers = Some(upstream_response.headers.clone());
            }
        }

        Ok(())
    }

    /// Collect upstream response body chunks for later caching in `logging`.
    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<Option<Duration>> {
        if ctx.cache_headers.is_none() {
            return Ok(None);
        }

        if let Some(chunk) = body.as_ref() {
            let buf = std::mem::take(&mut ctx.response_body_buf);
            let mut combined = bytes::BytesMut::with_capacity(buf.len() + chunk.len());
            combined.extend_from_slice(&buf);
            combined.extend_from_slice(chunk);
            ctx.response_body_buf = combined.freeze();
        }
        Ok(None)
    }

    /// Store cacheable responses when the request completes.
    async fn logging(
        &self,
        _session: &mut Session,
        e: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        if e.is_some() {
            ctx.cache_headers = None;
            ctx.cache_status = None;
            ctx.response_body_buf = Bytes::new();
            return;
        }

        if let (Some(cache_key), Some(cache_cfg)) = (
            &ctx.cache_key,
            ctx.selected.as_ref().and_then(|s| s.cache.as_ref()),
        ) {
            if !cache_store_allowed(cache_cfg, ctx.cache_store_allowed) {
                ctx.cache_headers = None;
                ctx.cache_status = None;
                ctx.response_body_buf = Bytes::new();
                return;
            }

            if let (Some(status), Some(headers)) = (ctx.cache_status, ctx.cache_headers.take()) {
                let body = std::mem::take(&mut ctx.response_body_buf);
                self.cache_backend
                    .put(
                        cache_key.clone(),
                        crate::cache::CachedResponse {
                            status,
                            headers,
                            body,
                            created_at: std::time::Instant::now(),
                        },
                        cache_cfg,
                    )
                    .await;
            }
        }
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

        let peer = match &selected.target {
            SelectedTarget::Upstream(peer) => peer,
            SelectedTarget::Return { .. } => {
                return Err(pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    "upstream_peer called on a return target — request_filter should have short-circuited",
                ));
            }
        };

        let mut http_peer =
            HttpPeer::new((peer.host.as_str(), peer.port), peer.tls, peer.sni.clone());
        apply_upstream_timeouts(&mut http_peer, selected.upstream_timeouts);
        apply_upstream_http_protocol(&mut http_peer, selected.upstream_protocol);
        apply_upstream_ssl_options(
            &mut http_peer,
            &selected.upstream_ssl_options,
            selected.upstream_trusted_ca.as_ref(),
        );

        Ok(Box::new(http_peer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;
    use ngxora_plugin_api::{HttpPlugin, PluginFlow, async_trait, empty_plugin_chain};
    use std::sync::Arc;
    use tokio::io::{AsyncWriteExt, duplex};

    async fn test_session() -> Session {
        let (mut client, server) = duplex(1024);
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("write request");

        let mut session = Session::new_h1(Box::new(server));
        session.read_request().await.expect("read request");
        session
    }

    fn cached_route(cache: CacheConfig, plugins: ngxora_plugin_api::PluginChain) -> SelectedRoute {
        SelectedRoute {
            route_id: 1,
            target: SelectedTarget::Upstream(SelectedPeer {
                host: "127.0.0.1".into(),
                port: 8080,
                tls: false,
                sni: String::new(),
            }),
            upstream_timeouts: UpstreamTimeouts::default(),
            upstream_protocol: None,
            upstream_ssl_options: UpstreamSslOptions::default(),
            upstream_trusted_ca: None,
            plugins,
            cache: Some(cache),
        }
    }

    struct StatusRewritePlugin {
        status: StatusCode,
    }

    #[async_trait]
    impl HttpPlugin for StatusRewritePlugin {
        fn name(&self) -> &'static str {
            "status-rewrite"
        }

        async fn on_response(&self, ctx: &mut ResponseCtx<'_>) -> Result<PluginFlow, PluginError> {
            *ctx.status = self.status;
            Ok(PluginFlow::Continue)
        }
    }

    #[tokio::test]
    async fn response_body_filter_preserves_downstream_body() {
        let proxy = DynamicProxy::from_router(CompiledRouter::default());
        let mut session = test_session().await;
        let mut ctx = ProxyContext {
            cache_headers: Some(http::HeaderMap::new()),
            ..Default::default()
        };
        let original = Bytes::from_static(b"hello");
        let mut body = Some(original.clone());

        ProxyHttp::response_body_filter(&proxy, &mut session, &mut body, false, &mut ctx)
            .expect("body filter succeeds");

        assert_eq!(body, Some(original.clone()));
        assert_eq!(ctx.response_body_buf, original);
    }

    #[tokio::test]
    async fn response_filter_uses_final_plugin_status_for_cacheability() {
        let proxy = DynamicProxy::from_router(CompiledRouter::default());
        let mut session = test_session().await;
        let cache_cfg = CacheConfig {
            valid_statuses: vec![302],
            ..CacheConfig::default()
        };
        let plugins: ngxora_plugin_api::PluginChain = vec![Arc::new(StatusRewritePlugin {
            status: StatusCode::FOUND,
        }) as Arc<dyn HttpPlugin>]
        .into();
        let mut ctx = ProxyContext {
            selected: Some(cached_route(cache_cfg.clone(), plugins)),
            cache_key: Some(CacheKey {
                route_id: 1,
                method: "GET".into(),
                uri: "/".into(),
            }),
            ..Default::default()
        };
        let mut upstream_response =
            ResponseHeader::build(StatusCode::OK, None).expect("build response");

        ProxyHttp::response_filter(&proxy, &mut session, &mut upstream_response, &mut ctx)
            .await
            .expect("response filter succeeds");

        assert_eq!(upstream_response.status, StatusCode::FOUND);
        assert_eq!(ctx.cache_status, Some(StatusCode::FOUND));
        assert!(ctx.cache_headers.is_some());
    }

    #[tokio::test]
    async fn logging_skips_cache_write_after_error() {
        let cache_backend = CacheBackend::new(10 * 1024 * 1024);
        let proxy = DynamicProxy::new_with_cache(
            Arc::new(RuntimeState::bootstrap(CompiledRouter::default())),
            cache_backend,
        );
        let mut session = test_session().await;
        let cache_cfg = CacheConfig::default();
        let key = CacheKey {
            route_id: 1,
            method: "GET".into(),
            uri: "/partial".into(),
        };
        let mut ctx = ProxyContext {
            selected: Some(cached_route(cache_cfg.clone(), empty_plugin_chain())),
            cache_key: Some(key.clone()),
            cache_status: Some(StatusCode::OK),
            cache_headers: Some(http::HeaderMap::new()),
            response_body_buf: Bytes::from_static(b"partial"),
            ..Default::default()
        };
        let err = pingora::Error::explain(pingora::ErrorType::InternalError, "boom");

        ProxyHttp::logging(&proxy, &mut session, Some(err.as_ref()), &mut ctx).await;

        assert!(proxy.cache_backend.get(&key, &cache_cfg).await.is_none());
        assert_eq!(proxy.cache_backend.total_entries(), 0);
        assert!(ctx.response_body_buf.is_empty());
    }

    #[tokio::test]
    async fn logging_caches_empty_cacheable_response() {
        let cache_backend = CacheBackend::new(10 * 1024 * 1024);
        let proxy = DynamicProxy::new_with_cache(
            Arc::new(RuntimeState::bootstrap(CompiledRouter::default())),
            cache_backend,
        );
        let mut session = test_session().await;
        let cache_cfg = CacheConfig {
            valid_statuses: vec![301],
            ..CacheConfig::default()
        };
        let key = CacheKey {
            route_id: 1,
            method: "GET".into(),
            uri: "/redirect".into(),
        };
        let mut ctx = ProxyContext {
            selected: Some(cached_route(cache_cfg.clone(), empty_plugin_chain())),
            cache_key: Some(key.clone()),
            ..Default::default()
        };
        let mut upstream_response =
            ResponseHeader::build(StatusCode::MOVED_PERMANENTLY, None).expect("build response");

        ProxyHttp::response_filter(&proxy, &mut session, &mut upstream_response, &mut ctx)
            .await
            .expect("response filter succeeds");
        ProxyHttp::logging(&proxy, &mut session, None, &mut ctx).await;

        let cached = proxy
            .cache_backend
            .get(&key, &cache_cfg)
            .await
            .expect("empty redirect should be cached");
        assert_eq!(cached.status, StatusCode::MOVED_PERMANENTLY);
        assert!(cached.body.is_empty());
    }

    #[tokio::test]
    async fn logging_skips_cache_write_until_min_uses_is_reached() {
        let cache_backend = CacheBackend::new(10 * 1024 * 1024);
        let proxy = DynamicProxy::new_with_cache(
            Arc::new(RuntimeState::bootstrap(CompiledRouter::default())),
            cache_backend,
        );
        let mut session = test_session().await;
        let cache_cfg = CacheConfig {
            min_uses: Some(2),
            ..CacheConfig::default()
        };
        let key = CacheKey {
            route_id: 1,
            method: "GET".into(),
            uri: "/warming".into(),
        };

        let mut first_ctx = ProxyContext {
            selected: Some(cached_route(cache_cfg.clone(), empty_plugin_chain())),
            cache_key: Some(key.clone()),
            cache_store_allowed: false,
            cache_status: Some(StatusCode::OK),
            cache_headers: Some(http::HeaderMap::new()),
            response_body_buf: Bytes::from_static(b"first"),
            ..Default::default()
        };

        ProxyHttp::logging(&proxy, &mut session, None, &mut first_ctx).await;
        assert!(proxy.cache_backend.get(&key, &cache_cfg).await.is_none());

        let mut second_ctx = ProxyContext {
            selected: Some(cached_route(cache_cfg.clone(), empty_plugin_chain())),
            cache_key: Some(key.clone()),
            cache_store_allowed: true,
            cache_status: Some(StatusCode::OK),
            cache_headers: Some(http::HeaderMap::new()),
            response_body_buf: Bytes::from_static(b"second"),
            ..Default::default()
        };

        ProxyHttp::logging(&proxy, &mut session, None, &mut second_ctx).await;

        let cached = proxy
            .cache_backend
            .get(&key, &cache_cfg)
            .await
            .expect("response should be cached after min_uses is reached");
        assert_eq!(cached.body, Bytes::from_static(b"second"));
    }
}
