use crate::control::{ApplyResult, ConfigSnapshot, RuntimeSnapshot, RuntimeState};
use crate::server::DownstreamTlsInfo;
use async_trait::async_trait;
use bytes::Bytes;
use ngxora_compile::ir::{
    DownstreamTlsOptions, Http, KeepaliveTimeout, Listen, Location, LocationDirective,
    LocationMatcher, PemSource, Server, TlsIdentity, TlsProtocolBounds, TlsVerifyClient,
    UpstreamTimeouts,
};
use ngxora_plugin_api::{
    HeaderMapMut, LocalResponse, PluginError, PluginFlow, PluginSpec, PluginState, RequestCtx,
    ResponseCtx, UpstreamRequestCtx,
};
use pingora::Result;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::upstreams::peer::HttpPeer;
use pingora_proxy::{ProxyHttp, Session};
use regex::{Regex, RegexBuilder};
use std::collections::HashMap;
use std::fmt::Display;
use std::net::IpAddr;
use std::sync::Arc;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct ListenKey {
    pub addr: IpAddr,
    pub port: u16,
    pub ssl: bool,
}

impl From<&Listen> for ListenKey {
    fn from(value: &Listen) -> Self {
        Self {
            addr: value.addr,
            port: value.port,
            ssl: value.ssl,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum RouteTarget {
    ProxyPass {
        host: String,
        port: u16,
        tls: bool,
        sni: String,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CompiledMatcher {
    Prefix(String),
    Exact(String),
    Regex(CompiledRegex),
    PreferPrefix(String),
    Named(String),
}

// Regex locations are compiled once during snapshot build so request matching
// stays cheap and invalid patterns are rejected before they hit the dataplane.
#[derive(Debug, Clone)]
pub struct CompiledRegex {
    pub case_insensitive: bool,
    pub pattern: String,
    regex: Regex,
}

impl PartialEq for CompiledRegex {
    fn eq(&self, other: &Self) -> bool {
        self.case_insensitive == other.case_insensitive && self.pattern == other.pattern
    }
}

impl Eq for CompiledRegex {}

impl CompiledRegex {
    fn new(pattern: String, case_insensitive: bool) -> Result<Self, String> {
        let regex = RegexBuilder::new(&pattern)
            .case_insensitive(case_insensitive)
            .build()
            .map_err(|err| format!("invalid location regex `{pattern}`: {err}"))?;

        Ok(Self {
            case_insensitive,
            pattern,
            regex,
        })
    }

    fn is_match(&self, path: &str) -> bool {
        self.regex.is_match(path)
    }
}

impl TryFrom<&LocationMatcher> for CompiledMatcher {
    type Error = String;

    fn try_from(value: &LocationMatcher) -> Result<Self, Self::Error> {
        match value {
            LocationMatcher::Prefix(path) => Ok(Self::Prefix(path.clone())),
            LocationMatcher::Exact(path) => Ok(Self::Exact(path.clone())),
            LocationMatcher::Regex {
                case_insensitive,
                pattern,
            } => Ok(Self::Regex(CompiledRegex::new(
                pattern.clone(),
                *case_insensitive,
            )?)),
            LocationMatcher::PreferPrefix(path) => Ok(Self::PreferPrefix(path.clone())),
            LocationMatcher::Named(name) => Ok(Self::Named(name.clone())),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CompiledLocation {
    pub route_id: u64,
    pub matcher: CompiledMatcher,
    pub target: RouteTarget,
    pub upstream_timeouts: UpstreamTimeouts,
    pub plugins: Vec<PluginSpec>,
}

impl CompiledLocation {
    pub fn with_plugins(mut self, plugins: Vec<PluginSpec>) -> Self {
        self.plugins = plugins;
        self
    }
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct ServerRoutes {
    pub locations: Vec<CompiledLocation>,
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct VirtualHostRoutes {
    pub named: HashMap<String, ServerRoutes>,
    pub default: Option<ServerRoutes>,
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct ListenerProtocolConfig {
    pub http2: bool,
    pub http2_only: bool,
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct ListenerTlsSettings {
    pub protocols: Option<TlsProtocolBounds>,
    pub verify_client: TlsVerifyClient,
    pub client_certificate: Option<PemSource>,
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct ListenerTlsConfig {
    pub named: HashMap<String, TlsIdentity>,
    pub default: Option<TlsIdentity>,
    pub settings: ListenerTlsSettings,
}

#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct HttpRuntimeOptions {
    pub downstream_keepalive_timeout: Option<u64>,
    pub keepalive_requests: Option<u32>,
    pub client_max_body_size: Option<u64>,
    pub tcp_nodelay: bool,
    pub allow_connect_method_proxying: bool,
    pub h2c: bool,
}

// CompiledRouter stores the Ir representation in an optimized form.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct CompiledRouter {
    pub listeners: HashMap<ListenKey, VirtualHostRoutes>,
    pub listener_protocols: HashMap<ListenKey, ListenerProtocolConfig>,
    pub listener_tls: HashMap<ListenKey, ListenerTlsConfig>,
    pub http_options: HttpRuntimeOptions,
}

// Alias to keep compatibility with the misspelled name used in discussion.
pub type CompliedRouter = CompiledRouter;

impl CompiledRouter {
    pub fn from_http(http: &Http) -> Result<Self, String> {
        let mut router = Self {
            http_options: HttpRuntimeOptions {
                downstream_keepalive_timeout: downstream_keepalive_timeout_secs(
                    &http.keepalive_timeout,
                ),
                keepalive_requests: http.keepalive_requests,
                client_max_body_size: http.client_max_body_size,
                tcp_nodelay: matches!(http.tcp_nodelay, ngxora_compile::ir::Switch::On),
                allow_connect_method_proxying: matches!(
                    http.allow_connect_method_proxying,
                    ngxora_compile::ir::Switch::On
                ),
                h2c: matches!(http.h2c, ngxora_compile::ir::Switch::On),
            },
            ..Self::default()
        };
        let mut next_route_id = 1;

        for server in &http.servers {
            router.add_server(server, &mut next_route_id)?;
        }

        Ok(router)
    }

    fn add_server(&mut self, server: &Server, next_route_id: &mut u64) -> Result<(), String> {
        let routes = ServerRoutes {
            locations: compile_locations(&server.locations, next_route_id)?,
        };

        for listen in &server.listens {
            let listen_key = ListenKey::from(listen);
            self.merge_listener_protocols(&listen_key, listen)?;
            let listener = self.listeners.entry(listen_key.clone()).or_default();

            for name in &server.server_names {
                listener
                    .named
                    .insert(name.to_ascii_lowercase(), routes.clone());
            }

            if listen.default_server
                || (server.server_names.is_empty() && listener.default.is_none())
            {
                listener.default = Some(routes.clone());
            }

            if listen.ssl {
                self.merge_listener_tls_settings(&listen_key, &server.tls_options)?;
                let listener_tls =
                    self.listener_tls
                        .entry(listen_key)
                        .or_insert_with(|| ListenerTlsConfig {
                            settings: ListenerTlsSettings::from(&server.tls_options),
                            ..ListenerTlsConfig::default()
                        });

                if let Some(tls) = server.tls.as_ref() {
                    for name in &server.server_names {
                        listener_tls
                            .named
                            .insert(name.to_ascii_lowercase(), tls.clone());
                    }

                    if listen.default_server
                        || listener_tls.default.is_none()
                        || server.server_names.is_empty()
                    {
                        listener_tls.default = Some(tls.clone());
                    }
                }
            }
        }

        Ok(())
    }

    fn merge_listener_protocols(&mut self, key: &ListenKey, listen: &Listen) -> Result<(), String> {
        let config = ListenerProtocolConfig {
            http2: listen.http2,
            http2_only: listen.http2_only,
        };
        if let Some(current) = self.listener_protocols.get(key) {
            if current != &config {
                return Err(format!(
                    "listener {} has conflicting protocol settings across server blocks",
                    listen_key_addr(key)
                ));
            }
            return Ok(());
        }

        self.listener_protocols.insert(key.clone(), config);
        Ok(())
    }

    fn merge_listener_tls_settings(
        &mut self,
        key: &ListenKey,
        options: &DownstreamTlsOptions,
    ) -> Result<(), String> {
        let settings = ListenerTlsSettings::from(options);
        if let Some(current) = self.listener_tls.get(key).map(|tls| &tls.settings) {
            if current != &settings {
                return Err(format!(
                    "listener {} has conflicting TLS settings across server blocks",
                    listen_key_addr(key)
                ));
            }
            return Ok(());
        }

        self.listener_tls.insert(
            key.clone(),
            ListenerTlsConfig {
                settings,
                ..ListenerTlsConfig::default()
            },
        );
        Ok(())
    }
}

impl From<&DownstreamTlsOptions> for ListenerTlsSettings {
    fn from(value: &DownstreamTlsOptions) -> Self {
        Self {
            protocols: value.protocols,
            verify_client: value.verify_client,
            client_certificate: value.client_certificate.clone(),
        }
    }
}

fn listen_key_addr(key: &ListenKey) -> String {
    std::net::SocketAddr::new(key.addr, key.port).to_string()
}

fn proxy_pass_sni(host: &str, tls: bool) -> String {
    if tls && host.parse::<IpAddr>().is_err() {
        host.to_string()
    } else {
        String::new()
    }
}

fn set_timeout_once(
    slot: &mut Option<std::time::Duration>,
    value: std::time::Duration,
    directive: &str,
) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("{directive} is duplicated in the same location"));
    }

    Ok(())
}

fn route_target_from_directive(directive: &LocationDirective) -> Option<RouteTarget> {
    match directive {
        LocationDirective::ProxyPass(url) => {
            let host = url.host_str()?.to_string();
            let port = url.port_or_known_default()?;
            let tls = match url.scheme() {
                "http" => false,
                "https" => true,
                _ => return None,
            };

            Some(RouteTarget::ProxyPass {
                sni: proxy_pass_sni(&host, tls),
                host,
                port,
                tls,
            })
        }
        _ => None,
    }
}

fn route_target(location: &Location) -> Option<RouteTarget> {
    location
        .directives
        .iter()
        .find_map(route_target_from_directive)
}

fn compile_upstream_timeouts(location: &Location) -> Result<UpstreamTimeouts, String> {
    let mut timeouts = UpstreamTimeouts::default();

    for directive in &location.directives {
        match directive {
            LocationDirective::ProxyConnectTimeout(value) => {
                set_timeout_once(&mut timeouts.connect, *value, "proxy_connect_timeout")?;
            }
            LocationDirective::ProxyReadTimeout(value) => {
                set_timeout_once(&mut timeouts.read, *value, "proxy_read_timeout")?;
            }
            LocationDirective::ProxyWriteTimeout(value) => {
                set_timeout_once(&mut timeouts.write, *value, "proxy_write_timeout")?;
            }
            _ => {}
        }
    }

    Ok(timeouts)
}

fn compile_location(
    location: &Location,
    next_route_id: &mut u64,
) -> Result<Option<CompiledLocation>, String> {
    let Some(target) = route_target(location) else {
        return Ok(None);
    };

    let compiled = CompiledLocation {
        route_id: *next_route_id,
        matcher: CompiledMatcher::try_from(&location.matcher)?,
        target,
        upstream_timeouts: compile_upstream_timeouts(location)?,
        plugins: location.plugins.clone(),
    };
    *next_route_id += 1;
    Ok(Some(compiled))
}

// Only locations with an actionable upstream target are kept. Regex validation
// also happens here, so broken snapshots fail before they are applied.
fn compile_locations(
    locations: &[Location],
    next_route_id: &mut u64,
) -> Result<Vec<CompiledLocation>, String> {
    locations
        .iter()
        .map(|location| compile_location(location, next_route_id))
        .filter_map(|result| match result {
            Ok(Some(location)) => Some(Ok(location)),
            Ok(None) => None,
            Err(err) => Some(Err(err)),
        })
        .collect()
}

fn downstream_keepalive_timeout_secs(timeout: &KeepaliveTimeout) -> Option<u64> {
    match timeout {
        KeepaliveTimeout::Off => None,
        KeepaliveTimeout::Timeout { idle, .. } => {
            let millis = idle.as_millis();
            if millis == 0 {
                None
            } else {
                let secs = millis.div_ceil(1_000);
                u64::try_from(secs).ok()
            }
        }
    }
}

// Match order mirrors nginx semantics:
// exact > longest ^~ prefix > first matching regex > longest plain prefix.
fn select_route_target<'a>(routes: &'a ServerRoutes, path: &str) -> Option<&'a CompiledLocation> {
    let mut best_prefix: Option<(&CompiledLocation, usize)> = None;
    let mut best_prefer_prefix: Option<(&CompiledLocation, usize)> = None;

    for location in &routes.locations {
        match &location.matcher {
            CompiledMatcher::Exact(p) if path == p => return Some(location),
            CompiledMatcher::Prefix(p) if path.starts_with(p) => {
                if best_prefix.is_none_or(|(_, len)| p.len() > len) {
                    best_prefix = Some((location, p.len()));
                }
            }
            CompiledMatcher::PreferPrefix(p) if path.starts_with(p) => {
                if best_prefer_prefix.is_none_or(|(_, len)| p.len() > len) {
                    best_prefer_prefix = Some((location, p.len()));
                }
            }
            _ => {}
        }
    }

    if let Some((location, _)) = best_prefer_prefix {
        return Some(location);
    }

    for location in &routes.locations {
        match &location.matcher {
            CompiledMatcher::Regex(regex) if regex.is_match(path) => {
                return Some(location);
            }
            _ => {}
        }
    }

    best_prefix.map(|(location, _)| location)
}

fn normalize_authority_host(value: &str) -> String {
    value
        .split(':')
        .next()
        .unwrap_or(value)
        .trim_end_matches('.')
        .to_ascii_lowercase()
}

// Normalize the HTTP authority used for vhost routing and reject invalid
// header encodings up front.
fn request_host(session: &Session) -> Result<Option<String>> {
    let Some(host) = session.get_header("host") else {
        return Ok(None);
    };

    let host = host.to_str().map_err(|_| {
        pingora::Error::explain(
            pingora::ErrorType::HTTPStatus(400),
            "invalid host header encoding",
        )
    })?;

    Ok(Some(normalize_authority_host(host)))
}

fn downstream_sni(session: &Session) -> Option<String> {
    session
        .digest()
        .and_then(|digest| digest.ssl_digest.as_ref())
        .and_then(|ssl| ssl.extension.get::<DownstreamTlsInfo>())
        .and_then(|info| info.sni.clone())
}

fn validate_sni_host_consistency(host: Option<&str>, sni: Option<&str>) -> Result<()> {
    if let (Some(host), Some(sni)) = (host, sni) {
        if host != sni {
            return Err(pingora::Error::explain(
                pingora::ErrorType::HTTPStatus(421),
                format!("tls sni `{sni}` does not match http host `{host}`"),
            ));
        }
    }

    Ok(())
}

fn request_is_tls(session: &Session) -> bool {
    session
        .digest()
        .and_then(|digest| digest.ssl_digest.as_ref())
        .is_some()
}

// Listener lookup is based on the accepted downstream socket, not request
// headers, so shared :80/:443 sockets stay isolated correctly.
fn session_listen_key(session: &Session) -> Result<ListenKey> {
    let server_addr = session.server_addr().ok_or_else(|| {
        pingora::Error::explain(
            pingora::ErrorType::InternalError,
            "missing downstream server addr",
        )
    })?;

    let inet = server_addr.as_inet().ok_or_else(|| {
        pingora::Error::explain(
            pingora::ErrorType::InternalError,
            "downstream server addr is not inet (likely UDS)",
        )
    })?;

    Ok(ListenKey {
        addr: inet.ip(),
        port: inet.port(),
        ssl: request_is_tls(session),
    })
}

fn select_server_routes<'a>(
    vhosts: &'a VirtualHostRoutes,
    host: Option<&str>,
) -> Option<&'a ServerRoutes> {
    host.and_then(|value| vhosts.named.get(value))
        .or(vhosts.default.as_ref())
}

#[derive(Debug)]
struct ResolvedLocation<'a> {
    location: &'a CompiledLocation,
    host: Option<String>,
}

#[derive(Clone)]
struct SelectedRoute {
    target: RouteTarget,
    upstream_timeouts: UpstreamTimeouts,
    plugins: ngxora_plugin_api::PluginChain,
}

#[derive(Default)]
pub struct ProxyContext {
    selected: Option<SelectedRoute>,
    plugin_state: PluginState,
    client_max_body_size: Option<u64>,
    received_body_bytes: u64,
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

// Route resolution first pins the accepted listener, then enforces TLS
// authority consistency, and only after that chooses the vhost + location.
fn resolve_route<'a>(
    router: &'a CompiledRouter,
    session: &Session,
) -> Result<Option<ResolvedLocation<'a>>> {
    let listen_key = session_listen_key(session)?;

    let Some(vhosts) = router.listeners.get(&listen_key) else {
        return Ok(None);
    };

    let host = request_host(session)?;
    let sni = listen_key.ssl.then(|| downstream_sni(session)).flatten();
    validate_sni_host_consistency(host.as_deref(), sni.as_deref())?;

    let routing_host = host.clone().or(sni);

    let Some(server_routes) = select_server_routes(vhosts, routing_host.as_deref()) else {
        return Ok(None);
    };

    let path = session.req_header().uri.path();
    let Some(location) = select_route_target(server_routes, path) else {
        return Ok(None);
    };

    Ok(Some(ResolvedLocation { location, host }))
}

impl SelectedRoute {
    fn from_resolved(snapshot: &RuntimeSnapshot, resolved: &ResolvedLocation<'_>) -> Self {
        Self {
            target: resolved.location.target.clone(),
            upstream_timeouts: resolved.location.upstream_timeouts,
            plugins: snapshot.plugin_chain(resolved.location.route_id),
        }
    }
}

fn select_runtime_route(
    snapshot: &RuntimeSnapshot,
    session: &Session,
) -> Result<Option<(SelectedRoute, Option<String>)>> {
    let Some(resolved) = resolve_route(&snapshot.router, session)? else {
        return Ok(None);
    };

    Ok(Some((
        SelectedRoute::from_resolved(snapshot, &resolved),
        resolved.host,
    )))
}

fn respond_from_plugin_flow(flow: PluginFlow, stage: &str) -> Result<()> {
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

fn set_content_length(header: &mut ResponseHeader, value: impl ToString) -> Result<()> {
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

fn normalized_peer_timeout(timeout: Option<std::time::Duration>) -> Option<std::time::Duration> {
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

fn content_length_limit_exceeded(
    header: Option<&http::HeaderValue>,
    limit: Option<u64>,
) -> Option<bool> {
    let limit = limit?;
    let header = header?;
    let size = header.to_str().ok()?.parse::<u64>().ok()?;
    Some(size > limit)
}

fn update_received_body_bytes(
    received: &mut u64,
    body: Option<&Bytes>,
    limit: Option<u64>,
) -> Result<()> {
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
fn apply_upstream_timeouts(peer: &mut HttpPeer, timeouts: UpstreamTimeouts) {
    peer.options.connection_timeout = normalized_peer_timeout(timeouts.connect);
    peer.options.read_timeout = normalized_peer_timeout(timeouts.read);
    peer.options.write_timeout = normalized_peer_timeout(timeouts.write);
}

// Content-Length is only a fast path. Chunked and h2 bodies are enforced later
// in request_body_filter while the downstream body stream is consumed.
async fn restrict_client_max_body_size(
    session: &mut Session,
    ctx: &mut ProxyContext,
) -> Result<bool> {
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
async fn write_local_response(session: &mut Session, response: LocalResponse) -> Result<()> {
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

    /// Retrieve routes for a specific key (Lock-free)
    pub fn get_routes(&self, key: &ListenKey) -> Option<Arc<VirtualHostRoutes>> {
        let snapshot = self.state.snapshot();
        snapshot.router.listeners.get(key).cloned().map(Arc::new)
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
    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
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
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> Result<()> {
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
    ) -> Result<()> {
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
    ) -> Result<()> {
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
    ) -> Result<Box<HttpPeer>> {
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
            RouteTarget::ProxyPass {
                host,
                port,
                tls,
                sni,
            } => {
                let mut peer = HttpPeer::new((host.as_str(), *port), *tls, sni.clone());
                apply_upstream_timeouts(&mut peer, selected.upstream_timeouts);
                peer
            }
        };

        Ok(Box::new(peer))
    }
}
