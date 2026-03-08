use crate::control::{ApplyResult, ConfigSnapshot, RuntimeSnapshot, RuntimeState};
use async_trait::async_trait;
use ngxora_compile::ir::{
    DownstreamTlsOptions, Http, KeepaliveTimeout, Listen, Location, LocationDirective,
    LocationMatcher, PemSource, Server, TlsIdentity, TlsProtocolBounds, TlsVerifyClient,
};
use ngxora_plugin_api::{
    HeaderMapMut, LocalResponse, PluginError, PluginFlow, PluginSpec, PluginState, RequestCtx,
    ResponseCtx, UpstreamRequestCtx,
};
use pingora::Result;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::upstreams::peer::HttpPeer;
use pingora_proxy::{ProxyHttp, Session};
use regex::RegexBuilder;
use std::collections::HashMap;
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
    Regex {
        case_insensitive: bool,
        pattern: String,
    },
    PreferPrefix(String),
    Named(String),
}

impl From<&LocationMatcher> for CompiledMatcher {
    fn from(value: &LocationMatcher) -> Self {
        match value {
            LocationMatcher::Prefix(path) => Self::Prefix(path.clone()),
            LocationMatcher::Exact(path) => Self::Exact(path.clone()),
            LocationMatcher::Regex {
                case_insensitive,
                pattern,
            } => Self::Regex {
                case_insensitive: *case_insensitive,
                pattern: pattern.clone(),
            },
            LocationMatcher::PreferPrefix(path) => Self::PreferPrefix(path.clone()),
            LocationMatcher::Named(name) => Self::Named(name.clone()),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CompiledLocation {
    pub route_id: u64,
    pub matcher: CompiledMatcher,
    pub target: RouteTarget,
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
            locations: compile_locations(&server.locations, next_route_id),
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
                let listener_tls = self.listener_tls.entry(listen_key).or_insert_with(|| {
                    ListenerTlsConfig {
                        settings: ListenerTlsSettings::from(&server.tls_options),
                        ..ListenerTlsConfig::default()
                    }
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

fn compile_locations(locations: &[Location], next_route_id: &mut u64) -> Vec<CompiledLocation> {
    locations
        .iter()
        .filter_map(|location| {
            let target = location
                .directives
                .iter()
                .find_map(|directive| match directive {
                    LocationDirective::ProxyPass(url) => {
                        let host = url.host_str()?.to_string();
                        let port = url.port_or_known_default()?;
                        let tls = match url.scheme() {
                            "http" => false,
                            "https" => true,
                            _ => return None,
                        };
                        let sni = if tls && host.parse::<IpAddr>().is_err() {
                            host.clone()
                        } else {
                            String::new()
                        };

                        Some(RouteTarget::ProxyPass {
                            host,
                            port,
                            tls,
                            sni,
                        })
                    }
                    _ => None,
                })?;

            let compiled = CompiledLocation {
                route_id: *next_route_id,
                matcher: CompiledMatcher::from(&location.matcher),
                target,
                plugins: Vec::new(),
            };
            *next_route_id += 1;

            Some(compiled)
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

fn regex_matches(path: &str, pattern: &str, case_insensitive: bool) -> bool {
    RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .build()
        .map(|re| re.is_match(path))
        .unwrap_or(false)
}

fn select_route_target<'a>(
    routes: &'a ServerRoutes,
    path: &str,
) -> Option<&'a CompiledLocation> {
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
            CompiledMatcher::Regex {
                case_insensitive,
                pattern,
            } if regex_matches(path, pattern, *case_insensitive) => {
                return Some(location);
            }
            _ => {}
        }
    }

    best_prefix.map(|(location, _)| location)
}

#[derive(Debug)]
struct ResolvedLocation<'a> {
    location: &'a CompiledLocation,
    host: Option<String>,
}

#[derive(Clone)]
struct SelectedRoute {
    target: RouteTarget,
    plugins: ngxora_plugin_api::PluginChain,
}

#[derive(Default)]
pub struct ProxyContext {
    selected: Option<SelectedRoute>,
    plugin_state: PluginState,
}

struct RequestHeaderEditor<'a> {
    inner: &'a mut RequestHeader,
}

impl HeaderMapMut for RequestHeaderEditor<'_> {
    fn add(
        &mut self,
        name: &http::HeaderName,
        value: http::HeaderValue,
    ) -> Result<(), PluginError> {
        self.inner
            .append_header(name, value)
            .map(|_| ())
            .map_err(|err| {
                PluginError::new(
                    "header-editor",
                    format!("failed to append header `{name}`: {err}"),
                )
            })
    }

    fn set(
        &mut self,
        name: &http::HeaderName,
        value: http::HeaderValue,
    ) -> Result<(), PluginError> {
        self.inner.insert_header(name, value).map_err(|err| {
            PluginError::new(
                "header-editor",
                format!("failed to insert header `{name}`: {err}"),
            )
        })
    }

    fn remove(&mut self, name: &http::HeaderName) {
        self.inner.remove_header(name);
    }
}

struct ResponseHeaderEditor<'a> {
    inner: &'a mut ResponseHeader,
}

impl HeaderMapMut for ResponseHeaderEditor<'_> {
    fn add(
        &mut self,
        name: &http::HeaderName,
        value: http::HeaderValue,
    ) -> Result<(), PluginError> {
        self.inner
            .append_header(name, value)
            .map(|_| ())
            .map_err(|err| {
                PluginError::new(
                    "header-editor",
                    format!("failed to append header `{name}`: {err}"),
                )
            })
    }

    fn set(
        &mut self,
        name: &http::HeaderName,
        value: http::HeaderValue,
    ) -> Result<(), PluginError> {
        self.inner.insert_header(name, value).map_err(|err| {
            PluginError::new(
                "header-editor",
                format!("failed to insert header `{name}`: {err}"),
            )
        })
    }

    fn remove(&mut self, name: &http::HeaderName) {
        self.inner.remove_header(name);
    }
}

fn resolve_route<'a>(
    router: &'a CompiledRouter,
    session: &Session,
) -> Result<Option<ResolvedLocation<'a>>> {
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

    let listen_key = ListenKey {
        addr: inet.ip(),
        port: inet.port(),
        ssl: session
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .is_some(),
    };

    let Some(vhosts) = router.listeners.get(&listen_key) else {
        return Ok(None);
    };

    let host = session
        .get_header("host")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(':').next().unwrap_or(value).to_ascii_lowercase());

    let Some(server_routes) = host
        .as_deref()
        .and_then(|value| vhosts.named.get(value))
        .or(vhosts.default.as_ref())
    else {
        return Ok(None);
    };

    let path = session.req_header().uri.path();
    let Some(location) = select_route_target(server_routes, path) else {
        return Ok(None);
    };

    Ok(Some(ResolvedLocation { location, host }))
}

fn select_runtime_route(
    snapshot: &RuntimeSnapshot,
    session: &Session,
) -> Result<Option<(SelectedRoute, Option<String>)>> {
    let Some(resolved) = resolve_route(&snapshot.router, session)? else {
        return Ok(None);
    };

    Ok(Some((
        SelectedRoute {
            target: resolved.location.target.clone(),
            plugins: snapshot.plugin_chain(resolved.location.route_id),
        },
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
        header.insert_header(http::header::CONTENT_LENGTH, 0).map_err(|err| {
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                format!("failed to finalize plugin response: {err}"),
            )
        })?;
        session.write_response_header(Box::new(header), true).await
    } else {
        header
            .insert_header(http::header::CONTENT_LENGTH, response.body.len().to_string())
            .map_err(|err| {
                pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    format!("failed to finalize plugin response: {err}"),
                )
            })?;
        session.write_response_header(Box::new(header), false).await?;
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

    async fn request_filter(&self, session: &mut Session, ctx: &mut Self::CTX) -> Result<bool> {
        let snapshot = self.state.snapshot();
        session.set_keepalive(snapshot.router.http_options.downstream_keepalive_timeout);

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

    // upstream_peer method allows for advanced configurations, including HTTPS, SNI, and dynamic load balancing based on the request headers.
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
            } => HttpPeer::new((host.as_str(), *port), *tls, sni.clone()),
        };

        Ok(Box::new(peer))
    }
}
