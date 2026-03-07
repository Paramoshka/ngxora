use arc_swap::ArcSwap;
use async_trait::async_trait;
use ngxora_compile::ir::{
    Http, Listen, Location, LocationDirective, LocationMatcher, Server, TlsIdentity,
};
use pingora::Result;
use pingora::upstreams::peer::HttpPeer;
use pingora_proxy::{ProxyHttp, Session};
use regex::RegexBuilder;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;

#[cfg(test)]
mod tests;

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
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
    pub matcher: CompiledMatcher,
    pub target: RouteTarget,
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
pub struct ListenerTlsConfig {
    pub named: HashMap<String, TlsIdentity>,
    pub default: Option<TlsIdentity>,
}

// CompiledRouter stores the Ir representation in an optimized form.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct CompiledRouter {
    pub listeners: HashMap<ListenKey, VirtualHostRoutes>,
    pub listener_tls: HashMap<ListenKey, ListenerTlsConfig>,
}

// Alias to keep compatibility with the misspelled name used in discussion.
pub type CompliedRouter = CompiledRouter;

impl CompiledRouter {
    pub fn from_http(http: &Http) -> Self {
        let mut router = Self::default();
        for server in &http.servers {
            router.add_server(server);
        }
        router
    }

    fn add_server(&mut self, server: &Server) {
        let routes = ServerRoutes {
            locations: compile_locations(&server.locations),
        };

        for listen in &server.listens {
            let listen_key = ListenKey::from(listen);
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
                let listener_tls = self.listener_tls.entry(listen_key).or_default();

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
    }
}

fn compile_locations(locations: &[Location]) -> Vec<CompiledLocation> {
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

            Some(CompiledLocation {
                matcher: CompiledMatcher::from(&location.matcher),
                target,
            })
        })
        .collect()
}

fn regex_matches(path: &str, pattern: &str, case_insensitive: bool) -> bool {
    RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .build()
        .map(|re| re.is_match(path))
        .unwrap_or(false)
}

fn select_route_target<'a>(routes: &'a ServerRoutes, path: &str) -> Option<&'a RouteTarget> {
    let mut best_prefix: Option<(&CompiledLocation, usize)> = None;
    let mut best_prefer_prefix: Option<(&CompiledLocation, usize)> = None;

    for location in &routes.locations {
        match &location.matcher {
            CompiledMatcher::Exact(p) if path == p => return Some(&location.target),
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
        return Some(&location.target);
    }

    for location in &routes.locations {
        match &location.matcher {
            CompiledMatcher::Regex {
                case_insensitive,
                pattern,
            } if regex_matches(path, pattern, *case_insensitive) => {
                return Some(&location.target);
            }
            _ => {}
        }
    }

    best_prefix.map(|(location, _)| &location.target)
}

pub struct DynamicProxy {
    routing: ArcSwap<CompiledRouter>,
}

impl DynamicProxy {
    pub fn new(routing: CompiledRouter) -> Self {
        Self {
            routing: ArcSwap::from_pointee(routing),
        }
    }

    /// Retrieve routes for a specific key (Lock-free)
    pub fn get_routes(&self, key: &ListenKey) -> Option<Arc<VirtualHostRoutes>> {
        // .load() returns a Guard which can be treated like Arc<CompiledRouter>
        let router = self.routing.load();

        // Return a reference-counted pointer to the specific routes
        // This assumes VirtualHostRoutes is wrapped in Arc or cloned
        router.listeners.get(key).cloned().map(Arc::new)
    }

    /// Replace the entire routing table (Atomic write)
    pub fn update_routing(&self, new_router: CompiledRouter) {
        self.routing.store(Arc::new(new_router));
    }
}

#[async_trait]
impl ProxyHttp for DynamicProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    // upstream_peer method allows for advanced configurations, including HTTPS, SNI, and dynamic load balancing based on the request headers.
    async fn upstream_peer(
        &self,
        session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        //extract listen_key, host, path

        // 2. Get the Host (returns Option<&HeaderValue>)
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

        let addr = inet.ip();
        let port = inet.port();

        // 3. Check is SSL.
        let is_ssl = session
            .digest()
            .and_then(|d| d.ssl_digest.as_ref())
            .is_some();

        //find listener in CompiledRouter
        let listen_key = ListenKey {
            addr: addr,
            port: port,
            ssl: is_ssl,
        };

        //choose vhost by host, fallback to default
        let vhosts = self.get_routes(&listen_key).ok_or_else(|| {
            pingora::Error::explain(pingora::ErrorType::HTTPStatus(404), "no listener matched")
        })?;

        // 2) Host fallback: exact host -> default vhost
        let host = session
            .get_header("host")
            .and_then(|v| v.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h).to_ascii_lowercase());

        let server_routes = host
            .as_deref()
            .and_then(|h| vhosts.named.get(h))
            .or(vhosts.default.as_ref())
            .ok_or_else(|| {
                pingora::Error::explain(
                    pingora::ErrorType::HTTPStatus(404),
                    "no virtual host matched",
                )
            })?;

        let path = session.req_header().uri.path();
        let target = select_route_target(server_routes, path).ok_or_else(|| {
            pingora::Error::explain(pingora::ErrorType::HTTPStatus(404), "no location matched")
        })?;

        let peer = match target {
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
