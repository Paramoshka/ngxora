use arc_swap::{ArcSwap, ArcSwapAny};
use async_trait::async_trait;
use ngxora_compile::ir::{Http, Listen, Location, LocationDirective, LocationMatcher, Server};
use pingora::Result;
use pingora::upstreams::peer::HttpPeer;
use pingora_proxy::{ProxyHttp, Session};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, RwLock};

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
    ProxyPass { upstream: String },
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

// CompiledRouter stores the Ir representation in an optimized form.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct CompiledRouter {
    pub listeners: HashMap<ListenKey, VirtualHostRoutes>,
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
            let listener = self.listeners.entry(ListenKey::from(listen)).or_default();

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
                    LocationDirective::ProxyPass(url) => Some(RouteTarget::ProxyPass {
                        upstream: url.to_string(),
                    }),
                    _ => None,
                })?;

            Some(CompiledLocation {
                matcher: CompiledMatcher::from(&location.matcher),
                target,
            })
        })
        .collect()
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
        ctx: &mut Self::CTX,
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
        let mut selected: Option<&RouteTarget> = None;

        for location in &server_routes.locations {
            let is_match = match &location.matcher {
                CompiledMatcher::Exact(p) => path == p,
                CompiledMatcher::Prefix(p) | CompiledMatcher::PreferPrefix(p) => {
                    path.starts_with(p)
                }
                CompiledMatcher::Regex { .. } => false,
                CompiledMatcher::Named(_) => false,
            };

            if is_match {
                selected = Some(&location.target);
                break; // first-match
            }
        }

        let target = selected.ok_or_else(|| {
            pingora::Error::explain(pingora::ErrorType::HTTPStatus(404), "no location matched")
        })?;

        //match location by nginx priority
        //build and return HttpPeer from selected target
        // if no route: return error.
        todo!("");
    }
}
