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
    routing: Arc<RwLock<CompiledRouter>>,
}

impl DynamicProxy {
    pub fn new(routing: CompiledRouter) -> Self {
        Self {
            routing: Arc::new(RwLock::new(routing)),
        }
    }

    pub fn router(&self) -> Arc<RwLock<CompiledRouter>> {
        Arc::clone(&self.routing)
    }
}

#[async_trait]
impl ProxyHttp for DynamicProxy {
    type CTX = ();

    fn new_ctx(&self) -> Self::CTX {}

    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {
        todo!("pick upstream using CompiledRouter")
    }
}
