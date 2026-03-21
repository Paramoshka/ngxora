use ngxora_compile::ir::{
    DownstreamTlsOptions, Listen, LocationMatcher, PemSource, TlsIdentity, TlsProtocolBounds,
    TlsVerifyClient, UpstreamHttpProtocol, UpstreamSelectionPolicy, UpstreamSslOptions,
    UpstreamTimeouts,
};
use ngxora_plugin_api::PluginSpec;
use regex::{Regex, RegexBuilder};
use std::collections::HashMap;
use std::fmt::Display;
use std::net::IpAddr;
use std::time::Duration;

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
    UpstreamGroup {
        name: String,
        tls: bool,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CompiledUpstreamServer {
    pub host: String,
    pub port: u16,
}

impl Display for CompiledUpstreamServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum HealthCheckType {
    Tcp,
    Http {
        host: String,
        path: String,
        use_tls: bool,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CompiledHealthCheck {
    pub check_type: HealthCheckType,
    pub timeout: Duration,
    pub interval: Duration,
    pub consecutive_success: usize,
    pub consecutive_failure: usize,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CompiledUpstreamGroup {
    pub name: String,
    pub policy: UpstreamSelectionPolicy,
    pub servers: Vec<CompiledUpstreamServer>,
    pub health_check: Option<CompiledHealthCheck>,
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
    pub(crate) fn new(pattern: String, case_insensitive: bool) -> Result<Self, String> {
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

    pub(crate) fn is_match(&self, path: &str) -> bool {
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
    pub upstream_protocol: Option<UpstreamHttpProtocol>,
    pub upstream_ssl_options: UpstreamSslOptions,
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

// CompiledRouter stores the IR representation in an optimized form.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct CompiledRouter {
    pub upstreams: HashMap<String, CompiledUpstreamGroup>,
    pub listeners: HashMap<ListenKey, VirtualHostRoutes>,
    pub listener_protocols: HashMap<ListenKey, ListenerProtocolConfig>,
    pub listener_tls: HashMap<ListenKey, ListenerTlsConfig>,
    pub http_options: HttpRuntimeOptions,
}

// Alias to keep compatibility with the misspelled name used in discussion.
pub type CompliedRouter = CompiledRouter;

impl From<&DownstreamTlsOptions> for ListenerTlsSettings {
    fn from(value: &DownstreamTlsOptions) -> Self {
        Self {
            protocols: value.protocols,
            verify_client: value.verify_client,
            client_certificate: value.client_certificate.clone(),
        }
    }
}
