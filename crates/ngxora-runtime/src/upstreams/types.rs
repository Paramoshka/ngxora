use ngxora_compile::ir::{
    DownstreamTlsOptions, LetsEncryptConfig, Listen, LocationIpRule, LocationMatcher,
    NrfEndpointScheme, PemSource, TlsIdentity, TlsProtocolBounds, TlsVerifyClient, UpstreamHashKey,
    UpstreamHttpProtocol, UpstreamSelectionPolicy, UpstreamSslOptions, UpstreamTimeouts,
};
use ngxora_plugin_api::PluginSpec;
use regex::{Regex, RegexBuilder};
use std::collections::HashMap;
use std::fmt::Display;
use std::net::IpAddr;
use std::time::Duration;

// ListenKey identifies one bound downstream socket after listen directives have
// been normalized.
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
    WeightedBackends(Vec<CompiledWeightedBackend>),
    DirectResponse(u16),
    HttpRedirect(ngxora_compile::ir::HttpRedirect),
    Scp {
        profile: String,
    },
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
    Return {
        status: u16,
        location: String,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CompiledWeightedBackend {
    pub weight: u32,
    pub target: RouteTarget,
}

// CompiledUpstreamServer is a backend endpoint already validated during
// snapshot build.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CompiledUpstreamServer {
    pub host: String,
    pub port: u16,
    pub weight: u16,
    pub api_prefix: Option<String>,
    pub nrf_service: Option<NrfServiceMetadata>,
}

#[derive(Debug, Clone, Eq, PartialEq, Hash, PartialOrd, Ord)]
pub struct NrfServiceMetadata {
    pub authority: Option<String>,
    pub nf_instance_id: String,
    pub service_instance_id: String,
    pub priority: u16,
    pub capacity: u16,
}

impl Display for CompiledUpstreamServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.host, self.port)?;
        if let Some(prefix) = self.api_prefix.as_deref() {
            f.write_str(prefix)?;
        }
        Ok(())
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
pub struct CompiledNrfDiscovery {
    pub api_root: url::Url,
    pub target_nf_type: String,
    pub requester_nf_type: String,
    pub service_name: String,
    pub endpoint_scheme: NrfEndpointScheme,
    pub timeout: Duration,
    pub stale_if_error: Duration,
    pub tls_options: UpstreamSslOptions,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CompiledUpstreamGroup {
    pub allow_empty: bool,
    pub name: String,
    pub policy: UpstreamSelectionPolicy,
    pub hash_key: Option<UpstreamHashKey>,
    pub servers: Vec<CompiledUpstreamServer>,
    pub nrf_discovery: Option<CompiledNrfDiscovery>,
    pub health_check: Option<CompiledHealthCheck>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum CompiledMatcher {
    Http(ngxora_compile::ir::HttpMatch),
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
            LocationMatcher::Http(matcher) => {
                Ok(Self::Http(super::http_routes::compile_match(matcher)?))
            }
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

use ngxora_compile::ir::CacheConfig;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CompiledLocation {
    pub url_rewrite: Option<ngxora_compile::ir::UrlRewrite>,
    pub route_id: u64,
    pub matcher: CompiledMatcher,
    pub access_rules: Vec<LocationIpRule>,
    pub target: RouteTarget,
    pub upstream_timeouts: UpstreamTimeouts,
    pub upstream_protocol: Option<UpstreamHttpProtocol>,
    pub upstream_ssl_options: UpstreamSslOptions,
    pub plugins: Vec<PluginSpec>,
    pub cache: Option<CacheConfig>,
}

impl CompiledLocation {
    // with_plugins is used by tests and builders that want to attach the
    // already-resolved plugin chain to a route.
    pub fn with_plugins(mut self, plugins: Vec<PluginSpec>) -> Self {
        self.plugins = plugins;
        self
    }
}

// ServerRoutes is the ordered location set for one virtual server after
// compilation.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct ServerRoutes {
    pub locations: Vec<CompiledLocation>,
}

// VirtualHostRoutes groups named and default virtual servers for one listener.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct VirtualHostRoutes {
    pub named: HashMap<String, ServerRoutes>,
    pub default: Option<ServerRoutes>,
}

// ListenerProtocolConfig captures bootstrap-time downstream protocol policy.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct ListenerProtocolConfig {
    pub http2: bool,
    pub http2_only: bool,
}

// ListenerTlsSettings holds listener-level TLS policy that affects socket
// bootstrap and therefore participates in restart boundary checks.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct ListenerTlsSettings {
    pub protocols: Option<TlsProtocolBounds>,
    pub verify_client: TlsVerifyClient,
    pub client_certificate: Option<PemSource>,
}

// ListenerTlsConfig stores the SNI identity map plus listener-level TLS
// settings for one bound TLS listener.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct ListenerTlsConfig {
    pub named: HashMap<String, TlsIdentity>,
    pub default: Option<TlsIdentity>,
    pub settings: ListenerTlsSettings,
}

// HttpRuntimeOptions is the subset of HTTP-level runtime behavior read by the
// Pingora proxy service and request filters.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct HttpRuntimeOptions {
    pub downstream_keepalive_timeout: Option<u64>,
    pub keepalive_requests: Option<u32>,
    pub client_max_body_size: Option<u64>,
    pub proxy_cache_max_size: Option<u64>,
    pub tcp_nodelay: bool,
    pub allow_connect_method_proxying: bool,
    pub h2c: bool,
}

// CompiledRouter is the immutable routing model consumed by the dataplane at
// request time and by restart-boundary checks at apply time.
#[derive(Debug, Default, Clone, Eq, PartialEq)]
pub struct CompiledRouter {
    pub scp_profiles: HashMap<String, ngxora_compile::ir::ScpProfile>,
    pub upstreams: HashMap<String, CompiledUpstreamGroup>,
    pub listeners: HashMap<ListenKey, VirtualHostRoutes>,
    pub listener_protocols: HashMap<ListenKey, ListenerProtocolConfig>,
    pub listener_tls: HashMap<ListenKey, ListenerTlsConfig>,
    pub http_options: HttpRuntimeOptions,
    /// Global Let's Encrypt configuration from `ssl_provider letsencrypt { ... }`.
    pub le_config: Option<LetsEncryptConfig>,
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
