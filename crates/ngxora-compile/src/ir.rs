use ngxora_plugin_api::PluginSpec;
use std::fmt::Error;
// Intermediate Representation layer
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;

use ipnet::IpNet;

use url::Url;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RealIpConfig {
    pub trusted_proxies: Vec<IpNet>,
    pub header: String,
    pub recursive: bool,
}

impl Default for RealIpConfig {
    fn default() -> Self {
        Self {
            trusted_proxies: Vec::new(),
            header: "X-Forwarded-For".into(),
            recursive: true,
        }
    }
}

impl RealIpConfig {
    pub fn validate(&self) -> Result<(), String> {
        if !self.header.eq_ignore_ascii_case("x-forwarded-for")
            && !self.header.eq_ignore_ascii_case("x-real-ip")
        {
            return Err("real_ip_header must be X-Forwarded-For or X-Real-IP".into());
        }
        Ok(())
    }
}

// Optional route overrides retain zero as an explicit disabled limit.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ClientLimits {
    pub max_body_size: Option<u64>,
    pub body_timeout: Option<Duration>,
    pub send_timeout: Option<Duration>,
    pub allowed_methods: Vec<String>,
}

pub fn validate_client_timeout(value: Option<Duration>) -> Result<(), String> {
    if value.is_some_and(|v| {
        v.as_millis() > u64::MAX as u128 || !v.subsec_nanos().is_multiple_of(1_000_000)
    }) {
        return Err("client timeout must be whole milliseconds fitting uint64".into());
    }
    Ok(())
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeoIpConfig {
    pub database: PathBuf,
    pub reload_interval: Duration,
    pub trusted_proxies: Vec<IpNet>,
}

impl GeoIpConfig {
    pub fn validate(&self) -> Result<(), String> {
        if self.database.as_os_str().is_empty() || self.database.to_str().is_none() {
            return Err("geoip database must be a nonempty UTF-8 path".into());
        }
        if self.reload_interval < Duration::from_millis(1)
            || self.reload_interval.as_millis() > u64::MAX as u128
            || !self
                .reload_interval
                .subsec_nanos()
                .is_multiple_of(1_000_000)
        {
            return Err("geoip reload_interval must be a positive whole number of milliseconds fitting uint64".into());
        }
        Ok(())
    }
}

/// How the server obtains its TLS certificate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SslProvider {
    /// Manually provided certificate and key paths (ssl_certificate / ssl_certificate_key).
    Custom(TlsIdentity),
    /// Automatically issued and renewed via ACME (Let's Encrypt).
    LetsEncrypt,
}

/// Global Let's Encrypt / ACME configuration declared inside `ssl_provider letsencrypt { ... }`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LetsEncryptConfig {
    /// ACME directory URL.  If omitted the Let's Encrypt production endpoint is used.
    pub acme_directory: Option<String>,
    /// Contact email registered with the ACME account (required).
    pub email: Option<String>,
    /// Directory where obtained certificates are stored on disk.
    /// Default: `/var/lib/ngxora/certs`.
    pub cache_dir: Option<PathBuf>,
}

#[derive(Debug, Eq, PartialEq, Default)]
pub struct Ir {
    pub http: Option<Http>,
    // events ?
}

#[derive(Debug, Eq, PartialEq)]
pub struct Http {
    pub real_ip: Option<RealIpConfig>,
    pub client_header_timeout: Option<Duration>,
    pub client_body_timeout: Option<Duration>,
    pub send_timeout: Option<Duration>,
    pub scp_profiles: Vec<ScpProfile>,
    pub upstreams: Vec<UpstreamBlock>,
    pub servers: Vec<Server>,
    pub keepalive_timeout: KeepaliveTimeout,
    pub keepalive_requests: Option<u32>,
    pub client_max_body_size: Option<u64>,
    pub proxy_cache_max_size: Option<u64>,
    pub tcp_nodelay: Switch,
    pub allow_connect_method_proxying: Switch,
    pub h2c: Switch,
    pub http2: Http2Options,
    pub ssl_provider: Option<LetsEncryptConfig>,
    pub geoip: Option<GeoIpConfig>,
}

impl Default for Http {
    fn default() -> Self {
        Self {
            real_ip: None,
            client_header_timeout: None,
            client_body_timeout: None,
            send_timeout: None,
            scp_profiles: Vec::new(),
            upstreams: Vec::new(),
            servers: Vec::new(),
            keepalive_timeout: KeepaliveTimeout::default(),
            keepalive_requests: None,
            client_max_body_size: None,
            proxy_cache_max_size: None,
            tcp_nodelay: Switch::On,
            allow_connect_method_proxying: Switch::Off,
            h2c: Switch::Off,
            http2: Http2Options::default(),
            ssl_provider: None,
            geoip: None,
        }
    }
}

/// A bounded SBI routing domain. Discovery upstreams supply the allowed
/// NF type/service/requester combinations and the existing NRF transport policy.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct ScpProfile {
    pub name: String,
    pub api_root: String,
    pub discovery_upstreams: Vec<String>,
    pub allowed_target_api_roots: Vec<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum KeepaliveTimeout {
    Off,
    Timeout {
        idle: Duration,
        header: Option<Duration>,
    },
}

impl Default for KeepaliveTimeout {
    fn default() -> Self {
        Self::Timeout {
            idle: Duration::from_secs(60),
            header: None,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Default)]
pub struct Server {
    pub server_names: Vec<String>,
    pub locations: Vec<Location>,
    pub listens: Vec<Listen>,
    /// How TLS certificates are obtained for this server.
    /// `None` means the server does not require TLS (no `ssl` listener).
    pub tls: Option<SslProvider>,
    pub tls_options: DownstreamTlsOptions,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UpstreamBlock {
    pub allow_empty: bool,
    pub name: String,
    pub policy: UpstreamSelectionPolicy,
    pub hash_key: Option<UpstreamHashKey>,
    pub servers: Vec<UpstreamServer>,
    pub nrf_discovery: Option<NrfDiscovery>,
    pub health_check: Option<UpstreamHealthCheck>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum NrfEndpointScheme {
    Http,
    Https,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct NrfDiscovery {
    pub api_root: String,
    pub target_nf_type: String,
    pub requester_nf_type: String,
    pub service_name: String,
    pub endpoint_scheme: NrfEndpointScheme,
    pub timeout: Duration,
    pub stale_if_error: Duration,
    pub tls_options: UpstreamSslOptions,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UpstreamServer {
    pub host: String,
    pub port: u16,
    pub weight: u16,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub enum UpstreamSelectionPolicy {
    #[default]
    RoundRobin,
    Random,
    ConsistentHash,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum UpstreamHashKey {
    ClientIp,
    Header(String),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum UpstreamHealthCheckType {
    Tcp,
    Http {
        host: String,
        path: String,
        use_tls: bool,
    },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UpstreamHealthCheck {
    pub check_type: UpstreamHealthCheckType,
    pub timeout: Duration,
    pub interval: Duration,
    pub consecutive_success: usize,
    pub consecutive_failure: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsIdentity {
    pub cert: PemSource,
    pub key: PemSource,
}

impl Default for TlsIdentity {
    fn default() -> Self {
        Self {
            cert: PemSource::Path(PathBuf::new()),
            key: PemSource::Path(PathBuf::new()),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PemSource {
    Path(PathBuf),
    InlinePem(String),
}

impl PemSource {
    pub fn new(raw_path: &[String], _is_inline: bool) -> Result<Self, Error> {
        let path: PathBuf = raw_path.iter().collect();
        let pem_source: PemSource = PemSource::Path(path);
        Ok(pem_source)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Listen {
    pub addr: IpAddr,
    pub port: u16,
    pub ssl: bool,
    pub default_server: bool,
    pub http2: bool,
    pub http2_only: bool,
}

impl Default for Listen {
    fn default() -> Self {
        Self {
            addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 80,
            ssl: false,
            default_server: false,
            http2: false,
            http2_only: false,
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct DownstreamTlsOptions {
    pub protocols: Option<TlsProtocolBounds>,
    pub verify_client: TlsVerifyClient,
    pub client_certificate: Option<PemSource>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub enum TlsProtocolVersion {
    Tls1,
    Tls1_2,
    Tls1_3,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TlsProtocolBounds {
    pub min: TlsProtocolVersion,
    pub max: TlsProtocolVersion,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub enum TlsVerifyClient {
    #[default]
    Off,
    Optional,
    Required,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Location {
    pub matcher: LocationMatcher,
    pub access_rules: Vec<LocationIpRule>,
    pub directives: Vec<LocationDirective>, // proxy_pass, root, try_files...
    pub plugins: Vec<PluginSpec>,
    pub cache: Option<CacheConfig>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum LocationIpRule {
    Allow(IpNet),
    Deny(IpNet),
    AllowAll,
    DenyAll,
}

impl LocationIpRule {
    pub fn matches(&self, ip: &IpAddr) -> bool {
        match self {
            Self::Allow(network) | Self::Deny(network) => network.contains(ip),
            Self::AllowAll | Self::DenyAll => true,
        }
    }

    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow(_) | Self::AllowAll)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CacheConfig {
    pub enabled: bool,
    pub max_size: Option<u64>,
    pub ttl: Option<Duration>,
    pub stale_if_error: Option<Duration>,
    pub cache_key: CacheKeyMode,
    pub min_uses: Option<usize>,
    pub valid_statuses: Vec<u16>,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_size: None,
            ttl: Some(Duration::from_secs(60)),
            stale_if_error: None,
            cache_key: CacheKeyMode::default(),
            min_uses: None,
            valid_statuses: vec![200, 301, 404],
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub enum CacheKeyMode {
    #[default]
    Uri,
    UriAndMethod,
    NormalizedUri,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub struct UpstreamTimeouts {
    pub connect: Option<Duration>,
    pub read: Option<Duration>,
    pub write: Option<Duration>,
}

#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub struct UpstreamSslOptions {
    pub verify_cert: Switch,
    pub trusted_certificate: Option<PemSource>,
    /// Client certificate presented to the upstream during mTLS
    /// (`proxy_ssl_certificate`).
    pub client_certificate: Option<PemSource>,
    /// Private key for `client_certificate` (`proxy_ssl_certificate_key`).
    pub client_certificate_key: Option<PemSource>,
}

#[derive(Debug, Eq, PartialEq)]
pub enum LocationMatcher {
    Http(HttpMatch),
    Prefix(String), // `location /api/ {}`
    Exact(String),  // `location = / {}`
    Regex {
        case_insensitive: bool,
        pattern: String,
    }, // `~` / `~*`
    PreferPrefix(String), // `^~`
    Named(String),  // `@name`
}

#[derive(Debug, Eq, PartialEq)]
pub enum LocationDirective {
    ClientMaxBodySize(u64),
    ClientBodyTimeout(Duration),
    SendTimeout(Duration),
    AllowMethods(Vec<String>),
    WeightedBackends(Vec<WeightedBackend>),
    DirectResponse(u16),
    HttpRedirect(HttpRedirect),
    UrlRewrite(UrlRewrite),
    ScpPass(String),
    ProxyPass(ProxyPassTarget),
    ProxyConnectTimeout(Duration),
    ProxyReadTimeout(Duration),
    ProxyWriteTimeout(Duration),
    ProxyUpstreamProtocol(UpstreamHttpProtocol),
    ProxyHttp2MaxConcurrentStreams(u32),
    ProxyHttp2StreamWindowSize(u32),
    ProxyHttp2ConnectionWindowSize(u32),
    ProxySslVerify(Switch),
    ProxySslTrustedCertificate(PemSource),
    ProxySslCertificate(PemSource),
    ProxySslCertificateKey(PemSource),
    Root(String),
    TryFiles(String),
    Return { status: u16, location: String },
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HttpMatch {
    pub path: HttpPathMatch,
    pub method: Option<String>,
    pub headers: Vec<(String, String)>,
    pub query_params: Vec<(String, String)>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum HttpPathMatch {
    Exact(String),
    PathPrefix(String),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WeightedBackend {
    pub weight: u32,
    pub target: BackendTarget,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum BackendTarget {
    Upstream(ProxyPassTarget),
    Response(u16),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum PathModifier {
    ReplaceFullPath(String),
    ReplacePrefixMatch(String),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct HttpRedirect {
    pub status: u16,
    pub scheme: Option<String>,
    pub hostname: Option<String>,
    pub port: Option<u16>,
    pub path: Option<PathModifier>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UrlRewrite {
    pub hostname: Option<String>,
    pub path: Option<PathModifier>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum ProxyPassTarget {
    Url(Url),
    UpstreamGroup { name: String, tls: bool },
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum UpstreamHttpProtocol {
    H1,
    H2,
    H2c,
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub enum Switch {
    #[default]
    On,
    Off,
}

/// HTTP/2 receive settings. Unset fields retain Pingora's bounded defaults.
#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub struct Http2Options {
    pub max_concurrent_streams: Option<u32>,
    pub max_header_list_size: Option<u32>,
    pub stream_window_size: Option<u32>,
    pub connection_window_size: Option<u32>,
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub struct UpstreamHttp2Options {
    pub max_concurrent_streams: Option<u32>,
    pub stream_window_size: Option<u32>,
    pub connection_window_size: Option<u32>,
}

impl Http2Options {
    pub fn validate(&self) -> Result<(), String> {
        validate_http2_value(
            self.max_concurrent_streams,
            u32::MAX,
            "http2_max_concurrent_streams",
        )?;
        validate_http2_value(
            self.max_header_list_size,
            u32::MAX,
            "http2_max_header_list_size",
        )?;
        validate_http2_value(
            self.stream_window_size,
            i32::MAX as u32,
            "http2_stream_window_size",
        )?;
        validate_http2_value(
            self.connection_window_size,
            i32::MAX as u32,
            "http2_connection_window_size",
        )
    }
}

impl UpstreamHttp2Options {
    pub fn validate(&self) -> Result<(), String> {
        validate_http2_value(
            self.max_concurrent_streams,
            u32::MAX,
            "proxy_http2_max_concurrent_streams",
        )?;
        validate_http2_value(
            self.stream_window_size,
            i32::MAX as u32,
            "proxy_http2_stream_window_size",
        )?;
        validate_http2_value(
            self.connection_window_size,
            i32::MAX as u32,
            "proxy_http2_connection_window_size",
        )
    }
}

fn validate_http2_value(value: Option<u32>, max: u32, name: &str) -> Result<(), String> {
    if value.is_some_and(|value| value == 0 || value > max) {
        return Err(format!("{name}: expected a value between 1 and {max}"));
    }
    Ok(())
}
