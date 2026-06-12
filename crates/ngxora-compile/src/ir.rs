use ngxora_plugin_api::PluginSpec;
use std::fmt::Error;
// Intermediate Representation layer
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;

use url::Url;

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
    pub upstreams: Vec<UpstreamBlock>,
    pub servers: Vec<Server>,
    pub keepalive_timeout: KeepaliveTimeout,
    pub keepalive_requests: Option<u32>,
    pub client_max_body_size: Option<u64>,
    pub proxy_cache_max_size: Option<u64>,
    pub tcp_nodelay: Switch,
    pub allow_connect_method_proxying: Switch,
    pub h2c: Switch,
    pub ssl_provider: Option<LetsEncryptConfig>,
}

impl Default for Http {
    fn default() -> Self {
        Self {
            upstreams: Vec::new(),
            servers: Vec::new(),
            keepalive_timeout: KeepaliveTimeout::default(),
            keepalive_requests: None,
            client_max_body_size: None,
            proxy_cache_max_size: None,
            tcp_nodelay: Switch::On,
            allow_connect_method_proxying: Switch::Off,
            h2c: Switch::Off,
            ssl_provider: None,
        }
    }
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
    pub name: String,
    pub policy: UpstreamSelectionPolicy,
    pub servers: Vec<UpstreamServer>,
    pub health_check: Option<UpstreamHealthCheck>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UpstreamServer {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Default)]
pub enum UpstreamSelectionPolicy {
    #[default]
    RoundRobin,
    Random,
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
    pub directives: Vec<LocationDirective>, // proxy_pass, root, try_files...
    pub plugins: Vec<PluginSpec>,
    pub cache: Option<CacheConfig>,
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
}

#[derive(Debug, Eq, PartialEq)]
pub enum LocationMatcher {
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
    ProxyPass(ProxyPassTarget),
    ProxyConnectTimeout(Duration),
    ProxyReadTimeout(Duration),
    ProxyWriteTimeout(Duration),
    ProxyUpstreamProtocol(UpstreamHttpProtocol),
    ProxySslVerify(Switch),
    ProxySslTrustedCertificate(PemSource),
    Root(String),
    TryFiles(String),
    Return { status: u16, location: String },
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
