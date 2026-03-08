use std::fmt::Error;
// Intermediate Representation layer
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::Duration;

use url::Url;

#[derive(Debug, Eq, PartialEq, Default)]
pub struct Ir {
    pub http: Option<Http>,
    // events ?
}

#[derive(Debug, Eq, PartialEq)]
pub struct Http {
    pub servers: Vec<Server>,
    pub keepalive_timeout: KeepaliveTimeout,
    pub keepalive_requests: Option<u32>,
    pub tcp_nodelay: Switch,
    pub allow_connect_method_proxying: Switch,
    pub h2c: Switch,
}

impl Default for Http {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            keepalive_timeout: KeepaliveTimeout::default(),
            keepalive_requests: None,
            tcp_nodelay: Switch::On,
            allow_connect_method_proxying: Switch::Off,
            h2c: Switch::Off,
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
    pub tls: Option<TlsIdentity>,
    pub tls_options: DownstreamTlsOptions,
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

#[derive(Debug, Clone, PartialEq, Eq)]
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
}

#[derive(Debug, Copy, Clone, Eq, PartialEq, Default)]
pub struct UpstreamTimeouts {
    pub connect: Option<Duration>,
    pub read: Option<Duration>,
    pub write: Option<Duration>,
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
    ProxyPass(Url),
    ProxyConnectTimeout(Duration),
    ProxyReadTimeout(Duration),
    ProxyWriteTimeout(Duration),
    Root(String),
    TryFiles(String),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Switch {
    On,
    Off,
}
