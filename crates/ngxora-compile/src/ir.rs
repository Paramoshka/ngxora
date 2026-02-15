use std::fmt::Error;
// Intermediate Representation layer
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use url::Url;

#[derive(Debug, Eq, PartialEq, Default)]
pub struct Ir {
    pub http: Option<Http>,
    // events ?
}

#[derive(Debug, Eq, PartialEq)]
pub struct Http {
    pub servers: Vec<Server>,
    pub keepalive_timeout: String,
    pub tcp_nodelay: Switch,
}

impl Default for Http {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            keepalive_timeout: "60s".to_string(),
            tcp_nodelay: Switch::On,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Default)]
pub struct Server {
    pub server_names: Vec<String>,
    pub locations: Vec<Location>,
    pub listens: Vec<Listen>,
    pub tls: Option<TlsIdentity>,
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
}

impl Default for Listen {
    fn default() -> Self {
        Self {
            addr: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            port: 80,
            ssl: false,
            default_server: false,
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Location {
    pub matcher: LocationMatcher,
    pub directives: Vec<LocationDirective>, // proxy_pass, root, try_files...
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
    Root(String),
    TryFiles(String),
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum Switch {
    On,
    Off,
}
