// Intermediate Representation layer

#[derive(Debug, Eq, PartialEq, Default)]
pub struct Ir {
    pub http: Option<Http>,
    // events ?
}

#[derive(Debug, Eq, PartialEq)]
pub struct Http {
    pub servers: Vec<Server>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Server {
    pub server_names: Vec<String>,
    pub locations: Vec<Location>,
    pub listens: Vec<Listen>,
}

#[derive(Debug, Eq, PartialEq)]
pub struct Listen {
    pub endpoint: ListenEndpoint,
    pub params: Vec<String>, // flags and key=value
}

#[derive(Debug, Eq, PartialEq)]
pub enum ListenEndpoint {
    Tcp { addr: Option<String>, port: u16 }, // "127.0.0.1", "[::]", "*"
    Unix { path: String },
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
    ProxyPass(String),
    Root(String),
    TryFiles(String),
}
