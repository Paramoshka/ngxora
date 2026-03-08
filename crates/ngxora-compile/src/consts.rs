pub const HTTP: &str = "http";
pub const SERVER: &str = "server";
pub const LOCATION: &str = "location";

pub const LISTEN: &str = "listen";
pub const SERVER_NAME: &str = "server_name";

// Inner directives in blocs
pub const TCP_NODELAY: &str = "tcp_nodelay";
pub const KEEPALIVE_TIMEOUT: &str = "keepalive_timeout";
pub const KEEPALIVE_REQUESTS: &str = "keepalive_requests";
pub const ALLOW_CONNECT_METHOD_PROXYING: &str = "allow_connect_method_proxying";
pub const H2C: &str = "h2c";
pub const HTTP2: &str = "http2";
pub const HTTP2_ONLY: &str = "http2_only";

// Listener directives
pub const PROXY_PASS: &str = "proxy_pass";
pub const PROXY_CONNECT_TIMEOUT: &str = "proxy_connect_timeout";
pub const PROXY_READ_TIMEOUT: &str = "proxy_read_timeout";
pub const PROXY_WRITE_TIMEOUT: &str = "proxy_write_timeout";

// TLS CERTS
pub const SSL_CERTIFICATE: &str = "ssl_certificate";
pub const SSL_CERTIFICATE_KEY: &str = "ssl_certificate_key";
pub const SSL_PROTOCOLS: &str = "ssl_protocols";
pub const SSL_VERIFY_CLIENT: &str = "ssl_verify_client";
pub const SSL_CLIENT_CERTIFICATE: &str = "ssl_client_certificate";
