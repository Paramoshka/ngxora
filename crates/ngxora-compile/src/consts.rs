pub const HTTP: &str = "http";
pub const SERVER: &str = "server";
pub const UPSTREAM: &str = "upstream";
pub const LOCATION: &str = "location";
pub const HEADERS: &str = "headers";
pub const BASIC_AUTH: &str = "basic-auth";
pub const BASIC_AUTH_ALIAS: &str = "basic_auth";
pub const RATE_LIMIT: &str = "rate-limit";
pub const RATE: &str = "rate";

pub const CORS: &str = "cors";
pub const ALLOW_ORIGIN: &str = "allow_origin";
pub const ALLOW_METHODS: &str = "allow_methods";
pub const ALLOW_HEADERS: &str = "allow_headers";
pub const EXPOSE_HEADERS: &str = "expose_headers";
pub const ALLOW_CREDENTIALS: &str = "allow_credentials";
pub const MAX_AGE: &str = "max_age";

pub const EXT_AUTHZ: &str = "ext_authz";
pub const URI: &str = "uri";
pub const PASS_REQUEST_HEADER: &str = "pass_request_header";
pub const PASS_RESPONSE_HEADER: &str = "pass_response_header";

pub const JWT_AUTH: &str = "jwt_auth";
pub const ALGORITHM: &str = "algorithm";
pub const SECRET: &str = "secret";
pub const SECRET_FILE: &str = "secret_file";

pub const LISTEN: &str = "listen";
pub const SERVER_NAME: &str = "server_name";
pub const POLICY: &str = "policy";
pub const HEALTH_CHECK: &str = "health_check";
pub const TYPE: &str = "type";
pub const TIMEOUT: &str = "timeout";
pub const INTERVAL: &str = "interval";
pub const CONSECUTIVE_SUCCESS: &str = "consecutive_success";
pub const CONSECUTIVE_FAILURE: &str = "consecutive_failure";
pub const HOST: &str = "host";
pub const PATH: &str = "path";
pub const USE_TLS: &str = "use_tls";

// Inner directives in blocs
pub const TCP_NODELAY: &str = "tcp_nodelay";
pub const KEEPALIVE_TIMEOUT: &str = "keepalive_timeout";
pub const KEEPALIVE_REQUESTS: &str = "keepalive_requests";
pub const CLIENT_MAX_BODY_SIZE: &str = "client_max_body_size";
pub const ALLOW_CONNECT_METHOD_PROXYING: &str = "allow_connect_method_proxying";
pub const H2C: &str = "h2c";
pub const HTTP2: &str = "http2";
pub const HTTP2_ONLY: &str = "http2_only";

// Listener directives
pub const PROXY_PASS: &str = "proxy_pass";
pub const PROXY_CONNECT_TIMEOUT: &str = "proxy_connect_timeout";
pub const PROXY_READ_TIMEOUT: &str = "proxy_read_timeout";
pub const PROXY_WRITE_TIMEOUT: &str = "proxy_write_timeout";
pub const PROXY_UPSTREAM_PROTOCOL: &str = "proxy_upstream_protocol";
pub const PROXY_SSL_VERIFY: &str = "proxy_ssl_verify";
pub const PROXY_SSL_TRUSTED_CERTIFICATE: &str = "proxy_ssl_trusted_certificate";
pub const REQUEST_ADD: &str = "request_add";
pub const REQUEST_SET: &str = "request_set";
pub const REQUEST_REMOVE: &str = "request_remove";
pub const UPSTREAM_REQUEST_ADD: &str = "upstream_request_add";
pub const UPSTREAM_REQUEST_SET: &str = "upstream_request_set";
pub const UPSTREAM_REQUEST_REMOVE: &str = "upstream_request_remove";
pub const RESPONSE_ADD: &str = "response_add";
pub const RESPONSE_SET: &str = "response_set";
pub const RESPONSE_REMOVE: &str = "response_remove";
pub const USERNAME: &str = "username";
pub const PASSWORD: &str = "password";
pub const REALM: &str = "realm";

// TLS CERTS
pub const SSL_CERTIFICATE: &str = "ssl_certificate";
pub const SSL_CERTIFICATE_KEY: &str = "ssl_certificate_key";
pub const SSL_PROTOCOLS: &str = "ssl_protocols";
pub const SSL_VERIFY_CLIENT: &str = "ssl_verify_client";
pub const SSL_CLIENT_CERTIFICATE: &str = "ssl_client_certificate";
