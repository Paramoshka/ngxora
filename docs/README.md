# Downstream Options And gRPC Reload Matrix

`ngxora` currently treats file config as bootstrap input, so any text config change still means process restart.

The table below describes `gRPC ApplySnapshot` behavior for the current runtime model.

For supported directives, upstream policies, and built-in plugin syntax, see [Config Options](./config-options.md).

For implementation discipline on new options and plugins, see [Feature Checklist](./feature-checklist.md).

For durable architecture choices, see [ADRs](./adr/README.md).

For module responsibilities and security boundaries, see [Code Architecture](./architecture.md).

For the runtime payload boundary, see [Snapshot Schema](./snapshot-schema.md).

## Downstream Config

```nginx
http {
    upstream app_pool {
        # Optional: policy random;
        server 127.0.0.1:8443;
        server 127.0.0.1:9443;
    }

    client_max_body_size 10m;
    keepalive_timeout 60s;
    keepalive_requests 1000;
    allow_connect_method_proxying off;
    h2c off;
    tcp_nodelay on;

    server {
        listen 0.0.0.0:443 ssl http2 default_server;
        server_name example.com www.example.com;

        ssl_certificate /etc/ngxora/tls/example.crt;
        ssl_certificate_key /etc/ngxora/tls/example.key;
        ssl_protocols TLSv1.2 TLSv1.3;
        ssl_verify_client optional;
        ssl_client_certificate /etc/ngxora/tls/client-ca.pem;

        location / {
            proxy_connect_timeout 3s;
            proxy_read_timeout 30s;
            proxy_write_timeout 30s;
            headers {
                request_set X-Tenant edge;
                upstream_request_add X-From-Proxy ngxora;
                response_add X-Proxy ngxora;
            }
            proxy_pass https://app_pool;
        }
    }
}
```

## Reload Matrix

On Unix, send `SIGHUP` to ngxora to reread its original text configuration and
includes: `kill -HUP <pid>` or `docker kill --signal=HUP <container>`. Parsing,
compilation, plugin and TLS validation use the same snapshot application path as
gRPC. Invalid changes and changes requiring restart leave the current snapshot
active; the reason is written to stderr. Successful reloads report the new
generation. A reload applies the whole file configuration, so it replaces any
intervening gRPC configuration. Use one configuration owner per deployment.
The GeoIP database watcher remains independent of text-config reload.

| Option | Scope | gRPC ApplySnapshot | Notes |
| --- | --- | --- | --- |
| `geoip` | HTTP | Restart | Local MMDB contents reload automatically; City/Country enrich upstream headers and access logs |
| `location` / `proxy_pass` | route | Live | Applied through `RuntimeState` swap |
| `scp` / `scp_pass` | profile / route | Live | Unchanged discovery templates retain per-profile caches; changed profiles are replaced; HTTP/2 listener settings remain bootstrap-only |
| `upstream` blocks / backend sets | upstream group | Live | Rebuilds changed weighted/NRF-discovered pools, selection state, hash keys, and health checks; unchanged groups retain runtime discovery state |
| `proxy_connect_timeout` / `proxy_read_timeout` / `proxy_write_timeout` | route | Live | Applied to `HttpPeer.options` per selected upstream route |
| `proxy_upstream_protocol` | route | Live | Applies upstream H1/H2/H2C selection per route; downstream listener HTTP/2 policy is still bootstrap-only |
| `proxy_ssl_verify` | route | Live | Applied to upstream certificate and hostname verification flags per selected route |
| `proxy_ssl_trusted_certificate` | route | Live | Custom upstream CA bundle is loaded per snapshot and attached to the selected upstream peer |
| `proxy_ssl_certificate` / `proxy_ssl_certificate_key` | route | Live | Upstream mTLS client identity is loaded per snapshot and attached to the selected upstream peer |
| `server_name` | virtual host | Live | Host routing updates without restart |
| `ssl_certificate` / `ssl_certificate_key` | TLS identity | Live | Works for existing TLS listeners through runtime SNI cert lookup; successful Let's Encrypt renewals are used by new TLS handshakes without restart |
| plugin config | route | Live | Only if plugin code is already compiled into the binary |
| `allow` / `deny`, `allow_methods` | route | Live | Ordered ACL and method allowlist survive GetSnapshot/ApplySnapshot |
| `set_real_ip_from`, `real_ip_header`, `real_ip_recursive` | http | Live | Shared identity resolved before plugins |
| `client_header_timeout` | http | Live | HTTP/1 header deadline, including keepalive reuse; applies to new sessions |
| `client_body_timeout`, `send_timeout` | http, route | Live | Route overrides; HTTP/2 body timeout is unsupported and rejected |
| `client_max_body_size` | http, route | Live | Route override; Content-Length precheck and streaming body enforcement |
| `keepalive_timeout` | http | Live | Applied per downstream session in request path |
| `listen addr:port` | listener | Restart required | New or removed socket cannot be rebound live |
| `listen ... ssl` | listener | Restart required | Transport stack changes |
| `listen ... http2` | TLS listener | Restart required | ALPN is configured when listener is built |
| `listen ... http2_only` | TLS listener | Restart required | ALPN is configured when listener is built |
| `http2_*` | service | Restart required | HTTP/2 stream/header limits and receive windows |
| `proxy_http2_*` | location | Live | Applied to upstream connections in the new snapshot generation |
| `h2c` | service/plain HTTP | Restart required | `HttpProxy.server_options` is bootstrap-only today |
| `keepalive_requests` | service | Restart required | `HttpProxy.server_options` is bootstrap-only today |
| `allow_connect_method_proxying` | service | Restart required | `HttpProxy.server_options` is bootstrap-only today |
| `ssl_protocols` | TLS listener | Restart required | TLS min/max protocol version is configured in `TlsSettings` at bind time |
| `ssl_verify_client` | TLS listener | Restart required | Client certificate verification mode is configured at bind time |
| `ssl_client_certificate` | TLS listener | Restart required | Client CA bundle is configured at bind time |
| `tcp_nodelay` | http | Bootstrap only | Pingora enables `TCP_NODELAY` on accepted downstream sockets; `tcp_nodelay off` is rejected |

## Current Rule

`ApplySnapshot` is live only for:

- routing
- upstream target selection
- upstream HTTP protocol selection (`h1`, `h2`, `h2c`)
- upstream TLS verification policy and trusted CA bundle
- upstream mTLS client identity (`proxy_ssl_certificate` / `proxy_ssl_certificate_key`)
- plugin chains
- downstream request body limit
- downstream keepalive timeout
- SNI certificate map on already opened TLS listeners

`ApplySnapshot` returns `restart_required=true` when bootstrap transport configuration changes:

- listener sockets
- listener ALPN / HTTP protocol policy
- service-level downstream protocol flags
- TLS version bounds
- downstream mTLS verification settings

This split is intentional: route state is runtime data, while listener and service transport settings are still constructed once during Pingora bootstrap.
