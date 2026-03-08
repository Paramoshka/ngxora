# Downstream Options And gRPC Reload Matrix

`ngxora` currently treats file config as bootstrap input, so any text config change still means process restart.

The table below describes `gRPC ApplySnapshot` behavior for the current runtime model.

For implementation discipline on new options and plugins, see [Feature Checklist](/home/ivan/projects/pet/ngxora/docs/feature-checklist.md).

## Downstream Config

```nginx
http {
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
            proxy_pass https://127.0.0.1:8443;
        }
    }
}
```

## Headers Plugin In Text Config

The built-in `headers` plugin can be attached directly inside a `location` block.

```nginx
location /api/ {
    headers {
        request_add X-Env dev;
        request_set X-Route api;
        request_remove X-Debug;

        upstream_request_add X-From-Proxy ngxora;
        upstream_request_set X-Upstream-Route api;
        upstream_request_remove X-Legacy;

        response_add X-Proxy ngxora;
        response_set Cache-Control no-store;
        response_remove X-Powered-By;
    }

    proxy_pass http://127.0.0.1:8080;
}
```

## Reload Matrix

| Option | Scope | gRPC ApplySnapshot | Notes |
| --- | --- | --- | --- |
| `location` / `proxy_pass` | route | Live | Applied through `RuntimeState` swap |
| `proxy_connect_timeout` / `proxy_read_timeout` / `proxy_write_timeout` | route | Live | Applied to `HttpPeer.options` per selected upstream route |
| `server_name` | virtual host | Live | Host routing updates without restart |
| `ssl_certificate` / `ssl_certificate_key` | TLS identity | Live | Works for existing TLS listeners through runtime SNI cert lookup |
| plugin config | route | Live | Only if plugin code is already compiled into the binary |
| `keepalive_timeout` | http | Live | Applied per downstream session in request path |
| `listen addr:port` | listener | Restart required | New or removed socket cannot be rebound live |
| `listen ... ssl` | listener | Restart required | Transport stack changes |
| `listen ... http2` | TLS listener | Restart required | ALPN is configured when listener is built |
| `listen ... http2_only` | TLS listener | Restart required | ALPN is configured when listener is built |
| `h2c` | service/plain HTTP | Restart required | `HttpProxy.server_options` is bootstrap-only today |
| `keepalive_requests` | service | Restart required | `HttpProxy.server_options` is bootstrap-only today |
| `allow_connect_method_proxying` | service | Restart required | `HttpProxy.server_options` is bootstrap-only today |
| `ssl_protocols` | TLS listener | Restart required | TLS min/max protocol version is configured in `TlsSettings` at bind time |
| `ssl_verify_client` | TLS listener | Restart required | Client certificate verification mode is configured at bind time |
| `ssl_client_certificate` | TLS listener | Restart required | Client CA bundle is configured at bind time |
| `tcp_nodelay` | http | Not implemented | Parsed in IR, but currently not enforced on downstream sockets |

## Current Rule

`ApplySnapshot` is live only for:

- routing
- upstream target selection
- plugin chains
- downstream keepalive timeout
- SNI certificate map on already opened TLS listeners

`ApplySnapshot` returns `restart_required=true` when bootstrap transport configuration changes:

- listener sockets
- listener ALPN / HTTP protocol policy
- service-level downstream protocol flags
- TLS version bounds
- downstream mTLS verification settings

This split is intentional: route state is runtime data, while listener and service transport settings are still constructed once during Pingora bootstrap.
