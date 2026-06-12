# Config Options

`ngxora` supports a focused nginx-style config subset.

This document is the source of truth for currently supported text-config directives, upstream policies, and built-in location plugins.

For `gRPC ApplySnapshot` reload semantics, see [docs/README.md](./README.md).

## HTTP Block

- `client_max_body_size <size>;`
  Sets the downstream request body limit. `0` disables the limit.
- `keepalive_timeout <idle> [header];`
  Sets downstream keepalive timeout. `0` disables keepalive timeout handling.
- `keepalive_requests <count>;`
  Sets the downstream keepalive request limit.
- `allow_connect_method_proxying on|off;`
  Enables or disables proxying of `CONNECT` requests.
- `h2c on|off;`
  Enables or disables cleartext HTTP/2 handling at the service level.
- `tcp_nodelay on|off;`
  `on` is the only supported value. `off` is rejected because Pingora enables `TCP_NODELAY` on accepted downstream sockets.
- `proxy_cache_max_size <size>;`
  Global default for per-location cache size. Overridden by `proxy_cache_max_size` in a `proxy_cache { ... }` block. Default if omitted: `50m`. Supports size suffixes: `k`/`K`, `m`/`M`, `g`/`G`.

## Upstream Blocks

Supported shape:

```nginx
upstream app_pool {
    policy random;
    server 127.0.0.1:8080;
    server 127.0.0.1:8081;

    health_check {
        type http;
        host app.internal;
        path /readyz;
        use_tls off;
        timeout 1s;
        interval 5s;
        consecutive_success 1;
        consecutive_failure 2;
    }
}
```

Supported directives:

- `server <host>:<port>;`
  Adds a static backend to the upstream group.
- `policy round_robin|random;`
  Selects backend balancing policy. Default is `round_robin`.
- `health_check { ... }`
  Configures active backend health checks for the upstream group.

Supported policies:

- `round_robin` - default policy
- `random`

`health_check {}` directives:

- `type tcp|http;`
  Selects check protocol. Default is `tcp`.
- `timeout <duration>;`
  Per-check connect/read timeout. Default is `1s`.
- `interval <duration>;`
  Period between checks. Default is `5s`.
- `consecutive_success <count>;`
  Number of successful checks required to mark a backend healthy. Default is `1`.
- `consecutive_failure <count>;`
  Number of failed checks required to mark a backend unhealthy. Default is `1`.
- `host <value>;`
  Required for `type http;`. Used as HTTP `Host` header and TLS SNI when `use_tls on;`.
  It does not select the backend address; backend connection still uses the `server <host>:<port>;` entries from the upstream pool.
- `path <value>;`
  HTTP check path. Default is `/`.
- `use_tls on|off;`
  Enables HTTPS health checks for `type http;`. Default is `off`.

Notes:

- `health_check` is configured per `upstream {}` block, not per `location {}`.
- Runtime scheduling is driven by the configured `interval`.
- gRPC snapshots expose the same shape under `UpstreamGroup.health_check`.
- For plain HTTP backends that do not route by virtual host, `host localhost;` is usually sufficient.
- For backends that depend on virtual host routing, set `host` to the hostname the application expects.
- For HTTPS health checks, `host` should match the backend certificate name because it is also used as TLS SNI.

## Server And Listener Options

- `listen <addr>:<port>;`
  Basic listener binding.
- `listen <port>;`
  Shorthand bind on wildcard address.
- `listen ... default_server;`
  Marks the server block as the listener default.
- `listen ... ssl;`
  Enables downstream TLS on the listener.
- `listen ... http2;`
  Enables HTTP/2 on TLS listeners.
- `listen ... http2_only;`
  Restricts TLS listener ALPN to HTTP/2 only.
- `server_name <name> ...;`
  Declares hostnames for virtual host routing.

## Downstream TLS Options

### Manual certificates

- `ssl_certificate <path>;`
  Server certificate for the listener. When present, the server uses manual
  certificate management.
- `ssl_certificate_key <path>;`
  Private key for the listener certificate.

### Let's Encrypt (ACME)

ngxora can automatically obtain and renew TLS certificates from Let's Encrypt.
Declare a global `ssl_provider letsencrypt` block inside `http`:

```nginx
http {
    ssl_provider letsencrypt {
        email admin@example.com;
    }

    server {
        server_name example.com;
        listen 443 ssl;

        location / {
            proxy_pass http://127.0.0.1:8080;
        }
    }
}
```

When `ssl_certificate` and `ssl_certificate_key` are **omitted** from a server
block, ngxora treats the server as Let's Encrypt-managed.  Certificates are
stored under the cache directory (`/var/lib/ngxora/certs` by default) and
renewed automatically.

If a server block explicitly provides `ssl_certificate`, it takes priority over
the global Let's Encrypt configuration.

`ssl_provider letsencrypt` directives:

| Directive | Arguments | Default | Description |
|---|---|---|---|
| `email` | `<address>` | — | Contact email registered with the ACME account. |
| `acme_directory` | `<url>` | `https://acme-v02.api.letsencrypt.org/directory` | ACME directory endpoint. Use the staging URL for testing. |
| `cache_dir` | `<path>` | `/var/lib/ngxora/certs` | Directory where obtained certificates are stored. |

Example with staging and custom cache:

```nginx
http {
    ssl_provider letsencrypt {
        acme_directory https://acme-staging-v02.api.letsencrypt.org/directory;
        email dev@example.com;
        cache_dir /data/ngxora/certs;
    }

    server {
        server_name api.example.com;
        listen 443 ssl;
        location / { proxy_pass http://backend; }
    }

    # This server uses a manually-provided certificate instead of LE:
    server {
        server_name internal.example.com;
        listen 443 ssl;
        ssl_certificate /etc/certs/internal.pem;
        ssl_certificate_key /etc/certs/internal-key.pem;
        location / { proxy_pass http://internal; }
    }
}
```

### TLS protocol and client verification

- `ssl_protocols TLSv1 TLSv1.2 TLSv1.3;`
  Sets downstream TLS protocol bounds.
- `ssl_verify_client off|optional|required;`
  Configures downstream client certificate verification.
- `ssl_client_certificate <path>;`
  Client CA bundle used with `ssl_verify_client`.

## Location Proxy Options

Supported proxy targets:

- direct upstream URL:
  `proxy_pass http://127.0.0.1:8080;`
- direct TLS upstream URL:
  `proxy_pass https://api.internal:8443;`
- named upstream group:
  `proxy_pass http://app_pool;`

Supported location directives:

- `proxy_connect_timeout <duration>;`
- `proxy_read_timeout <duration>;`
- `proxy_write_timeout <duration>;`
- `proxy_upstream_protocol h1|h2|h2c;`
- `proxy_ssl_verify on|off;`
  `off` disables both upstream certificate and hostname verification.
- `proxy_ssl_trusted_certificate <path>;`
  Sets a custom CA bundle for upstream TLS verification.
- `return <status> <location>;`
  Returns an HTTP redirect response (301, 302, 303, 307, or 308) with
  a `Location` header set to `<location>`. The request is not proxied
  to an upstream when this directive is present on a matched location.

  Example:

  ```nginx
  location /old {
      return 301 https://example.com/new;
  }

  location /temp {
      return 302 /temporary-destination;
  }
  ```

Notes:

- `proxy_ssl_trusted_certificate` currently requires an `openssl` build.
- There is no separate `send_timeout` directive today; upstream timeouts are modeled as `connect`, `read`, and `write`.
- `proxy_upstream_protocol h2` requires a TLS upstream target such as `proxy_pass https://...`.
- `proxy_upstream_protocol h2c` requires a plaintext upstream target such as `proxy_pass http://...`.
- Classic HTTP/1.1 WebSocket proxying works with plain `proxy_pass`; no extra `Upgrade` or `Connection` rewrite is required.
- For long-lived WebSocket tunnels, set `proxy_read_timeout` and `proxy_write_timeout` high enough for your workload.
- Do not use `listen ... http2_only` for classic WebSocket endpoints; the Upgrade handshake is an HTTP/1.1 flow.

Example:

```nginx
location /api/ {
    proxy_connect_timeout 3s;
    proxy_read_timeout 15s;
    proxy_write_timeout 20s;
    proxy_ssl_verify on;
    proxy_ssl_trusted_certificate /etc/ngxora/tls/upstream-ca.pem;
    proxy_pass https://app_pool;
}
```

Disable upstream verification only for local or disposable environments:

```nginx
location /lab/ {
    proxy_ssl_verify off;
    proxy_pass https://127.0.0.1:9443;
}
```

gRPC examples:

TLS upstream gRPC:

```nginx
server {
    listen 443 ssl http2;

    location /helloworld.Greeter/ {
        proxy_connect_timeout 3s;
        proxy_read_timeout 1h;
        proxy_write_timeout 1h;
        proxy_upstream_protocol h2;
        proxy_pass https://grpc-backend.internal:8443;
    }
}
```

Plaintext h2c upstream gRPC:

```nginx
http {
    h2c on;

    server {
        listen 8080;

        location /helloworld.Greeter/ {
            proxy_upstream_protocol h2c;
            proxy_pass http://127.0.0.1:50051;
        }
    }
}
```

WebSocket example:

```nginx
location /ws/ {
    proxy_connect_timeout 3s;
    proxy_read_timeout 1h;
    proxy_write_timeout 1h;
    proxy_pass http://127.0.0.1:7001;
}
```

## Built-In Location Plugins

### `headers`

Supported inside `location {}`:

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

### `basic_auth` / `basic-auth`

Supported inside `location {}` when the binary is built with `plugin-basic-auth`:

```nginx
location /admin/ {
    basic_auth {
        username demo;
        password s3cret;
        realm Admin Area;
    }

    proxy_pass http://127.0.0.1:8080;
}
```

Supported directives:

- `username <value>;`
- `password <value>;`
- `realm <value>;`

### `rate-limit` / `rate_limit`

Supported inside `location {}` when the binary is built with `plugin-rate-limit`:

```nginx
location /api/ {
    rate-limit {
        rate 10;
    }

    proxy_pass http://127.0.0.1:8080;
}
```

Supported directives:

- `rate <requests_per_second>;`

### `ext_authz`

Supported inside `location {}` when the binary is built with `plugin-ext-authz`.

Delegates request authentication to an external HTTP service, allowing request headers to be passed to the auth service, and response headers to be injected from the auth service upstream to your backend.

```nginx
location /api/ {
    ext_authz {
        # The external authorization endpoint
        uri http://127.0.0.1:9091/auth;
        
        # Sub-request timeout
        timeout 2000;
        
        # Headers extracted from client and passed to auth service
        pass_request_header Authorization;
        pass_request_header Cookie;
        
        # Headers extracted from 200 OK auth response and injected into the backend pipeline
        pass_response_header X-Remote-User;
        pass_response_header X-Role;
    }
    
    proxy_pass http://api_pool;
}
```

### `jwt_auth`

Supported inside `location {}` when the binary is built with `plugin-jwt-auth`.

Validates JSON Web Tokens in the `Authorization: Bearer <token>` header.

```nginx
location /secured-api/ {
    jwt_auth {
        # The cryptographic algorithm (e.g. HS256, RS256, ES256, EdDSA)
        algorithm RS256;
        
        # For HMAC algorithms (HS256/384/512), use 'secret'
        # secret "super-secret-key-phrase";
        
        # For RSA/ECDSA/EdDSA algorithms, use 'secret_file' to point to the public key PEM
        secret_file /etc/ngxora/certs/auth_pubkey.pem;
    }
    
    proxy_pass http://internal_api;
}
```

Directives:
- `algorithm <alg>;` : (**Required**) The JWT signing algorithm.
- `secret <value>;` : (**Required if HMAC**) The secret string for HS* algorithms.
- `secret_file <path>;` : (**Required if RSA/EC/Ed**) The path to the public key PEM file.

## Proxy Cache (Location-Level)

Cache configuration is location-scoped: enable it for specific paths only.
A location without cache directives does not cache responses.

### Inline form

Enable caching with defaults:

```nginx
location /api/ {
    proxy_cache on;
    proxy_pass http://127.0.0.1:8080;
}
```

Explicitly disable (e.g. for realtime endpoints):

```nginx
location /realtime/ {
    proxy_cache off;
    proxy_pass http://127.0.0.1:8080;
}
```

### Block form (recommended for fine-tuning)

```nginx
location /blog/ {
    proxy_cache {
        proxy_cache_ttl 5m;
        proxy_cache_stale_if_error 30s;
        proxy_cache_key normalized_uri;
        proxy_cache_valid 200 301 302;
        proxy_cache_max_size 256m;
    }
    proxy_pass http://127.0.0.1:8080;
}
```

### Supported cache directives

| Directive | Arguments | Default | Description |
|---|---|---|---|
| `proxy_cache` | `on` or `off` | — | Enable/disable caching for this location. When omitted, no caching occurs. |
| `proxy_cache_ttl` | `<duration>` | `60s` | How long a cached response stays fresh. |
| `proxy_cache_stale_if_error` | `<duration>` | — | Serve a stale cached response if proxying to the upstream fails. Adds `X-Cache: STALE`. The cached entry is eligible only while its age is less than `proxy_cache_ttl + proxy_cache_stale_if_error`. |
| `proxy_cache_key` | `uri`, `uri_and_method`, or `normalized_uri` | `uri` | Controls how the cache key is derived from the request. |
| `proxy_cache_min_uses` | `<count>` | — | Store a response only after the same cache key misses this many times. |
| `proxy_cache_valid` | `<status>...` | `200 301 404` | HTTP status codes eligible for caching. |
| `proxy_cache_max_size` | `<size>` | — | Per-location max cache size. Supports suffixes: `k`/`K`, `m`/`M`, `g`/`G`. |

### Cache key modes

| Mode | Key derivation |
|---|---|
| `uri` | Request URI path and query string (default). |
| `uri_and_method` | URI + HTTP method (e.g. `GET /api/users` vs `POST /api/users`). |
| `normalized_uri` | URI with sorted query parameters (stable keys regardless of param order). |

### Notes

- Cache is per-location: two locations with the same upstream do not share cache unless configured identically.
- Cache storage is in-memory. `proxy_cache_max_size` caps memory per location.
- Responses larger than the configured per-location max size are not cached.
- `proxy_cache off` explicitly disables caching for that location (useful to override a broader config).
- Responses with `Cache-Control: private`, `Cache-Control: no-store`, or `Set-Cookie` are not cached.
- `proxy_cache_valid` applies to the final response status after response plugins run.
