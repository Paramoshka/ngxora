# ngxora

`ngxora` is a reverse proxy built on top of Pingora:
familiar like nginx on the outside, dynamic and programmable on the inside.

It aims for a simple split:
- nginx-style config for bootstrap and local development
- dynamic control-plane snapshots for live routing updates
- Pingora underneath for fast networking, TLS, pooling, and HTTP proxying

## Why

`ngxora` is for the case where plain nginx config still feels right, but the runtime should be able to evolve like a modern control-plane driven proxy.

- familiar `server` / `listen` / `location` / `proxy_pass`
- shared `:443` listeners with SNI-based certificate selection
- **automatic Let's Encrypt TLS** — declare `ssl_provider letsencrypt`, forget about cert files
- atomic route updates through runtime snapshots
- location-level in-memory response caching with stale-on-upstream-error fallback
- compile-time plugins for policy and request/response behavior
- Pingora-powered data plane

## Quick start (Docker)

Pull the published image:

```bash
docker pull paramoshka/ngxora:latest
```

Run it with the bundled example config:

```bash
docker run --rm -p 8080:8080 paramoshka/ngxora:latest
```

Then check the default route:

```bash
curl http://127.0.0.1:8080/
```

Run it with your own config:

```bash
docker run --rm \
  -p 8080:8080 \
  -v "$(pwd)/examples/basic/ngxora.conf:/etc/ngxora/ngxora.conf:ro" \
  paramoshka/ngxora:latest
```

## nginx-style config

```nginx
http {
    client_max_body_size 10m;
    keepalive_timeout 30s;

    upstream app_pool {
        # Optional: policy random;
        server 127.0.0.1:8080;
        server 127.0.0.1:8081;
    }

    server {
        listen 8080 default_server;
        server_name localhost;

        location / {
            headers {
                response_add X-Proxy ngxora;
            }
            proxy_pass http://app_pool;
        }
    }
}
```

Check config:

```bash
cargo run -- --check examples/basic/ngxora.conf
```

Run proxy:

```bash
cargo run -- examples/basic/ngxora.conf
```

Supported directives, upstream policies, and built-in plugin config are documented in [Config Options](./docs/config-options.md).

## Let's Encrypt (automatic TLS)

`ngxora` can obtain and renew TLS certificates from Let's Encrypt automatically.
Add `ssl_provider letsencrypt` to the `http` block and omit `ssl_certificate` /
`ssl_certificate_key` — the proxy handles the rest.

```nginx
http {
    ssl_provider letsencrypt {
        email admin@example.com;
        # cache_dir /var/lib/ngxora/certs;                     # optional, default shown
        # acme_directory https://acme-staging-v02.api.letsencrypt.org/directory;  # optional: staging for tests, omit for production
    }

    # HTTP-01 validation requires port 80 (TLS-ALPN-01 on 443 is planned)
    server {
        listen 80;
        server_name example.com;
        location / { return 301 https://$host$request_uri; }
    }

    server {
        listen 443 ssl;
        server_name example.com;
        # No ssl_certificate — LE manages it automatically

        location / {
            proxy_pass http://127.0.0.1:8080;
        }
    }
}
```

How it works:

- On startup, ngxora creates (or restores) an ACME account in `cache_dir/account.json`.
- Omit `acme_directory` for production; set it to the staging URL for testing without rate limits.
- For each server with `listen 443 ssl` and no explicit `ssl_certificate`, a certificate
  is obtained via HTTP-01 challenge.
- Certificates are stored as `{cache_dir}/{domain}/fullchain.pem` and
  `{cache_dir}/{domain}/privkey.pem`.
- A background task checks every hour and renews certificates expiring within 30 days.
- After a successful renewal, new TLS handshakes use the renewed certificate
  without restarting ngxora; existing TLS sessions continue normally.
- Explicit `ssl_certificate` in a `server` block takes priority over Let's Encrypt —
  useful when mixing LE and custom certificates.

See [Config Options](./docs/config-options.md) for all `ssl_provider letsencrypt` directives.

## WebSocket proxying

Classic HTTP/1.1 WebSocket proxying works with plain `proxy_pass`; `ngxora` does not require extra `Upgrade` or `Connection` rewrite directives for the common case.

```nginx
location /ws/ {
    proxy_connect_timeout 3s;
    proxy_read_timeout 1h;
    proxy_write_timeout 1h;
    proxy_pass http://127.0.0.1:7001;
}
```

Notes:

- use long enough `proxy_read_timeout` / `proxy_write_timeout` for idle WebSocket sessions
- do not use `listen ... http2_only` for classic WebSocket endpoints, because the Upgrade handshake is HTTP/1.1

## gRPC proxying

`ngxora` can proxy gRPC by selecting HTTP/2 on the upstream route explicitly.

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

Notes:

- `proxy_upstream_protocol h2` requires `https://...` upstream
- `proxy_upstream_protocol h2c` requires `http://...` upstream
- downstream TLS listeners still need `listen ... http2` or `http2_only` for browser/client-side HTTP/2
- plaintext downstream gRPC requires service-level `h2c on`

## SBI-ready proxying

The same HTTP/2 and upstream mTLS path can be used as a transport foundation for
5G Service-Based Interfaces. Upstream groups also support weights and stable
selection by a request header:

```nginx
upstream sbi_pool {
    policy consistent_hash;
    hash_key header X-Tenant-ID;
    server 10.20.0.11:8443 weight=3;
    server 10.20.0.12:8443 weight=1;
}
```

See [`examples/sbi-ready`](./examples/sbi-ready/) for a complete config and the
[3GPP Release 18 roadmap](./docs/3gpp-roadmap.md) for the boundary between the
available generic proxy features and planned SBI-aware behavior. `ngxora` does
not currently claim SCP, SEPP, NRF, or general 3GPP conformance.

## Dynamic config

The runtime applies routing, upstream, plugin, and existing-listener TLS updates
through atomic snapshots. Listener topology changes are reported as
`restart_required`.

For local control, start the gRPC control plane on a Unix domain socket:

```bash
cargo run -- --grpc-uds /tmp/ngxora-control.sock examples/basic/ngxora.conf
```

Inspect the current snapshot with the example Rust client:

```bash
cargo run -p ngxora-runtime --example get_snapshot -- --uds /tmp/ngxora-control.sock
```

Generate the Go control-plane SDK with:

```bash
make gen-go-sdk
```

See the [reload matrix](./docs/README.md), [snapshot schema](./docs/snapshot-schema.md),
and [Go SDK guide](./sdk/go/README.md) for the complete control-plane contract,
TCP mTLS setup, and live/restart boundaries.

## Plugins

Plugins are compiled in, not loaded through unstable runtime ABI tricks.

Current shape:
- plugin API crate
- plugin registry with feature-gated registration
- built-in `headers`, `basic-auth`, `rate-limit`, `cors`, `ext_authz`, and `jwt_auth` extensions
- `plugins.cfg` + `make build-bin` for build-time plugin selection

Text config syntax for built-in location plugins is documented in [Config Options](./docs/config-options.md).

Example `headers` usage:

```nginx
location /api/ {
    headers {
        request_set X-Route api;
        upstream_request_add X-From-Proxy ngxora;
        forward_client_ip on;
        trusted_proxy 10.0.0.0/8;
        response_add X-Proxy ngxora;
    }

    proxy_pass http://127.0.0.1:8080;
}
```

Example:

```text
# plugins.cfg
headers
```

```bash
make build-bin
```

## Pingora underneath

`ngxora` does not reimplement the hard parts of a proxy from scratch.
It leans on Pingora for the data plane:

- HTTP/1.1 and HTTP/2 proxying
- route-level upstream H1/H2/H2C selection for gRPC-style backends
- classic WebSocket proxying over HTTP/1.1 upgrade
- connection reuse and pooling
- TLS termination and upstream TLS
- automatic Let's Encrypt certificate issuance and renewal
- efficient async request handling
- a programmable proxy lifecycle

That gives `ngxora` a clean direction: nginx-like config ergonomics, control-plane style updates, and a serious proxy engine under the hood.
