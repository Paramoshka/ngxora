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
- atomic route updates through runtime snapshots
- compile-time plugins for policy and request/response behavior
- Pingora-powered data plane

## Quick start

Pull the published image:

```bash
docker pull paramoshka/ngxora:main
```

Run it with the bundled example config:

```bash
docker run --rm -p 8080:8080 paramoshka/ngxora:main
```

Then check the default route:

```bash
curl http://127.0.0.1:8080/
```

Run it with your own config:

```bash
docker run --rm \
  -p 8080:8080 \
  -v "$(pwd)/examples/ngxora.conf:/etc/ngxora/ngxora.conf:ro" \
  paramoshka/ngxora:main
```

## nginx-style config

```nginx
http {
    keepalive_timeout 30s;

    server {
        listen 8080 default_server;
        server_name localhost;

        location / {
            headers {
                response_add X-Proxy ngxora;
            }
            proxy_pass http://example.com;
        }
    }
}
```

Check config:

```bash
cargo run -- --check examples/ngxora.conf
```

Run proxy:

```bash
cargo run -- examples/ngxora.conf
```

## Dynamic config

The runtime is built around atomic snapshot apply:

- routing can be swapped live
- upstreams can be changed live
- SNI certificate maps can be changed live on existing listeners
- listener topology changes are detected and reported as `restart_required`

The gRPC transport for the control plane is the intended next layer on top of this runtime model.

You can now start the built-in Rust gRPC control plane alongside the proxy:

```bash
cargo run -- --grpc-addr 127.0.0.1:50051 examples/ngxora.conf
```

For sidecar-style local control, use a Unix domain socket instead:

```bash
cargo run -- --grpc-uds /tmp/ngxora-control.sock examples/ngxora.conf
```

And inspect the current snapshot with the example Rust client:

```bash
cargo run -p ngxora-runtime --example get_snapshot -- --uds /tmp/ngxora-control.sock
```

Push a minimal replacement snapshot back into `ngxora`:

```bash
cargo run -p ngxora-runtime --example apply_snapshot -- \
  --uds /tmp/ngxora-control.sock \
  --version manual-v2 \
  --server-name localhost \
  --upstream-host example.com \
  --upstream-port 80
```

## Security roadmap

The runtime control-plane model is meant for trusted environments until the networked gRPC layer is fully hardened.

Planned hardening work:
- authenticated and authorized gRPC control-plane access
- rate limiting and audit logging for snapshot operations
- protected-header policy for mutation plugins such as `headers`

In practice, this means route and TLS snapshot updates are already part of the runtime model, but the public control-plane surface and plugin guardrails are still being tightened.

## Plugins

Plugins are compiled in, not loaded through unstable runtime ABI tricks.

Current shape:
- plugin API crate
- plugin registry with feature-gated registration
- `headers` extension as the first simple plugin
- `plugins.cfg` + `make build-bin` for build-time plugin selection

Near-term plugin roadmap:
- `basic_auth`
- `cors`
- `rate_limit`

Later plugin roadmap:
- `geoip`
- `jwt_auth`
- `cache`
- `ext_authz`

Text config can now attach the built-in `headers` plugin inside a `location` block:

```nginx
location /api/ {
    headers {
        request_set X-Route api;
        upstream_request_add X-From-Proxy ngxora;
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
- connection reuse and pooling
- TLS termination and upstream TLS
- efficient async request handling
- a programmable proxy lifecycle

That gives `ngxora` a clean direction: nginx-like config ergonomics, control-plane style updates, and a serious proxy engine under the hood.
