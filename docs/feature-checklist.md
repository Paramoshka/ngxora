# Feature Checklist

`ngxora` has two config adapters:

- text config: `nginx-style config -> AST -> IR -> runtime model`
- control plane: `gRPC proto -> runtime model`

The rule is simple:

- one runtime capability
- one dataplane behavior
- two ways to feed it

## Legend

- ✅ Done — both adapters + tests + docs
- 🟡 Partial — text config works, gRPC path missing or stub
- 🔧 Planned — not yet implemented, needed for production
- 💤 Deferred — nice to have, not blocking

## Core Proxy

| Feature | Status | Text Config | gRPC | Reload | Notes |
|---|---|---|---|---|---|
| HTTP/1.1 reverse proxy | ✅ | `proxy_pass http://...` | ✅ | Live | Pingora dataplane |
| HTTPS/TLS reverse proxy | ✅ | `proxy_pass https://...` | ✅ | Live | SNI + upstream TLS |
| HTTP/2 downstream (TLS) | ✅ | `listen ... http2` | Bootstrap | Restart | ALPN negotiation |
| HTTP/2 cleartext (h2c) | ✅ | `h2c on;` | Bootstrap | Restart | |
| Upstream groups | ✅ | `upstream {}` | ✅ | Live | Round-robin, random |
| Upstream health checks | ✅ | `health_check {}` | ✅ | Live | TCP + HTTP |
| WebSocket proxying | ✅ | `proxy_pass` | ✅ | Live | Auto upgrade, no extra config |
| gRPC proxying (h2/h2c) | ✅ | `proxy_upstream_protocol` | ✅ | Live | |
| **Redirect** `return <status> <url>` | ✅ | `return 301 https://...` | ✅ | Live | Text config and gRPC snapshots map to the same runtime return target |
| `try_files` | 💤 | Rejected | ❌ | — | Not implemented; never silently ignored |
| `root` | 💤 | Rejected | ❌ | — | Not implemented; never silently ignored |

## TLS

| Feature | Status | Text Config | gRPC | Reload | Notes |
|---|---|---|---|---|---|
| Downstream TLS | ✅ | `listen ... ssl` | Bootstrap | Restart | |
| SNI certificate selection | ✅ | `ssl_certificate{,_key}` | Bootstrap | Restart | Named + default |
| TLS protocol bounds | ✅ | `ssl_protocols` | Bootstrap | Restart | TLSv1–TLSv1.3 |
| Client cert verification | ✅ | `ssl_verify_client` | Bootstrap | Restart | off/optional/required |
| Upstream TLS verification | ✅ | `proxy_ssl_verify` | ✅ | Live | on/off |
| Upstream custom CA | ✅ | `proxy_ssl_trusted_certificate` | ✅ | Live | Requires `openssl` feature |
| mTLS to upstream | ✅ | ✅ | ✅ | Live | Client cert wired via `proxy_ssl_certificate`/`proxy_ssl_certificate_key` |

## Timeouts & Limits

| Feature | Status | Text Config | gRPC | Reload | Notes |
|---|---|---|---|---|---|
| `proxy_connect_timeout` | ✅ | ✅ | ✅ | Live | |
| `proxy_read_timeout` | ✅ | ✅ | ✅ | Live | |
| `proxy_write_timeout` | ✅ | ✅ | ✅ | Live | |
| `keepalive_timeout` | ✅ | ✅ | Bootstrap | Restart | |
| `keepalive_requests` | ✅ | ✅ | Bootstrap | Restart | |
| `client_max_body_size` | ✅ | ✅ | Bootstrap | Restart | Enforced per-request |
| `tcp_nodelay` | 🟡 | `on` only | ✅ | Bootstrap | Pingora forces `TCP_NODELAY`; `off` is rejected |

## Caching

| Feature | Status | Text Config | gRPC | Reload | Notes |
|---|---|---|---|---|---|
| Per-location cache | ✅ | `proxy_cache { ... }` | ✅ | Live | Bounded in-memory cache |
| `proxy_cache_ttl` | ✅ | ✅ | ✅ | Live | |
| `proxy_cache_stale_if_error` | ✅ | ✅ | ✅ | Live | `X-Cache: STALE` |
| `proxy_cache_key` | ✅ | ✅ | ✅ | Live | Snapshot/route/host isolation; `normalized_uri` is exact-URI compatibility mode |
| `proxy_cache_valid` | ✅ | ✅ | ✅ | Live | Status code allowlist |
| `proxy_cache_max_size` | ✅ | ✅ | ✅ | Live | Global + per-location |
| `proxy_cache_min_uses` | ✅ | ✅ | ✅ | Live | First N cache misses before initial store |

## Built-in Plugins

| Plugin | Status | Text Config | gRPC | Phase | Notes |
|---|---|---|---|---|---|
| `headers` | ✅ | ✅ | ✅ | request/upstream/response | Add/Set/Remove + trusted client IP forwarding |
| `cors` | ✅ | ✅ | ✅ | request/response | Preflight + headers |
| `basic-auth` | ✅ | ✅ | ✅ | request | RFC 7617 |
| `jwt-auth` | ✅ | ✅ | ✅ | request | HS256/RS256/ES256/EdDSA, jsonwebtoken 10.3 |
| `rate-limit` | ✅ | ✅ | ✅ | request | Per-IP sliding window |
| `ext-authz` | ✅ | ✅ | ✅ | request | External HTTP auth |
| **IP allow/deny** | 🔧 | — | — | request | nginx `allow`/`deny` analog |

## Observability

| Feature | Status | Notes |
|---|---|---|
| **Prometheus metrics** | ✅ | `prometheus` 0.13; `GET /metrics` via `--metrics-addr <host:port>` |
| **Structured access log (JSON)** | ✅ | Method, path, status, latency, upstream, cache; `ngxora_access` log target |
| Request ID propagation | 💤 | Can be done via `headers` plugin |
| Tracing (OpenTelemetry) | ✅ | W3C TraceContext, OTLP/gRPC via `--otel-endpoint` |

## Control Plane

| Feature | Status | Notes |
|---|---|---|
| gRPC `ApplySnapshot` | ✅ | Live route updates |
| gRPC `GetSnapshot` | ✅ | Runtime state export |
| gRPC over TCP | ✅ | Loopback by default; non-loopback requires `--unsafe-grpc-listen` and a private/firewalled network |
| gRPC over UDS | ✅ | `--grpc-uds`; socket mode `0600` |
| In-process control plane | ✅ | No gRPC, direct calls |
| Reload matrix docs | ✅ | See `docs/README.md` reload matrix |

## Operations

| Feature | Status | Notes |
|---|---|---|
| Docker image | ✅ | `paramoshka/ngxora:main` |
| Graceful shutdown | ✅ | Pingora built-in |
| Dry-run `--check` | ✅ | `ngxora --check ngxora.conf` |
| Liveness probe (`GET /healthz`) | ✅ | Served by `--metrics-addr` alongside `/metrics` |
| Readiness probe (`GET /readyz`) | ✅ | Active listeners + valid, current TLS cert/key material |
| Graceful reload (SIGHUP) | 💤 | Use gRPC for live updates |
| Let's Encrypt / ACME | ✅ | `instant-acme`, HTTP-01 challenges, background reconciler every 1h |
| Admin API endpoint | 💤 | Runtime inspection: routes, stats, cache |

---

# Production Roadmap

## Blockers for serious production

1. ✅ **Fail-closed cache safety** — authentication runs before lookup; private/conditional requests bypass; snapshots and hosts are isolated; response buffering is bounded.
2. ✅ **Safe management defaults** — remote unauthenticated TCP binds require an explicit unsafe opt-in; prefer loopback or gRPC UDS.
3. ✅ **Non-panicking IR validation** — unsupported programmatic IR is rejected before runtime.
4. 🔴 **Externalize rate-limit and cache backends** — both are in-process (`DashMap`), not shared across replicas. Add an optional shared backend before relying on consistent limits/cache across replicas.

## Useful before real load

5. ✅ **Separate liveness/readiness endpoints** — `/healthz` checks the process; `/readyz` checks active config and TLS material.
6. 🔧 **IP allow/deny** — `allow 10.0.0.0/8; deny all;` inside `location {}`.
7. 🔧 **SIGHUP live-reload for text config** — currently only gRPC `ApplySnapshot` or full restart.
8. 🔧 **PROXY protocol for trusted L4 load balancers** — requires a pre-TLS integration point in the listener stack.

## Nice to have

9. 💤 **HTTP/3 (QUIC)** — blocked on Pingora upstream support.
10. 💤 **Admin API** — runtime inspection: routes, stats, cache state.
11. 💤 **Static files (`try_files`, `root`)** — unsupported directives are rejected rather than accepted as NOPs.
