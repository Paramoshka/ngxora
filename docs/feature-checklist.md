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
| `try_files` | 🟡 | parsed only | ❌ | — | Runtime NOP |
| `root` | 🟡 | parsed only | ❌ | — | Runtime NOP |

## TLS

| Feature | Status | Text Config | gRPC | Reload | Notes |
|---|---|---|---|---|---|
| Downstream TLS | ✅ | `listen ... ssl` | Bootstrap | Restart | |
| SNI certificate selection | ✅ | `ssl_certificate{,_key}` | Bootstrap | Restart | Named + default |
| TLS protocol bounds | ✅ | `ssl_protocols` | Bootstrap | Restart | TLSv1–TLSv1.3 |
| Client cert verification | ✅ | `ssl_verify_client` | Bootstrap | Restart | off/optional/required |
| Upstream TLS verification | ✅ | `proxy_ssl_verify` | ✅ | Live | on/off |
| Upstream custom CA | ✅ | `proxy_ssl_trusted_certificate` | ✅ | Live | Requires `openssl` feature |
| mTLS to upstream | 🟡 | config parsed | ❌ | — | Client cert not wired in runtime |

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
| Per-location cache | ✅ | `proxy_cache { ... }` | ✅ | Live | In-memory LRU |
| `proxy_cache_ttl` | ✅ | ✅ | ✅ | Live | |
| `proxy_cache_stale_if_error` | ✅ | ✅ | ✅ | Live | `X-Cache: STALE` |
| `proxy_cache_key` | ✅ | ✅ | ✅ | Live | uri/uri_and_method/normalized_uri |
| `proxy_cache_valid` | ✅ | ✅ | ✅ | Live | Status code allowlist |
| `proxy_cache_max_size` | ✅ | ✅ | ✅ | Live | Global + per-location |
| `proxy_cache_min_uses` | ✅ | ✅ | ✅ | Live | First N cache misses before initial store |

## Built-in Plugins

| Plugin | Status | Text Config | gRPC | Phase | Notes |
|---|---|---|---|---|---|
| `headers` | ✅ | ✅ | ✅ | request/upstream/response | Add/Set/Remove |
| `cors` | ✅ | ✅ | ✅ | request/response | Preflight + headers |
| `basic-auth` | ✅ | ✅ | ✅ | request | RFC 7617 |
| `jwt-auth` | ✅ | ✅ | ✅ | request | HS256/RS256/ES256/EdDSA, jsonwebtoken 10.3 |
| `rate-limit` | ✅ | ✅ | ✅ | request | Per-IP sliding window |
| `ext-authz` | ✅ | ✅ | ✅ | request | External HTTP auth |
| **IP allow/deny** | 🔧 | — | — | request | nginx `allow`/`deny` analog |

## Observability

| Feature | Status | Notes |
|---|---|---|
| **Prometheus metrics** | 🔧 | Pingora depends on `prometheus` crate; expose `GET /metrics` |
| **Structured access log (JSON)** | 🔧 | Method, path, status, latency, upstream, cache |
| Request ID propagation | 💤 | Can be done via `headers` plugin |
| Tracing (OpenTelemetry) | 💤 | |

## Control Plane

| Feature | Status | Notes |
|---|---|---|
| gRPC `ApplySnapshot` | ✅ | Live route updates |
| gRPC `GetSnapshot` | ✅ | Runtime state export |
| gRPC over TCP | ✅ | `--grpc-addr` |
| gRPC over UDS | ✅ | `--grpc-uds` |
| In-process control plane | ✅ | No gRPC, direct calls |
| Reload matrix docs | ✅ | See `docs/README.md` reload matrix |

## Operations

| Feature | Status | Notes |
|---|---|---|
| Docker image | ✅ | `paramoshka/ngxora:main` |
| Graceful shutdown | ✅ | Pingora built-in |
| Dry-run `--check` | ✅ | `ngxora --check ngxora.conf` |
| Graceful reload (SIGHUP) | 💤 | Use gRPC for live updates |
| Let's Encrypt / ACME | 💤 | |
| Admin API endpoint | 💤 | Runtime inspection: routes, stats, cache |

---

# Production Roadmap

Three items to close before calling it production-ready:

1. 🔧 **IP allow/deny plugin** — `allow 10.0.0.0/8; deny all;` inside `location {}`
2. 🔧 **Prometheus metrics** — connection counts, request rates, cache hit ratio, upstream health
3. 🔧 **Structured access log** — JSON lines with method, path, status, latency, upstream, cache

Nice to have shortly after:

4. 🟡 Fill in gRPC path for `try_files`, `root`
5. 🟡 Document reload matrix explicitly (which fields are Live vs Restart)
6. 💤 Graceful reload via SIGHUP
