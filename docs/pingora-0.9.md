# Pingora 0.9.0 integration

ngxora now uses Pingora 0.9.0 with OpenSSL. The dependency update brings the
upstream connection-pool, HTTP framing/parser and graceful-shutdown fixes.
See the [upstream release](https://github.com/cloudflare/pingora/releases/tag/0.9.0).

## Included in ngxora

- Configurable downstream HTTP/2 stream/header limits and receive windows.
- Configurable upstream HTTP/2 multiplexing and receive windows for ordinary,
  weighted, discovery and SCP routes, including live snapshot updates.
- Safe header mutations for tracing and SCP after removal of `DerefMut`.
- Migration of the admin metrics handler to `pingora-prometheus`, sharing the
  Prometheus 0.14 registry with ngxora's collectors.
- No replay of non-idempotent requests after an upstream connection is established.

The new downstream defaults are 100 concurrent streams and 64 KiB decoded
headers. Standard hop-by-hop header sanitization remains enabled, including
normalized WebSocket upgrades. These stricter defaults may affect workloads
that relied on the old permissive behavior. Upstream defaults remain unchanged.
See [HTTP/2 configuration](config-options.md#http2-limits-and-flow-control).

## Candidates for later work

| Capability | Current fit |
| --- | --- |
| HTTP/2 downstream idle timeout | Useful next addition for reclaiming idle client connections; independent from HTTP/1 keepalive policy. |
| Connection-age callbacks and transport timings | Useful for diagnostics and connection metrics; define the exported measurements first. |
| TLS handshake offload pool and socket/L4 buffers | Expose when measurements identify a handshake or I/O bottleneck. |
| Pre-TLS PROXY protocol callback | Enables a separate PROXY protocol feature, which also needs parsing and trusted-proxy configuration. |
| Upstream modules and dictionary compression | An extension point for a concrete compression feature; no current ngxora module requires it. |
| Pingora cache admission, expiration and eviction improvements | ngxora uses its own cache, so adopting these requires a separate cache integration. |

Per-upstream trusted CAs and client certificates are already supported. The new
rustls in-memory listener acceptor is not needed for ngxora's current OpenSSL
listener implementation.
