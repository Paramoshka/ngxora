# Examples

Each subdirectory is a self-contained demo:

| Directory | Description |
|---|---|
| `basic/` | Minimal config: `listen 8080` + `proxy_pass` to a local backend. |
| `le/` | Let's Encrypt / ACME with `docker-compose.yml`. |
| `tls/` | Manual TLS with `ssl_certificate` / `ssl_certificate_key`. |
| `multi-upstream-demo/` | Load-balanced upstream groups with `docker-compose.yml`. |
| `observability/` | Prometheus metrics + OpenTelemetry tracing + Jaeger, `docker-compose.yml`. |

Run any compose demo from its directory:

```bash
cd examples/observability && docker compose up
```

Standalone configs (no compose) can be run directly:

```bash
ngxora examples/basic/ngxora.conf
```
