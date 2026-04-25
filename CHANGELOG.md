# Changelog

All notable user-visible changes to `ngxora` will be documented in this file.

This project follows a simple Keep a Changelog-style format.

## [Unreleased]

### Removed

- Kubernetes-oriented control-plane (Go sidecar) and all related Gateway API controller logic. The built-in Rust gRPC control-plane remains for dynamic configuration updates.

## [0.1.0] - 2026-03-14

Initial public release.

### Added

- nginx-style text config for `http`, `server`, `listen`, `server_name`, `location`, and `proxy_pass`
- Pingora-based reverse proxy runtime with HTTP proxying, TLS termination, and shared TLS listeners with SNI certificate selection
- dynamic runtime snapshots with in-process state swap and built-in gRPC control plane
- `upstream {}` blocks with multiple static backends and selectable `round_robin` / `random` policies
- route-level upstream timeouts: `proxy_connect_timeout`, `proxy_read_timeout`, and `proxy_write_timeout`
- route-level upstream TLS verification controls: `proxy_ssl_verify` and `proxy_ssl_trusted_certificate`
- built-in `headers` plugin for request, upstream-request, and response header mutation
- built-in `basic-auth` plugin for route protection with `401` + `WWW-Authenticate`
- example configs, multi-upstream demo compose setup, and Go SDK generation from `control.proto`
- dedicated config surface documentation in [docs/config-options.md](/home/ivan/projects/pet/ngxora/docs/config-options.md)

### Changed

- runtime reload semantics are now documented explicitly in [docs/README.md](/home/ivan/projects/pet/ngxora/docs/README.md)
- supported config directives, upstream policies, and built-in plugin syntax are documented in one place instead of being split across README sections

### Fixed

- wildcard listeners such as `0.0.0.0:PORT` and `[::]:PORT` now resolve routes correctly for concrete local socket addresses, which fixes shared-bind routing in Docker and similar environments

### Known Limitations

- text config is still bootstrap input; live changes are applied through `gRPC ApplySnapshot`
- listener topology and bootstrap transport settings still require restart
- the networked control plane is intended for trusted environments until authn/authz hardening is added
- `proxy_ssl_trusted_certificate` requires an `openssl` build
