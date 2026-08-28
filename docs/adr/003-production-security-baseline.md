# ADR-003: Production Security Baseline

## Context

The in-memory response cache can currently serve a hit before authentication
plugins run, reuse entries after a live snapshot change, and buffer an
oversized response before enforcing its configured limit. The TCP gRPC control
plane also needs a transport boundary suitable for a remote controller.

## Decision

- run request plugins before cache lookup
- cache only safe GET requests and fail closed for credentials, conditional
  requests, `Vary`, cookies, and non-cacheable `Cache-Control` directives
- isolate entries by snapshot generation, route, host, and exact URI
- stop buffering as soon as an entry exceeds the effective cache size
- require mTLS with a dedicated controller client CA for every TCP gRPC bind
- expose `/readyz` for active configuration and usable TLS material while
  keeping `/healthz` as a liveness check
- reject unsupported programmatic IR instead of panicking or silently ignoring
  it

## Consequences

Cache hit rate can decrease, especially for authenticated requests and the
legacy `normalized_uri` mode. TCP gRPC deployments need Secret-mounted
certificate material and a rollout when it rotates. PROXY protocol,
distributed cache/rate limiting, and authorization of individual controller
certificate identities remain separate follow-up work.
