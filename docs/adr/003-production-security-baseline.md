# ADR-003: Production Security Baseline

## Context

The in-memory response cache can currently serve a hit before authentication
plugins run, reuse entries after a live snapshot change, and buffer an
oversized response before enforcing its configured limit. Management listeners
also allow an unauthenticated non-loopback bind without an explicit warning.

## Decision

- run request plugins before cache lookup
- cache only safe GET requests and fail closed for credentials, conditional
  requests, `Vary`, cookies, and non-cacheable `Cache-Control` directives
- isolate entries by snapshot generation, route, host, and exact URI
- stop buffering as soon as an entry exceeds the effective cache size
- allow management listeners on loopback by default and require an explicit
  unsafe opt-in for non-loopback TCP binds
- expose `/readyz` for active configuration and usable TLS material while
  keeping `/healthz` as a liveness check
- reject unsupported programmatic IR instead of panicking or silently ignoring
  it

## Consequences

Cache hit rate can decrease, especially for authenticated requests and the
legacy `normalized_uri` mode. Existing remote management binds require an
explicit unsafe flag. PROXY protocol, distributed cache/rate limiting, and
authenticated remote management remain separate follow-up work.
