# ADR-005: Listener Restart Boundary

## Context

`ngxora` supports live `ApplySnapshot`, but Pingora listener sockets and transport policy are still created during bootstrap.

## Decision

Treat listener topology and bootstrap transport settings as restart-sensitive.

Live snapshot apply is allowed for:

- virtual hosts
- routes
- upstream groups
- plugin chains
- SNI certificate maps on already opened TLS listeners

Restart is required for:

- new or removed listen sockets
- switching plaintext/TLS transport
- ALPN / downstream HTTP protocol policy
- service-level downstream protocol flags
- listener TLS protocol bounds and downstream mTLS verification settings

## Consequences

- control-plane code must keep bootstrap listener topology aligned with intended runtime topology
- quick start and examples must pre-create the sockets they expect to use later
- if a change crosses this boundary, `ApplySnapshot` should report `restart_required=true` instead of partially mutating transport state
