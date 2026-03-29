# ADRs

This directory stores short Architecture Decision Records for `ngxora`.

Each ADR captures one durable decision:

- the context
- the decision
- the consequence

The goal is speed. In a new session, an agent should be able to read one or two ADRs and recover the architectural intent without scanning the whole codebase.

Current ADRs:

- [ADR-001](./001-local-grpc-control-plane.md): local gRPC control plane
- [ADR-002](./002-ir-and-snapshot-boundary.md): strict IR -> snapshot boundary
- [ADR-003](./003-gateway-status-and-condition-model.md): Gateway/HTTPRoute status handling
- [ADR-004](./004-tls-validation-strategy.md): TLS certificate validation and listener TLS behavior
- [ADR-005](./005-listener-restart-boundary.md): restart boundary for listeners and transport policy
- [ADR-006](./006-referencegrant-policy.md): cross-namespace reference policy
- [ADR-007](./007-httproute-extensionref-plugins.md): HTTPRoute plugin integration via ExtensionRef
