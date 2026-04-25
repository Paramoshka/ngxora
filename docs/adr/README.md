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
