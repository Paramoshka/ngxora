# ADR-001: Local gRPC Control Plane

## Context

`ngxora` needs dynamic configuration updates, but the project is still small and should not inherit the operational complexity of a networked service mesh control plane.

## Decision

Use gRPC as the control API, but keep it local to the pod or process:

- control-plane and dataplane are co-located
- transport is UDS or loopback
- the control-plane compiles desired state locally and pushes a full snapshot

## Consequences

- simpler trust boundary and debugging model
- no day-one authn/authz or multi-tenant control-plane problems
- future migration to remote gRPC control-plane stays possible
- listener topology is still bootstrap-sensitive; live apply is for snapshot state, not socket rebinding
