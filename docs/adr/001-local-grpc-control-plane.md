# ADR-001: gRPC Control Plane Transport

## Context

`ngxora` needs dynamic configuration updates, but the project is still small and should not inherit the operational complexity of a networked service mesh control plane.

## Decision

Use gRPC as the control API. Local agents use a Unix domain socket, while a
remote controller connects over TCP with mTLS:

- UDS is owner-only (`0600`) and remains local to the pod or process
- every TCP listener, including loopback, requires a server certificate, key,
  and dedicated controller client CA
- the client CA makes a client certificate mandatory; plaintext TCP is not
  supported
- certificate files are loaded once at startup from Secret-mounted paths
- the control-plane compiles desired state locally and pushes a full snapshot

## Consequences

- a remote controller has an authenticated encrypted transport without adding
  a service-mesh dependency
- certificate rotation requires a Pod/process rollout; hot reload is not part
  of this decision
- mTLS authenticates the issuing CA, but does not yet authorize individual
  certificate subjects or SANs
- listener topology is still bootstrap-sensitive; live apply is for snapshot state, not socket rebinding
