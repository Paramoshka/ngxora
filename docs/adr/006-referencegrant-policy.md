# ADR-006: ReferenceGrant Policy

## Context

Cross-namespace object references are a common source of accidental privilege escalation in Gateway API controllers.

## Decision

`ngxora` follows a strict allow policy:

- same-namespace refs are allowed by default
- cross-namespace refs require a matching `ReferenceGrant`
- this rule applies to both `backendRefs` and `certificateRefs`
- unsupported ref kinds are rejected even if a `ReferenceGrant` exists

Current supported cross-namespace references:

- `HTTPRoute` -> core `Service`
- `Gateway` `HTTPS` listener -> core `Secret`

## Consequences

- reference resolution stays explicit and auditable
- the control-plane can return `RefNotPermitted` early instead of letting the dataplane fail later
- adding new cross-namespace object types should be treated as a new ADR-worthy decision, not a casual extension
