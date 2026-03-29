# ADR-004: TLS Validation Strategy

## Context

`HTTPS` listeners are useless if the controller accepts malformed or unsupported certificate refs and only fails later in the dataplane.

## Decision

For `Gateway` `HTTPS` listeners:

- only `tls.mode: Terminate` is supported
- only a single core `Secret` `certificateRef` is supported
- cross-namespace refs require `ReferenceGrant`
- the Secret must contain a valid keypair
- the control-plane converts valid certs into snapshot TLS bindings
- runtime supports listener certs from inline PEM for live snapshot application

## Consequences

- bad TLS config fails early with `InvalidCertificateRef` or `RefNotPermitted`
- listener TLS remains compatible with the existing snapshot model
- multi-cert and richer TLS policy can be added later without changing the basic flow
