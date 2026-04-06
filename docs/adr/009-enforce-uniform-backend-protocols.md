# ADR-009: Enforce Uniform Backend Protocols per Route Rule

## Context

The Kubernetes Gateway API specification allows an `HTTPRouteRule` to define multiple `BackendRef` entries for a single rule path/match. In theory, this permits mixing backends with entirely different application protocols (e.g., mixing HTTP and HTTPS Services) within the same routing rule.

Our data-plane API (`ngxora` control protobuf definitions) configures the proxy `Scheme` strictly at the `Upstream` level, which applies to an entire `UpstreamGroup` containing multiple `UpstreamBackend`s. Supporting a heterogeneous mix of protocols within the same rule would require splitting a single Gateway API Rule into multiple Upstream Groups and introducing complex weight-based split logic within the proxy pipeline, or pushing protocol configuration directly into the foundational `UpstreamBackend` primitive.

## Decision

We will **explicitly reject heterogeneous backend protocols within a single `HTTPRouteRule`**. 

- During translation, the control-plane checks and resolves the communication protocols of all endpoints (`AppProtocol`) associated with a rule's backend references.
- If the endpoints resolve to mixed application protocols within the same rule (e.g., a mix of `http` and `https`), the control-plane halts resolution for that specific route.
- The control-plane writes a descriptive error strictly into the Route's `Status` block (setting the `ResolvedRefs` condition to `False`), explicitly indicating the protocol mismatch as the reason for configuration rejection.
- If all endpoints uniformly require HTTPS (or TLS), the upstream schema for the proxy is safely compiled as `https`.

## Consequences

- **Fail-Fast Feedback:** Users receive immediate, context-rich, Kubernetes-native feedback through the HTTPRoute `Status` if they attempt a questionable architectural pattern (such as mixing cleartext and encrypted traffic for the same application path).
- **Control-Plane Assurance:** The logic within `builder.go` remains deterministic. It is mathematically guaranteed that any rule reaching the configuration generation phase possesses a single, harmonized protocol scheme.
- **Data-Plane Simplicity:** The data-plane proxy implementation can maintain its simplified, highly-performant routing model, where security and protocol logic binds to the parent `UpstreamGroup` rather than individually tracking per-endpoint protocols.
