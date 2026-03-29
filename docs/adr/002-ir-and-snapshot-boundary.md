# ADR-002: Strict IR And Snapshot Boundary

## Context

The easiest way to degrade a dataplane project is to let raw Kubernetes objects leak into runtime config generation.

## Decision

Keep a strict pipeline:

`HTTPRoute` / text config -> normalized internal representation -> compiled snapshot -> runtime

Rules:

- translators may read Kubernetes objects
- snapshot builder reads only normalized desired state
- runtime reads only compiled snapshot
- raw `HTTPRoute`, `Gateway`, `Secret`, or `Service` objects do not enter the runtime layer

## Consequences

- one predictable dataplane behavior regardless of config source
- less accidental coupling between Kubernetes API shapes and Pingora runtime
- easier validation, testing, and future adapters
