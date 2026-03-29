# Implementation Plan - Go Mini Control Plane

This document is a first-pass implementation plan for a small Kubernetes-aware control plane for `ngxora`.

The scope is intentionally narrow:

- reconcile `HTTPRoute`
- translate it into `ngxora` snapshot intent
- push updates to the local `ngxora` dataplane over gRPC through UDS

This plan follows the recommendation in [Control Plane Architecture](./control-plane-architecture.md):

- keep control-plane and dataplane co-located
- keep gRPC as the control API
- use local-only transport by default
- keep Kubernetes integration outside the Rust workspace

## Goal

Build a small controller that runs next to `ngxora`, watches Kubernetes `HTTPRoute` objects, computes desired route state, and applies it to the local dataplane through the existing Go SDK.

This is not a mesh control plane and not a distributed config service.

## Why Go

For this component, Go is the better fit than adding a new Rust crate.

Reasons:

- Kubernetes controller tooling is much more mature in Go
- `controller-runtime` reduces boilerplate for watchers, reconciliation, and status updates
- the repository already has a generated Go SDK for `control.proto`
- this avoids pulling `kube`, `k8s-openapi`, and `gateway-api-rs` into the main Rust build graph

## Recommended Deployment Model

Default deployment model:

- one `ngxora` dataplane container
- one Go control-plane container in the same pod
- one shared Unix Domain Socket volume
- no network-exposed control API by default

Communication model:

- control-plane dials `ngxora` over UDS using the Go SDK
- dataplane exposes only local gRPC

This keeps the trust boundary small and matches the current project stage.

## Proposed Repository Shape

The control plane should live outside the Rust workspace.

Suggested layout:

```text
control-plane/go.mod
control-plane/cmd/ngxora-control-plane/main.go
control-plane/internal/controller/httproute_controller.go
control-plane/internal/translator/httproute.go
control-plane/internal/snapshot/builder.go
control-plane/internal/client/ngxora.go
control-plane/internal/config/config.go
control-plane/internal/status/conditions.go
control-plane/README.md
```

This keeps Kubernetes and controller concerns isolated from the Rust crates.

## High-Level Data Flow

The runtime flow should be:

`HTTPRoute` -> translator -> internal desired state -> snapshot builder -> gRPC `ApplySnapshot`

Important constraint:

- translation and policy expansion happen in the control plane
- request-time logic stays in the Rust dataplane

## Phase 1 Scope

Support only the minimal route model needed to prove the control path.

### In Scope

- watch `HTTPRoute`
- support hostname matching
- support `PathPrefix` and exact path matches
- support backend refs that resolve to Kubernetes `Service`
- produce one local snapshot version per reconcile loop
- apply snapshots over UDS to the local dataplane

### Out Of Scope

- full Gateway API coverage
- multi-namespace policy attachment
- distributed remote control-plane topology
- separate remote API server for the controller
- full plugin filter mapping on day one
- advanced status and condition reporting

## Initial Translation Contract

The translator should convert `HTTPRoute` into a small internal model, not directly into protobuf objects.

Example internal shape:

```go
type DesiredRoute struct {
    Hostnames []string
    Rules     []DesiredRule
}

type DesiredRule struct {
    PathMatch DesiredPathMatch
    Backends  []DesiredBackend
    Filters   []DesiredFilter
}

type DesiredPathMatch struct {
    Kind  string
    Value string
}

type DesiredBackend struct {
    Name      string
    Namespace string
    Port      int32
    Weight    int32
}
```

Then a separate builder converts this internal model into the `ngxora` snapshot/proto shape.

This keeps Kubernetes semantics and `ngxora` snapshot semantics decoupled.

## Proposed Changes

### New Go Module

#### [NEW] `/home/ivan/projects/ngxora/control-plane/go.mod`

- define a separate Go module for the controller
- depend on:
  - `sigs.k8s.io/controller-runtime`
  - `k8s.io/client-go`
  - Gateway API Go types
  - local `sdk/go` package from this repository

Suggested principle:

- prefer official Gateway API Go packages over introducing a custom generated model

### Control Plane Binary

#### [NEW] `/home/ivan/projects/ngxora/control-plane/cmd/ngxora-control-plane/main.go`

- initialize logger
- parse config
- open Kubernetes client
- open `ngxora` gRPC client over UDS
- start controller manager

### Controller

#### [NEW] `/home/ivan/projects/ngxora/control-plane/internal/controller/httproute_controller.go`

- reconcile `HTTPRoute`
- fetch referenced `Service` objects as needed
- call translator
- call snapshot builder
- call local `ngxora` client `ApplySnapshot`
- write minimal status/conditions

### Translator

#### [NEW] `/home/ivan/projects/ngxora/control-plane/internal/translator/httproute.go`

- map `HTTPRoute.spec.hostnames`
- map supported path matches
- map backend refs to internal desired backends
- map supported Gateway filters into internal filter representations

Initial supported filters should be narrow.

Suggested first set:

- request header add/set/remove
- response header add/set/remove

These map well to the existing `headers` plugin behavior.

### Snapshot Builder

#### [NEW] `/home/ivan/projects/ngxora/control-plane/internal/snapshot/builder.go`

- convert internal desired state into `control.v1.ConfigSnapshot`
- produce deterministic snapshot versions
- ensure stable ordering for hosts, rules, and backends

This builder should be deterministic so repeated reconciles do not create useless churn.

### gRPC Client Wrapper

#### [NEW] `/home/ivan/projects/ngxora/control-plane/internal/client/ngxora.go`

- wrap the Go SDK client
- connect over UDS
- expose:
  - `ApplySnapshot`
  - `GetSnapshot`
- centralize retry and timeout handling

### Config

#### [NEW] `/home/ivan/projects/ngxora/control-plane/internal/config/config.go`

Suggested fields:

- UDS path
- watched namespace
- reconcile timeout
- apply timeout
- resync period

### Local Dev Support

#### [NEW] `/home/ivan/projects/ngxora/control-plane/README.md`

- how to run against `kind` or `k3d`
- how to point the controller at the UDS path
- example `HTTPRoute`
- example local pod or sidecar setup

## Mapping Strategy For Plugins

Do not try to expose every `ngxora` plugin directly from `HTTPRoute` on day one.

Recommended mapping:

- Gateway-native filter fields map to built-in `ngxora` behavior where there is a clear 1:1 match
- non-native policy such as JWT, ext_authz, or advanced rate limit should come later through dedicated policy CRDs or annotations

That means:

- `HTTPRoute` first
- custom policy resources later

This keeps the first implementation small and understandable.

## Open Design Decisions

### 1. Sidecar Or In-Process

Recommended answer:

- separate container in the same pod

Why:

- clearer failure boundaries
- no need to embed Kubernetes client logic into the `ngxora` binary
- still keeps UDS-only local communication

### 2. Namespace Scope

Recommended answer:

- start with a single namespace

Do not start with all namespaces.

Cluster-wide watch introduces RBAC, tenancy, ownership, and conflict semantics too early.

### 3. Ownership Model

Recommended answer:

- one controller instance manages one local dataplane instance

This avoids inventing remote target discovery before the local model is stable.

## Verification Plan

### Automated Tests

Run Go unit tests for:

- `HTTPRoute` translation
- snapshot building
- deterministic ordering
- gRPC client wrapper behavior with mocked server

Suggested commands:

```bash
cd control-plane
go test ./...
```

### Manual Verification

1. Run `ngxora` with local gRPC over UDS enabled.
2. Run the Go controller locally against a `kind` or `k3d` cluster.
3. Apply a minimal `HTTPRoute`.
4. Verify `ApplySnapshot` reaches the dataplane.
5. Send traffic and confirm route behavior.

## Future Extensions

After the basic path is stable, add:

- dedicated policy CRDs for JWT, ext_authz, and rate limiting
- status conditions for translation and apply failures
- event recording
- conflict resolution for overlapping routes
- optional remote control-plane mode

## Short Recommendation

Build the first mini control plane in Go using the existing Go SDK.

Keep it:

- local
- UDS-only
- namespace-scoped
- limited to `HTTPRoute` plus a small supported filter subset

That is the shortest path to a working control-plane prototype without dragging Kubernetes complexity into the Rust dataplane codebase.
