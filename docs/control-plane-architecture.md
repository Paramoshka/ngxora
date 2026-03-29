# Control Plane Architecture

This document describes a practical control-plane shape for `ngxora` if the project starts accepting Kubernetes-style route objects such as `HTTPRoute`.

The design goal is not to copy Istio. The goal is to keep `ngxora` small, predictable, and operationally simple while still supporting dynamic policy and route updates.

## Goal

`ngxora` should be able to:

- accept route and policy intent from a control API
- translate that intent into the same runtime model used by text config
- compile plugin and policy behavior before requests hit the dataplane
- apply route and policy changes atomically through snapshot swap

The control plane should remain narrow. It should not become a second proxy runtime.

## Core Idea

Use one internal pipeline regardless of where config comes from:

`nginx config` or `HTTPRoute` -> adapter -> internal IR -> extension filters -> compiled snapshot -> Pingora runtime

This keeps one dataplane behavior and multiple config adapters.

## Proposed Architecture

### Control Input

The control plane accepts one or more of the following:

- nginx-style bootstrap config
- gRPC snapshot API
- `HTTPRoute` and related policy objects

All inputs must be translated into the same internal IR or runtime snapshot model.

### Translation Layer

The translator is responsible for:

- resolving `HTTPRoute` hostnames, path matches, and backend refs
- attaching referenced policy objects
- validating cross-object references
- producing a normalized internal representation

This layer should stay declarative. It should not execute request-time logic.

### Extension Filters

Extension filters are the policy compilation stage.

They should operate on route and policy intent before the runtime snapshot is built. This is the right place for:

- auth policy expansion
- CORS defaults and normalization
- rate-limit policy wiring
- request and response header mutation policy
- external authorization binding
- JWT requirements

The important constraint is that extension filters transform config, not traffic.

In practice:

- input: normalized route and policy IR
- output: compiled plugin chain and route metadata

This keeps request-time hooks small and predictable.

### Compiled Snapshot

The compiled snapshot is the only thing the dataplane should read at request time.

It should contain:

- listener map
- virtual host map
- compiled location matchers
- backend resolution data
- compiled plugin chains by phase
- TLS and SNI lookup data

The snapshot must be immutable and atomically swappable.

### Dataplane

The Pingora dataplane should only do request-time work:

- select listener
- resolve virtual host
- resolve route/location
- run compiled plugin chain in defined phases
- build upstream peer
- proxy traffic

It should not parse `HTTPRoute`, chase external references, or perform policy compilation.

## Plugin Model

If `HTTPRoute` becomes a control-plane input, plugins should not be bolted directly onto raw route objects.

The safer model is:

1. Translate `HTTPRoute` into internal route and policy objects.
2. Run extension filters over those objects.
3. Compile a plugin chain into the runtime snapshot.
4. Execute the chain in well-defined request phases.

Recommended phases:

- request
- authn
- authz
- upstream_request
- response

Each plugin should declare:

- which phase it runs in
- what config it consumes
- whether it mutates headers, routing, or response handling

This prevents the plugin layer from becoming an unstructured set of callbacks.

## Deployment Options

There are two realistic options.

### Option A: Separate Control Plane Pod

This is the Istio-style direction.

Shape:

- dedicated control-plane service
- networked gRPC API
- one or more `ngxora` dataplane instances subscribe or receive pushes

Pros:

- clear control-plane and dataplane separation
- easier central multi-proxy management
- better fit for cluster-wide policy and route ownership
- easier future integration with Kubernetes controllers

Cons:

- much more operational surface
- authn/authz and tenancy become mandatory immediately
- version skew between control plane and dataplane appears early
- retries, ordering, snapshot versioning, and reconciliation become first-class problems
- high complexity for a small project

This path makes sense only if `ngxora` is explicitly becoming a distributed service-mesh or ingress control system.

### Option B: Control Plane And Dataplane In One Pod

This is the smaller and more practical direction for the current project stage.

Shape:

- `ngxora` process owns the dataplane
- a local control-plane component runs in the same pod, or the same binary
- the control API is exposed only through UDS or localhost
- snapshot compilation and apply stay local

Pros:

- much smaller trust boundary
- simpler failure model
- no networked control-plane hardening required on day one
- easier debugging and release management
- keeps dynamic updates without committing to full distributed control-plane complexity

Cons:

- weaker story for centralized fleet management
- per-pod local state unless an external reconciler is added later
- cluster-wide policy rollout has to be layered on later

For `ngxora` today, this is the stronger default.

## Recommendation

Do not drop gRPC as a protocol. Drop the assumption that it must be network-exposed.

Recommended near-term shape:

- keep gRPC as the control API transport
- expose it only through UDS or loopback inside the pod
- keep control-plane compilation co-located with the dataplane
- treat `HTTPRoute` as another adapter that produces the same snapshot model

This gives the project:

- one runtime model
- one snapshot engine
- one request-time dataplane
- low operational complexity

It also preserves a future migration path to a remote control plane.

## Suggested Phased Plan

### Phase 1

Keep control-plane and dataplane in one pod.

- local gRPC only
- snapshot apply remains local
- `HTTPRoute` translator lives in-process or sidecar-local
- extension filters compile route policy into plugin chains

This should be the default design target.

### Phase 2

Stabilize the internal contracts.

- snapshot schema versioning
- deterministic translation from `HTTPRoute`
- deterministic extension filter ordering
- restart-required vs live-reload semantics for every field
- plugin phase contracts

Without this step, a remote control plane will be fragile.

### Phase 3

If the project needs centralized management, move only the control API boundary out of process.

- remote controller computes desired state
- dataplane still applies immutable snapshots locally
- transport can remain gRPC
- local runtime model stays unchanged

This minimizes rewrite cost.

## Boundaries To Preserve

To avoid architecture drift, keep these boundaries explicit:

- control input is not runtime state
- extension filters are not request-time plugins
- runtime snapshot is not raw `HTTPRoute`
- dataplane does not perform control-plane translation

If these boundaries hold, `ngxora` can stay small while still supporting a modern control model.

## Short Decision

For the current stage of the project:

- choose co-located control-plane plus dataplane
- keep gRPC, but local-only by default
- treat `HTTPRoute` as an adapter into the existing snapshot model
- use extension filters as compile-time policy transforms

This gives the project the most leverage for the least complexity.

For a concrete first-pass implementation shape using the existing Go SDK, see [Implementation Plan - Go Mini Control Plane](./control-plane-go-implementation-plan.md).
