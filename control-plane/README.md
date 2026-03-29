# ngxora Go Control Plane

This module contains a first-pass Kubernetes-aware control-plane for `ngxora`.

Current target shape:

- watch `HTTPRoute`
- translate route intent into `ngxora` snapshot intent
- push snapshots to the local `ngxora` dataplane over gRPC through UDS

## Status

This is a scaffold, not a production-ready controller.

What exists:

- process entrypoint
- config loading from environment
- `HTTPRoute` reconciliation skeleton
- route translator skeleton
- snapshot builder that maps each `HTTPRoute` rule to a `VirtualHost` route and `UpstreamGroup`
- gRPC client wrapper for local UDS transport

What does not exist yet:

- full Gateway API coverage
- Service and backend resolution
- status conditions
- conflict resolution
- production retry policy

## Layout

```text
control-plane/
  cmd/ngxora-control-plane/main.go
  internal/client/ngxora.go
  internal/config/config.go
  internal/controller/httproute_controller.go
  internal/controller/manager.go
  internal/snapshot/builder.go
  internal/status/conditions.go
  internal/translator/httproute.go
```

## Local Run

Expected environment variables:

- `NGXORA_SOCKET_PATH`
- `NGXORA_WATCH_NAMESPACE`
- `NGXORA_APPLY_TIMEOUT`
- `NGXORA_RECONCILE_TIMEOUT`

Example:

```bash
cd control-plane
NGXORA_SOCKET_PATH=/tmp/ngxora-control.sock \
NGXORA_WATCH_NAMESPACE=default \
go run ./cmd/ngxora-control-plane
```

This assumes the local `ngxora` dataplane is already running with gRPC over UDS enabled.

## Example HTTPRoute

A minimal example object is available at:

`control-plane/examples/httproute.yaml`

## Kubernetes Quick Start

A sidecar-style quick start manifest is available at:

`control-plane/examples/quickstart-deployment.yaml`

It creates:

- a bootstrap `ConfigMap` for `ngxora`
- a demo backend `Deployment` and `Service`
- an `ngxora` `Deployment`
- an `ngxora-control-plane` sidecar in the same pod
- a shared UDS volume at `/var/run/ngxora`

Prerequisite:

- Gateway API CRDs must already be installed in the cluster, because the controller watches `HTTPRoute`
- Install guide: https://gateway-api.sigs.k8s.io/guides/

Apply the workload:

```bash
kubectl apply -f control-plane/examples/quickstart-deployment.yaml
```

Then apply the route:

```bash
kubectl apply -f control-plane/examples/httproute.yaml
```

Port-forward the proxy:

```bash
kubectl port-forward deployment/ngxora 8080:8080
curl -H 'Host: localhost' http://127.0.0.1:8080/
```

Current note:

- the first scaffolded snapshot builder assumes one plain HTTP listener on `0.0.0.0:8080`
- the bootstrap config in the quick start is intentionally aligned with that assumption
