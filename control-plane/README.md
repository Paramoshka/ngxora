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
- `HTTPRoute` reconciliation against a target `Gateway`
- route translator for `HTTPRoute`
- backend `Service` resolution for `backendRefs`
- `ReferenceGrant` checks for cross-namespace backend and certificate refs
- snapshot builder that maps each `HTTPRoute` rule to a `VirtualHost` route and `UpstreamGroup`
- `HTTPRoute` and `Gateway` status updates
- HTTP and HTTPS listener synthesis from `Gateway.spec.listeners`
- gRPC client wrapper for local UDS transport

What does not exist yet:

- full Gateway API coverage
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
- `NGXORA_GATEWAY_NAME`
- `NGXORA_GATEWAY_NAMESPACE`
- `NGXORA_APPLY_TIMEOUT`
- `NGXORA_RECONCILE_TIMEOUT`

Example:

```bash
cd control-plane
NGXORA_SOCKET_PATH=/tmp/ngxora-control.sock \
NGXORA_WATCH_NAMESPACE=default \
NGXORA_GATEWAY_NAME=ngxora \
NGXORA_GATEWAY_NAMESPACE=default \
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
- a demo `GatewayClass` and `Gateway`
- a demo backend `Deployment` and `Service`
- an `ngxora` `Deployment`
- an `ngxora-control-plane` sidecar in the same pod
- a shared UDS volume at `/var/run/ngxora`

Prerequisite:

- Gateway API CRDs must already be installed in the cluster, because the controller watches `HTTPRoute`
- Install guide: https://gateway-api.sigs.k8s.io/guides/
- create a demo TLS Secret before applying the workload:

```bash
tmpdir="$(mktemp -d)"
openssl req -x509 -nodes -newkey rsa:2048 \
  -keyout "${tmpdir}/tls.key" \
  -out "${tmpdir}/tls.crt" \
  -subj '/CN=localhost' \
  -days 365
kubectl create secret tls ngxora-localhost-tls \
  --namespace default \
  --cert="${tmpdir}/tls.crt" \
  --key="${tmpdir}/tls.key"
rm -rf "${tmpdir}"
```

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
kubectl port-forward deployment/ngxora 8080:8080 8443:8443
curl -H 'Host: localhost' http://127.0.0.1:8080/
curl -k -H 'Host: localhost' https://127.0.0.1:8443/
```

Listener validation notes:

- the controller now filters `HTTPRoute` by matching `parentRefs` against the configured target `Gateway`
- `AllowedRoutes.kinds` is validated, and only `HTTPRoute` is supported today
- listeners with unsupported protocols are marked `Accepted=False` with reason `UnsupportedProtocol`
- listeners with invalid `allowedRoutes.kinds` are marked `ResolvedRefs=False` with reason `InvalidRouteKinds`
- `HTTPS` listeners require `tls.mode: Terminate` and a single core `Secret` `certificateRef`
- cross-namespace `certificateRefs` require a matching `ReferenceGrant`
- the quick start bootstrap config already exposes both `8080` and `8443`, so listener topology matches what the control-plane will program
