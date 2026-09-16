# Go SDK

This module contains Go bindings generated from [`crates/ngxora-runtime/proto/control.proto`](../../crates/ngxora-runtime/proto/control.proto).

Generate or refresh the SDK from the repository root:

```bash
make gen-go-sdk
```

The generated package path is:

```go
import controlv1 "github.com/paramoshka/ngxora/sdk/go/ngxora/control/v1"
```

The generator script installs `protoc-gen-go` and `protoc-gen-go-grpc` into `sdk/go/bin` if they are missing, and uses the vendored `protoc` that already exists in the Rust build.

## UDS snapshot synchronization

The handwritten `github.com/paramoshka/ngxora/sdk/go/client` package keeps the
latest desired snapshot applied to a local ngxora process:

```go
import (
    "context"

    "github.com/paramoshka/ngxora/sdk/go/client"
    controlv1 "github.com/paramoshka/ngxora/sdk/go/ngxora/control/v1"
)

func syncDataplane(ctx context.Context, desired *controlv1.ConfigSnapshot) error {
    c, err := client.NewUDS("/run/ngxora/control.sock", client.Options{})
    if err != nil {
        return err
    }
    if err := c.SetSnapshot(desired); err != nil {
        return err
    }
    return c.Run(ctx)
}
```

Retain the client and call `SetSnapshot` concurrently with `Run` when desired
state changes. It copies the input and retains only the latest pending snapshot.
Callers must not mutate the input concurrently with `SetSnapshot` itself.
Without a desired snapshot, the client makes no RPCs and leaves bootstrap state
alone. The absolute socket path may be absent initially; the server owns its
creation, permissions and cleanup. With ngxora's `0700` directory and `0600`
socket, a sidecar should share the directory and service UID.

Each snapshot needs a nonempty `version` uniquely identifying its contents,
including across restarts. Reusing the current version with different contents
is rejected locally; historical versions are not retained or checked. All
writers must follow the same version contract. Equality is checked by version,
not by comparing the runtime's normalized protobuf export with the input.
Manual changes that preserve the version cannot be detected.

`Run` waits for the UDS channel to become ready, then checks `GetSnapshot`,
applying the desired snapshot only if versions differ. Normal attempts are
separated by `PollInterval` (one second by default), including when an in-flight
result was superseded. New snapshots replace pending state without interrupting
this wait, so frequent updates cannot generate an RPC burst. Thus a replacement
process regains its configuration without a new Kubernetes event, and a lost successful
`ApplySnapshot` response can be confirmed without another apply. Manual updates
with another version, including SIGHUP, are overwritten by the desired snapshot.
RPCs are serialized; a result for an older desired version cannot acknowledge a
newer one.

Defaults are a 3-second deadline per RPC and exponential retry from 200 ms to
5 seconds with ±20% jitter. A new desired snapshot does not reset error backoff.
While the channel is unavailable, only grpc-go schedules reconnects; the SDK
waits for readiness without issuing RPCs or running a separate retry timer.
An observed disconnect interrupts the pending RPC cooldown, and reconnection
starts reconciliation immediately with the latest desired snapshot. RPC deadlines
start after channel readiness; waiting for connection is bounded by the `Run`
context. `RetryMax` bounds the base retry delay, not total recovery time.

On a ready channel, `Unavailable` and `DeadlineExceeded` responses use the
SDK retry delay, reset after success or reconnection. `Options` permits
overriding these durations. Other RPC errors and rejected applies terminate
`Run`. Inspect `*client.RestartRequiredError` or `*client.ApplyError` with
`errors.As`; fix the cause before running again. Restart-required errors never
trigger an automatic process upgrade.

`Status()` returns desired/confirmed versions, `Synced`, and `LastError`.
It represents the last observation: channel state changes and RPC results update
it asynchronously. Errors, changed desired state and exit clear `Synced`.
Transient errors remain observable through status while retrying. Canceling the
context interrupts RPCs and waits, closes the connection, and returns an error
matching `context.Canceled` or `context.DeadlineExceeded`. Only one `Run` may be
active; it can be invoked again after it returns.

This package does not persist snapshots, watch Kubernetes, control processes or
gate HTTP readiness. A new ngxora process can accept traffic before the desired
snapshot arrives. After a controller restart, its caller must reconstruct desired
state and supply it again.

Verification:

```bash
go -C sdk/go vet ./...
go -C sdk/go test -race ./...
# Linux: use a freshly built ngxora binary (absolute path).
NGXORA_TEST_BIN="$PWD/target/debug/ngxora" go -C sdk/go test -race -tags=integration ./client -run '^TestGracefulUpgrade' -count=1
```

The process integration test also runs in `make test-e2e` and CI. It starts two
ngxora generations and verifies automatic route restoration after graceful
upgrade, without calling `SetSnapshot` again.

## Snapshot construction

For HTTPRoute-style routing, use `Match_Http` instead of the nginx `Match_Prefix`:

```go
route := &controlv1.Route{
    Match: &controlv1.Match{Kind: &controlv1.Match_Http{Http: &controlv1.HttpMatch{
        Path: &controlv1.HttpMatch_PathPrefix{PathPrefix: "/api"},
        Headers: []*controlv1.ExactCondition{{Name: "x-tenant", Value: "blue"}},
    }}},
    Action: &controlv1.Route_WeightedBackends{WeightedBackends: &controlv1.WeightedBackends{
        Backends: []*controlv1.WeightedBackend{{
            // nil Weight defaults to 1; a pointer to 0 disables this choice.
            Target: &controlv1.WeightedBackend_Upstream{Upstream: &controlv1.Upstream{
                Scheme: "http", UpstreamGroup: "api-service",
            }},
        }},
    }},
}
```

Include the referenced upstream group in the same snapshot. `AllowEmpty: true`
lets a static group with zero ready endpoints be applied and return 503 until
endpoints arrive. New dataplanes must be deployed before using these fields.
See [snapshot semantics](../../docs/snapshot-schema.md#httproute-dataplane-primitives)
for precedence, redirects, rewrites and weighted error responses.


HTTP/2 tuning is available through `HttpOptions.Http2` and `Route.UpstreamHttp2`.
Their optional numeric fields use pointers: `nil` retains Pingora defaults;
explicit zero is rejected. Global HTTP/2 changes require restart, while route
settings apply live to new upstream connections. See
[HTTP/2 configuration](../../docs/config-options.md#http2-limits-and-flow-control).

GeoIP is configured through `ConfigSnapshot.Geoip` (`*controlv1.GeoIpConfig`):
`Database` is a local MMDB path, `ReloadIntervalMs` defaults to 5000 when nil
(explicit zero is rejected), and `TrustedProxies` contains IP addresses/CIDRs.
A nil GeoIP configuration disables the feature. Configuration changes require
restart; database file updates are loaded automatically. See
[GeoIP configuration](../../docs/config-options.md#geoip-maxmind).
