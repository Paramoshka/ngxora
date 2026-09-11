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
