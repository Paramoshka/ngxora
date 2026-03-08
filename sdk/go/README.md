# Go SDK

This module contains Go bindings generated from [`crates/ngxora-runtime/proto/control.proto`](/home/ivan/projects/pet/ngxora/crates/ngxora-runtime/proto/control.proto).

Generate or refresh the SDK from the repository root:

```bash
make gen-go-sdk
```

The generated package path is:

```go
import controlv1 "github.com/paramoshka/ngxora/sdk/go/ngxora/control/v1"
```

The generator script installs `protoc-gen-go` and `protoc-gen-go-grpc` into `sdk/go/bin` if they are missing, and uses the vendored `protoc` that already exists in the Rust build.
