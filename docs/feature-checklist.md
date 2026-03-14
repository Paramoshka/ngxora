# Feature Checklist

`ngxora` has two config adapters:

- text config: `nginx-style config -> AST -> IR -> runtime model`
- control plane: `gRPC proto -> runtime model`

The rule is simple:

- one runtime capability
- one dataplane behavior
- two ways to feed it

If a feature is meant to be supported from both file config and gRPC snapshots, it should be implemented in both adapters against the same runtime model.

## Core Option Checklist

Use this for options like `proxy_write_timeout`, `client_max_body_size`, `proxy_ssl_verify`, or upstream behavior flags.

1. Add parser constants and syntax support in the text config layer.
2. Add a typed field in IR, not a raw string.
3. Carry the field into the compiled/runtime model.
4. Apply the behavior in the dataplane.
5. Add the field to `control.proto` if the feature should be visible to the agent/control plane.
6. Implement `proto -> runtime` conversion.
7. Implement `runtime -> proto` conversion for `GetSnapshot`.
8. Update reload semantics:
   `Live`, `Restart required`, or `Not implemented`.
9. Add text config tests.
10. Add gRPC conversion or control-plane tests.
11. Update examples and docs.

## Plugin Checklist

Use this for plugins like `headers`, `basic_auth`, `cors`, or `rate_limit`.

1. Define or reuse a `PluginSpec` shape.
2. Add text config syntax if the plugin should be available from file config.
3. Add gRPC/proto representation if the plugin should be agent-driven.
4. Register the plugin factory in the plugin registry.
5. Validate config during snapshot build, not per request.
6. Compile plugin chains into the runtime snapshot.
7. Execute the plugin in the correct hook phase.
8. Add text config tests.
9. Add gRPC snapshot tests.
10. Add at least one example config or example snapshot.

## Bootstrap-Only Rule

Some features belong to listener bootstrap and cannot be applied live with current Pingora wiring.

For those features:

- still model them in runtime state and proto if the control plane must understand them
- return `restart_required=true` on `ApplySnapshot`
- document the behavior in the reload matrix

Typical examples:

- listener sockets
- ALPN / HTTP protocol policy
- downstream TLS verification settings

## Done Criteria

A feature is not done when only the parser or only gRPC works.

A feature is done when:

- text config path is correct
- gRPC path is correct
- runtime behavior is correct
- reload semantics are explicit
- tests cover both adapters
- docs and examples match the implementation
