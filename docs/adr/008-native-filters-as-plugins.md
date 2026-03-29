# ADR-008: Native Gateway API Filters as Plugins

## Context

The Kubernetes Gateway API provides native filters, such as `RequestHeaderModifier` and `ResponseHeaderModifier`, which define standard ways to mutate traffic. Our `ngxora` data-plane is built around a generic plugin execution engine (`headers`, `rate-limit`, `jwt_auth`, etc.). We needed to decide how to implement and execute these native API standard features within the data-plane without compromising performance or duplicating mutation logic.

## Decision

We will implement native Gateway API modification filters by **translating them directly into data-plane plugin configurations** at the control-plane level.

- Standard Gateway API filters (like `RequestHeaderModifier` and `ResponseHeaderModifier`) are intercepted during translation (`TranslateHTTPRoute`).
- Instead of building custom core logic in the Rust data-plane for these standards, the control-plane converts the filter payloads into JSON config representations matching one of our existing plugins (e.g., the `headers` plugin).
- Each native filter instance is compiled into a standalone plugin execution block to perfectly preserve the sequential filter execution order defined by the Gateway API specification.

## Consequences

- **Data-Plane Simplicity:** The Rust data-plane remains unaware of Kubernetes or Gateway API specifics. It strictly executes a list of configured plugins, maintaining a lean and highly performant core.
- **Code Reusability:** Native features like header modification automatically benefit from the robust, tested implementation of our generic plugins.
- **Snapshot Size Overhead:** Emitting separate plugin instances for each header modifier slightly increases the footprint of the intermediate representation (IR) compared to fully aggregating them. However, this is negligible and guarantees 100% adherence to filter ordering (e.g., executing a header set before an external auth check).
- **Control-Plane Autonomy:** The control plane is fully responsible for mapping Gateway API semantics to the proxy's primitive components.
