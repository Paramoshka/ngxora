# ADR-007: HTTPRoute Plugin Integration via ExtensionRef

## Context

`ngxora` has custom data-plane plugins, such as RateLimit and JWT Auth. The Gateway API standard allows custom capabilities in two primary ways: Policy Attachment (attaching a custom CRD to a Gateway or Route) or `ExtensionRef` inside a Route's `filters` list. We need to decide the standard mechanism to expose ngxora plugins to end users.

## Decision

We will use the **`ExtensionRef` mechanism** inside `HTTPRoute.filters` as the primary configuration vector for Request/Response modification plugins (e.g., RateLimit, JWT).

- `HTTPRoute` rules can define an `ExtensionRef` within their `filters` list.
- The `ExtensionRef` will point to a custom resource (e.g., `RateLimitPolicy`, `JwtAuthPolicy`) in the same namespace (or a different namespace if a strict `ReferenceGrant` allows it, adhering to ADR-006).
- The `ngxora` control-plane will validate these references, read the referenced CRD, and embed the extracted plugin configuration directly into the intermediate representation (IR) translated for the data-plane.

## Consequences

- The Gateway API translation logic in the control-plane must implement explicit type checking for referenced Groups and Kinds. Invalid references or unsupported kinds will trigger status conditions (e.g., `ResolvedRefs=False` with `Reason=InvalidExtensionRef`).
- We avoid an explosion of Policy CRDs implicitly linked to resources, making the routing intent highly visible directly on the `HTTPRoute`.
- Since plugins might be referenced by multiple `HTTPRoute`s, the snapshot generator must efficiently cache or inline plugin data to prevent duplicate reads and maintain the strict IR boundary defined in ADR-002.
