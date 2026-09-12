# Snapshot Schema

This document records the intended data flow boundary for runtime configuration.

## Rule

The dataplane consumes only compiled snapshot state.

It does not read:

- raw Kubernetes objects
- text config AST
- unresolved references

## Current Flow

`HTTPRoute` / `Gateway` / `Service` / `Secret`
-> translator and reference resolution
-> normalized desired state
-> compiled `ConfigSnapshot`
-> gRPC `ApplySnapshot`
-> runtime `CompiledRouter`
-> Pingora request handling

## Snapshot Responsibilities

The snapshot is responsible for carrying:

- listeners
- virtual hosts
- route matchers
- upstream groups
- named SCP profiles (`scp_profiles`) and route `scp_profile` actions; references
  resolve to allowed NRF upstream templates and explicit target roots
- TLS bindings and listener TLS options
- upstream TLS configurations (including inline CA certificate payloads and mTLS client identities)
- plugin configuration already compiled for runtime use

## What Must Not Cross The Boundary

The snapshot builder must not depend on raw Kubernetes object shapes once translation is done.

Examples of bad flow:

- passing `gatewayv1.HTTPRoute` directly into runtime routing
- reading `corev1.Secret` from request-time code
- resolving `Service` ports inside the dataplane

## Why This Exists

This boundary is the main guardrail against architecture drift. If a future change bypasses it, treat that as a design regression, not a convenience shortcut.

## HTTPRoute dataplane primitives

The gRPC/IR adapter exposes HTTP matching, weighted backend choices, structured
redirects and URL rewriting. These are dataplane building blocks, not a Kubernetes
controller or a claim of Gateway API conformance. A controller still resolves
parent references, hostname intersections, Service endpoints, Secrets and
ReferenceGrants, and reports Kubernetes status conditions.

### Matches and hostnames

`Match.http` contains an `exact` or `path_prefix` path (default `/` prefix),
optional `method`, and exact `headers` and `query_params` conditions. Conditions
are ANDed; translate alternative HTTPRoute matches to separate snapshot routes.
Header names are case-insensitive, values are case-sensitive. First occurrences
win for duplicate conditions and request values. Query values are URL-decoded
(including `+` as space); paths retain their percent encoding.

HTTP prefixes match complete slash-separated segments: `/foo` matches `/foo/`
and `/foo/bar`, but not `/foobar`. Trailing slashes in configured prefixes are
ignored. Priority is exact path, longest prefix, method, number of header
conditions, then number of query conditions. Snapshot route order breaks ties:
the controller must order equal-priority routes by creation timestamp,
namespace/name and rule index before publishing. Merge routes sharing a virtual
host into one `VirtualHost` entry.

The original nginx match variants keep their existing behavior. Mixing nginx and
HTTP matchers inside one virtual host is rejected. No new text-config match
syntax is introduced.

HTTP routing and TLS identity selection support exact names and leading `*.`
wildcards, with exact names before the longest wildcard suffix, then default.
`*.example.com` matches `a.example.com` and `a.b.example.com`, not `example.com`.
For HTTP matchers, a more specific hostname without a matching rule does not hide
a matching wildcard rule. SNI/Host consistency checks remain enabled.

### Backend choices

`Route.weighted_backends.backends` selects an upstream target or a
`DirectResponse` using weighted round-robin, then applies the existing endpoint
balancer inside the selected upstream group. A choice's absent weight is 1;
explicit 0 disables it. Weights range from 0 to 1,000,000. An empty choice list is
invalid; all-zero choices return 503. Counters belong to the active snapshot and
restart on snapshot replacement.

Represent an invalid backendRef as a `DirectResponse { status: 500 }` choice with
its original weight. A selected group with no available endpoints returns 503;
its share is not redistributed to other groups. A static group with
`allow_empty: true` may contain zero endpoints and can be updated live. The flag
defaults to false and is only configurable through gRPC/IR. Existing endpoint
weights retain the legacy `0`-means-`1` interpretation.

`Route.direct_response` also permits a route-wide local status (200–599), without
a body. Backend choices share the route's plugins, timeouts and TLS options.

### Redirects and rewrites

`Route.http_redirect` supports status (default 302), optional scheme, hostname,
port and a path modifier. Explicit scheme chooses its default port when no port
is supplied; otherwise the accepted listener port is retained. Standard ports
are omitted from Location. Unchanged path and query are preserved.

`Route.url_rewrite` changes the upstream Host header and/or path of upstream and
weighted-backend routes. It runs after matching and before upstream header
plugins; it does not change the backend TLS identity. Both actions support
`replace_full_path` and `replace_prefix_match`; prefix replacement requires an
HTTP PathPrefix match. Redirect and rewrite cannot be combined on one route.
SCP routes do not accept this rewrite field.

The legacy `Redirect.location` and text `return` support `$host`, `$request_uri`,
`$scheme`, and `$$` for a literal dollar sign. Unknown variables fail validation.
The new structured fields have no text-config syntax.

### Responses, reload and compatibility

Request plugins and cache lookup run before backend selection. Local responses
from auth/CORS, redirects, direct responses and errors run the selected route's
entire response-plugin chain in reverse order, once. Plugins must not require
their request hook to have run before their response hook. Cache HIT/STALE
responses already contain the processed headers and skip that chain. Responses
before route selection have no route plugins. A response-plugin failure returns
500 without invoking that chain again; started responses are never replaced.

New fields round-trip through GetSnapshot and apply live on existing listeners.
Invalid snapshots preserve the current configuration. Existing protobuf field
numbers and nginx match semantics are unchanged. Deploy the new dataplane before
controllers start using these additions; old dataplanes cannot interpret them.

## Client policy

`Route.access_rules` is an ordered list of `IpAccessRule { action, source }`.
Action must explicitly be `ALLOW` or `DENY`; source is an IP, CIDR, or `all`.
The first matching rule wins. An empty list allows all clients; a nonempty list
with no match denies access, matching the existing ngxora text-config semantics.
Unknown actions and invalid networks reject the complete snapshot. GetSnapshot
preserves the rule order and exports individual IPs as /32 or /128 networks.

`HttpOptions.real_ip` supplies trusted proxy networks, `header` (default
X-Forwarded-For), and optional `recursive` (default true). Presence enables the
shared client identity for ACL, plugins, GeoIP, hashing and logs; an empty trusted
list trusts no forwarding headers. Absence retains legacy configuration behavior.

`Route.allowed_methods` is an ordered, case-sensitive list. Empty means no method
restriction. Repeated methods are deduplicated in order; invalid method tokens
reject the snapshot. GET, HEAD and OPTIONS are independent entries. Rejected
methods receive 405 with the list in `Allow`.

`HttpOptions.client_header_timeout_ms`, `client_body_timeout_ms`, `send_timeout_ms`
are optional millisecond durations. Route fields `client_body_timeout_ms`,
`send_timeout_ms`, and `client_max_body_size_bytes` are overrides: absent inherits,
explicit zero disables. These fields are live configuration. See
[client policy and protocol limitations](config-options.md#client-identity-and-request-policy).

Deploy the updated dataplane before using these fields: older protobuf readers
ignore unknown fields and cannot enforce these policies.
