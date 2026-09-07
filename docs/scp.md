# Practical SBI/SCP v1

`scp_pass` is an opt-in, single-hop SBI routing profile on top of Pingora.
It supports direct routing and a limited delegated-discovery path. It is **not a
claim of full Release 18 SCP conformance**. Ordinary `proxy_pass` retains its
existing transport-proxy behavior.

## Request path

```mermaid
sequenceDiagram
    participant NF as Consumer NF
    participant SCP as ngxora SCP pod
    participant NRF as NRF registry
    participant P as Producer NF
    NF->>SCP: HTTP/2 + Target-apiRoot or Discovery headers
    SCP->>SCP: ACL/plugins, header validation, profile policy
    opt Delegated discovery, no usable local snapshot
        SCP->>NRF: Nnrf_NFDiscovery with allowed selectors
        NRF-->>SCP: NF profiles + validityPeriod
        SCP->>SCP: Filter identities/version, preflight, select service/endpoint
    end
    SCP->>P: HTTP/2; replace apiRoot; remove routing headers
    P-->>SCP: Response + Location / Binding
    SCP-->>NF: Response + Producer-Id; Target-apiRoot when applicable
```

The NRF stores registered NF profiles. ngxora only reads them: it is neither an
NRF server nor an NF-registration client. Each pod has its own bounded in-memory
discovery cache and health state. Pods do not share Redis/etcd or replicate cache
entries. A consumer carries `3gpp-Sbi-Routing-Binding` into the next request, so a
different pod can discover the same NF/service instance. Round-robin position and
health observations need not be identical across pods.

## Configuration and local lab

Start from [`examples/scp/ngxora.conf`](../examples/scp/ngxora.conf):

```sh
cargo run -- --check examples/scp/ngxora.conf
cargo run -- examples/scp/ngxora.conf
```

That config expects an NRF on port 7777 and, for direct routing, an HTTP/2 producer
on port 9000. It does not start either dependency. A complete disposable lab is
available through `make test-open5gs` (Docker and HTTP/2-enabled curl required).

Direct request, including a callback path:

```sh
curl --http2-prior-knowledge \
  -H '3gpp-Sbi-Target-apiRoot: http://127.0.0.1:9000/operator/edge' \
  http://127.0.0.1:8080/scp/callbacks/42
```

Delegated discovery:

```sh
curl --http2-prior-knowledge \
  -H '3gpp-Sbi-Discovery-target-nf-type: SMF' \
  -H '3gpp-Sbi-Discovery-requester-nf-type: AMF' \
  -H '3gpp-Sbi-Discovery-service-names: nsmf-pdusession' \
  http://127.0.0.1:8080/scp/nsmf-pdusession/v1/sm-contexts
```

The profile references existing `nrf_discovery` upstreams as allowed discovery
templates. They specify the NRF, target/requester NF types, service, endpoint
scheme, balancing and health policy. This keeps NRF TLS and health configuration
in one place. Additional services require additional allowed templates. Missing
type selectors can use configured defaults only when exactly one template
matches. The first service name must match the request path; the API major version
must appear in the selected NF Service's `versions`.
On SCP routes, a configured hash header must be a single non-empty value if
present; absence uses the socket client IP.

For TLS, use `listen ... ssl http2`, configure downstream certificates and
`ssl_verify_client required`, and use HTTPS NRF/producer roots. NRF certificates
use the `nrf_discovery` block's `ssl_*` options. Producer certificates use the
location's `proxy_ssl_trusted_certificate`, `proxy_ssl_certificate` and
`proxy_ssl_certificate_key`. Verification is on by default. An NRF-provided FQDN
is used for authority, SNI and certificate verification while an advertised IP is
used for the connection. Do not set `proxy_upstream_protocol`: SCP always selects
HTTP/2, with TLS for HTTPS and prior-knowledge h2c for HTTP.

## Supported boundary

| Input / behavior | v1 handling |
| --- | --- |
| `3gpp-Sbi-Target-apiRoot` | Exact configured root, or a root in this pod/profile's valid discovery cache; never an arbitrary forward-proxy destination |
| Discovery headers | `target-nf-type`, `requester-nf-type`, `service-names`, `target-nf-instance-id`, `requester-nf-instance-id` |
| Routing binding | `bl=nf-instance; nfinst=...` or `bl=nfservice-instance; nfinst=...; nfservinst=...`; optional `servname` |
| Target plus discovery/binding | Prefer the matching target; reselect only within the filtered domain if unavailable; conflicting selectors fail |
| `3gpp-Sbi-Max-Forward-Hops` | Default 1; decrement; zero/self-target fails before forwarding |
| Request URI | Replace SCP prefix with producer `apiPrefix`; remove `ck`; preserve remaining encoded path/query; reject traversal and encoded path separators |
| Producer-bound headers | Remove Target-apiRoot, Discovery headers and Routing-Binding; leave service payload and other headers opaque |
| Response | Preserve producer Location and Binding; add `Producer-Id: nfinst=...; nfservinst=...` for discovered targets; selected Target-apiRoot when there is no Location |
| Retry | At most one alternative after connect failure, within the same discovery/binding domain; no replay after proxying begins, including reused connections and POST |

Direct-only roots have no NF identity metadata. For cross-pod direct routing,
configure the root explicitly, or include discovery/binding; a cache learned by
pod A does not authorize a direct-only request on a cold pod B. Callback paths
without a service/version are supported with an explicit allowed direct root;
delegated callback discovery is outside v1.

Unsupported discovery factors, binding sets, multi-hop routing headers and
malformed/duplicate routing headers are rejected explicitly. Response caching is
forbidden on `scp_pass`. Request ACLs and plugins run before discovery. TLS trust,
authenticated consumers, rate limits and network egress policy remain deployment
responsibilities: an advertised requester NF type is not proof of identity, and
NRF-advertised destinations are trusted within the configured profile.

## State, errors and operations

Per profile/pod: at most 256 query-cache entries, 16 concurrent NRF refreshes,
256 endpoints per discovery result and 1 MiB per NRF response. Identical queries
share an owned refresh even if a waiting client disconnects. Unused cache entries
expire after five minutes; active entries are not evicted to admit a new query.
Snapshots refresh using NRF validity and bounded `stale_if_error`. After full
expiry, selection fails closed until discovery succeeds again.

Routing failures return `application/problem+json` with status and cause:

| HTTP | Cause / condition |
| --- | --- |
| 400 | `INVALID_DISCOVERY_PARAM`, `INVALID_API`, `NF_DISCOVERY_FAILURE`, or malformed/conflicting routing information |
| 403 | Target or discovery combination outside the configured profile |
| 503 | `SCP_CONGESTION`: cache full with active entries |
| 504 | `NRF_NOT_REACHABLE` or `TARGET_NF_NOT_REACHABLE` |
| 505 / 508 | HTTP/2 required / routing loop or exhausted hops |

Producer HTTP errors pass through. Once a response is streaming, a connection
failure terminates it; no ProblemDetails body is appended. Generic HTTP limits
and plugin responses retain their own status/format.

SCP metrics use profile/event labels, not query IDs or discovered target URLs.
Structured access logs include selected root, profile and NF/service instance IDs.
`ApplySnapshot`/`GetSnapshot` carry `scp_profiles` and the route `scp_profile`
action. Unchanged profile/templates retain caches; policy/template changes replace
them atomically. In-flight requests finish against their captured configuration.
SCP pooled connections are isolated by route and snapshot generation.

## Tests and remaining scope

`make test` includes parser/config/reload tests and hermetic process E2E using
independent Hyper HTTP/2 producers: two pods, resource binding, concurrent cold
discovery, cancellation, expiry/recovery, mTLS with FQDN/IP, and no POST replay.
The NRF suite also exercises endpoint failure and the three balancing policies.
`make test-open5gs` verifies real Open5GS NRF discovery, service distribution,
instance selection/binding and standby failover. Its HTTP/1 mock producers sit
behind HTTP/2 adapter listeners; it is not a complete real 5G Core or conformance
test. This interop suite runs on the existing scheduled/manual CI workflow.

Still outside this implementation: OAuth token acquisition/validation, SCP
registration and NRF subscriptions, binding to NF/service sets, slice/PLMN/roaming
selectors, overload/load control, topology hiding, delegated callback discovery,
multi-hop SCP/SEPP and a Release 18 conformance suite.

Read [TS 29.500](https://www.etsi.org/deliver/etsi_ts/129500_129599/129500/18.09.00_60/ts_129500v180900p.pdf)
for SBI routing/headers, [TS 29.510](https://portal.3gpp.org/desktopmodules/Specifications/SpecificationDetails.aspx?specificationId=3345)
for NRF discovery, and the [roadmap](3gpp-roadmap.md) for the broader boundary.
