//! Runtime routing and upstream execution for compiled ngxora HTTP config.
//!
//! The module boundary is:
//! - `compile`: IR -> `CompiledRouter`
//! - `routing`: request-time listener/vhost/location selection
//! - `runtime`: request state and public proxy API
//! - `runtime::proxy`: Pingora request/response lifecycle
//! - `runtime::selection`, `groups`: route targets and live upstream selection
//! - `runtime::tls`, `limits`, `response`, `completion`: transport and policy boundaries
//! - `scp`: bounded SBI discovery/routing; `scp::request` validates destinations and headers
//! - `nrf`: NRF HTTP client and discovery response validation
//! - `health`: active upstream health checks
//! - `types`: shared compiled routing model

mod compile;
mod health;
pub(crate) mod http_routes;
mod nrf;
mod routing;
mod runtime;
pub(crate) mod scp;
mod types;
pub(crate) use types::NrfServiceMetadata;

pub use runtime::{DynamicProxy, ProxyContext, RuntimeUpstreamGroup};
pub use types::{
    CompiledHealthCheck, CompiledLocation, CompiledMatcher, CompiledNrfDiscovery, CompiledRegex,
    CompiledRouter, CompiledUpstreamGroup, CompiledUpstreamServer, CompliedRouter, HealthCheckType,
    HttpRuntimeOptions, ListenKey, ListenerProtocolConfig, ListenerTlsConfig, ListenerTlsSettings,
    RouteTarget, ServerRoutes, VirtualHostRoutes,
};

pub(crate) use runtime::{
    ClientIdentityKey, RuntimeClientIdentity, RuntimeTrustedCa, build_runtime_client_identities,
    build_runtime_trusted_cas,
};

#[cfg(test)]
pub(crate) use compile::downstream_keepalive_timeout_secs;
#[cfg(test)]
pub(crate) use routing::{listener_routes, select_route_target, validate_sni_host_consistency};
#[cfg(test)]
pub(crate) use runtime::{
    apply_upstream_http_protocol, apply_upstream_ssl_options, apply_upstream_timeouts,
    content_length_limit_exceeded, update_received_body_bytes, upstream_selection_key,
};

#[cfg(test)]
mod tests;
