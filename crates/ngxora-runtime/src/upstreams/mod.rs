//! Runtime routing and upstream execution for compiled ngxora HTTP config.
//!
//! The module boundary is:
//! - `compile`: IR -> `CompiledRouter`
//! - `routing`: request-time listener/vhost/location selection
//! - `runtime`: Pingora-facing proxy execution and upstream groups
//! - `health`: active upstream health checks
//! - `types`: shared compiled routing model

mod compile;
mod health;
mod routing;
mod runtime;
mod types;

pub use runtime::{DynamicProxy, ProxyContext, RuntimeUpstreamGroup};
pub use types::{
    CompiledHealthCheck, CompiledLocation, CompiledMatcher, CompiledRegex, CompiledRouter,
    CompiledUpstreamGroup, CompiledUpstreamServer, CompliedRouter, HealthCheckType,
    HttpRuntimeOptions, ListenKey, ListenerProtocolConfig, ListenerTlsConfig, ListenerTlsSettings,
    RouteTarget, ServerRoutes, VirtualHostRoutes,
};

pub(crate) use runtime::{RuntimeTrustedCa, build_runtime_trusted_cas};

#[cfg(test)]
pub(crate) use compile::downstream_keepalive_timeout_secs;
#[cfg(test)]
pub(crate) use routing::{listener_routes, select_route_target, validate_sni_host_consistency};
#[cfg(test)]
pub(crate) use runtime::{
    apply_upstream_http_protocol, apply_upstream_ssl_options, apply_upstream_timeouts,
    content_length_limit_exceeded, update_received_body_bytes,
};

#[cfg(test)]
mod tests;
