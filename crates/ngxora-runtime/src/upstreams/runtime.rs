//! Request state and the public Pingora runtime API. Internal modules own selection, TLS and response writing.

use super::types::RouteTarget;
use crate::cache::{CacheBackend, CacheKey};
use crate::control::{RuntimeSnapshot, RuntimeState};
use crate::le::ChallengeTokens;
use bytes::BytesMut;
use ngxora_compile::ir::{CacheConfig, UpstreamHttpProtocol, UpstreamSslOptions, UpstreamTimeouts};
use ngxora_plugin_api::PluginState;
use std::sync::Arc;

mod completion;
mod groups;
mod limits;
mod proxy;
mod response;
mod selection;
mod tls;

#[derive(Debug, Clone, Eq, PartialEq)]
struct SelectedPeer {
    host: String,
    port: u16,
    tls: bool,
    sni: String,
    upstream_group: Option<String>,
    api_prefix: Option<String>,
}

#[derive(Debug, Clone)]
enum SelectedTarget {
    Pending(RouteTarget),
    DirectResponse(u16),
    Scp(String),
    Upstream(SelectedPeer),
    Return { status: u16, location: String },
}

#[derive(Clone)]
pub(crate) struct SelectedRoute {
    url_rewrite: Option<ngxora_compile::ir::UrlRewrite>,
    matched_prefix: Option<String>,
    route_id: u64,
    target: SelectedTarget,
    access_rules: Vec<ngxora_compile::ir::LocationIpRule>,
    upstream_timeouts: UpstreamTimeouts,
    upstream_protocol: Option<UpstreamHttpProtocol>,
    upstream_http2: ngxora_compile::ir::UpstreamHttp2Options,
    upstream_ssl_options: UpstreamSslOptions,
    upstream_trusted_ca: Option<RuntimeTrustedCa>,
    upstream_client_identity: Option<RuntimeClientIdentity>,
    plugins: ngxora_plugin_api::PluginChain,
    cache: Option<CacheConfig>,
}

impl SelectedRoute {
    pub(crate) fn route_id(&self) -> u64 {
        self.route_id
    }
}

pub struct ProxyContext {
    pub(crate) snapshot: Option<Arc<RuntimeSnapshot>>,
    pub(crate) response_plugins_applied: bool,
    pub(crate) snapshot_generation: u64,
    pub(crate) scp: Option<super::scp::ScpExchange>,
    pub(crate) scp_profile: Option<Arc<super::scp::RuntimeScp>>,
    pub(crate) selected: Option<SelectedRoute>,
    pub(crate) plugin_state: PluginState,
    pub(crate) client_max_body_size: Option<u64>,
    pub(crate) received_body_bytes: u64,
    pub(crate) cache_key: Option<CacheKey>,
    pub(crate) cache_store_allowed: bool,
    pub(crate) cache_status: Option<http::StatusCode>,
    pub(crate) cache_headers: Option<http::HeaderMap>,
    pub(crate) cache_body_limit: Option<u64>,
    pub(crate) response_body_buf: BytesMut,
    /// Timestamp when the request was created; used for latency calculation.
    pub(crate) start_time: std::time::Instant,
    /// True when the request was served from cache (set in request_filter).
    pub(crate) cache_hit: bool,
    /// True once Pingora asks for an upstream peer for this request.
    pub(crate) upstream_attempted: bool,
    /// OpenTelemetry span for this request (None if tracing is not configured).
    pub(crate) span: Option<opentelemetry::global::BoxedSpan>,
    /// Extracted W3C TraceContext from downstream headers.
    pub(crate) parent_ctx: opentelemetry::Context,
    /// Trace context derived from the current proxy span for upstream propagation.
    pub(crate) upstream_trace_ctx: opentelemetry::Context,
}

impl Default for ProxyContext {
    fn default() -> Self {
        Self {
            snapshot: None,
            response_plugins_applied: false,
            snapshot_generation: 0,
            scp: None,
            scp_profile: None,
            selected: None,
            plugin_state: PluginState::default(),
            client_max_body_size: None,
            received_body_bytes: 0,
            cache_key: None,
            cache_store_allowed: false,
            cache_status: None,
            cache_headers: None,
            cache_body_limit: None,
            response_body_buf: BytesMut::new(),
            start_time: std::time::Instant::now(),
            cache_hit: false,
            upstream_attempted: false,
            span: None,
            parent_ctx: opentelemetry::Context::new(),
            upstream_trace_ctx: opentelemetry::Context::new(),
        }
    }
}

pub struct DynamicProxy {
    state: Arc<RuntimeState>,
    cache_backend: CacheBackend,
    /// Shared HTTP-01 challenge token store for Let's Encrypt certificate issuance.
    challenge_tokens: ChallengeTokens,
}

pub use groups::RuntimeUpstreamGroup;

pub(crate) use tls::ClientIdentityKey;

pub(crate) use tls::RuntimeClientIdentity;

pub(crate) use tls::RuntimeTrustedCa;

pub(crate) use tls::build_runtime_client_identities;

pub(crate) use tls::build_runtime_trusted_cas;

#[cfg(test)]
pub(crate) use tls::apply_upstream_http_protocol;

#[cfg(test)]
pub(crate) use tls::apply_upstream_ssl_options;

#[cfg(test)]
pub(crate) use tls::apply_upstream_timeouts;

#[cfg(test)]
pub(crate) use limits::content_length_limit_exceeded;

#[cfg(test)]
pub(crate) use limits::update_received_body_bytes;

#[cfg(test)]
pub(crate) use selection::upstream_selection_key;

#[cfg(test)]
mod tests;

fn cache_store_allowed(cfg: &CacheConfig, threshold_reached: bool) -> bool {
    cfg.min_uses.unwrap_or(1) <= 1 || threshold_reached
}

fn runtime_config_error(error: impl std::fmt::Display) -> Box<pingora::Error> {
    pingora::Error::explain(pingora::ErrorType::InternalError, error.to_string())
}
