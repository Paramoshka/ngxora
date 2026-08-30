use super::compile::proxy_pass_sni;
use super::nrf::NrfClient;
use super::routing::{ResolvedLocation, listener_routes, resolve_route};
use super::types::{
    CompiledRouter, CompiledUpstreamGroup, CompiledUpstreamServer, ListenKey, RouteTarget,
    VirtualHostRoutes,
};
use crate::cache::{
    CacheBackend, CacheKey, build_cache_key, estimated_headers_size, is_cacheable,
    is_cacheable_request,
};
use crate::control::{ApplyResult, ConfigSnapshot, RuntimeSnapshot, RuntimeState};
use crate::le::ChallengeTokens;
use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::{Bytes, BytesMut};
use futures::{FutureExt, StreamExt, future, stream};
use ngxora_compile::ir::{
    CacheConfig, PemSource, Switch, UpstreamHashKey, UpstreamHttpProtocol, UpstreamSelectionPolicy,
    UpstreamSslOptions, UpstreamTimeouts,
};
use ngxora_plugin_api::{
    HeaderMapMut, LocalResponse, PluginError, PluginFlow, PluginState, RequestCtx, ResponseCtx,
    UpstreamRequestCtx,
};
use opentelemetry::trace::{Span, TraceContextExt};
use pingora::Result as PingoraResult;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora::lb::discovery::ServiceDiscovery;
use pingora::lb::{Backend, Backends, LoadBalancer, discovery, selection};
use pingora::protocols::l4::socket::SocketAddr as PingoraSocketAddr;
use pingora::protocols::tls::CaType;
#[cfg(feature = "openssl")]
use pingora::tls::pkey::PKey;
#[cfg(feature = "openssl")]
use pingora::tls::x509::X509;
use pingora::upstreams::peer::HttpPeer;
use pingora::utils::tls::CertKey;
use pingora_proxy::{ProxyHttp, Session};
use std::collections::{BTreeSet, HashMap};
use std::fmt::Display;
use std::hash::{Hash, Hasher};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

const NRF_PREFLIGHT_CONCURRENCY: usize = 16;

fn nrf_failure_retry_at(now: Instant, expires_at: Option<Instant>, failures: u32) -> Instant {
    let exponent = failures.saturating_sub(1).min(5);
    let backoff = Duration::from_secs((1u64 << exponent).min(30));
    let backoff_at = now.checked_add(backoff).unwrap_or(now);
    expires_at.map_or(backoff_at, |expires_at| backoff_at.min(expires_at))
}

fn nrf_snapshot_expiry(
    now: Instant,
    validity: Duration,
    stale_if_error: Duration,
) -> Option<Instant> {
    now.checked_add(validity)
        .and_then(|valid_until| valid_until.checked_add(stale_if_error))
}

pub(crate) type RuntimeTrustedCa = Arc<CaType>;
pub(crate) type RuntimeClientIdentity = Arc<CertKey>;

/// Key identifying one (cert, key) pair so identical identities are loaded once.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub(crate) struct ClientIdentityKey {
    pub cert: PemSource,
    pub key: PemSource,
}

pub struct RuntimeUpstreamGroup {
    selector: RuntimeUpstreamSelector,
    hash_key: Option<UpstreamHashKey>,
    health_check: Option<RuntimeHealthCheckSchedule>,
    nrf_discovery: Option<RuntimeNrfDiscovery>,
}

#[derive(Clone, Default)]
struct RuntimeDiscoverySource {
    backends: Arc<ArcSwap<BTreeSet<Backend>>>,
}

struct RuntimeNrfDiscovery {
    group_name: String,
    client: NrfClient,
    source: RuntimeDiscoverySource,
    health_check: super::CompiledHealthCheck,
    stale_if_error: Duration,
    schedule: Mutex<NrfRefreshSchedule>,
}

struct NrfRefreshSchedule {
    next_run_at: Instant,
    expires_at: Option<Instant>,
    failures: u32,
    last_success_at: Option<Instant>,
    endpoint_count: usize,
}

enum RuntimeUpstreamSelector {
    RoundRobin(LoadBalancer<selection::RoundRobin>),
    Random(LoadBalancer<selection::Random>),
    ConsistentHash(LoadBalancer<selection::Consistent>),
}

struct RuntimeHealthCheckSchedule {
    interval: Duration,
    next_run_at: Mutex<Instant>,
}

fn synthetic_backends(servers: &[CompiledUpstreamServer]) -> Result<BTreeSet<Backend>, String> {
    servers
        .iter()
        .enumerate()
        .map(|(index, server)| {
            let mut ext = http::Extensions::new();
            ext.insert(server.clone());

            Ok(Backend {
                addr: PingoraSocketAddr::Inet(synthetic_backend_addr(
                    u64::try_from(index).unwrap_or(u64::MAX),
                )),
                weight: usize::from(server.weight),
                ext,
            })
        })
        .collect()
}

fn dynamic_synthetic_backends(
    servers: &[CompiledUpstreamServer],
) -> Result<BTreeSet<Backend>, String> {
    let mut used = BTreeSet::new();
    servers
        .iter()
        .map(|server| {
            let mut ext = http::Extensions::new();
            ext.insert(server.clone());
            let mut id = stable_backend_id(server);
            while !used.insert(id) {
                id = id.wrapping_add(1);
            }

            Ok(Backend {
                addr: PingoraSocketAddr::Inet(synthetic_backend_addr(id)),
                weight: usize::from(server.weight),
                ext,
            })
        })
        .collect()
}

fn stable_backend_id(server: &CompiledUpstreamServer) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    server.host.hash(&mut hasher);
    server.port.hash(&mut hasher);
    hasher.finish()
}

fn synthetic_backend_addr(id: u64) -> SocketAddr {
    let ip = Ipv6Addr::new(
        0xfd00,
        0,
        0,
        0,
        ((id >> 32) & 0xffff) as u16,
        ((id >> 16) & 0xffff) as u16,
        (id & 0xffff) as u16,
        1,
    );

    SocketAddr::V6(SocketAddrV6::new(ip, 1, 0, 0))
}

fn build_load_balancer<S>(
    backends: Backends,
    health_check: Option<&super::CompiledHealthCheck>,
) -> Result<LoadBalancer<S>, String>
where
    S: selection::BackendSelection + 'static,
    S::Iter: selection::BackendIter,
{
    let mut lb = LoadBalancer::from_backends(backends);
    if let Some(health_check) = health_check {
        lb.set_health_check(health_check.build()?);
    }
    lb.update()
        .now_or_never()
        .ok_or_else(|| "static upstream update unexpectedly blocked".to_string())?
        .map_err(|err| format!("failed to initialize upstream load balancer: {err}"))?;
    Ok(lb)
}

impl RuntimeDiscoverySource {
    fn with_backends(backends: BTreeSet<Backend>) -> Self {
        Self {
            backends: Arc::new(ArcSwap::from_pointee(backends)),
        }
    }

    fn set(&self, backends: BTreeSet<Backend>) {
        self.backends.store(Arc::new(backends));
    }
}

#[async_trait]
impl ServiceDiscovery for RuntimeDiscoverySource {
    async fn discover(&self) -> PingoraResult<(BTreeSet<Backend>, HashMap<u64, bool>)> {
        Ok(((**self.backends.load()).clone(), HashMap::new()))
    }
}

impl RuntimeNrfDiscovery {
    fn record_metrics(&self, now: Instant) {
        let schedule = self.schedule.lock().unwrap();
        let age = schedule
            .last_success_at
            .map(|last_success| now.saturating_duration_since(last_success))
            .unwrap_or_default();
        crate::metrics::set_nrf_discovery_snapshot(&self.group_name, age, schedule.endpoint_count);
    }

    async fn expire_snapshot(&self, selector: &RuntimeUpstreamSelector) {
        if self.schedule.lock().unwrap().endpoint_count == 0 {
            return;
        }

        self.source.set(BTreeSet::new());
        match selector.update().await {
            Ok(()) => self.schedule.lock().unwrap().endpoint_count = 0,
            Err(err) => {
                log::warn!(
                    "NRF discovery for upstream `{}` failed to expire stale backends: {err}",
                    self.group_name
                );
            }
        }
    }

    async fn discover(
        &self,
        now: Instant,
        selector: &RuntimeUpstreamSelector,
    ) -> Result<super::nrf::DiscoveryResult, String> {
        let expires_at = self.schedule.lock().unwrap().expires_at;
        let Some(expires_at) = expires_at.filter(|expires_at| *expires_at > now) else {
            return self.client.discover().await;
        };

        let request = self.client.discover();
        tokio::pin!(request);
        tokio::select! {
            result = &mut request => result,
            _ = tokio::time::sleep_until(expires_at) => {
                self.expire_snapshot(selector).await;
                request.await
            }
        }
    }

    async fn record_failure(&self, now: Instant, selector: &RuntimeUpstreamSelector) -> Instant {
        crate::metrics::record_nrf_discovery_request(&self.group_name, "error");
        let (next_run_at, expired) = {
            let mut schedule = self.schedule.lock().unwrap();
            schedule.failures = schedule.failures.saturating_add(1);
            schedule.next_run_at =
                nrf_failure_retry_at(now, schedule.expires_at, schedule.failures);
            (
                schedule.next_run_at,
                schedule
                    .expires_at
                    .is_some_and(|expires_at| now >= expires_at),
            )
        };

        if expired {
            self.expire_snapshot(selector).await;
        }
        next_run_at
    }
}

fn nrf_refresh_delay(validity: Duration, group_name: &str) -> Duration {
    let identity = std::env::var("HOSTNAME").unwrap_or_else(|_| std::process::id().to_string());
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    identity.hash(&mut hasher);
    group_name.hash(&mut hasher);
    let percent = 70 + hasher.finish() % 21;
    let millis = validity.as_millis().saturating_mul(u128::from(percent)) / 100;
    Duration::from_millis(millis.max(1_000).try_into().unwrap_or(u64::MAX))
}

impl RuntimeUpstreamSelector {
    fn select(&self, key: &[u8], max_iterations: usize) -> Option<Backend> {
        match self {
            Self::RoundRobin(lb) => lb.select(key, max_iterations),
            Self::Random(lb) => lb.select(key, max_iterations),
            Self::ConsistentHash(lb) => lb.select(key, max_iterations),
        }
    }

    async fn run_health_check(&self) {
        match self {
            Self::RoundRobin(lb) => lb.backends().run_health_check(false).await,
            Self::Random(lb) => lb.backends().run_health_check(false).await,
            Self::ConsistentHash(lb) => lb.backends().run_health_check(false).await,
        }
    }

    async fn update(&self) -> PingoraResult<()> {
        match self {
            Self::RoundRobin(lb) => lb.update().await,
            Self::Random(lb) => lb.update().await,
            Self::ConsistentHash(lb) => lb.update().await,
        }
    }

    fn backends(&self) -> &Backends {
        match self {
            Self::RoundRobin(lb) => lb.backends(),
            Self::Random(lb) => lb.backends(),
            Self::ConsistentHash(lb) => lb.backends(),
        }
    }
}

impl RuntimeUpstreamGroup {
    pub(crate) fn from_compiled(group: &CompiledUpstreamGroup) -> Result<Self, String> {
        if group.servers.is_empty() && group.nrf_discovery.is_none() {
            return Err(format!(
                "upstream `{}` must define at least one server or nrf_discovery",
                group.name
            ));
        }

        let backends = synthetic_backends(&group.servers)?;
        let nrf_source = group
            .nrf_discovery
            .as_ref()
            .map(|_| RuntimeDiscoverySource::with_backends(backends.clone()));
        let discovery: Box<dyn ServiceDiscovery + Send + Sync> = match &nrf_source {
            Some(source) => Box::new(source.clone()),
            None => discovery::Static::new(backends),
        };
        let backends = Backends::new(discovery);
        let selector = match group.policy {
            UpstreamSelectionPolicy::RoundRobin => RuntimeUpstreamSelector::RoundRobin(
                build_load_balancer(backends, group.health_check.as_ref())?,
            ),
            UpstreamSelectionPolicy::Random => RuntimeUpstreamSelector::Random(
                build_load_balancer(backends, group.health_check.as_ref())?,
            ),
            UpstreamSelectionPolicy::ConsistentHash => RuntimeUpstreamSelector::ConsistentHash(
                build_load_balancer(backends, group.health_check.as_ref())?,
            ),
        };

        let nrf_discovery = match (&group.nrf_discovery, nrf_source, &group.health_check) {
            (Some(config), Some(source), Some(health_check)) => Some(RuntimeNrfDiscovery {
                group_name: group.name.clone(),
                client: NrfClient::new(config)?,
                source,
                health_check: health_check.clone(),
                stale_if_error: config.stale_if_error,
                schedule: Mutex::new(NrfRefreshSchedule {
                    next_run_at: Instant::now(),
                    expires_at: None,
                    failures: 0,
                    last_success_at: None,
                    endpoint_count: 0,
                }),
            }),
            (None, None, _) => None,
            _ => {
                return Err(format!(
                    "upstream `{}` has incomplete nrf_discovery runtime state",
                    group.name
                ));
            }
        };

        Ok(Self {
            selector,
            hash_key: group.hash_key.clone(),
            health_check: group.health_check.as_ref().map(|health_check| {
                RuntimeHealthCheckSchedule {
                    interval: health_check.interval,
                    next_run_at: Mutex::new(Instant::now()),
                }
            }),
            nrf_discovery,
        })
    }

    pub(crate) fn select(&self, key: &[u8]) -> Option<CompiledUpstreamServer> {
        let backend_count = self.selector.backends().get_backend().len();
        let max_iterations = if self.uses_consistent_hash() {
            backend_count.max(256)
        } else {
            backend_count
        };
        let backend = self.selector.select(key, max_iterations)?;
        backend.ext.get::<CompiledUpstreamServer>().cloned()
    }

    pub(crate) async fn run_due_nrf_discovery(&self, now: Instant) -> Option<Instant> {
        let discovery = self.nrf_discovery.as_ref()?;
        discovery.record_metrics(now);
        let (next_run, expired) = {
            let schedule = discovery.schedule.lock().unwrap();
            (
                schedule.next_run_at,
                schedule
                    .expires_at
                    .is_some_and(|expires_at| now >= expires_at),
            )
        };
        if expired {
            discovery.expire_snapshot(&self.selector).await;
        }
        if now < next_run {
            return Some(next_run);
        }

        discovery.schedule.lock().unwrap().next_run_at =
            now.checked_add(Duration::from_secs(1)).unwrap_or(now);
        match discovery.discover(now, &self.selector).await {
            Ok(result) => {
                let expires_at =
                    nrf_snapshot_expiry(now, result.validity, discovery.stale_if_error);
                let Some(expires_at) = expires_at else {
                    log::warn!(
                        "NRF discovery for upstream `{}` returned an unsupported validityPeriod",
                        discovery.group_name
                    );
                    return Some(discovery.record_failure(now, &self.selector).await);
                };
                let checker = match discovery.health_check.build() {
                    Ok(checker) => checker,
                    Err(err) => {
                        log::warn!(
                            "NRF discovery for upstream `{}` could not build preflight check: {err}",
                            discovery.group_name
                        );
                        return Some(discovery.record_failure(now, &self.selector).await);
                    }
                };
                let candidates = match dynamic_synthetic_backends(&result.endpoints) {
                    Ok(candidates) => candidates,
                    Err(err) => {
                        log::warn!(
                            "NRF discovery for upstream `{}` produced invalid backends: {err}",
                            discovery.group_name
                        );
                        return Some(discovery.record_failure(now, &self.selector).await);
                    }
                };
                let ready = stream::iter(candidates)
                    .map(|backend| {
                        let checker = checker.as_ref();
                        async move { checker.check(&backend).await.is_ok().then_some(backend) }
                    })
                    .buffer_unordered(NRF_PREFLIGHT_CONCURRENCY)
                    .filter_map(future::ready)
                    .collect::<BTreeSet<_>>()
                    .await;

                let endpoint_count = ready.len();
                discovery.source.set(ready);
                if let Err(err) = self.selector.update().await {
                    log::warn!(
                        "NRF discovery for upstream `{}` failed to publish backends: {err}",
                        discovery.group_name
                    );
                    return Some(discovery.record_failure(now, &self.selector).await);
                }
                crate::metrics::record_nrf_discovery_request(&discovery.group_name, "success");

                let delay = nrf_refresh_delay(result.validity, &discovery.group_name);
                let next_run_at = now.checked_add(delay).unwrap_or(expires_at).min(expires_at);
                let mut schedule = discovery.schedule.lock().unwrap();
                schedule.next_run_at = next_run_at;
                schedule.expires_at = Some(expires_at);
                schedule.failures = 0;
                schedule.last_success_at = Some(now);
                schedule.endpoint_count = endpoint_count;
                Some(next_run_at)
            }
            Err(err) => {
                log::warn!(
                    "NRF discovery for upstream `{}` failed: {err}",
                    discovery.group_name
                );
                Some(discovery.record_failure(now, &self.selector).await)
            }
        }
    }

    fn hash_key(&self) -> Option<&UpstreamHashKey> {
        self.hash_key.as_ref()
    }

    fn uses_consistent_hash(&self) -> bool {
        matches!(self.selector, RuntimeUpstreamSelector::ConsistentHash(_))
    }

    pub(crate) fn readiness(&self) -> Vec<(CompiledUpstreamServer, bool)> {
        let backends = self.selector.backends();
        backends
            .get_backend()
            .iter()
            .filter_map(|backend| {
                backend
                    .ext
                    .get::<CompiledUpstreamServer>()
                    .cloned()
                    .map(|server| (server, backends.ready(backend)))
            })
            .collect()
    }

    pub(crate) async fn run_due_health_check(&self, now: Instant) -> Option<Instant> {
        let schedule = self.health_check.as_ref()?;
        let next_run_at = {
            let mut next_run_at = schedule
                .next_run_at
                .lock()
                .expect("health check lock poisoned");
            if *next_run_at > now {
                return Some(*next_run_at);
            }
            *next_run_at = now + schedule.interval;
            *next_run_at
        };
        self.selector.run_health_check().await;
        Some(next_run_at)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct SelectedPeer {
    host: String,
    port: u16,
    tls: bool,
    sni: String,
    upstream_group: Option<String>,
}

#[derive(Debug, Clone)]
enum SelectedTarget {
    Upstream(SelectedPeer),
    Return { status: u16, location: String },
}

#[derive(Clone)]
pub(crate) struct SelectedRoute {
    route_id: u64,
    target: SelectedTarget,
    access_rules: Vec<ngxora_compile::ir::LocationIpRule>,
    upstream_timeouts: UpstreamTimeouts,
    upstream_protocol: Option<UpstreamHttpProtocol>,
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

fn cache_store_allowed(cfg: &CacheConfig, threshold_reached: bool) -> bool {
    cfg.min_uses.unwrap_or(1) <= 1 || threshold_reached
}

pub struct ProxyContext {
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

fn should_mark_span_as_error(e: Option<&pingora::Error>, status: u16) -> bool {
    if status >= 500 {
        return true;
    }

    matches!(
        e,
        Some(err) if !matches!(err.etype, pingora::ErrorType::HTTPStatus(_))
    )
}

fn header_editor_error(action: &str, name: &http::HeaderName, err: impl Display) -> PluginError {
    PluginError::new(
        "header-editor",
        format!("failed to {action} header `{name}`: {err}"),
    )
}

struct RequestHeaderEditor<'a> {
    inner: &'a mut RequestHeader,
}

impl HeaderMapMut for RequestHeaderEditor<'_> {
    fn get(&self, name: &http::HeaderName) -> Option<&http::HeaderValue> {
        self.inner.headers.get(name)
    }

    fn add(
        &mut self,
        name: &http::HeaderName,
        value: http::HeaderValue,
    ) -> Result<(), PluginError> {
        self.inner
            .append_header(name, value)
            .map(|_| ())
            .map_err(|err| header_editor_error("append", name, err))
    }

    fn set(
        &mut self,
        name: &http::HeaderName,
        value: http::HeaderValue,
    ) -> Result<(), PluginError> {
        self.inner
            .insert_header(name, value)
            .map_err(|err| header_editor_error("insert", name, err))
    }

    fn remove(&mut self, name: &http::HeaderName) {
        self.inner.remove_header(name);
    }
}

struct ResponseHeaderEditor<'a> {
    inner: &'a mut ResponseHeader,
}

impl HeaderMapMut for ResponseHeaderEditor<'_> {
    fn get(&self, name: &http::HeaderName) -> Option<&http::HeaderValue> {
        self.inner.headers.get(name)
    }

    fn add(
        &mut self,
        name: &http::HeaderName,
        value: http::HeaderValue,
    ) -> Result<(), PluginError> {
        self.inner
            .append_header(name, value)
            .map(|_| ())
            .map_err(|err| header_editor_error("append", name, err))
    }

    fn set(
        &mut self,
        name: &http::HeaderName,
        value: http::HeaderValue,
    ) -> Result<(), PluginError> {
        self.inner
            .insert_header(name, value)
            .map_err(|err| header_editor_error("insert", name, err))
    }

    fn remove(&mut self, name: &http::HeaderName) {
        self.inner.remove_header(name);
    }
}

impl SelectedRoute {
    fn from_resolved(
        snapshot: &RuntimeSnapshot,
        resolved: &ResolvedLocation<'_>,
        session: &Session,
    ) -> PingoraResult<Self> {
        let target = match &resolved.location.target {
            RouteTarget::Return { status, location } => {
                return Ok(Self {
                    route_id: resolved.location.route_id,
                    access_rules: Vec::new(),
                    target: SelectedTarget::Return {
                        status: *status,
                        location: location.clone(),
                    },
                    upstream_timeouts: UpstreamTimeouts::default(),
                    upstream_protocol: None,
                    upstream_ssl_options: UpstreamSslOptions::default(),
                    upstream_trusted_ca: None,
                    upstream_client_identity: None,
                    plugins: snapshot.plugin_chain(resolved.location.route_id),
                    cache: resolved.location.cache.clone(),
                });
            }
            RouteTarget::ProxyPass {
                host,
                port,
                tls,
                sni,
            } => SelectedTarget::Upstream(SelectedPeer {
                host: host.clone(),
                port: *port,
                tls: *tls,
                sni: sni.clone(),
                upstream_group: None,
            }),
            RouteTarget::UpstreamGroup { name, tls } => {
                let group = snapshot.upstream_group(name).ok_or_else(|| {
                    pingora::Error::explain(
                        pingora::ErrorType::InternalError,
                        format!("compiled upstream group `{name}` is missing at runtime"),
                    )
                })?;
                let key = if group.uses_consistent_hash() {
                    upstream_selection_key(group.hash_key(), session)?
                } else {
                    Vec::new()
                };
                let backend = group.select(&key).ok_or_else(|| {
                    pingora::Error::explain(
                        pingora::ErrorType::HTTPStatus(503),
                        format!("upstream `{name}` has no available backends"),
                    )
                })?;

                SelectedTarget::Upstream(SelectedPeer {
                    sni: proxy_pass_sni(&backend.host, *tls),
                    host: backend.host,
                    port: backend.port,
                    tls: *tls,
                    upstream_group: Some(name.trim_end_matches('.').to_ascii_lowercase()),
                })
            }
        };

        let upstream_client_identity = match (
            resolved
                .location
                .upstream_ssl_options
                .client_certificate
                .as_ref(),
            resolved
                .location
                .upstream_ssl_options
                .client_certificate_key
                .as_ref(),
        ) {
            (Some(cert), Some(key)) => {
                Some(snapshot.client_identity(cert, key).ok_or_else(|| {
                    pingora::Error::explain(
                        pingora::ErrorType::InternalError,
                        "compiled upstream client identity is missing at runtime",
                    )
                })?)
            }
            _ => None,
        };

        Ok(Self {
            route_id: resolved.location.route_id,
            access_rules: resolved.location.access_rules.clone(),
            target,
            upstream_timeouts: resolved.location.upstream_timeouts,
            upstream_protocol: resolved.location.upstream_protocol,
            upstream_ssl_options: resolved.location.upstream_ssl_options.clone(),
            upstream_trusted_ca: resolved
                .location
                .upstream_ssl_options
                .trusted_certificate
                .as_ref()
                .map(|source| {
                    snapshot.trusted_ca(source).ok_or_else(|| {
                        pingora::Error::explain(
                            pingora::ErrorType::InternalError,
                            "compiled trusted upstream CA is missing at runtime",
                        )
                    })
                })
                .transpose()?,
            upstream_client_identity,
            plugins: snapshot.plugin_chain(resolved.location.route_id),
            cache: resolved.location.cache.clone(),
        })
    }
}

fn select_runtime_route(
    snapshot: &RuntimeSnapshot,
    session: &Session,
) -> PingoraResult<Option<(SelectedRoute, Option<String>)>> {
    let Some(resolved) = resolve_route(&snapshot.router, session)? else {
        return Ok(None);
    };

    Ok(Some((
        SelectedRoute::from_resolved(snapshot, &resolved, session)?,
        resolved.host,
    )))
}

pub(crate) fn upstream_selection_key(
    configured: Option<&UpstreamHashKey>,
    session: &Session,
) -> PingoraResult<Vec<u8>> {
    if let Some(UpstreamHashKey::Header(name)) = configured {
        let mut values = session.req_header().headers.get_all(name).iter();
        if let (Some(value), None) = (values.next(), values.next())
            && !value.as_bytes().is_empty()
        {
            return Ok(value.as_bytes().to_vec());
        }
    }

    request_client_ip(session)
        .map(|ip| ip.to_string().into_bytes())
        .ok_or_else(|| {
            pingora::Error::explain(
                pingora::ErrorType::HTTPStatus(503),
                "consistent hash requires a request header key or socket client IP",
            )
        })
}

fn request_client_ip(session: &Session) -> Option<std::net::IpAddr> {
    session
        .downstream_session
        .client_addr()
        .and_then(|addr| addr.as_inet())
        .map(|addr| addr.ip())
}

fn location_allows_client(
    rules: &[ngxora_compile::ir::LocationIpRule],
    client_ip: Option<std::net::IpAddr>,
) -> bool {
    if rules.is_empty() {
        return true;
    }

    let Some(ip) = client_ip else {
        return false;
    };

    for rule in rules {
        if rule.matches(&ip) {
            return rule.is_allow();
        }
    }

    false
}

fn respond_from_plugin_flow(flow: PluginFlow, stage: &str) -> PingoraResult<()> {
    match flow {
        PluginFlow::Continue => Ok(()),
        PluginFlow::Respond(_) => Err(pingora::Error::explain(
            pingora::ErrorType::InternalError,
            format!("plugin attempted local response during {stage}, which is not supported"),
        )),
    }
}

fn map_plugin_error(stage: &str, err: PluginError) -> Box<pingora::Error> {
    pingora::Error::explain(
        pingora::ErrorType::InternalError,
        format!("plugin hook failed during {stage}: {err}"),
    )
}

fn set_content_length(header: &mut ResponseHeader, value: impl ToString) -> PingoraResult<()> {
    let value = value.to_string();
    header
        .insert_header(http::header::CONTENT_LENGTH, value)
        .map_err(|err| {
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                format!("failed to finalize plugin response: {err}"),
            )
        })
}

fn normalized_peer_timeout(timeout: Option<Duration>) -> Option<Duration> {
    match timeout {
        Some(timeout) if timeout.is_zero() => None,
        other => other,
    }
}

fn body_too_large_error() -> Box<pingora::Error> {
    pingora::Error::explain(
        pingora::ErrorType::HTTPStatus(413),
        "request body exceeds client_max_body_size",
    )
}

pub(crate) fn content_length_limit_exceeded(
    header: Option<&http::HeaderValue>,
    limit: Option<u64>,
) -> Option<bool> {
    let limit = limit?;
    let header = header?;
    let size = header.to_str().ok()?.parse::<u64>().ok()?;
    Some(size > limit)
}

pub(crate) fn update_received_body_bytes(
    received: &mut u64,
    body: Option<&Bytes>,
    limit: Option<u64>,
) -> PingoraResult<()> {
    let Some(limit) = limit else {
        return Ok(());
    };
    let Some(body) = body else {
        return Ok(());
    };

    let chunk_len = u64::try_from(body.len()).map_err(|_| body_too_large_error())?;
    let next = received
        .checked_add(chunk_len)
        .ok_or_else(body_too_large_error)?;
    if next > limit {
        return Err(body_too_large_error());
    }

    *received = next;
    Ok(())
}

// Route-level timeout directives are mapped directly to Pingora upstream peer
// options, so they can change live with route snapshots.
pub(crate) fn apply_upstream_timeouts(peer: &mut HttpPeer, timeouts: UpstreamTimeouts) {
    peer.options.connection_timeout = normalized_peer_timeout(timeouts.connect);
    peer.options.read_timeout = normalized_peer_timeout(timeouts.read);
    peer.options.write_timeout = normalized_peer_timeout(timeouts.write);
}

pub(crate) fn apply_upstream_http_protocol(
    peer: &mut HttpPeer,
    protocol: Option<UpstreamHttpProtocol>,
) {
    match protocol {
        Some(UpstreamHttpProtocol::H1) => peer.options.set_http_version(1, 1),
        Some(UpstreamHttpProtocol::H2 | UpstreamHttpProtocol::H2c) => {
            peer.options.set_http_version(2, 2)
        }
        None => {}
    }
}

// Apply SSL options from location directives to Pingora peer options.
pub(crate) fn apply_upstream_ssl_options(
    peer: &mut HttpPeer,
    options: &UpstreamSslOptions,
    trusted_ca: Option<&RuntimeTrustedCa>,
    client_identity: Option<&RuntimeClientIdentity>,
) {
    match options.verify_cert {
        Switch::On => {
            peer.options.verify_cert = true;
            peer.options.verify_hostname = true;
        }
        Switch::Off => {
            peer.options.verify_cert = false;
            peer.options.verify_hostname = false;
        }
    }

    peer.options.ca = trusted_ca.cloned();
    peer.client_cert_key = client_identity.cloned();
}

pub(crate) fn build_runtime_trusted_cas(
    router: &CompiledRouter,
) -> Result<HashMap<PemSource, RuntimeTrustedCa>, String> {
    let mut trusted_cas = HashMap::new();

    for routes in router.listeners.values() {
        collect_trusted_cas_from_vhosts(routes, &mut trusted_cas)?;
    }

    Ok(trusted_cas)
}

fn collect_trusted_cas_from_vhosts(
    routes: &VirtualHostRoutes,
    trusted_cas: &mut HashMap<PemSource, RuntimeTrustedCa>,
) -> Result<(), String> {
    for server_routes in routes.named.values().chain(routes.default.iter()) {
        collect_trusted_cas_from_server(server_routes, trusted_cas)?;
    }

    Ok(())
}

fn collect_trusted_cas_from_server(
    routes: &super::ServerRoutes,
    trusted_cas: &mut HashMap<PemSource, RuntimeTrustedCa>,
) -> Result<(), String> {
    for location in &routes.locations {
        let Some(source) = location.upstream_ssl_options.trusted_certificate.as_ref() else {
            continue;
        };
        if trusted_cas.contains_key(source) {
            continue;
        }

        trusted_cas.insert(source.clone(), load_runtime_trusted_ca(source)?);
    }

    Ok(())
}

fn read_pem_source(source: &PemSource, label: &str) -> Result<Vec<u8>, String> {
    match source {
        PemSource::Path(path) => std::fs::read(path)
            .map_err(|err| format!("failed to read {label} `{}`: {err}", path.display())),
        PemSource::InlinePem(pem) => Ok(pem.as_bytes().to_vec()),
    }
}

#[cfg(feature = "openssl")]
fn load_runtime_trusted_ca(source: &PemSource) -> Result<RuntimeTrustedCa, String> {
    let pem = read_pem_source(source, "proxy_ssl_trusted_certificate")?;
    let certs = X509::stack_from_pem(&pem)
        .map_err(|err| format!("failed to parse proxy_ssl_trusted_certificate: {err}"))?;
    if certs.is_empty() {
        return Err("proxy_ssl_trusted_certificate does not contain any certificates".into());
    }

    Ok(Arc::new(certs.into_boxed_slice()))
}

#[cfg(not(feature = "openssl"))]
fn load_runtime_trusted_ca(_source: &PemSource) -> Result<RuntimeTrustedCa, String> {
    Err("proxy_ssl_trusted_certificate requires build with feature `openssl`".into())
}

// Collect every distinct upstream client identity declared in the router so
// each (cert, key) pair is parsed exactly once per snapshot build.
pub(crate) fn build_runtime_client_identities(
    router: &CompiledRouter,
) -> Result<HashMap<ClientIdentityKey, RuntimeClientIdentity>, String> {
    let mut identities = HashMap::new();

    for routes in router.listeners.values() {
        collect_client_identities_from_vhosts(routes, &mut identities)?;
    }

    Ok(identities)
}

fn collect_client_identities_from_vhosts(
    routes: &VirtualHostRoutes,
    identities: &mut HashMap<ClientIdentityKey, RuntimeClientIdentity>,
) -> Result<(), String> {
    for server_routes in routes.named.values().chain(routes.default.iter()) {
        collect_client_identities_from_server(server_routes, identities)?;
    }

    Ok(())
}

fn collect_client_identities_from_server(
    routes: &super::ServerRoutes,
    identities: &mut HashMap<ClientIdentityKey, RuntimeClientIdentity>,
) -> Result<(), String> {
    for location in &routes.locations {
        let (Some(cert), Some(key)) = (
            location.upstream_ssl_options.client_certificate.as_ref(),
            location
                .upstream_ssl_options
                .client_certificate_key
                .as_ref(),
        ) else {
            continue;
        };

        let identity_key = ClientIdentityKey {
            cert: cert.clone(),
            key: key.clone(),
        };
        if identities.contains_key(&identity_key) {
            continue;
        }

        identities.insert(identity_key, load_runtime_client_identity(cert, key)?);
    }

    Ok(())
}

#[cfg(feature = "openssl")]
fn load_runtime_client_identity(
    cert_source: &PemSource,
    key_source: &PemSource,
) -> Result<RuntimeClientIdentity, String> {
    let cert_pem = read_pem_source(cert_source, "proxy_ssl_certificate")?;
    let certs = X509::stack_from_pem(&cert_pem)
        .map_err(|err| format!("failed to parse proxy_ssl_certificate: {err}"))?;
    if certs.is_empty() {
        return Err("proxy_ssl_certificate does not contain any certificates".into());
    }

    let key_pem = read_pem_source(key_source, "proxy_ssl_certificate_key")?;
    let key = PKey::private_key_from_pem(&key_pem)
        .map_err(|err| format!("failed to parse proxy_ssl_certificate_key: {err}"))?;

    Ok(Arc::new(CertKey::new(certs, key)))
}

#[cfg(not(feature = "openssl"))]
fn load_runtime_client_identity(
    _cert_source: &PemSource,
    _key_source: &PemSource,
) -> Result<RuntimeClientIdentity, String> {
    Err("proxy_ssl_certificate requires build with feature `openssl`".into())
}

// Content-Length is only a fast path. Chunked and h2 bodies are enforced later
// in request_body_filter while the downstream body stream is consumed.
async fn restrict_client_max_body_size(
    session: &mut Session,
    ctx: &mut ProxyContext,
) -> PingoraResult<bool> {
    if content_length_limit_exceeded(
        session.get_header(http::header::CONTENT_LENGTH),
        ctx.client_max_body_size,
    ) == Some(true)
    {
        session.set_keepalive(None);
        session.respond_error(413).await?;
        return Ok(true);
    }

    Ok(false)
}

// Plugins can short-circuit the request path with a local response, but that
// response is still normalized through Pingora's typed response writer.
async fn write_local_response(session: &mut Session, response: LocalResponse) -> PingoraResult<()> {
    let mut header = ResponseHeader::build(response.status, None).map_err(|err| {
        pingora::Error::explain(
            pingora::ErrorType::InternalError,
            format!("failed to build plugin response: {err}"),
        )
    })?;
    for (name, value) in response.headers {
        header.insert_header(name, value).map_err(|err| {
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                format!("failed to insert plugin response header: {err}"),
            )
        })?;
    }

    if response.body.is_empty() {
        set_content_length(&mut header, 0)?;
        session.write_response_header(Box::new(header), true).await
    } else {
        set_content_length(&mut header, response.body.len().to_string())?;
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session.write_response_body(Some(response.body), true).await
    }
}

async fn write_cached_response(
    session: &mut Session,
    cached: &crate::cache::CachedResponse,
) -> PingoraResult<()> {
    let mut header = ResponseHeader::build(cached.status, None).map_err(|err| {
        pingora::Error::explain(
            pingora::ErrorType::InternalError,
            format!("failed to build cached response header: {err}"),
        )
    })?;
    for (name, value) in cached.headers.iter() {
        header
            .insert_header(name.clone(), value.clone())
            .map_err(|err| {
                pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    format!("failed to insert cached header `{name}`: {err}"),
                )
            })?;
    }
    if cached.body.is_empty() {
        session.write_response_header(Box::new(header), true).await
    } else {
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(cached.body.clone()), true)
            .await
    }
}

pub struct DynamicProxy {
    state: Arc<RuntimeState>,
    cache_backend: CacheBackend,
    /// Shared HTTP-01 challenge token store for Let's Encrypt certificate issuance.
    challenge_tokens: ChallengeTokens,
}

impl DynamicProxy {
    pub fn new(state: Arc<RuntimeState>) -> Self {
        Self {
            state,
            cache_backend: CacheBackend::new(50 * 1024 * 1024), // 50MB default
            challenge_tokens: Arc::new(dashmap::DashMap::new()),
        }
    }

    pub fn new_with_cache(state: Arc<RuntimeState>, cache_backend: CacheBackend) -> Self {
        Self {
            state,
            cache_backend,
            challenge_tokens: Arc::new(dashmap::DashMap::new()),
        }
    }

    /// Set the challenge token store (called after LE manager is created).
    pub fn set_challenge_tokens(&mut self, tokens: ChallengeTokens) {
        self.challenge_tokens = tokens;
    }

    pub fn from_router(routing: CompiledRouter) -> Self {
        Self::new(Arc::new(RuntimeState::bootstrap(routing)))
    }

    pub fn runtime_state(&self) -> &Arc<RuntimeState> {
        &self.state
    }

    /// Retrieve routes for a specific key (lock-free).
    pub fn get_routes(&self, key: &ListenKey) -> Option<Arc<VirtualHostRoutes>> {
        let snapshot = self.state.snapshot();
        listener_routes(&snapshot.router, key)
            .cloned()
            .map(Arc::new)
    }

    /// Replace the entire routing table if listener topology stays compatible.
    pub fn update_routing(&self, new_router: CompiledRouter) -> ApplyResult {
        self.state
            .apply_snapshot(ConfigSnapshot::new("runtime-update", new_router))
    }
}

#[async_trait]
impl ProxyHttp for DynamicProxy {
    type CTX = ProxyContext;

    fn new_ctx(&self) -> Self::CTX {
        ProxyContext::default()
    }

    // Request plugins run in declaration order and may terminate the request
    // locally before any upstream peer is selected.
    async fn request_filter(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<bool> {
        // ── Tracing: extract parent context from downstream headers ──
        ctx.parent_ctx = crate::tracing::extract_context(&session.req_header().headers);
        let method = session.req_header().method.to_string();
        let path = session.req_header().uri.path().to_string();
        let span = crate::tracing::start_request_span(&method, &path, &ctx.parent_ctx);
        ctx.upstream_trace_ctx =
            opentelemetry::Context::new().with_remote_span_context(span.span_context().clone());
        ctx.span = Some(span);

        let snapshot = self.state.snapshot();
        session.set_keepalive(snapshot.router.http_options.downstream_keepalive_timeout);
        ctx.client_max_body_size = snapshot.router.http_options.client_max_body_size;
        ctx.received_body_bytes = 0;

        // Apply global proxy_cache_max_size from config (once per snapshot
        // change — set_default_max_size is a relaxed atomic store).
        if let Some(global_size) = snapshot.router.http_options.proxy_cache_max_size {
            self.cache_backend.set_default_max_size(global_size);
        }

        if restrict_client_max_body_size(session, ctx).await? {
            return Ok(true);
        }

        // Let's Encrypt HTTP-01 challenge responder.
        if let Some(token) = session
            .req_header()
            .uri
            .path()
            .strip_prefix("/.well-known/acme-challenge/")
        {
            if !token.is_empty() && !token.contains('/') {
                if let Some(key_auth) = self.challenge_tokens.get(token).map(|v| v.clone()) {
                    let mut response = LocalResponse::new(http::StatusCode::OK, "");
                    response.headers.push((
                        http::header::CONTENT_TYPE,
                        http::HeaderValue::from_static("text/plain"),
                    ));
                    response.body = key_auth.into_bytes().into();
                    session.set_keepalive(None);
                    write_local_response(session, response).await?;
                    return Ok(true);
                }
            }
        }

        let Some((selected, host)) = select_runtime_route(&snapshot, session)? else {
            ctx.selected = None;
            return Ok(false);
        };

        let path = session.req_header().uri.path().to_string();
        let method = session.req_header().method.clone();
        let request_was_cacheable = is_cacheable_request(&method, &session.req_header().headers);
        let client_ip = request_client_ip(session);
        if !location_allows_client(&selected.access_rules, client_ip) {
            session.set_keepalive(None);
            session
                .respond_error(http::StatusCode::FORBIDDEN.into())
                .await?;
            return Ok(true);
        }

        let mut headers = RequestHeaderEditor {
            inner: session.downstream_session.req_header_mut(),
        };

        for plugin in selected.plugins.iter() {
            let flow = plugin
                .on_request(&mut RequestCtx {
                    state: &mut ctx.plugin_state,
                    path: &path,
                    host: host.as_deref(),
                    method: &method,
                    client_ip,
                    headers: &mut headers,
                })
                .await
                .map_err(|err| map_plugin_error("request_filter", err))?;
            if let PluginFlow::Respond(response) = flow {
                session.set_keepalive(None);
                write_local_response(session, response).await?;
                return Ok(true);
            }
        }

        ctx.selected = Some(selected.clone());

        // Authentication, rate limiting, and other request plugins must run
        // before a cache hit can terminate the request.
        if request_was_cacheable
            && is_cacheable_request(&session.req_header().method, &session.req_header().headers)
        {
            if let Some(cache_cfg) = &selected.cache {
                let full_uri = session.req_header().uri.to_string();
                let cache_key = build_cache_key(
                    &session.req_header().method,
                    &full_uri,
                    snapshot.generation,
                    selected.route_id(),
                    host.as_deref().unwrap_or(""),
                    cache_cfg,
                );
                if let Some(cached) = self.cache_backend.get(&cache_key, cache_cfg).await {
                    ctx.cache_hit = true;
                    write_cached_response(session, &cached).await?;
                    return Ok(true);
                }
                ctx.cache_store_allowed = self.cache_backend.record_miss(&cache_key, cache_cfg);
                ctx.cache_key = Some(cache_key);
            }
        }

        // Handle return/redirect targets
        if let SelectedTarget::Return { status, location } = &selected.target {
            let status_code = http::StatusCode::from_u16(*status).map_err(|_| {
                pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    format!("invalid redirect status code: {status}"),
                )
            })?;

            let mut response = LocalResponse::new(status_code, "");
            response.headers.push((
                http::header::LOCATION,
                http::HeaderValue::from_str(location).map_err(|_| {
                    pingora::Error::explain(
                        pingora::ErrorType::InternalError,
                        format!("invalid redirect location: {location}"),
                    )
                })?,
            ));

            session.set_keepalive(None);
            write_local_response(session, response).await?;
            return Ok(true);
        }

        Ok(false)
    }

    async fn request_body_filter(
        &self,
        session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()> {
        // Classic WebSocket upgrades switch the downstream body stream into a
        // raw upgraded tunnel after the 101 response. That traffic must not be
        // counted against HTTP request body limits.
        if session.was_upgraded() {
            return Ok(());
        }

        update_received_body_bytes(
            &mut ctx.received_body_bytes,
            body.as_ref(),
            ctx.client_max_body_size,
        )
    }

    async fn upstream_request_filter(
        &self,
        _session: &mut Session,
        upstream_request: &mut RequestHeader,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()> {
        let Some(selected) = ctx.selected.as_ref() else {
            return Ok(());
        };

        let mut headers = RequestHeaderEditor {
            inner: upstream_request,
        };

        for plugin in selected.plugins.iter() {
            let flow = plugin
                .on_upstream_request(&mut UpstreamRequestCtx {
                    state: &mut ctx.plugin_state,
                    headers: &mut headers,
                })
                .await
                .map_err(|err| map_plugin_error("upstream_request_filter", err))?;
            respond_from_plugin_flow(flow, "upstream_request_filter")?;
        }

        // ── Inject W3C TraceContext into upstream headers ──
        crate::tracing::inject_context(&ctx.upstream_trace_ctx, &mut upstream_request.headers);

        Ok(())
    }

    /// Serve a stale cached response when upstream returns an error.
    ///
    /// Only activates when the location has `proxy_cache_stale_if_error`
    /// configured and a cached entry exists (TTL is ignored for stale).
    async fn fail_to_proxy(
        &self,
        session: &mut Session,
        _error: &pingora::Error,
        ctx: &mut Self::CTX,
    ) -> pingora_proxy::FailToProxy
    where
        Self::CTX: Send + Sync,
    {
        let Some(selected) = ctx.selected.as_ref() else {
            return pingora_proxy::FailToProxy {
                can_reuse_downstream: false,
                error_code: 502,
            };
        };
        let Some(cache_cfg) = selected.cache.as_ref() else {
            return pingora_proxy::FailToProxy {
                can_reuse_downstream: false,
                error_code: 502,
            };
        };
        // stale_if_error must be explicitly configured
        if cache_cfg.stale_if_error.is_none() {
            return pingora_proxy::FailToProxy {
                can_reuse_downstream: false,
                error_code: 502,
            };
        }
        let Some(cache_key) = &ctx.cache_key else {
            return pingora_proxy::FailToProxy {
                can_reuse_downstream: false,
                error_code: 502,
            };
        };

        let Some(mut cached) = self.cache_backend.get_stale(cache_key, cache_cfg).await else {
            return pingora_proxy::FailToProxy {
                can_reuse_downstream: false,
                error_code: 502,
            };
        };

        cached.headers.insert(
            http::HeaderName::from_static("x-cache"),
            http::HeaderValue::from_static("STALE"),
        );

        ctx.cache_hit = true;
        if write_cached_response(session, &cached).await.is_err() {
            return pingora_proxy::FailToProxy {
                can_reuse_downstream: false,
                error_code: 502,
            };
        }

        pingora_proxy::FailToProxy {
            can_reuse_downstream: true,
            error_code: cached.status.as_u16(),
        }
    }

    // Response plugins run in reverse order so they behave like unwind-style
    // middleware around the upstream exchange.
    async fn response_filter(
        &self,
        _session: &mut Session,
        upstream_response: &mut ResponseHeader,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<()> {
        let Some(selected) = ctx.selected.as_ref() else {
            return Ok(());
        };

        let mut status = upstream_response.status;
        {
            let mut headers = ResponseHeaderEditor {
                inner: upstream_response,
            };

            for plugin in selected.plugins.iter().rev() {
                let flow = plugin
                    .on_response(&mut ResponseCtx {
                        state: &mut ctx.plugin_state,
                        status: &mut status,
                        headers: &mut headers,
                    })
                    .await
                    .map_err(|err| map_plugin_error("response_filter", err))?;
                respond_from_plugin_flow(flow, "response_filter")?;
            }
        }

        upstream_response.set_status(status).map_err(|err| {
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                format!("failed to update response status from plugin chain: {err}"),
            )
        })?;

        // Cacheability must be evaluated against the final response that the
        // client will actually receive after plugins mutate headers/status.
        if let (Some(_cache_key), Some(cache_cfg)) = (&ctx.cache_key, selected.cache.as_ref()) {
            if cache_store_allowed(cache_cfg, ctx.cache_store_allowed)
                && is_cacheable(status, &upstream_response.headers, cache_cfg)
            {
                let entry_overhead =
                    estimated_headers_size(&upstream_response.headers).saturating_add(128);
                let body_limit = self
                    .cache_backend
                    .max_size(cache_cfg)
                    .saturating_sub(entry_overhead);
                let content_length_fits = upstream_response
                    .headers
                    .get(http::header::CONTENT_LENGTH)
                    .map(|value| {
                        value
                            .to_str()
                            .ok()
                            .and_then(|value| value.parse::<u64>().ok())
                            .is_some_and(|length| length <= body_limit)
                    })
                    .unwrap_or(true);

                if content_length_fits {
                    ctx.cache_status = Some(status);
                    ctx.cache_headers = Some(upstream_response.headers.clone());
                    ctx.cache_body_limit = Some(body_limit);
                }
            }
        }

        Ok(())
    }

    /// Collect upstream response body chunks for later caching in `logging`.
    fn response_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        _end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<Option<Duration>> {
        let Some(body_limit) = ctx.cache_body_limit else {
            return Ok(None);
        };

        if let Some(chunk) = body.as_ref() {
            let next_size = (ctx.response_body_buf.len() as u64).saturating_add(chunk.len() as u64);
            if next_size > body_limit {
                ctx.cache_status = None;
                ctx.cache_headers = None;
                ctx.cache_body_limit = None;
                ctx.response_body_buf.clear();
                return Ok(None);
            }

            ctx.response_body_buf.extend_from_slice(chunk);
        }
        Ok(None)
    }

    /// Store cacheable responses when the request completes, record metrics,
    /// and emit the structured access log.
    async fn logging(
        &self,
        session: &mut Session,
        e: Option<&pingora::Error>,
        ctx: &mut Self::CTX,
    ) {
        // ── Collect observability data ──
        let method = session.req_header().method.to_string();
        let path = session.req_header().uri.path().to_string();
        let status = e
            .and_then(|err| match &err.etype {
                pingora::ErrorType::HTTPStatus(code) => Some(*code),
                _ => None,
            })
            .or_else(|| session.response_written().map(|r| r.status.as_u16()))
            .unwrap_or(0);
        let latency = ctx.start_time.elapsed();
        let upstream = ctx.selected.as_ref().and_then(|s| match &s.target {
            SelectedTarget::Upstream(peer) => Some(format!("{}:{}", peer.host, peer.port)),
            SelectedTarget::Return { .. } => None,
        });
        let upstream_group = ctx.selected.as_ref().and_then(|s| match &s.target {
            SelectedTarget::Upstream(peer) => peer.upstream_group.as_deref(),
            SelectedTarget::Return { .. } => None,
        });
        let route_id = ctx.selected.as_ref().map(|s| s.route_id());

        // Cache status: hit when served from cache in request_filter, miss
        // when a cache key exists but we went upstream, bypass otherwise.
        let had_upstream = !matches!(
            ctx.selected.as_ref().map(|s| &s.target),
            Some(SelectedTarget::Return { .. }) | None
        ) && e.is_none();
        let cache_status = if ctx.cache_hit {
            "hit"
        } else if e.is_some() {
            "bypass"
        } else if ctx.cache_key.is_some() {
            "miss"
        } else {
            "bypass"
        };

        // ── Set trace span attributes ──
        if let Some(ref mut span) = ctx.span {
            span.set_attribute(opentelemetry::KeyValue::new(
                "http.status_code",
                status as i64,
            ));
            span.set_attribute(opentelemetry::KeyValue::new("http.method", method.clone()));
            span.set_attribute(opentelemetry::KeyValue::new("http.route", path.clone()));
            if let Some(ref u) = upstream {
                span.set_attribute(opentelemetry::KeyValue::new("upstream", u.clone()));
            }
            span.set_attribute(opentelemetry::KeyValue::new(
                "cache.status",
                cache_status.to_string(),
            ));
            if should_mark_span_as_error(e, status) {
                span.set_status(opentelemetry::trace::Status::error("proxy error"));
            }
            span.end();
        }

        // ── Write structured JSON access log ──
        if method != "GET" || path != "/metrics" {
            crate::metrics::write_access_log(
                session,
                &method,
                &path,
                status,
                Some(latency),
                upstream.as_deref(),
                upstream_group,
                Some(cache_status),
                route_id,
            );
        }

        // ── Record Prometheus metrics ──
        let cache_metric_status = match cache_status {
            "hit" => crate::metrics::CacheStatus::Hit,
            "miss" => crate::metrics::CacheStatus::Miss,
            _ => crate::metrics::CacheStatus::Bypass,
        };
        crate::metrics::record_metrics(
            &crate::metrics::RequestLabels {
                method: method.clone(),
                status: status.to_string(),
                cache_status: cache_metric_status,
                has_upstream: had_upstream,
                route_id: route_id.unwrap_or(0),
            },
            latency.as_secs_f64(),
            0,
            ctx.response_body_buf.len() as u64,
        );
        if ctx.upstream_attempted
            && let (Some(group), Some(backend)) = (upstream_group, upstream.as_deref())
        {
            crate::metrics::record_upstream_backend_metrics(
                group,
                backend,
                status,
                latency.as_secs_f64(),
            );
        }

        // ── Original cache-store logic ──
        if e.is_some() {
            ctx.cache_headers = None;
            ctx.cache_status = None;
            ctx.cache_body_limit = None;
            ctx.response_body_buf.clear();
            return;
        }

        if let (Some(cache_key), Some(cache_cfg)) = (
            &ctx.cache_key,
            ctx.selected.as_ref().and_then(|s| s.cache.as_ref()),
        ) {
            if !cache_store_allowed(cache_cfg, ctx.cache_store_allowed) {
                ctx.cache_headers = None;
                ctx.cache_status = None;
                ctx.cache_body_limit = None;
                ctx.response_body_buf.clear();
                return;
            }

            if let (Some(status), Some(headers)) = (ctx.cache_status, ctx.cache_headers.take()) {
                let body = std::mem::take(&mut ctx.response_body_buf).freeze();
                self.cache_backend
                    .put(
                        cache_key.clone(),
                        crate::cache::CachedResponse {
                            status,
                            headers,
                            body,
                            created_at: std::time::Instant::now(),
                        },
                        cache_cfg,
                    )
                    .await;
            }
        }
    }

    // Upstream selection is derived from the already resolved route; if the
    // request_filter path did not run, we resolve lazily here as a fallback.
    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> PingoraResult<Box<HttpPeer>> {
        let selected = if let Some(selected) = ctx.selected.as_ref().cloned() {
            selected
        } else {
            let snapshot = self.state.snapshot();
            let Some((selected, _host)) = select_runtime_route(&snapshot, session)? else {
                return Err(pingora::Error::explain(
                    pingora::ErrorType::HTTPStatus(404),
                    "no location matched",
                ));
            };
            ctx.selected = Some(selected.clone());
            selected
        };

        let peer = match &selected.target {
            SelectedTarget::Upstream(peer) => peer,
            SelectedTarget::Return { .. } => {
                return Err(pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    "upstream_peer called on a return target — request_filter should have short-circuited",
                ));
            }
        };
        ctx.upstream_attempted = true;

        let mut http_peer =
            HttpPeer::new((peer.host.as_str(), peer.port), peer.tls, peer.sni.clone());
        apply_upstream_timeouts(&mut http_peer, selected.upstream_timeouts);
        apply_upstream_http_protocol(&mut http_peer, selected.upstream_protocol);
        apply_upstream_ssl_options(
            &mut http_peer,
            &selected.upstream_ssl_options,
            selected.upstream_trusted_ca.as_ref(),
            selected.upstream_client_identity.as_ref(),
        );

        Ok(Box::new(http_peer))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::StatusCode;
    use ipnet::IpNet;
    use ngxora_compile::ir::LocationIpRule;
    use ngxora_plugin_api::{HttpPlugin, PluginFlow, async_trait, empty_plugin_chain};
    use std::sync::Arc;
    use tokio::io::{AsyncWriteExt, duplex};

    async fn test_session() -> Session {
        let (mut client, server) = duplex(1024);
        client
            .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .await
            .expect("write request");

        let mut session = Session::new_h1(Box::new(server));
        session.read_request().await.expect("read request");
        session
    }

    #[test]
    fn nrf_failure_backoff_never_schedules_past_snapshot_expiry() {
        let now = Instant::now();
        let expires_at = now + Duration::from_secs(5);

        assert_eq!(
            nrf_failure_retry_at(now, Some(expires_at), 1),
            now + Duration::from_secs(1)
        );
        assert_eq!(nrf_failure_retry_at(now, Some(expires_at), 6), expires_at);
    }

    #[test]
    fn nrf_snapshot_expiry_rejects_unrepresentable_validity() {
        let now = Instant::now();

        assert_eq!(
            nrf_snapshot_expiry(now, Duration::from_secs(30), Duration::from_secs(60)),
            Some(now + Duration::from_secs(90))
        );
        assert!(nrf_snapshot_expiry(now, Duration::MAX, Duration::from_secs(1)).is_none());
    }

    fn cached_route(cache: CacheConfig, plugins: ngxora_plugin_api::PluginChain) -> SelectedRoute {
        SelectedRoute {
            route_id: 1,
            access_rules: Vec::new(),
            target: SelectedTarget::Upstream(SelectedPeer {
                host: "127.0.0.1".into(),
                port: 8080,
                tls: false,
                sni: String::new(),
                upstream_group: Some("backend".into()),
            }),
            upstream_timeouts: UpstreamTimeouts::default(),
            upstream_protocol: None,
            upstream_ssl_options: UpstreamSslOptions::default(),
            upstream_trusted_ca: None,
            upstream_client_identity: None,
            plugins,
            cache: Some(cache),
        }
    }

    struct StatusRewritePlugin {
        status: StatusCode,
    }

    #[async_trait]
    impl HttpPlugin for StatusRewritePlugin {
        fn name(&self) -> &'static str {
            "status-rewrite"
        }

        async fn on_response(&self, ctx: &mut ResponseCtx<'_>) -> Result<PluginFlow, PluginError> {
            *ctx.status = self.status;
            Ok(PluginFlow::Continue)
        }
    }

    #[tokio::test]
    async fn response_body_filter_preserves_downstream_body() {
        let proxy = DynamicProxy::from_router(CompiledRouter::default());
        let mut session = test_session().await;
        let mut ctx = ProxyContext {
            cache_headers: Some(http::HeaderMap::new()),
            cache_body_limit: Some(1024),
            ..Default::default()
        };
        let original = Bytes::from_static(b"hello");
        let mut body = Some(original.clone());

        ProxyHttp::response_body_filter(&proxy, &mut session, &mut body, false, &mut ctx)
            .expect("body filter succeeds");

        assert_eq!(body, Some(original.clone()));
        assert_eq!(ctx.response_body_buf, original);
    }

    #[tokio::test]
    async fn response_body_filter_stops_buffering_at_cache_limit() {
        let proxy = DynamicProxy::from_router(CompiledRouter::default());
        let mut session = test_session().await;
        let mut ctx = ProxyContext {
            cache_status: Some(StatusCode::OK),
            cache_headers: Some(http::HeaderMap::new()),
            cache_body_limit: Some(4),
            response_body_buf: BytesMut::from(&b"abc"[..]),
            ..Default::default()
        };
        let original = Bytes::from_static(b"de");
        let mut body = Some(original.clone());

        ProxyHttp::response_body_filter(&proxy, &mut session, &mut body, false, &mut ctx)
            .expect("body filter succeeds");

        assert_eq!(body, Some(original));
        assert!(ctx.response_body_buf.is_empty());
        assert!(ctx.cache_headers.is_none());
        assert!(ctx.cache_body_limit.is_none());
    }

    #[test]
    fn location_access_rules_defaults_to_allow() {
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
        assert!(location_allows_client(&[], Some(ip)));
    }

    #[test]
    fn location_access_rules_first_match_wins() {
        let rules = vec![
            LocationIpRule::Deny("10.0.0.0/8".parse::<IpNet>().expect("allowlist parse")),
            LocationIpRule::Allow(
                "10.0.0.1/32"
                    .parse::<IpNet>()
                    .expect("10.0.0.1/32 is valid"),
            ),
        ];
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 0, 0, 1));
        assert!(!location_allows_client(&rules, Some(ip)));
    }

    #[test]
    fn location_access_rules_without_client_ip_is_denied_if_restricted() {
        let rules = vec![LocationIpRule::AllowAll];
        assert!(!location_allows_client(&rules, None));
    }

    #[tokio::test]
    async fn response_filter_uses_final_plugin_status_for_cacheability() {
        let proxy = DynamicProxy::from_router(CompiledRouter::default());
        let mut session = test_session().await;
        let cache_cfg = CacheConfig {
            valid_statuses: vec![302],
            ..CacheConfig::default()
        };
        let plugins: ngxora_plugin_api::PluginChain = vec![Arc::new(StatusRewritePlugin {
            status: StatusCode::FOUND,
        }) as Arc<dyn HttpPlugin>]
        .into();
        let mut ctx = ProxyContext {
            selected: Some(cached_route(cache_cfg.clone(), plugins)),
            cache_key: Some(CacheKey {
                generation: 1,
                route_id: 1,
                host: "localhost".into(),
                method: "GET".into(),
                uri: "/".into(),
            }),
            ..Default::default()
        };
        let mut upstream_response =
            ResponseHeader::build(StatusCode::OK, None).expect("build response");

        ProxyHttp::response_filter(&proxy, &mut session, &mut upstream_response, &mut ctx)
            .await
            .expect("response filter succeeds");

        assert_eq!(upstream_response.status, StatusCode::FOUND);
        assert_eq!(ctx.cache_status, Some(StatusCode::FOUND));
        assert!(ctx.cache_headers.is_some());
    }

    #[tokio::test]
    async fn logging_skips_cache_write_after_error() {
        let cache_backend = CacheBackend::new(10 * 1024 * 1024);
        let proxy = DynamicProxy::new_with_cache(
            Arc::new(RuntimeState::bootstrap(CompiledRouter::default())),
            cache_backend,
        );
        let mut session = test_session().await;
        let cache_cfg = CacheConfig::default();
        let key = CacheKey {
            generation: 1,
            route_id: 1,
            host: "localhost".into(),
            method: "GET".into(),
            uri: "/partial".into(),
        };
        let mut ctx = ProxyContext {
            selected: Some(cached_route(cache_cfg.clone(), empty_plugin_chain())),
            cache_key: Some(key.clone()),
            cache_status: Some(StatusCode::OK),
            cache_headers: Some(http::HeaderMap::new()),
            response_body_buf: BytesMut::from(&b"partial"[..]),
            ..Default::default()
        };
        let err = pingora::Error::explain(pingora::ErrorType::InternalError, "boom");

        ProxyHttp::logging(&proxy, &mut session, Some(err.as_ref()), &mut ctx).await;

        assert!(proxy.cache_backend.get(&key, &cache_cfg).await.is_none());
        assert_eq!(proxy.cache_backend.total_entries(), 0);
        assert!(ctx.response_body_buf.is_empty());
    }

    #[tokio::test]
    async fn logging_caches_empty_cacheable_response() {
        let cache_backend = CacheBackend::new(10 * 1024 * 1024);
        let proxy = DynamicProxy::new_with_cache(
            Arc::new(RuntimeState::bootstrap(CompiledRouter::default())),
            cache_backend,
        );
        let mut session = test_session().await;
        let cache_cfg = CacheConfig {
            valid_statuses: vec![301],
            ..CacheConfig::default()
        };
        let key = CacheKey {
            generation: 1,
            route_id: 1,
            host: "localhost".into(),
            method: "GET".into(),
            uri: "/redirect".into(),
        };
        let mut ctx = ProxyContext {
            selected: Some(cached_route(cache_cfg.clone(), empty_plugin_chain())),
            cache_key: Some(key.clone()),
            ..Default::default()
        };
        let mut upstream_response =
            ResponseHeader::build(StatusCode::MOVED_PERMANENTLY, None).expect("build response");

        ProxyHttp::response_filter(&proxy, &mut session, &mut upstream_response, &mut ctx)
            .await
            .expect("response filter succeeds");
        ProxyHttp::logging(&proxy, &mut session, None, &mut ctx).await;

        let cached = proxy
            .cache_backend
            .get(&key, &cache_cfg)
            .await
            .expect("empty redirect should be cached");
        assert_eq!(cached.status, StatusCode::MOVED_PERMANENTLY);
        assert!(cached.body.is_empty());
    }

    #[tokio::test]
    async fn logging_skips_cache_write_until_min_uses_is_reached() {
        let cache_backend = CacheBackend::new(10 * 1024 * 1024);
        let proxy = DynamicProxy::new_with_cache(
            Arc::new(RuntimeState::bootstrap(CompiledRouter::default())),
            cache_backend,
        );
        let mut session = test_session().await;
        let cache_cfg = CacheConfig {
            min_uses: Some(2),
            ..CacheConfig::default()
        };
        let key = CacheKey {
            generation: 1,
            route_id: 1,
            host: "localhost".into(),
            method: "GET".into(),
            uri: "/warming".into(),
        };

        let mut first_ctx = ProxyContext {
            selected: Some(cached_route(cache_cfg.clone(), empty_plugin_chain())),
            cache_key: Some(key.clone()),
            cache_store_allowed: false,
            cache_status: Some(StatusCode::OK),
            cache_headers: Some(http::HeaderMap::new()),
            response_body_buf: BytesMut::from(&b"first"[..]),
            ..Default::default()
        };

        ProxyHttp::logging(&proxy, &mut session, None, &mut first_ctx).await;
        assert!(proxy.cache_backend.get(&key, &cache_cfg).await.is_none());

        let mut second_ctx = ProxyContext {
            selected: Some(cached_route(cache_cfg.clone(), empty_plugin_chain())),
            cache_key: Some(key.clone()),
            cache_store_allowed: true,
            cache_status: Some(StatusCode::OK),
            cache_headers: Some(http::HeaderMap::new()),
            response_body_buf: BytesMut::from(&b"second"[..]),
            ..Default::default()
        };

        ProxyHttp::logging(&proxy, &mut session, None, &mut second_ctx).await;

        let cached = proxy
            .cache_backend
            .get(&key, &cache_cfg)
            .await
            .expect("response should be cached after min_uses is reached");
        assert_eq!(cached.body, Bytes::from_static(b"second"));
    }

    #[test]
    fn span_status_ignores_http_4xx_error_responses() {
        let err = pingora::Error::explain(pingora::ErrorType::HTTPStatus(404), "not found");
        assert!(!should_mark_span_as_error(Some(err.as_ref()), 404));
    }

    #[test]
    fn span_status_marks_http_5xx_responses_as_errors() {
        let err = pingora::Error::explain(pingora::ErrorType::HTTPStatus(503), "unavailable");
        assert!(should_mark_span_as_error(Some(err.as_ref()), 503));
        assert!(should_mark_span_as_error(None, 502));
    }

    #[test]
    fn span_status_marks_non_http_errors_as_failures() {
        let err = pingora::Error::explain(pingora::ErrorType::InternalError, "boom");
        assert!(should_mark_span_as_error(Some(err.as_ref()), 0));
    }
}
