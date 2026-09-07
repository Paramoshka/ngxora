//! Upstream groups and endpoint health/selection; NRF state is managed by discovery and topology.

use crate::upstreams::nrf::NrfClient;
use crate::upstreams::types::{CompiledUpstreamGroup, CompiledUpstreamServer};
use arc_swap::{ArcSwap, ArcSwapOption};
use async_trait::async_trait;
use discovery::{nrf_refresh_delay, nrf_snapshot_expiry};
use futures::{FutureExt, StreamExt, future, stream};
use ngxora_compile::ir::{UpstreamHashKey, UpstreamSelectionPolicy};
use pingora::Result as PingoraResult;
use pingora::lb::discovery::{ServiceDiscovery, Static};
use pingora::lb::{Backend, Backends, LoadBalancer, selection};
use pingora::protocols::l4::socket::SocketAddr as PingoraSocketAddr;
use std::collections::{BTreeSet, HashMap};
use std::hash::{Hash, Hasher};
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;
use topology::NrfServiceTopology;

mod discovery;
mod topology;

const NRF_PREFLIGHT_CONCURRENCY: usize = 16;

pub struct RuntimeUpstreamGroup {
    scp_refreshing: std::sync::atomic::AtomicBool,
    scp_refreshed: tokio::sync::Notify,
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
    refresh_lock: tokio::sync::Mutex<()>,
    permits: Option<Arc<tokio::sync::Semaphore>>,
    group_name: String,
    client: NrfClient,
    source: RuntimeDiscoverySource,
    health_check: crate::upstreams::CompiledHealthCheck,
    stale_if_error: Duration,
    policy: UpstreamSelectionPolicy,
    selection: ArcSwapOption<NrfServiceTopology>,
    schedule: Mutex<NrfRefreshSchedule>,
}

struct NrfRefreshSchedule {
    invalid_api: bool,
    candidate_count: usize,
    candidates: Vec<CompiledUpstreamServer>,
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
    server.api_prefix.hash(&mut hasher);
    if let Some(service) = server.nrf_service.as_ref() {
        service.nf_instance_id.hash(&mut hasher);
        service.service_instance_id.hash(&mut hasher);
    }
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
    health_check: Option<&crate::upstreams::CompiledHealthCheck>,
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

fn build_runtime_selector(
    policy: UpstreamSelectionPolicy,
    backends: Backends,
    health_check: Option<&crate::upstreams::CompiledHealthCheck>,
) -> Result<RuntimeUpstreamSelector, String> {
    match policy {
        UpstreamSelectionPolicy::RoundRobin => Ok(RuntimeUpstreamSelector::RoundRobin(
            build_load_balancer(backends, health_check)?,
        )),
        UpstreamSelectionPolicy::Random => Ok(RuntimeUpstreamSelector::Random(
            build_load_balancer(backends, health_check)?,
        )),
        UpstreamSelectionPolicy::ConsistentHash => Ok(RuntimeUpstreamSelector::ConsistentHash(
            build_load_balancer(backends, health_check)?,
        )),
    }
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

impl RuntimeUpstreamSelector {
    fn select(&self, key: &[u8], max_iterations: usize) -> Option<Backend> {
        match self {
            Self::RoundRobin(lb) => lb.select(key, max_iterations),
            Self::Random(lb) => lb.select(key, max_iterations),
            Self::ConsistentHash(lb) => lb.select(key, max_iterations),
        }
    }

    fn select_with<F>(&self, key: &[u8], max_iterations: usize, accept: F) -> Option<Backend>
    where
        F: Fn(&Backend, bool) -> bool,
    {
        match self {
            Self::RoundRobin(lb) => lb.select_with(key, max_iterations, accept),
            Self::Random(lb) => lb.select_with(key, max_iterations, accept),
            Self::ConsistentHash(lb) => lb.select_with(key, max_iterations, accept),
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
        Self::from_compiled_query(group, None, None)
    }

    pub(in crate::upstreams) fn from_compiled_query(
        group: &CompiledUpstreamGroup,
        query: Option<crate::upstreams::nrf::NrfQuery>,
        permits: Option<Arc<tokio::sync::Semaphore>>,
    ) -> Result<Self, String> {
        if group.servers.is_empty() && group.nrf_discovery.is_none() && !group.allow_empty {
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
            None => Static::new(backends),
        };
        let backends = Backends::new(discovery);
        let selector = build_runtime_selector(group.policy, backends, group.health_check.as_ref())?;

        let nrf_discovery = match (&group.nrf_discovery, nrf_source, &group.health_check) {
            (Some(config), Some(source), Some(health_check)) => Some(RuntimeNrfDiscovery {
                refresh_lock: tokio::sync::Mutex::new(()),
                permits,
                group_name: group.name.clone(),
                client: {
                    let mut client = NrfClient::new(config)?;
                    client.query = query;
                    client
                },
                source,
                health_check: health_check.clone(),
                stale_if_error: config.stale_if_error,
                policy: group.policy,
                selection: ArcSwapOption::empty(),
                schedule: Mutex::new(NrfRefreshSchedule {
                    invalid_api: false,
                    candidate_count: 0,
                    candidates: Vec::new(),
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
            scp_refreshing: std::sync::atomic::AtomicBool::new(false),
            scp_refreshed: tokio::sync::Notify::new(),
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
        if let Some(discovery) = self.nrf_discovery.as_ref() {
            let selection = discovery.selection.load_full()?;
            return selection.select(key, |backend| self.selector.backends().ready(backend));
        }

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
        let _refresh_guard = discovery.refresh_lock.lock().await;
        let now = now.max(Instant::now());
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

        let _permit = match &discovery.permits {
            Some(permits) => Some(permits.acquire().await.ok()?),
            None => None,
        };

        discovery.schedule.lock().unwrap().next_run_at =
            now.checked_add(Duration::from_secs(1)).unwrap_or(now);
        match discovery.discover(now, &self.selector).await {
            Ok(result) => {
                let candidate_count = result.endpoints.len();
                if discovery.client.query.is_some() && candidate_count > 256 {
                    log::warn!("SCP NRF result exceeds 256 endpoints");
                    return Some(discovery.record_failure(now, &self.selector).await);
                }
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
                let selection = match NrfServiceTopology::build(&ready, discovery.policy) {
                    Ok(selection) => selection,
                    Err(err) => {
                        log::warn!(
                            "NRF discovery for upstream `{}` produced an invalid service topology: {err}",
                            discovery.group_name
                        );
                        return Some(discovery.record_failure(now, &self.selector).await);
                    }
                };
                discovery.source.set(ready);
                if let Err(err) = self.selector.update().await {
                    log::warn!(
                        "NRF discovery for upstream `{}` failed to publish backends: {err}",
                        discovery.group_name
                    );
                    return Some(discovery.record_failure(now, &self.selector).await);
                }
                discovery.publish_selection(selection);
                if discovery.client.query.is_some() {
                    crate::metrics::record_scp_event(&discovery.group_name, "discovery_success");
                } else {
                    crate::metrics::record_nrf_discovery_request(&discovery.group_name, "success");
                }

                let delay = nrf_refresh_delay(result.validity, &discovery.group_name);
                let next_run_at = now.checked_add(delay).unwrap_or(expires_at).min(expires_at);
                let mut schedule = discovery.schedule.lock().unwrap();
                schedule.invalid_api = result.invalid_api;
                schedule.candidate_count = candidate_count;
                if discovery.client.query.is_some() {
                    schedule.candidates = result.endpoints;
                }
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

    pub(in crate::upstreams) fn hash_key(&self) -> Option<&UpstreamHashKey> {
        self.hash_key.as_ref()
    }

    pub(in crate::upstreams) fn scp_candidates(&self) -> Vec<CompiledUpstreamServer> {
        self.nrf_discovery
            .as_ref()
            .map(|d| d.schedule.lock().unwrap().candidates.clone())
            .unwrap_or_default()
    }

    pub(in crate::upstreams) async fn refresh_scp(self: &Arc<Self>) {
        let notified = self.scp_refreshed.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        self.start_scp_refresh();
        notified.await;
    }

    pub(in crate::upstreams) fn start_scp_refresh(self: &Arc<Self>) {
        if self
            .scp_refreshing
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            let group = self.clone();
            tokio::spawn(async move {
                group.run_due_health_check(Instant::now()).await;
                group.run_due_nrf_discovery(Instant::now()).await;
                group.scp_refreshing.store(false, Ordering::Release);
                group.scp_refreshed.notify_waiters();
            });
        }
    }

    pub(in crate::upstreams) fn scp_status(&self) -> Result<(), crate::upstreams::scp::ScpError> {
        let Some(discovery) = &self.nrf_discovery else {
            return Ok(());
        };
        let schedule = discovery.schedule.lock().unwrap();
        if schedule.last_success_at.is_none()
            || schedule.expires_at.is_none_or(|at| at <= Instant::now())
        {
            return Err(crate::upstreams::scp::ScpError::nrf_unreachable());
        }
        if schedule.invalid_api {
            return Err(crate::upstreams::scp::ScpError::new(
                400,
                "INVALID_API",
                "No NF supports the requested API major version",
            ));
        }
        if schedule.candidate_count == 0 {
            return Err(crate::upstreams::scp::ScpError::new(
                400,
                "NF_DISCOVERY_FAILURE",
                "No NF matches the discovery factors",
            ));
        }
        Ok(())
    }

    pub(in crate::upstreams) fn scp_select(
        &self,
        key: &[u8],
        accept: impl Fn(&CompiledUpstreamServer) -> bool,
    ) -> Option<CompiledUpstreamServer> {
        self.scp_status().ok()?;
        let selection = self.nrf_discovery.as_ref()?.selection.load_full()?;
        selection.select(key, |backend| {
            self.selector.backends().ready(backend)
                && backend
                    .ext
                    .get::<CompiledUpstreamServer>()
                    .is_some_and(&accept)
        })
    }

    pub(super) fn uses_consistent_hash(&self) -> bool {
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

#[cfg(test)]
mod tests;
