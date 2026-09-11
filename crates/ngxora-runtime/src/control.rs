use crate::upstreams::{
    ClientIdentityKey, CompiledRouter, ListenKey, ListenerProtocolConfig, ListenerTlsSettings,
    RuntimeClientIdentity, RuntimeTrustedCa, RuntimeUpstreamGroup, ServerRoutes, VirtualHostRoutes,
    build_runtime_client_identities, build_runtime_trusted_cas,
};
use arc_swap::ArcSwap;
use async_trait::async_trait;
use ngxora_compile::ir::PemSource;
use ngxora_plugin_api::{PluginChain, empty_plugin_chain};
use ngxora_plugin_registry::PluginRegistry;
use pingora::services::ServiceReadyNotifier;
use pingora::services::background::BackgroundService;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::time::Instant;

#[cfg(test)]
#[path = "control_tests.rs"]
mod tests;

/// ConfigSnapshot is the apply-time unit exchanged between the control-plane
/// adapter layer and the runtime state machine.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConfigSnapshot {
    pub version: String,
    pub router: CompiledRouter,
}

impl ConfigSnapshot {
    pub fn new(version: impl Into<String>, router: CompiledRouter) -> Self {
        Self {
            version: version.into(),
            router,
        }
    }
}

/// ApplyResult reports whether a new snapshot became active and whether the
/// caller crossed the restart boundary instead of a live-reload boundary.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ApplyResult {
    pub applied: bool,
    pub restart_required: bool,
    pub message: String,
    pub active_version: String,
    pub active_generation: u64,
}

/// RuntimeSnapshot is the request-time view of the active config with plugin
/// chains, upstream groups, and trusted CA material prebuilt.
#[derive(Clone)]
pub struct RuntimeSnapshot {
    pub(crate) backend_counters: HashMap<u64, Arc<AtomicU64>>,
    pub(crate) scp_profiles: HashMap<String, Arc<crate::upstreams::scp::RuntimeScp>>,
    pub generation: u64,
    pub version: String,
    pub router: CompiledRouter,
    plugin_chains: HashMap<u64, PluginChain>,
    upstream_groups: HashMap<String, Arc<RuntimeUpstreamGroup>>,
    trusted_cas: HashMap<PemSource, RuntimeTrustedCa>,
    client_identities: HashMap<ClientIdentityKey, RuntimeClientIdentity>,
}

impl RuntimeSnapshot {
    /// Returns the prebuilt plugin chain for a route.
    /// Missing chains are treated as an empty plugin stack.
    pub fn plugin_chain(&self, route_id: u64) -> PluginChain {
        self.plugin_chains
            .get(&route_id)
            .cloned()
            .unwrap_or_else(empty_plugin_chain)
    }

    pub fn upstream_group(&self, name: &str) -> Option<&Arc<RuntimeUpstreamGroup>> {
        self.upstream_groups
            .get(&name.trim_end_matches('.').to_ascii_lowercase())
    }

    pub fn trusted_ca(&self, source: &PemSource) -> Option<RuntimeTrustedCa> {
        self.trusted_cas.get(source).cloned()
    }

    pub fn client_identity(
        &self,
        cert: &PemSource,
        key: &PemSource,
    ) -> Option<RuntimeClientIdentity> {
        self.client_identities
            .get(&ClientIdentityKey {
                cert: cert.clone(),
                key: key.clone(),
            })
            .cloned()
    }

    pub(crate) fn upstream_backend_readiness(&self) -> Vec<(String, String, bool)> {
        let mut readiness = Vec::new();
        for (name, group) in &self.upstream_groups {
            readiness.extend(
                group
                    .readiness()
                    .into_iter()
                    .map(|(backend, ready)| (name.clone(), backend.to_string(), ready)),
            );
        }
        readiness
    }
}

/// RuntimeState owns the current immutable snapshot and enforces the restart
/// boundary for transport-sensitive config.
pub struct RuntimeState {
    current: ArcSwap<RuntimeSnapshot>,
    pub(crate) geoip: Option<Arc<crate::geoip::GeoIp>>,
    apply_lock: Mutex<()>,
    // Transport/bootstrap settings cannot be changed live with Pingora listeners,
    // so we reject snapshots that modify this fingerprint.
    bootstrap_config: RestartConfigFingerprint,
    registry: Arc<PluginRegistry>,
    tls_material_generation: AtomicU64,
}

impl RuntimeState {
    /// Creates a runtime state with the built-in plugin registry.
    pub fn new(snapshot: ConfigSnapshot) -> Self {
        Self::with_registry(snapshot, Arc::new(PluginRegistry::with_builtin_plugins()))
    }

    /// Creates a runtime state with a caller-provided plugin registry.
    pub fn with_registry(snapshot: ConfigSnapshot, registry: Arc<PluginRegistry>) -> Self {
        let bootstrap_config = restart_fingerprint(&snapshot.router);
        let geoip = snapshot
            .router
            .geoip
            .clone()
            .map(crate::geoip::GeoIp::new)
            .map(Arc::new);
        let initial_snapshot =
            Self::build_runtime_snapshot(&registry, snapshot.version, snapshot.router, 1, None)
                .expect("bootstrap snapshot plugin resolution failed");
        Self {
            current: ArcSwap::from_pointee(initial_snapshot),
            geoip,
            apply_lock: Mutex::new(()),
            bootstrap_config,
            registry,
            tls_material_generation: AtomicU64::new(1),
        }
    }

    /// Helper for bootstrap-only setups that do not care about snapshot versioning.
    pub fn bootstrap(router: CompiledRouter) -> Self {
        Self::new(ConfigSnapshot::new("bootstrap", router))
    }

    /// Returns the currently active runtime snapshot.
    pub fn snapshot(&self) -> Arc<RuntimeSnapshot> {
        self.current.load_full()
    }

    /// Returns the current monotonic runtime generation.
    pub fn generation(&self) -> u64 {
        self.current.load().generation
    }

    pub(crate) fn tls_material_generation(&self) -> u64 {
        self.tls_material_generation.load(Ordering::Acquire)
    }

    pub(crate) fn invalidate_tls_material(&self) -> u64 {
        self.tls_material_generation.fetch_add(1, Ordering::AcqRel) + 1
    }

    /// Applies a new snapshot if only live-reloadable state changed.
    /// Listener topology and bootstrap transport settings still require restart.
    pub fn apply_snapshot(&self, next: ConfigSnapshot) -> ApplyResult {
        let _apply = match self.apply_lock.lock() {
            Ok(guard) => guard,
            Err(_) => {
                let current = self.snapshot();
                return ApplyResult {
                    applied: false,
                    restart_required: false,
                    message: "snapshot apply lock is poisoned".into(),
                    active_version: current.version.clone(),
                    active_generation: current.generation,
                };
            }
        };
        if restart_fingerprint(&next.router) != self.bootstrap_config {
            let current = self.snapshot();
            return ApplyResult {
                applied: false,
                restart_required: true,
                message: "listener or bootstrap transport settings changed; restart required"
                    .into(),
                active_version: current.version.clone(),
                active_generation: current.generation,
            };
        }

        let next_version = next.version;
        let next_router = next.router;
        let current = self.snapshot();
        let runtime_snapshot = match Self::build_runtime_snapshot(
            &self.registry,
            next_version.clone(),
            next_router,
            self.generation() + 1,
            Some(&current),
        ) {
            Ok(snapshot) => snapshot,
            Err(message) => {
                return ApplyResult {
                    applied: false,
                    restart_required: false,
                    message,
                    active_version: current.version.clone(),
                    active_generation: current.generation,
                };
            }
        };

        // The generation is only committed after plugin resolution succeeds.
        let active_generation = runtime_snapshot.generation;
        let active_version = runtime_snapshot.version.clone();
        self.current.store(Arc::new(runtime_snapshot));

        ApplyResult {
            applied: true,
            restart_required: false,
            message: "snapshot applied".into(),
            active_version,
            active_generation,
        }
    }

    /// Compiles route plugin specs into executable chains and packages a runtime snapshot.
    fn build_runtime_snapshot(
        registry: &PluginRegistry,
        version: String,
        router: CompiledRouter,
        generation: u64,
        previous: Option<&RuntimeSnapshot>,
    ) -> Result<RuntimeSnapshot, String> {
        if previous.is_some() {
            crate::server::validate_snapshot_tls(&router)?;
        }
        let plugin_chains = build_plugin_chains(&router, registry)?;
        let upstream_groups = build_runtime_upstream_groups(&router, previous)?;
        let trusted_cas = build_runtime_trusted_cas(&router)?;
        let client_identities = build_runtime_client_identities(&router)?;
        let scp_profiles = router
            .scp_profiles
            .iter()
            .map(|(name, profile)| {
                if let Some(runtime) = previous
                    .and_then(|p| p.scp_profiles.get(name))
                    .filter(|runtime| runtime.matches(profile, &router.upstreams))
                {
                    return Ok((name.clone(), runtime.clone()));
                }
                crate::upstreams::scp::RuntimeScp::new(profile, &router.upstreams)
                    .map(|runtime| (name.clone(), Arc::new(runtime)))
            })
            .collect::<Result<HashMap<_, _>, _>>()?;

        let backend_counters = router
            .listeners
            .values()
            .flat_map(|v| v.named.values().chain(v.default.iter()))
            .flat_map(|routes| &routes.locations)
            .filter(|route| {
                matches!(
                    route.target,
                    crate::upstreams::RouteTarget::WeightedBackends(_)
                )
            })
            .map(|route| (route.route_id, Arc::new(AtomicU64::new(0))))
            .collect();
        Ok(RuntimeSnapshot {
            backend_counters,
            scp_profiles,
            generation,
            version,
            router,
            plugin_chains,
            upstream_groups,
            trusted_cas,
            client_identities,
        })
    }
}

/// InProcessControlPlane is a small adapter used by gRPC handlers, tests, and
/// other local control-plane integrations.
#[derive(Clone)]
pub struct InProcessControlPlane {
    state: Arc<RuntimeState>,
}

impl InProcessControlPlane {
    /// Thin in-process wrapper used by tests and future control-plane adapters.
    pub fn new(state: Arc<RuntimeState>) -> Self {
        Self { state }
    }

    pub fn state(&self) -> &Arc<RuntimeState> {
        &self.state
    }

    pub fn get_snapshot(&self) -> Arc<RuntimeSnapshot> {
        self.state.snapshot()
    }

    pub fn apply_snapshot(&self, snapshot: ConfigSnapshot) -> ApplyResult {
        self.state.apply_snapshot(snapshot)
    }
}

/// RuntimeUpstreamHealthChecks periodically runs configured active health
/// checks against compiled upstream groups from the current snapshot.
pub struct RuntimeUpstreamHealthChecks {
    state: Arc<RuntimeState>,
    snapshot_refresh_interval: Duration,
}

/// RuntimeNrfDiscovery periodically refreshes NRF-backed upstream groups.
pub struct RuntimeNrfDiscovery {
    state: Arc<RuntimeState>,
    snapshot_refresh_interval: Duration,
}

impl RuntimeNrfDiscovery {
    pub fn new(state: Arc<RuntimeState>) -> Self {
        Self {
            state,
            snapshot_refresh_interval: Duration::from_secs(1),
        }
    }

    async fn run(
        &self,
        mut shutdown: pingora::server::ShutdownWatch,
        mut ready_opt: Option<ServiceReadyNotifier>,
    ) {
        loop {
            if *shutdown.borrow() {
                return;
            }

            let snapshot = self.state.snapshot();
            let now = Instant::now();
            let mut next_wake = now + self.snapshot_refresh_interval;
            for group in snapshot.upstream_groups.values() {
                if let Some(next_run) = group.run_due_nrf_discovery(now).await {
                    next_wake = next_wake.min(next_run);
                }
            }
            for profile in snapshot.scp_profiles.values() {
                profile.maintain();
            }

            if let Some(ready) = ready_opt.take() {
                ServiceReadyNotifier::notify_ready(ready);
            }

            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
                _ = tokio::time::sleep_until(next_wake) => {}
            }
        }
    }
}

#[async_trait]
impl BackgroundService for RuntimeNrfDiscovery {
    async fn start_with_ready_notifier(
        &self,
        shutdown: pingora::server::ShutdownWatch,
        ready: ServiceReadyNotifier,
    ) {
        self.run(shutdown, Some(ready)).await
    }

    async fn start(&self, shutdown: pingora::server::ShutdownWatch) {
        self.run(shutdown, None).await
    }
}

impl RuntimeUpstreamHealthChecks {
    pub fn new(state: Arc<RuntimeState>) -> Self {
        Self {
            state,
            snapshot_refresh_interval: Duration::from_secs(1),
        }
    }

    async fn run(
        &self,
        mut shutdown: pingora::server::ShutdownWatch,
        mut ready_opt: Option<ServiceReadyNotifier>,
    ) {
        loop {
            if *shutdown.borrow() {
                return;
            }

            let snapshot = self.state.snapshot();
            let now = Instant::now();
            let mut next_wake = now + self.snapshot_refresh_interval;

            for group in snapshot.upstream_groups.values() {
                if let Some(next_run) = group.run_due_health_check(now).await {
                    next_wake = next_wake.min(next_run);
                }
            }

            if let Some(ready) = ready_opt.take() {
                ServiceReadyNotifier::notify_ready(ready);
            }

            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
                _ = tokio::time::sleep_until(next_wake) => {}
            }
        }
    }
}

#[async_trait]
impl BackgroundService for RuntimeUpstreamHealthChecks {
    async fn start_with_ready_notifier(
        &self,
        shutdown: pingora::server::ShutdownWatch,
        ready: ServiceReadyNotifier,
    ) {
        self.run(shutdown, Some(ready)).await
    }

    async fn start(&self, shutdown: pingora::server::ShutdownWatch) {
        self.run(shutdown, None).await
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct RestartConfigFingerprint {
    geoip: Option<ngxora_compile::ir::GeoIpConfig>,
    listeners: BTreeMap<ListenKey, ListenerRestartConfig>,
    allow_connect_method_proxying: bool,
    h2c: bool,
    keepalive_requests: Option<u32>,
    http2: ngxora_compile::ir::Http2Options,
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct ListenerRestartConfig {
    protocol: ListenerProtocolConfig,
    tls: Option<ListenerTlsSettings>,
}

/// Captures the subset of config that cannot be swapped live.
/// Any change here means the process must keep the old snapshot until restart.
fn restart_fingerprint(router: &CompiledRouter) -> RestartConfigFingerprint {
    let mut listeners = BTreeMap::new();
    for key in router.listeners.keys() {
        listeners.insert(
            key.clone(),
            ListenerRestartConfig {
                protocol: router
                    .listener_protocols
                    .get(key)
                    .cloned()
                    .unwrap_or_default(),
                tls: router.listener_tls.get(key).map(|cfg| cfg.settings.clone()),
            },
        );
    }

    RestartConfigFingerprint {
        geoip: router.geoip.clone(),
        listeners,
        allow_connect_method_proxying: router.http_options.allow_connect_method_proxying,
        h2c: router.http_options.h2c,
        keepalive_requests: router.http_options.keepalive_requests,
        http2: router.http_options.http2,
    }
}

/// Resolves all plugin specs eagerly so bad plugin config rejects the whole snapshot.
fn build_plugin_chains(
    router: &CompiledRouter,
    registry: &PluginRegistry,
) -> Result<HashMap<u64, PluginChain>, String> {
    let mut plugin_chains = HashMap::new();

    for routes in router.listeners.values() {
        collect_plugin_chains_from_vhosts(routes, registry, &mut plugin_chains)?;
    }

    Ok(plugin_chains)
}

fn build_runtime_upstream_groups(
    router: &CompiledRouter,
    previous: Option<&RuntimeSnapshot>,
) -> Result<HashMap<String, Arc<RuntimeUpstreamGroup>>, String> {
    router
        .upstreams
        .iter()
        .map(|(name, group)| {
            if let Some(runtime_group) = previous.and_then(|snapshot| {
                (snapshot.router.upstreams.get(name) == Some(group))
                    .then(|| snapshot.upstream_groups.get(name).cloned())
                    .flatten()
            }) {
                return Ok((name.clone(), runtime_group));
            }
            RuntimeUpstreamGroup::from_compiled(group).map(|group| (name.clone(), Arc::new(group)))
        })
        .collect()
}

/// Walks every virtual host attached to a listener and collects route-level plugin chains.
fn collect_plugin_chains_from_vhosts(
    routes: &VirtualHostRoutes,
    registry: &PluginRegistry,
    plugin_chains: &mut HashMap<u64, PluginChain>,
) -> Result<(), String> {
    for server_routes in routes.named.values().chain(routes.default.iter()) {
        collect_plugin_chains_from_server(server_routes, registry, plugin_chains)?;
    }

    Ok(())
}

/// A route ID is globally stable inside the compiled router, so duplicate routes
/// reached via aliases/default host lookup share the same compiled plugin chain.
fn collect_plugin_chains_from_server(
    routes: &ServerRoutes,
    registry: &PluginRegistry,
    plugin_chains: &mut HashMap<u64, PluginChain>,
) -> Result<(), String> {
    for location in &routes.locations {
        if plugin_chains.contains_key(&location.route_id) {
            continue;
        }

        let chain = registry.build_chain(&location.plugins).map_err(|err| {
            format!(
                "failed to build plugin chain for route {}: {err}",
                location.route_id
            )
        })?;
        plugin_chains.insert(location.route_id, chain);
    }

    Ok(())
}
