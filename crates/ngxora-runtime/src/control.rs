use crate::upstreams::{
    CompiledRouter, ListenKey, ListenerProtocolConfig, ListenerTlsSettings, RuntimeTrustedCa,
    RuntimeUpstreamGroup, ServerRoutes, VirtualHostRoutes, build_runtime_trusted_cas,
};
use arc_swap::ArcSwap;
use ngxora_compile::ir::PemSource;
use ngxora_plugin_api::{PluginChain, empty_plugin_chain};
use ngxora_plugin_registry::PluginRegistry;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(test)]
#[path = "control_tests.rs"]
mod tests;

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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ApplyResult {
    pub applied: bool,
    pub restart_required: bool,
    pub message: String,
    pub active_version: String,
    pub active_generation: u64,
}

#[derive(Clone)]
pub struct RuntimeSnapshot {
    pub generation: u64,
    pub version: String,
    pub router: CompiledRouter,
    plugin_chains: HashMap<u64, PluginChain>,
    upstream_groups: HashMap<String, Arc<RuntimeUpstreamGroup>>,
    trusted_cas: HashMap<PemSource, RuntimeTrustedCa>,
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
}

pub struct RuntimeState {
    current: ArcSwap<RuntimeSnapshot>,
    // Transport/bootstrap settings cannot be changed live with Pingora listeners,
    // so we reject snapshots that modify this fingerprint.
    bootstrap_config: RestartConfigFingerprint,
    registry: Arc<PluginRegistry>,
    generation: AtomicU64,
}

impl RuntimeState {
    /// Creates a runtime state with the built-in plugin registry.
    pub fn new(snapshot: ConfigSnapshot) -> Self {
        Self::with_registry(snapshot, Arc::new(PluginRegistry::with_builtin_plugins()))
    }

    /// Creates a runtime state with a caller-provided plugin registry.
    pub fn with_registry(snapshot: ConfigSnapshot, registry: Arc<PluginRegistry>) -> Self {
        let bootstrap_config = restart_fingerprint(&snapshot.router);
        let initial_snapshot =
            Self::build_runtime_snapshot(&registry, snapshot.version, snapshot.router, 1)
                .expect("bootstrap snapshot plugin resolution failed");
        Self {
            current: ArcSwap::from_pointee(initial_snapshot),
            bootstrap_config,
            registry,
            generation: AtomicU64::new(1),
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
        self.generation.load(Ordering::Relaxed)
    }

    /// Applies a new snapshot if only live-reloadable state changed.
    /// Listener topology and bootstrap transport settings still require restart.
    pub fn apply_snapshot(&self, next: ConfigSnapshot) -> ApplyResult {
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
        let runtime_snapshot = match Self::build_runtime_snapshot(
            &self.registry,
            next_version.clone(),
            next_router,
            self.generation() + 1,
        ) {
            Ok(snapshot) => snapshot,
            Err(message) => {
                let current = self.snapshot();
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
        let active_generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        let active_version = runtime_snapshot.version.clone();
        self.current.store(Arc::new(RuntimeSnapshot {
            generation: active_generation,
            ..runtime_snapshot
        }));

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
    ) -> Result<RuntimeSnapshot, String> {
        let plugin_chains = build_plugin_chains(&router, registry)?;
        let upstream_groups = build_runtime_upstream_groups(&router)?;
        let trusted_cas = build_runtime_trusted_cas(&router)?;

        Ok(RuntimeSnapshot {
            generation,
            version,
            router,
            plugin_chains,
            upstream_groups,
            trusted_cas,
        })
    }
}

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

#[derive(Debug, Clone, Eq, PartialEq)]
struct RestartConfigFingerprint {
    listeners: BTreeMap<ListenKey, ListenerRestartConfig>,
    allow_connect_method_proxying: bool,
    h2c: bool,
    keepalive_requests: Option<u32>,
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
        listeners,
        allow_connect_method_proxying: router.http_options.allow_connect_method_proxying,
        h2c: router.http_options.h2c,
        keepalive_requests: router.http_options.keepalive_requests,
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
) -> Result<HashMap<String, Arc<RuntimeUpstreamGroup>>, String> {
    router
        .upstreams
        .iter()
        .map(|(name, group)| {
            RuntimeUpstreamGroup::from_compiled(group)
                .map(|group| (name.clone(), Arc::new(group)))
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
