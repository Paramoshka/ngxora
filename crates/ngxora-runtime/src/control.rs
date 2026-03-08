use crate::upstreams::{
    CompiledRouter, ListenKey, ListenerProtocolConfig, ListenerTlsSettings, ServerRoutes,
    VirtualHostRoutes,
};
use arc_swap::ArcSwap;
use ngxora_plugin_api::{PluginChain, empty_plugin_chain};
use ngxora_plugin_registry::PluginRegistry;
use std::collections::{BTreeMap, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

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
}

impl RuntimeSnapshot {
    pub fn plugin_chain(&self, route_id: u64) -> PluginChain {
        self.plugin_chains
            .get(&route_id)
            .cloned()
            .unwrap_or_else(empty_plugin_chain)
    }
}

pub struct RuntimeState {
    current: ArcSwap<RuntimeSnapshot>,
    bootstrap_config: RestartConfigFingerprint,
    registry: Arc<PluginRegistry>,
    generation: AtomicU64,
}

impl RuntimeState {
    pub fn new(snapshot: ConfigSnapshot) -> Self {
        Self::with_registry(snapshot, Arc::new(PluginRegistry::with_builtin_plugins()))
    }

    pub fn with_registry(snapshot: ConfigSnapshot, registry: Arc<PluginRegistry>) -> Self {
        let bootstrap_config = restart_fingerprint(&snapshot.router);
        let initial_snapshot = Self::build_runtime_snapshot(
            &registry,
            snapshot.version,
            snapshot.router,
            1,
        )
        .expect("bootstrap snapshot plugin resolution failed");
        Self {
            current: ArcSwap::from_pointee(initial_snapshot),
            bootstrap_config,
            registry,
            generation: AtomicU64::new(1),
        }
    }

    pub fn bootstrap(router: CompiledRouter) -> Self {
        Self::new(ConfigSnapshot::new("bootstrap", router))
    }

    pub fn snapshot(&self) -> Arc<RuntimeSnapshot> {
        self.current.load_full()
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Relaxed)
    }

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
        let active_generation = self.generation() + 1;
        let runtime_snapshot = match Self::build_runtime_snapshot(
            &self.registry,
            next_version.clone(),
            next_router,
            active_generation,
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

    fn build_runtime_snapshot(
        registry: &PluginRegistry,
        version: String,
        router: CompiledRouter,
        generation: u64,
    ) -> Result<RuntimeSnapshot, String> {
        let plugin_chains = build_plugin_chains(&router, registry)?;

        Ok(RuntimeSnapshot {
            generation,
            version,
            router,
            plugin_chains,
        })
    }
}

#[derive(Clone)]
pub struct InProcessControlPlane {
    state: Arc<RuntimeState>,
}

impl InProcessControlPlane {
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

fn collect_plugin_chains_from_server(
    routes: &ServerRoutes,
    registry: &PluginRegistry,
    plugin_chains: &mut HashMap<u64, PluginChain>,
) -> Result<(), String> {
    for location in &routes.locations {
        if plugin_chains.contains_key(&location.route_id) {
            continue;
        }

        let chain = registry
            .build_chain(&location.plugins)
            .map_err(|err| format!("failed to build plugin chain for route {}: {err}", location.route_id))?;
        plugin_chains.insert(location.route_id, chain);
    }

    Ok(())
}
