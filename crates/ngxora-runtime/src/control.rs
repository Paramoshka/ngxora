use crate::upstreams::{CompiledRouter, ListenKey};
use arc_swap::ArcSwap;
use std::collections::BTreeSet;
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RuntimeSnapshot {
    pub generation: u64,
    pub version: String,
    pub router: CompiledRouter,
}

#[derive(Debug)]
pub struct RuntimeState {
    current: ArcSwap<RuntimeSnapshot>,
    bootstrap_topology: BTreeSet<ListenKey>,
    generation: AtomicU64,
}

impl RuntimeState {
    pub fn new(snapshot: ConfigSnapshot) -> Self {
        let bootstrap_topology = listener_topology(&snapshot.router);
        Self {
            current: ArcSwap::from_pointee(RuntimeSnapshot {
                generation: 1,
                version: snapshot.version,
                router: snapshot.router,
            }),
            bootstrap_topology,
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
        if listener_topology(&next.router) != self.bootstrap_topology {
            let current = self.snapshot();
            return ApplyResult {
                applied: false,
                restart_required: true,
                message: "listener topology changed; restart required".into(),
                active_version: current.version.clone(),
                active_generation: current.generation,
            };
        }

        let active_generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        let active_version = next.version.clone();
        self.current.store(Arc::new(RuntimeSnapshot {
            generation: active_generation,
            version: next.version,
            router: next.router,
        }));

        ApplyResult {
            applied: true,
            restart_required: false,
            message: "snapshot applied".into(),
            active_version,
            active_generation,
        }
    }

    pub fn force_apply(&self, next: ConfigSnapshot) {
        let generation = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.current.store(Arc::new(RuntimeSnapshot {
            generation,
            version: next.version,
            router: next.router,
        }));
    }
}

#[derive(Debug, Clone)]
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

fn listener_topology(router: &CompiledRouter) -> BTreeSet<ListenKey> {
    router.listeners.keys().cloned().collect()
}
