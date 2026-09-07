//! NRF service priority tiers and capacity-weighted selection within each tier.

use super::{RuntimeUpstreamSelector, build_runtime_selector, synthetic_backend_addr};
use crate::upstreams::types::{CompiledUpstreamServer, NrfServiceMetadata};
use ngxora_compile::ir::UpstreamSelectionPolicy;
use pingora::lb::{Backend, Backends, discovery};
use pingora::protocols::l4::socket::SocketAddr as PingoraSocketAddr;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct NrfTopologySignature(Vec<(NrfServiceMetadata, Vec<NrfEndpointIdentity>)>);

#[derive(Debug, Clone, Eq, PartialEq, PartialOrd, Ord)]
struct NrfEndpointIdentity {
    host: String,
    port: u16,
    api_prefix: Option<String>,
}

pub(super) struct NrfServiceTopology {
    pub(super) signature: NrfTopologySignature,
    tiers: Vec<NrfServiceTier>,
}

struct NrfServiceTier {
    positive_capacity: Option<NrfServicePool>,
    zero_capacity: Option<NrfServicePool>,
}

struct NrfServicePool {
    selector: RuntimeUpstreamSelector,
    services: HashMap<NrfServiceMetadata, RuntimeNrfService>,
}

struct RuntimeNrfService {
    endpoints: Vec<Backend>,
    next_endpoint: AtomicUsize,
}

fn stable_nrf_service_id(service: &NrfServiceMetadata) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    service.hash(&mut hasher);
    hasher.finish()
}

pub(super) fn normalized_capacities(capacities: &[u16]) -> Result<Vec<u16>, String> {
    if capacities.is_empty() {
        return Ok(Vec::new());
    }
    if capacities.contains(&0) {
        return Err("positive-capacity NRF pool contains a zero capacity".into());
    }

    let limit = u64::from(u16::MAX);
    let service_count = u64::try_from(capacities.len()).unwrap_or(u64::MAX);
    if service_count > limit {
        return Err(format!(
            "NRF priority tier contains more than {limit} services"
        ));
    }

    let total = capacities
        .iter()
        .map(|capacity| u64::from(*capacity))
        .sum::<u64>();
    if total <= limit {
        return Ok(capacities.to_vec());
    }

    let remaining = limit - service_count;
    let mut weights = Vec::with_capacity(capacities.len());
    let mut remainders = Vec::with_capacity(capacities.len());
    let mut assigned = 0u64;
    for (index, capacity) in capacities.iter().enumerate() {
        let scaled = u64::from(*capacity) * remaining;
        let weight = 1 + scaled / total;
        weights.push(u16::try_from(weight).unwrap_or(u16::MAX));
        remainders.push((scaled % total, index));
        assigned += weight;
    }

    remainders.sort_unstable_by(|left, right| right.cmp(left));
    for (_, index) in remainders.into_iter().take((limit - assigned) as usize) {
        weights[index] = weights[index].saturating_add(1);
    }
    Ok(weights)
}

impl NrfServiceTopology {
    pub(super) fn build(
        backends: &BTreeSet<Backend>,
        policy: UpstreamSelectionPolicy,
    ) -> Result<Option<Self>, String> {
        let mut services = BTreeMap::<NrfServiceMetadata, Vec<Backend>>::new();
        for backend in backends {
            let server = backend
                .ext
                .get::<CompiledUpstreamServer>()
                .ok_or_else(|| "NRF backend is missing compiled endpoint metadata".to_string())?;
            let service = server
                .nrf_service
                .as_ref()
                .ok_or_else(|| "NRF backend is missing service metadata".to_string())?;
            services
                .entry(service.clone())
                .or_default()
                .push(backend.clone());
        }
        if services.is_empty() {
            return Ok(None);
        }

        let signature = NrfTopologySignature(
            services
                .iter()
                .map(|(service, endpoints)| {
                    let endpoints = endpoints
                        .iter()
                        .filter_map(|backend| backend.ext.get::<CompiledUpstreamServer>())
                        .map(|server| NrfEndpointIdentity {
                            host: server.host.clone(),
                            port: server.port,
                            api_prefix: server.api_prefix.clone(),
                        })
                        .collect();
                    (service.clone(), endpoints)
                })
                .collect(),
        );

        let mut by_priority = BTreeMap::<u16, Vec<(NrfServiceMetadata, Vec<Backend>)>>::new();
        for (service, endpoints) in services {
            by_priority
                .entry(service.priority)
                .or_default()
                .push((service, endpoints));
        }
        let tiers = by_priority
            .into_values()
            .map(|services| NrfServiceTier::build(services, policy))
            .collect::<Result<Vec<_>, _>>()?;

        Ok(Some(Self { signature, tiers }))
    }

    pub(super) fn select<F>(&self, key: &[u8], ready: F) -> Option<CompiledUpstreamServer>
    where
        F: Fn(&Backend) -> bool,
    {
        for tier in &self.tiers {
            if let Some(server) = tier.select(key, &ready) {
                return Some(server);
            }
        }
        None
    }
}

impl NrfServiceTier {
    fn build(
        services: Vec<(NrfServiceMetadata, Vec<Backend>)>,
        policy: UpstreamSelectionPolicy,
    ) -> Result<Self, String> {
        let (positive, zero): (Vec<_>, Vec<_>) = services
            .into_iter()
            .partition(|(service, _)| service.capacity > 0);
        Ok(Self {
            positive_capacity: NrfServicePool::build(positive, policy)?,
            zero_capacity: NrfServicePool::build(zero, policy)?,
        })
    }

    fn select<F>(&self, key: &[u8], ready: &F) -> Option<CompiledUpstreamServer>
    where
        F: Fn(&Backend) -> bool,
    {
        self.positive_capacity
            .as_ref()
            .and_then(|pool| pool.select(key, ready))
            .or_else(|| {
                self.zero_capacity
                    .as_ref()
                    .and_then(|pool| pool.select(key, ready))
            })
    }
}

impl NrfServicePool {
    fn build(
        services: Vec<(NrfServiceMetadata, Vec<Backend>)>,
        policy: UpstreamSelectionPolicy,
    ) -> Result<Option<Self>, String> {
        if services.is_empty() {
            return Ok(None);
        }

        let capacities = services
            .iter()
            .map(|(service, _)| service.capacity.max(1))
            .collect::<Vec<_>>();
        let weights = normalized_capacities(&capacities)?;
        let mut used = BTreeSet::new();
        let mut representative_backends = BTreeSet::new();
        let mut runtime_services = HashMap::with_capacity(services.len());
        for ((service, endpoints), weight) in services.into_iter().zip(weights) {
            let mut id = stable_nrf_service_id(&service);
            while !used.insert(id) {
                id = id.wrapping_add(1);
            }
            let mut ext = http::Extensions::new();
            ext.insert(service.clone());
            representative_backends.insert(Backend {
                addr: PingoraSocketAddr::Inet(synthetic_backend_addr(id)),
                weight: usize::from(weight),
                ext,
            });
            runtime_services.insert(
                service,
                RuntimeNrfService {
                    endpoints,
                    next_endpoint: AtomicUsize::new(0),
                },
            );
        }

        let backends = Backends::new(discovery::Static::new(representative_backends));
        Ok(Some(Self {
            selector: build_runtime_selector(policy, backends, None)?,
            services: runtime_services,
        }))
    }

    fn select<F>(&self, key: &[u8], ready: &F) -> Option<CompiledUpstreamServer>
    where
        F: Fn(&Backend) -> bool,
    {
        let max_iterations = self.services.len().max(256);
        let backend = self
            .selector
            .select_with(key, max_iterations, |backend, _| {
                backend
                    .ext
                    .get::<NrfServiceMetadata>()
                    .and_then(|service| self.services.get(service))
                    .is_some_and(|service| service.endpoints.iter().any(ready))
            })?;
        let metadata = backend.ext.get::<NrfServiceMetadata>()?;
        self.services.get(metadata)?.select_endpoint(ready)
    }
}

impl RuntimeNrfService {
    fn select_endpoint<F>(&self, ready: &F) -> Option<CompiledUpstreamServer>
    where
        F: Fn(&Backend) -> bool,
    {
        let len = self.endpoints.len();
        let start = self.next_endpoint.fetch_add(1, Ordering::Relaxed);
        for offset in 0..len {
            let backend = &self.endpoints[(start + offset) % len];
            if ready(backend) {
                return backend.ext.get::<CompiledUpstreamServer>().cloned();
            }
        }
        None
    }
}
