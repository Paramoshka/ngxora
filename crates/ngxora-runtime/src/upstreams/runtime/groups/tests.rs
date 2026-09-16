use super::discovery::nrf_failure_retry_at;
use super::topology::normalized_capacities;
use super::*;
use crate::upstreams::types::NrfServiceMetadata;

use crate::upstreams::types::CompiledUpstreamServer;
use ngxora_compile::ir::UpstreamSelectionPolicy;
use std::collections::{BTreeSet, HashMap};
use std::time::Duration;
use tokio::time::Instant;

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

fn nrf_server(
    nf_instance_id: &str,
    service_instance_id: &str,
    priority: u16,
    capacity: u16,
    host: &str,
    port: u16,
) -> CompiledUpstreamServer {
    CompiledUpstreamServer {
        host: host.into(),
        port,
        weight: 1,
        api_prefix: None,
        nrf_service: Some(NrfServiceMetadata {
            authority: None,
            nf_instance_id: nf_instance_id.into(),
            service_instance_id: service_instance_id.into(),
            priority,
            capacity,
        }),
    }
}

fn nrf_topology(
    policy: UpstreamSelectionPolicy,
    servers: Vec<CompiledUpstreamServer>,
) -> NrfServiceTopology {
    let backends = dynamic_synthetic_backends(&servers).unwrap();
    NrfServiceTopology::build(&backends, policy)
        .unwrap()
        .unwrap()
}

#[test]
fn nrf_refresh_keeps_selection_and_readiness_consistent() {
    use crate::upstreams::{CompiledHealthCheck, CompiledNrfDiscovery, HealthCheckType};
    use ngxora_compile::ir::{NrfEndpointScheme, UpstreamSslOptions};

    let group = RuntimeUpstreamGroup::from_compiled(&CompiledUpstreamGroup {
        name: "refresh".into(),
        allow_empty: false,
        policy: UpstreamSelectionPolicy::RoundRobin,
        hash_key: None,
        servers: Vec::new(),
        nrf_discovery: Some(CompiledNrfDiscovery {
            api_root: "http://127.0.0.1:1/nnrf-disc/v1".parse().unwrap(),
            target_nf_type: "SMF".into(),
            requester_nf_type: "SCP".into(),
            service_name: "nsmf-pdusession".into(),
            endpoint_scheme: NrfEndpointScheme::Http,
            timeout: Duration::from_secs(1),
            stale_if_error: Duration::from_secs(60),
            tls_options: UpstreamSslOptions::default(),
        }),
        health_check: Some(CompiledHealthCheck {
            check_type: HealthCheckType::Tcp,
            timeout: Duration::from_secs(1),
            interval: Duration::from_secs(5),
            consecutive_success: 1,
            consecutive_failure: 1,
        }),
    })
    .unwrap();
    let discovery = group.nrf_discovery.as_ref().unwrap();
    let endpoints = [
        nrf_server("nf", "service", 1, 1, "192.0.2.1", 80),
        nrf_server("nf", "service", 1, 1, "192.0.2.2", 80),
    ];
    let publish = |server: &CompiledUpstreamServer| {
        let backends = dynamic_synthetic_backends(std::slice::from_ref(server)).unwrap();
        let topology = NrfServiceTopology::build(&backends, discovery.policy).unwrap();
        discovery
            .publish_backends(&group.selector, backends, topology)
            .unwrap();
    };
    publish(&endpoints[0]);
    {
        let mut schedule = discovery.schedule.lock().unwrap();
        schedule.last_success_at = Some(Instant::now());
        schedule.expires_at = Some(Instant::now() + Duration::from_secs(60));
        schedule.candidate_count = 1;
    }

    let start = std::sync::Barrier::new(5);
    let running = std::sync::atomic::AtomicBool::new(true);
    std::thread::scope(|threads| {
        let readers: Vec<_> = (0..4)
            .map(|_| {
                threads.spawn(|| {
                    start.wait();
                    let mut failures = 0;
                    let mut requests = 0;
                    while running.load(Ordering::Relaxed) {
                        failures += usize::from(group.select(b"").is_none());
                        failures += usize::from(group.scp_select(b"", |_| true).is_none());
                        requests += 2;
                    }
                    (requests, failures)
                })
            })
            .collect();
        start.wait();
        for index in 0..2_000 {
            publish(&endpoints[index % 2]);
        }
        running.store(false, Ordering::Relaxed);
        for reader in readers {
            let (requests, failures) = reader.join().unwrap();
            assert!(requests > 0);
            assert_eq!(
                failures, 0,
                "healthy endpoints must stay selectable during refresh"
            );
        }
    });

    let backends = group.selector.backends().get_backend();
    group
        .selector
        .backends()
        .set_enable(backends.first().unwrap(), false);
    publish(&endpoints[1]);
    assert!(group.select(b"").is_none());
    assert!(group.scp_select(b"", |_| true).is_none());

    discovery
        .publish_backends(&group.selector, BTreeSet::new(), None)
        .unwrap();
    assert!(group.select(b"").is_none());
    assert!(group.scp_select(b"", |_| true).is_none());
    assert!(group.readiness().is_empty());
}

#[test]
fn nrf_service_capacity_weights_services_not_endpoints() {
    let topology = nrf_topology(
        UpstreamSelectionPolicy::RoundRobin,
        vec![
            nrf_server("nf-a", "service-a", 10, 1, "192.0.2.1", 80),
            nrf_server("nf-a", "service-a", 10, 1, "192.0.2.2", 80),
            nrf_server("nf-b", "service-b", 10, 1, "192.0.2.3", 80),
        ],
    );
    let mut service_a = 0;
    let mut service_b = 0;
    let mut endpoint_a = HashMap::new();

    for _ in 0..40 {
        let selected = topology.select(b"", |_| true).unwrap();
        let service = selected.nrf_service.as_ref().unwrap();
        match service.service_instance_id.as_str() {
            "service-a" => {
                service_a += 1;
                *endpoint_a.entry(selected.host).or_insert(0) += 1;
            }
            "service-b" => service_b += 1,
            other => panic!("unexpected service {other}"),
        }
    }

    assert_eq!((service_a, service_b), (20, 20));
    assert_eq!(
        endpoint_a.values().copied().collect::<BTreeSet<_>>(),
        BTreeSet::from([10])
    );
}

#[test]
fn nrf_service_capacity_controls_weight_within_priority_tier() {
    let topology = nrf_topology(
        UpstreamSelectionPolicy::RoundRobin,
        vec![
            nrf_server("nf-a", "service-a", 10, 3, "192.0.2.1", 80),
            nrf_server("nf-b", "service-b", 10, 1, "192.0.2.2", 80),
        ],
    );
    let mut counts = HashMap::new();

    for _ in 0..40 {
        let selected = topology.select(b"", |_| true).unwrap();
        let id = selected.nrf_service.unwrap().service_instance_id;
        *counts.entry(id).or_insert(0) += 1;
    }

    assert_eq!(counts.get("service-a"), Some(&30));
    assert_eq!(counts.get("service-b"), Some(&10));
}

#[test]
fn nrf_service_selection_falls_back_by_health_then_priority() {
    let topology = nrf_topology(
        UpstreamSelectionPolicy::RoundRobin,
        vec![
            nrf_server("nf-a", "preferred", 1, 1, "192.0.2.1", 80),
            nrf_server("nf-b", "standby", 20, 1, "192.0.2.2", 80),
        ],
    );

    let preferred = topology.select(b"", |_| true).unwrap();
    assert_eq!(
        preferred.nrf_service.unwrap().service_instance_id,
        "preferred"
    );

    let standby = topology
        .select(b"", |backend| {
            backend
                .ext
                .get::<CompiledUpstreamServer>()
                .is_some_and(|server| server.host != "192.0.2.1")
        })
        .unwrap();
    assert_eq!(standby.nrf_service.unwrap().service_instance_id, "standby");
}

#[test]
fn nrf_zero_capacity_is_used_only_without_positive_capacity() {
    let topology = nrf_topology(
        UpstreamSelectionPolicy::RoundRobin,
        vec![
            nrf_server("nf-a", "positive", 1, 1, "192.0.2.1", 80),
            nrf_server("nf-b", "zero", 1, 0, "192.0.2.2", 80),
        ],
    );

    for _ in 0..10 {
        let selected = topology.select(b"", |_| true).unwrap();
        assert_eq!(
            selected.nrf_service.unwrap().service_instance_id,
            "positive"
        );
    }

    let selected = topology
        .select(b"", |backend| {
            backend
                .ext
                .get::<CompiledUpstreamServer>()
                .is_some_and(|server| server.host != "192.0.2.1")
        })
        .unwrap();
    assert_eq!(selected.nrf_service.unwrap().service_instance_id, "zero");
}

#[test]
fn nrf_consistent_hash_stays_on_one_service() {
    let topology = nrf_topology(
        UpstreamSelectionPolicy::ConsistentHash,
        vec![
            nrf_server("nf-a", "service-a", 1, 1, "192.0.2.1", 80),
            nrf_server("nf-b", "service-b", 1, 1, "192.0.2.2", 80),
        ],
    );
    let selected_service = topology
        .select(b"subscriber-1", |_| true)
        .unwrap()
        .nrf_service
        .unwrap()
        .service_instance_id;

    for _ in 0..20 {
        let selected = topology.select(b"subscriber-1", |_| true).unwrap();
        assert_eq!(
            selected.nrf_service.unwrap().service_instance_id,
            selected_service
        );
    }
}

#[test]
fn nrf_capacity_normalization_is_bounded_and_positive() {
    let weights = normalized_capacities(&[u16::MAX, u16::MAX - 1, 1]).unwrap();

    assert_eq!(
        weights.iter().map(|weight| u64::from(*weight)).sum::<u64>(),
        u64::from(u16::MAX)
    );
    assert!(weights.iter().all(|weight| *weight > 0));
    assert!(normalized_capacities(&[0]).is_err());
}
