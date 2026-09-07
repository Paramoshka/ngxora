//! NRF/SCP conversion and cache compatibility.

use crate::grpc::{
    proto, proto_snapshot_from_runtime, runtime_snapshot_from_proto, upstreams_from_proto,
};
use crate::upstreams::CompiledRouter;
use std::sync::Arc;
use std::time::Duration;

#[test]
fn scp_profiles_round_trip_and_reload_keeps_only_compatible_caches() {
    let ast = ngxora_config::Ast::parse_config(
        r#"http { h2c on;
        scp core { api_root http://scp.test/scp; allow_target_api_root https://nf.test/edge; }
        server { listen 127.0.0.1:8080; location /scp/ { scp_pass core; } }
    }"#,
    )
    .unwrap();
    let ir = ngxora_compile::ir::Ir::from_ast(&ast).unwrap();
    ir.validate().unwrap();
    let router = CompiledRouter::from_http(&ir.http.unwrap()).unwrap();
    let state = crate::control::RuntimeState::bootstrap(router.clone());
    let first = state.snapshot();
    let wire = proto_snapshot_from_runtime(&first).unwrap();
    assert_eq!(wire.scp_profiles.len(), 1);
    assert_eq!(wire.scp_profiles[0].api_root, "http://scp.test/scp");
    let decoded = runtime_snapshot_from_proto(wire).unwrap();
    assert_eq!(decoded.router.scp_profiles, router.scp_profiles);
    assert!(state.apply_snapshot(decoded).applied);
    assert!(Arc::ptr_eq(
        &first.scp_profiles["core"],
        &state.snapshot().scp_profiles["core"]
    ));
    let mut changed = router;
    changed
        .scp_profiles
        .get_mut("core")
        .unwrap()
        .allowed_target_api_roots = vec!["https://other.test/edge".into()];
    assert!(
        state
            .apply_snapshot(crate::control::ConfigSnapshot::new("changed", changed))
            .applied
    );
    assert!(!Arc::ptr_eq(
        &first.scp_profiles["core"],
        &state.snapshot().scp_profiles["core"]
    ));
}

#[test]
fn proto_nrf_discovery_converts_to_ir() {
    let upstreams = upstreams_from_proto(&[proto::UpstreamGroup {
        allow_empty: false,
        name: "smf_pool".into(),
        backends: Vec::new(),
        policy: proto::UpstreamSelectionPolicy::RoundRobin as i32,
        health_check: Some(proto::UpstreamHealthCheck {
            kind: Some(proto::upstream_health_check::Kind::Tcp(
                proto::UpstreamTcpHealthCheck {},
            )),
            timeout_ms: 1_000,
            interval_ms: 5_000,
            consecutive_success: 1,
            consecutive_failure: 2,
        }),
        hash_key: None,
        nrf_discovery: Some(proto::NrfDiscovery {
            api_root: "https://nrf.internal/nnrf-disc/v1".into(),
            target_nf_type: "SMF".into(),
            requester_nf_type: "SCP".into(),
            service_name: "nsmf-pdusession".into(),
            endpoint_scheme: proto::NrfEndpointScheme::Https as i32,
            timeout_ms: 2_000,
            stale_if_error_ms: 60_000,
            tls_options: Some(proto::UpstreamTlsOptions {
                verify: proto::Switch::On as i32,
                trusted_certificate: None,
                client_certificate: None,
                client_certificate_key: None,
            }),
        }),
    }])
    .expect("NRF proto converts");

    let discovery = upstreams[0]
        .nrf_discovery
        .as_ref()
        .expect("NRF discovery present");
    assert_eq!(discovery.target_nf_type, "SMF");
    assert_eq!(discovery.requester_nf_type, "SCP");
    assert_eq!(discovery.timeout, Duration::from_secs(2));
    assert_eq!(discovery.stale_if_error, Duration::from_secs(60));
    assert!(upstreams[0].servers.is_empty());
}

#[test]
fn proto_nrf_discovery_rejects_unknown_endpoint_scheme() {
    let error = upstreams_from_proto(&[proto::UpstreamGroup {
        allow_empty: false,
        name: "smf_pool".into(),
        nrf_discovery: Some(proto::NrfDiscovery {
            api_root: "https://nrf.internal/nnrf-disc/v1".into(),
            target_nf_type: "SMF".into(),
            requester_nf_type: "SCP".into(),
            service_name: "nsmf-pdusession".into(),
            endpoint_scheme: 99,
            ..Default::default()
        }),
        ..Default::default()
    }])
    .expect_err("unknown endpoint scheme must fail");

    assert!(error.contains("endpoint_scheme is required"));
}
