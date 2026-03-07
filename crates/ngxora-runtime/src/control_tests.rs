use super::{ConfigSnapshot, InProcessControlPlane, RuntimeState};
use crate::upstreams::CompiledRouter;
use ngxora_compile::ir::{Http, Listen, Server};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

fn router_on_listener(port: u16) -> CompiledRouter {
    let http = Http {
        servers: vec![Server {
            listens: vec![Listen {
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port,
                ssl: false,
                default_server: true,
            }],
            ..Server::default()
        }],
        ..Http::default()
    };

    CompiledRouter::from_http(&http)
}

#[test]
fn runtime_state_applies_compatible_snapshot() {
    let state = RuntimeState::new(ConfigSnapshot::new("v1", router_on_listener(8080)));
    let result = state.apply_snapshot(ConfigSnapshot::new("v2", router_on_listener(8080)));
    let snapshot = state.snapshot();

    assert!(result.applied);
    assert!(!result.restart_required);
    assert_eq!(result.active_version, "v2");
    assert_eq!(result.active_generation, 2);
    assert_eq!(snapshot.version, "v2");
}

#[test]
fn runtime_state_rejects_listener_topology_change() {
    let state = RuntimeState::new(ConfigSnapshot::new("v1", router_on_listener(8080)));
    let result = state.apply_snapshot(ConfigSnapshot::new("v2", router_on_listener(8443)));
    let snapshot = state.snapshot();

    assert!(!result.applied);
    assert!(result.restart_required);
    assert_eq!(result.active_version, "v1");
    assert_eq!(result.active_generation, 1);
    assert_eq!(snapshot.version, "v1");
}

#[test]
fn in_process_control_plane_delegates_to_runtime_state() {
    let state = Arc::new(RuntimeState::new(ConfigSnapshot::new(
        "v1",
        router_on_listener(8080),
    )));
    let control = InProcessControlPlane::new(Arc::clone(&state));

    let result = control.apply_snapshot(ConfigSnapshot::new("v2", router_on_listener(8080)));
    let snapshot = control.get_snapshot();

    assert!(result.applied);
    assert_eq!(snapshot.version, "v2");
    assert_eq!(control.state().generation(), 2);
}
