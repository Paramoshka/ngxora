use super::{ConfigSnapshot, InProcessControlPlane, RuntimeState};
use crate::upstreams::{
    CompiledLocation, CompiledMatcher, CompiledRouter, ListenKey, RouteTarget, ServerRoutes,
    VirtualHostRoutes,
};
use ngxora_compile::ir::{Http, Listen, Server};
use ngxora_plugin_api::PluginSpec;
use std::collections::HashMap;
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

fn router_with_route_plugin(port: u16, plugin_name: &str) -> CompiledRouter {
    let listen_key = ListenKey {
        addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        port,
        ssl: false,
    };
    let location = CompiledLocation {
        route_id: 1,
        matcher: CompiledMatcher::Prefix("/".into()),
        target: RouteTarget::ProxyPass {
            host: "example.com".into(),
            port: 80,
            tls: false,
            sni: String::new(),
        },
        plugins: vec![PluginSpec {
            name: plugin_name.into(),
            config: Default::default(),
        }],
    };

    CompiledRouter {
        listeners: HashMap::from([(
            listen_key,
            VirtualHostRoutes {
                named: HashMap::new(),
                default: Some(ServerRoutes {
                    locations: vec![location],
                }),
            },
        )]),
        ..CompiledRouter::default()
    }
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

#[test]
fn runtime_state_rejects_unknown_plugin() {
    let state = RuntimeState::new(ConfigSnapshot::new("v1", router_on_listener(8080)));
    let result = state.apply_snapshot(ConfigSnapshot::new(
        "v2",
        router_with_route_plugin(8080, "missing-plugin"),
    ));
    let snapshot = state.snapshot();

    assert!(!result.applied);
    assert!(!result.restart_required);
    assert!(result.message.contains("plugin is not compiled into this binary"));
    assert_eq!(snapshot.version, "v1");
}
