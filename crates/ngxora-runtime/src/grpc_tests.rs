use super::{proto, proto_snapshot_from_runtime, runtime_snapshot_from_proto};
use crate::control::{ConfigSnapshot, RuntimeState};
use crate::upstreams::{CompiledMatcher, CompiledRouter, ListenKey, RouteTarget};
use ngxora_compile::ir::{
    Http, KeepaliveTimeout, Listen, Location, LocationDirective, LocationMatcher, PemSource,
    Server, Switch, TlsIdentity,
};
use ngxora_plugin_api::PluginSpec;
use serde_json::json;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use url::Url;

#[test]
fn proto_snapshot_converts_into_runtime_router() {
    let snapshot = proto::ConfigSnapshot {
        version: "v2".into(),
        http: Some(proto::HttpOptions {
            downstream_keepalive_timeout_seconds: 15,
            tcp_nodelay: true,
            keepalive_requests: 200,
            allow_connect_method_proxying: true,
            h2c: false,
        }),
        listeners: vec![proto::Listener {
            name: "edge".into(),
            address: "0.0.0.0".into(),
            port: 8080,
            tls: false,
            http2: false,
            http2_only: false,
            tls_options: None,
        }],
        virtual_hosts: vec![proto::VirtualHost {
            listener: "edge".into(),
            server_names: vec!["example.com".into()],
            default_server: true,
            tls: None,
            routes: vec![proto::Route {
                r#match: Some(proto::Match {
                    kind: Some(proto::r#match::Kind::Prefix("/api".into())),
                }),
                upstream: Some(proto::Upstream {
                    scheme: "https".into(),
                    host: "backend.internal".into(),
                    port: 8443,
                }),
                timeouts: Some(proto::RouteTimeouts {
                    connect_timeout_ms: 1_000,
                    read_timeout_ms: 2_000,
                    write_timeout_ms: 3_000,
                }),
                plugins: vec![proto::Plugin {
                    name: "headers".into(),
                    json_config: r#"{"response":{"add":[["x-proxy","ngxora"]]}}"#.into(),
                }],
            }],
        }],
    };

    let runtime = runtime_snapshot_from_proto(snapshot).expect("proto snapshot compiles");
    let listen_key = ListenKey {
        addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        port: 8080,
        ssl: false,
    };
    let server = runtime
        .router
        .listeners
        .get(&listen_key)
        .and_then(|routes| routes.default.as_ref())
        .expect("default server exists");
    let route = server.locations.first().expect("route exists");

    assert_eq!(runtime.version, "v2");
    assert_eq!(
        runtime.router.http_options.downstream_keepalive_timeout,
        Some(15)
    );
    assert_eq!(runtime.router.http_options.keepalive_requests, Some(200));
    assert!(runtime.router.http_options.tcp_nodelay);
    assert!(runtime.router.http_options.allow_connect_method_proxying);
    assert_eq!(route.matcher, CompiledMatcher::Prefix("/api".into()));
    assert_eq!(
        route.target,
        RouteTarget::ProxyPass {
            host: "backend.internal".into(),
            port: 8443,
            tls: true,
            sni: "backend.internal".into(),
        }
    );
    assert_eq!(
        route.upstream_timeouts.connect,
        Some(Duration::from_secs(1))
    );
    assert_eq!(route.upstream_timeouts.read, Some(Duration::from_secs(2)));
    assert_eq!(route.upstream_timeouts.write, Some(Duration::from_secs(3)));
    assert_eq!(route.plugins.len(), 1);
    assert_eq!(route.plugins[0].name, "headers");
}

#[test]
fn runtime_snapshot_converts_back_to_proto() {
    let router = router_with_tls_and_plugin();
    let state = RuntimeState::new(ConfigSnapshot::new("v1", router));
    let snapshot = state.snapshot();
    let proto =
        proto_snapshot_from_runtime(snapshot.as_ref()).expect("runtime snapshot serializes");

    assert_eq!(proto.version, "v1");
    assert_eq!(
        proto
            .http
            .as_ref()
            .expect("http options")
            .downstream_keepalive_timeout_seconds,
        30
    );
    assert_eq!(proto.listeners.len(), 1);
    assert_eq!(proto.listeners[0].address, "0.0.0.0");
    assert!(proto.listeners[0].tls);
    assert!(proto.listeners[0].http2);
    assert_eq!(proto.virtual_hosts.len(), 1);

    let vhost = &proto.virtual_hosts[0];
    assert_eq!(vhost.server_names, vec!["example.com".to_string()]);
    assert!(vhost.default_server);
    assert!(vhost.tls.is_some());
    assert_eq!(vhost.routes.len(), 1);
    assert_eq!(vhost.routes[0].plugins.len(), 1);
    assert_eq!(vhost.routes[0].plugins[0].name, "headers");
    assert_eq!(
        vhost.routes[0].upstream.as_ref().expect("upstream").scheme,
        "https"
    );
}

fn router_with_tls_and_plugin() -> CompiledRouter {
    let http = Http {
        servers: vec![Server {
            server_names: vec!["example.com".into()],
            locations: vec![Location {
                matcher: LocationMatcher::Prefix("/".into()),
                directives: vec![
                    LocationDirective::ProxyConnectTimeout(Duration::from_secs(1)),
                    LocationDirective::ProxyReadTimeout(Duration::from_secs(2)),
                    LocationDirective::ProxyWriteTimeout(Duration::from_secs(3)),
                    LocationDirective::ProxyPass(
                        Url::parse("https://backend.internal:8443").expect("valid url"),
                    ),
                ],
                plugins: vec![PluginSpec {
                    name: "headers".into(),
                    config: json!({"response":{"add":[["x-proxy","ngxora"]]}}),
                }],
            }],
            listens: vec![Listen {
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port: 443,
                ssl: true,
                default_server: true,
                http2: true,
                http2_only: false,
            }],
            tls: Some(TlsIdentity {
                cert: PemSource::Path("/etc/ngxora/tls/example.crt".into()),
                key: PemSource::Path("/etc/ngxora/tls/example.key".into()),
            }),
            ..Server::default()
        }],
        keepalive_timeout: KeepaliveTimeout::Timeout {
            idle: Duration::from_secs(30),
            header: None,
        },
        keepalive_requests: Some(1000),
        tcp_nodelay: Switch::On,
        allow_connect_method_proxying: Switch::Off,
        h2c: Switch::Off,
    };

    CompiledRouter::from_http(&http).expect("router compiles")
}
