//! Snapshot import/export and route semantics.

use super::{TEST_CA_PEM, TRUSTED_UPSTREAM_CA_PATH, router_with_tls_and_plugin};
use crate::control::{ConfigSnapshot, RuntimeState};
use crate::grpc::{proto, proto_snapshot_from_runtime, runtime_snapshot_from_proto};
use crate::upstreams::{CompiledMatcher, CompiledRouter, ListenKey, RouteTarget};
use ngxora_compile::ir::{
    Http, Listen, Location, LocationDirective, LocationMatcher, PemSource, Server, Switch,
    UpstreamHashKey, UpstreamHttpProtocol, UpstreamSelectionPolicy,
};
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

#[test]
fn proto_snapshot_converts_into_runtime_router() {
    let snapshot = proto::ConfigSnapshot {
        version: "v2".into(),
        scp_profiles: Vec::new(),
        http: Some(proto::HttpOptions {
            downstream_keepalive_timeout_seconds: 15,
            tcp_nodelay: true,
            keepalive_requests: 200,
            allow_connect_method_proxying: true,
            h2c: false,
            client_max_body_size_bytes: 8 * 1024 * 1024,
            proxy_cache_max_size_bytes: 0,
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
        upstreams: vec![proto::UpstreamGroup {
            allow_empty: false,
            nrf_discovery: None,
            name: "backend-pool".into(),
            backends: vec![
                proto::UpstreamBackend {
                    host: "backend-1.internal".into(),
                    port: 8080,
                    weight: 4,
                },
                proto::UpstreamBackend {
                    host: "backend-2.internal".into(),
                    port: 8081,
                    weight: 0,
                },
            ],
            policy: proto::UpstreamSelectionPolicy::ConsistentHash as i32,
            health_check: Some(proto::UpstreamHealthCheck {
                kind: Some(proto::upstream_health_check::Kind::Http(
                    proto::UpstreamHttpHealthCheck {
                        host: "backend.internal".into(),
                        path: "/readyz".into(),
                        use_tls: true,
                    },
                )),
                timeout_ms: 2_000,
                interval_ms: 10_000,
                consecutive_success: 2,
                consecutive_failure: 3,
            }),
            hash_key: Some(proto::UpstreamHashKey {
                source: Some(proto::upstream_hash_key::Source::Header(
                    "X-Tenant-ID".into(),
                )),
            }),
        }],
        virtual_hosts: vec![proto::VirtualHost {
            listener: "edge".into(),
            server_names: vec!["example.com".into()],
            default_server: true,
            tls: None,
            routes: vec![proto::Route {
                url_rewrite: None,
                r#match: Some(proto::Match {
                    kind: Some(proto::r#match::Kind::Prefix("/api".into())),
                }),
                action: Some(proto::route::Action::Upstream(proto::Upstream {
                    scheme: "http".into(),
                    host: String::new(),
                    port: 0,
                    upstream_group: "backend-pool".into(),
                })),
                timeouts: Some(proto::RouteTimeouts {
                    connect_timeout_ms: 1_000,
                    read_timeout_ms: 2_000,
                    write_timeout_ms: 3_000,
                }),
                cache: Some(proto::RouteCache {
                    enabled: proto::Switch::On as i32,
                    max_size_bytes: 256 * 1024,
                    ttl_ms: 5 * 60 * 1_000,
                    stale_if_error_ms: 30 * 1_000,
                    key_mode: proto::CacheKeyMode::NormalizedUri as i32,
                    min_uses: 2,
                    valid_statuses: vec![200, 301, 302],
                }),
                tls_options: Some(proto::UpstreamTlsOptions {
                    verify: proto::Switch::Off as i32,
                    trusted_certificate: Some(proto::PemSource {
                        source: Some(proto::pem_source::Source::Path(
                            TRUSTED_UPSTREAM_CA_PATH.into(),
                        )),
                    }),
                    client_certificate: None,
                    client_certificate_key: None,
                }),
                upstream_protocol: proto::UpstreamHttpProtocol::H2c as i32,
                plugins: vec![proto::Plugin {
                    name: "headers".into(),
                    json_config: r#"{"response":{"add":[["x-proxy","ngxora"]]}}"#.into(),
                }],
            }],
        }],
        le_config: None,
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
    assert_eq!(
        runtime.router.http_options.client_max_body_size,
        Some(8 * 1024 * 1024)
    );
    assert!(runtime.router.http_options.tcp_nodelay);
    assert!(runtime.router.http_options.allow_connect_method_proxying);
    assert_eq!(route.matcher, CompiledMatcher::Prefix("/api".into()));
    assert_eq!(
        route.target,
        RouteTarget::UpstreamGroup {
            name: "backend-pool".into(),
            tls: false,
        }
    );
    assert_eq!(
        route.upstream_timeouts.connect,
        Some(Duration::from_secs(1))
    );
    assert_eq!(route.upstream_timeouts.read, Some(Duration::from_secs(2)));
    assert_eq!(route.upstream_timeouts.write, Some(Duration::from_secs(3)));
    assert_eq!(route.upstream_protocol, Some(UpstreamHttpProtocol::H2c));
    assert_eq!(route.upstream_ssl_options.verify_cert, Switch::Off);
    let cache = route.cache.as_ref().expect("cache config present");
    assert!(cache.enabled);
    assert_eq!(cache.max_size, Some(256 * 1024));
    assert_eq!(cache.ttl, Some(Duration::from_secs(5 * 60)));
    assert_eq!(cache.stale_if_error, Some(Duration::from_secs(30)));
    assert_eq!(
        cache.cache_key,
        ngxora_compile::ir::CacheKeyMode::NormalizedUri
    );
    assert_eq!(cache.min_uses, Some(2));
    assert_eq!(cache.valid_statuses, vec![200, 301, 302]);
    assert_eq!(
        route.upstream_ssl_options.trusted_certificate,
        Some(PemSource::Path(TRUSTED_UPSTREAM_CA_PATH.into()))
    );
    assert_eq!(route.plugins.len(), 1);
    assert_eq!(route.plugins[0].name, "headers");
    assert_eq!(
        runtime.router.upstreams["backend-pool"].policy,
        UpstreamSelectionPolicy::ConsistentHash
    );
    assert_eq!(
        runtime.router.upstreams["backend-pool"].servers[0].weight,
        4
    );
    assert_eq!(
        runtime.router.upstreams["backend-pool"].servers[1].weight,
        1
    );
    assert_eq!(
        runtime.router.upstreams["backend-pool"].hash_key,
        Some(UpstreamHashKey::Header("X-Tenant-ID".into()))
    );
    assert_eq!(
        runtime.router.upstreams["backend-pool"].health_check,
        Some(crate::upstreams::CompiledHealthCheck {
            check_type: crate::upstreams::HealthCheckType::Http {
                host: "backend.internal".into(),
                path: "/readyz".into(),
                use_tls: true,
            },
            timeout: Duration::from_secs(2),
            interval: Duration::from_secs(10),
            consecutive_success: 2,
            consecutive_failure: 3,
        })
    );
}

#[test]
fn proto_snapshot_defaults_tcp_nodelay_to_on() {
    let snapshot = proto::ConfigSnapshot {
        version: "v1".into(),
        scp_profiles: Vec::new(),
        http: Some(proto::HttpOptions::default()),
        listeners: vec![proto::Listener {
            name: "edge".into(),
            address: "0.0.0.0".into(),
            port: 8080,
            tls: false,
            http2: false,
            http2_only: false,
            tls_options: None,
        }],
        upstreams: Vec::new(),
        virtual_hosts: vec![proto::VirtualHost {
            listener: "edge".into(),
            server_names: vec!["example.com".into()],
            default_server: true,
            tls: None,
            routes: vec![proto::Route {
                url_rewrite: None,
                r#match: Some(proto::Match {
                    kind: Some(proto::r#match::Kind::Prefix("/".into())),
                }),
                action: Some(proto::route::Action::Upstream(proto::Upstream {
                    scheme: "http".into(),
                    host: "127.0.0.1".into(),
                    port: 8080,
                    upstream_group: String::new(),
                })),
                timeouts: None,
                cache: None,
                plugins: Vec::new(),
                tls_options: None,
                upstream_protocol: proto::UpstreamHttpProtocol::Unspecified as i32,
            }],
        }],
        le_config: None,
    };

    let runtime = runtime_snapshot_from_proto(snapshot).expect("proto snapshot compiles");
    assert!(runtime.router.http_options.tcp_nodelay);
}

#[test]
fn proto_redirect_route_converts_into_runtime_return_target() {
    let snapshot = proto::ConfigSnapshot {
        version: "v-redirect".into(),
        scp_profiles: Vec::new(),
        http: Some(proto::HttpOptions::default()),
        listeners: vec![proto::Listener {
            name: "edge".into(),
            address: "0.0.0.0".into(),
            port: 8080,
            tls: false,
            http2: false,
            http2_only: false,
            tls_options: None,
        }],
        upstreams: Vec::new(),
        virtual_hosts: vec![proto::VirtualHost {
            listener: "edge".into(),
            server_names: vec!["example.com".into()],
            default_server: true,
            tls: None,
            routes: vec![proto::Route {
                url_rewrite: None,
                r#match: Some(proto::Match {
                    kind: Some(proto::r#match::Kind::Prefix("/old".into())),
                }),
                action: Some(proto::route::Action::Redirect(proto::Redirect {
                    status: 301,
                    location: "https://example.com/new".into(),
                })),
                timeouts: None,
                cache: None,
                plugins: Vec::new(),
                tls_options: None,
                upstream_protocol: proto::UpstreamHttpProtocol::Unspecified as i32,
            }],
        }],
        le_config: None,
    };

    let runtime = runtime_snapshot_from_proto(snapshot).expect("proto snapshot compiles");
    let listen_key = ListenKey {
        addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        port: 8080,
        ssl: false,
    };
    let route = runtime
        .router
        .listeners
        .get(&listen_key)
        .and_then(|routes| routes.default.as_ref())
        .and_then(|server| server.locations.first())
        .expect("redirect route exists");

    assert_eq!(
        route.target,
        RouteTarget::Return {
            status: 301,
            location: "https://example.com/new".into(),
        }
    );
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
    assert_eq!(
        proto
            .http
            .as_ref()
            .expect("http options")
            .client_max_body_size_bytes,
        16 * 1024 * 1024
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
    #[cfg(feature = "plugin-headers")]
    {
        assert_eq!(vhost.routes[0].plugins.len(), 1);
        assert_eq!(vhost.routes[0].plugins[0].name, "headers");
    }
    #[cfg(not(feature = "plugin-headers"))]
    assert!(vhost.routes[0].plugins.is_empty());
    assert_eq!(
        vhost.routes[0]
            .tls_options
            .as_ref()
            .expect("route tls options")
            .verify,
        proto::Switch::Off as i32
    );
    assert_eq!(
        vhost.routes[0]
            .tls_options
            .as_ref()
            .and_then(|options| options.trusted_certificate.as_ref())
            .and_then(|source| source.source.as_ref()),
        Some(&proto::pem_source::Source::InlinePem(TEST_CA_PEM.into(),))
    );
    assert_eq!(
        vhost.routes[0].action.as_ref(),
        Some(&proto::route::Action::Upstream(proto::Upstream {
            scheme: "https".into(),
            host: String::new(),
            port: 0,
            upstream_group: "backend-pool".into(),
        }))
    );
    assert_eq!(
        vhost.routes[0].cache.as_ref(),
        Some(&proto::RouteCache {
            enabled: proto::Switch::On as i32,
            max_size_bytes: 256 * 1024,
            ttl_ms: 5 * 60 * 1_000,
            stale_if_error_ms: 30 * 1_000,
            key_mode: proto::CacheKeyMode::NormalizedUri as i32,
            min_uses: 2,
            valid_statuses: vec![200, 301, 302],
        })
    );
    assert_eq!(
        vhost.routes[0].upstream_protocol,
        proto::UpstreamHttpProtocol::H2 as i32
    );
    assert_eq!(proto.upstreams.len(), 1);
    assert_eq!(proto.upstreams[0].backends.len(), 2);
    assert_eq!(
        proto.upstreams[0].policy,
        proto::UpstreamSelectionPolicy::ConsistentHash as i32
    );
    assert_eq!(proto.upstreams[0].backends[0].weight, 3);
    assert_eq!(proto.upstreams[0].backends[1].weight, 1);
    assert_eq!(
        proto.upstreams[0]
            .hash_key
            .as_ref()
            .and_then(|hash_key| hash_key.source.as_ref()),
        Some(&proto::upstream_hash_key::Source::Header(
            "X-Tenant-ID".into()
        ))
    );
    assert_eq!(
        proto.upstreams[0]
            .health_check
            .as_ref()
            .and_then(|health_check| health_check.kind.as_ref()),
        Some(&proto::upstream_health_check::Kind::Tcp(
            proto::UpstreamTcpHealthCheck {}
        ))
    );
    assert_eq!(
        proto.upstreams[0]
            .health_check
            .as_ref()
            .map(|health_check| health_check.interval_ms),
        Some(5_000)
    );
}

#[test]
fn runtime_return_route_converts_back_to_proto_redirect() {
    let http = Http {
        servers: vec![Server {
            server_names: vec!["example.com".into()],
            locations: vec![Location {
                matcher: LocationMatcher::Prefix("/old".into()),
                directives: vec![LocationDirective::Return {
                    status: 308,
                    location: "https://example.com/new".into(),
                }],
                access_rules: Vec::new(),
                plugins: Vec::new(),
                cache: None,
            }],
            listens: vec![Listen {
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port: 8080,
                default_server: true,
                ..Listen::default()
            }],
            ..Server::default()
        }],
        ..Http::default()
    };
    let router = CompiledRouter::from_http(&http).expect("router compiles");
    let state = RuntimeState::new(ConfigSnapshot::new("redirect-v1", router));
    let snapshot = state.snapshot();
    let proto =
        proto_snapshot_from_runtime(snapshot.as_ref()).expect("runtime snapshot serializes");
    let route = &proto.virtual_hosts[0].routes[0];

    assert_eq!(
        route.action.as_ref(),
        Some(&proto::route::Action::Redirect(proto::Redirect {
            status: 308,
            location: "https://example.com/new".into(),
        }))
    );
}
