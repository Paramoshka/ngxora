//! Balancing policies and active health checks.

use crate::upstreams::{
    CompiledHealthCheck, CompiledRouter, CompiledUpstreamGroup, CompiledUpstreamServer,
    HealthCheckType, RouteTarget, upstream_selection_key,
};
use ngxora_compile::ir::{
    Http, Listen, Location, LocationDirective, LocationMatcher, ProxyPassTarget, Server,
    UpstreamBlock, UpstreamHealthCheck, UpstreamHealthCheckType, UpstreamSelectionPolicy,
    UpstreamServer,
};
use pingora_proxy::Session;
use std::time::Duration;
use tokio::io::{AsyncWriteExt, duplex};

#[test]
fn compiled_router_maps_named_upstream_groups() {
    let http = Http {
        upstreams: vec![UpstreamBlock {
            allow_empty: false,
            nrf_discovery: None,
            name: "backend".into(),
            policy: UpstreamSelectionPolicy::RoundRobin,
            hash_key: None,
            servers: vec![
                UpstreamServer {
                    host: "127.0.0.1".into(),
                    port: 8080,
                    weight: 1,
                },
                UpstreamServer {
                    host: "127.0.0.1".into(),
                    port: 8081,
                    weight: 1,
                },
            ],
            health_check: None,
        }],
        servers: vec![Server {
            listens: vec![Listen {
                default_server: true,
                ..Listen::default()
            }],
            locations: vec![Location {
                matcher: LocationMatcher::Prefix("/".into()),
                directives: vec![LocationDirective::ProxyPass(ProxyPassTarget::Url(
                    "http://backend".parse().unwrap(),
                ))],
                access_rules: Vec::new(),
                plugins: Vec::new(),
                cache: None,
            }],
            ..Server::default()
        }],
        ..Http::default()
    };

    let router = CompiledRouter::from_http(&http).expect("router compiles");
    let location = &router
        .listeners
        .values()
        .next()
        .expect("listener present")
        .default
        .as_ref()
        .expect("default route present")
        .locations[0];

    assert_eq!(
        location.target,
        RouteTarget::UpstreamGroup {
            name: "backend".into(),
            tls: false,
        }
    );
}

#[test]
fn runtime_upstream_group_round_robins_backends() {
    let group = crate::upstreams::RuntimeUpstreamGroup::from_compiled(&CompiledUpstreamGroup {
        allow_empty: false,
        nrf_discovery: None,
        name: "backend".into(),
        policy: UpstreamSelectionPolicy::RoundRobin,
        hash_key: None,
        servers: vec![
            CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 8080,
                weight: 1,
                api_prefix: None,
                nrf_service: None,
            },
            CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 8081,
                weight: 1,
                api_prefix: None,
                nrf_service: None,
            },
        ],
        health_check: None,
    })
    .expect("runtime group builds");

    let first = group.select(b"").expect("first backend");
    let second = group.select(b"").expect("second backend");
    let third = group.select(b"").expect("third backend");

    assert_eq!(first.port, 8080);
    assert_eq!(second.port, 8081);
    assert_eq!(third.port, 8080);
}

#[test]
fn runtime_upstream_group_honors_round_robin_weights() {
    let group = crate::upstreams::RuntimeUpstreamGroup::from_compiled(&CompiledUpstreamGroup {
        allow_empty: false,
        nrf_discovery: None,
        name: "backend".into(),
        policy: UpstreamSelectionPolicy::RoundRobin,
        hash_key: None,
        servers: vec![
            CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 8080,
                weight: 3,
                api_prefix: None,
                nrf_service: None,
            },
            CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 8081,
                weight: 1,
                api_prefix: None,
                nrf_service: None,
            },
        ],
        health_check: None,
    })
    .expect("runtime group builds");

    let ports = (0..4)
        .map(|_| group.select(b"").expect("backend").port)
        .collect::<Vec<_>>();
    assert_eq!(ports.iter().filter(|port| **port == 8080).count(), 3);
    assert_eq!(ports.iter().filter(|port| **port == 8081).count(), 1);
}

#[test]
fn runtime_upstream_group_consistent_hash_is_stable_and_distributes_keys() {
    let group = crate::upstreams::RuntimeUpstreamGroup::from_compiled(&CompiledUpstreamGroup {
        allow_empty: false,
        nrf_discovery: None,
        name: "backend".into(),
        policy: UpstreamSelectionPolicy::ConsistentHash,
        hash_key: Some(ngxora_compile::ir::UpstreamHashKey::Header(
            "X-Tenant-ID".into(),
        )),
        servers: vec![
            CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 8080,
                weight: 1,
                api_prefix: None,
                nrf_service: None,
            },
            CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 8081,
                weight: 1,
                api_prefix: None,
                nrf_service: None,
            },
        ],
        health_check: None,
    })
    .expect("runtime group builds");

    let first = group.select(b"tenant-a").expect("first selection");
    for _ in 0..10 {
        assert_eq!(group.select(b"tenant-a"), Some(first.clone()));
    }

    let selected_ports = (0..100)
        .map(|index| {
            group
                .select(format!("tenant-{index}").as_bytes())
                .expect("backend")
                .port
        })
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(selected_ports.len(), 2);
}

#[tokio::test]
async fn consistent_hash_header_requires_one_nonempty_value() {
    let (mut client, server) = duplex(1024);
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Tenant-ID: tenant-a\r\n\r\n")
        .await
        .expect("write request");
    let mut session = Session::new_h1(Box::new(server));
    session.read_request().await.expect("read request");

    assert_eq!(
        upstream_selection_key(
            Some(&ngxora_compile::ir::UpstreamHashKey::Header(
                "X-Tenant-ID".into(),
            )),
            &session,
        )
        .expect("header key"),
        b"tenant-a"
    );

    session.req_header_mut().remove_header("X-Tenant-ID");
    session
        .req_header_mut()
        .append_header("X-Tenant-ID", "tenant-a")
        .expect("append first header");
    session
        .req_header_mut()
        .append_header("X-Tenant-ID", "tenant-b")
        .expect("append second header");
    let err = upstream_selection_key(
        Some(&ngxora_compile::ir::UpstreamHashKey::Header(
            "X-Tenant-ID".into(),
        )),
        &session,
    )
    .expect_err("repeated header and missing socket IP must fail");
    assert_eq!(err.etype(), &pingora::ErrorType::HTTPStatus(503));
}

#[test]
fn runtime_upstream_group_random_selects_configured_backend() {
    let group = crate::upstreams::RuntimeUpstreamGroup::from_compiled(&CompiledUpstreamGroup {
        allow_empty: false,
        nrf_discovery: None,
        name: "backend".into(),
        policy: UpstreamSelectionPolicy::Random,
        hash_key: None,
        servers: vec![
            CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 8080,
                weight: 1,
                api_prefix: None,
                nrf_service: None,
            },
            CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 8081,
                weight: 1,
                api_prefix: None,
                nrf_service: None,
            },
        ],
        health_check: None,
    })
    .expect("runtime group builds");

    let selected = group.select(b"").expect("selected backend");
    assert!(matches!(selected.port, 8080 | 8081));
}

#[test]
fn compiled_router_maps_upstream_health_check() {
    let http = Http {
        upstreams: vec![UpstreamBlock {
            allow_empty: false,
            nrf_discovery: None,
            name: "backend".into(),
            policy: UpstreamSelectionPolicy::RoundRobin,
            hash_key: None,
            servers: vec![UpstreamServer {
                host: "127.0.0.1".into(),
                port: 8080,
                weight: 1,
            }],
            health_check: Some(UpstreamHealthCheck {
                check_type: UpstreamHealthCheckType::Http {
                    host: "backend.internal".into(),
                    path: "/readyz".into(),
                    use_tls: true,
                },
                timeout: Duration::from_secs(2),
                interval: Duration::from_secs(10),
                consecutive_success: 2,
                consecutive_failure: 3,
            }),
        }],
        ..Http::default()
    };

    let router = CompiledRouter::from_http(&http).expect("router compiles");
    assert_eq!(
        router.upstreams["backend"].health_check,
        Some(CompiledHealthCheck {
            check_type: HealthCheckType::Http {
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

#[tokio::test]
async fn runtime_upstream_group_tcp_health_check_marks_unreachable_backends_unhealthy() {
    let group = crate::upstreams::RuntimeUpstreamGroup::from_compiled(&CompiledUpstreamGroup {
        allow_empty: false,
        nrf_discovery: None,
        name: "backend".into(),
        policy: UpstreamSelectionPolicy::RoundRobin,
        hash_key: None,
        servers: vec![
            CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 1,
                weight: 1,
                api_prefix: None,
                nrf_service: None,
            },
            CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 2,
                weight: 1,
                api_prefix: None,
                nrf_service: None,
            },
        ],
        health_check: Some(CompiledHealthCheck {
            check_type: HealthCheckType::Tcp,
            timeout: Duration::from_secs(1),
            interval: Duration::from_secs(5),
            consecutive_success: 1,
            consecutive_failure: 1,
        }),
    })
    .expect("runtime group builds");

    group
        .run_due_health_check(tokio::time::Instant::now())
        .await
        .expect("scheduled health check");
    assert!(group.select(b"").is_none());
}

#[tokio::test]
async fn runtime_upstream_group_http_health_check_marks_unreachable_backends_unhealthy() {
    let group = crate::upstreams::RuntimeUpstreamGroup::from_compiled(&CompiledUpstreamGroup {
        allow_empty: false,
        nrf_discovery: None,
        name: "backend".into(),
        policy: UpstreamSelectionPolicy::RoundRobin,
        hash_key: None,
        servers: vec![
            CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 1,
                weight: 1,
                api_prefix: None,
                nrf_service: None,
            },
            CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 2,
                weight: 1,
                api_prefix: None,
                nrf_service: None,
            },
        ],
        health_check: Some(CompiledHealthCheck {
            check_type: HealthCheckType::Http {
                host: "backend.internal".into(),
                path: "/readyz".into(),
                use_tls: false,
            },
            timeout: Duration::from_secs(1),
            interval: Duration::from_secs(5),
            consecutive_success: 1,
            consecutive_failure: 1,
        }),
    })
    .expect("runtime group builds");

    group
        .run_due_health_check(tokio::time::Instant::now())
        .await
        .expect("scheduled health check");
    assert!(group.select(b"").is_none());
}
