use super::{
    CompiledLocation, CompiledMatcher, CompiledRegex, CompiledRouter, RouteTarget, ServerRoutes,
    VirtualHostRoutes, apply_upstream_timeouts, content_length_limit_exceeded,
    downstream_keepalive_timeout_secs, listener_routes, select_route_target,
    update_received_body_bytes, validate_sni_host_consistency,
};
use bytes::Bytes;
use ngxora_compile::ir::{
    Http, KeepaliveTimeout, Listen, Location, LocationDirective, LocationMatcher,
    ProxyPassTarget, Server, UpstreamBlock, UpstreamSelectionPolicy, UpstreamServer,
    UpstreamTimeouts,
};
use ngxora_plugin_api::PluginSpec;
use pingora::upstreams::peer::HttpPeer;
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

fn target(id: &str) -> RouteTarget {
    RouteTarget::ProxyPass {
        host: format!("{id}.example.com"),
        port: 80,
        tls: false,
        sni: String::new(),
    }
}

fn location(matcher: CompiledMatcher, id: &str) -> CompiledLocation {
    CompiledLocation {
        route_id: 1,
        matcher,
        target: target(id),
        upstream_timeouts: UpstreamTimeouts::default(),
        plugins: Vec::<PluginSpec>::new(),
    }
}

fn regex(pattern: &str, case_insensitive: bool) -> CompiledMatcher {
    CompiledMatcher::Regex(
        CompiledRegex::new(pattern.to_string(), case_insensitive).expect("regex compiles"),
    )
}

fn selected_host<'a>(routes: &'a ServerRoutes, path: &str) -> Option<&'a str> {
    match select_route_target(routes, path) {
        Some(CompiledLocation {
            target: RouteTarget::ProxyPass { host, .. },
            ..
        }) => Some(host.as_str()),
        Some(_) => None,
        None => None,
    }
}

#[test]
fn exact_match_wins() {
    let routes = ServerRoutes {
        locations: vec![
            location(CompiledMatcher::Prefix("/".into()), "prefix"),
            location(CompiledMatcher::Exact("/app".into()), "exact"),
            location(regex("^/app$", false), "regex"),
        ],
    };

    assert_eq!(selected_host(&routes, "/app"), Some("exact.example.com"));
}

#[test]
fn prefer_prefix_blocks_regex() {
    let routes = ServerRoutes {
        locations: vec![
            location(
                CompiledMatcher::PreferPrefix("/images/".into()),
                "prefer-prefix",
            ),
            location(regex("\\.(png|jpg)$", false), "regex"),
        ],
    };

    assert_eq!(
        selected_host(&routes, "/images/logo.png"),
        Some("prefer-prefix.example.com")
    );
}

#[test]
fn first_matching_regex_wins_over_plain_prefix() {
    let routes = ServerRoutes {
        locations: vec![
            location(CompiledMatcher::Prefix("/api/".into()), "prefix"),
            location(regex("^/api/v[0-9]+/", false), "regex-1"),
            location(regex("^/api/", false), "regex-2"),
        ],
    };

    assert_eq!(
        selected_host(&routes, "/api/v1/users"),
        Some("regex-1.example.com")
    );
}

#[test]
fn longest_plain_prefix_is_used_when_no_regex_matches() {
    let routes = ServerRoutes {
        locations: vec![
            location(CompiledMatcher::Prefix("/".into()), "root"),
            location(CompiledMatcher::Prefix("/api/".into()), "api"),
            location(CompiledMatcher::Prefix("/api/internal/".into()), "internal"),
            location(regex("^/admin/", false), "regex"),
        ],
    };

    assert_eq!(
        selected_host(&routes, "/api/internal/users"),
        Some("internal.example.com")
    );
}

#[test]
fn named_location_is_not_selected_for_request_path() {
    let routes = ServerRoutes {
        locations: vec![
            location(CompiledMatcher::Named("fallback".into()), "named"),
            location(CompiledMatcher::Prefix("/".into()), "prefix"),
        ],
    };

    assert_eq!(selected_host(&routes, "/"), Some("prefix.example.com"));
}

#[test]
fn wildcard_listener_routes_match_concrete_local_addr() {
    let wildcard = super::ListenKey {
        addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        port: 8080,
        ssl: false,
    };
    let concrete = super::ListenKey {
        addr: IpAddr::V4(Ipv4Addr::new(172, 18, 0, 10)),
        port: 8080,
        ssl: false,
    };
    let router = CompiledRouter {
        listeners: HashMap::from([(
            wildcard,
            VirtualHostRoutes {
                named: HashMap::new(),
                default: Some(ServerRoutes {
                    locations: vec![location(CompiledMatcher::Prefix("/".into()), "wildcard")],
                }),
            },
        )]),
        ..CompiledRouter::default()
    };

    let routes = listener_routes(&router, &concrete).expect("wildcard listener should match");
    assert_eq!(
        selected_host(routes.default.as_ref().expect("default routes"), "/"),
        Some("wildcard.example.com")
    );
}

#[test]
fn downstream_keepalive_timeout_maps_off_to_none() {
    assert_eq!(
        downstream_keepalive_timeout_secs(&KeepaliveTimeout::Off),
        None
    );
}

#[test]
fn downstream_keepalive_timeout_rounds_up_subsecond_values() {
    assert_eq!(
        downstream_keepalive_timeout_secs(&KeepaliveTimeout::Timeout {
            idle: Duration::from_millis(1_500),
            header: None,
        }),
        Some(2)
    );
}

#[test]
fn downstream_keepalive_timeout_treats_zero_idle_as_disabled() {
    assert_eq!(
        downstream_keepalive_timeout_secs(&KeepaliveTimeout::Timeout {
            idle: Duration::ZERO,
            header: Some(Duration::from_secs(10)),
        }),
        None
    );
}

#[test]
fn validate_sni_host_consistency_rejects_mismatch() {
    let err = validate_sni_host_consistency(Some("api.example.com"), Some("edge.example.com"))
        .expect_err("expected mismatch to fail");

    assert_eq!(err.etype(), &pingora::ErrorType::HTTPStatus(421));
}

#[test]
fn compiled_router_rejects_invalid_location_regex() {
    let http = Http {
        servers: vec![Server {
            listens: vec![Listen {
                default_server: true,
                ..Listen::default()
            }],
            locations: vec![Location {
                matcher: LocationMatcher::Regex {
                    case_insensitive: false,
                    pattern: "(".into(),
                },
                directives: vec![LocationDirective::ProxyPass(
                    ProxyPassTarget::Url("http://127.0.0.1:8080".parse().unwrap()),
                )],
                plugins: Vec::new(),
            }],
            ..Server::default()
        }],
        ..Http::default()
    };

    let err = CompiledRouter::from_http(&http).expect_err("expected invalid regex to fail");
    assert!(err.contains("invalid location regex"));
}

#[test]
fn compiled_router_parses_proxy_timeouts() {
    let http = Http {
        servers: vec![Server {
            listens: vec![Listen {
                default_server: true,
                ..Listen::default()
            }],
            locations: vec![Location {
                matcher: LocationMatcher::Prefix("/".into()),
                directives: vec![
                    LocationDirective::ProxyConnectTimeout(Duration::from_secs(2)),
                    LocationDirective::ProxyReadTimeout(Duration::from_secs(15)),
                    LocationDirective::ProxyWriteTimeout(Duration::from_secs(20)),
                    LocationDirective::ProxyPass(ProxyPassTarget::Url(
                        "http://127.0.0.1:8080".parse().unwrap(),
                    )),
                ],
                plugins: Vec::new(),
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
        location.upstream_timeouts,
        UpstreamTimeouts {
            connect: Some(Duration::from_secs(2)),
            read: Some(Duration::from_secs(15)),
            write: Some(Duration::from_secs(20)),
        }
    );
}

#[test]
fn compiled_router_maps_client_max_body_size_into_runtime_options() {
    let mut http = Http::default();
    http.client_max_body_size = Some(10 * 1024 * 1024);
    http.servers.push(Server {
        listens: vec![Listen {
            default_server: true,
            ..Listen::default()
        }],
        ..Server::default()
    });

    let router = CompiledRouter::from_http(&http).expect("router compiles");

    assert_eq!(
        router.http_options.client_max_body_size,
        Some(10 * 1024 * 1024)
    );
}

#[test]
fn compiled_router_maps_named_upstream_groups() {
    let http = Http {
        upstreams: vec![UpstreamBlock {
            name: "backend".into(),
            policy: UpstreamSelectionPolicy::RoundRobin,
            servers: vec![
                UpstreamServer {
                    host: "127.0.0.1".into(),
                    port: 8080,
                },
                UpstreamServer {
                    host: "127.0.0.1".into(),
                    port: 8081,
                },
            ],
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
                plugins: Vec::new(),
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
    let group = super::RuntimeUpstreamGroup::from_compiled(&super::CompiledUpstreamGroup {
        name: "backend".into(),
        policy: UpstreamSelectionPolicy::RoundRobin,
        servers: vec![
            super::CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 8080,
            },
            super::CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 8081,
            },
        ],
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
fn runtime_upstream_group_random_selects_configured_backend() {
    let group = super::RuntimeUpstreamGroup::from_compiled(&super::CompiledUpstreamGroup {
        name: "backend".into(),
        policy: UpstreamSelectionPolicy::Random,
        servers: vec![
            super::CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 8080,
            },
            super::CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 8081,
            },
        ],
    })
    .expect("runtime group builds");

    let selected = group.select(b"").expect("selected backend");
    assert!(matches!(selected.port, 8080 | 8081));
}

#[test]
fn content_length_limit_exceeded_rejects_large_body() {
    let header = http::HeaderValue::from_static("10485761");

    assert_eq!(
        content_length_limit_exceeded(Some(&header), Some(10 * 1024 * 1024)),
        Some(true)
    );
}

#[test]
fn update_received_body_bytes_tracks_streamed_body() {
    let mut received = 0;

    update_received_body_bytes(&mut received, Some(&Bytes::from_static(b"hello")), Some(10))
        .expect("first chunk fits");
    update_received_body_bytes(&mut received, Some(&Bytes::from_static(b"rust")), Some(10))
        .expect("second chunk fits");

    assert_eq!(received, 9);
}

#[test]
fn update_received_body_bytes_rejects_overflowing_stream() {
    let mut received = 8;
    let err = update_received_body_bytes(
        &mut received,
        Some(&Bytes::from_static(b"toolong")),
        Some(10),
    )
    .expect_err("expected body limit to be enforced");

    assert_eq!(err.etype(), &pingora::ErrorType::HTTPStatus(413));
}

#[test]
fn compiled_router_preserves_location_plugins() {
    let http = Http {
        servers: vec![Server {
            listens: vec![Listen {
                default_server: true,
                ..Listen::default()
            }],
            locations: vec![Location {
                matcher: LocationMatcher::Prefix("/".into()),
                directives: vec![LocationDirective::ProxyPass(
                    ProxyPassTarget::Url("http://127.0.0.1:8080".parse().unwrap()),
                )],
                plugins: vec![PluginSpec {
                    name: "headers".into(),
                    config: json!({
                        "response": {
                            "add": [
                                { "name": "X-Proxy", "value": "ngxora" }
                            ]
                        }
                    }),
                }],
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

    assert_eq!(location.plugins, http.servers[0].locations[0].plugins);
}

#[test]
fn apply_upstream_timeouts_maps_zero_to_none() {
    let mut peer = HttpPeer::new(("127.0.0.1", 8080), false, String::new());
    apply_upstream_timeouts(
        &mut peer,
        UpstreamTimeouts {
            connect: Some(Duration::ZERO),
            read: Some(Duration::from_secs(10)),
            write: Some(Duration::from_secs(5)),
        },
    );

    assert_eq!(peer.options.connection_timeout, None);
    assert_eq!(peer.options.read_timeout, Some(Duration::from_secs(10)));
    assert_eq!(peer.options.write_timeout, Some(Duration::from_secs(5)));
}
