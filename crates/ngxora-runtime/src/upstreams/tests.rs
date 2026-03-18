use super::{
    CompiledHealthCheck, CompiledLocation, CompiledMatcher, CompiledRegex, CompiledRouter,
    CompiledUpstreamGroup, CompiledUpstreamServer, HealthCheckType, RouteTarget, ServerRoutes,
    VirtualHostRoutes, apply_upstream_ssl_options, apply_upstream_timeouts,
    content_length_limit_exceeded, downstream_keepalive_timeout_secs, listener_routes,
    select_route_target, update_received_body_bytes, validate_sni_host_consistency,
};
use bytes::Bytes;
use ngxora_compile::ir::{
    Http, KeepaliveTimeout, Listen, Location, LocationDirective, LocationMatcher, PemSource,
    ProxyPassTarget, Server, Switch, UpstreamBlock, UpstreamHealthCheck,
    UpstreamHealthCheckType, UpstreamSelectionPolicy, UpstreamServer, UpstreamSslOptions,
    UpstreamTimeouts,
};
use ngxora_plugin_api::PluginSpec;
use pingora::upstreams::peer::HttpPeer;
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

#[cfg(feature = "openssl")]
const TEST_CA_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDXTCCAkWgAwIBAgIJAOIvDiVb18eVMA0GCSqGSIb3DQEBCwUAMEUxCzAJBgNV
BAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBX
aWRnaXRzIFB0eSBMdGQwHhcNMTYwODE0MTY1NjExWhcNMjYwODEyMTY1NjExWjBF
MQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29tZS1TdGF0ZTEhMB8GA1UECgwYSW50
ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIB
CgKCAQEArVHWFn52Lbl1l59exduZntVSZyDYpzDND+S2LUcO6fRBWhV/1Kzox+2G
ZptbuMGmfI3iAnb0CFT4uC3kBkQQlXonGATSVyaFTFR+jq/lc0SP+9Bd7SBXieIV
eIXlY1TvlwIvj3Ntw9zX+scTA4SXxH6M0rKv9gTOub2vCMSHeF16X8DQr4XsZuQr
7Cp7j1I4aqOJyap5JTl5ijmG8cnu0n+8UcRlBzy99dLWJG0AfI3VRJdWpGTNVZ92
aFff3RpK3F/WI2gp3qV1ynRAKuvmncGC3LDvYfcc2dgsc1N6Ffq8GIrkgRob6eBc
klDHp1d023Lwre+VaVDSo1//Y72UFwIDAQABo1AwTjAdBgNVHQ4EFgQUbNOlA6sN
XyzJjYqciKeId7g3/ZowHwYDVR0jBBgwFoAUbNOlA6sNXyzJjYqciKeId7g3/Zow
DAYDVR0TBAUwAwEB/zANBgkqhkiG9w0BAQsFAAOCAQEAVVaR5QWLZIRR4Dw6TSBn
BQiLpBSXN6oAxdDw6n4PtwW6CzydaA+creiK6LfwEsiifUfQe9f+T+TBSpdIYtMv
Z2H2tjlFX8VrjUFvPrvn5c28CuLI0foBgY8XGSkR2YMYzWw2jPEq3Th/KM5Catn3
AFm3bGKWMtGPR4v+90chEN0jzaAmJYRrVUh9vea27bOCn31Nse6XXQPmSI6Gyncy
OAPUsvPClF3IjeL1tmBotWqSGn1cYxLo+Lwjk22A9h6vjcNQRyZF2VLVvtwYrNU3
mwJ6GCLsLHpwW/yjyvn8iEltnJvByM/eeRnfXV6WDObyiZsE/n6DxIRJodQzFqy9
GA==
-----END CERTIFICATE-----
";

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
        upstream_ssl_options: UpstreamSslOptions::default(),
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
fn compiled_router_parses_proxy_ssl_options() {
    let trusted_certificate = PemSource::Path("/etc/ssl/upstreams/ca.pem".into());
    let http = Http {
        servers: vec![Server {
            listens: vec![Listen {
                default_server: true,
                ..Listen::default()
            }],
            locations: vec![Location {
                matcher: LocationMatcher::Prefix("/".into()),
                directives: vec![
                    LocationDirective::ProxySslVerify(Switch::Off),
                    LocationDirective::ProxySslTrustedCertificate(trusted_certificate.clone()),
                    LocationDirective::ProxyPass(ProxyPassTarget::Url(
                        "https://127.0.0.1:8443".parse().unwrap(),
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
        location.upstream_ssl_options,
        UpstreamSslOptions {
            verify_cert: Switch::Off,
            trusted_certificate: Some(trusted_certificate),
        }
    );
}

#[test]
fn apply_upstream_ssl_options_disables_verification() {
    let mut peer = HttpPeer::new(("127.0.0.1", 8443), true, String::new());

    apply_upstream_ssl_options(
        &mut peer,
        &UpstreamSslOptions {
            verify_cert: Switch::Off,
            trusted_certificate: None,
        },
        None,
    );

    assert!(!peer.options.verify_cert);
    assert!(!peer.options.verify_hostname);
    assert!(peer.options.ca.is_none());
}

#[cfg(feature = "openssl")]
#[test]
fn apply_upstream_ssl_options_sets_trusted_ca() {
    let source = PemSource::InlinePem(TEST_CA_PEM.into());
    let http = Http {
        servers: vec![Server {
            listens: vec![Listen {
                default_server: true,
                ..Listen::default()
            }],
            locations: vec![Location {
                matcher: LocationMatcher::Prefix("/".into()),
                directives: vec![
                    LocationDirective::ProxySslTrustedCertificate(source.clone()),
                    LocationDirective::ProxyPass(ProxyPassTarget::Url(
                        "https://127.0.0.1:8443".parse().unwrap(),
                    )),
                ],
                plugins: Vec::new(),
            }],
            ..Server::default()
        }],
        ..Http::default()
    };

    let router = CompiledRouter::from_http(&http).expect("router compiles");
    let trusted_cas = super::build_runtime_trusted_cas(&router).expect("trusted ca builds");
    let trusted_ca = trusted_cas.get(&source).expect("trusted ca cached");
    let mut peer = HttpPeer::new(("127.0.0.1", 8443), true, String::new());

    apply_upstream_ssl_options(
        &mut peer,
        &UpstreamSslOptions {
            verify_cert: Switch::On,
            trusted_certificate: Some(source),
        },
        Some(trusted_ca),
    );

    assert!(peer.options.verify_cert);
    assert!(peer.options.verify_hostname);
    assert!(peer.options.ca.is_some());
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
    let group = super::RuntimeUpstreamGroup::from_compiled(&CompiledUpstreamGroup {
        name: "backend".into(),
        policy: UpstreamSelectionPolicy::RoundRobin,
        servers: vec![
            CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 8080,
            },
            CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 8081,
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
fn runtime_upstream_group_random_selects_configured_backend() {
    let group = super::RuntimeUpstreamGroup::from_compiled(&CompiledUpstreamGroup {
        name: "backend".into(),
        policy: UpstreamSelectionPolicy::Random,
        servers: vec![
            CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 8080,
            },
            CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 8081,
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
            name: "backend".into(),
            policy: UpstreamSelectionPolicy::RoundRobin,
            servers: vec![UpstreamServer {
                host: "127.0.0.1".into(),
                port: 8080,
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
    let group = super::RuntimeUpstreamGroup::from_compiled(&CompiledUpstreamGroup {
        name: "backend".into(),
        policy: UpstreamSelectionPolicy::RoundRobin,
        servers: vec![
            CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 1,
            },
            CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 2,
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
    let group = super::RuntimeUpstreamGroup::from_compiled(&CompiledUpstreamGroup {
        name: "backend".into(),
        policy: UpstreamSelectionPolicy::RoundRobin,
        servers: vec![
            CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 1,
            },
            CompiledUpstreamServer {
                host: "127.0.0.1".into(),
                port: 2,
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
