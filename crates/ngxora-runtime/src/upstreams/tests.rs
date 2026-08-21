use super::{
    CompiledHealthCheck, CompiledLocation, CompiledMatcher, CompiledRegex, CompiledRouter,
    CompiledUpstreamGroup, CompiledUpstreamServer, HealthCheckType, RouteTarget, ServerRoutes,
    VirtualHostRoutes, apply_upstream_http_protocol, apply_upstream_ssl_options,
    apply_upstream_timeouts, content_length_limit_exceeded, downstream_keepalive_timeout_secs,
    listener_routes, select_route_target, update_received_body_bytes,
    validate_sni_host_consistency,
};
use bytes::Bytes;
use ipnet::IpNet;
use ngxora_compile::ir::{
    Http, KeepaliveTimeout, Listen, Location, LocationDirective, LocationIpRule, LocationMatcher,
    PemSource, ProxyPassTarget, Server, SslProvider, Switch, UpstreamBlock, UpstreamHealthCheck,
    UpstreamHealthCheckType, UpstreamHttpProtocol, UpstreamSelectionPolicy, UpstreamServer,
    UpstreamSslOptions, UpstreamTimeouts,
};
use ngxora_plugin_api::PluginSpec;
use pingora::http::ResponseHeader;
use pingora::upstreams::peer::HttpPeer;
use pingora_proxy::{ProxyHttp, Session};
use serde_json::json;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;
use tokio::io::{AsyncWriteExt, duplex};

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
        access_rules: Vec::new(),
        target: target(id),
        upstream_timeouts: UpstreamTimeouts::default(),
        upstream_protocol: None,
        upstream_ssl_options: UpstreamSslOptions::default(),
        plugins: Vec::<PluginSpec>::new(),
        cache: None,
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
                directives: vec![LocationDirective::ProxyPass(ProxyPassTarget::Url(
                    "http://127.0.0.1:8080".parse().unwrap(),
                ))],
                access_rules: Vec::new(),
                plugins: Vec::new(),
                cache: None,
            }],
            ..Server::default()
        }],
        ..Http::default()
    };

    let err = CompiledRouter::from_http(&http).expect_err("expected invalid regex to fail");
    assert!(err.contains("invalid location regex"));
}

#[test]
fn compiled_router_rejects_letsencrypt_with_multiple_server_names() {
    let http = Http {
        ssl_provider: Some(ngxora_compile::ir::LetsEncryptConfig {
            acme_directory: None,
            email: Some("admin@example.com".into()),
            cache_dir: None,
        }),
        servers: vec![Server {
            listens: vec![Listen {
                port: 443,
                ssl: true,
                default_server: true,
                ..Listen::default()
            }],
            server_names: vec!["example.com".into(), "www.example.com".into()],
            tls: Some(SslProvider::LetsEncrypt),
            locations: vec![Location {
                matcher: LocationMatcher::Prefix("/".into()),
                directives: vec![LocationDirective::ProxyPass(ProxyPassTarget::Url(
                    "http://127.0.0.1:8080".parse().unwrap(),
                ))],
                access_rules: Vec::new(),
                plugins: Vec::new(),
                cache: None,
            }],
            ..Server::default()
        }],
        ..Http::default()
    };

    let err = CompiledRouter::from_http(&http).expect_err("expected LE alias rejection");
    assert!(err.contains("supports exactly one server_name"));
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
        location.upstream_ssl_options,
        UpstreamSslOptions {
            verify_cert: Switch::Off,
            trusted_certificate: Some(trusted_certificate),
            ..UpstreamSslOptions::default()
        }
    );
}

#[test]
fn compiled_router_parses_proxy_ssl_client_certificate() {
    let client_cert = PemSource::Path("/etc/ssl/upstreams/client.crt".into());
    let client_key = PemSource::Path("/etc/ssl/upstreams/client.key".into());
    let http = Http {
        servers: vec![Server {
            listens: vec![Listen {
                default_server: true,
                ..Listen::default()
            }],
            locations: vec![Location {
                matcher: LocationMatcher::Prefix("/".into()),
                directives: vec![
                    LocationDirective::ProxySslCertificate(client_cert.clone()),
                    LocationDirective::ProxySslCertificateKey(client_key.clone()),
                    LocationDirective::ProxyPass(ProxyPassTarget::Url(
                        "https://127.0.0.1:8443".parse().unwrap(),
                    )),
                ],
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
        location.upstream_ssl_options.client_certificate,
        Some(client_cert)
    );
    assert_eq!(
        location.upstream_ssl_options.client_certificate_key,
        Some(client_key)
    );
}

#[test]
fn compiled_router_rejects_proxy_ssl_certificate_without_key() {
    let http = Http {
        servers: vec![Server {
            listens: vec![Listen {
                default_server: true,
                ..Listen::default()
            }],
            locations: vec![Location {
                matcher: LocationMatcher::Prefix("/".into()),
                directives: vec![
                    LocationDirective::ProxySslCertificate(PemSource::Path(
                        "/etc/ssl/upstreams/client.crt".into(),
                    )),
                    LocationDirective::ProxyPass(ProxyPassTarget::Url(
                        "https://127.0.0.1:8443".parse().unwrap(),
                    )),
                ],
                access_rules: Vec::new(),
                plugins: Vec::new(),
                cache: None,
            }],
            ..Server::default()
        }],
        ..Http::default()
    };

    let err = CompiledRouter::from_http(&http).expect_err("expected cert-without-key rejection");
    assert!(err.contains("proxy_ssl_certificate requires proxy_ssl_certificate_key"));
}

#[test]
fn compiled_router_rejects_proxy_ssl_certificate_key_without_cert() {
    let http = Http {
        servers: vec![Server {
            listens: vec![Listen {
                default_server: true,
                ..Listen::default()
            }],
            locations: vec![Location {
                matcher: LocationMatcher::Prefix("/".into()),
                directives: vec![
                    LocationDirective::ProxySslCertificateKey(PemSource::Path(
                        "/etc/ssl/upstreams/client.key".into(),
                    )),
                    LocationDirective::ProxyPass(ProxyPassTarget::Url(
                        "https://127.0.0.1:8443".parse().unwrap(),
                    )),
                ],
                access_rules: Vec::new(),
                plugins: Vec::new(),
                cache: None,
            }],
            ..Server::default()
        }],
        ..Http::default()
    };

    let err = CompiledRouter::from_http(&http).expect_err("expected key-without-cert rejection");
    assert!(err.contains("proxy_ssl_certificate_key requires proxy_ssl_certificate"));
}

#[test]
fn compiled_router_parses_proxy_upstream_protocol() {
    let http = Http {
        servers: vec![Server {
            listens: vec![Listen {
                default_server: true,
                ..Listen::default()
            }],
            locations: vec![Location {
                matcher: LocationMatcher::Prefix("/grpc".into()),
                directives: vec![
                    LocationDirective::ProxyUpstreamProtocol(UpstreamHttpProtocol::H2c),
                    LocationDirective::ProxyPass(ProxyPassTarget::Url(
                        "http://127.0.0.1:50051".parse().unwrap(),
                    )),
                ],
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

    assert_eq!(location.upstream_protocol, Some(UpstreamHttpProtocol::H2c));
}

#[test]
fn compiled_router_rejects_h2_without_tls_upstream() {
    let http = Http {
        servers: vec![Server {
            listens: vec![Listen {
                default_server: true,
                ..Listen::default()
            }],
            locations: vec![Location {
                matcher: LocationMatcher::Prefix("/grpc".into()),
                directives: vec![
                    LocationDirective::ProxyUpstreamProtocol(UpstreamHttpProtocol::H2),
                    LocationDirective::ProxyPass(ProxyPassTarget::Url(
                        "http://127.0.0.1:50051".parse().unwrap(),
                    )),
                ],
                access_rules: Vec::new(),
                plugins: Vec::new(),
                cache: None,
            }],
            ..Server::default()
        }],
        ..Http::default()
    };

    let err = CompiledRouter::from_http(&http).expect_err("expected h2/http mismatch");
    assert!(err.contains("proxy_upstream_protocol h2 requires TLS upstream"));
}

#[test]
fn compiled_router_rejects_h2c_with_tls_upstream() {
    let http = Http {
        servers: vec![Server {
            listens: vec![Listen {
                default_server: true,
                ..Listen::default()
            }],
            locations: vec![Location {
                matcher: LocationMatcher::Prefix("/grpc".into()),
                directives: vec![
                    LocationDirective::ProxyUpstreamProtocol(UpstreamHttpProtocol::H2c),
                    LocationDirective::ProxyPass(ProxyPassTarget::Url(
                        "https://127.0.0.1:50051".parse().unwrap(),
                    )),
                ],
                access_rules: Vec::new(),
                plugins: Vec::new(),
                cache: None,
            }],
            ..Server::default()
        }],
        ..Http::default()
    };

    let err = CompiledRouter::from_http(&http).expect_err("expected h2c/https mismatch");
    assert!(err.contains("proxy_upstream_protocol h2c requires plaintext upstream"));
}

#[test]
fn apply_upstream_ssl_options_disables_verification() {
    let mut peer = HttpPeer::new(("127.0.0.1", 8443), true, String::new());

    apply_upstream_ssl_options(
        &mut peer,
        &UpstreamSslOptions {
            verify_cert: Switch::Off,
            trusted_certificate: None,
            ..UpstreamSslOptions::default()
        },
        None,
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
                access_rules: Vec::new(),
                plugins: Vec::new(),
                cache: None,
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
            ..UpstreamSslOptions::default()
        },
        Some(trusted_ca),
        None,
    );

    assert!(peer.options.verify_cert);
    assert!(peer.options.verify_hostname);
    assert!(peer.options.ca.is_some());
}

#[cfg(feature = "openssl")]
const TEST_CLIENT_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----
MIIDDTCCAfWgAwIBAgIUdKGZt5gNE2+avoqPrpa66Y0RggEwDQYJKoZIhvcNAQEL
BQAwFjEUMBIGA1UEAwwLdGVzdC1jbGllbnQwHhcNMjYwNjE5MDA0OTIyWhcNMjYw
NjIwMDA0OTIyWjAWMRQwEgYDVQQDDAt0ZXN0LWNsaWVudDCCASIwDQYJKoZIhvcN
AQEBBQADggEPADCCAQoCggEBAIdHdBZd95zhLHNjKf7UgFLIDj36wPTATIS561z/
ZonGRxMtL+FKrjylzGJiej6dxkKpCxQc6zP/R9Kd1ct+Nt2svlHtDsDJGRmty4Aq
6/ZMIWL1CuXLeL394OoDuUMqxayBpwSRnXk+yidJBxeJqKqpdRiOOgpaM5IpErVS
Vf8O5DbqKT9CZ98lzl3pzRRTdg+BsuINYVcrW2CTMogZmvEF0gOXgXv6kmhmyHgR
rT0AJDhUKSZADMPTqq6+LAIxeu45x+qxJfCVPgrE3gYarSRqGACegShbE29y3Cxq
5PPLVdTGUOXL/K1fmWqW2rhpT9fthSrAZ0kD4w099Fk69c8CAwEAAaNTMFEwHQYD
VR0OBBYEFAcA73Yd5ygCwTAHyrt2PK3hbsxGMB8GA1UdIwQYMBaAFAcA73Yd5ygC
wTAHyrt2PK3hbsxGMA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEB
ADc4AidSHfy1o9mW9CPQDO/Aw/1TT9VNR57esqZRKXjVrwK+VvHyWrafLQSRIgDy
tgaOWl/MTDCCeULrNiknDqalSbJXBEI/vjcOEE2EVYQPadCzC0Jd6YDykwf9P8Ye
wnRokag0QEr3qV1DLQHSxDKTEsgsG0gWcvYDhyOUVw2YUgLYr/Q0XPOJceVinmlT
pPruQljMd3sVb9E00sr6kLlLqgZU5iDFF1aUvoYrVgY9dYXNdZhzXI2gOYFHkZx4
pn/sQAnRNSrJ6Jz0JqcuAsH5vyLX16EA0OhB5Ta96nAvplnpAkUq6iCJPtC+KAgB
Jstr72HAqISmzpFePtqDflE=
-----END CERTIFICATE-----
";

#[cfg(feature = "openssl")]
const TEST_CLIENT_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCHR3QWXfec4Sxz
Yyn+1IBSyA49+sD0wEyEuetc/2aJxkcTLS/hSq48pcxiYno+ncZCqQsUHOsz/0fS
ndXLfjbdrL5R7Q7AyRkZrcuAKuv2TCFi9Qrly3i9/eDqA7lDKsWsgacEkZ15Pson
SQcXiaiqqXUYjjoKWjOSKRK1UlX/DuQ26ik/QmffJc5d6c0UU3YPgbLiDWFXK1tg
kzKIGZrxBdIDl4F7+pJoZsh4Ea09ACQ4VCkmQAzD06quviwCMXruOcfqsSXwlT4K
xN4GGq0kahgAnoEoWxNvctwsauTzy1XUxlDly/ytX5lqltq4aU/X7YUqwGdJA+MN
PfRZOvXPAgMBAAECggEADJFo3u3FTr/kv1DxL9785QlNDsO4dYSqwedRTzHd4Y2Y
QNcr4ZnB7O8tDomTozRJR8bTY/+jzRA501QdRBXqcayA1LUExTMUWpG48aQLNAtd
TAeesZFhGwBL4FyO3lyfl31Gz7faPM9xPIvJADjRK2R+9Sm8NAYD+zTxq1gw68yL
IdA+LbUqr7Jx3deBJjlwjrrDk9wT3kTCN7amlMvnnJX/q0xLX1XHG/j9NfnanDcL
Ufss9Tft1v42K9HgweD4eKqcNnOipZRmMc1zPvxKu4qFFjBwZpgNlykt7k6aH238
AeN2pnlZAu6PqtNJbW4kmhdatd14HAyFzxnAKp4FgQKBgQC6R5aJy5+44gSmizpS
MqJgiqfuodT63/i9hjQ/v4z57KbUICCVkeGj02dDPBY93IpRzCUtPGlNMrzP8FYG
OFuC2qJXmTc2GmgitWXMIYfZP3biWt0VELYyUAl8D3OT4OB/95N1yGXEtgajnhHp
drVJ8ZK8OC35yZTeHLoVQLTULwKBgQC56T4KOIwaR7n3dXSTKsw9kSgKxtX/Ykny
AgZxz8K8+Hl/Y8KotqttX4pVGAfbGBKdUXpYiWfYI3X/A3iiFatDqUiUr1PwENsE
CCm9iBfe+SnJOY0CSnjHtE3GnPxYFIKy4z9VsZEuu4Vc5E4McZ/65vHyPahK2Dwf
VPAZU75wYQKBgB0l/JFdUoXsoAurd5nLIIt4xuRZYGlNSK/nYx+iip3FASnqSQ7+
f89R0jO8IELX0rEP/7U/Yb7ZtJ/ZHKzmfrNQIN0SNYh6w1bDCcXSbV56RtEOpM+a
CNiAm6tVA6HdK2P6ypFApWQNk6Zgoq7ki2OhsHNRWyhd+bRzzE5tDJ6zAoGBAIs3
MhINTjzPwV6hQe6CefcQn9+SDeX0AFONWK4ZWkaP+st+NOKKB80bYkdee2OBn07X
GLr8Chs8UrvoKYmWmG1Oct+Ee2Kl/JwEUN1w8A80ninlQsaYZeGGD0fPftemZEj5
CxBsq79HBRMOk7OV0qrcDgnMSh3h1wPPYwxUPaOBAoGAY4taNHE51y1+3odo+05f
1Mhdp7khfxgN9FUKRKeWLRVtRuV6DR/6/iN8meRTvy6xTJ4vzjVdZ5uv++TVkzSm
rRX/YrvfqflFs03gj35mGkWt6KBX2ckBEzgGlohOJFnt7qY+t1FrPhtjQFnJ9azA
URSca2xnSfE3tGjoFkbktp4=
-----END PRIVATE KEY-----
";

#[cfg(feature = "openssl")]
#[test]
fn apply_upstream_ssl_options_sets_client_identity() {
    let cert_source = PemSource::InlinePem(TEST_CLIENT_CERT_PEM.into());
    let key_source = PemSource::InlinePem(TEST_CLIENT_KEY_PEM.into());
    let http = Http {
        servers: vec![Server {
            listens: vec![Listen {
                default_server: true,
                ..Listen::default()
            }],
            locations: vec![Location {
                matcher: LocationMatcher::Prefix("/".into()),
                directives: vec![
                    LocationDirective::ProxySslCertificate(cert_source.clone()),
                    LocationDirective::ProxySslCertificateKey(key_source.clone()),
                    LocationDirective::ProxyPass(ProxyPassTarget::Url(
                        "https://127.0.0.1:8443".parse().unwrap(),
                    )),
                ],
                access_rules: Vec::new(),
                plugins: Vec::new(),
                cache: None,
            }],
            ..Server::default()
        }],
        ..Http::default()
    };

    let router = CompiledRouter::from_http(&http).expect("router compiles");
    let identities =
        super::build_runtime_client_identities(&router).expect("client identities build");
    let identity_key = super::ClientIdentityKey {
        cert: cert_source,
        key: key_source,
    };
    let identity = identities
        .get(&identity_key)
        .expect("client identity cached");

    let mut peer = HttpPeer::new(("127.0.0.1", 8443), true, String::new());
    apply_upstream_ssl_options(
        &mut peer,
        &UpstreamSslOptions {
            verify_cert: Switch::On,
            client_certificate: Some(identity_key.cert.clone()),
            client_certificate_key: Some(identity_key.key.clone()),
            ..UpstreamSslOptions::default()
        },
        None,
        Some(identity),
    );

    assert!(peer.client_cert_key.is_some());
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
fn compiled_router_rejects_tcp_nodelay_off() {
    let mut http = Http::default();
    http.tcp_nodelay = Switch::Off;
    http.servers.push(Server {
        listens: vec![Listen {
            default_server: true,
            ..Listen::default()
        }],
        ..Server::default()
    });

    let err = CompiledRouter::from_http(&http).expect_err("expected tcp_nodelay off rejection");
    assert!(err.contains("tcp_nodelay off is not supported"));
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

#[tokio::test]
async fn request_body_filter_ignores_upgraded_websocket_stream() {
    let (mut client, server) = duplex(1024);
    client
        .write_all(
            b"GET /ws HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\nConnection: upgrade\r\n\r\n",
        )
        .await
        .expect("write upgrade request");

    let mut session = Session::new_h1(Box::new(server));
    session.read_request().await.expect("read request");

    let mut switching_protocols =
        ResponseHeader::build(http::StatusCode::SWITCHING_PROTOCOLS, None)
            .expect("build 101 response");
    switching_protocols.set_version(http::Version::HTTP_11);
    session
        .write_response_header(Box::new(switching_protocols), false)
        .await
        .expect("write 101 response");
    assert!(session.was_upgraded());

    let proxy = super::DynamicProxy::from_router(CompiledRouter::default());
    let mut ctx = super::ProxyContext {
        client_max_body_size: Some(1),
        ..Default::default()
    };
    let mut body = Some(Bytes::from_static(b"hello"));

    ProxyHttp::request_body_filter(&proxy, &mut session, &mut body, false, &mut ctx)
        .await
        .expect("upgraded body should bypass http body limits");

    assert_eq!(body, Some(Bytes::from_static(b"hello")));
    assert_eq!(ctx.received_body_bytes, 0);
}

#[test]
fn compiled_router_preserves_location_access_rules() {
    let allow = "10.0.0.0/8".parse::<IpNet>().expect("test network");
    let deny = "192.0.2.1/32"
        .parse::<IpNet>()
        .expect("192.0.2.1/32 is valid");

    let http = Http {
        servers: vec![Server {
            listens: vec![Listen {
                default_server: true,
                ..Listen::default()
            }],
            locations: vec![Location {
                matcher: LocationMatcher::Prefix("/".into()),
                access_rules: vec![LocationIpRule::Deny(deny), LocationIpRule::Allow(allow)],
                directives: vec![LocationDirective::ProxyPass(ProxyPassTarget::Url(
                    "http://127.0.0.1:8080".parse().unwrap(),
                ))],
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
        location.access_rules,
        vec![LocationIpRule::Deny(deny), LocationIpRule::Allow(allow)]
    );
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
                directives: vec![LocationDirective::ProxyPass(ProxyPassTarget::Url(
                    "http://127.0.0.1:8080".parse().unwrap(),
                ))],
                access_rules: Vec::new(),
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

#[test]
fn apply_upstream_http_protocol_sets_peer_http_version() {
    let mut peer = HttpPeer::new(("127.0.0.1", 50051), true, String::new());

    apply_upstream_http_protocol(&mut peer, Some(UpstreamHttpProtocol::H2));
    assert_eq!(peer.options.alpn.get_min_http_version(), 2);
    assert_eq!(peer.options.alpn.get_max_http_version(), 2);

    apply_upstream_http_protocol(&mut peer, Some(UpstreamHttpProtocol::H1));
    assert_eq!(peer.options.alpn.get_min_http_version(), 1);
    assert_eq!(peer.options.alpn.get_max_http_version(), 1);
}
