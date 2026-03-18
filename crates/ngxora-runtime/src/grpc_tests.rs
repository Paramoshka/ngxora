use super::{proto, proto_snapshot_from_runtime, runtime_snapshot_from_proto};
use crate::control::{ConfigSnapshot, RuntimeState};
use crate::upstreams::{CompiledMatcher, CompiledRouter, ListenKey, RouteTarget};
use ngxora_compile::ir::{
    Http, KeepaliveTimeout, Listen, Location, LocationDirective, LocationMatcher, PemSource,
    ProxyPassTarget, Server, Switch, TlsIdentity, UpstreamBlock, UpstreamHealthCheck,
    UpstreamHealthCheckType, UpstreamSelectionPolicy, UpstreamServer,
};
use ngxora_plugin_api::PluginSpec;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

const TRUSTED_UPSTREAM_CA_PATH: &str = "/etc/ngxora/upstreams/ca.pem";
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
            client_max_body_size_bytes: 8 * 1024 * 1024,
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
            name: "backend-pool".into(),
            backends: vec![
                proto::UpstreamBackend {
                    host: "backend-1.internal".into(),
                    port: 8080,
                },
                proto::UpstreamBackend {
                    host: "backend-2.internal".into(),
                    port: 8081,
                },
            ],
            policy: proto::UpstreamSelectionPolicy::Random as i32,
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
                    scheme: "http".into(),
                    host: String::new(),
                    port: 0,
                    upstream_group: "backend-pool".into(),
                }),
                timeouts: Some(proto::RouteTimeouts {
                    connect_timeout_ms: 1_000,
                    read_timeout_ms: 2_000,
                    write_timeout_ms: 3_000,
                }),
                tls_options: Some(proto::UpstreamTlsOptions {
                    verify: proto::Switch::Off as i32,
                    trusted_certificate: Some(proto::PemSource {
                        source: Some(proto::pem_source::Source::Path(
                            TRUSTED_UPSTREAM_CA_PATH.into(),
                        )),
                    }),
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
    assert_eq!(route.upstream_ssl_options.verify_cert, Switch::Off);
    assert_eq!(
        route.upstream_ssl_options.trusted_certificate,
        Some(PemSource::Path(TRUSTED_UPSTREAM_CA_PATH.into()))
    );
    assert_eq!(route.plugins.len(), 1);
    assert_eq!(route.plugins[0].name, "headers");
    assert_eq!(
        runtime.router.upstreams["backend-pool"].policy,
        UpstreamSelectionPolicy::Random
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
        vhost.routes[0]
            .upstream
            .as_ref()
            .expect("upstream")
            .upstream_group,
        "backend-pool"
    );
    assert_eq!(proto.upstreams.len(), 1);
    assert_eq!(proto.upstreams[0].backends.len(), 2);
    assert_eq!(
        proto.upstreams[0].policy,
        proto::UpstreamSelectionPolicy::RoundRobin as i32
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

fn test_route_plugins() -> Vec<PluginSpec> {
    #[cfg(feature = "plugin-headers")]
    {
        return vec![PluginSpec {
            name: "headers".into(),
            config: serde_json::json!({"response":{"add":[["x-proxy","ngxora"]]}}),
        }];
    }

    #[cfg(not(feature = "plugin-headers"))]
    {
        Vec::new()
    }
}

fn router_with_tls_and_plugin() -> CompiledRouter {
    let http = Http {
        upstreams: vec![UpstreamBlock {
            name: "backend-pool".into(),
            policy: UpstreamSelectionPolicy::RoundRobin,
            servers: vec![
                UpstreamServer {
                    host: "backend-1.internal".into(),
                    port: 8443,
                },
                UpstreamServer {
                    host: "backend-2.internal".into(),
                    port: 9443,
                },
            ],
            health_check: Some(UpstreamHealthCheck {
                check_type: UpstreamHealthCheckType::Tcp,
                timeout: Duration::from_secs(1),
                interval: Duration::from_secs(5),
                consecutive_success: 1,
                consecutive_failure: 2,
            }),
        }],
        servers: vec![Server {
            server_names: vec!["example.com".into()],
            locations: vec![Location {
                matcher: LocationMatcher::Prefix("/".into()),
                directives: vec![
                    LocationDirective::ProxyConnectTimeout(Duration::from_secs(1)),
                    LocationDirective::ProxyReadTimeout(Duration::from_secs(2)),
                    LocationDirective::ProxyWriteTimeout(Duration::from_secs(3)),
                    LocationDirective::ProxySslVerify(Switch::Off),
                    LocationDirective::ProxySslTrustedCertificate(PemSource::InlinePem(
                        TEST_CA_PEM.into(),
                    )),
                    LocationDirective::ProxyPass(ProxyPassTarget::UpstreamGroup {
                        name: "backend-pool".into(),
                        tls: true,
                    }),
                ],
                plugins: test_route_plugins(),
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
        client_max_body_size: Some(16 * 1024 * 1024),
        tcp_nodelay: Switch::On,
        allow_connect_method_proxying: Switch::Off,
        h2c: Switch::Off,
    };

    CompiledRouter::from_http(&http).expect("router compiles")
}
