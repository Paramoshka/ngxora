//! Round-trip and rejection tests for upstream client identities.

use super::{MTLS_CLIENT_CERT_PEM, MTLS_CLIENT_KEY_PEM};
use crate::grpc::{proto, proto_snapshot_from_runtime, runtime_snapshot_from_proto};
use crate::upstreams::ListenKey;
use ngxora_compile::ir::PemSource;
use std::net::{IpAddr, Ipv4Addr};

#[test]
fn proto_snapshot_roundtrips_upstream_client_certificate() {
    const CLIENT_CERT_PATH: &str = "/etc/ngxora/upstreams/client.crt";
    const CLIENT_KEY_PATH: &str = "/etc/ngxora/upstreams/client.key";

    let snapshot = proto::ConfigSnapshot {
        version: "mtls-v1".into(),
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
                    scheme: "https".into(),
                    host: "127.0.0.1".into(),
                    port: 8443,
                    upstream_group: String::new(),
                })),
                timeouts: None,
                cache: None,
                plugins: Vec::new(),
                tls_options: Some(proto::UpstreamTlsOptions {
                    verify: proto::Switch::On as i32,
                    trusted_certificate: None,
                    client_certificate: Some(proto::PemSource {
                        source: Some(proto::pem_source::Source::Path(CLIENT_CERT_PATH.into())),
                    }),
                    client_certificate_key: Some(proto::PemSource {
                        source: Some(proto::pem_source::Source::Path(CLIENT_KEY_PATH.into())),
                    }),
                }),
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
        .expect("route exists");

    assert_eq!(
        route.upstream_ssl_options.client_certificate,
        Some(PemSource::Path(CLIENT_CERT_PATH.into()))
    );
    assert_eq!(
        route.upstream_ssl_options.client_certificate_key,
        Some(PemSource::Path(CLIENT_KEY_PATH.into()))
    );
}

#[test]
fn proto_snapshot_rejects_client_cert_without_key() {
    const CLIENT_CERT_PATH: &str = "/etc/ngxora/upstreams/client.crt";

    let snapshot = proto::ConfigSnapshot {
        version: "mtls-broken".into(),
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
                    scheme: "https".into(),
                    host: "127.0.0.1".into(),
                    port: 8443,
                    upstream_group: String::new(),
                })),
                timeouts: None,
                cache: None,
                plugins: Vec::new(),
                tls_options: Some(proto::UpstreamTlsOptions {
                    verify: proto::Switch::On as i32,
                    trusted_certificate: None,
                    client_certificate: Some(proto::PemSource {
                        source: Some(proto::pem_source::Source::Path(CLIENT_CERT_PATH.into())),
                    }),
                    client_certificate_key: None,
                }),
                upstream_protocol: proto::UpstreamHttpProtocol::Unspecified as i32,
            }],
        }],
        le_config: None,
    };

    let err =
        runtime_snapshot_from_proto(snapshot).expect_err("expected cert-without-key rejection");
    assert!(err.contains("client_certificate requires client_certificate_key"));
}

#[test]
fn proto_upstream_tls_options_roundtrips_client_certificate() {
    use crate::control::{ConfigSnapshot, RuntimeState};

    let cert_pem = MTLS_CLIENT_CERT_PEM.to_string();
    let key_pem = MTLS_CLIENT_KEY_PEM.to_string();

    let snapshot = proto::ConfigSnapshot {
        version: "v-mtls".into(),
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
                    scheme: "https".into(),
                    host: "127.0.0.1".into(),
                    port: 8443,
                    upstream_group: String::new(),
                })),
                timeouts: None,
                cache: None,
                plugins: Vec::new(),
                tls_options: Some(proto::UpstreamTlsOptions {
                    verify: proto::Switch::On as i32,
                    trusted_certificate: None,
                    client_certificate: Some(proto::PemSource {
                        source: Some(proto::pem_source::Source::InlinePem(cert_pem.clone())),
                    }),
                    client_certificate_key: Some(proto::PemSource {
                        source: Some(proto::pem_source::Source::InlinePem(key_pem.clone())),
                    }),
                }),
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
        .expect("route exists");

    assert_eq!(
        route.upstream_ssl_options.client_certificate,
        Some(PemSource::InlinePem(cert_pem.clone()))
    );
    assert_eq!(
        route.upstream_ssl_options.client_certificate_key,
        Some(PemSource::InlinePem(key_pem.clone()))
    );

    // Round-trip back to proto via the runtime snapshot path.
    let router = runtime.router.clone();
    let state = RuntimeState::new(ConfigSnapshot::new("v-mtls", router));
    let snap = state.snapshot();
    let proto = proto_snapshot_from_runtime(snap.as_ref()).expect("serializes");
    let tls_opts = proto.virtual_hosts[0].routes[0]
        .tls_options
        .as_ref()
        .expect("tls options present");
    let cert_src = tls_opts
        .client_certificate
        .as_ref()
        .and_then(|s| s.source.as_ref())
        .expect("client_certificate present");
    let key_src = tls_opts
        .client_certificate_key
        .as_ref()
        .and_then(|s| s.source.as_ref())
        .expect("client_certificate_key present");
    assert!(
        matches!(cert_src, proto::pem_source::Source::InlinePem(p) if p == &cert_pem),
        "cert inline roundtrips"
    );
    assert!(
        matches!(key_src, proto::pem_source::Source::InlinePem(p) if p == &key_pem),
        "key inline roundtrips"
    );
}

#[test]
fn proto_rejects_client_certificate_without_key() {
    let snapshot = proto::ConfigSnapshot {
        version: "v-bad".into(),
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
                    scheme: "https".into(),
                    host: "127.0.0.1".into(),
                    port: 8443,
                    upstream_group: String::new(),
                })),
                timeouts: None,
                cache: None,
                plugins: Vec::new(),
                tls_options: Some(proto::UpstreamTlsOptions {
                    verify: proto::Switch::On as i32,
                    trusted_certificate: None,
                    client_certificate: Some(proto::PemSource {
                        source: Some(proto::pem_source::Source::Path(
                            "/etc/ngxora/upstreams/client.crt".into(),
                        )),
                    }),
                    client_certificate_key: None,
                }),
                upstream_protocol: proto::UpstreamHttpProtocol::Unspecified as i32,
            }],
        }],
        le_config: None,
    };

    let err = runtime_snapshot_from_proto(snapshot).expect_err("expected rejection");
    assert!(err.contains("client_certificate requires client_certificate_key"));
}
