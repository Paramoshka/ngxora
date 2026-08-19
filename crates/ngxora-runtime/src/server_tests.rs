#[cfg(feature = "openssl")]
use super::openssl_listener_tls::SniCertResolver;
use super::{
    default_listener_tls, listener_addr, listener_has_multiple_identities, select_listener_tls,
};
#[cfg(feature = "openssl")]
use crate::control::RuntimeState;
use crate::upstreams::{CompiledRouter, ListenKey, ListenerTlsConfig};
use ngxora_compile::ir::{Http, Listen, PemSource, Server, SslProvider, TlsIdentity};
#[cfg(feature = "openssl")]
use openssl::asn1::Asn1Time;
#[cfg(feature = "openssl")]
use openssl::bn::BigNum;
#[cfg(feature = "openssl")]
use openssl::ec::{EcGroup, EcKey};
#[cfg(feature = "openssl")]
use openssl::hash::MessageDigest;
#[cfg(feature = "openssl")]
use openssl::nid::Nid;
#[cfg(feature = "openssl")]
use openssl::pkey::PKey;
#[cfg(feature = "openssl")]
use openssl::ssl::{Ssl, SslConnector, SslContextBuilder, SslMethod, SslStream, SslVerifyMode};
#[cfg(feature = "openssl")]
use openssl::x509::{X509, X509NameBuilder};
use std::collections::HashMap;
#[cfg(feature = "openssl")]
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
#[cfg(feature = "openssl")]
use std::net::{TcpListener, TcpStream};
use std::path::PathBuf;
#[cfg(feature = "openssl")]
use std::sync::Arc;
#[cfg(feature = "openssl")]
use std::thread;

fn tls_identity(cert: &str, key: &str) -> TlsIdentity {
    TlsIdentity {
        cert: PemSource::Path(PathBuf::from(cert)),
        key: PemSource::Path(PathBuf::from(key)),
    }
}

fn tls_listener(port: u16, default_server: bool) -> Listen {
    Listen {
        addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        port,
        ssl: true,
        default_server,
        ..Listen::default()
    }
}

#[cfg(feature = "openssl")]
fn write_self_signed_certificate(
    cert_path: &std::path::Path,
    key_path: &std::path::Path,
    serial: u32,
) {
    let group = EcGroup::from_curve_name(Nid::X9_62_PRIME256V1).expect("create EC group");
    let key = PKey::from_ec_key(EcKey::generate(&group).expect("generate EC key"))
        .expect("create private key");

    let mut name = X509NameBuilder::new().expect("create X509 name");
    name.append_entry_by_text("CN", "example.com")
        .expect("set common name");
    let name = name.build();

    let mut cert = X509::builder().expect("create X509 builder");
    cert.set_version(2).expect("set certificate version");
    let serial = BigNum::from_u32(serial)
        .expect("create serial")
        .to_asn1_integer()
        .expect("convert serial");
    cert.set_serial_number(&serial).expect("set serial");
    cert.set_subject_name(&name).expect("set subject");
    cert.set_issuer_name(&name).expect("set issuer");
    cert.set_pubkey(&key).expect("set public key");
    let not_before = Asn1Time::days_from_now(0).expect("set not-before time");
    let not_after = Asn1Time::days_from_now(1).expect("set not-after time");
    cert.set_not_before(&not_before).expect("set not-before");
    cert.set_not_after(&not_after).expect("set not-after");
    cert.sign(&key, MessageDigest::sha256())
        .expect("sign certificate");

    fs::write(
        cert_path,
        cert.build().to_pem().expect("encode certificate"),
    )
    .expect("write certificate");
    fs::write(
        key_path,
        key.private_key_to_pem_pkcs8().expect("encode private key"),
    )
    .expect("write private key");
}

#[cfg(feature = "openssl")]
#[test]
fn sni_cache_reloads_certificate_after_tls_material_invalidation() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let cert_path = dir.path().join("fullchain.pem");
    let key_path = dir.path().join("privkey.pem");
    write_self_signed_certificate(&cert_path, &key_path, 1);

    let listen_key = ListenKey {
        addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 443,
        ssl: true,
    };
    let identity = TlsIdentity {
        cert: PemSource::Path(cert_path.clone()),
        key: PemSource::Path(key_path.clone()),
    };
    let router = CompiledRouter {
        listener_tls: HashMap::from([(
            listen_key.clone(),
            ListenerTlsConfig {
                named: HashMap::from([("example.com".into(), identity.clone())]),
                default: Some(identity),
                ..ListenerTlsConfig::default()
            },
        )]),
        ..CompiledRouter::default()
    };
    let state = Arc::new(RuntimeState::bootstrap(router));
    let resolver = SniCertResolver::new(Arc::clone(&state), listen_key);

    let first = resolver
        .selected_cert_der_for_test(Some("example.com"))
        .expect("load first certificate");
    write_self_signed_certificate(&cert_path, &key_path, 2);

    let cached = resolver
        .selected_cert_der_for_test(Some("example.com"))
        .expect("load cached certificate");
    assert_eq!(cached, first);

    state.invalidate_tls_material();

    let renewed = resolver
        .selected_cert_der_for_test(Some("example.com"))
        .expect("load renewed certificate");
    assert_ne!(renewed, first);
}

#[cfg(feature = "openssl")]
#[test]
fn sni_resolver_sends_full_certificate_chain() {
    let dir = tempfile::tempdir().expect("create temp dir");
    let cert_path = dir.path().join("fullchain.pem");
    let key_path = dir.path().join("privkey.pem");
    let intermediate_cert_path = dir.path().join("intermediate.pem");
    let intermediate_key_path = dir.path().join("intermediate-key.pem");

    write_self_signed_certificate(&cert_path, &key_path, 1);
    write_self_signed_certificate(&intermediate_cert_path, &intermediate_key_path, 2);

    let mut fullchain = fs::read(&cert_path).expect("read leaf certificate");
    fullchain.extend_from_slice(
        &fs::read(&intermediate_cert_path).expect("read intermediate certificate"),
    );
    fs::write(&cert_path, fullchain).expect("write certificate chain");

    let listen_key = ListenKey {
        addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 443,
        ssl: true,
    };
    let identity = TlsIdentity {
        cert: PemSource::Path(cert_path),
        key: PemSource::Path(key_path),
    };
    let router = CompiledRouter {
        listener_tls: HashMap::from([(
            listen_key.clone(),
            ListenerTlsConfig {
                named: HashMap::from([("example.com".into(), identity.clone())]),
                default: Some(identity),
                ..ListenerTlsConfig::default()
            },
        )]),
        ..CompiledRouter::default()
    };
    let state = Arc::new(RuntimeState::bootstrap(router));
    let resolver = SniCertResolver::new(state, listen_key);

    let context = SslContextBuilder::new(SslMethod::tls_server())
        .expect("create server TLS context")
        .build();
    let mut ssl = Ssl::new(&context).expect("create server TLS session");
    resolver
        .install_selected_identity_for_test(&mut ssl, Some("example.com"))
        .expect("install server identity");

    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("bind test listener");
    let addr = listener.local_addr().expect("get test listener address");
    let server = thread::spawn(move || {
        let (stream, _) = listener.accept().expect("accept test connection");
        let mut stream = SslStream::new(ssl, stream).expect("create server TLS stream");
        stream.accept().expect("accept TLS handshake");
    });

    let mut connector =
        SslConnector::builder(SslMethod::tls_client()).expect("create client TLS connector");
    connector.set_verify(SslVerifyMode::NONE);
    let stream = TcpStream::connect(addr).expect("connect to test listener");
    let stream = connector
        .build()
        .connect("example.com", stream)
        .expect("connect TLS client");

    let peer_chain = stream
        .ssl()
        .peer_cert_chain()
        .expect("server should send a certificate chain");
    assert_eq!(peer_chain.len(), 2);

    server.join().expect("join test server");
}

#[test]
fn compiled_router_deduplicates_shared_tls_listener() {
    let shared_tls = tls_identity("/tmp/shared.crt", "/tmp/shared.key");
    let http = Http {
        servers: vec![
            Server {
                server_names: vec!["example.com".into()],
                listens: vec![tls_listener(443, true)],
                tls: Some(SslProvider::Custom(shared_tls.clone())),
                ..Server::default()
            },
            Server {
                server_names: vec!["www.example.com".into()],
                listens: vec![tls_listener(443, false)],
                tls: Some(SslProvider::Custom(shared_tls)),
                ..Server::default()
            },
        ],
        ..Http::default()
    };

    let router = CompiledRouter::from_http(&http).expect("router compiles");
    let listen_key = ListenKey {
        addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        port: 443,
        ssl: true,
    };

    assert_eq!(router.listeners.len(), 1);

    let tls = router
        .listener_tls
        .get(&listen_key)
        .expect("tls config missing");
    assert_eq!(
        tls.named.get("example.com"),
        Some(&tls_identity("/tmp/shared.crt", "/tmp/shared.key"))
    );
    assert_eq!(
        tls.named.get("www.example.com"),
        Some(&tls_identity("/tmp/shared.crt", "/tmp/shared.key"))
    );
    assert_eq!(
        tls.default.as_ref(),
        Some(&tls_identity("/tmp/shared.crt", "/tmp/shared.key"))
    );
}

#[test]
fn compiled_router_rejects_conflicting_shared_listener_protocols() {
    let http = Http {
        servers: vec![
            Server {
                server_names: vec!["example.com".into()],
                listens: vec![Listen {
                    http2: true,
                    ..tls_listener(443, true)
                }],
                tls: Some(SslProvider::Custom(tls_identity(
                    "/tmp/example.crt",
                    "/tmp/example.key",
                ))),
                ..Server::default()
            },
            Server {
                server_names: vec!["www.example.com".into()],
                listens: vec![tls_listener(443, false)],
                tls: Some(SslProvider::Custom(tls_identity(
                    "/tmp/example.crt",
                    "/tmp/example.key",
                ))),
                ..Server::default()
            },
        ],
        ..Http::default()
    };

    let err = CompiledRouter::from_http(&http).expect_err("expected listener conflict");
    assert!(err.contains("conflicting protocol settings"));
}

#[test]
fn select_listener_tls_prefers_named_sni() {
    let key = ListenKey {
        addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 443,
        ssl: true,
    };
    let tls = ListenerTlsConfig {
        named: HashMap::from([(
            "example.com".into(),
            tls_identity("/tmp/example.crt", "/tmp/example.key"),
        )]),
        default: Some(tls_identity("/tmp/default.crt", "/tmp/default.key")),
        ..ListenerTlsConfig::default()
    };

    let resolved =
        select_listener_tls(&key, &tls, Some("EXAMPLE.com")).expect("expected named identity");
    assert_eq!(
        resolved,
        &tls_identity("/tmp/example.crt", "/tmp/example.key")
    );
}

#[test]
fn select_listener_tls_falls_back_to_default() {
    let key = ListenKey {
        addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 443,
        ssl: true,
    };
    let tls = ListenerTlsConfig {
        named: HashMap::from([(
            "example.com".into(),
            tls_identity("/tmp/example.crt", "/tmp/example.key"),
        )]),
        default: Some(tls_identity("/tmp/default.crt", "/tmp/default.key")),
        ..ListenerTlsConfig::default()
    };

    let resolved =
        select_listener_tls(&key, &tls, Some("missing.example.com")).expect("expected default");
    assert_eq!(
        resolved,
        &tls_identity("/tmp/default.crt", "/tmp/default.key")
    );
}

#[test]
fn default_listener_tls_uses_first_named_when_default_missing() {
    let key = ListenKey {
        addr: IpAddr::V4(Ipv4Addr::LOCALHOST),
        port: 443,
        ssl: true,
    };
    let named_only = tls_identity("/tmp/example.crt", "/tmp/example.key");
    let tls = ListenerTlsConfig {
        named: HashMap::from([("example.com".into(), named_only.clone())]),
        default: None,
        ..ListenerTlsConfig::default()
    };

    let resolved = default_listener_tls(&key, &tls).expect("expected named fallback");
    assert_eq!(resolved, &named_only);
}

#[test]
fn listener_has_multiple_identities_detects_conflict() {
    let tls = ListenerTlsConfig {
        named: HashMap::from([
            (
                "example.com".into(),
                tls_identity("/tmp/example.crt", "/tmp/example.key"),
            ),
            (
                "other.example.com".into(),
                tls_identity("/tmp/other.crt", "/tmp/other.key"),
            ),
        ]),
        default: Some(tls_identity("/tmp/default.crt", "/tmp/default.key")),
        ..ListenerTlsConfig::default()
    };

    assert!(listener_has_multiple_identities(&tls));
}

#[test]
fn listener_addr_formats_ipv6() {
    let key = ListenKey {
        addr: IpAddr::V6(Ipv6Addr::LOCALHOST),
        port: 8443,
        ssl: true,
    };

    assert_eq!(listener_addr(&key), "[::1]:8443");
}
