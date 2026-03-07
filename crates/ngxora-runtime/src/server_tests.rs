use super::{
    default_listener_tls, listener_addr, listener_has_multiple_identities, select_listener_tls,
};
use crate::upstreams::{CompiledRouter, ListenKey, ListenerTlsConfig};
use ngxora_compile::ir::{Http, Listen, PemSource, Server, TlsIdentity};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

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
    }
}

#[test]
fn compiled_router_deduplicates_shared_tls_listener() {
    let shared_tls = tls_identity("/tmp/shared.crt", "/tmp/shared.key");
    let http = Http {
        servers: vec![
            Server {
                server_names: vec!["example.com".into()],
                listens: vec![tls_listener(443, true)],
                tls: Some(shared_tls.clone()),
                ..Server::default()
            },
            Server {
                server_names: vec!["www.example.com".into()],
                listens: vec![tls_listener(443, false)],
                tls: Some(shared_tls),
                ..Server::default()
            },
        ],
        ..Http::default()
    };

    let router = CompiledRouter::from_http(&http);
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
    };

    let resolved =
        select_listener_tls(&key, &tls, Some("EXAMPLE.com")).expect("expected named identity");
    assert_eq!(resolved, &tls_identity("/tmp/example.crt", "/tmp/example.key"));
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
    };

    let resolved =
        select_listener_tls(&key, &tls, Some("missing.example.com")).expect("expected default");
    assert_eq!(resolved, &tls_identity("/tmp/default.crt", "/tmp/default.key"));
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
