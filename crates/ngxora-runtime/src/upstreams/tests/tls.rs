//! Upstream trust, client identities and protocol validation.

use crate::upstreams::{CompiledRouter, apply_upstream_ssl_options};
use ngxora_compile::ir::{
    Http, Listen, Location, LocationDirective, LocationMatcher, PemSource, ProxyPassTarget, Server,
    SslProvider, Switch, UpstreamHttpProtocol, UpstreamSslOptions,
};
use pingora::upstreams::peer::HttpPeer;

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
    let trusted_cas =
        crate::upstreams::build_runtime_trusted_cas(&router).expect("trusted ca builds");
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
    let identities = crate::upstreams::build_runtime_client_identities(&router)
        .expect("client identities build");
    let identity_key = crate::upstreams::ClientIdentityKey {
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
