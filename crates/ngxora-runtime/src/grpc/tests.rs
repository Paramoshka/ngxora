//! Shared snapshot fixtures and control-plane regression suites.

use crate::upstreams::CompiledRouter;
use ngxora_compile::ir::{
    Http, KeepaliveTimeout, Listen, Location, LocationDirective, LocationMatcher, PemSource,
    ProxyPassTarget, Server, SslProvider, Switch, TlsIdentity, UpstreamBlock, UpstreamHashKey,
    UpstreamHealthCheck, UpstreamHealthCheckType, UpstreamHttpProtocol, UpstreamSelectionPolicy,
    UpstreamServer,
};
use ngxora_plugin_api::PluginSpec;
use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

mod discovery;
mod snapshots;
mod tls;
mod transport;

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

const MTLS_CLIENT_CERT_PEM: &str = r#"-----BEGIN CERTIFICATE-----
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
"#;

const MTLS_CLIENT_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
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
"#;

fn test_route_plugins() -> Vec<PluginSpec> {
    #[cfg(feature = "plugin-headers")]
    {
        vec![PluginSpec {
            name: "headers".into(),
            config: serde_json::json!({"response":{"add":[["x-proxy","ngxora"]]}}),
        }]
    }

    #[cfg(not(feature = "plugin-headers"))]
    {
        Vec::new()
    }
}

fn router_with_tls_and_plugin() -> CompiledRouter {
    let http = Http {
        scp_profiles: Vec::new(),
        upstreams: vec![UpstreamBlock {
            allow_empty: false,
            nrf_discovery: None,
            name: "backend-pool".into(),
            policy: UpstreamSelectionPolicy::ConsistentHash,
            hash_key: Some(UpstreamHashKey::Header("X-Tenant-ID".into())),
            servers: vec![
                UpstreamServer {
                    host: "backend-1.internal".into(),
                    port: 8443,
                    weight: 3,
                },
                UpstreamServer {
                    host: "backend-2.internal".into(),
                    port: 9443,
                    weight: 1,
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
                    LocationDirective::ProxyUpstreamProtocol(UpstreamHttpProtocol::H2),
                    LocationDirective::ProxyPass(ProxyPassTarget::UpstreamGroup {
                        name: "backend-pool".into(),
                        tls: true,
                    }),
                ],
                access_rules: Vec::new(),
                plugins: test_route_plugins(),
                cache: Some(ngxora_compile::ir::CacheConfig {
                    enabled: true,
                    max_size: Some(256 * 1024),
                    ttl: Some(Duration::from_secs(5 * 60)),
                    stale_if_error: Some(Duration::from_secs(30)),
                    cache_key: ngxora_compile::ir::CacheKeyMode::NormalizedUri,
                    min_uses: Some(2),
                    valid_statuses: vec![200, 301, 302],
                }),
            }],
            listens: vec![Listen {
                addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                port: 443,
                ssl: true,
                default_server: true,
                http2: true,
                http2_only: false,
            }],
            tls: Some(SslProvider::Custom(TlsIdentity {
                cert: PemSource::Path("/etc/ngxora/tls/example.crt".into()),
                key: PemSource::Path("/etc/ngxora/tls/example.key".into()),
            })),
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
        http2: Default::default(),
        proxy_cache_max_size: None,
        ssl_provider: None,
    };

    CompiledRouter::from_http(&http).expect("router compiles")
}
