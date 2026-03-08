use crate::control::RuntimeState;
use crate::upstreams::{
    CompiledRouter, ListenKey, ListenerProtocolConfig, ListenerTlsConfig, ListenerTlsSettings,
};
use ngxora_compile::ir::{PemSource, TlsIdentity, TlsProtocolVersion, TlsVerifyClient};
use pingora::apps::HttpServerOptions;
use pingora::listeners::ALPN;
use pingora::listeners::tls::TlsSettings;
use pingora::services::listening::Service;
use pingora::Result;
use pingora::tls::ssl::{SslVerifyMode, SslVersion};
use pingora_proxy::{HttpProxy, ProxyHttp};
use std::net::SocketAddr;
use std::sync::Arc;

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;

#[derive(Debug, Clone)]
pub(crate) struct DownstreamTlsInfo {
    pub(crate) sni: Option<String>,
}

#[cfg(feature = "openssl")]
mod openssl_listener_tls {
    use super::{
        DownstreamTlsInfo, ListenKey, RuntimeState, listener_addr, pem_source_path,
        select_listener_tls,
    };
    use async_trait::async_trait;
    use ngxora_compile::ir::TlsIdentity;
    use pingora::listeners::TlsAccept;
    use pingora::protocols::tls::TlsRef;
    use pingora::tls::ext;
    use pingora::tls::pkey::{PKey, Private};
    use pingora::tls::ssl::{NameType, SslRef};
    use pingora::tls::x509::X509;
    use pingora::Result;
    use std::any::Any;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex};

    #[derive(Debug, Clone, Eq, PartialEq, Hash)]
    struct LoadedIdentityKey {
        cert_path: String,
        key_path: String,
    }

    struct LoadedTlsIdentity {
        cert: X509,
        key: PKey<Private>,
    }

    impl LoadedTlsIdentity {
        fn load_paths(key: &ListenKey, cert_path: &str, key_path: &str) -> Result<Self> {
            let cert_bytes = std::fs::read(cert_path).map_err(|err| {
                pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    format!(
                        "failed to read ssl certificate for listener {} from {}: {err}",
                        listener_addr(key),
                        cert_path
                    ),
                )
            })?;
            let cert = X509::from_pem(&cert_bytes).map_err(|err| {
                pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    format!(
                        "failed to parse ssl certificate for listener {} from {}: {err}",
                        listener_addr(key),
                        cert_path
                    ),
                )
            })?;

            let key_bytes = std::fs::read(key_path).map_err(|err| {
                pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    format!(
                        "failed to read ssl private key for listener {} from {}: {err}",
                        listener_addr(key),
                        key_path
                    ),
                )
            })?;
            let key = PKey::private_key_from_pem(&key_bytes).map_err(|err| {
                pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    format!(
                        "failed to parse ssl private key for listener {} from {}: {err}",
                        listener_addr(key),
                        key_path
                    ),
                )
            })?;

            Ok(Self { cert, key })
        }
    }

    #[derive(Default)]
    struct LoadedTlsIdentityCache {
        generation: u64,
        identities: HashMap<LoadedIdentityKey, Arc<LoadedTlsIdentity>>,
    }

    pub(super) struct SniCertResolver {
        state: Arc<RuntimeState>,
        listen_key: ListenKey,
        cache: Mutex<LoadedTlsIdentityCache>,
    }

    impl SniCertResolver {
        pub(super) fn new(state: Arc<RuntimeState>, listen_key: ListenKey) -> Box<Self> {
            Box::new(Self {
                state,
                listen_key,
                cache: Mutex::new(LoadedTlsIdentityCache::default()),
            })
        }

        fn select(&self, server_name: Option<&str>) -> Result<Arc<LoadedTlsIdentity>> {
            let snapshot = self.state.snapshot();
            let tls = snapshot
                .router
                .listener_tls
                .get(&self.listen_key)
                .ok_or_else(|| {
                    pingora::Error::explain(
                        pingora::ErrorType::InternalError,
                        format!(
                            "ssl listener {} is missing certificate configuration",
                            listener_addr(&self.listen_key)
                        ),
                    )
                })?;
            let identity = select_listener_tls(&self.listen_key, tls, server_name)?;
            self.load_cached(snapshot.generation, identity)
        }

        fn load_cached(&self, generation: u64, identity: &TlsIdentity) -> Result<Arc<LoadedTlsIdentity>> {
            let key = LoadedIdentityKey {
                cert_path: pem_source_path(&identity.cert, "ssl certificate")?.to_owned(),
                key_path: pem_source_path(&identity.key, "ssl certificate key")?.to_owned(),
            };

            let mut cache = self.cache.lock().expect("tls cache poisoned");
            if cache.generation != generation {
                cache.generation = generation;
                cache.identities.clear();
            }

            if let Some(loaded) = cache.identities.get(&key) {
                return Ok(Arc::clone(loaded));
            }

            let loaded = Arc::new(LoadedTlsIdentity::load_paths(
                &self.listen_key,
                &key.cert_path,
                &key.key_path,
            )?);
            cache.identities.insert(key, Arc::clone(&loaded));
            Ok(loaded)
        }
    }

    #[async_trait]
    impl TlsAccept for SniCertResolver {
        async fn certificate_callback(&self, ssl: &mut SslRef) {
            let result = self.select(ssl.servername(NameType::HOST_NAME)).and_then(|identity| {
                ext::ssl_use_certificate(ssl, &identity.cert).map_err(|err| {
                    pingora::Error::explain(
                        pingora::ErrorType::InternalError,
                        format!(
                            "failed to install ssl certificate for listener {}: {err}",
                            listener_addr(&self.listen_key)
                        ),
                    )
                })?;
                ext::ssl_use_private_key(ssl, &identity.key).map_err(|err| {
                    pingora::Error::explain(
                        pingora::ErrorType::InternalError,
                        format!(
                            "failed to install ssl private key for listener {}: {err}",
                            listener_addr(&self.listen_key)
                        ),
                    )
                })?;
                Ok(())
            });

            if let Err(err) = result {
                eprintln!(
                    "failed to resolve certificate for listener {}: {err}",
                    listener_addr(&self.listen_key)
                );
            }
        }

        async fn handshake_complete_callback(
            &self,
            ssl: &TlsRef,
        ) -> Option<Arc<dyn Any + Send + Sync>> {
            let sni = ssl
                .servername(NameType::HOST_NAME)
                .map(|value| value.to_ascii_lowercase());
            Some(Arc::new(DownstreamTlsInfo { sni }))
        }
    }
}

fn listener_addr(key: &ListenKey) -> String {
    SocketAddr::new(key.addr, key.port).to_string()
}

fn pem_source_path<'a>(source: &'a PemSource, label: &str) -> Result<&'a str> {
    match source {
        PemSource::Path(path) => path.to_str().ok_or_else(|| {
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                format!("{label} path is not valid UTF-8"),
            )
        }),
        PemSource::InlinePem(_) => Err(pingora::Error::explain(
            pingora::ErrorType::InternalError,
            format!("{label} inline PEM is not supported for listeners yet"),
        )),
    }
}

type ListenerTlsConfigIdentity<'a> = &'a TlsIdentity;

fn default_listener_tls<'a>(
    key: &ListenKey,
    tls: &'a ListenerTlsConfig,
) -> Result<ListenerTlsConfigIdentity<'a>> {
    tls.default.as_ref().or_else(|| tls.named.values().next()).ok_or_else(|| {
        pingora::Error::explain(
            pingora::ErrorType::InternalError,
            format!("ssl listener {} has no certificate", listener_addr(key)),
        )
    })
}

#[cfg(any(test, not(feature = "openssl")))]
fn listener_has_multiple_identities(tls: &ListenerTlsConfig) -> bool {
    let Some(reference) = tls.default.as_ref().or_else(|| tls.named.values().next()) else {
        return false;
    };

    tls.default
        .iter()
        .chain(tls.named.values())
        .any(|candidate| candidate != reference)
}

fn select_listener_tls<'a>(
    key: &ListenKey,
    tls: &'a ListenerTlsConfig,
    server_name: Option<&str>,
) -> Result<ListenerTlsConfigIdentity<'a>> {
    if let Some(server_name) = server_name {
        if let Some(identity) = tls.named.get(&server_name.to_ascii_lowercase()) {
            return Ok(identity);
        }
    }

    default_listener_tls(key, tls)
}

#[cfg(not(feature = "openssl"))]
fn resolve_single_listener_tls<'a>(
    key: &ListenKey,
    tls: &'a ListenerTlsConfig,
) -> Result<ListenerTlsConfigIdentity<'a>> {
    let identity = default_listener_tls(key, tls)?;

    if listener_has_multiple_identities(tls) {
        return Err(pingora::Error::explain(
            pingora::ErrorType::InternalError,
            format!(
                "ssl listener {} has multiple certificate identities; build with feature `openssl` to enable SNI-based certificate selection",
                listener_addr(key)
            ),
        ));
    }

    Ok(identity)
}

fn listener_tls_settings(
    key: &ListenKey,
    tls: &ListenerTlsConfig,
    protocol: &ListenerProtocolConfig,
    state: Arc<RuntimeState>,
) -> Result<TlsSettings> {
    #[cfg(feature = "openssl")]
    {
        let callbacks = openssl_listener_tls::SniCertResolver::new(state, key.clone());
        let mut settings = TlsSettings::with_callbacks(callbacks)?;
        apply_listener_tls_settings(&mut settings, protocol, &tls.settings)?;
        Ok(settings)
    }

    #[cfg(not(feature = "openssl"))]
    {
        let _ = state;
        let identity = resolve_single_listener_tls(key, tls)?;
        let cert_path = pem_source_path(&identity.cert, "ssl certificate")?;
        let key_path = pem_source_path(&identity.key, "ssl certificate key")?;

        let mut settings = TlsSettings::intermediate(cert_path, key_path)?;
        apply_listener_tls_settings(&mut settings, protocol, &tls.settings)?;
        Ok(settings)
    }
}

fn apply_listener_tls_settings(
    settings: &mut TlsSettings,
    protocol: &ListenerProtocolConfig,
    tls: &ListenerTlsSettings,
) -> Result<()> {
    let alpn = if protocol.http2_only {
        ALPN::H2
    } else if protocol.http2 {
        ALPN::H2H1
    } else {
        ALPN::H1
    };
    settings.set_alpn(alpn);

    #[cfg(not(feature = "openssl"))]
    {
        if tls.protocols.is_some() {
            return Err(pingora::Error::explain(
                pingora::ErrorType::InternalError,
                "ssl_protocols requires build with feature `openssl`",
            ));
        }

        if tls.verify_client != TlsVerifyClient::Off || tls.client_certificate.is_some() {
            return Err(pingora::Error::explain(
                pingora::ErrorType::InternalError,
                "ssl_verify_client and ssl_client_certificate require build with feature `openssl`",
            ));
        }
    }

    #[cfg(feature = "openssl")]
    if let Some(protocols) = tls.protocols {
        settings
            .set_min_proto_version(Some(ssl_version(protocols.min)))
            .map_err(|err| {
                pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    format!("failed to set minimum TLS version: {err}"),
                )
            })?;
        settings
            .set_max_proto_version(Some(ssl_version(protocols.max)))
            .map_err(|err| {
                pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    format!("failed to set maximum TLS version: {err}"),
                )
            })?;
    }

    #[cfg(feature = "openssl")]
    match tls.verify_client {
        TlsVerifyClient::Off => settings.set_verify(SslVerifyMode::NONE),
        TlsVerifyClient::Optional => settings.set_verify(SslVerifyMode::PEER),
        TlsVerifyClient::Required => settings.set_verify(required_verify_mode()),
    }

    #[cfg(feature = "openssl")]
    if matches!(
        tls.verify_client,
        TlsVerifyClient::Optional | TlsVerifyClient::Required
    ) {
        let client_ca = tls.client_certificate.as_ref().ok_or_else(|| {
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                "ssl_verify_client requires ssl_client_certificate",
            )
        })?;
        let client_ca_path = pem_source_path(client_ca, "ssl client certificate authority")?;
        settings.set_ca_file(client_ca_path).map_err(|err| {
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                format!("failed to set ssl_client_certificate `{client_ca_path}`: {err}"),
            )
        })?;
    }

    Ok(())
}

fn ssl_version(version: TlsProtocolVersion) -> SslVersion {
    match version {
        TlsProtocolVersion::Tls1 => SslVersion::TLS1,
        TlsProtocolVersion::Tls1_2 => SslVersion::TLS1_2,
        TlsProtocolVersion::Tls1_3 => SslVersion::TLS1_3,
    }
}

#[cfg(feature = "openssl")]
fn required_verify_mode() -> SslVerifyMode {
    SslVerifyMode::PEER | SslVerifyMode::FAIL_IF_NO_PEER_CERT
}

#[cfg(not(feature = "openssl"))]
fn required_verify_mode() -> SslVerifyMode {
    SslVerifyMode::PEER
}

fn configure_proxy_service<SV>(
    svc: &mut Service<HttpProxy<SV, ()>>,
    router: &CompiledRouter,
) -> Result<()>
where
    SV: ProxyHttp,
{
    let proxy = svc.app_logic_mut().ok_or_else(|| {
        pingora::Error::explain(
            pingora::ErrorType::InternalError,
            "http proxy service application is missing",
        )
    })?;

    let mut options = HttpServerOptions::default();
    options.h2c = router.http_options.h2c;
    options.allow_connect_method_proxying = router.http_options.allow_connect_method_proxying;
    options.keepalive_request_limit = router.http_options.keepalive_requests;
    proxy.server_options = Some(options);
    Ok(())
}

fn bind_listeners<SV>(
    svc: &mut Service<HttpProxy<SV, ()>>,
    router: &CompiledRouter,
    state: Arc<RuntimeState>,
) -> Result<()>
where
    SV: ProxyHttp,
{
    configure_proxy_service(svc, router)?;

    let mut listeners: Vec<_> = router.listeners.keys().cloned().collect();
    listeners.sort_by(|left, right| {
        (left.addr.to_string(), left.port, left.ssl).cmp(&(
            right.addr.to_string(),
            right.port,
            right.ssl,
        ))
    });

    for key in listeners {
        let addr = listener_addr(&key);

        if key.ssl {
            let tls = router.listener_tls.get(&key).ok_or_else(|| {
                pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    format!("ssl listener {addr} is missing certificate configuration"),
                )
            })?;
            let protocol = router.listener_protocols.get(&key).ok_or_else(|| {
                pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    format!("listener {addr} is missing protocol configuration"),
                )
            })?;
            let settings = listener_tls_settings(&key, tls, protocol, Arc::clone(&state))?;
            svc.add_tls_with_settings(&addr, None, settings);
        } else {
            svc.add_tcp(&addr);
        }
    }

    Ok(())
}

pub fn bind_listeners_from_state<SV>(
    svc: &mut Service<HttpProxy<SV, ()>>,
    state: Arc<RuntimeState>,
) -> Result<()>
where
    SV: ProxyHttp,
{
    let snapshot = state.snapshot();
    bind_listeners(svc, &snapshot.router, state)
}

// Bind one endpoint per unique listen socket. Virtual hosts sharing the same
// addr:port are routed later via CompiledRouter.
pub fn bind_listeners_from_router<SV>(
    svc: &mut Service<HttpProxy<SV, ()>>,
    router: &CompiledRouter,
) -> Result<()>
where
    SV: ProxyHttp,
{
    bind_listeners(svc, router, Arc::new(RuntimeState::bootstrap(router.clone())))
}
