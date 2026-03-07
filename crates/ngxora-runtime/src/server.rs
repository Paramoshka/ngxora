use crate::upstreams::{CompiledRouter, ListenKey, ListenerTlsConfig};
use ngxora_compile::ir::{PemSource, TlsIdentity};
use pingora::listeners::tls::TlsSettings;
use pingora::Result;
use pingora::services::listening::Service;
use pingora_proxy::{HttpProxy, ProxyHttp};
use std::net::SocketAddr;

#[cfg(test)]
#[path = "server_tests.rs"]
mod tests;

#[cfg(feature = "openssl")]
mod openssl_listener_tls {
    use super::{
        default_listener_tls, listener_addr, pem_source_path, ListenKey, ListenerTlsConfig,
        ListenerTlsConfigIdentity,
    };
    use async_trait::async_trait;
    use pingora::listeners::TlsAccept;
    use pingora::tls::ext;
    use pingora::tls::pkey::{PKey, Private};
    use pingora::tls::ssl::{NameType, SslRef};
    use pingora::tls::x509::X509;
    use pingora::Result;
    use std::collections::HashMap;
    use std::sync::Arc;

    struct LoadedTlsIdentity {
        cert: X509,
        key: PKey<Private>,
    }

    impl LoadedTlsIdentity {
        fn load(key: &ListenKey, identity: ListenerTlsConfigIdentity<'_>) -> Result<Self> {
            let cert_path = pem_source_path(&identity.cert, "ssl certificate")?;
            let key_path = pem_source_path(&identity.key, "ssl certificate key")?;
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

    pub(super) struct SniCertResolver {
        named: HashMap<String, Arc<LoadedTlsIdentity>>,
        default: Arc<LoadedTlsIdentity>,
    }

    impl SniCertResolver {
        pub(super) fn from_listener_tls(
            key: &ListenKey,
            tls: &ListenerTlsConfig,
        ) -> Result<Box<Self>> {
            let default = Arc::new(LoadedTlsIdentity::load(key, default_listener_tls(key, tls)?)?);
            let mut named = HashMap::with_capacity(tls.named.len());

            for (name, identity) in &tls.named {
                named.insert(
                    name.clone(),
                    Arc::new(LoadedTlsIdentity::load(key, identity)?),
                );
            }

            Ok(Box::new(Self { named, default }))
        }

        fn select(&self, server_name: Option<&str>) -> Arc<LoadedTlsIdentity> {
            if let Some(server_name) = server_name {
                if let Some(identity) = self.named.get(&server_name.to_ascii_lowercase()) {
                    return Arc::clone(identity);
                }
            }

            Arc::clone(&self.default)
        }
    }

    #[async_trait]
    impl TlsAccept for SniCertResolver {
        async fn certificate_callback(&self, ssl: &mut SslRef) {
            let identity = self.select(ssl.servername(NameType::HOST_NAME));
            ext::ssl_use_certificate(ssl, &identity.cert).unwrap();
            ext::ssl_use_private_key(ssl, &identity.key).unwrap();
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

#[cfg(test)]
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

fn listener_tls_settings(key: &ListenKey, tls: &ListenerTlsConfig) -> Result<TlsSettings> {
    #[cfg(feature = "openssl")]
    {
        let callbacks = openssl_listener_tls::SniCertResolver::from_listener_tls(key, tls)?;
        let mut settings = TlsSettings::with_callbacks(callbacks)?;
        settings.enable_h2();
        Ok(settings)
    }

    #[cfg(not(feature = "openssl"))]
    {
        let identity = resolve_single_listener_tls(key, tls)?;
        let cert_path = pem_source_path(&identity.cert, "ssl certificate")?;
        let key_path = pem_source_path(&identity.key, "ssl certificate key")?;

        let mut settings = TlsSettings::intermediate(cert_path, key_path)?;
        settings.enable_h2();
        Ok(settings)
    }
}

// Bind one endpoint per unique listen socket. Virtual hosts sharing the same
// addr:port are routed later via CompiledRouter.
pub fn bind_listeners_from_router<SV>(
    svc: &mut Service<HttpProxy<SV, ()>>,
    router: &CompiledRouter,
)
-> Result<()>
where
    SV: ProxyHttp,
{
    let mut listeners: Vec<_> = router.listeners.keys().cloned().collect();
    listeners.sort_by(|left, right| {
        (
            left.addr.to_string(),
            left.port,
            left.ssl,
        )
            .cmp(&(right.addr.to_string(), right.port, right.ssl))
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
            let settings = listener_tls_settings(&key, tls)?;
            svc.add_tls_with_settings(&addr, None, settings);
        } else {
            svc.add_tcp(&addr);
        }
    }

    Ok(())
}
