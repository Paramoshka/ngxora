//! OpenSSL listener certificate resolution and handshake callbacks.

use super::{
    DownstreamTlsInfo, ListenKey, PemSource, RuntimeState, listener_addr, select_listener_tls,
};
use async_trait::async_trait;
use ngxora_compile::ir::TlsIdentity;
use pingora::Result;
use pingora::listeners::TlsAccept;
use pingora::protocols::tls::TlsRef;
use pingora::tls::ext;
use pingora::tls::pkey::{PKey, Private};
use pingora::tls::ssl::{NameType, SslRef};
use pingora::tls::x509::X509;
use std::any::Any;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
enum LoadedPemSourceKey {
    Path(String),
    Inline(String),
}

#[derive(Debug, Clone, Eq, PartialEq, Hash)]
struct LoadedIdentityKey {
    cert: LoadedPemSourceKey,
    key: LoadedPemSourceKey,
}

struct LoadedTlsIdentity {
    cert: X509,
    chain: Vec<X509>,
    key: PKey<Private>,
}

impl LoadedTlsIdentity {
    fn source_key(source: &PemSource, label: &str) -> Result<LoadedPemSourceKey> {
        match source {
            PemSource::Path(path) => path
                .to_str()
                .map(|value| LoadedPemSourceKey::Path(value.to_owned()))
                .ok_or_else(|| {
                    pingora::Error::explain(
                        pingora::ErrorType::InternalError,
                        format!("{label} path is not valid UTF-8"),
                    )
                }),
            PemSource::InlinePem(pem) => Ok(LoadedPemSourceKey::Inline(pem.clone())),
        }
    }

    fn read_source(key: &ListenKey, source: &PemSource, label: &str) -> Result<Vec<u8>> {
        match source {
            PemSource::Path(path) => std::fs::read(path).map_err(|err| {
                pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    format!(
                        "failed to read {label} for listener {} from {}: {err}",
                        listener_addr(key),
                        path.display()
                    ),
                )
            }),
            PemSource::InlinePem(pem) => Ok(pem.as_bytes().to_vec()),
        }
    }

    fn load(key: &ListenKey, cert_source: &PemSource, key_source: &PemSource) -> Result<Self> {
        let cert_bytes = Self::read_source(key, cert_source, "ssl certificate")?;
        let certs = X509::stack_from_pem(&cert_bytes).map_err(|err| {
            let origin = match cert_source {
                PemSource::Path(path) => path.display().to_string(),
                PemSource::InlinePem(_) => "inline PEM".to_owned(),
            };
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                format!(
                    "failed to parse ssl certificate for listener {} from {}: {err}",
                    listener_addr(key),
                    origin
                ),
            )
        })?;
        let mut certs = certs.into_iter();
        let cert = certs.next().ok_or_else(|| {
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                format!(
                    "ssl certificate for listener {} does not contain any certificates",
                    listener_addr(key)
                ),
            )
        })?;
        let chain = certs.collect();

        let key_bytes = Self::read_source(key, key_source, "ssl private key")?;
        let key = PKey::private_key_from_pem(&key_bytes).map_err(|err| {
            let origin = match key_source {
                PemSource::Path(path) => path.display().to_string(),
                PemSource::InlinePem(_) => "inline PEM".to_owned(),
            };
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                format!(
                    "failed to parse ssl private key for listener {} from {}: {err}",
                    listener_addr(key),
                    origin
                ),
            )
        })?;

        Ok(Self { cert, chain, key })
    }
}

#[derive(Default)]
struct LoadedTlsIdentityCache {
    snapshot_generation: u64,
    tls_material_generation: u64,
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

    // Certificates are selected from the current runtime snapshot on every
    // handshake, while parsed PEM objects are cached until config or file
    // material changes.
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
        self.load_cached(
            snapshot.generation,
            self.state.tls_material_generation(),
            identity,
        )
    }

    fn load_cached(
        &self,
        snapshot_generation: u64,
        tls_material_generation: u64,
        identity: &TlsIdentity,
    ) -> Result<Arc<LoadedTlsIdentity>> {
        let key = LoadedIdentityKey {
            cert: LoadedTlsIdentity::source_key(&identity.cert, "ssl certificate")?,
            key: LoadedTlsIdentity::source_key(&identity.key, "ssl certificate key")?,
        };

        let mut cache = self.cache.lock().expect("tls cache poisoned");
        if cache.snapshot_generation != snapshot_generation
            || cache.tls_material_generation != tls_material_generation
        {
            cache.snapshot_generation = snapshot_generation;
            cache.tls_material_generation = tls_material_generation;
            cache.identities.clear();
        }

        if let Some(loaded) = cache.identities.get(&key) {
            return Ok(Arc::clone(loaded));
        }

        let loaded = Arc::new(LoadedTlsIdentity::load(
            &self.listen_key,
            &identity.cert,
            &identity.key,
        )?);
        cache.identities.insert(key, Arc::clone(&loaded));
        Ok(loaded)
    }

    #[cfg(test)]
    pub(super) fn selected_cert_der_for_test(&self, server_name: Option<&str>) -> Result<Vec<u8>> {
        self.select(server_name)?.cert.to_der().map_err(|err| {
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                format!("failed to encode selected certificate: {err}"),
            )
        })
    }

    fn install_identity(&self, ssl: &mut SslRef, identity: &LoadedTlsIdentity) -> Result<()> {
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
        for cert in &identity.chain {
            ext::ssl_add_chain_cert(ssl, cert).map_err(|err| {
                pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    format!(
                        "failed to install ssl certificate chain for listener {}: {err}",
                        listener_addr(&self.listen_key)
                    ),
                )
            })?;
        }
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn install_selected_identity_for_test(
        &self,
        ssl: &mut SslRef,
        server_name: Option<&str>,
    ) -> Result<()> {
        let identity = self.select(server_name)?;
        self.install_identity(ssl, &identity)
    }
}

#[async_trait]
impl TlsAccept for SniCertResolver {
    async fn certificate_callback(&self, ssl: &mut SslRef) {
        let result = self
            .select(ssl.servername(NameType::HOST_NAME))
            .and_then(|identity| self.install_identity(ssl, &identity));

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
