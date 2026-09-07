//! Upstream TLS identities, trust material and peer transport options.

use super::super::types::{CompiledRouter, VirtualHostRoutes};
use ngxora_compile::ir::{
    PemSource, Switch, UpstreamHttpProtocol, UpstreamSslOptions, UpstreamTimeouts,
};
use pingora::protocols::tls::CaType;
#[cfg(feature = "openssl")]
use pingora::tls::pkey::PKey;
#[cfg(feature = "openssl")]
use pingora::tls::x509::X509;
use pingora::upstreams::peer::HttpPeer;
use pingora::utils::tls::CertKey;
use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;
use std::time::Duration;

pub(crate) type RuntimeTrustedCa = Arc<CaType>;

pub(crate) type RuntimeClientIdentity = Arc<CertKey>;

/// Key identifying one (cert, key) pair so identical identities are loaded once.
#[derive(Debug, Clone, Eq, PartialEq, Hash)]
pub(crate) struct ClientIdentityKey {
    pub cert: PemSource,
    pub key: PemSource,
}

fn normalized_peer_timeout(timeout: Option<Duration>) -> Option<Duration> {
    match timeout {
        Some(timeout) if timeout.is_zero() => None,
        other => other,
    }
}

// Route-level timeout directives are mapped directly to Pingora upstream peer
// options, so they can change live with route snapshots.
pub(crate) fn apply_upstream_timeouts(peer: &mut HttpPeer, timeouts: UpstreamTimeouts) {
    peer.options.connection_timeout = normalized_peer_timeout(timeouts.connect);
    peer.options.read_timeout = normalized_peer_timeout(timeouts.read);
    peer.options.write_timeout = normalized_peer_timeout(timeouts.write);
}

pub(crate) fn apply_upstream_http_protocol(
    peer: &mut HttpPeer,
    protocol: Option<UpstreamHttpProtocol>,
) {
    match protocol {
        Some(UpstreamHttpProtocol::H1) => peer.options.set_http_version(1, 1),
        Some(UpstreamHttpProtocol::H2 | UpstreamHttpProtocol::H2c) => {
            peer.options.set_http_version(2, 2)
        }
        None => {}
    }
}

// Apply SSL options from location directives to Pingora peer options.
pub(crate) fn apply_upstream_ssl_options(
    peer: &mut HttpPeer,
    options: &UpstreamSslOptions,
    trusted_ca: Option<&RuntimeTrustedCa>,
    client_identity: Option<&RuntimeClientIdentity>,
) {
    match options.verify_cert {
        Switch::On => {
            peer.options.verify_cert = true;
            peer.options.verify_hostname = true;
        }
        Switch::Off => {
            peer.options.verify_cert = false;
            peer.options.verify_hostname = false;
        }
    }

    peer.options.ca = trusted_ca.cloned();
    peer.client_cert_key = client_identity.cloned();
}

pub(crate) fn build_runtime_trusted_cas(
    router: &CompiledRouter,
) -> Result<HashMap<PemSource, RuntimeTrustedCa>, String> {
    let mut trusted_cas = HashMap::new();

    for routes in router.listeners.values() {
        collect_trusted_cas_from_vhosts(routes, &mut trusted_cas)?;
    }

    Ok(trusted_cas)
}

fn collect_trusted_cas_from_vhosts(
    routes: &VirtualHostRoutes,
    trusted_cas: &mut HashMap<PemSource, RuntimeTrustedCa>,
) -> Result<(), String> {
    for server_routes in routes.named.values().chain(routes.default.iter()) {
        collect_trusted_cas_from_server(server_routes, trusted_cas)?;
    }

    Ok(())
}

fn collect_trusted_cas_from_server(
    routes: &super::super::ServerRoutes,
    trusted_cas: &mut HashMap<PemSource, RuntimeTrustedCa>,
) -> Result<(), String> {
    for location in &routes.locations {
        let Some(source) = location.upstream_ssl_options.trusted_certificate.as_ref() else {
            continue;
        };
        if trusted_cas.contains_key(source) {
            continue;
        }

        trusted_cas.insert(source.clone(), load_runtime_trusted_ca(source)?);
    }

    Ok(())
}

fn read_pem_source(source: &PemSource, label: &str) -> Result<Vec<u8>, String> {
    match source {
        PemSource::Path(path) => std::fs::read(path)
            .map_err(|err| format!("failed to read {label} `{}`: {err}", path.display())),
        PemSource::InlinePem(pem) => Ok(pem.as_bytes().to_vec()),
    }
}

#[cfg(feature = "openssl")]
fn load_runtime_trusted_ca(source: &PemSource) -> Result<RuntimeTrustedCa, String> {
    let pem = read_pem_source(source, "proxy_ssl_trusted_certificate")?;
    let certs = X509::stack_from_pem(&pem)
        .map_err(|err| format!("failed to parse proxy_ssl_trusted_certificate: {err}"))?;
    if certs.is_empty() {
        return Err("proxy_ssl_trusted_certificate does not contain any certificates".into());
    }

    Ok(Arc::new(certs.into_boxed_slice()))
}

#[cfg(not(feature = "openssl"))]
fn load_runtime_trusted_ca(_source: &PemSource) -> Result<RuntimeTrustedCa, String> {
    Err("proxy_ssl_trusted_certificate requires build with feature `openssl`".into())
}

// Collect every distinct upstream client identity declared in the router so
// each (cert, key) pair is parsed exactly once per snapshot build.
pub(crate) fn build_runtime_client_identities(
    router: &CompiledRouter,
) -> Result<HashMap<ClientIdentityKey, RuntimeClientIdentity>, String> {
    let mut identities = HashMap::new();

    for routes in router.listeners.values() {
        collect_client_identities_from_vhosts(routes, &mut identities)?;
    }

    Ok(identities)
}

fn collect_client_identities_from_vhosts(
    routes: &VirtualHostRoutes,
    identities: &mut HashMap<ClientIdentityKey, RuntimeClientIdentity>,
) -> Result<(), String> {
    for server_routes in routes.named.values().chain(routes.default.iter()) {
        collect_client_identities_from_server(server_routes, identities)?;
    }

    Ok(())
}

fn collect_client_identities_from_server(
    routes: &super::super::ServerRoutes,
    identities: &mut HashMap<ClientIdentityKey, RuntimeClientIdentity>,
) -> Result<(), String> {
    for location in &routes.locations {
        let (Some(cert), Some(key)) = (
            location.upstream_ssl_options.client_certificate.as_ref(),
            location
                .upstream_ssl_options
                .client_certificate_key
                .as_ref(),
        ) else {
            continue;
        };

        let identity_key = ClientIdentityKey {
            cert: cert.clone(),
            key: key.clone(),
        };
        if identities.contains_key(&identity_key) {
            continue;
        }

        identities.insert(identity_key, load_runtime_client_identity(cert, key)?);
    }

    Ok(())
}

#[cfg(feature = "openssl")]
fn load_runtime_client_identity(
    cert_source: &PemSource,
    key_source: &PemSource,
) -> Result<RuntimeClientIdentity, String> {
    let cert_pem = read_pem_source(cert_source, "proxy_ssl_certificate")?;
    let certs = X509::stack_from_pem(&cert_pem)
        .map_err(|err| format!("failed to parse proxy_ssl_certificate: {err}"))?;
    if certs.is_empty() {
        return Err("proxy_ssl_certificate does not contain any certificates".into());
    }

    let key_pem = read_pem_source(key_source, "proxy_ssl_certificate_key")?;
    let key = PKey::private_key_from_pem(&key_pem)
        .map_err(|err| format!("failed to parse proxy_ssl_certificate_key: {err}"))?;

    Ok(Arc::new(CertKey::new(certs, key)))
}

#[cfg(not(feature = "openssl"))]
fn load_runtime_client_identity(
    _cert_source: &PemSource,
    _key_source: &PemSource,
) -> Result<RuntimeClientIdentity, String> {
    Err("proxy_ssl_certificate requires build with feature `openssl`".into())
}
