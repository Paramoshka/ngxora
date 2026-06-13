//! Let's Encrypt / ACME certificate manager.
//!
//! ## Architecture
//!
//! 1. `LeManager::new()` — creates or restores an ACME account via `instant-acme`.
//! 2. `LeManager::reconcile()` — checks all LE-managed domains, (re)issues if needed.
//! 3. `spawn_le_reconciler()` — background task: immediate reconcile, then every hour.
//! 4. `ChallengeTokens` — shared store for HTTP-01 responses.  The proxy must check
//!    `lookup_challenge()` for `/.well-known/acme-challenge/<token>` requests.

use crate::upstreams::CompiledRouter;
use dashmap::DashMap;
use instant_acme::{
    Account, AccountBuilder, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use ngxora_compile::ir::{LetsEncryptConfig, PemSource};
use pingora::tls::x509;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::time;

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

/// Write `data` to `path` and set permissions to 0o600 (owner-only).
fn write_secure(path: &Path, data: &[u8]) -> Result<(), String> {
    fs::write(path, data).map_err(|e| format!("failed to write {}: {e}", path.display()))?;
    #[cfg(unix)]
    {
        fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(|e| format!("failed to set permissions on {}: {e}", path.display()))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Challenge token store
// ---------------------------------------------------------------------------

pub type ChallengeTokens = Arc<DashMap<String, String>>;

pub fn lookup_challenge(tokens: &ChallengeTokens, token: &str) -> Option<String> {
    tokens.get(token).map(|v| v.clone())
}

// ---------------------------------------------------------------------------
// Certificate status
// ---------------------------------------------------------------------------

enum CertStatus {
    Fresh,
    Missing,
    ExpiringSoon,
}

// ---------------------------------------------------------------------------
// Let's Encrypt manager
// ---------------------------------------------------------------------------

pub struct LeManager {
    account: Account,
    cache_dir: PathBuf,
    pub tokens: ChallengeTokens,
}

impl LeManager {
    /// Create a new manager, restoring or creating the ACME account.
    pub async fn new(config: &LetsEncryptConfig) -> Result<Self, String> {
        let directory_url = config
            .acme_directory
            .clone()
            .unwrap_or_else(|| instant_acme::LetsEncrypt::Production.url().to_string());

        let cache_dir = config
            .cache_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("/var/lib/ngxora/certs"));

        fs::create_dir_all(&cache_dir)
            .map_err(|e| format!("failed to create LE cache dir {}: {e}", cache_dir.display()))?;

        let account = Self::load_or_create_account(&directory_url, config, &cache_dir).await?;

        Ok(Self {
            account,
            cache_dir,
            tokens: Arc::new(DashMap::new()),
        })
    }

    /// Create a manager that shares an existing token store (for snapshot reloads).
    pub async fn with_tokens(
        config: &LetsEncryptConfig,
        tokens: ChallengeTokens,
    ) -> Result<Self, String> {
        let directory_url = config
            .acme_directory
            .clone()
            .unwrap_or_else(|| instant_acme::LetsEncrypt::Production.url().to_string());

        let cache_dir = config
            .cache_dir
            .clone()
            .unwrap_or_else(|| PathBuf::from("/var/lib/ngxora/certs"));

        fs::create_dir_all(&cache_dir)
            .map_err(|e| format!("failed to create LE cache dir {}: {e}", cache_dir.display()))?;

        let account = Self::load_or_create_account(&directory_url, config, &cache_dir).await?;

        Ok(Self {
            account,
            cache_dir,
            tokens,
        })
    }

    /// Reconcile all LE-managed domains in the given router.
    pub async fn reconcile(&self, router: &CompiledRouter) {
        for tls in router.listener_tls.values() {
            for (domain, identity) in &tls.named {
                let cert_path = match &identity.cert {
                    PemSource::Path(p) => p.clone(),
                    _ => continue,
                };
                if !cert_path.starts_with(&self.cache_dir) {
                    continue;
                }
                if let Err(e) = self
                    .ensure_certificate(domain, &cert_path, &identity.key)
                    .await
                {
                    log::error!("LE certificate error for {domain}: {e}");
                }
            }
        }
    }

    // ------------------------------------------------------------------
    // Account
    // ------------------------------------------------------------------

    fn account_path(cache_dir: &Path) -> PathBuf {
        cache_dir.join("account.json")
    }

    async fn load_or_create_account(
        directory_url: &str,
        config: &LetsEncryptConfig,
        cache_dir: &Path,
    ) -> Result<Account, String> {
        let path = Self::account_path(cache_dir);

        let builder = Self::acme_builder()?;

        if path.exists() {
            let raw = fs::read_to_string(&path)
                .map_err(|e| format!("failed to read {}: {e}", path.display()))?;
            let credentials: instant_acme::AccountCredentials = serde_json::from_str(&raw)
                .map_err(|e| format!("failed to parse {}: {e}", path.display()))?;
            builder
                .from_credentials(credentials)
                .await
                .map_err(|e| format!("failed to restore ACME account: {e}"))
        } else {
            let contact = config
                .email
                .as_deref()
                .map(|e| format!("mailto:{e}"))
                .unwrap_or_default();
            let contacts: Vec<&str> = vec![contact.as_str()];

            let new_account = NewAccount {
                contact: if contacts[0].is_empty() {
                    &[]
                } else {
                    &contacts
                },
                terms_of_service_agreed: true,
                only_return_existing: false,
            };

            let (account, credentials) = builder
                .create(&new_account, directory_url.to_string(), None)
                .await
                .map_err(|e| format!("failed to create ACME account: {e}"))?;

            let raw = serde_json::to_string(&credentials)
                .map_err(|e| format!("failed to serialise ACME credentials: {e}"))?;
            write_secure(&path, raw.as_bytes())?;

            log::info!("created new ACME account at {}", path.display());
            Ok(account)
        }
    }

    fn acme_builder() -> Result<AccountBuilder, String> {
        Account::builder().map_err(|e| format!("failed to create ACME account builder: {e}"))
    }

    // ------------------------------------------------------------------
    // Certificate lifecycle
    // ------------------------------------------------------------------

    async fn ensure_certificate(
        &self,
        domain: &str,
        cert_path: &Path,
        key_source: &PemSource,
    ) -> Result<(), String> {
        match self.check_cert(cert_path) {
            CertStatus::Fresh => return Ok(()),
            CertStatus::ExpiringSoon => {
                log::info!("{domain}: certificate expiring soon, renewing…")
            }
            CertStatus::Missing => log::info!("{domain}: no certificate found, obtaining…"),
        }
        self.issue_certificate(domain, cert_path, key_source).await
    }

    fn check_cert(&self, cert_path: &Path) -> CertStatus {
        if !cert_path.exists() {
            return CertStatus::Missing;
        }
        let pem = match fs::read(cert_path) {
            Ok(p) => p,
            Err(_) => return CertStatus::Missing,
        };
        let x509 = match x509::X509::from_pem(&pem) {
            Ok(x) => x,
            Err(_) => return CertStatus::Missing,
        };
        let not_after = x509.not_after();
        let renew_before = match openssl::asn1::Asn1Time::days_from_now(30) {
            Ok(t) => t,
            Err(_) => return CertStatus::ExpiringSoon,
        };
        if not_after < &renew_before {
            CertStatus::ExpiringSoon
        } else {
            CertStatus::Fresh
        }
    }

    async fn issue_certificate(
        &self,
        domain: &str,
        cert_path: &Path,
        key_source: &PemSource,
    ) -> Result<(), String> {
        // 1. Create ACME order.
        let mut order = self
            .account
            .new_order(&NewOrder::new(&[Identifier::Dns(domain.into())]))
            .await
            .map_err(|e| format!("{domain}: failed to create ACME order: {e}"))?;

        // 2. Get the first authorization.
        let mut authorizations = order.authorizations();
        let mut auth = authorizations
            .next()
            .await
            .ok_or_else(|| format!("{domain}: order has no authorizations"))?
            .map_err(|e| format!("{domain}: failed to get authorization: {e}"))?;

        // 3. Get the HTTP-01 challenge handle.
        let mut challenge = auth
            .challenge(ChallengeType::Http01)
            .ok_or_else(|| format!("{domain}: no HTTP-01 challenge available"))?;

        // 4. Compute key authorization and store it for the proxy.
        let key_auth = challenge.key_authorization();
        let token = challenge.token.clone();
        self.tokens
            .insert(token.clone(), key_auth.as_str().to_string());

        // 5. Signal readiness.
        challenge
            .set_ready()
            .await
            .map_err(|e| format!("{domain}: failed to set challenge ready: {e}"))?;

        // 6. Poll until ready or invalid.
        let status = order
            .poll_ready(&RetryPolicy::default())
            .await
            .map_err(|e| format!("{domain}: order failed: {e}"))?;

        // 7. Clean up token regardless of outcome.
        self.tokens.remove(&token);

        if status != OrderStatus::Ready {
            return Err(format!("{domain}: unexpected order status {status:?}"));
        }

        // 8. Generate key + CSR, finalize.
        let private_key = Self::load_or_generate_key(key_source)?;
        let csr_der = Self::make_csr(&private_key, domain)?;

        order
            .finalize_csr(&csr_der)
            .await
            .map_err(|e| format!("{domain}: failed to finalize order: {e}"))?;

        // 9. Poll for the certificate.
        let cert_pem = order
            .poll_certificate(&RetryPolicy::default())
            .await
            .map_err(|e| format!("{domain}: failed to get certificate: {e}"))?;

        // 10. Write certificate to disk.
        let parent = cert_path
            .parent()
            .ok_or_else(|| format!("{domain}: cert path {} has no parent", cert_path.display()))?;
        fs::create_dir_all(parent)
            .map_err(|e| format!("{domain}: failed to create dir {}: {e}", parent.display()))?;
        write_secure(cert_path, cert_pem.as_bytes())?;

        log::info!(
            "{domain}: obtained new certificate, wrote to {}",
            cert_path.display()
        );
        Ok(())
    }

    // ------------------------------------------------------------------
    // CSR generation (openssl)
    // ------------------------------------------------------------------

    fn load_or_generate_key(
        key_source: &PemSource,
    ) -> Result<openssl::pkey::PKey<openssl::pkey::Private>, String> {
        match key_source {
            PemSource::Path(path) => {
                if path.as_os_str().is_empty() || !path.exists() {
                    let ec_group =
                        openssl::ec::EcGroup::from_curve_name(openssl::nid::Nid::X9_62_PRIME256V1)
                            .map_err(|e| format!("failed to create EC group: {e}"))?;
                    let ec_key = openssl::ec::EcKey::generate(&ec_group)
                        .map_err(|e| format!("failed to generate ECDSA key: {e}"))?;
                    let key = openssl::pkey::PKey::from_ec_key(ec_key)
                        .map_err(|e| format!("failed to convert EC key: {e}"))?;
                    if let Some(parent) = path.parent() {
                        fs::create_dir_all(parent).map_err(|e| {
                            format!("failed to create key dir {}: {e}", parent.display())
                        })?;
                    }
                    let pem = key
                        .private_key_to_pem_pkcs8()
                        .map_err(|e| format!("failed to encode private key: {e}"))?;
                    write_secure(path, &pem)?;
                    Ok(key)
                } else {
                    let pem_bytes = fs::read(path)
                        .map_err(|e| format!("failed to read key {}: {e}", path.display()))?;
                    openssl::pkey::PKey::private_key_from_pem(&pem_bytes)
                        .map_err(|e| format!("failed to parse key {}: {e}", path.display()))
                }
            }
            PemSource::InlinePem(pem) => openssl::pkey::PKey::private_key_from_pem(pem.as_bytes())
                .map_err(|e| format!("failed to parse inline key: {e}")),
        }
    }

    fn make_csr(
        key: &openssl::pkey::PKey<openssl::pkey::Private>,
        domain: &str,
    ) -> Result<Vec<u8>, String> {
        let mut req = openssl::x509::X509ReqBuilder::new()
            .map_err(|e| format!("failed to create X509 req builder: {e}"))?;
        req.set_pubkey(key)
            .map_err(|e| format!("failed to set CSR public key: {e}"))?;

        let mut extensions = openssl::stack::Stack::new()
            .map_err(|e| format!("failed to create extension stack: {e}"))?;
        let ctx = req.x509v3_context(None);
        let san = openssl::x509::extension::SubjectAlternativeName::new()
            .dns(domain)
            .build(&ctx)
            .map_err(|e| format!("failed to build SAN extension: {e}"))?;
        extensions
            .push(san)
            .map_err(|e| format!("failed to push SAN: {e}"))?;
        req.add_extensions(&extensions)
            .map_err(|e| format!("failed to add extensions: {e}"))?;

        req.sign(key, openssl::hash::MessageDigest::sha256())
            .map_err(|e| format!("failed to sign CSR: {e}"))?;

        Ok(req
            .build()
            .to_der()
            .map_err(|e| format!("failed to DER-encode CSR: {e}"))?)
    }
}

// ---------------------------------------------------------------------------
// Background service (integrates with Pingora lifecycle)
// ---------------------------------------------------------------------------

use async_trait::async_trait;
use pingora::server::ShutdownWatch;
use pingora::services::background::BackgroundService;

/// Pingora background service that manages the LE certificate lifecycle.
///
/// Created via [`LeReconcilerService::new`] and registered with
/// `background_service("le-reconciler", LeReconcilerService::new(...))`.
pub struct LeReconcilerService {
    state: Arc<crate::control::RuntimeState>,
    tokens: ChallengeTokens,
}

impl LeReconcilerService {
    pub fn new(state: Arc<crate::control::RuntimeState>, tokens: ChallengeTokens) -> Self {
        Self { state, tokens }
    }
}

#[async_trait]
impl BackgroundService for LeReconcilerService {
    async fn start(&self, mut shutdown: ShutdownWatch) {
        let mut manager: Option<Arc<LeManager>> = None;
        let mut last_config: Option<LetsEncryptConfig> = None;

        // First reconciliation immediately.
        reconcile_once(&self.state, &self.tokens, &mut manager, &mut last_config).await;

        let mut hourly = time::interval(Duration::from_secs(3600));

        loop {
            if *shutdown.borrow() {
                log::info!("LE reconciler shutting down");
                return;
            }

            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        log::info!("LE reconciler shutting down");
                        return;
                    }
                }
                _ = hourly.tick() => {
                    reconcile_once(&self.state, &self.tokens, &mut manager, &mut last_config).await;
                }
            }
        }
    }
}

async fn reconcile_once(
    state: &crate::control::RuntimeState,
    tokens: &ChallengeTokens,
    manager: &mut Option<Arc<LeManager>>,
    last_config: &mut Option<LetsEncryptConfig>,
) {
    let snapshot = state.snapshot();
    let current = snapshot.router.le_config.clone();
    let needs_refresh = current != *last_config || (current.is_some() && manager.is_none());

    if needs_refresh {
        match current.as_ref() {
            Some(config) => match LeManager::with_tokens(config, Arc::clone(tokens)).await {
                Ok(m) => {
                    log::info!(
                        "LE manager created (cache: {:?})",
                        config
                            .cache_dir
                            .as_deref()
                            .unwrap_or(std::path::Path::new("/var/lib/ngxora/certs"))
                    );
                    *manager = Some(Arc::new(m));
                    *last_config = current;
                }
                Err(e) => {
                    log::error!("failed to create LE manager: {e}");
                    *manager = None;
                }
            },
            None => {
                *manager = None;
                *last_config = None;
            }
        }
    }

    if let Some(m) = manager {
        m.reconcile(&snapshot.router).await;
    }
}

#[cfg(test)]
#[path = "le_tests.rs"]
mod tests;
