//! Tests for the Let's Encrypt / ACME manager live here.
//! Integration-style tests require a staging ACME endpoint.

use super::*;
use crate::control::RuntimeState;
use crate::upstreams::CompiledRouter;
use ngxora_compile::ir::LetsEncryptConfig;
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Once;
use std::sync::atomic::{AtomicU64, Ordering};

fn install_rustls_provider() {
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        rustls::crypto::aws_lc_rs::default_provider()
            .install_default()
            .expect("install rustls crypto provider");
    });
}

fn unique_test_dir(name: &str) -> PathBuf {
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!("ngxora-{name}-{id}"))
}

#[tokio::test]
async fn reconcile_once_retries_manager_creation_after_failure() {
    install_rustls_provider();

    let cache_dir = unique_test_dir("le-retry");
    fs::create_dir_all(&cache_dir).expect("create cache dir");
    fs::write(cache_dir.join("account.json"), b"{not-json").expect("write invalid account");

    let state = RuntimeState::bootstrap(CompiledRouter {
        le_config: Some(LetsEncryptConfig {
            acme_directory: None,
            email: Some("admin@example.com".into()),
            cache_dir: Some(cache_dir.clone()),
        }),
        ..CompiledRouter::default()
    });
    let tokens: ChallengeTokens = Arc::new(DashMap::new());
    let mut manager = None;
    let mut last_config = None;

    reconcile_once(&state, &tokens, &mut manager, &mut last_config).await;

    assert!(manager.is_none());
    assert!(last_config.is_none());

    let _ = fs::remove_dir_all(cache_dir);
}
