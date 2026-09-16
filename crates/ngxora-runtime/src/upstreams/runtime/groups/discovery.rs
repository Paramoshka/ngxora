//! NRF refresh scheduling, bounded stale state and atomic service publication.

use super::topology::NrfServiceTopology;
use super::{NrfSelectionSnapshot, RuntimeNrfDiscovery};
use pingora::lb::{Backend, Backends, discovery::Static};
use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::Duration;
use tokio::time::Instant;

pub(super) fn nrf_failure_retry_at(
    now: Instant,
    expires_at: Option<Instant>,
    failures: u32,
) -> Instant {
    let exponent = failures.saturating_sub(1).min(5);
    let backoff = Duration::from_secs((1u64 << exponent).min(30));
    let backoff_at = now.checked_add(backoff).unwrap_or(now);
    expires_at.map_or(backoff_at, |expires_at| backoff_at.min(expires_at))
}

pub(super) fn nrf_snapshot_expiry(
    now: Instant,
    validity: Duration,
    stale_if_error: Duration,
) -> Option<Instant> {
    now.checked_add(validity)
        .and_then(|valid_until| valid_until.checked_add(stale_if_error))
}

impl RuntimeNrfDiscovery {
    pub(super) fn record_metrics(&self, now: Instant) {
        if self.client.query.is_some() {
            return;
        }
        let schedule = self.schedule.lock().unwrap();
        let age = schedule
            .last_success_at
            .map(|last_success| now.saturating_duration_since(last_success))
            .unwrap_or_default();
        crate::metrics::set_nrf_discovery_snapshot(&self.group_name, age, schedule.endpoint_count);
    }

    pub(super) fn expire_snapshot(&self) {
        self.selection.store(None);
        self.schedule.lock().unwrap().endpoint_count = 0;
    }

    pub(super) async fn publish_backends(&self, backends: BTreeSet<Backend>) -> Result<(), String> {
        let Some(topology) = NrfServiceTopology::build(&backends, self.policy)? else {
            self.selection.store(None);
            return Ok(());
        };
        let current = self.selection.load_full();
        if current
            .as_ref()
            .is_some_and(|snapshot| snapshot.topology.signature == topology.signature)
        {
            return Ok(());
        }
        // Keep the old view alive while registering the new one, preserving shared
        // health observations and thresholds for endpoints present in both snapshots.
        let backends = Backends::new_with_health_registry(
            Static::new(backends),
            Arc::clone(&self.health_registry),
        );
        backends
            .update(|_| {})
            .await
            .map_err(|err| err.to_string())?;
        self.selection
            .store(Some(Arc::new(NrfSelectionSnapshot { topology, backends })));
        Ok(())
    }

    pub(super) async fn discover(
        &self,
        now: Instant,
    ) -> Result<crate::upstreams::nrf::DiscoveryResult, String> {
        let expires_at = self.schedule.lock().unwrap().expires_at;
        let Some(expires_at) = expires_at.filter(|expires_at| *expires_at > now) else {
            return self.client.discover().await;
        };

        let request = self.client.discover();
        tokio::pin!(request);
        tokio::select! {
            result = &mut request => result,
            _ = tokio::time::sleep_until(expires_at) => {
                self.expire_snapshot();
                request.await
            }
        }
    }

    pub(super) fn record_failure(&self, now: Instant) -> Instant {
        if self.client.query.is_some() {
            crate::metrics::record_scp_event(&self.group_name, "discovery_error");
        } else {
            crate::metrics::record_nrf_discovery_request(&self.group_name, "error");
        }
        let (next_run_at, expired) = {
            let mut schedule = self.schedule.lock().unwrap();
            schedule.failures = schedule.failures.saturating_add(1);
            schedule.next_run_at =
                nrf_failure_retry_at(now, schedule.expires_at, schedule.failures);
            (
                schedule.next_run_at,
                schedule
                    .expires_at
                    .is_some_and(|expires_at| now >= expires_at),
            )
        };

        if expired {
            self.expire_snapshot();
        }
        next_run_at
    }
}

pub(super) fn nrf_refresh_delay(validity: Duration, group_name: &str) -> Duration {
    let identity = std::env::var("HOSTNAME").unwrap_or_else(|_| std::process::id().to_string());
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    identity.hash(&mut hasher);
    group_name.hash(&mut hasher);
    let percent = 70 + hasher.finish() % 21;
    let millis = validity.as_millis().saturating_mul(u128::from(percent)) / 100;
    Duration::from_millis(millis.max(1_000).try_into().unwrap_or(u64::MAX))
}
