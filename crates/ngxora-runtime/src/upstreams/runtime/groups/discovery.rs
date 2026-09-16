//! NRF refresh scheduling, bounded stale state and atomic service publication.

use super::topology::NrfServiceTopology;
use super::{RuntimeNrfDiscovery, RuntimeUpstreamSelector};
use futures::FutureExt;
use std::collections::BTreeSet;
use std::hash::{Hash, Hasher};
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

    pub(super) async fn expire_snapshot(&self, selector: &RuntimeUpstreamSelector) {
        if self.schedule.lock().unwrap().endpoint_count == 0 {
            return;
        }

        match self.publish_backends(selector, BTreeSet::new(), None) {
            Ok(()) => self.schedule.lock().unwrap().endpoint_count = 0,
            Err(err) => {
                log::warn!(
                    "NRF discovery for upstream `{}` failed to expire stale backends: {err}",
                    self.group_name
                );
            }
        }
    }

    pub(super) fn publish_backends(
        &self,
        selector: &RuntimeUpstreamSelector,
        backends: BTreeSet<pingora::lb::Backend>,
        selection: Option<NrfServiceTopology>,
    ) -> Result<(), String> {
        let mut current = self.selection.write().unwrap();
        self.source.set(backends);
        // RuntimeDiscoverySource is in-memory: never hold the write lock across I/O.
        selector
            .update()
            .now_or_never()
            .ok_or_else(|| "NRF backend publication unexpectedly blocked".to_string())?
            .map_err(|err| err.to_string())?;
        if current.as_ref().map(|value| &value.signature)
            != selection.as_ref().map(|value| &value.signature)
        {
            *current = selection;
        }
        Ok(())
    }

    pub(super) async fn discover(
        &self,
        now: Instant,
        selector: &RuntimeUpstreamSelector,
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
                self.expire_snapshot(selector).await;
                request.await
            }
        }
    }

    pub(super) async fn record_failure(
        &self,
        now: Instant,
        selector: &RuntimeUpstreamSelector,
    ) -> Instant {
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
            self.expire_snapshot(selector).await;
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
