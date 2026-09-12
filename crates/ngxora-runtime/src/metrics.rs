//! Prometheus metrics and structured JSON access logging.
//!
//! Metrics follow the [Prometheus naming conventions](https://prometheus.io/docs/practices/naming/):
//! - Counter for cumulative counts (requests, bytes, cache events)
//! - Histogram for distributions (latency, response size)

use crate::admin::{admin_server, admin_server_with_state};
use crate::control::RuntimeState;
use pingora::services::listening::Service;
use pingora_proxy::Session;
use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, IntGaugeVec, Opts};
use serde::Serialize;
use std::collections::HashSet;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

// ---- Registry ----

fn metrics_registry() -> &'static prometheus::Registry {
    prometheus::default_registry()
}

// ---- Metrics definitions ----

macro_rules! metric {
    ($ctor:ident, $ctor_new:expr, $opts:expr, $labels:expr) => {{
        static CELL: OnceLock<$ctor> = OnceLock::new();
        CELL.get_or_init(|| {
            let m = $ctor_new($opts, $labels).unwrap();
            metrics_registry().register(Box::new(m.clone())).unwrap();
            m
        })
    }};
}

pub(crate) fn record_scp_event(profile: &str, event: &str) {
    metric!(
        IntCounterVec,
        IntCounterVec::new,
        Opts::new(
            "ngxora_scp_events_total",
            "SCP routing and discovery events."
        ),
        &["profile", "event"]
    )
    .with_label_values(&[profile, event])
    .inc();
}

pub(crate) fn set_scp_cache_entries(profile: &str, count: usize) {
    metric!(
        IntGaugeVec,
        IntGaugeVec::new,
        Opts::new("ngxora_scp_cache_entries", "SCP discovery cache entries."),
        &["profile"]
    )
    .with_label_values(&[profile])
    .set(count as i64);
}

/// Total number of proxied HTTP requests.
fn requests_total() -> &'static IntCounterVec {
    metric!(
        IntCounterVec,
        IntCounterVec::new,
        Opts::new(
            "ngxora_requests_total",
            "Total number of HTTP requests processed."
        ),
        &["method", "status", "cache", "has_upstream", "route_id"]
    )
}

/// Request duration in seconds (downstream → final byte).
fn request_duration_seconds() -> &'static HistogramVec {
    metric!(
        HistogramVec,
        HistogramVec::new,
        HistogramOpts::new(
            "ngxora_request_duration_seconds",
            "Request duration from first byte received to final byte sent."
        ),
        &["method", "status", "cache", "has_upstream", "route_id"]
    )
}

/// Bytes sent in upstream request bodies.
fn upstream_request_bytes_total() -> &'static IntCounterVec {
    metric!(
        IntCounterVec,
        IntCounterVec::new,
        Opts::new(
            "ngxora_upstream_request_bytes_total",
            "Total bytes sent to upstream in request bodies."
        ),
        &["method", "status", "cache", "has_upstream", "route_id"]
    )
}

/// Bytes received in upstream response bodies.
fn upstream_response_bytes_total() -> &'static IntCounterVec {
    metric!(
        IntCounterVec,
        IntCounterVec::new,
        Opts::new(
            "ngxora_upstream_response_bytes_total",
            "Total bytes received from upstream in response bodies."
        ),
        &["method", "status", "cache", "has_upstream", "route_id"]
    )
}

/// Cache hit counter.
fn cache_hits_total() -> &'static IntCounterVec {
    metric!(
        IntCounterVec,
        IntCounterVec::new,
        Opts::new("ngxora_cache_hits_total", "Total number of cache hits."),
        &["method", "status", "cache", "has_upstream", "route_id"]
    )
}

/// Cache miss counter.
fn cache_misses_total() -> &'static IntCounterVec {
    metric!(
        IntCounterVec,
        IntCounterVec::new,
        Opts::new("ngxora_cache_misses_total", "Total number of cache misses."),
        &["method", "status", "cache", "has_upstream", "route_id"]
    )
}

fn upstream_backend_requests_total() -> &'static IntCounterVec {
    metric!(
        IntCounterVec,
        IntCounterVec::new,
        Opts::new(
            "ngxora_upstream_backend_requests_total",
            "Total requests sent to a configured upstream backend."
        ),
        &["upstream_group", "backend", "status_class"]
    )
}

fn upstream_backend_request_duration_seconds() -> &'static HistogramVec {
    metric!(
        HistogramVec,
        HistogramVec::new,
        HistogramOpts::new(
            "ngxora_upstream_backend_request_duration_seconds",
            "End-to-end request duration for requests sent to an upstream backend."
        ),
        &["upstream_group", "backend"]
    )
}

fn upstream_backend_ready() -> &'static IntGaugeVec {
    metric!(
        IntGaugeVec,
        IntGaugeVec::new,
        Opts::new(
            "ngxora_upstream_backend_ready",
            "Whether a configured upstream backend is healthy and enabled."
        ),
        &["upstream_group", "backend"]
    )
}

fn nrf_discovery_requests_total() -> &'static IntCounterVec {
    metric!(
        IntCounterVec,
        IntCounterVec::new,
        Opts::new(
            "ngxora_nrf_discovery_requests_total",
            "Total NRF discovery requests by outcome."
        ),
        &["upstream_group", "result"]
    )
}

fn nrf_discovery_snapshot_age_seconds() -> &'static IntGaugeVec {
    metric!(
        IntGaugeVec,
        IntGaugeVec::new,
        Opts::new(
            "ngxora_nrf_discovery_snapshot_age_seconds",
            "Age of the last successful NRF discovery snapshot in seconds."
        ),
        &["upstream_group"]
    )
}

fn nrf_discovery_endpoints() -> &'static IntGaugeVec {
    metric!(
        IntGaugeVec,
        IntGaugeVec::new,
        Opts::new(
            "ngxora_nrf_discovery_endpoints",
            "Number of NRF-discovered endpoints published for traffic."
        ),
        &["upstream_group"]
    )
}

fn readiness_series() -> &'static std::sync::Mutex<HashSet<(String, String)>> {
    static SERIES: OnceLock<std::sync::Mutex<HashSet<(String, String)>>> = OnceLock::new();
    SERIES.get_or_init(|| std::sync::Mutex::new(HashSet::new()))
}

// ---- Metrics recording ----

pub(crate) fn record_nrf_discovery_request(group: &str, result: &str) {
    nrf_discovery_requests_total()
        .with_label_values(&[group, result])
        .inc();
}

pub(crate) fn set_nrf_discovery_snapshot(group: &str, age: Duration, endpoints: usize) {
    nrf_discovery_snapshot_age_seconds()
        .with_label_values(&[group])
        .set(age.as_secs().try_into().unwrap_or(i64::MAX));
    nrf_discovery_endpoints()
        .with_label_values(&[group])
        .set(endpoints.try_into().unwrap_or(i64::MAX));
}

/// Common labels attached to every metric.
#[derive(Debug, Clone)]
pub(crate) struct RequestLabels {
    pub method: String,
    pub status: String,
    pub cache_status: CacheStatus,
    /// Whether an upstream peer was used (vs. served from cache / redirect / plugin response).
    pub has_upstream: bool,
    /// Route ID for per-route metrics.
    pub route_id: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum CacheStatus {
    Hit,
    Miss,
    Bypass,
}

impl CacheStatus {
    fn as_str(&self) -> &'static str {
        match self {
            CacheStatus::Hit => "hit",
            CacheStatus::Miss => "miss",
            CacheStatus::Bypass => "bypass",
        }
    }
}

/// Record metrics at the end of a request.
pub(crate) fn record_metrics(
    labels: &RequestLabels,
    latency_secs: f64,
    request_body_bytes: u64,
    response_body_bytes: u64,
) {
    let route_id_str = labels.route_id.to_string();
    let label_values = [
        labels.method.as_str(),
        labels.status.as_str(),
        labels.cache_status.as_str(),
        if labels.has_upstream { "true" } else { "false" },
        route_id_str.as_str(),
    ];

    requests_total().with_label_values(&label_values).inc();
    request_duration_seconds()
        .with_label_values(&label_values)
        .observe(latency_secs);
    upstream_request_bytes_total()
        .with_label_values(&label_values)
        .inc_by(request_body_bytes);
    upstream_response_bytes_total()
        .with_label_values(&label_values)
        .inc_by(response_body_bytes);

    match labels.cache_status {
        CacheStatus::Hit => cache_hits_total().with_label_values(&label_values).inc(),
        CacheStatus::Miss => cache_misses_total().with_label_values(&label_values).inc(),
        CacheStatus::Bypass => {}
    }
}

pub(crate) fn record_upstream_backend_metrics(
    upstream_group: &str,
    backend: &str,
    status: u16,
    latency_secs: f64,
) {
    let status_class = match status {
        100..=199 => "1xx",
        200..=299 => "2xx",
        300..=399 => "3xx",
        400..=499 => "4xx",
        500..=599 => "5xx",
        _ => "error",
    };
    upstream_backend_requests_total()
        .with_label_values(&[upstream_group, backend, status_class])
        .inc();
    upstream_backend_request_duration_seconds()
        .with_label_values(&[upstream_group, backend])
        .observe(latency_secs);
}

pub(crate) fn replace_upstream_backend_readiness(
    readiness: impl IntoIterator<Item = (String, String, bool)>,
) {
    let gauge = upstream_backend_ready();
    let mut current = HashSet::new();
    for (group, backend, ready) in readiness {
        gauge
            .with_label_values(&[group.as_str(), backend.as_str()])
            .set(i64::from(ready));
        current.insert((group, backend));
    }

    let mut previous = readiness_series()
        .lock()
        .expect("upstream readiness metrics lock poisoned");
    for (group, backend) in previous.difference(&current) {
        let _ = gauge.remove_label_values(&[group.as_str(), backend.as_str()]);
    }
    *previous = current;
}

// ---- Structured access log (JSON) ----

#[derive(Debug, Serialize)]
struct AccessLogEntry {
    #[serde(flatten)]
    geoip: crate::geoip::GeoIpRecord,
    method: String,
    path: String,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_secs: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream_group: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_sent: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    peer_addr: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    route_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nf_instance_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    nf_service_instance_id: Option<String>,
}

/// Write a structured JSON access log line.
pub(crate) struct AccessLogContext<'a> {
    pub client_ip: Option<std::net::IpAddr>,
    pub geoip: &'a crate::geoip::GeoIpRecord,
    pub method: &'a str,
    pub path: &'a str,
    pub status: u16,
    pub latency: Option<std::time::Duration>,
    pub upstream: Option<&'a str>,
    pub upstream_group: Option<&'a str>,
    pub cache_status: Option<&'a str>,
    pub route_id: Option<u64>,
    pub nf: Option<&'a crate::upstreams::NrfServiceMetadata>,
}

pub(crate) fn write_access_log(session: &Session, context: AccessLogContext<'_>) {
    let AccessLogContext {
        client_ip,
        geoip,
        method,
        path,
        status,
        latency,
        upstream,
        upstream_group,
        cache_status,
        route_id,
        nf,
    } = context;
    let latency_secs = latency.map(|d| d.as_secs_f64());

    let peer_addr = session.as_downstream().client_addr().map(|a| a.to_string());
    let client_ip = client_ip.map(|ip| ip.to_string());

    let request_id = session
        .req_header()
        .headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let entry = AccessLogEntry {
        geoip: geoip.clone(),
        method: method.to_string(),
        path: path.to_string(),
        status,
        latency_secs,
        upstream: upstream.map(|s| s.to_string()),
        upstream_group: upstream_group.map(|s| s.to_string()),
        cache_status: cache_status.map(|s| s.to_string()),
        bytes_sent: None,
        client_ip,
        route_id,
        peer_addr,
        request_id,
        nf_instance_id: nf.map(|m| m.nf_instance_id.clone()),
        nf_service_instance_id: nf.map(|m| m.service_instance_id.clone()),
    };

    // Write to stdout (explicit flush — Docker buffers non-tty stdout).
    if let Ok(json) = serde_json::to_string(&entry) {
        println!("{json}");
        std::io::stdout().flush().ok();
    }
}

// ---- Prometheus metrics service ----

/// Compatibility helper without runtime readiness state.
///
/// Serves metrics and liveness normally; `GET /readyz` returns `503`.
pub fn spawn_metrics_service(
    server: &mut pingora::server::Server,
    addr: SocketAddr,
) -> pingora::Result<()> {
    let mut svc = Service::new("Admin HTTP".to_string(), admin_server());
    svc.add_tcp(&addr.to_string());
    server.add_service(svc);
    Ok(())
}

/// Build the admin service with readiness tied to the active runtime state.
pub fn spawn_metrics_service_with_state(
    server: &mut pingora::server::Server,
    addr: SocketAddr,
    state: Arc<RuntimeState>,
) -> pingora::Result<()> {
    let mut svc = Service::new("Admin HTTP".to_string(), admin_server_with_state(state));
    svc.add_tcp(&addr.to_string());
    server.add_service(svc);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        CacheStatus, RequestLabels, record_metrics, record_nrf_discovery_request,
        record_upstream_backend_metrics, replace_upstream_backend_readiness,
        set_nrf_discovery_snapshot,
    };
    use std::time::Duration;

    #[test]
    fn record_metrics_registers_collectors_in_default_registry() {
        record_metrics(
            &RequestLabels {
                method: "GET".into(),
                status: "200".into(),
                cache_status: CacheStatus::Miss,
                has_upstream: true,
                route_id: 7,
            },
            0.125,
            32,
            64,
        );

        let metric_names = prometheus::gather()
            .into_iter()
            .map(|family| family.name().to_string())
            .collect::<Vec<_>>();

        assert!(
            metric_names
                .iter()
                .any(|name| name == "ngxora_requests_total")
        );
        assert!(
            metric_names
                .iter()
                .any(|name| name == "ngxora_request_duration_seconds")
        );
        assert!(
            metric_names
                .iter()
                .any(|name| name == "ngxora_upstream_request_bytes_total")
        );
        assert!(
            metric_names
                .iter()
                .any(|name| name == "ngxora_upstream_response_bytes_total")
        );
        assert!(
            metric_names
                .iter()
                .any(|name| name == "ngxora_cache_misses_total")
        );
    }

    #[test]
    fn upstream_backend_metrics_register_request_duration_and_readiness() {
        record_upstream_backend_metrics("sbi", "127.0.0.1:8080", 200, 0.025);
        replace_upstream_backend_readiness([(
            "sbi".to_string(),
            "127.0.0.1:8080".to_string(),
            true,
        )]);

        let metric_names = prometheus::gather()
            .into_iter()
            .map(|family| family.name().to_string())
            .collect::<Vec<_>>();
        for expected in [
            "ngxora_upstream_backend_requests_total",
            "ngxora_upstream_backend_request_duration_seconds",
            "ngxora_upstream_backend_ready",
        ] {
            assert!(metric_names.iter().any(|name| name == expected));
        }
    }

    #[test]
    fn nrf_discovery_metrics_register_outcomes_and_snapshot() {
        record_nrf_discovery_request("smf", "success");
        record_nrf_discovery_request("smf", "error");
        set_nrf_discovery_snapshot("smf", Duration::from_secs(3), 2);

        let metric_names = prometheus::gather()
            .into_iter()
            .map(|family| family.name().to_string())
            .collect::<Vec<_>>();
        for expected in [
            "ngxora_nrf_discovery_requests_total",
            "ngxora_nrf_discovery_snapshot_age_seconds",
            "ngxora_nrf_discovery_endpoints",
        ] {
            assert!(metric_names.iter().any(|name| name == expected));
        }
    }
}
