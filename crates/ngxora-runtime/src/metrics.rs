//! Prometheus metrics and structured JSON access logging.
//!
//! Metrics follow the [Prometheus naming conventions](https://prometheus.io/docs/practices/naming/):
//! - Counter for cumulative counts (requests, bytes, cache events)
//! - Histogram for distributions (latency, response size)

use pingora::apps::prometheus_http_app::PrometheusServer;
use pingora::services::listening::Service;
use pingora_proxy::Session;
use prometheus::{HistogramOpts, HistogramVec, IntCounterVec, Opts};
use serde::Serialize;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::OnceLock;

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

// ---- Metrics recording ----

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

// ---- Structured access log (JSON) ----

#[derive(Debug, Serialize)]
struct AccessLogEntry {
    method: String,
    path: String,
    status: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    latency_secs: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    upstream: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    cache_status: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    bytes_sent: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    client_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    route_id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
}

/// Write a structured JSON access log line.
pub(crate) fn write_access_log(
    session: &Session,
    method: &str,
    path: &str,
    status: u16,
    latency: Option<std::time::Duration>,
    upstream: Option<&str>,
    cache_status: Option<&str>,
    route_id: Option<u64>,
) {
    let latency_secs = latency.map(|d| d.as_secs_f64());

    let client_ip = session.as_downstream().client_addr().map(|a| a.to_string());

    let request_id = session
        .req_header()
        .headers
        .get("x-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let entry = AccessLogEntry {
        method: method.to_string(),
        path: path.to_string(),
        status,
        latency_secs,
        upstream: upstream.map(|s| s.to_string()),
        cache_status: cache_status.map(|s| s.to_string()),
        bytes_sent: None,
        client_ip,
        route_id,
        request_id,
    };

    // Write to stdout (explicit flush — Docker buffers non-tty stdout).
    if let Ok(json) = serde_json::to_string(&entry) {
        println!("{json}");
        std::io::stdout().flush().ok();
    }
}

// ---- Prometheus metrics service ----

/// Create a Pingora [Service] that serves `GET /metrics` with Prometheus metrics.
///
/// Bind it to an address via `Service::add_tcp()`.
pub fn prometheus_metrics_service() -> Service<PrometheusServer> {
    Service::prometheus_http_service()
}

/// Convenience: build and bind the metrics service to `addr`.
pub fn spawn_metrics_service(
    server: &mut pingora::server::Server,
    addr: SocketAddr,
) -> pingora::Result<()> {
    let mut svc = prometheus_metrics_service();
    svc.add_tcp(&addr.to_string());
    server.add_service(svc);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CacheStatus, RequestLabels, record_metrics};

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
            .map(|family| family.get_name().to_string())
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
}
