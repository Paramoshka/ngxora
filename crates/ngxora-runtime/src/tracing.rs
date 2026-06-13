//! OpenTelemetry distributed tracing.
//!
//! When enabled via `--otel-endpoint`, each proxied request gets a trace span
//! with W3C TraceContext propagation across upstream calls.
//!
//! The OTLP exporter (gRPC/tonic) is built lazily on the first span so that a
//! Tokio runtime is already running.

use opentelemetry::{
    InstrumentationScope, KeyValue, global,
    propagation::{Extractor, Injector},
    trace::{Span, SpanKind, Tracer, TracerProvider},
};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::{Resource, propagation::TraceContextPropagator, trace::SdkTracerProvider};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

static TRACE_CONFIG: OnceLock<(String, String)> = OnceLock::new();
static PROVIDER_INIT: AtomicBool = AtomicBool::new(false);

/// Store the OTLP endpoint and service name. The actual exporter is built
/// lazily inside the Tokio runtime.
pub fn configure(endpoint: &str, service_name: &str) {
    global::set_text_map_propagator(TraceContextPropagator::new());
    TRACE_CONFIG
        .set((endpoint.to_string(), service_name.to_string()))
        .ok();
}

fn try_init_provider() {
    if PROVIDER_INIT.swap(true, Ordering::Relaxed) {
        return;
    }

    let Some((endpoint, service_name)) = TRACE_CONFIG.get() else {
        return;
    };

    let exporter = match SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.clone())
        .build()
    {
        Ok(e) => e,
        Err(err) => {
            log::error!("failed to build OTLP span exporter: {err}");
            PROVIDER_INIT.store(false, Ordering::Relaxed);
            return;
        }
    };

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            Resource::builder()
                .with_service_name(service_name.clone())
                .build(),
        )
        .build();

    let scope = InstrumentationScope::builder("ngxora")
        .with_version(env!("CARGO_PKG_VERSION"))
        .build();
    let _ = provider.tracer_with_scope(scope);

    global::set_tracer_provider(provider);
    log::info!("OTLP tracer provider initialized, endpoint={endpoint}");
}

/// Return a reference to the global tracer (noop until `configure` + first span).
pub fn tracer() -> opentelemetry::global::BoxedTracer {
    global::tracer("ngxora")
}

/// Extract W3C `traceparent` from incoming request headers, if present.
pub fn extract_context(headers: &http::HeaderMap) -> opentelemetry::Context {
    global::get_text_map_propagator(|propagator| propagator.extract(&HeaderMapExtractor(headers)))
}

/// Inject `traceparent` into upstream request headers.
pub fn inject_context(cx: &opentelemetry::Context, headers: &mut http::HeaderMap) {
    global::get_text_map_propagator(|propagator| {
        propagator.inject_context(cx, &mut HeaderMapInjector(headers));
    });
}

/// Create a server span for an incoming request.
/// On first call triggers lazy OTLP exporter build (requires Tokio runtime).
pub fn start_request_span(
    method: &str,
    path: &str,
    parent_cx: &opentelemetry::Context,
) -> opentelemetry::global::BoxedSpan {
    try_init_provider();

    let mut span = tracer()
        .span_builder(format!("{method} {path}"))
        .with_kind(SpanKind::Server)
        .start_with_context(&tracer(), parent_cx);
    span.set_attribute(KeyValue::new("http.method", method.to_string()));
    span.set_attribute(KeyValue::new("http.route", path.to_string()));
    span
}

// ---- W3C TraceContext propagation helpers ----

struct HeaderMapExtractor<'a>(&'a http::HeaderMap);

impl<'a> Extractor for HeaderMapExtractor<'a> {
    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).and_then(|v| v.to_str().ok())
    }

    fn keys(&self) -> Vec<&str> {
        self.0.keys().map(|k| k.as_str()).collect()
    }
}

struct HeaderMapInjector<'a>(&'a mut http::HeaderMap);

impl<'a> Injector for HeaderMapInjector<'a> {
    fn set(&mut self, key: &str, value: String) {
        if let Ok(name) = http::HeaderName::from_bytes(key.as_bytes()) {
            if let Ok(val) = http::HeaderValue::from_str(&value) {
                self.0.insert(name, val);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{configure, inject_context};
    use opentelemetry::{
        Context,
        trace::{SpanContext, SpanId, TraceContextExt, TraceFlags, TraceId, TraceState},
    };

    #[test]
    fn configure_enables_w3c_tracecontext_injection() {
        configure("http://127.0.0.1:4317", "ngxora-test");

        let span_context = SpanContext::new(
            TraceId::from_hex("1234567890abcdef1234567890abcdef").expect("valid trace id"),
            SpanId::from_hex("1234567890abcdef").expect("valid span id"),
            TraceFlags::SAMPLED,
            false,
            TraceState::default(),
        );
        let cx = Context::new().with_remote_span_context(span_context);
        let mut headers = http::HeaderMap::new();

        inject_context(&cx, &mut headers);

        let traceparent = headers
            .get("traceparent")
            .and_then(|value| value.to_str().ok());
        assert_eq!(
            traceparent,
            Some("00-1234567890abcdef1234567890abcdef-1234567890abcdef-01")
        );
    }
}
