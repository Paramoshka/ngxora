//! OpenTelemetry distributed tracing.
//!
//! When enabled via `--otel-endpoint`, each proxied request gets a trace span
//! with W3C TraceContext propagation across upstream calls.

use opentelemetry::{
    InstrumentationScope, KeyValue, global,
    propagation::{Extractor, Injector},
    trace::{Span, SpanKind, Tracer, TracerProvider},
};
use opentelemetry_otlp::{SpanExporter, WithExportConfig};
use opentelemetry_sdk::{Resource, trace::SdkTracerProvider};

/// Initialize the OTLP tracer provider. Call once at startup.
pub fn init_tracer(endpoint: &str, service_name: &str) {
    let exporter = SpanExporter::builder()
        .with_tonic()
        .with_endpoint(endpoint.to_string())
        .build()
        .expect("failed to build OTLP span exporter");

    let provider = SdkTracerProvider::builder()
        .with_batch_exporter(exporter)
        .with_resource(
            Resource::builder()
                .with_service_name(service_name.to_string())
                .build(),
        )
        .build();

    let scope = InstrumentationScope::builder("ngxora")
        .with_version(env!("CARGO_PKG_VERSION"))
        .build();
    let _ = provider.tracer_with_scope(scope);

    global::set_tracer_provider(provider.clone());
}

/// Return a reference to the global tracer.
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
pub fn start_request_span(
    method: &str,
    path: &str,
    parent_cx: &opentelemetry::Context,
) -> opentelemetry::global::BoxedSpan {
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
