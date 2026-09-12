//! Request completion: emit telemetry and commit only complete, cacheable responses.

use super::cache_store_allowed;
use super::{DynamicProxy, ProxyContext, SelectedTarget};
use opentelemetry::trace::Span;
use pingora_proxy::Session;

pub(super) fn should_mark_span_as_error(e: Option<&pingora::Error>, status: u16) -> bool {
    if status >= 500 {
        return true;
    }

    matches!(
        e,
        Some(err) if !matches!(err.etype, pingora::ErrorType::HTTPStatus(_))
    )
}

impl DynamicProxy {
    /// Store cacheable responses when the request completes, record metrics,
    /// and emit the structured access log.
    pub(super) async fn finish_request(
        &self,
        session: &mut Session,
        e: Option<&pingora::Error>,
        ctx: &mut ProxyContext,
    ) {
        // ── Collect observability data ──
        let method = session.req_header().method.to_string();
        let path = session.req_header().uri.path().to_string();
        let status = session
            .response_written()
            .map(|r| r.status.as_u16())
            .or_else(|| {
                e.and_then(|err| match &err.etype {
                    pingora::ErrorType::HTTPStatus(code) => Some(*code),
                    _ => None,
                })
            })
            .unwrap_or(0);
        let latency = ctx.start_time.elapsed();
        let upstream = ctx.selected.as_ref().and_then(|s| match &s.target {
            SelectedTarget::Scp(_) => ctx.scp.as_ref().map(|e| e.root.value()),
            SelectedTarget::Upstream(peer) => Some(format!("{}:{}", peer.host, peer.port)),
            SelectedTarget::Return { .. }
            | SelectedTarget::Pending(_)
            | SelectedTarget::DirectResponse(_) => None,
        });
        let upstream_group = ctx.selected.as_ref().and_then(|s| match &s.target {
            SelectedTarget::Scp(name) => Some(name.as_str()),
            SelectedTarget::Upstream(peer) => peer.upstream_group.as_deref(),
            SelectedTarget::Return { .. }
            | SelectedTarget::Pending(_)
            | SelectedTarget::DirectResponse(_) => None,
        });
        let route_id = ctx.selected.as_ref().map(|s| s.route_id());

        // Cache status: hit when served from cache in request_filter, miss
        // when a cache key exists but we went upstream, bypass otherwise.
        let had_upstream = !matches!(
            ctx.selected.as_ref().map(|s| &s.target),
            Some(SelectedTarget::Return { .. }) | None
        ) && e.is_none();
        let cache_status = if ctx.cache_hit {
            "hit"
        } else if e.is_some() {
            "bypass"
        } else if ctx.cache_key.is_some() {
            "miss"
        } else {
            "bypass"
        };

        // ── Set trace span attributes ──
        if let Some(ref mut span) = ctx.span {
            span.set_attribute(opentelemetry::KeyValue::new(
                "http.status_code",
                status as i64,
            ));
            span.set_attribute(opentelemetry::KeyValue::new("http.method", method.clone()));
            span.set_attribute(opentelemetry::KeyValue::new("http.route", path.clone()));
            if let Some(ref u) = upstream {
                span.set_attribute(opentelemetry::KeyValue::new("upstream", u.clone()));
            }
            span.set_attribute(opentelemetry::KeyValue::new(
                "cache.status",
                cache_status.to_string(),
            ));
            if should_mark_span_as_error(e, status) {
                span.set_status(opentelemetry::trace::Status::error("proxy error"));
            }
            span.end();
        }

        // ── Write structured JSON access log ──
        if method != "GET" || path != "/metrics" {
            crate::metrics::write_access_log(
                session,
                crate::metrics::AccessLogContext {
                    client_ip: ctx.client_ip,
                    geoip: &ctx.geoip,
                    method: &method,
                    path: &path,
                    status,
                    latency: Some(latency),
                    upstream: upstream.as_deref(),
                    upstream_group,
                    cache_status: Some(cache_status),
                    route_id,
                    nf: ctx
                        .scp
                        .as_ref()
                        .and_then(|e| e.backend.nrf_service.as_ref()),
                },
            );
        }

        // ── Record Prometheus metrics ──
        let cache_metric_status = match cache_status {
            "hit" => crate::metrics::CacheStatus::Hit,
            "miss" => crate::metrics::CacheStatus::Miss,
            _ => crate::metrics::CacheStatus::Bypass,
        };
        crate::metrics::record_metrics(
            &crate::metrics::RequestLabels {
                method: method.clone(),
                status: status.to_string(),
                cache_status: cache_metric_status,
                has_upstream: had_upstream,
                route_id: route_id.unwrap_or(0),
            },
            latency.as_secs_f64(),
            0,
            ctx.response_body_buf.len() as u64,
        );
        if ctx.upstream_attempted
            && ctx.scp_profile.is_none()
            && let (Some(group), Some(backend)) = (upstream_group, upstream.as_deref())
        {
            crate::metrics::record_upstream_backend_metrics(
                group,
                backend,
                status,
                latency.as_secs_f64(),
            );
        }

        self.cache_backend
            .advance_generation(self.state.generation());
        // ── Original cache-store logic ──
        if e.is_some() {
            ctx.cache_headers = None;
            ctx.cache_status = None;
            ctx.cache_body_limit = None;
            ctx.response_body_buf.clear();
            return;
        }

        if let (Some(cache_key), Some(cache_cfg)) = (
            &ctx.cache_key,
            ctx.selected.as_ref().and_then(|s| s.cache.as_ref()),
        ) {
            if !cache_store_allowed(cache_cfg, ctx.cache_store_allowed) {
                ctx.cache_headers = None;
                ctx.cache_status = None;
                ctx.cache_body_limit = None;
                ctx.response_body_buf.clear();
                return;
            }

            if let (Some(status), Some(headers)) = (ctx.cache_status, ctx.cache_headers.take()) {
                let body = std::mem::take(&mut ctx.response_body_buf).freeze();
                self.cache_backend
                    .put(
                        cache_key.clone(),
                        crate::cache::CachedResponse {
                            status,
                            headers,
                            body,
                            created_at: std::time::Instant::now(),
                        },
                        cache_cfg,
                    )
                    .await;
            }
        }
    }
}
