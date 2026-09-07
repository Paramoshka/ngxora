//! NRF configuration validation and live endpoint publication.

use crate::upstreams::{
    CompiledHealthCheck, CompiledNrfDiscovery, CompiledRouter, CompiledUpstreamGroup,
    HealthCheckType,
};
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use ngxora_compile::ir::{
    Http, Listen, Location, LocationDirective, LocationMatcher, NrfDiscovery, NrfEndpointScheme,
    PemSource, ProxyPassTarget, Server, UpstreamBlock, UpstreamHealthCheck,
    UpstreamHealthCheckType, UpstreamSelectionPolicy, UpstreamSslOptions,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;

fn http_with_nrf_upstream(
    api_root: &str,
    endpoint_scheme: NrfEndpointScheme,
    proxy_pass: &str,
) -> Http {
    Http {
        upstreams: vec![UpstreamBlock {
            allow_empty: false,
            name: "smf_pool".into(),
            policy: UpstreamSelectionPolicy::RoundRobin,
            hash_key: None,
            servers: Vec::new(),
            nrf_discovery: Some(NrfDiscovery {
                api_root: api_root.into(),
                target_nf_type: "SMF".into(),
                requester_nf_type: "SCP".into(),
                service_name: "nsmf-pdusession".into(),
                endpoint_scheme,
                timeout: Duration::from_secs(3),
                stale_if_error: Duration::from_secs(60),
                tls_options: UpstreamSslOptions::default(),
            }),
            health_check: Some(UpstreamHealthCheck {
                check_type: UpstreamHealthCheckType::Tcp,
                timeout: Duration::from_secs(1),
                interval: Duration::from_secs(5),
                consecutive_success: 1,
                consecutive_failure: 1,
            }),
        }],
        servers: vec![Server {
            listens: vec![Listen {
                default_server: true,
                ..Listen::default()
            }],
            locations: vec![Location {
                matcher: LocationMatcher::Prefix("/".into()),
                directives: vec![LocationDirective::ProxyPass(ProxyPassTarget::Url(
                    proxy_pass.parse().unwrap(),
                ))],
                access_rules: Vec::new(),
                plugins: Vec::new(),
                cache: None,
            }],
            ..Server::default()
        }],
        ..Http::default()
    }
}

#[test]
fn compiled_router_rejects_nrf_api_root_query() {
    let http = http_with_nrf_upstream(
        "https://nrf.internal/nnrf-disc/v1?tenant=a",
        NrfEndpointScheme::Https,
        "https://smf_pool",
    );

    let error = CompiledRouter::from_http(&http).expect_err("query must be rejected");
    assert!(error.contains("must not contain a query or fragment"));
}

#[test]
fn compiled_router_rejects_nrf_route_scheme_mismatch() {
    let http = http_with_nrf_upstream(
        "https://nrf.internal/nnrf-disc/v1",
        NrfEndpointScheme::Https,
        "http://smf_pool",
    );

    let error = CompiledRouter::from_http(&http).expect_err("route scheme must match");
    assert!(error.contains("must match endpoint_scheme https"));
}

#[test]
fn compiled_router_rejects_incomplete_nrf_client_identity() {
    let mut http = http_with_nrf_upstream(
        "https://nrf.internal/nnrf-disc/v1",
        NrfEndpointScheme::Https,
        "https://smf_pool",
    );
    http.upstreams[0]
        .nrf_discovery
        .as_mut()
        .unwrap()
        .tls_options
        .client_certificate = Some(PemSource::InlinePem("certificate".into()));

    let error = CompiledRouter::from_http(&http).expect_err("identity pair must be required");
    assert!(error.contains("must be configured together"));
}

#[tokio::test]
async fn nrf_discovery_preflights_and_publishes_reachable_backend() {
    let producer = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind producer");
    let producer_port = producer.local_addr().unwrap().port();
    let nrf = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mock NRF");
    let nrf_addr = nrf.local_addr().unwrap();
    let body = serde_json::json!({
        "validityPeriod": 30,
        "nfInstances": [{
            "nfInstanceId": "smf-instance-1",
            "nfStatus": "REGISTERED",
            "nfServices": [{
                "serviceInstanceId": "nsmf-pdusession-1",
                "serviceName": "nsmf-pdusession",
                "scheme": "http",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [{"ipv4Address": "127.0.0.1", "port": producer_port}]
            }]
        }]
    })
    .to_string();
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();
    let request_tx = Arc::new(Mutex::new(Some(request_tx)));
    let mock = tokio::spawn(async move {
        let (socket, _) = nrf.accept().await.expect("accept NRF request");
        let service = service_fn(move |request: Request<Incoming>| {
            let body = body.clone();
            let request_tx = Arc::clone(&request_tx);
            async move {
                if let Some(request_tx) = request_tx.lock().unwrap().take() {
                    let _ = request_tx.send(request.uri().to_string());
                }
                Ok::<_, std::convert::Infallible>(
                    Response::builder()
                        .header("content-type", "application/json")
                        .body(Full::new(Bytes::from(body)))
                        .unwrap(),
                )
            }
        });
        let mut connection = Box::pin(
            http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(socket), service),
        );
        let request = tokio::select! {
            result = &mut connection => panic!("NRF connection ended early: {result:?}"),
            request = request_rx => request.expect("observe NRF request"),
        };
        connection.as_mut().graceful_shutdown();
        connection.await.expect("serve NRF response");
        request
    });

    let group = crate::upstreams::RuntimeUpstreamGroup::from_compiled(&CompiledUpstreamGroup {
        allow_empty: false,
        name: "smf_pool".into(),
        policy: UpstreamSelectionPolicy::RoundRobin,
        hash_key: None,
        servers: Vec::new(),
        nrf_discovery: Some(CompiledNrfDiscovery {
            api_root: format!("http://{nrf_addr}/nnrf-disc/v1").parse().unwrap(),
            target_nf_type: "SMF".into(),
            requester_nf_type: "SCP".into(),
            service_name: "nsmf-pdusession".into(),
            endpoint_scheme: NrfEndpointScheme::Http,
            timeout: Duration::from_secs(2),
            stale_if_error: Duration::from_secs(60),
            tls_options: UpstreamSslOptions::default(),
        }),
        health_check: Some(CompiledHealthCheck {
            check_type: HealthCheckType::Tcp,
            timeout: Duration::from_secs(1),
            interval: Duration::from_secs(5),
            consecutive_success: 1,
            consecutive_failure: 1,
        }),
    })
    .expect("build NRF upstream");

    let started_at = tokio::time::Instant::now();
    assert!(group.select(&[]).is_none());
    group
        .run_due_nrf_discovery(started_at)
        .await
        .expect("NRF discovery configured");
    let selected = group.select(&[]).expect("discovered backend selected");
    assert_eq!(selected.host, "127.0.0.1");
    assert_eq!(selected.port, producer_port);

    let request = mock.await.expect("mock NRF task");
    assert!(request.contains("target-nf-type=SMF"));
    assert!(request.contains("requester-nf-type=SCP"));
    assert!(request.contains("service-names=nsmf-pdusession"));

    group
        .run_due_nrf_discovery(started_at + Duration::from_secs(31))
        .await
        .expect("NRF discovery configured");
    assert!(
        group.select(&[]).is_some(),
        "last-known-good snapshot must remain available during stale window"
    );

    group
        .run_due_nrf_discovery(started_at + Duration::from_secs(91))
        .await
        .expect("NRF discovery configured");
    assert!(
        group.select(&[]).is_none(),
        "expired discovery snapshot must fail closed"
    );
}
