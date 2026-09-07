use super::*;
use bytes::Bytes;
use http_body_util::Full;
use hyper::body::Incoming;
use hyper::server::conn::http2;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Version};
use hyper_util::rt::{TokioExecutor, TokioIo};
use ngxora_compile::ir::UpstreamSslOptions;
use std::sync::{Arc, Mutex};

async fn spawn_h2_response(
    status: StatusCode,
    body: impl Into<Bytes>,
    location: Option<&str>,
    client_may_disconnect: bool,
) -> (
    std::net::SocketAddr,
    tokio::task::JoinHandle<(Version, String)>,
) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind h2 test server");
    let addr = listener.local_addr().expect("h2 test server address");
    let body = body.into();
    let location = location.map(str::to_string);
    let (request_tx, request_rx) = tokio::sync::oneshot::channel();
    let request_tx = Arc::new(Mutex::new(Some(request_tx)));
    let task = tokio::spawn(async move {
        let (socket, _) = listener.accept().await.expect("accept h2 request");
        let service = service_fn(move |request: Request<Incoming>| {
            let body = body.clone();
            let location = location.clone();
            let request_tx = Arc::clone(&request_tx);
            async move {
                if let Some(request_tx) = request_tx.lock().unwrap().take() {
                    let _ = request_tx.send((request.version(), request.uri().to_string()));
                }
                let mut response = Response::builder().status(status);
                if let Some(location) = location {
                    response = response.header("location", location);
                }
                Ok::<_, std::convert::Infallible>(
                    response.body(Full::new(body)).expect("build h2 response"),
                )
            }
        });
        let mut connection = Box::pin(
            http2::Builder::new(TokioExecutor::new())
                .serve_connection(TokioIo::new(socket), service),
        );
        let request = tokio::select! {
            result = &mut connection => panic!("h2 connection ended early: {result:?}"),
            request = request_rx => request.expect("observe h2 request"),
        };
        connection.as_mut().graceful_shutdown();
        let result = connection.await;
        if !client_may_disconnect {
            result.expect("serve h2 response");
        }
        request
    });
    (addr, task)
}

fn http_config(addr: std::net::SocketAddr) -> CompiledNrfDiscovery {
    CompiledNrfDiscovery {
        api_root: format!("http://{addr}/nnrf-disc/v1").parse().unwrap(),
        endpoint_scheme: NrfEndpointScheme::Http,
        ..config()
    }
}

fn config() -> CompiledNrfDiscovery {
    CompiledNrfDiscovery {
        api_root: "https://nrf.example/nnrf-disc/v1".parse().unwrap(),
        target_nf_type: "SMF".into(),
        requester_nf_type: "SCP".into(),
        service_name: "nsmf-pdusession".into(),
        endpoint_scheme: NrfEndpointScheme::Https,
        timeout: Duration::from_secs(3),
        stale_if_error: Duration::from_secs(60),
        tls_options: UpstreamSslOptions::default(),
    }
}

fn metadata(
    nf_instance_id: &str,
    service_instance_id: &str,
    priority: u16,
    capacity: u16,
) -> NrfServiceMetadata {
    NrfServiceMetadata {
        authority: None,
        nf_instance_id: nf_instance_id.into(),
        service_instance_id: service_instance_id.into(),
        priority,
        capacity,
    }
}

#[test]
fn filters_unregistered_wrong_service_and_invalid_api_prefix() {
    let profiles = serde_json::from_value::<SearchResult>(serde_json::json!({
        "validityPeriod": 30,
        "nfInstances": [{
            "nfInstanceId": "nf-filter",
            "nfStatus": "REGISTERED",
            "fqdn": "smf.example",
            "nfServices": [
                {"serviceInstanceId":"wrong","serviceName":"wrong","scheme":"https","nfServiceStatus":"REGISTERED"},
                {"serviceInstanceId":"suspended","serviceName":"nsmf-pdusession","scheme":"https","nfServiceStatus":"SUSPENDED"},
                {"serviceInstanceId":"bad-prefix","serviceName":"nsmf-pdusession","scheme":"https","nfServiceStatus":"REGISTERED","apiPrefix":"edge"},
                {"serviceInstanceId":"valid","serviceName":"nsmf-pdusession","scheme":"https","nfServiceStatus":"REGISTERED","ipEndPoints":[{"port":8443}]}
            ]
        }]
    }))
    .unwrap()
    .nf_instances;

    assert_eq!(
        extract_endpoints(&config(), profiles),
        vec![CompiledUpstreamServer {
            host: "smf.example".into(),
            port: 8443,
            weight: 1,
            api_prefix: None,
            nrf_service: Some(metadata("nf-filter", "valid", u16::MAX, 1)),
        }]
    );
}

#[test]
fn delegated_query_filters_nrf_profiles_locally_and_preserves_fqdn_with_ip() {
    let profile = serde_json::json!({
        "nfInstanceId":"nf-a", "nfType":"SMF", "nfStatus":"REGISTERED",
        "nfServiceList": { "service-a": {
            "serviceInstanceId":"service-a", "serviceName":"nsmf-pdusession",
            "nfServiceStatus":"REGISTERED", "scheme":"https", "fqdn":"nf.test",
            "versions":[{"apiVersionInUri":"v1"}], "apiPrefix":"/edge",
            "ipEndPoints":[{"ipv4Address":"192.0.2.10", "port":8443}]
        }}
    });
    let query = NrfQuery {
        nf_instance_id: Some("nf-a".into()),
        service_instance_id: Some("service-a".into()),
        api_version: "v1".into(),
        service_names: vec!["nsmf-pdusession".into()],
        ..Default::default()
    };
    let extract = |profile: serde_json::Value, query: &NrfQuery| {
        extract_query_endpoints(
            &config(),
            vec![serde_json::from_value(profile).unwrap()],
            Some(query),
        )
    };
    let (backends, invalid_api) = extract(profile.clone(), &query);
    assert!(!invalid_api);
    assert_eq!(backends.len(), 1);
    assert_eq!(backends[0].host, "192.0.2.10");
    assert_eq!(
        backends[0]
            .nrf_service
            .as_ref()
            .unwrap()
            .authority
            .as_deref(),
        Some("nf.test")
    );
    for (field, value) in [
        ("nfType", "UDM"),
        ("nfInstanceId", "nf-b"),
        ("nfStatus", "SUSPENDED"),
    ] {
        let mut bad = profile.clone();
        bad[field] = value.into();
        assert_eq!(extract(bad, &query), (vec![], false));
    }
    for (field, value) in [
        ("serviceInstanceId", "wrong-key"),
        ("nfServiceStatus", "SUSPENDED"),
        ("fqdn", "nf.test/escape"),
        ("apiPrefix", "/edge/../private"),
    ] {
        let mut bad = profile.clone();
        bad["nfServiceList"]["service-a"][field] = value.into();
        assert_eq!(extract(bad, &query), (vec![], false));
    }
    assert_eq!(
        extract(
            profile.clone(),
            &NrfQuery {
                api_version: "v2".into(),
                ..query.clone()
            }
        ),
        (vec![], true)
    );
    assert_eq!(
        extract(
            profile,
            &NrfQuery {
                service_instance_id: Some("other".into()),
                ..query
            }
        ),
        (vec![], false)
    );
}

#[test]
fn preserves_distinct_normalized_api_prefixes_for_the_same_endpoint() {
    let profiles = serde_json::from_value::<SearchResult>(serde_json::json!({
        "nfInstances": [{
            "nfInstanceId": "nf-prefix",
            "nfStatus": "REGISTERED",
            "nfServices": [
                {
                    "serviceInstanceId": "edge-a",
                    "serviceName": "nsmf-pdusession",
                    "scheme": "https",
                    "nfServiceStatus": "REGISTERED",
                    "apiPrefix": "/edge/a/",
                    "ipEndPoints": [{"ipv4Address":"192.0.2.30","port":8443}]
                },
                {
                    "serviceInstanceId": "edge-b",
                    "serviceName": "nsmf-pdusession",
                    "scheme": "https",
                    "nfServiceStatus": "REGISTERED",
                    "apiPrefix": "/edge/b",
                    "ipEndPoints": [{"ipv4Address":"192.0.2.30","port":8443}]
                }
            ]
        }]
    }))
    .unwrap()
    .nf_instances;

    assert_eq!(
        extract_endpoints(&config(), profiles),
        vec![
            CompiledUpstreamServer {
                host: "192.0.2.30".into(),
                port: 8443,
                weight: 1,
                api_prefix: Some("/edge/a".into()),
                nrf_service: Some(metadata("nf-prefix", "edge-a", u16::MAX, 1)),
            },
            CompiledUpstreamServer {
                host: "192.0.2.30".into(),
                port: 8443,
                weight: 1,
                api_prefix: Some("/edge/b".into()),
                nrf_service: Some(metadata("nf-prefix", "edge-b", u16::MAX, 1)),
            },
        ]
    );
}

#[test]
fn validates_and_normalizes_api_prefix() {
    assert_eq!(normalize_api_prefix(None).unwrap(), None);
    assert_eq!(normalize_api_prefix(Some("")).unwrap(), None);
    assert_eq!(normalize_api_prefix(Some("/")).unwrap(), None);
    assert_eq!(
        normalize_api_prefix(Some("/operator/edge/")).unwrap(),
        Some("/operator/edge".into())
    );

    for invalid in [
        "edge",
        "//edge",
        "/edge?tenant=a",
        "/edge#fragment",
        "/bad path",
    ] {
        assert!(
            normalize_api_prefix(Some(invalid)).is_err(),
            "prefix {invalid:?} must be rejected"
        );
    }
}

#[test]
fn service_selection_metadata_overrides_profile_defaults() {
    let profiles = serde_json::from_value::<SearchResult>(serde_json::json!({
        "nfInstances": [{
            "nfInstanceId": "nf-metadata",
            "nfStatus": "REGISTERED",
            "priority": 20,
            "capacity": 30,
            "nfServices": [
                {
                    "serviceInstanceId": "inherits",
                    "serviceName": "nsmf-pdusession",
                    "scheme": "https",
                    "nfServiceStatus": "REGISTERED",
                    "ipEndPoints": [{"ipv4Address":"192.0.2.40","port":8443}]
                },
                {
                    "serviceInstanceId": "overrides",
                    "serviceName": "nsmf-pdusession",
                    "scheme": "https",
                    "nfServiceStatus": "REGISTERED",
                    "priority": 5,
                    "capacity": 7,
                    "ipEndPoints": [{"ipv4Address":"192.0.2.41","port":8443}]
                },
                {
                    "serviceInstanceId": "invalid",
                    "serviceName": "nsmf-pdusession",
                    "scheme": "https",
                    "nfServiceStatus": "REGISTERED",
                    "priority": 65536,
                    "ipEndPoints": [{"ipv4Address":"192.0.2.42","port":8443}]
                }
            ]
        }]
    }))
    .unwrap()
    .nf_instances;

    let endpoints = extract_endpoints(&config(), profiles);

    assert_eq!(endpoints.len(), 2);
    assert_eq!(
        endpoints
            .iter()
            .find(|endpoint| endpoint.host == "192.0.2.41")
            .unwrap()
            .nrf_service
            .clone(),
        Some(metadata("nf-metadata", "overrides", 5, 7))
    );
    assert_eq!(
        endpoints
            .iter()
            .find(|endpoint| endpoint.host == "192.0.2.40")
            .unwrap()
            .nrf_service
            .clone(),
        Some(metadata("nf-metadata", "inherits", 20, 30))
    );
}

#[test]
fn skips_registered_profiles_and_services_without_ids() {
    let profiles = serde_json::from_value::<SearchResult>(serde_json::json!({
        "nfInstances": [
            {
                "nfStatus": "REGISTERED",
                "nfServices": [{
                    "serviceInstanceId": "service",
                    "serviceName": "nsmf-pdusession",
                    "scheme": "https",
                    "nfServiceStatus": "REGISTERED",
                    "ipEndPoints": [{"ipv4Address":"192.0.2.50","port":8443}]
                }]
            },
            {
                "nfInstanceId": "nf",
                "nfStatus": "REGISTERED",
                "nfServices": [{
                    "serviceName": "nsmf-pdusession",
                    "scheme": "https",
                    "nfServiceStatus": "REGISTERED",
                    "ipEndPoints": [{"ipv4Address":"192.0.2.51","port":8443}]
                }]
            }
        ]
    }))
    .unwrap()
    .nf_instances;

    assert!(extract_endpoints(&config(), profiles).is_empty());
}

#[test]
fn extracts_dual_stack_endpoints_and_deduplicates_them() {
    let profiles = serde_json::from_value::<SearchResult>(serde_json::json!({
        "nfInstances": [{
            "nfInstanceId": "nf-dual",
            "nfStatus": "REGISTERED",
            "nfServices": [{
                "serviceInstanceId": "dual",
                "serviceName": "nsmf-pdusession",
                "scheme": "https",
                "nfServiceStatus": "REGISTERED",
                "ipEndPoints": [
                    {"ipv4Address":"192.0.2.10","ipv6Address":"2001:db8::10","port":8443},
                    {"ipv4Address":"192.0.2.10","port":8443}
                ]
            }]
        }]
    }))
    .unwrap()
    .nf_instances;

    assert_eq!(
        extract_endpoints(&config(), profiles),
        vec![
            CompiledUpstreamServer {
                host: "192.0.2.10".into(),
                port: 8443,
                weight: 1,
                api_prefix: None,
                nrf_service: Some(metadata("nf-dual", "dual", u16::MAX, 1)),
            },
            CompiledUpstreamServer {
                host: "2001:db8::10".into(),
                port: 8443,
                weight: 1,
                api_prefix: None,
                nrf_service: Some(metadata("nf-dual", "dual", u16::MAX, 1)),
            },
        ]
    );
}

#[test]
fn uses_profile_addresses_and_default_port_as_fallback() {
    let profiles = serde_json::from_value::<SearchResult>(serde_json::json!({
        "nfInstances": [{
            "nfInstanceId": "nf-fallback",
            "nfStatus": "REGISTERED",
            "ipv4Addresses": ["192.0.2.20"],
            "ipv6Addresses": ["2001:db8::20"],
            "nfServices": [{
                "serviceInstanceId": "fallback",
                "serviceName": "nsmf-pdusession",
                "scheme": "https",
                "nfServiceStatus": "REGISTERED"
            }]
        }]
    }))
    .unwrap()
    .nf_instances;

    let endpoints = extract_endpoints(&config(), profiles);
    assert_eq!(endpoints.len(), 2);
    assert!(endpoints.iter().all(|endpoint| endpoint.port == 443));
}

#[tokio::test]
async fn discovery_uses_h2_prior_knowledge_and_expected_query() {
    let body = serde_json::json!({"validityPeriod": 15, "nfInstances": []}).to_string();
    let (addr, request) = spawn_h2_response(StatusCode::OK, body, None, false).await;

    let result = NrfClient::new(&http_config(addr))
        .unwrap()
        .discover()
        .await
        .expect("h2 discovery succeeds");
    let (version, uri) = request.await.expect("h2 server task");

    assert_eq!(version, Version::HTTP_2);
    assert!(uri.contains("/nnrf-disc/v1/nf-instances?"));
    assert!(uri.contains("target-nf-type=SMF"));
    assert!(uri.contains("requester-nf-type=SCP"));
    assert!(uri.contains("service-names=nsmf-pdusession"));
    assert_eq!(result.validity, Duration::from_secs(15));
    assert!(result.endpoints.is_empty());
}

#[tokio::test]
async fn discovery_does_not_follow_redirects() {
    let (addr, request) = spawn_h2_response(
        StatusCode::TEMPORARY_REDIRECT,
        Bytes::new(),
        Some("http://127.0.0.1:1/redirected"),
        false,
    )
    .await;

    let error = NrfClient::new(&http_config(addr))
        .unwrap()
        .discover()
        .await
        .expect_err("redirect must fail");
    request.await.expect("h2 server task");

    assert!(error.contains("HTTP 307"), "unexpected error: {error}");
}

#[tokio::test]
async fn discovery_rejects_malformed_json() {
    let (addr, request) = spawn_h2_response(StatusCode::OK, "{", None, false).await;

    let error = NrfClient::new(&http_config(addr))
        .unwrap()
        .discover()
        .await
        .expect_err("malformed response must fail");
    request.await.expect("h2 server task");

    assert!(error.contains("invalid NRF SearchResult"));
}

#[tokio::test]
async fn discovery_rejects_oversized_body() {
    let body = Bytes::from(vec![b'x'; MAX_RESPONSE_BODY + 1]);
    let (addr, request) = spawn_h2_response(StatusCode::OK, body, None, true).await;

    let error = NrfClient::new(&http_config(addr))
        .unwrap()
        .discover()
        .await
        .expect_err("oversized response must fail");
    request.await.expect("h2 server task");

    assert!(
        error.contains("response exceeds"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn discovery_uses_default_validity_for_zero() {
    let body = serde_json::json!({"validityPeriod": 0, "nfInstances": []}).to_string();
    let (addr, request) = spawn_h2_response(StatusCode::OK, body, None, false).await;

    let result = NrfClient::new(&http_config(addr))
        .unwrap()
        .discover()
        .await
        .expect("zero validity uses the default");
    request.await.expect("h2 server task");

    assert_eq!(result.validity, DEFAULT_VALIDITY);
}
