use super::*;
use crate::upstreams::CompiledRouter;

fn compile(config: &str) -> Result<CompiledRouter, String> {
    let ast = ngxora_config::Ast::parse_config(config).map_err(|e| format!("{e:?}"))?;
    let ir = ngxora_compile::ir::Ir::from_ast(&ast).map_err(|e| format!("{e:?}"))?;
    CompiledRouter::from_http(&ir.http.unwrap())
}

#[test]
fn configuration_rejects_ambiguous_actions_and_invalid_profiles() {
    let config = r#"http { h2c on;
        scp core { api_root http://scp.test/scp; allow_target_api_root https://nf.test/edge; }
        server { listen 127.0.0.1:8080; location /scp/ { scp_pass core; } }
    }"#;
    let router = compile(config).unwrap();
    assert_eq!(
        router.scp_profiles["core"].allowed_target_api_roots,
        vec!["https://nf.test/edge"]
    );
    for bad in [
        config.replace("scp_pass core;", "scp_pass absent;"),
        config.replace(
            "scp_pass core;",
            "scp_pass core; proxy_pass http://nf.test;",
        ),
        config.replace("scp_pass core;", "scp_pass core; return 200 ok;"),
        config.replace("scp_pass core;", "scp_pass core; proxy_cache on;"),
        config.replace("h2c on;", "h2c off;"),
        config.replace("https://nf.test/edge", "http://scp.test/other"),
        config.replace(
            "scp_pass core;",
            "scp_pass core; proxy_upstream_protocol h1;",
        ),
        config.replace(
            "allow_target_api_root https://nf.test/edge;",
            "discovery_upstream missing;",
        ),
    ] {
        assert!(compile(&bad).is_err(), "accepted {bad}");
    }
}

#[test]
fn api_roots_are_exact_normalized_and_do_not_hide_unsafe_syntax() {
    assert_eq!(
        ApiRoot::parse("https://NF.test:443/edge/").unwrap().value(),
        "https://nf.test/edge"
    );
    assert_eq!(
        ApiRoot::parse("http://[::1]:8080/a").unwrap().value(),
        "http://[::1]:8080/a"
    );
    for bad in [
        "nf.test",
        "ftp://nf.test",
        "http://user@nf.test",
        "https://nf.test:0",
        "https://nf.test:99999",
        "https://nf.test:",
        "https://nf.test/a/../b",
        "https://nf.test/%2e",
        "https://nf.test/a?x=1",
        "https://nf.test/#x",
        "https://nf.test/a\\b",
        "https://nf.test./",
        "https://nf.test/a//b",
    ] {
        assert!(ApiRoot::parse(bad).is_err(), "accepted {bad}");
    }
}

fn request(headers: &[(&str, &str)], path: &str) -> Result<ScpRequest, ScpError> {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        map.append(
            http::HeaderName::from_bytes(name.as_bytes()).unwrap(),
            value.parse().unwrap(),
        );
    }
    ScpRequest::parse(
        &map,
        &Method::GET,
        &path.parse().unwrap(),
        &ApiRoot::parse("https://scp.test/scp").unwrap(),
    )
}

#[test]
fn parser_preserves_encoded_resources_and_removes_only_ck() {
    let parsed = request(
        &[(TARGET, "http://nf.test/prefix")],
        "/scp/callback/a%20b?ck=42&x=%2F&x=2",
    )
    .unwrap();
    assert_eq!(parsed.path_query, "/callback/a%20b?x=%2F&x=2");
    assert_eq!(parsed.hops, 0);
    for path in [
        "/scpx/a",
        "/scp/../admin",
        "/scp/%2E%2e/admin",
        "/scp/a%2fb",
    ] {
        assert!(
            request(&[(TARGET, "http://nf.test")], path).is_err(),
            "{path}"
        );
    }
}

#[test]
fn discovery_and_binding_are_validated_before_routing() {
    let parsed = request(
        &[
            ("3gpp-sbi-discovery-target-nf-type", "SMF"),
            (
                "3gpp-sbi-routing-binding",
                "bl=nfservice-instance; nfinst=nf-a; nfservinst=svc-a",
            ),
        ],
        "/scp/nsmf-pdusession/v1/a",
    )
    .unwrap();
    assert_eq!(parsed.query.nf_instance_id.as_deref(), Some("nf-a"));
    assert_eq!(parsed.query.service_instance_id.as_deref(), Some("svc-a"));
    for headers in [
        vec![(TARGET, "http://nf.test"), (TARGET, "http://nf.test")],
        vec![("3gpp-sbi-routing-binding", "bl=nf-set; nfset=a")],
        vec![(
            "3gpp-sbi-routing-binding",
            "bl=nf-instance; nfinst=a; nfinst=b",
        )],
        vec![
            ("3gpp-sbi-routing-binding", "bl=nf-instance; nfinst=a"),
            ("3gpp-sbi-discovery-target-nf-instance-id", "b"),
        ],
        vec![("3gpp-sbi-discovery-service-names", "other")],
        vec![("3gpp-sbi-discovery-snssais", "[]")],
        vec![("3gpp-sbi-nrf-uri", "http://elsewhere.test")],
        vec![(TARGET, "https://scp.test/other")],
    ] {
        assert!(
            request(&headers, "/scp/nsmf-pdusession/v1/a").is_err(),
            "{headers:?}"
        );
    }
}

#[test]
fn response_error_status_matches_body() {
    let error = ScpError::nrf_unreachable();
    let response = error.response("scp.test");
    let json: serde_json::Value = serde_json::from_slice(&response.body).unwrap();
    assert_eq!(json["status"], response.status.as_u16());
    assert_eq!(json["cause"], "NRF_NOT_REACHABLE");
    assert!(
        response
            .headers
            .iter()
            .any(|(name, value)| name == http::header::SERVER && value == "SCP-scp.test")
    );
}

#[tokio::test]
async fn busy_cache_is_bounded_and_idle_entries_are_evicted() {
    let router = compile(
        r#"http { h2c on;
        upstream smf { nrf_discovery {
            api_root http://127.0.0.1:9/nnrf-disc/v1; target_nf_type SMF;
            requester_nf_type AMF; service_name nsmf-pdusession; endpoint_scheme http;
        } health_check { type tcp; } }
        scp core { api_root http://scp.test/scp; discovery_upstream smf; }
    }"#,
    )
    .unwrap();
    let profile = RuntimeScp::new(&router.scp_profiles["core"], &router.upstreams).unwrap();
    let mut held = Vec::new();
    for index in 0..MAX_CACHE_ENTRIES {
        let query = NrfQuery {
            requester_instance_id: Some(format!("requester-{index}")),
            api_version: "v1".into(),
            service_names: vec!["nsmf-pdusession".into()],
            ..Default::default()
        };
        let group = Arc::new(
            RuntimeUpstreamGroup::from_compiled_query(
                &router.upstreams["smf"],
                Some(query.clone()),
                Some(profile.permits.clone()),
            )
            .unwrap(),
        );
        held.push(group.clone());
        profile.cache.lock().unwrap().insert(
            CacheKey {
                upstream: "smf".into(),
                query,
            },
            CacheEntry {
                group,
                last_used: Instant::now() - IDLE_TTL,
            },
        );
    }
    let request = request(&[], "/scp/nsmf-pdusession/v1/resources").unwrap();
    let error = match profile.discovered(&request).await {
        Err(e) => e,
        Ok(_) => panic!("cache limit ignored"),
    };
    assert_eq!((error.status, error.cause), (503, "SCP_CONGESTION"));
    assert_eq!(profile.cache.lock().unwrap().len(), MAX_CACHE_ENTRIES);
    assert_eq!(profile.permits.available_permits(), MAX_NRF_REQUESTS);
    drop(held);
    profile.maintain();
    assert!(profile.cache.lock().unwrap().is_empty());
}
