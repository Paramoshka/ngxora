use super::types::{CompiledNrfDiscovery, CompiledUpstreamServer, NrfServiceMetadata};
use ngxora_compile::ir::{NrfEndpointScheme, PemSource, Switch};
use reqwest::{Certificate, Client, Identity};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::Duration;

const DEFAULT_VALIDITY: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BODY: usize = 1024 * 1024;

pub(super) struct NrfClient {
    config: CompiledNrfDiscovery,
    client: Client,
}

#[derive(Debug)]
pub(super) struct DiscoveryResult {
    pub endpoints: Vec<CompiledUpstreamServer>,
    pub validity: Duration,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SearchResult {
    #[serde(default)]
    validity_period: Option<u64>,
    nf_instances: Vec<NfProfile>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NfProfile {
    #[serde(default)]
    nf_instance_id: Option<String>,
    nf_status: String,
    #[serde(default)]
    priority: Option<u64>,
    #[serde(default)]
    capacity: Option<u64>,
    #[serde(default)]
    fqdn: Option<String>,
    #[serde(default)]
    ipv4_addresses: Vec<String>,
    #[serde(default)]
    ipv6_addresses: Vec<String>,
    #[serde(default)]
    nf_services: Vec<NfService>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NfService {
    #[serde(default)]
    service_instance_id: Option<String>,
    service_name: String,
    scheme: String,
    nf_service_status: String,
    #[serde(default)]
    priority: Option<u64>,
    #[serde(default)]
    capacity: Option<u64>,
    #[serde(default)]
    fqdn: Option<String>,
    #[serde(default)]
    ip_end_points: Vec<IpEndPoint>,
    #[serde(default)]
    api_prefix: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IpEndPoint {
    #[serde(default)]
    ipv4_address: Option<String>,
    #[serde(default)]
    ipv6_address: Option<String>,
    #[serde(default)]
    port: Option<u16>,
}

impl NrfClient {
    pub(super) fn new(config: &CompiledNrfDiscovery) -> Result<Self, String> {
        let mut builder = Client::builder()
            .timeout(config.timeout)
            .http2_prior_knowledge()
            .redirect(reqwest::redirect::Policy::none())
            .user_agent(concat!("ngxora/", env!("CARGO_PKG_VERSION")));

        if matches!(config.tls_options.verify_cert, Switch::Off) {
            builder = builder.danger_accept_invalid_certs(true);
        }
        if let Some(source) = config.tls_options.trusted_certificate.as_ref() {
            let pem = read_pem_source(source, "nrf_discovery ssl_trusted_certificate")?;
            let certificates = Certificate::from_pem_bundle(&pem).map_err(|err| {
                format!("failed to parse nrf_discovery ssl_trusted_certificate: {err}")
            })?;
            if certificates.is_empty() {
                return Err(
                    "nrf_discovery ssl_trusted_certificate contains no certificates".into(),
                );
            }
            for certificate in certificates {
                builder = builder.add_root_certificate(certificate);
            }
        }
        if let (Some(cert), Some(key)) = (
            config.tls_options.client_certificate.as_ref(),
            config.tls_options.client_certificate_key.as_ref(),
        ) {
            let mut pem = read_pem_source(cert, "nrf_discovery ssl_certificate")?;
            pem.extend_from_slice(&read_pem_source(key, "nrf_discovery ssl_certificate_key")?);
            let identity = Identity::from_pem(&pem)
                .map_err(|err| format!("failed to parse nrf_discovery client identity: {err}"))?;
            builder = builder.identity(identity);
        }

        let client = builder
            .build()
            .map_err(|err| format!("failed to build nrf_discovery HTTP client: {err}"))?;
        Ok(Self {
            config: config.clone(),
            client,
        })
    }

    pub(super) async fn discover(&self) -> Result<DiscoveryResult, String> {
        let mut url = self.config.api_root.clone();
        let path = format!("{}/nf-instances", url.path().trim_end_matches('/'));
        url.set_path(&path);
        url.query_pairs_mut()
            .append_pair("target-nf-type", &self.config.target_nf_type)
            .append_pair("requester-nf-type", &self.config.requester_nf_type)
            .append_pair("service-names", &self.config.service_name);

        let mut response = self
            .client
            .get(url)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|err| format!("NRF discovery request failed: {err}"))?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(format!("NRF discovery returned HTTP {}", response.status()));
        }
        if response
            .content_length()
            .is_some_and(|length| length > MAX_RESPONSE_BODY as u64)
        {
            return Err(format!(
                "NRF discovery response exceeds {MAX_RESPONSE_BODY} bytes"
            ));
        }

        let mut body = Vec::new();
        while let Some(chunk) = response
            .chunk()
            .await
            .map_err(|err| format!("failed to read NRF discovery response: {err}"))?
        {
            if body.len().saturating_add(chunk.len()) > MAX_RESPONSE_BODY {
                return Err(format!(
                    "NRF discovery response exceeds {MAX_RESPONSE_BODY} bytes"
                ));
            }
            body.extend_from_slice(&chunk);
        }

        let result: SearchResult = serde_json::from_slice(&body)
            .map_err(|err| format!("invalid NRF SearchResult: {err}"))?;
        let endpoints = extract_endpoints(&self.config, result.nf_instances);
        Ok(DiscoveryResult {
            endpoints,
            validity: result
                .validity_period
                .map(Duration::from_secs)
                .filter(|duration| !duration.is_zero())
                .unwrap_or(DEFAULT_VALIDITY),
        })
    }
}

fn extract_endpoints(
    config: &CompiledNrfDiscovery,
    profiles: Vec<NfProfile>,
) -> Vec<CompiledUpstreamServer> {
    let expected_scheme = match config.endpoint_scheme {
        NrfEndpointScheme::Http => "http",
        NrfEndpointScheme::Https => "https",
    };
    let default_port = if expected_scheme == "https" { 443 } else { 80 };
    let mut endpoints = BTreeSet::new();

    for profile in profiles {
        if !profile.nf_status.eq_ignore_ascii_case("REGISTERED") {
            continue;
        }
        let Some(nf_instance_id) = non_empty_id(profile.nf_instance_id.as_deref()) else {
            log::warn!("ignoring registered NRF profile without nfInstanceId");
            continue;
        };
        let profile_priority = match optional_u16(profile.priority, "profile priority") {
            Ok(value) => value,
            Err(err) => {
                log::warn!("ignoring NRF profile `{nf_instance_id}`: {err}");
                continue;
            }
        };
        let profile_capacity = match optional_u16(profile.capacity, "profile capacity") {
            Ok(value) => value,
            Err(err) => {
                log::warn!("ignoring NRF profile `{nf_instance_id}`: {err}");
                continue;
            }
        };

        for service in profile.nf_services {
            if service.service_name != config.service_name
                || !service.nf_service_status.eq_ignore_ascii_case("REGISTERED")
                || !service.scheme.eq_ignore_ascii_case(expected_scheme)
            {
                continue;
            }
            let Some(service_instance_id) = non_empty_id(service.service_instance_id.as_deref())
            else {
                log::warn!(
                    "ignoring NRF service `{}` without serviceInstanceId",
                    service.service_name
                );
                continue;
            };
            let service_priority = match optional_u16(service.priority, "service priority") {
                Ok(value) => value,
                Err(err) => {
                    log::warn!(
                        "ignoring NRF service `{service_instance_id}` in profile `{nf_instance_id}`: {err}"
                    );
                    continue;
                }
            };
            let service_capacity = match optional_u16(service.capacity, "service capacity") {
                Ok(value) => value,
                Err(err) => {
                    log::warn!(
                        "ignoring NRF service `{service_instance_id}` in profile `{nf_instance_id}`: {err}"
                    );
                    continue;
                }
            };
            let metadata = NrfServiceMetadata {
                nf_instance_id: nf_instance_id.to_string(),
                service_instance_id: service_instance_id.to_string(),
                priority: service_priority.or(profile_priority).unwrap_or(u16::MAX),
                capacity: service_capacity.or(profile_capacity).unwrap_or(1),
            };
            let raw_api_prefix = service.api_prefix.as_deref();
            let api_prefix = match normalize_api_prefix(raw_api_prefix) {
                Ok(api_prefix) => api_prefix,
                Err(err) => {
                    log::warn!(
                        "ignoring NRF service `{}` with invalid apiPrefix {raw_api_prefix:?}: {err}",
                        service.service_name,
                    );
                    continue;
                }
            };

            let ports = service
                .ip_end_points
                .iter()
                .filter_map(|endpoint| endpoint.port)
                .collect::<BTreeSet<_>>();
            if let Some(host) = service.fqdn.as_deref().or(profile.fqdn.as_deref()) {
                let ports = if ports.is_empty() {
                    BTreeSet::from([default_port])
                } else {
                    ports
                };
                for port in ports {
                    add_endpoint(&mut endpoints, host, port, api_prefix.as_deref(), &metadata);
                }
                continue;
            }

            let endpoint_count = endpoints.len();
            for endpoint in service.ip_end_points {
                let port = endpoint.port.unwrap_or(default_port);
                if let Some(host) = endpoint.ipv4_address {
                    add_endpoint(
                        &mut endpoints,
                        &host,
                        port,
                        api_prefix.as_deref(),
                        &metadata,
                    );
                }
                if let Some(host) = endpoint.ipv6_address {
                    add_endpoint(
                        &mut endpoints,
                        &host,
                        port,
                        api_prefix.as_deref(),
                        &metadata,
                    );
                }
            }
            if endpoints.len() == endpoint_count {
                for host in profile.ipv4_addresses.iter().chain(&profile.ipv6_addresses) {
                    add_endpoint(
                        &mut endpoints,
                        host,
                        default_port,
                        api_prefix.as_deref(),
                        &metadata,
                    );
                }
            }
        }
    }

    endpoints
        .into_iter()
        .map(
            |(metadata, host, port, api_prefix)| CompiledUpstreamServer {
                host,
                port,
                weight: 1,
                api_prefix,
                nrf_service: Some(metadata),
            },
        )
        .collect()
}

fn non_empty_id(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn optional_u16(value: Option<u64>, label: &str) -> Result<Option<u16>, String> {
    value
        .map(|value| {
            u16::try_from(value).map_err(|_| format!("{label} must be in the range 0..=65535"))
        })
        .transpose()
}

fn normalize_api_prefix(prefix: Option<&str>) -> Result<Option<String>, String> {
    let Some(prefix) = prefix.filter(|prefix| !prefix.is_empty()) else {
        return Ok(None);
    };
    if !prefix.starts_with('/') || prefix.starts_with("//") {
        return Err("expected an absolute path beginning with one `/`".into());
    }
    if prefix.contains('#') {
        return Err("fragments are not allowed".into());
    }
    let path_and_query = prefix
        .parse::<http::uri::PathAndQuery>()
        .map_err(|err| format!("invalid path: {err}"))?;
    if path_and_query.query().is_some() {
        return Err("query parameters are not allowed".into());
    }

    let prefix = prefix.trim_end_matches('/');
    Ok((!prefix.is_empty()).then(|| prefix.to_string()))
}

fn add_endpoint(
    endpoints: &mut BTreeSet<(NrfServiceMetadata, String, u16, Option<String>)>,
    host: &str,
    port: u16,
    api_prefix: Option<&str>,
    metadata: &NrfServiceMetadata,
) {
    let host = host.trim().trim_matches(['[', ']']);
    let valid_host = host.parse::<IpAddr>().is_ok() || url::Host::parse(host).is_ok();
    if host.is_empty() || port == 0 || !valid_host {
        return;
    }
    endpoints.insert((
        metadata.clone(),
        host.to_ascii_lowercase(),
        port,
        api_prefix.map(str::to_string),
    ));
}

fn read_pem_source(source: &PemSource, label: &str) -> Result<Vec<u8>, String> {
    match source {
        PemSource::Path(path) => std::fs::read(path)
            .map_err(|err| format!("failed to read {label} `{}`: {err}", path.display())),
        PemSource::InlinePem(pem) => Ok(pem.as_bytes().to_vec()),
    }
}

#[cfg(test)]
mod tests {
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
}
