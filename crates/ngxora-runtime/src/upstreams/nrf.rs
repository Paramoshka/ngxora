use super::types::{CompiledNrfDiscovery, CompiledUpstreamServer};
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
    nf_status: String,
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
    service_name: String,
    scheme: String,
    nf_service_status: String,
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
        for service in profile.nf_services {
            if service.service_name != config.service_name
                || !service.nf_service_status.eq_ignore_ascii_case("REGISTERED")
                || !service.scheme.eq_ignore_ascii_case(expected_scheme)
                || service
                    .api_prefix
                    .as_deref()
                    .is_some_and(|prefix| !prefix.is_empty())
            {
                continue;
            }

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
                    add_endpoint(&mut endpoints, host, port);
                }
                continue;
            }

            let endpoint_count = endpoints.len();
            for endpoint in service.ip_end_points {
                let port = endpoint.port.unwrap_or(default_port);
                if let Some(host) = endpoint.ipv4_address {
                    add_endpoint(&mut endpoints, &host, port);
                }
                if let Some(host) = endpoint.ipv6_address {
                    add_endpoint(&mut endpoints, &host, port);
                }
            }
            if endpoints.len() == endpoint_count {
                for host in profile.ipv4_addresses.iter().chain(&profile.ipv6_addresses) {
                    add_endpoint(&mut endpoints, host, default_port);
                }
            }
        }
    }

    endpoints
        .into_iter()
        .map(|(host, port)| CompiledUpstreamServer {
            host,
            port,
            weight: 1,
        })
        .collect()
}

fn add_endpoint(endpoints: &mut BTreeSet<(String, u16)>, host: &str, port: u16) {
    let host = host.trim().trim_matches(['[', ']']);
    let valid_host = host.parse::<IpAddr>().is_ok() || url::Host::parse(host).is_ok();
    if host.is_empty() || port == 0 || !valid_host {
        return;
    }
    endpoints.insert((host.to_ascii_lowercase(), port));
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
            connection.await.expect("serve h2 response");
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

    #[test]
    fn filters_unregistered_wrong_service_and_api_prefix() {
        let profiles = serde_json::from_value::<SearchResult>(serde_json::json!({
            "validityPeriod": 30,
            "nfInstances": [{
                "nfStatus": "REGISTERED",
                "fqdn": "smf.example",
                "nfServices": [
                    {"serviceName":"wrong","scheme":"https","nfServiceStatus":"REGISTERED"},
                    {"serviceName":"nsmf-pdusession","scheme":"https","nfServiceStatus":"SUSPENDED"},
                    {"serviceName":"nsmf-pdusession","scheme":"https","nfServiceStatus":"REGISTERED","apiPrefix":"edge"},
                    {"serviceName":"nsmf-pdusession","scheme":"https","nfServiceStatus":"REGISTERED","ipEndPoints":[{"port":8443}]}
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
            }]
        );
    }

    #[test]
    fn extracts_dual_stack_endpoints_and_deduplicates_them() {
        let profiles = serde_json::from_value::<SearchResult>(serde_json::json!({
            "nfInstances": [{
                "nfStatus": "REGISTERED",
                "nfServices": [{
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
                },
                CompiledUpstreamServer {
                    host: "2001:db8::10".into(),
                    port: 8443,
                    weight: 1,
                },
            ]
        );
    }

    #[test]
    fn uses_profile_addresses_and_default_port_as_fallback() {
        let profiles = serde_json::from_value::<SearchResult>(serde_json::json!({
            "nfInstances": [{
                "nfStatus": "REGISTERED",
                "ipv4Addresses": ["192.0.2.20"],
                "ipv6Addresses": ["2001:db8::20"],
                "nfServices": [{
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
        let (addr, request) = spawn_h2_response(StatusCode::OK, body, None).await;

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
        let (addr, request) = spawn_h2_response(StatusCode::OK, "{", None).await;

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
        let (addr, request) = spawn_h2_response(StatusCode::OK, body, None).await;

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
        let (addr, request) = spawn_h2_response(StatusCode::OK, body, None).await;

        let result = NrfClient::new(&http_config(addr))
            .unwrap()
            .discover()
            .await
            .expect("zero validity uses the default");
        request.await.expect("h2 server task");

        assert_eq!(result.validity, DEFAULT_VALIDITY);
    }
}
