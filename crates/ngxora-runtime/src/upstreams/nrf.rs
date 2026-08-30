use super::types::{CompiledNrfDiscovery, CompiledUpstreamServer};
use ngxora_compile::ir::{NrfEndpointScheme, PemSource, Switch};
use reqwest::{Certificate, Client, Identity};
use serde::Deserialize;
use std::collections::BTreeSet;
use std::time::Duration;

const DEFAULT_VALIDITY: Duration = Duration::from_secs(30);
const MAX_RESPONSE_BODY: usize = 1024 * 1024;

pub(super) struct NrfClient {
    config: CompiledNrfDiscovery,
    client: Client,
}

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
                if let Some(host) = endpoint.ipv4_address.or(endpoint.ipv6_address) {
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
    if host.is_empty() || port == 0 || url::Host::parse(host).is_err() {
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
    use ngxora_compile::ir::UpstreamSslOptions;

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
}
