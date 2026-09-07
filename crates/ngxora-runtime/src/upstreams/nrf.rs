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
    pub(super) query: Option<NrfQuery>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Hash)]
pub(super) struct NrfQuery {
    pub nf_instance_id: Option<String>,
    pub requester_instance_id: Option<String>,
    pub service_instance_id: Option<String>,
    pub api_version: String,
    pub service_names: Vec<String>,
}

#[derive(Debug)]
pub(super) struct DiscoveryResult {
    pub endpoints: Vec<CompiledUpstreamServer>,
    pub validity: Duration,
    pub invalid_api: bool,
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
    nf_type: Option<String>,
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
    #[serde(default)]
    nf_service_list: std::collections::BTreeMap<String, NfService>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct NfService {
    #[serde(default)]
    versions: Vec<NfServiceVersion>,
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
struct NfServiceVersion {
    api_version_in_uri: String,
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
            query: None,
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
        if let Some(query) = &self.query {
            url.set_query(None);
            url.query_pairs_mut()
                .append_pair("target-nf-type", &self.config.target_nf_type)
                .append_pair("requester-nf-type", &self.config.requester_nf_type)
                .append_pair("service-names", &query.service_names.join(","));
            if let Some(id) = &query.nf_instance_id {
                url.query_pairs_mut()
                    .append_pair("target-nf-instance-id", id);
            }
            if let Some(id) = &query.requester_instance_id {
                url.query_pairs_mut()
                    .append_pair("requester-nf-instance-id", id);
            }
        }

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
        let (endpoints, invalid_api) =
            extract_query_endpoints(&self.config, result.nf_instances, self.query.as_ref());
        Ok(DiscoveryResult {
            endpoints,
            invalid_api,
            validity: result
                .validity_period
                .map(Duration::from_secs)
                .filter(|duration| !duration.is_zero())
                .unwrap_or(DEFAULT_VALIDITY),
        })
    }
}

#[cfg(test)]
fn extract_endpoints(
    config: &CompiledNrfDiscovery,
    profiles: Vec<NfProfile>,
) -> Vec<CompiledUpstreamServer> {
    extract_query_endpoints(config, profiles, None).0
}

fn extract_query_endpoints(
    config: &CompiledNrfDiscovery,
    profiles: Vec<NfProfile>,
    query: Option<&NrfQuery>,
) -> (Vec<CompiledUpstreamServer>, bool) {
    let mut invalid_api = false;
    let expected_scheme = match config.endpoint_scheme {
        NrfEndpointScheme::Http => "http",
        NrfEndpointScheme::Https => "https",
    };
    let default_port = if expected_scheme == "https" { 443 } else { 80 };
    let mut endpoints = BTreeSet::new();

    for profile in profiles {
        if query.is_some() && profile.nf_type.as_deref() != Some(config.target_nf_type.as_str()) {
            continue;
        }
        if !profile.nf_status.eq_ignore_ascii_case("REGISTERED") {
            continue;
        }
        let Some(nf_instance_id) = non_empty_id(profile.nf_instance_id.as_deref()) else {
            log::warn!("ignoring registered NRF profile without nfInstanceId");
            continue;
        };
        if query
            .and_then(|q| q.nf_instance_id.as_deref())
            .is_some_and(|id| id != nf_instance_id)
        {
            continue;
        }
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

        for service in
            profile
                .nf_services
                .into_iter()
                .chain(profile.nf_service_list.into_iter().filter_map(
                |(key, service)| {
                    if service.service_instance_id.as_deref() != Some(key.as_str()) {
                        log::warn!(
                            "ignoring NRF nfServiceList entry with mismatched serviceInstanceId"
                        );
                        None
                    } else {
                        Some(service)
                    }
                },
            ))
        {
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
            if let Some(query) = query {
                if query
                    .service_instance_id
                    .as_deref()
                    .is_some_and(|id| id != service_instance_id)
                {
                    continue;
                }
                if !service
                    .versions
                    .iter()
                    .any(|v| v.api_version_in_uri == query.api_version)
                {
                    invalid_api = true;
                    continue;
                }
            }
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
                authority: query.and_then(|_| service.fqdn.clone().or(profile.fqdn.clone())),
                nf_instance_id: nf_instance_id.to_string(),
                service_instance_id: service_instance_id.to_string(),
                priority: service_priority.or(profile_priority).unwrap_or(u16::MAX),
                capacity: service_capacity.or(profile_capacity).unwrap_or(1),
            };
            if query.is_some()
                && (!super::scp::token(nf_instance_id) || !super::scp::token(service_instance_id))
            {
                log::warn!("ignoring NRF service with invalid instance identifiers");
                continue;
            }
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
            if query.is_some() {
                let host = metadata.authority.as_deref().unwrap_or("nf.invalid");
                if super::scp::ApiRoot::parse(&format!(
                    "{expected_scheme}://{host}{}",
                    api_prefix.as_deref().unwrap_or("")
                ))
                .map_or(true, |root| {
                    root.host != host.to_ascii_lowercase() || root.port != default_port
                }) {
                    log::warn!("ignoring NRF service with invalid SBI authority or apiPrefix");
                    continue;
                }
            }

            let ports = service
                .ip_end_points
                .iter()
                .filter_map(|endpoint| endpoint.port)
                .collect::<BTreeSet<_>>();
            if let Some(host) = service.fqdn.as_deref().or(profile.fqdn.as_deref())
                && (query.is_none()
                    || service
                        .ip_end_points
                        .iter()
                        .all(|e| e.ipv4_address.is_none() && e.ipv6_address.is_none()))
            {
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

    let endpoints = endpoints
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
        .collect::<Vec<_>>();
    let invalid_api = invalid_api && endpoints.is_empty();
    (endpoints, invalid_api)
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
mod tests;
