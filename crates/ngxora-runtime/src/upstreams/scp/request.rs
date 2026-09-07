//! Validate SBI apiRoots, headers and bindings before selecting any destination.

use super::{DISCOVERY, ScpError, TARGET};
use crate::upstreams::nrf::NrfQuery;
use crate::upstreams::types::{CompiledUpstreamGroup, CompiledUpstreamServer};
use http::{HeaderMap, Method, Uri};
use ngxora_compile::ir::ScpProfile;
use std::collections::{HashMap, HashSet};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(in crate::upstreams) struct ApiRoot {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub prefix: String,
}

impl ApiRoot {
    pub(in crate::upstreams) fn parse(value: &str) -> Result<Self, String> {
        // Validate before URL parsing: URL normalization must not hide traversal
        // or an alternative spelling that bypasses an exact configured root.
        if value.len() > 2048
            || value.bytes().any(|b| b <= b' ' || b >= 127)
            || value.contains(['\\', '%', '?', '#', '@'])
        {
            return Err("apiRoot contains unsupported URI characters".into());
        }
        let uri: Uri = value.parse().map_err(|_| "invalid apiRoot")?;
        let scheme = uri
            .scheme_str()
            .ok_or("apiRoot requires http:// or https://")?;
        if scheme != "http" && scheme != "https" {
            return Err("invalid apiRoot scheme".into());
        }
        let authority = uri.authority().ok_or("apiRoot requires an authority")?;
        let host = authority
            .host()
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_ascii_lowercase();
        if host.is_empty() || host.ends_with('.') || authority.as_str().ends_with(':') {
            return Err("invalid apiRoot host or port".into());
        }
        let raw_port = if authority.as_str().starts_with('[') {
            authority.as_str().split_once("]:").map(|(_, p)| p)
        } else {
            authority.as_str().split_once(':').map(|(_, p)| p)
        };
        let port = raw_port
            .map(|p| p.parse::<u16>().map_err(|_| "invalid apiRoot port"))
            .transpose()?
            .unwrap_or(if scheme == "https" { 443 } else { 80 });
        if port == 0 {
            return Err("apiRoot port must be nonzero".into());
        }
        let prefix = uri.path().trim_end_matches('/').to_string();
        if prefix.contains("//") || prefix.split('/').any(|part| part == "." || part == "..") {
            return Err("invalid apiRoot prefix".into());
        }
        Ok(Self {
            scheme: scheme.into(),
            host,
            port,
            prefix,
        })
    }

    pub(in crate::upstreams) fn authority(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let default = if self.scheme == "https" { 443 } else { 80 };
        if self.port == default {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    pub(in crate::upstreams) fn value(&self) -> String {
        format!("{}://{}{}", self.scheme, self.authority(), self.prefix)
    }

    pub(super) fn backend(&self) -> CompiledUpstreamServer {
        CompiledUpstreamServer {
            host: self.host.clone(),
            port: self.port,
            weight: 1,
            api_prefix: (!self.prefix.is_empty()).then(|| self.prefix.clone()),
            nrf_service: None,
        }
    }
}

pub(in crate::upstreams) fn validate_profile(
    profile: &ScpProfile,
    upstreams: &HashMap<String, CompiledUpstreamGroup>,
) -> Result<(), String> {
    if profile.name.is_empty()
        || !profile
            .name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
    {
        return Err("scp name must contain only letters, digits, underscore or hyphen".into());
    }
    let root = ApiRoot::parse(&profile.api_root)?;
    let mut seen = HashSet::new();
    for name in &profile.discovery_upstreams {
        let group = upstreams
            .get(name)
            .ok_or_else(|| format!("scp references unknown discovery upstream `{name}`"))?;
        let nrf = group
            .nrf_discovery
            .as_ref()
            .ok_or_else(|| format!("scp upstream `{name}` requires nrf_discovery"))?;
        if !seen.insert((
            &nrf.target_nf_type,
            &nrf.service_name,
            &nrf.requester_nf_type,
        )) {
            return Err(
                "scp discovery upstreams have ambiguous NF/service/requester combinations".into(),
            );
        }
    }
    let mut roots = HashSet::new();
    for value in &profile.allowed_target_api_roots {
        let target = ApiRoot::parse(value)?;
        if target.host == root.host && target.port == root.port {
            return Err("scp cannot target its own authority".into());
        }
        if !roots.insert(target.value()) {
            return Err("duplicate scp allowed target".into());
        }
    }
    if profile.discovery_upstreams.is_empty() && roots.is_empty() {
        return Err("scp requires discovery_upstream or allow_target_api_root".into());
    }
    Ok(())
}

pub(super) fn single(headers: &HeaderMap, name: &str) -> Result<Option<String>, ScpError> {
    let mut values = headers.get_all(name).iter();
    let Some(first) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(ScpError::invalid(format!("Duplicate {name}")));
    }
    let value = first
        .to_str()
        .map_err(|_| ScpError::invalid(format!("Invalid {name}")))?
        .trim();
    if value.is_empty() || value.len() > 2048 {
        return Err(ScpError::invalid(format!("Invalid {name}")));
    }
    Ok(Some(value.into()))
}

pub(in crate::upstreams) fn token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.".contains(&b))
}

#[derive(Clone, Debug, Default)]
struct Binding {
    nf: Option<String>,
    service: Option<String>,
    service_name: Option<String>,
}

fn binding(value: &str) -> Result<Binding, ScpError> {
    let mut fields = HashMap::new();
    for part in value.split(';') {
        let (key, value) = part
            .trim()
            .split_once('=')
            .ok_or_else(|| ScpError::invalid("Malformed routing binding"))?;
        if !token(value) || fields.insert(key, value).is_some() {
            return Err(ScpError::invalid("Invalid or duplicate binding parameter"));
        }
        if !matches!(key, "bl" | "nfinst" | "nfservinst" | "servname") {
            return Err(ScpError::invalid("Unsupported binding parameter"));
        }
    }
    let level = fields.get("bl").copied().unwrap_or("");
    if !matches!(level, "nf-instance" | "nfservice-instance")
        || !fields.contains_key("nfinst")
        || (level == "nfservice-instance" && !fields.contains_key("nfservinst"))
        || (level == "nf-instance" && fields.contains_key("nfservinst"))
    {
        return Err(ScpError::invalid(
            "Unsupported or incomplete routing binding",
        ));
    }
    Ok(Binding {
        nf: fields.get("nfinst").map(|v| v.to_string()),
        service: fields.get("nfservinst").map(|v| v.to_string()),
        service_name: fields.get("servname").map(|v| v.to_string()),
    })
}

#[derive(Clone, Debug)]
pub(in crate::upstreams) struct ScpRequest {
    pub(super) target: Option<ApiRoot>,
    pub(super) target_type: Option<String>,
    pub(super) requester_type: Option<String>,
    pub(super) query: NrfQuery,
    pub(super) discovery: bool,
    pub bound: bool,
    pub path_query: String,
    pub hops: u8,
}

impl ScpRequest {
    pub(in crate::upstreams) fn parse(
        headers: &HeaderMap,
        method: &Method,
        uri: &Uri,
        root: &ApiRoot,
    ) -> Result<Self, ScpError> {
        if method == Method::CONNECT {
            return Err(ScpError::new(
                405,
                "UNSPECIFIED_MSG_FAILURE",
                "CONNECT is not supported by SCP",
            ));
        }
        for name in headers.keys().map(|n| n.as_str()) {
            if let Some(selector) = name.strip_prefix(DISCOVERY)
                && !matches!(
                    selector,
                    "target-nf-type"
                        | "requester-nf-type"
                        | "service-names"
                        | "target-nf-instance-id"
                        | "requester-nf-instance-id"
                )
            {
                return Err(ScpError::new(
                    400,
                    "INVALID_DISCOVERY_PARAM",
                    "Unsupported discovery parameter",
                ));
            }
            if matches!(
                name,
                "3gpp-sbi-nrf-uri" | "3gpp-sbi-scp-apiroot" | "3gpp-sbi-selection-info"
            ) {
                return Err(ScpError::invalid(
                    "Request-driven NRF or next-hop selection is unsupported",
                ));
            }
        }
        let target = single(headers, TARGET)?
            .map(|v| ApiRoot::parse(&v).map_err(ScpError::invalid))
            .transpose()?;
        if target
            .as_ref()
            .is_some_and(|t| t.host == root.host && t.port == root.port)
        {
            return Err(ScpError::new(
                508,
                "UNSPECIFIED_MSG_FAILURE",
                "SCP routing loop",
            ));
        }
        let hops = single(headers, "3gpp-sbi-max-forward-hops")?
            .map(|v| {
                v.parse::<u8>()
                    .map_err(|_| ScpError::invalid("Invalid hop count"))
            })
            .transpose()?
            .unwrap_or(1);
        if hops == 0 {
            return Err(ScpError::new(
                508,
                "UNSPECIFIED_MSG_FAILURE",
                "SCP hop limit exhausted",
            ));
        }
        let path = uri
            .path()
            .strip_prefix(&root.prefix)
            .filter(|p| p.is_empty() || p.starts_with('/'))
            .ok_or_else(|| {
                ScpError::invalid("Request path is outside the configured SCP apiRoot")
            })?;
        let path = if path.is_empty() { "/" } else { path };
        let checked_path = path.to_ascii_lowercase().replace("%2e", ".");
        if checked_path.contains(['\\'])
            || checked_path.contains("%2f")
            || checked_path.contains("%5c")
            || checked_path
                .split('/')
                .any(|segment| segment == "." || segment == "..")
        {
            return Err(ScpError::invalid("Ambiguous or traversing request path"));
        }
        let query = uri.query().map(|q| {
            q.split('&')
                .filter(|part| part.split('=').next() != Some("ck"))
                .collect::<Vec<_>>()
                .join("&")
        });
        let path_query = match query.filter(|q| !q.is_empty()) {
            Some(q) => format!("{path}?{q}"),
            None => path.into(),
        };
        let mut selectors = HashMap::new();
        for name in [
            "target-nf-type",
            "requester-nf-type",
            "target-nf-instance-id",
            "requester-nf-instance-id",
        ] {
            if let Some(value) = single(headers, &format!("{DISCOVERY}{name}"))? {
                if !token(&value) {
                    return Err(ScpError::invalid("Invalid discovery selector"));
                }
                selectors.insert(name, value);
            }
        }
        let names = single(headers, "3gpp-sbi-discovery-service-names")?;
        let binding = single(headers, "3gpp-sbi-routing-binding")?
            .map(|v| binding(&v))
            .transpose()?;
        let discovery =
            target.is_none() || !selectors.is_empty() || names.is_some() || binding.is_some();
        let mut service_names = names
            .map(|v| {
                v.split(',')
                    .map(|n| n.trim().to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if service_names.iter().any(|n| !token(n))
            || service_names.len() > 16
            || service_names.iter().collect::<HashSet<_>>().len() != service_names.len()
        {
            return Err(ScpError::invalid("Invalid service-names"));
        }
        let mut api_version = String::new();
        if discovery || target.is_none() {
            let mut parts = path.trim_start_matches('/').split('/');
            let service = parts.next().unwrap_or("");
            let version = parts.next().unwrap_or("");
            if !token(service)
                || !version
                    .strip_prefix('v')
                    .is_some_and(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
            {
                return Err(ScpError::new(
                    400,
                    "INVALID_API",
                    "Expected /service/vN/resource",
                ));
            }
            api_version = version.into();
            if service_names.is_empty() {
                service_names.push(service.into());
            }
            if service_names.first().map(String::as_str) != Some(service) {
                return Err(ScpError::new(
                    400,
                    "INVALID_API",
                    "First service name differs from request API",
                ));
            }
        }
        let mut nf_instance_id = selectors.remove("target-nf-instance-id");
        let mut service_instance_id = None;
        if let Some(b) = &binding {
            if nf_instance_id
                .as_ref()
                .is_some_and(|id| Some(id) != b.nf.as_ref())
                || b.service_name
                    .as_ref()
                    .is_some_and(|n| Some(n) != service_names.first())
            {
                return Err(ScpError::invalid("Binding conflicts with discovery"));
            }
            nf_instance_id = b.nf.clone();
            service_instance_id = b.service.clone();
        }
        Ok(Self {
            target,
            target_type: selectors.remove("target-nf-type"),
            requester_type: selectors.remove("requester-nf-type"),
            query: NrfQuery {
                nf_instance_id,
                requester_instance_id: selectors.remove("requester-nf-instance-id"),
                service_instance_id,
                api_version,
                service_names,
            },
            discovery,
            bound: binding.is_some(),
            path_query,
            hops: hops - 1,
        })
    }
}
