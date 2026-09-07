//! The supported single-hop SBI routing profile. All destinations come from
//! configured roots or discovery through configured NRF upstreams.
use super::nrf::NrfQuery;
use super::runtime::RuntimeUpstreamGroup;
use super::types::{CompiledUpstreamGroup, CompiledUpstreamServer};
use http::{HeaderMap, Method, Uri};
use ngxora_compile::ir::ScpProfile;
use ngxora_plugin_api::LocalResponse;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::Instant;

const MAX_CACHE_ENTRIES: usize = 256;
const MAX_NRF_REQUESTS: usize = 16;
const IDLE_TTL: Duration = Duration::from_secs(300);
const DISCOVERY: &str = "3gpp-sbi-discovery-";
const TARGET: &str = "3gpp-sbi-target-apiroot";

#[cfg(test)]
#[path = "scp_tests.rs"]
mod tests;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ApiRoot {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub prefix: String,
}

impl ApiRoot {
    pub(super) fn parse(value: &str) -> Result<Self, String> {
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

    pub(super) fn authority(&self) -> String {
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

    pub(super) fn value(&self) -> String {
        format!("{}://{}{}", self.scheme, self.authority(), self.prefix)
    }

    fn backend(&self) -> CompiledUpstreamServer {
        CompiledUpstreamServer {
            host: self.host.clone(),
            port: self.port,
            weight: 1,
            api_prefix: (!self.prefix.is_empty()).then(|| self.prefix.clone()),
            nrf_service: None,
        }
    }
}

pub(super) fn validate_profile(
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

#[derive(Clone, Debug)]
pub(super) struct ScpError {
    pub status: u16,
    pub cause: &'static str,
    pub detail: String,
}

impl ScpError {
    pub(super) fn new(status: u16, cause: &'static str, detail: impl Into<String>) -> Self {
        Self {
            status,
            cause,
            detail: detail.into(),
        }
    }
    fn invalid(detail: impl Into<String>) -> Self {
        Self::new(400, "MANDATORY_IE_INCORRECT", detail)
    }
    pub(super) fn nrf_unreachable() -> Self {
        Self::new(504, "NRF_NOT_REACHABLE", "No usable NRF snapshot")
    }
    pub(super) fn target_unreachable() -> Self {
        Self::new(
            504,
            "TARGET_NF_NOT_REACHABLE",
            "No reachable target in the allowed routing domain",
        )
    }
    pub(super) fn response(&self, identity: &str) -> LocalResponse {
        let mut response = LocalResponse::new(
            http::StatusCode::from_u16(self.status).expect("SCP status constant"),
            "",
        );
        response.headers.push((
            http::header::CONTENT_TYPE,
            http::HeaderValue::from_static("application/problem+json"),
        ));
        response.headers.push((
            http::header::SERVER,
            http::HeaderValue::from_str(&format!("SCP-{identity}"))
                .expect("validated SCP identity"),
        ));
        response.body =
            serde_json::json!({"status": self.status, "cause": self.cause, "detail": self.detail})
                .to_string()
                .into_bytes()
                .into();
        response
    }
}

fn single(headers: &HeaderMap, name: &str) -> Result<Option<String>, ScpError> {
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

pub(super) fn token(value: &str) -> bool {
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
pub(super) struct ScpRequest {
    target: Option<ApiRoot>,
    target_type: Option<String>,
    requester_type: Option<String>,
    query: NrfQuery,
    discovery: bool,
    pub bound: bool,
    pub path_query: String,
    pub hops: u8,
}

impl ScpRequest {
    pub(super) fn parse(
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

#[derive(Clone, Eq, PartialEq, Hash)]
struct CacheKey {
    upstream: String,
    query: NrfQuery,
}
struct CacheEntry {
    group: Arc<RuntimeUpstreamGroup>,
    last_used: Instant,
}

pub(crate) struct RuntimeScp {
    pub(super) root: ApiRoot,
    pub(super) config: ScpProfile,
    templates: Vec<CompiledUpstreamGroup>,
    allowed: Vec<ApiRoot>,
    cache: Mutex<HashMap<CacheKey, CacheEntry>>,
    permits: Arc<Semaphore>,
}

impl RuntimeScp {
    pub(crate) fn matches(
        &self,
        config: &ScpProfile,
        upstreams: &HashMap<String, CompiledUpstreamGroup>,
    ) -> bool {
        &self.config == config
            && self
                .templates
                .iter()
                .all(|g| upstreams.get(&g.name) == Some(g))
    }
    pub(crate) fn new(
        config: &ScpProfile,
        upstreams: &HashMap<String, CompiledUpstreamGroup>,
    ) -> Result<Self, String> {
        validate_profile(config, upstreams)?;
        Ok(Self {
            root: ApiRoot::parse(&config.api_root)?,
            config: config.clone(),
            templates: config
                .discovery_upstreams
                .iter()
                .map(|n| upstreams[n].clone())
                .collect(),
            allowed: config
                .allowed_target_api_roots
                .iter()
                .map(|v| ApiRoot::parse(v))
                .collect::<Result<_, _>>()?,
            cache: Mutex::new(HashMap::new()),
            permits: Arc::new(Semaphore::new(MAX_NRF_REQUESTS)),
        })
    }

    fn template(&self, request: &ScpRequest) -> Result<&CompiledUpstreamGroup, ScpError> {
        let candidates = self
            .templates
            .iter()
            .filter(|g| {
                let nrf = g.nrf_discovery.as_ref().expect("validated NRF upstream");
                request.query.service_names.first() == Some(&nrf.service_name)
                    && request
                        .target_type
                        .as_ref()
                        .is_none_or(|t| t == &nrf.target_nf_type)
                    && request
                        .requester_type
                        .as_ref()
                        .is_none_or(|t| t == &nrf.requester_nf_type)
            })
            .collect::<Vec<_>>();
        if candidates.len() != 1 {
            return Err(ScpError::new(
                403,
                "UNSPECIFIED_MSG_FAILURE",
                "Discovery factors must identify one allowed NF/service/requester combination",
            ));
        }
        let selected = candidates[0].nrf_discovery.as_ref().expect("NRF template");
        if request.query.service_names.iter().any(|name| {
            !self.templates.iter().any(|g| {
                g.nrf_discovery.as_ref().is_some_and(|nrf| {
                    &nrf.service_name == name
                        && nrf.target_nf_type == selected.target_nf_type
                        && nrf.requester_nf_type == selected.requester_nf_type
                })
            })
        }) {
            return Err(ScpError::new(
                403,
                "UNSPECIFIED_MSG_FAILURE",
                "Service is outside the allowed discovery domain",
            ));
        }
        Ok(candidates[0])
    }

    async fn discovered(
        &self,
        request: &ScpRequest,
    ) -> Result<Arc<RuntimeUpstreamGroup>, ScpError> {
        let template = self.template(request)?;
        let key = CacheKey {
            upstream: template.name.clone(),
            query: request.query.clone(),
        };
        let group = {
            let mut cache = self.cache.lock().expect("SCP cache lock");
            if !cache.contains_key(&key) {
                if cache.len() == MAX_CACHE_ENTRIES {
                    let evict = cache
                        .iter()
                        .filter(|(_, e)| Arc::strong_count(&e.group) == 1)
                        .min_by_key(|(_, e)| e.last_used)
                        .map(|(k, _)| k.clone());
                    if let Some(evict) = evict {
                        cache.remove(&evict);
                    } else {
                        return Err(ScpError::new(
                            503,
                            "SCP_CONGESTION",
                            "Discovery cache is busy",
                        ));
                    }
                }
                let mut compiled = template.clone();
                compiled.name = self.config.name.clone();
                let group = RuntimeUpstreamGroup::from_compiled_query(
                    &compiled,
                    Some(request.query.clone()),
                    Some(self.permits.clone()),
                )
                .map_err(|e| ScpError::new(500, "SYSTEM_FAILURE", e))?;
                cache.insert(
                    key.clone(),
                    CacheEntry {
                        group: Arc::new(group),
                        last_used: Instant::now(),
                    },
                );
                crate::metrics::record_scp_event(&self.config.name, "discovery_miss");
            } else {
                crate::metrics::record_scp_event(&self.config.name, "discovery_hit");
            }
            let entry = cache.get_mut(&key).expect("inserted cache entry");
            entry.last_used = Instant::now();
            entry.group.clone()
        };
        if group.scp_status().is_err() {
            // The bounded refresh owns its lifetime so disconnecting one waiter
            // cannot cancel discovery for other requests sharing the same key.
            let timeout = template
                .nrf_discovery
                .as_ref()
                .expect("validated NRF upstream")
                .timeout;
            tokio::time::timeout(timeout, group.refresh_scp())
                .await
                .map_err(|_| ScpError::nrf_unreachable())?;
        }
        group.scp_status()?;
        Ok(group)
    }

    pub(crate) fn maintain(&self) {
        let groups = {
            let mut cache = self.cache.lock().expect("SCP cache lock");
            cache
                .retain(|_, e| e.last_used.elapsed() < IDLE_TTL || Arc::strong_count(&e.group) > 1);
            crate::metrics::set_scp_cache_entries(&self.config.name, cache.len());
            cache.values().map(|e| e.group.clone()).collect::<Vec<_>>()
        };
        for group in groups {
            group.start_scp_refresh();
        }
    }

    pub(super) async fn route(
        self: &Arc<Self>,
        request: ScpRequest,
        headers: &HeaderMap,
        client_ip: &[u8],
    ) -> Result<ScpExchange, ScpError> {
        if !request.discovery
            && let Some(root) = &request.target
        {
            if self.allowed.contains(root) {
                return Ok(ScpExchange {
                    profile: self.clone(),
                    request: request.clone(),
                    root: root.clone(),
                    backend: root.backend(),
                    group: None,
                    key: Vec::new(),
                    attempted: Vec::new(),
                });
            }
            // A previously discovered root remains usable only while its
            // snapshot is valid. Never search other profiles' caches.
            let mut cache = self.cache.lock().expect("SCP cache lock");
            let mut unavailable = None;
            for (key, entry) in cache.iter_mut() {
                let template = self
                    .templates
                    .iter()
                    .find(|g| g.name == key.upstream)
                    .expect("cached template");
                let scheme = template_scheme(template);
                if !entry
                    .group
                    .scp_candidates()
                    .iter()
                    .any(|b| backend_root(b, scheme).as_ref() == Some(root))
                {
                    continue;
                }
                entry.last_used = Instant::now();
                unavailable = Some(
                    entry
                        .group
                        .scp_status()
                        .err()
                        .unwrap_or_else(ScpError::target_unreachable),
                );
                if let Some(backend) = entry.group.scp_select(client_ip, |b| {
                    backend_root(b, scheme).as_ref() == Some(root)
                }) {
                    return Ok(ScpExchange {
                        profile: self.clone(),
                        request: request.clone(),
                        root: root.clone(),
                        backend,
                        group: Some(entry.group.clone()),
                        key: client_ip.to_vec(),
                        attempted: Vec::new(),
                    });
                }
            }
            if let Some(error) = unavailable {
                return Err(error);
            }
            return Err(ScpError::new(
                403,
                "UNSPECIFIED_MSG_FAILURE",
                "Target apiRoot is not authorized by this profile",
            ));
        }
        let group = self.discovered(&request).await?;
        let key = match group.hash_key() {
            Some(ngxora_compile::ir::UpstreamHashKey::Header(name)) => single(headers, name)?
                .map(String::into_bytes)
                .unwrap_or_else(|| client_ip.to_vec()),
            _ => client_ip.to_vec(),
        };
        let scheme = template_scheme(self.template(&request)?);
        let mut backend = request.target.as_ref().and_then(|target| {
            group.scp_select(&key, |b| backend_root(b, scheme).as_ref() == Some(target))
        });
        if backend.is_none() {
            if let Some(target) = &request.target
                && !group
                    .scp_candidates()
                    .iter()
                    .any(|b| backend_root(b, scheme).as_ref() == Some(target))
            {
                return Err(ScpError::invalid(
                    "Target conflicts with discovery or binding",
                ));
            }
            backend = group.scp_select(&key, |_| true);
        }
        let backend = backend.ok_or_else(ScpError::target_unreachable)?;
        let root = backend_root(&backend, scheme).ok_or_else(|| {
            ScpError::new(
                502,
                "SYSTEM_FAILURE",
                "NRF returned an invalid target authority",
            )
        })?;
        if root.host == self.root.host && root.port == self.root.port {
            return Err(ScpError::new(
                508,
                "UNSPECIFIED_MSG_FAILURE",
                "SCP routing loop",
            ));
        }
        Ok(ScpExchange {
            profile: self.clone(),
            request,
            root,
            backend,
            group: Some(group),
            key,
            attempted: Vec::new(),
        })
    }
}

fn template_scheme(template: &CompiledUpstreamGroup) -> &'static str {
    match template
        .nrf_discovery
        .as_ref()
        .expect("validated NRF upstream")
        .endpoint_scheme
    {
        ngxora_compile::ir::NrfEndpointScheme::Http => "http",
        ngxora_compile::ir::NrfEndpointScheme::Https => "https",
    }
}

fn backend_root(backend: &CompiledUpstreamServer, scheme: &str) -> Option<ApiRoot> {
    let host = backend
        .nrf_service
        .as_ref()
        .and_then(|m| m.authority.as_ref())
        .unwrap_or(&backend.host);
    let host = if host.contains(':') {
        format!("[{host}]")
    } else {
        host.clone()
    };
    ApiRoot::parse(&format!(
        "{scheme}://{host}:{}{}",
        backend.port,
        backend.api_prefix.as_deref().unwrap_or("")
    ))
    .ok()
}

pub(crate) struct ScpExchange {
    pub(super) profile: Arc<RuntimeScp>,
    pub(super) request: ScpRequest,
    pub(super) root: ApiRoot,
    pub(super) backend: CompiledUpstreamServer,
    group: Option<Arc<RuntimeUpstreamGroup>>,
    key: Vec<u8>,
    attempted: Vec<CompiledUpstreamServer>,
}

impl ScpExchange {
    pub(super) fn retry_connect(&mut self) -> bool {
        if !self.attempted.is_empty() {
            return false;
        }
        let Some(group) = &self.group else {
            return false;
        };
        self.attempted.push(self.backend.clone());
        let backend = group.scp_select(&self.key, |b| {
            !self.attempted.contains(b)
                && (self.request.discovery
                    || backend_root(b, &self.root.scheme).as_ref() == self.request.target.as_ref())
        });
        let Some(backend) = backend else {
            return false;
        };
        let Some(root) = backend_root(&backend, &self.root.scheme) else {
            return false;
        };
        if root.host == self.profile.root.host && root.port == self.profile.root.port {
            return false;
        }
        self.root = root;
        self.backend = backend;
        crate::metrics::record_scp_event(&self.profile.config.name, "connect_retry");
        true
    }

    pub(super) fn upstream_uri(&self) -> Result<Uri, ScpError> {
        format!(
            "{}://{}{}{}",
            self.root.scheme,
            self.root.authority(),
            self.root.prefix,
            self.request.path_query
        )
        .parse()
        .map_err(|_| ScpError::invalid("Invalid upstream URI"))
    }

    pub(super) fn request_headers(&self, headers: &mut HeaderMap) {
        let remove = headers
            .keys()
            .filter(|n| {
                n.as_str() == TARGET
                    || n.as_str().starts_with(DISCOVERY)
                    || n.as_str() == "3gpp-sbi-routing-binding"
            })
            .cloned()
            .collect::<Vec<_>>();
        for name in remove {
            headers.remove(name);
        }
        headers.insert(
            http::header::HOST,
            self.root.authority().parse().expect("validated authority"),
        );
        headers.insert(
            "3gpp-sbi-max-forward-hops",
            self.request
                .hops
                .to_string()
                .parse()
                .expect("integer header"),
        );
    }

    pub(super) fn response_headers(&self, headers: &mut HeaderMap) {
        if let Some(metadata) = &self.backend.nrf_service
            && let Ok(value) = format!(
                "nfinst={}; nfservinst={}",
                metadata.nf_instance_id, metadata.service_instance_id
            )
            .parse()
        {
            headers.insert("3gpp-sbi-producer-id", value);
        }
        if !headers.contains_key(http::header::LOCATION)
            && (self.request.discovery || self.request.target.as_ref() != Some(&self.root))
        {
            headers.insert(
                TARGET,
                self.root.value().parse().expect("validated apiRoot"),
            );
        }
    }
}
