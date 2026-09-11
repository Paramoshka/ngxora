//! Bounded SCP discovery cache, selection, retries and producer exchange.

use crate::upstreams::nrf::NrfQuery;
use crate::upstreams::runtime::RuntimeUpstreamGroup;
use crate::upstreams::types::{CompiledUpstreamGroup, CompiledUpstreamServer};
use http::{HeaderMap, Uri};
use ngxora_compile::ir::ScpProfile;
use ngxora_plugin_api::LocalResponse;
use request::single;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::Semaphore;
use tokio::time::Instant;

mod request;

const MAX_CACHE_ENTRIES: usize = 256;

const MAX_NRF_REQUESTS: usize = 16;

const IDLE_TTL: Duration = Duration::from_secs(300);

const DISCOVERY: &str = "3gpp-sbi-discovery-";

const TARGET: &str = "3gpp-sbi-target-apiroot";

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
    pub(super) fn invalid(detail: impl Into<String>) -> Self {
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

    pub(super) fn request_headers(
        &self,
        header: &mut pingora::http::RequestHeader,
    ) -> pingora::Result<()> {
        let remove = header
            .headers
            .keys()
            .filter(|n| {
                n.as_str() == TARGET
                    || n.as_str().starts_with(DISCOVERY)
                    || n.as_str() == "3gpp-sbi-routing-binding"
            })
            .cloned()
            .collect::<Vec<_>>();
        for name in remove {
            header.remove_header(&name);
        }
        header.insert_header(http::header::HOST, self.root.authority())?;
        header.insert_header("3gpp-sbi-max-forward-hops", self.request.hops.to_string())?;
        Ok(())
    }

    pub(super) fn response_headers(
        &self,
        header: &mut pingora::http::ResponseHeader,
    ) -> pingora::Result<()> {
        if let Some(metadata) = &self.backend.nrf_service {
            header.insert_header(
                "3gpp-sbi-producer-id",
                format!(
                    "nfinst={}; nfservinst={}",
                    metadata.nf_instance_id, metadata.service_instance_id
                ),
            )?;
        }
        if !header.headers.contains_key(http::header::LOCATION)
            && (self.request.discovery || self.request.target.as_ref() != Some(&self.root))
        {
            header.insert_header(TARGET, self.root.value())?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "scp_tests.rs"]
mod tests;

pub(super) use request::ApiRoot;

pub(super) use request::ScpRequest;

pub(super) use request::token;

pub(super) use request::validate_profile;
