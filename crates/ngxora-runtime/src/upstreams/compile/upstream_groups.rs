//! Compile upstream endpoints, balancing, health checks and NRF configuration.

use crate::upstreams::types::{
    CompiledHealthCheck, CompiledNrfDiscovery, CompiledUpstreamGroup, CompiledUpstreamServer,
    HealthCheckType,
};
use ngxora_compile::ir::{
    NrfDiscovery, UpstreamBlock, UpstreamHealthCheck, UpstreamHealthCheckType,
    UpstreamSelectionPolicy, UpstreamServer,
};
use std::collections::HashMap;

pub(super) fn normalize_upstream_name(name: &str) -> String {
    name.trim_end_matches('.').to_ascii_lowercase()
}

fn compile_upstream_server(server: &UpstreamServer) -> Result<CompiledUpstreamServer, String> {
    if server.host.trim().is_empty() {
        return Err("upstream server host cannot be empty".into());
    }
    if server.port == 0 {
        return Err(format!(
            "upstream server `{}` port must be greater than zero",
            server.host
        ));
    }

    Ok(CompiledUpstreamServer {
        host: server.host.clone(),
        port: server.port,
        weight: server.weight,
        api_prefix: None,
        nrf_service: None,
    })
}

fn compile_upstream_health_check(
    health_check: &UpstreamHealthCheck,
) -> Result<CompiledHealthCheck, String> {
    if health_check.timeout.is_zero() {
        return Err("health_check timeout must be greater than zero".into());
    }
    if health_check.interval.is_zero() {
        return Err("health_check interval must be greater than zero".into());
    }
    if health_check.consecutive_success == 0 {
        return Err("health_check consecutive_success must be greater than zero".into());
    }
    if health_check.consecutive_failure == 0 {
        return Err("health_check consecutive_failure must be greater than zero".into());
    }

    let check_type = match &health_check.check_type {
        UpstreamHealthCheckType::Tcp => HealthCheckType::Tcp,
        UpstreamHealthCheckType::Http {
            host,
            path,
            use_tls,
        } => {
            if host.trim().is_empty() {
                return Err("health_check http host cannot be empty".into());
            }
            let uri = path
                .parse::<http::Uri>()
                .map_err(|err| format!("invalid health_check path `{path}`: {err}"))?;
            if uri.scheme().is_some() || uri.authority().is_some() || !path.starts_with('/') {
                return Err(format!(
                    "health_check path `{path}` must be an origin-form path starting with `/`"
                ));
            }
            HealthCheckType::Http {
                host: host.clone(),
                path: path.clone(),
                use_tls: *use_tls,
            }
        }
    };

    Ok(CompiledHealthCheck {
        check_type,
        timeout: health_check.timeout,
        interval: health_check.interval,
        consecutive_success: health_check.consecutive_success,
        consecutive_failure: health_check.consecutive_failure,
    })
}

fn compile_nrf_discovery(discovery: &NrfDiscovery) -> Result<CompiledNrfDiscovery, String> {
    let api_root = url::Url::parse(&discovery.api_root)
        .map_err(|err| format!("nrf_discovery api_root is invalid: {err}"))?;
    if !matches!(api_root.scheme(), "http" | "https") {
        return Err("nrf_discovery api_root must use http or https".into());
    }
    if api_root.host_str().is_none() || api_root.cannot_be_a_base() {
        return Err("nrf_discovery api_root must be an absolute HTTP URL".into());
    }
    if api_root.query().is_some() || api_root.fragment().is_some() {
        return Err("nrf_discovery api_root must not contain a query or fragment".into());
    }
    if discovery.timeout.is_zero() {
        return Err("nrf_discovery timeout must be greater than zero".into());
    }
    if discovery.stale_if_error.is_zero() {
        return Err("nrf_discovery stale_if_error must be greater than zero".into());
    }
    match (
        &discovery.tls_options.client_certificate,
        &discovery.tls_options.client_certificate_key,
    ) {
        (Some(_), Some(_)) | (None, None) => {}
        _ => {
            return Err(
                "nrf_discovery ssl_certificate and ssl_certificate_key must be configured together"
                    .into(),
            );
        }
    }

    Ok(CompiledNrfDiscovery {
        api_root,
        target_nf_type: discovery.target_nf_type.trim().to_ascii_uppercase(),
        requester_nf_type: discovery.requester_nf_type.trim().to_ascii_uppercase(),
        service_name: discovery.service_name.trim().to_string(),
        endpoint_scheme: discovery.endpoint_scheme,
        timeout: discovery.timeout,
        stale_if_error: discovery.stale_if_error,
        tls_options: discovery.tls_options.clone(),
    })
}

pub(super) fn compile_upstreams(
    upstreams: &[UpstreamBlock],
) -> Result<HashMap<String, CompiledUpstreamGroup>, String> {
    let mut compiled = HashMap::with_capacity(upstreams.len());

    for upstream in upstreams {
        let name = normalize_upstream_name(&upstream.name);
        if name.is_empty() {
            return Err("upstream name cannot be empty".into());
        }
        if upstream.servers.is_empty() && upstream.nrf_discovery.is_none() && !upstream.allow_empty
        {
            return Err(format!(
                "upstream `{}` must define at least one server or nrf_discovery",
                upstream.name
            ));
        }
        if !upstream.servers.is_empty() && upstream.nrf_discovery.is_some() {
            return Err(format!(
                "upstream `{}` cannot combine server directives with nrf_discovery",
                upstream.name
            ));
        }
        if upstream.nrf_discovery.is_some() && upstream.health_check.is_none() {
            return Err(format!(
                "upstream `{}` with nrf_discovery must define health_check",
                upstream.name
            ));
        }
        let total_weight = upstream.servers.iter().try_fold(0u32, |total, server| {
            if server.weight == 0 {
                return Err(format!(
                    "upstream `{}` backend `{}:{}` weight must be greater than zero",
                    upstream.name, server.host, server.port
                ));
            }
            Ok(total + u32::from(server.weight))
        })?;
        if total_weight > u32::from(u16::MAX) {
            return Err(format!(
                "upstream `{}` total backend weight must not exceed {}",
                upstream.name,
                u16::MAX
            ));
        }
        if upstream.hash_key.is_some() && upstream.policy != UpstreamSelectionPolicy::ConsistentHash
        {
            return Err(format!(
                "upstream `{}` hash_key requires policy consistent_hash",
                upstream.name
            ));
        }
        if let Some(ngxora_compile::ir::UpstreamHashKey::Header(name)) = &upstream.hash_key {
            http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| {
                format!(
                    "upstream `{}` hash_key has invalid HTTP header name `{name}`",
                    upstream.name
                )
            })?;
        }

        let group = CompiledUpstreamGroup {
            allow_empty: upstream.allow_empty,
            name: upstream.name.clone(),
            policy: upstream.policy,
            hash_key: upstream.hash_key.clone(),
            servers: upstream
                .servers
                .iter()
                .map(compile_upstream_server)
                .collect::<Result<Vec<_>, _>>()?,
            nrf_discovery: upstream
                .nrf_discovery
                .as_ref()
                .map(compile_nrf_discovery)
                .transpose()?,
            health_check: upstream
                .health_check
                .as_ref()
                .map(compile_upstream_health_check)
                .transpose()?,
        };

        if compiled.insert(name.clone(), group).is_some() {
            return Err(format!("upstream `{}` is duplicated", upstream.name));
        }
    }

    Ok(compiled)
}
