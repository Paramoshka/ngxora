//! Compile route actions, policy, cache and upstream transport settings.

use super::proxy_pass_sni;
use super::upstream_groups::normalize_upstream_name;
use crate::upstreams::types::{
    CompiledLocation, CompiledMatcher, CompiledUpstreamGroup, RouteTarget,
};
use ngxora_compile::ir::{
    Location, LocationDirective, ProxyPassTarget, UpstreamHttpProtocol, UpstreamSslOptions,
    UpstreamTimeouts,
};
use std::collections::HashMap;

fn proxy_pass_tls(scheme: &str) -> Option<bool> {
    match scheme {
        "http" => Some(false),
        "https" => Some(true),
        _ => None,
    }
}

fn upstream_group_from_url<'a>(
    url: &url::Url,
    upstreams: &'a HashMap<String, CompiledUpstreamGroup>,
) -> Option<&'a CompiledUpstreamGroup> {
    if url.port().is_some() {
        return None;
    }
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return None;
    }

    let host = normalize_upstream_name(url.host_str()?);
    upstreams.get(&host)
}

fn set_timeout_once(
    slot: &mut Option<std::time::Duration>,
    value: std::time::Duration,
    directive: &str,
) -> Result<(), String> {
    if slot.replace(value).is_some() {
        return Err(format!("{directive} is duplicated in the same location"));
    }

    Ok(())
}

fn route_target_from_directive(
    directive: &LocationDirective,
    upstreams: &HashMap<String, CompiledUpstreamGroup>,
) -> Result<Option<RouteTarget>, String> {
    match directive {
        LocationDirective::DirectResponse(status) => {
            validate_direct_status(*status)?;
            Ok(Some(RouteTarget::DirectResponse(*status)))
        }
        LocationDirective::HttpRedirect(config) => {
            Ok(Some(RouteTarget::HttpRedirect(config.clone())))
        }
        LocationDirective::WeightedBackends(backends) => {
            if backends.is_empty() {
                return Err("weighted_backends must not be empty".into());
            }
            let backends = backends
                .iter()
                .map(|backend| {
                    if backend.weight > 1_000_000 {
                        return Err("backend weight exceeds 1000000".into());
                    }
                    let directive = match &backend.target {
                        ngxora_compile::ir::BackendTarget::Upstream(target) => {
                            LocationDirective::ProxyPass(target.clone())
                        }
                        ngxora_compile::ir::BackendTarget::Response(status) => {
                            LocationDirective::DirectResponse(*status)
                        }
                    };
                    let target = route_target_from_directive(&directive, upstreams)?
                        .ok_or("invalid weighted backend target")?;
                    Ok(crate::upstreams::types::CompiledWeightedBackend {
                        weight: backend.weight,
                        target,
                    })
                })
                .collect::<Result<Vec<_>, String>>()?;
            Ok(Some(RouteTarget::WeightedBackends(backends)))
        }
        LocationDirective::ScpPass(profile) => Ok(Some(RouteTarget::Scp {
            profile: profile.clone(),
        })),
        LocationDirective::ProxyPass(ProxyPassTarget::Url(url)) => {
            if let Some(group) = upstream_group_from_url(url, upstreams) {
                let tls = proxy_pass_tls(url.scheme())
                    .ok_or_else(|| format!("unsupported proxy_pass scheme `{}`", url.scheme()))?;
                validate_nrf_route_scheme(group, tls)?;
                return Ok(Some(RouteTarget::UpstreamGroup {
                    name: group.name.clone(),
                    tls,
                }));
            }

            let Some(host) = url.host_str().map(ToString::to_string) else {
                return Ok(None);
            };
            let Some(port) = url.port_or_known_default() else {
                return Ok(None);
            };
            let tls = match proxy_pass_tls(url.scheme()) {
                Some(value) => value,
                None => return Ok(None),
            };

            Ok(Some(RouteTarget::ProxyPass {
                sni: proxy_pass_sni(&host, tls),
                host,
                port,
                tls,
            }))
        }

        LocationDirective::ProxyPass(ProxyPassTarget::UpstreamGroup { name, tls }) => {
            let normalized = normalize_upstream_name(name);
            let group = upstreams
                .get(&normalized)
                .ok_or_else(|| format!("proxy_pass references unknown upstream `{name}`"))?;
            validate_nrf_route_scheme(group, *tls)?;
            Ok(Some(RouteTarget::UpstreamGroup {
                name: group.name.clone(),
                tls: *tls,
            }))
        }

        LocationDirective::Return { status, location } => Ok(Some(RouteTarget::Return {
            status: *status,
            location: location.clone(),
        })),

        _ => Ok(None),
    }
}

fn validate_nrf_route_scheme(group: &CompiledUpstreamGroup, tls: bool) -> Result<(), String> {
    let Some(discovery) = group.nrf_discovery.as_ref() else {
        return Ok(());
    };
    let expects_tls = matches!(
        discovery.endpoint_scheme,
        ngxora_compile::ir::NrfEndpointScheme::Https
    );
    if tls != expects_tls {
        return Err(format!(
            "proxy_pass scheme for NRF upstream `{}` must match endpoint_scheme {}",
            group.name,
            if expects_tls { "https" } else { "http" }
        ));
    }
    Ok(())
}

fn route_target(
    location: &Location,
    upstreams: &HashMap<String, CompiledUpstreamGroup>,
) -> Result<Option<RouteTarget>, String> {
    location
        .directives
        .iter()
        .find_map(
            |directive| match route_target_from_directive(directive, upstreams) {
                Ok(Some(target)) => Some(Ok(target)),
                Ok(None) => None,
                Err(err) => Some(Err(err)),
            },
        )
        .transpose()
}

fn compile_upstream_timeouts(location: &Location) -> Result<UpstreamTimeouts, String> {
    let mut timeouts = UpstreamTimeouts::default();

    for directive in &location.directives {
        match directive {
            LocationDirective::ProxyConnectTimeout(value) => {
                set_timeout_once(&mut timeouts.connect, *value, "proxy_connect_timeout")?;
            }
            LocationDirective::ProxyReadTimeout(value) => {
                set_timeout_once(&mut timeouts.read, *value, "proxy_read_timeout")?;
            }
            LocationDirective::ProxyWriteTimeout(value) => {
                set_timeout_once(&mut timeouts.write, *value, "proxy_write_timeout")?;
            }
            _ => {}
        }
    }

    Ok(timeouts)
}

fn compile_upstream_protocol(
    location: &Location,
    target: &RouteTarget,
) -> Result<Option<UpstreamHttpProtocol>, String> {
    let mut protocol = None;

    for directive in &location.directives {
        if let LocationDirective::ProxyUpstreamProtocol(value) = directive
            && protocol.replace(*value).is_some()
        {
            return Err("proxy_upstream_protocol is duplicated in the same location".into());
        }
    }

    if let Some(protocol) = protocol {
        let target_uses_tls = match target {
            RouteTarget::Scp { .. } => return Err("scp_pass chooses HTTP/2 transport from the target scheme; omit proxy_upstream_protocol".into()),
            RouteTarget::ProxyPass { tls, .. } | RouteTarget::UpstreamGroup { tls, .. } => *tls,
            RouteTarget::Return { .. } | RouteTarget::DirectResponse(_) | RouteTarget::HttpRedirect(_) => return Ok(None),
            RouteTarget::WeightedBackends(backends) => {
                for backend in backends { compile_upstream_protocol(location, &backend.target)?; }
                return Ok(Some(protocol));
            }
        };

        match protocol {
            UpstreamHttpProtocol::H1 => {}
            UpstreamHttpProtocol::H2 if !target_uses_tls => {
                return Err(
                    "proxy_upstream_protocol h2 requires TLS upstream; use https proxy_pass or h2c"
                        .into(),
                );
            }
            UpstreamHttpProtocol::H2c if target_uses_tls => {
                return Err(
                    "proxy_upstream_protocol h2c requires plaintext upstream; use http proxy_pass"
                        .into(),
                );
            }
            _ => {}
        }
    }

    Ok(protocol)
}

fn compile_upstream_ssl_options(location: &Location) -> Result<UpstreamSslOptions, String> {
    let mut options = UpstreamSslOptions::default();
    let mut seen_cert = false;
    let mut seen_key = false;

    for directive in &location.directives {
        match directive {
            LocationDirective::ProxySslVerify(switch) => {
                options.verify_cert = *switch;
            }
            LocationDirective::ProxySslTrustedCertificate(pem_source) => {
                options.trusted_certificate = Some(pem_source.clone());
            }
            LocationDirective::ProxySslCertificate(pem_source) => {
                if seen_cert {
                    return Err("proxy_ssl_certificate is duplicated in the same location".into());
                }
                seen_cert = true;
                options.client_certificate = Some(pem_source.clone());
            }
            LocationDirective::ProxySslCertificateKey(pem_source) => {
                if seen_key {
                    return Err(
                        "proxy_ssl_certificate_key is duplicated in the same location".into(),
                    );
                }
                seen_key = true;
                options.client_certificate_key = Some(pem_source.clone());
            }
            _ => {}
        }
    }

    // mTLS to upstream requires both the client certificate and its private key.
    match (
        options.client_certificate.is_some(),
        options.client_certificate_key.is_some(),
    ) {
        (true, false) => {
            return Err("proxy_ssl_certificate requires proxy_ssl_certificate_key".into());
        }
        (false, true) => {
            return Err("proxy_ssl_certificate_key requires proxy_ssl_certificate".into());
        }
        _ => {}
    }

    Ok(options)
}

fn compile_location(
    location: &Location,
    upstreams: &HashMap<String, CompiledUpstreamGroup>,
    next_route_id: &mut u64,
) -> Result<Option<CompiledLocation>, String> {
    let mut action_count = 0;
    for directive in &location.directives {
        match directive {
            LocationDirective::ProxyPass(_)
            | LocationDirective::ScpPass(_)
            | LocationDirective::Return { .. }
            | LocationDirective::WeightedBackends(_)
            | LocationDirective::DirectResponse(_)
            | LocationDirective::HttpRedirect(_) => {
                action_count += 1;
            }
            LocationDirective::Root(_) => return Err("root is not supported at runtime".into()),
            LocationDirective::TryFiles(_) => {
                return Err("try_files is not supported at runtime".into());
            }
            _ => {}
        }
    }
    if action_count != 1 {
        return Err("location must contain exactly one proxy_pass or return directive".into());
    }

    let Some(target) = route_target(location, upstreams)? else {
        return Ok(None);
    };
    let upstream_protocol = compile_upstream_protocol(location, &target)?;
    if matches!(target, RouteTarget::Scp { .. }) && location.cache.is_some() {
        return Err("scp_pass cannot be combined with proxy_cache".into());
    }

    let matcher = CompiledMatcher::try_from(&location.matcher)?;
    let mut url_rewrite = None;
    for directive in &location.directives {
        if let LocationDirective::UrlRewrite(rewrite) = directive {
            if url_rewrite.replace(rewrite.clone()).is_some() {
                return Err("duplicate URL rewrite".into());
            }
            if !matches!(
                target,
                RouteTarget::ProxyPass { .. }
                    | RouteTarget::UpstreamGroup { .. }
                    | RouteTarget::WeightedBackends(_)
            ) {
                return Err("URL rewrite requires an upstream action".into());
            }
            if let Some(host) = &rewrite.hostname {
                crate::upstreams::http_routes::validate_hostname(host)?;
            }
            crate::upstreams::http_routes::validate_modifier(rewrite.path.as_ref(), &matcher)?;
        }
    }
    match &target {
        RouteTarget::HttpRedirect(config) => {
            if ![301, 302, 303, 307, 308].contains(&config.status) {
                return Err("invalid HTTP redirect status".into());
            }
            if config
                .scheme
                .as_deref()
                .is_some_and(|s| !matches!(s, "http" | "https"))
            {
                return Err("redirect scheme must be http or https".into());
            }
            if config.port == Some(0) {
                return Err("redirect port must be positive".into());
            }
            if let Some(host) = &config.hostname {
                crate::upstreams::http_routes::validate_hostname(host)?;
            }
            crate::upstreams::http_routes::validate_modifier(config.path.as_ref(), &matcher)?;
        }
        RouteTarget::Return { status, location } => {
            if !(300..400).contains(status) {
                return Err("return requires a 3xx status".into());
            }
            crate::upstreams::http_routes::expand_return(location, "example.com", "/", "http")?;
            http::HeaderValue::from_str(location).map_err(|_| "invalid redirect location")?;
        }
        _ => {}
    }
    let compiled = CompiledLocation {
        client_limits: compile_client_limits(location)?,
        url_rewrite,
        route_id: *next_route_id,
        matcher,
        access_rules: location.access_rules.clone(),
        target,
        upstream_timeouts: compile_upstream_timeouts(location)?,
        upstream_protocol,
        upstream_http2: compile_upstream_http2(location)?,
        upstream_ssl_options: compile_upstream_ssl_options(location)?,
        plugins: location.plugins.clone(),
        cache: location.cache.clone(),
    };
    *next_route_id += 1;
    Ok(Some(compiled))
}

// Only locations with an actionable upstream target are kept. Regex validation
// also happens here, so broken snapshots fail before they are applied.
pub(super) fn compile_locations(
    locations: &[Location],
    upstreams: &HashMap<String, CompiledUpstreamGroup>,
    next_route_id: &mut u64,
) -> Result<Vec<CompiledLocation>, String> {
    let http_count = locations
        .iter()
        .filter(|l| matches!(l.matcher, ngxora_compile::ir::LocationMatcher::Http(_)))
        .count();
    if http_count != 0 && http_count != locations.len() {
        return Err("cannot mix HTTP and nginx matchers in one virtual host".into());
    }
    locations
        .iter()
        .map(|location| compile_location(location, upstreams, next_route_id))
        .filter_map(|result| match result {
            Ok(Some(location)) => Some(Ok(location)),
            Ok(None) => None,
            Err(err) => Some(Err(err)),
        })
        .collect()
}

fn compile_client_limits(location: &Location) -> Result<ngxora_compile::ir::ClientLimits, String> {
    let mut limits = ngxora_compile::ir::ClientLimits::default();
    let mut seen_methods = false;
    for directive in &location.directives {
        match directive {
            LocationDirective::ClientMaxBodySize(value) => {
                if limits.max_body_size.is_some() {
                    return Err("client_max_body_size is duplicated in location".into());
                }
                limits.max_body_size = Some(*value);
            }
            LocationDirective::ClientBodyTimeout(value) => {
                set_timeout_once(&mut limits.body_timeout, *value, "client_body_timeout")?;
            }
            LocationDirective::SendTimeout(value) => {
                set_timeout_once(&mut limits.send_timeout, *value, "send_timeout")?;
            }
            LocationDirective::AllowMethods(methods) => {
                if seen_methods || methods.is_empty() {
                    return Err("allow_methods must be nonempty and declared once".into());
                }
                seen_methods = true;
                for method in methods {
                    http::Method::from_bytes(method.as_bytes())
                        .map_err(|_| "invalid allowed HTTP method")?;
                    if !limits.allowed_methods.contains(method) {
                        limits.allowed_methods.push(method.clone());
                    }
                }
            }
            _ => {}
        }
    }
    for timeout in [limits.body_timeout, limits.send_timeout] {
        ngxora_compile::ir::validate_client_timeout(timeout)?;
    }
    Ok(limits)
}

fn validate_direct_status(status: u16) -> Result<(), String> {
    if !(200..=599).contains(&status) {
        return Err("direct response status must be 200..599".into());
    }
    Ok(())
}

fn compile_upstream_http2(
    location: &Location,
) -> Result<ngxora_compile::ir::UpstreamHttp2Options, String> {
    let mut options = ngxora_compile::ir::UpstreamHttp2Options::default();
    for directive in &location.directives {
        let (slot, value, name) = match directive {
            LocationDirective::ProxyHttp2MaxConcurrentStreams(value) => (
                &mut options.max_concurrent_streams,
                *value,
                "proxy_http2_max_concurrent_streams",
            ),
            LocationDirective::ProxyHttp2StreamWindowSize(value) => (
                &mut options.stream_window_size,
                *value,
                "proxy_http2_stream_window_size",
            ),
            LocationDirective::ProxyHttp2ConnectionWindowSize(value) => (
                &mut options.connection_window_size,
                *value,
                "proxy_http2_connection_window_size",
            ),
            _ => continue,
        };
        if slot.replace(value).is_some() {
            return Err(format!("{name} is duplicated in the same location"));
        }
    }
    options.validate()?;
    Ok(options)
}
