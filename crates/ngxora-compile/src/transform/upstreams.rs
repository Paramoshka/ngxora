//! Upstream groups, health checks and NRF/SCP discovery configuration.

use super::LowerErr;
use super::values::{
    ensure_non_zero_duration, get_directive_switch, parse_exactly_one_argument,
    parse_positive_usize, parse_single_duration_directive, set_once,
};
use crate::consts;
use crate::ir::{
    NrfDiscovery, NrfEndpointScheme, PemSource, Switch, UpstreamBlock, UpstreamHashKey,
    UpstreamHealthCheck, UpstreamHealthCheckType, UpstreamSelectionPolicy, UpstreamServer,
    UpstreamSslOptions,
};
use ngxora_config::{Block, Directive, Node};

pub(super) fn lower_scp(block: &Block) -> Result<crate::ir::ScpProfile, LowerErr> {
    let mut profile = crate::ir::ScpProfile {
        name: parse_exactly_one_argument(&block.args, "scp")?.to_string(),
        ..Default::default()
    };
    for child in &block.children {
        let Node::Directive(directive) = child else {
            return Err(LowerErr {
                message: "scp: nested blocks are not supported".into(),
            });
        };
        let value = parse_exactly_one_argument(&directive.args, &directive.name)?.to_string();
        match directive.name.as_str() {
            "api_root" if profile.api_root.is_empty() => profile.api_root = value,
            "discovery_upstream" => profile.discovery_upstreams.push(value),
            "allow_target_api_root" => profile.allowed_target_api_roots.push(value),
            _ => {
                return Err(LowerErr {
                    message: format!(
                        "scp: unsupported or duplicate directive `{}`",
                        directive.name
                    ),
                });
            }
        }
    }
    Ok(profile)
}

pub(super) fn lower_upstream(block: &Block) -> Result<UpstreamBlock, LowerErr> {
    let name = match block.args.as_slice() {
        [name] if !name.trim().is_empty() => name.clone(),
        [] => {
            return Err(LowerErr {
                message: "upstream block: expected upstream name".into(),
            });
        }
        _ => {
            return Err(LowerErr {
                message: "upstream block: expected exactly 1 argument".into(),
            });
        }
    };

    let mut upstream = UpstreamBlock {
        allow_empty: false,
        name,
        policy: UpstreamSelectionPolicy::RoundRobin,
        hash_key: None,
        servers: Vec::new(),
        nrf_discovery: None,
        health_check: None,
    };

    for child in &block.children {
        match child {
            Node::Directive(directive) => apply_upstream_directive(&mut upstream, directive)?,
            Node::Block(nested) => match nested.name.as_str() {
                consts::HEALTH_CHECK => {
                    if upstream.health_check.is_some() {
                        return Err(LowerErr {
                            message: "upstream block: health_check block is duplicated".into(),
                        });
                    }
                    upstream.health_check = Some(lower_upstream_health_check(nested)?);
                }
                consts::NRF_DISCOVERY => {
                    if upstream.nrf_discovery.is_some() {
                        return Err(LowerErr {
                            message: "upstream block: nrf_discovery block is duplicated".into(),
                        });
                    }
                    upstream.nrf_discovery = Some(lower_nrf_discovery(nested)?);
                }
                _ => {
                    return Err(LowerErr {
                        message: format!(
                            "upstream block: nested blocks are not supported: {}",
                            nested.name
                        ),
                    });
                }
            },
        }
    }

    Ok(upstream)
}

#[derive(Default)]
struct NrfDiscoveryDraft {
    api_root: Option<String>,
    target_nf_type: Option<String>,
    requester_nf_type: Option<String>,
    service_name: Option<String>,
    endpoint_scheme: Option<NrfEndpointScheme>,
    timeout: Option<std::time::Duration>,
    stale_if_error: Option<std::time::Duration>,
    tls_options: UpstreamSslOptions,
}

fn lower_nrf_discovery(block: &Block) -> Result<NrfDiscovery, LowerErr> {
    if !block.args.is_empty() {
        return Err(LowerErr {
            message: "nrf_discovery block: does not accept arguments".into(),
        });
    }

    let mut draft = NrfDiscoveryDraft::default();
    for child in &block.children {
        let Node::Directive(directive) = child else {
            return Err(LowerErr {
                message: "nrf_discovery block: nested blocks are not supported".into(),
            });
        };
        apply_nrf_discovery_directive(&mut draft, directive)?;
    }

    let required = |value: Option<String>, name: &str| {
        value.ok_or_else(|| LowerErr {
            message: format!("nrf_discovery: {name} is required"),
        })
    };

    Ok(NrfDiscovery {
        api_root: required(draft.api_root, consts::API_ROOT)?,
        target_nf_type: required(draft.target_nf_type, consts::TARGET_NF_TYPE)?,
        requester_nf_type: required(draft.requester_nf_type, consts::REQUESTER_NF_TYPE)?,
        service_name: required(draft.service_name, consts::SERVICE_NAME)?,
        endpoint_scheme: draft.endpoint_scheme.ok_or_else(|| LowerErr {
            message: "nrf_discovery: endpoint_scheme is required".into(),
        })?,
        timeout: draft
            .timeout
            .unwrap_or_else(|| std::time::Duration::from_secs(3)),
        stale_if_error: draft
            .stale_if_error
            .unwrap_or_else(|| std::time::Duration::from_secs(60)),
        tls_options: draft.tls_options,
    })
}

fn apply_nrf_discovery_directive(
    draft: &mut NrfDiscoveryDraft,
    directive: &Directive,
) -> Result<(), LowerErr> {
    let name = directive.name.as_str();
    match name {
        consts::API_ROOT
        | consts::TARGET_NF_TYPE
        | consts::REQUESTER_NF_TYPE
        | consts::SERVICE_NAME => {
            let value = parse_exactly_one_argument(&directive.args, name)?;
            if value.trim().is_empty() {
                return Err(LowerErr {
                    message: format!("nrf_discovery {name}: value cannot be empty"),
                });
            }
            let slot = match name {
                consts::API_ROOT => &mut draft.api_root,
                consts::TARGET_NF_TYPE => &mut draft.target_nf_type,
                consts::REQUESTER_NF_TYPE => &mut draft.requester_nf_type,
                _ => &mut draft.service_name,
            };
            set_once(slot, value, &format!("nrf_discovery {name}"))?;
        }
        consts::ENDPOINT_SCHEME => {
            let value =
                parse_exactly_one_argument(&directive.args, "nrf_discovery endpoint_scheme")?;
            let scheme = match value.as_str() {
                "http" => NrfEndpointScheme::Http,
                "https" => NrfEndpointScheme::Https,
                _ => {
                    return Err(LowerErr {
                        message: format!(
                            "nrf_discovery endpoint_scheme: unsupported value `{value}`; expected http|https"
                        ),
                    });
                }
            };
            set_once(
                &mut draft.endpoint_scheme,
                scheme,
                "nrf_discovery endpoint_scheme",
            )?;
        }
        consts::TIMEOUT | consts::STALE_IF_ERROR => {
            let context = format!("nrf_discovery {name}");
            let value = parse_single_duration_directive(&directive.args, &context)?;
            ensure_non_zero_duration(value, &context)?;
            let slot = if name == consts::TIMEOUT {
                &mut draft.timeout
            } else {
                &mut draft.stale_if_error
            };
            set_once(slot, value, &context)?;
        }
        consts::SSL_VERIFY => {
            draft.tls_options.verify_cert = get_directive_switch(directive)?;
        }
        consts::SSL_TRUSTED_CERTIFICATE | consts::SSL_CERTIFICATE | consts::SSL_CERTIFICATE_KEY => {
            let value = parse_exactly_one_argument(&directive.args, name)?;
            let source =
                PemSource::new(std::slice::from_ref(&value), false).map_err(|_| LowerErr {
                    message: format!("nrf_discovery {name}: invalid PEM source"),
                })?;
            let slot = match name {
                consts::SSL_TRUSTED_CERTIFICATE => &mut draft.tls_options.trusted_certificate,
                consts::SSL_CERTIFICATE => &mut draft.tls_options.client_certificate,
                _ => &mut draft.tls_options.client_certificate_key,
            };
            set_once(slot, source, &format!("nrf_discovery {name}"))?;
        }
        _ => {
            return Err(LowerErr {
                message: format!("unsupported nrf_discovery directive: {name}"),
            });
        }
    }
    Ok(())
}

fn apply_upstream_directive(
    upstream: &mut UpstreamBlock,
    directive: &Directive,
) -> Result<(), LowerErr> {
    match directive.name.as_str() {
        consts::SERVER => {
            upstream
                .servers
                .push(parse_upstream_server(&directive.args)?);
        }
        consts::POLICY => {
            upstream.policy = parse_upstream_policy(&directive.args)?;
        }
        consts::HASH_KEY => {
            if upstream.hash_key.is_some() {
                return Err(LowerErr {
                    message: "hash_key: directive is duplicated".into(),
                });
            }
            upstream.hash_key = Some(parse_upstream_hash_key(&directive.args)?);
        }
        _ => {
            return Err(LowerErr {
                message: format!("unsupported upstream directive: {}", directive.name),
            });
        }
    }

    Ok(())
}

#[derive(Default)]
struct UpstreamHealthCheckDraft {
    check_type: Option<UpstreamHealthCheckKind>,
    timeout: Option<std::time::Duration>,
    interval: Option<std::time::Duration>,
    consecutive_success: Option<usize>,
    consecutive_failure: Option<usize>,
    host: Option<String>,
    path: Option<String>,
    use_tls: Option<bool>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum UpstreamHealthCheckKind {
    Tcp,
    Http,
}

fn lower_upstream_health_check(block: &Block) -> Result<UpstreamHealthCheck, LowerErr> {
    if !block.args.is_empty() {
        return Err(LowerErr {
            message: "health_check block: does not accept arguments".into(),
        });
    }

    let mut draft = UpstreamHealthCheckDraft::default();
    for child in &block.children {
        match child {
            Node::Directive(directive) => {
                apply_upstream_health_check_directive(&mut draft, directive)?
            }
            Node::Block(nested) => {
                return Err(LowerErr {
                    message: format!(
                        "health_check block: nested blocks are not supported: {}",
                        nested.name
                    ),
                });
            }
        }
    }

    let check_type = match draft.check_type.unwrap_or(UpstreamHealthCheckKind::Tcp) {
        UpstreamHealthCheckKind::Tcp => {
            if draft.host.is_some() || draft.path.is_some() || draft.use_tls.is_some() {
                return Err(LowerErr {
                    message: "health_check: host/path/use_tls are only supported for type http"
                        .into(),
                });
            }
            UpstreamHealthCheckType::Tcp
        }
        UpstreamHealthCheckKind::Http => {
            let host = draft.host.ok_or_else(|| LowerErr {
                message: "health_check: host is required for type http".into(),
            })?;
            let path = draft.path.unwrap_or_else(|| "/".into());
            if path.is_empty() {
                return Err(LowerErr {
                    message: "health_check: path cannot be empty".into(),
                });
            }
            UpstreamHealthCheckType::Http {
                host,
                path,
                use_tls: draft.use_tls.unwrap_or(false),
            }
        }
    };

    Ok(UpstreamHealthCheck {
        check_type,
        timeout: draft
            .timeout
            .unwrap_or_else(|| std::time::Duration::from_secs(1)),
        interval: draft
            .interval
            .unwrap_or_else(|| std::time::Duration::from_secs(5)),
        consecutive_success: draft.consecutive_success.unwrap_or(1),
        consecutive_failure: draft.consecutive_failure.unwrap_or(1),
    })
}

fn apply_upstream_health_check_directive(
    draft: &mut UpstreamHealthCheckDraft,
    directive: &Directive,
) -> Result<(), LowerErr> {
    match directive.name.as_str() {
        consts::TYPE => {
            let value = parse_exactly_one_argument(&directive.args, "health_check type")?;
            let kind = match value.as_str() {
                "tcp" => UpstreamHealthCheckKind::Tcp,
                "http" => UpstreamHealthCheckKind::Http,
                _ => {
                    return Err(LowerErr {
                        message: format!(
                            "health_check type: unsupported value `{value}`; expected tcp|http"
                        ),
                    });
                }
            };
            set_once(&mut draft.check_type, kind, "health_check type")?;
        }
        consts::TIMEOUT => {
            let value = parse_single_duration_directive(&directive.args, "health_check timeout")?;
            ensure_non_zero_duration(value, "health_check timeout")?;
            set_once(&mut draft.timeout, value, "health_check timeout")?;
        }
        consts::INTERVAL => {
            let value = parse_single_duration_directive(&directive.args, "health_check interval")?;
            ensure_non_zero_duration(value, "health_check interval")?;
            set_once(&mut draft.interval, value, "health_check interval")?;
        }
        consts::CONSECUTIVE_SUCCESS => {
            let value = parse_positive_usize(&directive.args, "health_check consecutive_success")?;
            set_once(
                &mut draft.consecutive_success,
                value,
                "health_check consecutive_success",
            )?;
        }
        consts::CONSECUTIVE_FAILURE => {
            let value = parse_positive_usize(&directive.args, "health_check consecutive_failure")?;
            set_once(
                &mut draft.consecutive_failure,
                value,
                "health_check consecutive_failure",
            )?;
        }
        consts::HOST => {
            let value = parse_exactly_one_argument(&directive.args, "health_check host")?;
            if value.trim().is_empty() {
                return Err(LowerErr {
                    message: "health_check host: value cannot be empty".into(),
                });
            }
            set_once(&mut draft.host, value, "health_check host")?;
        }
        consts::PATH => {
            let value = parse_exactly_one_argument(&directive.args, "health_check path")?;
            set_once(&mut draft.path, value, "health_check path")?;
        }
        consts::USE_TLS => {
            let value = matches!(get_directive_switch(directive)?, Switch::On);
            set_once(&mut draft.use_tls, value, "health_check use_tls")?;
        }
        _ => {
            return Err(LowerErr {
                message: format!("unsupported health_check directive: {}", directive.name),
            });
        }
    }

    Ok(())
}

fn parse_upstream_policy(args: &[String]) -> Result<UpstreamSelectionPolicy, LowerErr> {
    match args {
        [value] => match value.as_str() {
            "round_robin" => Ok(UpstreamSelectionPolicy::RoundRobin),
            "random" => Ok(UpstreamSelectionPolicy::Random),
            "consistent_hash" => Ok(UpstreamSelectionPolicy::ConsistentHash),
            _ => Err(LowerErr {
                message: format!(
                    "policy: unsupported upstream selection policy `{value}`; expected round_robin|random|consistent_hash"
                ),
            }),
        },
        [] => Err(LowerErr {
            message: "policy: expected 1 argument".into(),
        }),
        _ => Err(LowerErr {
            message: "policy: expected exactly 1 argument".into(),
        }),
    }
}

fn parse_upstream_hash_key(args: &[String]) -> Result<UpstreamHashKey, LowerErr> {
    match args {
        [value] if value == "client_ip" => Ok(UpstreamHashKey::ClientIp),
        [kind, name] if kind == "header" => {
            http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| LowerErr {
                message: format!("hash_key: invalid HTTP header name `{name}`"),
            })?;
            Ok(UpstreamHashKey::Header(name.clone()))
        }
        _ => Err(LowerErr {
            message: "hash_key: expected `client_ip` or `header <name>`".into(),
        }),
    }
}

fn parse_upstream_server(args: &[String]) -> Result<UpstreamServer, LowerErr> {
    let raw = match args.first() {
        Some(value) => value,
        None => {
            return Err(LowerErr {
                message: "upstream server: expected host:port".into(),
            });
        }
    };

    let (host, port) = split_upstream_host_port(raw).ok_or_else(|| LowerErr {
        message: format!("upstream server: expected host:port, got `{raw}`"),
    })?;
    if host.is_empty() {
        return Err(LowerErr {
            message: format!("upstream server: missing host in `{raw}`"),
        });
    }
    let port = port.parse::<u16>().map_err(|_| LowerErr {
        message: format!("upstream server: invalid port in `{raw}`"),
    })?;

    let mut weight = 1u16;
    let mut saw_weight = false;
    for parameter in &args[1..] {
        let Some(value) = parameter.strip_prefix("weight=") else {
            return Err(LowerErr {
                message: format!("upstream server: unsupported parameter `{parameter}`"),
            });
        };
        if saw_weight {
            return Err(LowerErr {
                message: "upstream server: weight is duplicated".into(),
            });
        }
        weight = value.parse::<u16>().map_err(|_| LowerErr {
            message: format!("upstream server: invalid weight `{value}`"),
        })?;
        if weight == 0 {
            return Err(LowerErr {
                message: "upstream server: weight must be greater than zero".into(),
            });
        }
        saw_weight = true;
    }

    Ok(UpstreamServer {
        host: host.to_string(),
        port,
        weight,
    })
}

fn split_upstream_host_port(raw: &str) -> Option<(&str, &str)> {
    if let Some(rest) = raw.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port = rest[end + 1..].strip_prefix(':')?;
        if host.is_empty() || port.is_empty() || port.contains(['/', '?', '#', '@']) {
            return None;
        }
        return Some((host, port));
    }

    let (host, port) = raw.rsplit_once(':')?;
    if host.is_empty()
        || port.is_empty()
        || host.contains(['/', '?', '#', '@'])
        || port.contains(['/', '?', '#', '@', ':'])
    {
        return None;
    }

    Some((host, port))
}
