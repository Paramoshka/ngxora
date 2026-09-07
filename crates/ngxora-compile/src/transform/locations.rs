//! Location matching, access rules, caching and proxy directives.

use super::LowerErr;
use super::plugins::parse_location_plugin_block;
use super::values::{
    get_directive_switch, parse_exactly_one_argument, parse_positive_usize,
    parse_single_duration_directive, parse_size_literal,
};
use crate::consts;
use crate::ir::{
    CacheConfig, Location, LocationDirective, LocationIpRule, LocationMatcher, PemSource,
    ProxyPassTarget, UpstreamHttpProtocol,
};
use ipnet::IpNet;
use ngxora_config::{Block, Directive, Node};
use ngxora_plugin_api::PluginSpec;
use std::net::IpAddr;
use url::Url;

pub(super) fn lower_location(block: &Block) -> Result<Location, LowerErr> {
    let matcher = parse_location_matcher(&block.args)?;
    let (directives, plugins, cache, access_rules) = parse_location_contents(&block.children)?;

    Ok(Location {
        matcher,
        access_rules,
        directives,
        plugins,
        cache,
    })
}

fn parse_location_matcher(args: &[String]) -> Result<LocationMatcher, LowerErr> {
    match args {
        [op, path] if op == "=" => Ok(LocationMatcher::Exact(path.clone())),

        [op, pattern] if op == "~" => Ok(LocationMatcher::Regex {
            case_insensitive: false,
            pattern: pattern.clone(),
        }),

        [op, pattern] if op == "~*" => Ok(LocationMatcher::Regex {
            case_insensitive: true,
            pattern: pattern.clone(),
        }),

        [op, path] if op == "^~" => Ok(LocationMatcher::PreferPrefix(path.clone())),

        [name] if name.starts_with('@') => Ok(LocationMatcher::Named(
            name.trim_start_matches('@').to_string(),
        )),

        [path] => Ok(LocationMatcher::Prefix(path.clone())),

        _ => Err(LowerErr {
            message: format!("invalid location args: {:?}", args),
        }),
    }
}

fn parse_location_contents(
    nodes: &[Node],
) -> Result<
    (
        Vec<LocationDirective>,
        Vec<PluginSpec>,
        Option<CacheConfig>,
        Vec<LocationIpRule>,
    ),
    LowerErr,
> {
    let mut directives: Vec<LocationDirective> = Vec::new();
    let mut plugins: Vec<PluginSpec> = Vec::new();
    let mut cache: Option<CacheConfig> = None;
    let mut access_rules: Vec<LocationIpRule> = Vec::new();
    for node in nodes {
        match node {
            Node::Directive(directive) => {
                if let Some(cache_field) = apply_cache_directive(directive, cache.as_ref())? {
                    if cache.replace(cache_field).is_some() {
                        return Err(LowerErr {
                            message: "duplicate proxy_cache directive in location".into(),
                        });
                    }
                    continue;
                }

                if let Some(rule) = apply_location_access_rule(directive)? {
                    access_rules.push(rule);
                    continue;
                }

                let location_directive = apply_location_directive(directive)?;
                directives.push(location_directive);
            }
            Node::Block(block) => {
                if block.name.as_str() == consts::PROXY_CACHE {
                    if cache.is_some() {
                        return Err(LowerErr {
                            message: "duplicate proxy_cache block in location".into(),
                        });
                    }
                    cache = Some(parse_proxy_cache_block(block)?);
                } else {
                    plugins.push(parse_location_plugin_block(block)?);
                }
            }
        }
    }

    Ok((directives, plugins, cache, access_rules))
}

fn apply_location_access_rule(directive: &Directive) -> Result<Option<LocationIpRule>, LowerErr> {
    fn parse_network(value: &str, directive: &str) -> Result<IpNet, LowerErr> {
        if let Ok(network) = value.parse::<IpNet>() {
            return Ok(network);
        }
        if let Ok(address) = value.parse::<IpAddr>() {
            return Ok(IpNet::from(address));
        }

        Err(LowerErr {
            message: format!("{directive}: expected an IP address or CIDR, got `{value}`"),
        })
    }

    match directive.name.as_str() {
        consts::ALLOW => match directive.args.as_slice() {
            [value] if value == consts::ALL => Ok(Some(LocationIpRule::AllowAll)),
            [value] => Ok(Some(LocationIpRule::Allow(parse_network(
                value,
                consts::ALLOW,
            )?))),
            [] => Err(LowerErr {
                message: "allow: expected <ip>|<cidr>|all".into(),
            }),
            _ => Err(LowerErr {
                message: "allow: expected exactly 1 argument".into(),
            }),
        },
        consts::DENY => match directive.args.as_slice() {
            [value] if value == consts::ALL => Ok(Some(LocationIpRule::DenyAll)),
            [value] => Ok(Some(LocationIpRule::Deny(parse_network(
                value,
                consts::DENY,
            )?))),
            [] => Err(LowerErr {
                message: "deny: expected <ip>|<cidr>|all".into(),
            }),
            _ => Err(LowerErr {
                message: "deny: expected exactly 1 argument".into(),
            }),
        },
        _ => Ok(None),
    }
}

fn apply_cache_directive(
    directive: &Directive,
    existing: Option<&CacheConfig>,
) -> Result<Option<CacheConfig>, LowerErr> {
    use crate::ir::CacheKeyMode;

    match directive.name.as_str() {
        consts::PROXY_CACHE => match directive.args.as_slice() {
            [value] if value == "on" || value == "off" => {
                if value == "off" {
                    if existing.is_some() {
                        return Err(LowerErr {
                            message: "proxy_cache off cannot be used with other cache directives"
                                .into(),
                        });
                    }
                    // off = no cache for this location, represented as None
                    // but we keep it as a disabled CacheConfig to distinguish from "not configured"
                    return Ok(Some(CacheConfig {
                        enabled: false,
                        ..CacheConfig::default()
                    }));
                }
                // "on" — keep the defaults, just enable
                Ok(Some(CacheConfig::default()))
            }
            [] => Ok(Some(CacheConfig::default())),
            _ => Err(LowerErr {
                message: format!(
                    "proxy_cache: expected 'on' or 'off', got {:?}",
                    directive.args
                ),
            }),
        },
        consts::PROXY_CACHE_TTL => {
            let ttl = parse_single_duration_directive(&directive.args, consts::PROXY_CACHE_TTL)?;
            Ok(existing.map(|c| CacheConfig {
                ttl: Some(ttl),
                ..c.clone()
            }))
        }
        consts::PROXY_CACHE_STALE_IF_ERROR => {
            let duration = parse_single_duration_directive(
                &directive.args,
                consts::PROXY_CACHE_STALE_IF_ERROR,
            )?;
            Ok(existing.map(|c| CacheConfig {
                stale_if_error: Some(duration),
                ..c.clone()
            }))
        }
        consts::PROXY_CACHE_KEY => match directive.args.as_slice() {
            [mode] => {
                let mode = match mode.as_str() {
                    "uri" => CacheKeyMode::Uri,
                    "uri_and_method" => CacheKeyMode::UriAndMethod,
                    "normalized_uri" => CacheKeyMode::NormalizedUri,
                    _ => {
                        return Err(LowerErr {
                            message: format!(
                                "proxy_cache_key: expected uri, uri_and_method, or normalized_uri, got {mode}"
                            ),
                        });
                    }
                };
                Ok(existing.map(|c| CacheConfig {
                    cache_key: mode,
                    ..c.clone()
                }))
            }
            [] => Err(LowerErr {
                message: "proxy_cache_key: expected argument".into(),
            }),
            _ => Err(LowerErr {
                message: "proxy_cache_key: expected exactly 1 argument".into(),
            }),
        },
        consts::PROXY_CACHE_MIN_USES => {
            let min = parse_positive_usize(&directive.args, consts::PROXY_CACHE_MIN_USES)?;
            Ok(existing.map(|c| CacheConfig {
                min_uses: Some(min),
                ..c.clone()
            }))
        }
        consts::PROXY_CACHE_VALID => {
            let statuses: Vec<u16> = directive
                .args
                .iter()
                .map(|s| {
                    s.parse::<u16>().map_err(|_| LowerErr {
                        message: format!("proxy_cache_valid: invalid status code `{s}`"),
                    })
                })
                .collect::<Result<_, _>>()?;
            if statuses.is_empty() {
                return Err(LowerErr {
                    message: "proxy_cache_valid: expected at least one status code".into(),
                });
            }
            Ok(existing.map(|c| CacheConfig {
                valid_statuses: statuses,
                ..c.clone()
            }))
        }
        consts::PROXY_CACHE_MAX_SIZE => {
            let raw = parse_exactly_one_argument(&directive.args, consts::PROXY_CACHE_MAX_SIZE)?;
            let size = parse_size_literal(&raw, consts::PROXY_CACHE_MAX_SIZE)?;
            Ok(existing.map(|c| CacheConfig {
                max_size: Some(size),
                ..c.clone()
            }))
        }
        _ => Ok(None),
    }
}

fn parse_proxy_cache_block(block: &Block) -> Result<CacheConfig, LowerErr> {
    if !block.args.is_empty() {
        return Err(LowerErr {
            message: "proxy_cache block does not accept arguments".into(),
        });
    }

    let mut cache = CacheConfig::default();

    for child in &block.children {
        match child {
            Node::Directive(directive) => {
                if let Some(updated) = apply_cache_directive(directive, Some(&cache))? {
                    cache = updated;
                }
            }
            Node::Block(nested) => {
                return Err(LowerErr {
                    message: format!(
                        "proxy_cache block: nested blocks are not supported: {}",
                        nested.name
                    ),
                });
            }
        }
    }

    Ok(cache)
}

fn parse_proxy_upstream_protocol(args: &[String]) -> Result<UpstreamHttpProtocol, LowerErr> {
    match args {
        [value] => match value.as_str() {
            "h1" => Ok(UpstreamHttpProtocol::H1),
            "h2" => Ok(UpstreamHttpProtocol::H2),
            "h2c" => Ok(UpstreamHttpProtocol::H2c),
            _ => Err(LowerErr {
                message: "proxy_upstream_protocol: expected h1|h2|h2c".into(),
            }),
        },
        [] => Err(LowerErr {
            message: "proxy_upstream_protocol: expected h1|h2|h2c".into(),
        }),
        _ => Err(LowerErr {
            message: "proxy_upstream_protocol: expected exactly 1 argument".into(),
        }),
    }
}

fn apply_location_directive(directive: &Directive) -> Result<LocationDirective, LowerErr> {
    match directive.name.as_str() {
        "scp_pass" => Ok(LocationDirective::ScpPass(
            parse_exactly_one_argument(&directive.args, "scp_pass")?.to_string(),
        )),
        consts::PROXY_PASS => match directive.args.as_slice() {
            [raw_url] => {
                let parsed_url = Url::parse(raw_url).map_err(|e| LowerErr {
                    message: format!("proxy_pass: invalid URL: {:?}", e),
                })?;
                Ok(LocationDirective::ProxyPass(ProxyPassTarget::Url(
                    parsed_url,
                )))
            }
            [] => Err(LowerErr {
                message: "proxy_pass: expected URL".into(),
            }),
            _ => Err(LowerErr {
                message: "proxy_pass: expected exactly 1 argument".into(),
            }),
        },
        consts::PROXY_CONNECT_TIMEOUT => Ok(LocationDirective::ProxyConnectTimeout(
            parse_single_duration_directive(&directive.args, consts::PROXY_CONNECT_TIMEOUT)?,
        )),
        consts::PROXY_READ_TIMEOUT => Ok(LocationDirective::ProxyReadTimeout(
            parse_single_duration_directive(&directive.args, consts::PROXY_READ_TIMEOUT)?,
        )),
        consts::PROXY_WRITE_TIMEOUT => Ok(LocationDirective::ProxyWriteTimeout(
            parse_single_duration_directive(&directive.args, consts::PROXY_WRITE_TIMEOUT)?,
        )),
        consts::PROXY_UPSTREAM_PROTOCOL => Ok(LocationDirective::ProxyUpstreamProtocol(
            parse_proxy_upstream_protocol(&directive.args)?,
        )),
        consts::PROXY_SSL_VERIFY => Ok(LocationDirective::ProxySslVerify(get_directive_switch(
            directive,
        )?)),
        consts::PROXY_SSL_TRUSTED_CERTIFICATE => match directive.args.as_slice() {
            [path] => {
                let ps =
                    PemSource::new(std::slice::from_ref(path), false).map_err(|_| LowerErr {
                        message: "proxy_ssl_trusted_certificate: invalid certificate source".into(),
                    })?;
                Ok(LocationDirective::ProxySslTrustedCertificate(ps))
            }
            [] => Err(LowerErr {
                message: "proxy_ssl_trusted_certificate: expected 1 argument".into(),
            }),
            _ => Err(LowerErr {
                message: "proxy_ssl_trusted_certificate: expected exactly 1 argument".into(),
            }),
        },

        consts::PROXY_SSL_CERTIFICATE => match directive.args.as_slice() {
            [path] => {
                let ps =
                    PemSource::new(std::slice::from_ref(path), false).map_err(|_| LowerErr {
                        message: "proxy_ssl_certificate: invalid certificate source".into(),
                    })?;
                Ok(LocationDirective::ProxySslCertificate(ps))
            }
            [] => Err(LowerErr {
                message: "proxy_ssl_certificate: expected 1 argument".into(),
            }),
            _ => Err(LowerErr {
                message: "proxy_ssl_certificate: expected exactly 1 argument".into(),
            }),
        },

        consts::PROXY_SSL_CERTIFICATE_KEY => match directive.args.as_slice() {
            [path] => {
                let ps =
                    PemSource::new(std::slice::from_ref(path), false).map_err(|_| LowerErr {
                        message: "proxy_ssl_certificate_key: invalid key source".into(),
                    })?;
                Ok(LocationDirective::ProxySslCertificateKey(ps))
            }
            [] => Err(LowerErr {
                message: "proxy_ssl_certificate_key: expected 1 argument".into(),
            }),
            _ => Err(LowerErr {
                message: "proxy_ssl_certificate_key: expected exactly 1 argument".into(),
            }),
        },

        consts::RETURN => match directive.args.as_slice() {
            [code, location] => {
                let status = code.parse().map_err(|_| LowerErr {
                    message: format!("return: invalid status code `{code}`"),
                })?;
                if !(300..=399).contains(&status) {
                    return Err(LowerErr {
                        message: format!(
                            "return: status {status} is not a redirect (expected 3xx)"
                        ),
                    });
                }

                Ok(LocationDirective::Return {
                    status,
                    location: location.clone(),
                })
            }

            [] => Err(LowerErr {
                message: "return: expected 2 arguments: <status> <location>".into(),
            }),

            _ => Err(LowerErr {
                message: "return: expected exactly 2 arguments: <status> <location>".into(),
            }),
        },

        _ => Err(LowerErr {
            message: format!("unknown directive in location: {}", directive.name),
        }),
    }
}
