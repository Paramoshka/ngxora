//! Location plugin dispatch, CORS and rate-limit configuration.

use super::LowerErr;
use super::auth_plugins::{lower_basic_auth_plugin, lower_ext_authz_plugin, lower_jwt_auth_plugin};
use super::headers_plugin::lower_headers_plugin;
use super::values::parse_exactly_one_argument;
use crate::consts;
use ngxora_config::{Block, Directive, Node};
use ngxora_plugin_api::PluginSpec;
use serde::Serialize;

#[derive(Debug, Default, Serialize)]
struct RateLimitPluginConfig {
    max_requests_per_second: isize,
}

#[derive(Debug, Default, Serialize)]
struct CorsPluginConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_origin: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_methods: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_headers: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expose_headers: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    allow_credentials: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    max_age: Option<u64>,
}

pub(super) fn parse_location_plugin_block(block: &Block) -> Result<PluginSpec, LowerErr> {
    match block.name.as_str() {
        consts::HEADERS => lower_headers_plugin(block),
        consts::BASIC_AUTH | consts::BASIC_AUTH_ALIAS => lower_basic_auth_plugin(block),
        consts::RATE_LIMIT => lower_rate_limit_plugin(block),
        consts::CORS => lower_cors_plugin(block),
        consts::EXT_AUTHZ => lower_ext_authz_plugin(block),
        consts::JWT_AUTH => lower_jwt_auth_plugin(block),
        _ => Err(LowerErr {
            message: format!("unexpected inner block in location: {}", block.name),
        }),
    }
}

fn lower_rate_limit_plugin(block: &Block) -> Result<PluginSpec, LowerErr> {
    if !block.args.is_empty() {
        return Err(LowerErr {
            message: format!("{} block: does not accept arguments", block.name),
        });
    }

    let mut config = RateLimitPluginConfig::default();
    for child in &block.children {
        match child {
            Node::Directive(directive) => apply_rate_limit_directive(&mut config, directive)?,
            Node::Block(nested) => {
                return Err(LowerErr {
                    message: format!(
                        "rate-limit block: nested blocks are not supported: {}",
                        nested.name
                    ),
                });
            }
        }
    }

    if config.max_requests_per_second <= 0 {
        return Err(LowerErr {
            message: "rate-limit block: must specify positive `rate`".into(),
        });
    }

    let config = serde_json::to_value(config).expect("rate-limit plugin config serializes");
    Ok(PluginSpec {
        name: consts::RATE_LIMIT.into(),
        config,
    })
}

fn apply_rate_limit_directive(
    config: &mut RateLimitPluginConfig,
    directive: &Directive,
) -> Result<(), LowerErr> {
    match directive.name.as_str() {
        consts::RATE => {
            let val = parse_exactly_one_argument(&directive.args, consts::RATE)?;
            let rate = val.parse::<isize>().map_err(|_| LowerErr {
                message: format!("rate-limit block: rate must be an integer, got `{val}`"),
            })?;
            if rate <= 0 {
                return Err(LowerErr {
                    message: format!("rate-limit block: rate must be positive, got `{rate}`"),
                });
            }
            if config.max_requests_per_second > 0 {
                return Err(LowerErr {
                    message: "rate-limit block: duplicate `rate` directive".into(),
                });
            }
            config.max_requests_per_second = rate;
        }
        _ => {
            return Err(LowerErr {
                message: format!("rate-limit block: unsupported directive {}", directive.name),
            });
        }
    }
    Ok(())
}

fn lower_cors_plugin(block: &Block) -> Result<PluginSpec, LowerErr> {
    if !block.args.is_empty() {
        return Err(LowerErr {
            message: format!("{} block: does not accept arguments", block.name),
        });
    }

    let mut config = CorsPluginConfig::default();
    for child in &block.children {
        match child {
            Node::Directive(directive) => apply_cors_directive(&mut config, directive)?,
            Node::Block(nested) => {
                return Err(LowerErr {
                    message: format!(
                        "cors block: nested blocks are not supported: {}",
                        nested.name
                    ),
                });
            }
        }
    }

    let config_val = serde_json::to_value(config).expect("cors plugin config serializes");
    Ok(PluginSpec {
        name: consts::CORS.into(),
        config: config_val,
    })
}

fn apply_cors_directive(
    config: &mut CorsPluginConfig,
    directive: &Directive,
) -> Result<(), LowerErr> {
    let check_dup = |opt: &Option<String>, name: &str| -> Result<(), LowerErr> {
        if opt.is_some() {
            Err(LowerErr {
                message: format!("cors block: duplicate `{name}` directive"),
            })
        } else {
            Ok(())
        }
    };

    let join_args = |args: &[String], name: &str| -> Result<String, LowerErr> {
        if args.is_empty() {
            return Err(LowerErr {
                message: format!("cors block: `{name}` requires at least 1 argument"),
            });
        }
        let mut joined = args.join(" ");
        if (joined.starts_with('"') && joined.ends_with('"') && joined.len() >= 2)
            || (joined.starts_with('\'') && joined.ends_with('\'') && joined.len() >= 2)
        {
            joined = joined[1..joined.len() - 1].to_string();
        }
        Ok(joined)
    };

    match directive.name.as_str() {
        consts::ALLOW_ORIGIN => {
            check_dup(&config.allow_origin, consts::ALLOW_ORIGIN)?;
            config.allow_origin = Some(join_args(&directive.args, consts::ALLOW_ORIGIN)?);
        }
        consts::ALLOW_METHODS => {
            check_dup(&config.allow_methods, consts::ALLOW_METHODS)?;
            config.allow_methods = Some(join_args(&directive.args, consts::ALLOW_METHODS)?);
        }
        consts::ALLOW_HEADERS => {
            check_dup(&config.allow_headers, consts::ALLOW_HEADERS)?;
            config.allow_headers = Some(join_args(&directive.args, consts::ALLOW_HEADERS)?);
        }
        consts::EXPOSE_HEADERS => {
            check_dup(&config.expose_headers, consts::EXPOSE_HEADERS)?;
            config.expose_headers = Some(join_args(&directive.args, consts::EXPOSE_HEADERS)?);
        }
        consts::ALLOW_CREDENTIALS => {
            if config.allow_credentials.is_some() {
                return Err(LowerErr {
                    message: format!(
                        "cors block: duplicate `{}` directive",
                        consts::ALLOW_CREDENTIALS
                    ),
                });
            }
            let val = parse_exactly_one_argument(&directive.args, consts::ALLOW_CREDENTIALS)?;
            let b = match val.as_str() {
                "on" => true,
                "off" => false,
                _ => {
                    return Err(LowerErr {
                        message: format!(
                            "cors block: {} must be `on` or `off`, got `{val}`",
                            consts::ALLOW_CREDENTIALS
                        ),
                    });
                }
            };
            config.allow_credentials = Some(b);
        }
        consts::MAX_AGE => {
            if config.max_age.is_some() {
                return Err(LowerErr {
                    message: format!("cors block: duplicate `{}` directive", consts::MAX_AGE),
                });
            }
            let val = parse_exactly_one_argument(&directive.args, consts::MAX_AGE)?;
            let age = val.parse::<u64>().map_err(|_| LowerErr {
                message: format!(
                    "cors block: {} must be an integer, got `{val}`",
                    consts::MAX_AGE
                ),
            })?;
            config.max_age = Some(age);
        }
        _ => {
            return Err(LowerErr {
                message: format!("cors block: unsupported directive {}", directive.name),
            });
        }
    }
    Ok(())
}
