//! Authentication plugin configuration and validation.

use super::LowerErr;
use super::values::{
    parse_basic_auth_joined_value, parse_basic_auth_single_value, parse_exactly_one_argument,
};
use crate::consts;
use ngxora_config::{Block, Directive, Node};
use ngxora_plugin_api::PluginSpec;
use serde::Serialize;

#[derive(Debug, Default, Serialize)]
struct BasicAuthPluginConfig {
    username: String,
    password: String,
    realm: Option<String>,
}

#[derive(Debug, Default, Serialize)]
struct ExtAuthzPluginConfig {
    uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout_ms: Option<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    allowed_hosts: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pass_request_headers: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pass_response_headers: Vec<String>,
}

#[derive(Debug, Default, Serialize)]
struct JwtAuthPluginConfig {
    algorithm: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    secret_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    aud: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sub: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    required_scopes: Vec<String>,
}

pub(super) fn lower_basic_auth_plugin(block: &Block) -> Result<PluginSpec, LowerErr> {
    if !block.args.is_empty() {
        return Err(LowerErr {
            message: format!("{} block: does not accept arguments", block.name),
        });
    }

    let mut config = BasicAuthPluginConfig::default();
    for child in &block.children {
        match child {
            Node::Directive(directive) => apply_basic_auth_directive(&mut config, directive)?,
            Node::Block(nested) => {
                return Err(LowerErr {
                    message: format!(
                        "basic-auth block: nested blocks are not supported: {}",
                        nested.name
                    ),
                });
            }
        }
    }

    let config = serde_json::to_value(config).expect("basic-auth plugin config serializes");
    Ok(PluginSpec {
        name: consts::BASIC_AUTH.into(),
        config,
    })
}

fn apply_basic_auth_directive(
    config: &mut BasicAuthPluginConfig,
    directive: &Directive,
) -> Result<(), LowerErr> {
    match directive.name.as_str() {
        consts::USERNAME => {
            assign_basic_auth_string(
                &mut config.username,
                "username",
                parse_basic_auth_single_value(
                    &directive.args,
                    consts::USERNAME,
                    "expected exactly 1 argument",
                )?,
            )?;
        }
        consts::PASSWORD => {
            assign_basic_auth_string(
                &mut config.password,
                "password",
                parse_basic_auth_joined_value(
                    &directive.args,
                    consts::PASSWORD,
                    "expected at least 1 argument",
                )?,
            )?;
        }
        consts::REALM => {
            let realm = parse_basic_auth_joined_value(
                &directive.args,
                consts::REALM,
                "expected at least 1 argument",
            )?;
            if config.realm.replace(realm).is_some() {
                return Err(LowerErr {
                    message: "basic-auth block: duplicate realm directive".into(),
                });
            }
        }
        _ => {
            return Err(LowerErr {
                message: format!("basic-auth block: unsupported directive {}", directive.name),
            });
        }
    }

    Ok(())
}

pub(super) fn lower_ext_authz_plugin(block: &Block) -> Result<PluginSpec, LowerErr> {
    if !block.args.is_empty() {
        return Err(LowerErr {
            message: format!("{} block: does not accept arguments", block.name),
        });
    }

    let mut config = ExtAuthzPluginConfig::default();
    for child in &block.children {
        match child {
            Node::Directive(directive) => apply_ext_authz_directive(&mut config, directive)?,
            Node::Block(nested) => {
                return Err(LowerErr {
                    message: format!(
                        "ext_authz block: nested blocks are not supported: {}",
                        nested.name
                    ),
                });
            }
        }
    }

    if config.uri.is_empty() {
        return Err(LowerErr {
            message: "ext_authz block: missing `uri` directive".into(),
        });
    }
    if config.allowed_hosts.is_empty() {
        return Err(LowerErr {
            message: "ext_authz block: missing `allowed_host` directive".into(),
        });
    }

    let config_val = serde_json::to_value(config).expect("ext_authz plugin config serializes");
    Ok(PluginSpec {
        name: consts::EXT_AUTHZ.into(),
        config: config_val,
    })
}

fn apply_ext_authz_directive(
    config: &mut ExtAuthzPluginConfig,
    directive: &Directive,
) -> Result<(), LowerErr> {
    match directive.name.as_str() {
        consts::URI => {
            if !config.uri.is_empty() {
                return Err(LowerErr {
                    message: format!("ext_authz block: duplicate `{}` directive", consts::URI),
                });
            }
            let val = parse_exactly_one_argument(&directive.args, consts::URI)?;
            config.uri = val;
        }
        consts::TIMEOUT => {
            if config.timeout_ms.is_some() {
                return Err(LowerErr {
                    message: format!("ext_authz block: duplicate `{}` directive", consts::TIMEOUT),
                });
            }
            let val = parse_exactly_one_argument(&directive.args, consts::TIMEOUT)?;
            if val.ends_with("ms") || val.ends_with('s') {
                return Err(LowerErr {
                    message: format!(
                        "ext_authz block: `{}` expects integer ms, got `{val}`. Strip suffix.",
                        consts::TIMEOUT
                    ),
                });
            }
            let ms = val.parse::<u64>().map_err(|_| LowerErr {
                message: format!(
                    "ext_authz block: `{}` must be an integer (ms), got `{val}`",
                    consts::TIMEOUT
                ),
            })?;
            config.timeout_ms = Some(ms);
        }
        consts::ALLOWED_HOST => {
            let val = parse_exactly_one_argument(&directive.args, consts::ALLOWED_HOST)?;
            config.allowed_hosts.push(val);
        }
        consts::PASS_REQUEST_HEADER => {
            let val = parse_exactly_one_argument(&directive.args, consts::PASS_REQUEST_HEADER)?;
            config.pass_request_headers.push(val);
        }
        consts::PASS_RESPONSE_HEADER => {
            let val = parse_exactly_one_argument(&directive.args, consts::PASS_RESPONSE_HEADER)?;
            config.pass_response_headers.push(val);
        }
        _ => {
            return Err(LowerErr {
                message: format!("ext_authz block: unsupported directive {}", directive.name),
            });
        }
    }
    Ok(())
}

pub(super) fn lower_jwt_auth_plugin(block: &Block) -> Result<PluginSpec, LowerErr> {
    if !block.args.is_empty() {
        return Err(LowerErr {
            message: format!("{} block: does not accept arguments", block.name),
        });
    }

    let mut config = JwtAuthPluginConfig::default();
    for child in &block.children {
        match child {
            Node::Directive(directive) => apply_jwt_auth_directive(&mut config, directive)?,
            Node::Block(nested) => {
                return Err(LowerErr {
                    message: format!(
                        "jwt_auth block: nested blocks are not supported: {}",
                        nested.name
                    ),
                });
            }
        }
    }

    if config.algorithm.is_empty() {
        return Err(LowerErr {
            message: "jwt_auth block: missing `algorithm` directive".into(),
        });
    }
    if config.secret.is_none() && config.secret_file.is_none() {
        return Err(LowerErr {
            message: "jwt_auth block: either `secret` or `secret_file` must be provided".into(),
        });
    }

    let config_val = serde_json::to_value(config).expect("jwt_auth plugin config serializes");
    Ok(PluginSpec {
        name: consts::JWT_AUTH.into(),
        config: config_val,
    })
}

fn apply_jwt_auth_directive(
    config: &mut JwtAuthPluginConfig,
    directive: &Directive,
) -> Result<(), LowerErr> {
    match directive.name.as_str() {
        consts::ALGORITHM => {
            if !config.algorithm.is_empty() {
                return Err(LowerErr {
                    message: format!(
                        "jwt_auth block: duplicate `{}` directive",
                        consts::ALGORITHM
                    ),
                });
            }
            let val = parse_exactly_one_argument(&directive.args, consts::ALGORITHM)?;
            config.algorithm = val;
        }
        consts::SECRET => {
            if config.secret.is_some() {
                return Err(LowerErr {
                    message: format!("jwt_auth block: duplicate `{}` directive", consts::SECRET),
                });
            }
            let val = parse_exactly_one_argument(&directive.args, consts::SECRET)?;
            config.secret = Some(val);
        }
        consts::SECRET_FILE => {
            if config.secret_file.is_some() {
                return Err(LowerErr {
                    message: format!(
                        "jwt_auth block: duplicate `{}` directive",
                        consts::SECRET_FILE
                    ),
                });
            }
            let val = parse_exactly_one_argument(&directive.args, consts::SECRET_FILE)?;
            config.secret_file = Some(val);
        }
        consts::ISS => {
            if config.iss.is_some() {
                return Err(LowerErr {
                    message: format!("jwt_auth block: duplicate `{}` directive", consts::ISS),
                });
            }
            config.iss = Some(parse_exactly_one_argument(&directive.args, consts::ISS)?);
        }
        consts::AUD => {
            config
                .aud
                .push(parse_exactly_one_argument(&directive.args, consts::AUD)?);
        }
        consts::SUB => {
            if config.sub.is_some() {
                return Err(LowerErr {
                    message: format!("jwt_auth block: duplicate `{}` directive", consts::SUB),
                });
            }
            config.sub = Some(parse_exactly_one_argument(&directive.args, consts::SUB)?);
        }
        consts::REQUIRED_SCOPE => {
            config.required_scopes.push(parse_exactly_one_argument(
                &directive.args,
                consts::REQUIRED_SCOPE,
            )?);
        }
        _ => {
            return Err(LowerErr {
                message: format!("jwt_auth block: unsupported directive {}", directive.name),
            });
        }
    }
    Ok(())
}

fn assign_basic_auth_string(slot: &mut String, field: &str, value: String) -> Result<(), LowerErr> {
    if !slot.is_empty() {
        return Err(LowerErr {
            message: format!("basic-auth block: duplicate {field} directive"),
        });
    }

    *slot = value;
    Ok(())
}
