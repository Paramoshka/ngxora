//! Header mutation plugin configuration.

use super::LowerErr;
use super::values::{get_directive_switch, parse_exactly_one_argument};
use crate::consts;
use crate::ir::Switch;
use ngxora_config::{Block, Directive, Node};
use ngxora_plugin_api::PluginSpec;
use serde::Serialize;

#[derive(Debug, Default, Serialize)]
struct HeadersPluginConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    forward_client_ip: Option<bool>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    trusted_proxies: Vec<String>,
    request: HeaderPatchConfig,
    upstream_request: HeaderPatchConfig,
    response: HeaderPatchConfig,
}

#[derive(Debug, Default, Serialize)]
struct HeaderPatchConfig {
    add: Vec<HeaderEntry>,
    set: Vec<HeaderEntry>,
    remove: Vec<String>,
}

#[derive(Debug, Serialize)]
struct HeaderEntry {
    name: String,
    value: String,
}

pub(super) fn lower_headers_plugin(block: &Block) -> Result<PluginSpec, LowerErr> {
    if !block.args.is_empty() {
        return Err(LowerErr {
            message: "headers block: does not accept arguments".into(),
        });
    }

    let mut config = HeadersPluginConfig::default();
    for child in &block.children {
        match child {
            Node::Directive(directive) => apply_headers_directive(&mut config, directive)?,
            Node::Block(block) => {
                return Err(LowerErr {
                    message: format!(
                        "headers block: nested blocks are not supported: {}",
                        block.name
                    ),
                });
            }
        }
    }

    let config = serde_json::to_value(config).expect("headers plugin config serializes");
    Ok(PluginSpec {
        name: consts::HEADERS.into(),
        config,
    })
}

fn apply_headers_directive(
    config: &mut HeadersPluginConfig,
    directive: &Directive,
) -> Result<(), LowerErr> {
    match directive.name.as_str() {
        consts::REQUEST_ADD => {
            config
                .request
                .add
                .push(parse_header_entry(&directive.args, consts::REQUEST_ADD)?);
        }
        consts::REQUEST_SET => {
            config
                .request
                .set
                .push(parse_header_entry(&directive.args, consts::REQUEST_SET)?);
        }
        consts::REQUEST_REMOVE => {
            config.request.remove.push(parse_header_remove(
                &directive.args,
                consts::REQUEST_REMOVE,
            )?);
        }
        consts::UPSTREAM_REQUEST_ADD => {
            config.upstream_request.add.push(parse_header_entry(
                &directive.args,
                consts::UPSTREAM_REQUEST_ADD,
            )?);
        }
        consts::UPSTREAM_REQUEST_SET => {
            config.upstream_request.set.push(parse_header_entry(
                &directive.args,
                consts::UPSTREAM_REQUEST_SET,
            )?);
        }
        consts::UPSTREAM_REQUEST_REMOVE => {
            config.upstream_request.remove.push(parse_header_remove(
                &directive.args,
                consts::UPSTREAM_REQUEST_REMOVE,
            )?);
        }
        consts::RESPONSE_ADD => {
            config
                .response
                .add
                .push(parse_header_entry(&directive.args, consts::RESPONSE_ADD)?);
        }
        consts::RESPONSE_SET => {
            config
                .response
                .set
                .push(parse_header_entry(&directive.args, consts::RESPONSE_SET)?);
        }
        consts::RESPONSE_REMOVE => {
            config.response.remove.push(parse_header_remove(
                &directive.args,
                consts::RESPONSE_REMOVE,
            )?);
        }
        consts::FORWARD_CLIENT_IP => {
            if config.forward_client_ip.is_some() {
                return Err(LowerErr {
                    message: "headers block: duplicate forward_client_ip directive".into(),
                });
            }
            config.forward_client_ip = Some(get_directive_switch(directive)? == Switch::On);
        }
        consts::TRUSTED_PROXY => {
            config.trusted_proxies.push(parse_exactly_one_argument(
                &directive.args,
                consts::TRUSTED_PROXY,
            )?);
        }
        _ => {
            return Err(LowerErr {
                message: format!("headers block: unsupported directive {}", directive.name),
            });
        }
    }

    Ok(())
}

fn parse_header_entry(args: &[String], directive: &str) -> Result<HeaderEntry, LowerErr> {
    match args {
        [] => Err(LowerErr {
            message: format!("{directive}: expected header name and value"),
        }),
        [name] => Err(LowerErr {
            message: format!("{directive}: expected header value for `{name}`"),
        }),
        [name, value @ ..] => Ok(HeaderEntry {
            name: name.clone(),
            value: value.join(" "),
        }),
    }
}

fn parse_header_remove(args: &[String], directive: &str) -> Result<String, LowerErr> {
    match args {
        [name] => Ok(name.clone()),
        [] => Err(LowerErr {
            message: format!("{directive}: expected header name"),
        }),
        _ => Err(LowerErr {
            message: format!("{directive}: expected exactly 1 argument"),
        }),
    }
}
