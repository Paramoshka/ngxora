//! Lower nginx-style AST into the shared IR; reject unsupported input before runtime.

use crate::consts;
use crate::ir::{Http, Ir, PemSource, SslProvider};
use listeners::{lower_server, lower_ssl_provider};
use ngxora_config::{Ast, Block, Directive, Node};
use std::path::PathBuf;
use upstreams::{lower_scp, lower_upstream};
use values::{
    get_directive_switch, parse_client_max_body_size, parse_exactly_one_argument,
    parse_keepalive_requests, parse_keepalive_timeout, parse_size_literal,
};

mod auth_plugins;
mod geoip;
mod headers_plugin;
mod listeners;
mod locations;
mod plugins;
mod upstreams;
mod values;

#[derive(Debug)]
pub struct LowerErr {
    pub message: String,
}

impl Ir {
    pub fn from_ast(ast: &Ast) -> Result<Self, LowerErr> {
        let mut ir = Ir::default();
        let mut http: Option<Http> = None;
        for node in &ast.items {
            match node {
                Node::Directive(_directive) => {}
                Node::Block(block) => {
                    if block.name.as_str() == consts::HTTP {
                        match lower_http(block) {
                            Ok(h) => http = Some(h),
                            Err(e) => return Err(e),
                        }
                    }
                }
            }
        }

        ir.http = http;
        Ok(ir)
    }
}

fn lower_http(block: &Block) -> Result<Http, LowerErr> {
    let mut http: Http = Http::default();

    for children_block in &block.children {
        match children_block {
            Node::Directive(directive) => apply_http_directive(&mut http, directive)?,
            Node::Block(block) => match block.name.as_str() {
                "geoip" => {
                    if http.geoip.is_some() {
                        return Err(LowerErr {
                            message: "duplicate geoip block".into(),
                        });
                    }
                    http.geoip = Some(geoip::lower_geoip(block)?);
                }
                "scp" => http.scp_profiles.push(lower_scp(block)?),
                consts::SERVER => {
                    let server = lower_server(block)?;
                    http.servers.push(server);
                }
                consts::UPSTREAM => {
                    let upstream = lower_upstream(block)?;
                    http.upstreams.push(upstream);
                }
                consts::SSL_PROVIDER => {
                    if http.ssl_provider.is_some() {
                        return Err(LowerErr {
                            message: "duplicate ssl_provider block".into(),
                        });
                    }
                    http.ssl_provider = Some(lower_ssl_provider(block)?);
                }
                _ => {
                    return Err(LowerErr {
                        message: format!("Unknown block name: {:?}", block.name),
                    });
                }
            },
        }
    }

    // Assign LetsEncrypt to servers that have an SSL listener but no explicit
    // ssl_certificate when a global ssl_provider letsencrypt is configured.
    if http.ssl_provider.is_some() {
        for server in &mut http.servers {
            let has_ssl_listener = server.listens.iter().any(|l| l.ssl);
            if has_ssl_listener && server.tls.is_none() {
                server.tls = Some(SslProvider::LetsEncrypt);
            }
        }
    }

    for server in &http.servers {
        let has_ssl_listener = server.listens.iter().any(|l| l.ssl);
        if !has_ssl_listener {
            continue;
        }

        match &server.tls {
            Some(SslProvider::Custom(tls)) => {
                if tls.cert == PemSource::Path(PathBuf::new()) {
                    return Err(LowerErr {
                        message: "ssl listener requires ssl_certificate".into(),
                    });
                }
                if tls.key == PemSource::Path(PathBuf::new()) {
                    return Err(LowerErr {
                        message: "ssl listener requires ssl_certificate_key".into(),
                    });
                }
            }
            Some(SslProvider::LetsEncrypt) => {
                if http.ssl_provider.is_none() {
                    return Err(LowerErr {
                        message:
                            "ssl listener with LetsEncrypt provider requires an ssl_provider letsencrypt { ... } block in http"
                                .into(),
                    });
                }
                if server.server_names.is_empty() {
                    return Err(LowerErr {
                        message:
                            "ssl listener with LetsEncrypt requires at least one server_name for certificate issuance"
                                .into(),
                    });
                }
                if server.server_names.len() > 1 {
                    return Err(LowerErr {
                        message:
                            "ssl listener with LetsEncrypt currently supports exactly one server_name; split aliases into separate server blocks or use a manual certificate"
                                .into(),
                    });
                }
            }
            None => {
                return Err(LowerErr {
                    message: "ssl listener requires a certificate: use ssl_certificate / ssl_certificate_key, or enable ssl_provider letsencrypt"
                        .into(),
                });
            }
        }
    }

    Ok(http)
}

fn apply_http_directive(http: &mut Http, d: &Directive) -> Result<(), LowerErr> {
    let http2_slot = match d.name.as_str() {
        "http2_max_concurrent_streams" => Some(&mut http.http2.max_concurrent_streams),
        "http2_max_header_list_size" => Some(&mut http.http2.max_header_list_size),
        "http2_stream_window_size" => Some(&mut http.http2.stream_window_size),
        "http2_connection_window_size" => Some(&mut http.http2.connection_window_size),
        _ => None,
    };
    if let Some(slot) = http2_slot {
        if slot.replace(values::parse_http2_value(d)?).is_some() {
            return Err(LowerErr {
                message: format!("{} is duplicated in http", d.name),
            });
        }
        return Ok(());
    }
    match d.name.as_str() {
        consts::KEEPALIVE_TIMEOUT => {
            http.keepalive_timeout = parse_keepalive_timeout(&d.args)?;
        }
        consts::KEEPALIVE_REQUESTS => {
            http.keepalive_requests = Some(parse_keepalive_requests(&d.args)?);
        }
        consts::CLIENT_MAX_BODY_SIZE => {
            http.client_max_body_size = parse_client_max_body_size(&d.args)?;
        }
        consts::TCP_NODELAY => http.tcp_nodelay = get_directive_switch(d)?,
        consts::ALLOW_CONNECT_METHOD_PROXYING => {
            http.allow_connect_method_proxying = get_directive_switch(d)?
        }
        consts::H2C => http.h2c = get_directive_switch(d)?,
        consts::PROXY_CACHE_MAX_SIZE => {
            let raw = parse_exactly_one_argument(&d.args, consts::PROXY_CACHE_MAX_SIZE)?;
            http.proxy_cache_max_size =
                Some(parse_size_literal(&raw, consts::PROXY_CACHE_MAX_SIZE)?);
        }

        _ => {
            return Err(LowerErr {
                message: format!("unsupported http directive: {}", d.name),
            });
        }
    }

    Ok(())
}
