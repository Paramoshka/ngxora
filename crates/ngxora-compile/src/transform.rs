use ngxora_config::{Ast, Block, Directive, Node};
use ngxora_plugin_api::PluginSpec;
use serde::Serialize;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use url::Url;

use crate::{
    consts,
    ir::{
        Http, Ir, KeepaliveTimeout, Listen, Location, LocationDirective, LocationMatcher,
        PemSource, Server, Switch, TlsIdentity, TlsProtocolBounds, TlsProtocolVersion,
        TlsVerifyClient,
    },
};

#[derive(Debug)]
pub struct LowerErr {
    pub message: String,
}

#[derive(Debug, Default, Serialize)]
struct HeadersPluginConfig {
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

impl Ir {
    pub fn from_ast(ast: &Ast) -> Result<Self, LowerErr> {
        let mut ir = Ir::default();
        let mut http: Option<Http> = None;
        for node in &ast.items {
            match node {
                Node::Directive(_directive) => {}
                Node::Block(block) => match block.name.as_str() {
                    consts::HTTP => match lower_http(block) {
                        Ok(h) => http = Some(h),
                        Err(e) => return Err(e),
                    },
                    _ => {}
                },
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
            Node::Block(block) => match block_named(children_block, consts::SERVER) {
                // fill up server block
                Some(b) => {
                    let server = lower_server(b)?;
                    http.servers.push(server);
                }
                None => {
                    return Err(LowerErr {
                        message: format!("Unknown block name: {:?}", block.name),
                    });
                }
            },
        }
    }

    Ok(http)
}

fn apply_http_directive(http: &mut Http, d: &Directive) -> Result<(), LowerErr> {
    match d.name.as_str() {
        consts::KEEPALIVE_TIMEOUT => {
            http.keepalive_timeout = parse_keepalive_timeout(&d.args)?;
        }
        consts::KEEPALIVE_REQUESTS => {
            http.keepalive_requests = Some(parse_keepalive_requests(&d.args)?);
        }
        consts::TCP_NODELAY => http.tcp_nodelay = get_directive_switch(d)?,
        consts::ALLOW_CONNECT_METHOD_PROXYING => {
            http.allow_connect_method_proxying = get_directive_switch(d)?
        }
        consts::H2C => http.h2c = get_directive_switch(d)?,

        _ => {
            return Err(LowerErr {
                message: format!("unsupported http directive: {}", d.name),
            });
        }
    }

    Ok(())
}

fn lower_server(block: &Block) -> Result<Server, LowerErr> {
    let mut server = Server::default();
    for children in &block.children {
        match children {
            Node::Directive(directive) => apply_server_directive(&mut server, directive)?,

            Node::Block(block) => match block_named(children, consts::LOCATION) {
                Some(b) => {
                    let location = lower_location(b)?;
                    server.locations.push(location);
                }
                None => {
                    return Err(LowerErr {
                        message: format!("Unknown name of block: {:?}", block.name),
                    });
                }
            },
        }
    }

    validate_server(&server)?;
    Ok(server)
}

fn apply_server_directive(server: &mut Server, d: &Directive) -> Result<(), LowerErr> {
    match d.name.as_str() {
        // fill up `listen 80 default_server`;
        consts::LISTEN => {
            let listen = parse_listen_directives(&d.args)?;
            server.listens.push(listen);
        }

        consts::SERVER_NAME => match d.args.as_slice() {
            [] => {
                return Err(LowerErr {
                    message: "server_name: expected at least 1 argument".into(),
                });
            }
            names => {
                server.server_names.extend(names.iter().cloned());
            }
        },

        consts::SSL_CERTIFICATE => match d.args.as_slice() {
            [cert] => {
                let ps =
                    PemSource::new(std::slice::from_ref(cert), false).map_err(|_| LowerErr {
                        message: "ssl_certificate: invalid certificate source".into(),
                    })?;

                let tls = server.tls.get_or_insert_with(TlsIdentity::default);
                tls.cert = ps;
            }
            [] => {
                return Err(LowerErr {
                    message: "ssl_certificate: expected 1 argument".into(),
                });
            }
            _ => {
                return Err(LowerErr {
                    message: "ssl_certificate: expected exactly 1 argument".into(),
                });
            }
        },

        consts::SSL_CERTIFICATE_KEY => match d.args.as_slice() {
            [key] => {
                let ps =
                    PemSource::new(std::slice::from_ref(key), false).map_err(|_| LowerErr {
                        message: "ssl_certificate_key: invalid key source".into(),
                    })?;

                let tls = server.tls.get_or_insert_with(TlsIdentity::default);
                tls.key = ps;
            }
            [] => {
                return Err(LowerErr {
                    message: "ssl_certificate_key: expected 1 argument".into(),
                });
            }
            _ => {
                return Err(LowerErr {
                    message: "ssl_certificate_key: expected exactly 1 argument".into(),
                });
            }
        },

        consts::SSL_PROTOCOLS => {
            server.tls_options.protocols = Some(parse_ssl_protocols(&d.args)?);
        }

        consts::SSL_VERIFY_CLIENT => {
            server.tls_options.verify_client = parse_ssl_verify_client(&d.args)?;
        }

        consts::SSL_CLIENT_CERTIFICATE => match d.args.as_slice() {
            [path] => {
                let ps =
                    PemSource::new(std::slice::from_ref(path), false).map_err(|_| LowerErr {
                        message: "ssl_client_certificate: invalid certificate source".into(),
                    })?;
                server.tls_options.client_certificate = Some(ps);
            }
            [] => {
                return Err(LowerErr {
                    message: "ssl_client_certificate: expected 1 argument".into(),
                });
            }
            _ => {
                return Err(LowerErr {
                    message: "ssl_client_certificate: expected exactly 1 argument".into(),
                });
            }
        },

        _ => {
            return Err(LowerErr {
                message: format!("unsupported server directive: {}", d.name),
            });
        }
    }

    Ok(())
}

fn lower_location(block: &Block) -> Result<Location, LowerErr> {
    let matcher = parse_location_matcher(&block.args)?;
    let (directives, plugins) = parse_location_contents(&block.children)?;

    Ok(Location {
        matcher,
        directives,
        plugins,
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
) -> Result<(Vec<LocationDirective>, Vec<PluginSpec>), LowerErr> {
    let mut directives: Vec<LocationDirective> = Vec::new();
    let mut plugins: Vec<PluginSpec> = Vec::new();
    for node in nodes {
        match node {
            Node::Directive(directive) => {
                let location_directive = apply_location_directive(directive)?;
                directives.push(location_directive);
            }
            Node::Block(block) => {
                plugins.push(parse_location_plugin_block(block)?);
            }
        }
    }

    Ok((directives, plugins))
}

fn parse_location_plugin_block(block: &Block) -> Result<PluginSpec, LowerErr> {
    match block.name.as_str() {
        consts::HEADERS => lower_headers_plugin(block),
        _ => Err(LowerErr {
            message: format!("unexpected inner block in location: {}", block.name),
        }),
    }
}

fn lower_headers_plugin(block: &Block) -> Result<PluginSpec, LowerErr> {
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

fn apply_location_directive(directive: &Directive) -> Result<LocationDirective, LowerErr> {
    match directive.name.as_str() {
        consts::PROXY_PASS => match directive.args.as_slice() {
            [raw_url] => {
                let parsed_url = Url::parse(raw_url).map_err(|e| LowerErr {
                    message: format!("proxy_pass: invalid URL: {:?}", e),
                })?;
                Ok(LocationDirective::ProxyPass(parsed_url))
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

        _ => Err(LowerErr {
            message: format!("unknown directive in location: {}", directive.name),
        }),
    }
}

fn block_named<'a>(node: &'a Node, name: &'a str) -> Option<&'a Block> {
    match node {
        Node::Block(block) if name == block.name => Some(block),
        _ => None,
    }
}

fn get_directive_switch(d: &Directive) -> Result<Switch, LowerErr> {
    match d.args.as_slice() {
        [value] => match value.as_str() {
            "on" => Ok(Switch::On),
            "off" => Ok(Switch::Off),
            _ => Err(LowerErr {
                message: format!("{}: expected on|off", d.name),
            }),
        },
        [] => Err(LowerErr {
            message: format!("{}: expected on|off", d.name),
        }),
        _ => Err(LowerErr {
            message: format!("{}: expected exactly one argument on|off", d.name),
        }),
    }
}

fn parse_keepalive_timeout(args: &[String]) -> Result<KeepaliveTimeout, LowerErr> {
    match args {
        [] => Err(LowerErr {
            message: "keepalive_timeout: expected 1 or 2 arguments".into(),
        }),
        [idle] => {
            let idle = parse_duration_literal(idle, "keepalive_timeout")?;
            if idle.is_zero() {
                Ok(KeepaliveTimeout::Off)
            } else {
                Ok(KeepaliveTimeout::Timeout { idle, header: None })
            }
        }
        [idle, header] => {
            let idle = parse_duration_literal(idle, "keepalive_timeout")?;
            let header = parse_duration_literal(header, "keepalive_timeout")?;
            if idle.is_zero() && header.is_zero() {
                Ok(KeepaliveTimeout::Off)
            } else {
                Ok(KeepaliveTimeout::Timeout {
                    idle,
                    header: Some(header),
                })
            }
        }
        _ => Err(LowerErr {
            message: "keepalive_timeout: expected 1 or 2 arguments".into(),
        }),
    }
}

fn parse_keepalive_requests(args: &[String]) -> Result<u32, LowerErr> {
    match args {
        [value] => value.parse::<u32>().map_err(|_| LowerErr {
            message: format!("keepalive_requests: invalid integer `{value}`"),
        }),
        [] => Err(LowerErr {
            message: "keepalive_requests: expected 1 argument".into(),
        }),
        _ => Err(LowerErr {
            message: "keepalive_requests: expected exactly 1 argument".into(),
        }),
    }
}

fn parse_single_duration_directive(
    args: &[String],
    directive: &str,
) -> Result<std::time::Duration, LowerErr> {
    match args {
        [value] => parse_duration_literal(value, directive),
        [] => Err(LowerErr {
            message: format!("{directive}: expected 1 argument"),
        }),
        _ => Err(LowerErr {
            message: format!("{directive}: expected exactly 1 argument"),
        }),
    }
}

fn parse_duration_literal(raw: &str, directive: &str) -> Result<std::time::Duration, LowerErr> {
    fn unit_multiplier_millis(unit: &str) -> Option<u128> {
        match unit {
            "ms" => Some(1),
            "s" => Some(1_000),
            "m" => Some(60_000),
            "h" => Some(3_600_000),
            "d" => Some(86_400_000),
            "w" => Some(604_800_000),
            "M" => Some(2_592_000_000),  // 30d
            "y" => Some(31_536_000_000), // 365d
            _ => None,
        }
    }

    if raw.is_empty() {
        return Err(LowerErr {
            message: format!("{directive}: invalid time value `{raw}`"),
        });
    }

    let mut idx = 0usize;
    let bytes = raw.as_bytes();
    let mut total_millis = 0u128;
    let mut saw_segment = false;

    while idx < bytes.len() {
        let start = idx;
        while idx < bytes.len() && bytes[idx].is_ascii_digit() {
            idx += 1;
        }

        if start == idx {
            return Err(LowerErr {
                message: format!("{directive}: invalid time value `{raw}`"),
            });
        }

        let value = raw[start..idx].parse::<u128>().map_err(|_| LowerErr {
            message: format!("{directive}: invalid time value `{raw}`"),
        })?;

        let unit = if idx == bytes.len() {
            if saw_segment {
                return Err(LowerErr {
                    message: format!("{directive}: missing unit in `{raw}`"),
                });
            }
            "s"
        } else if raw[idx..].starts_with("ms") {
            idx += 2;
            "ms"
        } else {
            let unit = &raw[idx..idx + 1];
            idx += 1;
            unit
        };

        let multiplier = unit_multiplier_millis(unit).ok_or_else(|| LowerErr {
            message: format!("{directive}: unsupported time unit `{unit}` in `{raw}`"),
        })?;

        let segment_millis = value.checked_mul(multiplier).ok_or_else(|| LowerErr {
            message: format!("{directive}: time value `{raw}` is too large"),
        })?;
        total_millis = total_millis
            .checked_add(segment_millis)
            .ok_or_else(|| LowerErr {
                message: format!("{directive}: time value `{raw}` is too large"),
            })?;
        saw_segment = true;
    }

    let total_millis = u64::try_from(total_millis).map_err(|_| LowerErr {
        message: format!("{directive}: time value `{raw}` is too large"),
    })?;
    Ok(std::time::Duration::from_millis(total_millis))
}

fn parse_listen_directives(args: &[String]) -> Result<Listen, LowerErr> {
    let mut listen = Listen::default();

    match args {
        [] => {
            return Err(LowerErr {
                message: "listen: expected endpoint".into(),
            });
        }
        [endpoint, params @ ..] => {
            if let Some(port_str) = endpoint.strip_prefix("*:") {
                let port = port_str.parse::<u16>().map_err(|_| LowerErr {
                    message: format!("listen: invalid port {:?}", port_str),
                })?;
                listen.addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
                listen.port = port;
            } else if endpoint.starts_with("unix:") {
                return Err(LowerErr {
                    message: "listen: unix sockets not supported".into(),
                });
            } else if let Ok(sa) = endpoint.parse::<SocketAddr>() {
                listen.addr = sa.ip();
                listen.port = sa.port();
            } else if let Ok(port) = endpoint.parse::<u16>() {
                listen.addr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
                listen.port = port;
            } else {
                return Err(LowerErr {
                    message: format!("Failed parse address: {:?}", endpoint),
                });
            }

            for p in params {
                match p.as_str() {
                    "ssl" => listen.ssl = true,
                    "default_server" => listen.default_server = true,
                    consts::HTTP2 => listen.http2 = true,
                    consts::HTTP2_ONLY => {
                        listen.http2 = true;
                        listen.http2_only = true;
                    }
                    _ => {
                        return Err(LowerErr {
                            message: format!("Unknow params: {:?}", params),
                        });
                    }
                }
            }
        }
    }

    if listen.http2 && !listen.ssl {
        return Err(LowerErr {
            message: "listen: http2/http2_only requires ssl; use h2c for plaintext HTTP/2".into(),
        });
    }

    Ok(listen)
}

fn parse_ssl_protocols(args: &[String]) -> Result<TlsProtocolBounds, LowerErr> {
    if args.is_empty() {
        return Err(LowerErr {
            message: "ssl_protocols: expected at least 1 argument".into(),
        });
    }

    let mut versions = BTreeSet::new();
    for arg in args {
        let version = match arg.as_str() {
            "TLSv1" => TlsProtocolVersion::Tls1,
            "TLSv1.2" => TlsProtocolVersion::Tls1_2,
            "TLSv1.3" => TlsProtocolVersion::Tls1_3,
            _ => {
                return Err(LowerErr {
                    message: format!("ssl_protocols: unsupported protocol `{arg}`"),
                });
            }
        };
        versions.insert(version);
    }

    let versions = versions.into_iter().collect::<Vec<_>>();
    match versions.as_slice() {
        [version] => Ok(TlsProtocolBounds {
            min: *version,
            max: *version,
        }),
        [TlsProtocolVersion::Tls1_2, TlsProtocolVersion::Tls1_3] => Ok(TlsProtocolBounds {
            min: TlsProtocolVersion::Tls1_2,
            max: TlsProtocolVersion::Tls1_3,
        }),
        _ => Err(LowerErr {
            message: "ssl_protocols: supported combinations are `TLSv1`, `TLSv1.2`, `TLSv1.3`, or `TLSv1.2 TLSv1.3`".into(),
        }),
    }
}

fn parse_ssl_verify_client(args: &[String]) -> Result<TlsVerifyClient, LowerErr> {
    match args {
        [value] => match value.as_str() {
            "off" => Ok(TlsVerifyClient::Off),
            "optional" => Ok(TlsVerifyClient::Optional),
            "required" => Ok(TlsVerifyClient::Required),
            _ => Err(LowerErr {
                message: "ssl_verify_client: expected off|optional|required".into(),
            }),
        },
        [] => Err(LowerErr {
            message: "ssl_verify_client: expected off|optional|required".into(),
        }),
        _ => Err(LowerErr {
            message: "ssl_verify_client: expected exactly one argument".into(),
        }),
    }
}

fn validate_server(server: &Server) -> Result<(), LowerErr> {
    if server.tls_options.verify_client != TlsVerifyClient::Off
        && server.tls_options.client_certificate.is_none()
    {
        return Err(LowerErr {
            message: "ssl_verify_client: requires ssl_client_certificate".into(),
        });
    }

    Ok(())
}
