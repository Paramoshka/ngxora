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
        PemSource, ProxyPassTarget, Server, Switch, TlsIdentity, TlsProtocolBounds,
        TlsProtocolVersion, TlsVerifyClient, UpstreamBlock, UpstreamHealthCheck,
        UpstreamHealthCheckType, UpstreamHttpProtocol, UpstreamSelectionPolicy, UpstreamServer,
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
struct BasicAuthPluginConfig {
    username: String,
    password: String,
    realm: Option<String>,
}

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

#[derive(Debug, Default, Serialize)]
struct ExtAuthzPluginConfig {
    uri: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    timeout_ms: Option<u64>,
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
                consts::SERVER => {
                    let server = lower_server(block)?;
                    http.servers.push(server);
                }
                consts::UPSTREAM => {
                    let upstream = lower_upstream(block)?;
                    http.upstreams.push(upstream);
                }
                _ => {
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
        consts::CLIENT_MAX_BODY_SIZE => {
            http.client_max_body_size = parse_client_max_body_size(&d.args)?;
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

fn lower_upstream(block: &Block) -> Result<UpstreamBlock, LowerErr> {
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
        name,
        policy: UpstreamSelectionPolicy::RoundRobin,
        servers: Vec::new(),
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
            _ => Err(LowerErr {
                message: format!(
                    "policy: unsupported upstream selection policy `{value}`; expected round_robin|random"
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

fn parse_exactly_one_argument(args: &[String], directive: &str) -> Result<String, LowerErr> {
    match args {
        [value] => Ok(value.clone()),
        [] => Err(LowerErr {
            message: format!("{directive}: expected 1 argument"),
        }),
        _ => Err(LowerErr {
            message: format!("{directive}: expected exactly 1 argument"),
        }),
    }
}

fn parse_positive_usize(args: &[String], directive: &str) -> Result<usize, LowerErr> {
    let value = parse_exactly_one_argument(args, directive)?;
    let parsed = value.parse::<usize>().map_err(|_| LowerErr {
        message: format!("{directive}: invalid integer `{value}`"),
    })?;
    if parsed == 0 {
        return Err(LowerErr {
            message: format!("{directive}: value must be greater than zero"),
        });
    }
    Ok(parsed)
}

fn ensure_non_zero_duration(value: std::time::Duration, directive: &str) -> Result<(), LowerErr> {
    if value.is_zero() {
        return Err(LowerErr {
            message: format!("{directive}: value must be greater than zero"),
        });
    }
    Ok(())
}

fn set_once<T>(slot: &mut Option<T>, value: T, directive: &str) -> Result<(), LowerErr> {
    if slot.replace(value).is_some() {
        return Err(LowerErr {
            message: format!("{directive}: duplicated directive"),
        });
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

fn parse_upstream_server(args: &[String]) -> Result<UpstreamServer, LowerErr> {
    let raw = match args {
        [value] => value,
        [] => {
            return Err(LowerErr {
                message: "upstream server: expected host:port".into(),
            });
        }
        _ => {
            return Err(LowerErr {
                message: "upstream server: expected exactly 1 argument".into(),
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

    Ok(UpstreamServer {
        host: host.to_string(),
        port,
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

fn parse_location_plugin_block(block: &Block) -> Result<PluginSpec, LowerErr> {
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

fn lower_basic_auth_plugin(block: &Block) -> Result<PluginSpec, LowerErr> {
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

fn lower_ext_authz_plugin(block: &Block) -> Result<PluginSpec, LowerErr> {
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

fn lower_jwt_auth_plugin(block: &Block) -> Result<PluginSpec, LowerErr> {
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
        _ => {
            return Err(LowerErr {
                message: format!("jwt_auth block: unsupported directive {}", directive.name),
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

fn assign_basic_auth_string(slot: &mut String, field: &str, value: String) -> Result<(), LowerErr> {
    if !slot.is_empty() {
        return Err(LowerErr {
            message: format!("basic-auth block: duplicate {field} directive"),
        });
    }

    *slot = value;
    Ok(())
}

fn parse_basic_auth_single_value(
    args: &[String],
    directive: &str,
    expected_message: &str,
) -> Result<String, LowerErr> {
    match args {
        [value] => Ok(value.clone()),
        _ => Err(LowerErr {
            message: format!("{directive}: {expected_message}"),
        }),
    }
}

fn parse_basic_auth_joined_value(
    args: &[String],
    directive: &str,
    expected_message: &str,
) -> Result<String, LowerErr> {
    match args {
        [] => Err(LowerErr {
            message: format!("{directive}: {expected_message}"),
        }),
        values => Ok(values.join(" ")),
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

fn parse_client_max_body_size(args: &[String]) -> Result<Option<u64>, LowerErr> {
    match args {
        [value] => {
            let size = parse_size_literal(value, consts::CLIENT_MAX_BODY_SIZE)?;
            if size == 0 { Ok(None) } else { Ok(Some(size)) }
        }
        [] => Err(LowerErr {
            message: "client_max_body_size: expected 1 argument".into(),
        }),
        _ => Err(LowerErr {
            message: "client_max_body_size: expected exactly 1 argument".into(),
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

fn parse_size_literal(raw: &str, directive: &str) -> Result<u64, LowerErr> {
    if raw.is_empty() {
        return Err(LowerErr {
            message: format!("{directive}: invalid size value `{raw}`"),
        });
    }

    let digits_len = raw.bytes().take_while(|byte| byte.is_ascii_digit()).count();
    if digits_len == 0 {
        return Err(LowerErr {
            message: format!("{directive}: invalid size value `{raw}`"),
        });
    }

    let value = raw[..digits_len].parse::<u64>().map_err(|_| LowerErr {
        message: format!("{directive}: invalid size value `{raw}`"),
    })?;
    let suffix = &raw[digits_len..];
    let multiplier = match suffix {
        "" => 1u64,
        "k" | "K" => 1024,
        "m" | "M" => 1024 * 1024,
        "g" | "G" => 1024 * 1024 * 1024,
        _ => {
            return Err(LowerErr {
                message: format!("{directive}: unsupported size unit `{suffix}` in `{raw}`"),
            });
        }
    };

    value.checked_mul(multiplier).ok_or_else(|| LowerErr {
        message: format!("{directive}: size value `{raw}` is too large"),
    })
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
