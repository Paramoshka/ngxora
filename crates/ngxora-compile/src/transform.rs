use ngxora_config::{Ast, Block, Directive, Node};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use url::Url;

use crate::{
    consts,
    ir::{
        Http, Ir, Listen, Location, LocationDirective, LocationMatcher, PemSource, Server, Switch,
        TlsIdentity,
    },
};

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
        consts::KEEPALIVE_TIMEOUT => match d.args.as_slice() {
            [t] => http.keepalive_timeout = t.clone(),
            [] => {
                return Err(LowerErr {
                    message: format!("{}: expected 1 argument", d.name),
                });
            }
            _ => {
                return Err(LowerErr {
                    message: format!("{}: expected exactly 1 argument", d.name),
                });
            }
        },

        consts::TCP_NODELAY => http.tcp_nodelay = get_directive_switch(d)?,

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
    let directives = parse_location_directives(&block.children)?;

    Ok(Location {
        matcher,
        directives,
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

fn parse_location_directives(nodes: &Vec<Node>) -> Result<Vec<LocationDirective>, LowerErr> {
    let mut directives: Vec<LocationDirective> = Vec::new();
    for node in nodes {
        match node {
            Node::Directive(directive) => {
                let location_directive = apply_location_directive(directive)?;
                directives.push(location_directive);
            }
            Node::Block(block) => {
                return Err(LowerErr {
                    message: format!("Unexpected inner block in location block: {:?}", block.name),
                });
            }
        }
    }

    Ok(directives)
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
                    _ => {
                        return Err(LowerErr {
                            message: format!("Unknow params: {:?}", params),
                        });
                    }
                }
            }
        }
    }

    Ok(listen)
}
