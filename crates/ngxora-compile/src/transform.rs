use ngxora_config::{Ast, Block, Directive, Node};
use std::{fmt::format, net::SocketAddr};
use url::{ParseError, Url};

use crate::{
    consts,
    ir::{Http, Ir, Listen, Location, LocationDirective, LocationMatcher, Server, Switch},
};

pub struct LowerErr {
    pub message: String,
}

impl Ir {
    pub fn from_ast(ast: &Ast) -> Self {
        let mut ir = Ir::default();
        let mut http: Option<Http> = None;
        for node in &ast.items {
            match node {
                Node::Directive(_directive) => {}
                Node::Block(block) => match block.name.as_str() {
                    consts::HTTP => match lower_http(block) {
                        Ok(h) => http = Some(h),
                        Err(_) => todo!(),
                    },
                    _ => {}
                },
            }
        }

        ir.http = http;
        ir
    }
}

fn lower_http(block: &Block) -> Result<Http, LowerErr> {
    let mut http: Http = Http::default();

    for children_block in &block.children {
        match children_block {
            Node::Directive(directive) => apply_http_directive(&mut http, directive)?,
            Node::Block(block) => match block_named(children_block, consts::SERVER) {
                // fill up server block
                Some(b) => match b.name.as_str() {
                    consts::SERVER_NAME => match lower_server(&b) {
                        Ok(server) => http.servers.push(server),
                        Err(e) => return Err(e),
                    },
                    _ => {
                        return Err(LowerErr {
                            message: format!("Unknown block name: {:?}", block.name),
                        });
                    }
                },
                None => todo!(),
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
                Some(b) => match b.name.as_str() {
                    // fill up location block
                    consts::LOCATION => match lower_location(&b) {
                        Ok(location) => server.locations.push(location),
                        Err(e) => return Err(e),
                    },

                    _ => {
                        return Err(LowerErr {
                            message: format!("Unkonown name of block: {:?}", block.name),
                        });
                    }
                },

                _ => {
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
            if let Ok(listen) = parse_listen_directives(&d.args) {
                server.listens.push(listen);
            }
        }

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

    Ok(())
}

fn parse_location_matcher(args: &[String]) -> Result<LocationMatcher, LowerErr> {
    match args {
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
                let location_directive = appy_location_directive(directive)?;
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
            if let Ok(sa) = endpoint.parse::<SocketAddr>() {
                listen.addr = sa.ip();
                listen.port = sa.port();
            } else if let Ok(port) = endpoint.parse::<u16>() {
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
