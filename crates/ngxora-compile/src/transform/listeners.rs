//! Server, listener and certificate directives.

use super::LowerErr;
use super::locations::lower_location;
use super::values::{block_named, parse_exactly_one_argument};
use crate::consts;
use crate::ir::{
    LetsEncryptConfig, Listen, PemSource, Server, SslProvider, TlsIdentity, TlsProtocolBounds,
    TlsProtocolVersion, TlsVerifyClient,
};
use ngxora_config::{Block, Directive, Node};
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;

pub(super) fn lower_ssl_provider(block: &Block) -> Result<LetsEncryptConfig, LowerErr> {
    match block.args.as_slice() {
        [name] if name == consts::LETSENCRYPT => {}
        [] => {
            return Err(LowerErr {
                message: "ssl_provider: expected provider name (letsencrypt)".into(),
            });
        }
        _ => {
            return Err(LowerErr {
                message: "ssl_provider: only 'letsencrypt' is supported as a provider name".into(),
            });
        }
    }

    let mut config = LetsEncryptConfig {
        acme_directory: None,
        email: None,
        cache_dir: None,
    };

    for child in &block.children {
        let directive = match child {
            Node::Directive(d) => d,
            Node::Block(b) => {
                return Err(LowerErr {
                    message: format!("ssl_provider: unexpected block `{}`", b.name),
                });
            }
        };

        match directive.name.as_str() {
            consts::ACME_DIRECTORY => {
                let raw = parse_exactly_one_argument(&directive.args, consts::ACME_DIRECTORY)?;
                config.acme_directory = Some(raw);
            }
            consts::EMAIL => {
                let raw = parse_exactly_one_argument(&directive.args, consts::EMAIL)?;
                config.email = Some(raw);
            }
            consts::CACHE_DIR => {
                let raw = parse_exactly_one_argument(&directive.args, consts::CACHE_DIR)?;
                config.cache_dir = Some(PathBuf::from(raw));
            }
            _ => {
                return Err(LowerErr {
                    message: format!("ssl_provider: unsupported directive `{}`", directive.name),
                });
            }
        }
    }

    Ok(config)
}

pub(super) fn lower_server(block: &Block) -> Result<Server, LowerErr> {
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

                let provider = server
                    .tls
                    .get_or_insert_with(|| SslProvider::Custom(TlsIdentity::default()));
                if let SslProvider::Custom(tls) = provider {
                    tls.cert = ps;
                }
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

                let provider = server
                    .tls
                    .get_or_insert_with(|| SslProvider::Custom(TlsIdentity::default()));
                if let SslProvider::Custom(tls) = provider {
                    tls.key = ps;
                }
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
