use crate::ir::{Ir, LocationDirective, UpstreamHashKey, UpstreamSelectionPolicy};

#[derive(Debug, Eq, PartialEq)]
pub struct ValidateErr {
    pub message: String,
}

impl Ir {
    pub fn validate(&self) -> Result<(), ValidateErr> {
        let http = self.http.as_ref().ok_or_else(|| ValidateErr {
            message: "configuration does not contain an http block".into(),
        })?;
        if http.servers.is_empty() {
            return Err(ValidateErr {
                message: "http block does not contain any server blocks".into(),
            });
        }

        for upstream in &http.upstreams {
            if upstream.servers.is_empty() && upstream.nrf_discovery.is_none() {
                return Err(ValidateErr {
                    message: format!(
                        "upstream `{}` must define at least one server or nrf_discovery",
                        upstream.name
                    ),
                });
            }
            if !upstream.servers.is_empty() && upstream.nrf_discovery.is_some() {
                return Err(ValidateErr {
                    message: format!(
                        "upstream `{}` cannot combine server directives with nrf_discovery",
                        upstream.name
                    ),
                });
            }
            if upstream.nrf_discovery.is_some() && upstream.health_check.is_none() {
                return Err(ValidateErr {
                    message: format!(
                        "upstream `{}` with nrf_discovery must define health_check",
                        upstream.name
                    ),
                });
            }
            let total_weight = upstream.servers.iter().try_fold(0u32, |total, server| {
                if server.weight == 0 {
                    return Err(ValidateErr {
                        message: format!(
                            "upstream `{}` backend `{}:{}` weight must be greater than zero",
                            upstream.name, server.host, server.port
                        ),
                    });
                }
                Ok(total + u32::from(server.weight))
            })?;
            if total_weight > u32::from(u16::MAX) {
                return Err(ValidateErr {
                    message: format!(
                        "upstream `{}` total backend weight must not exceed {}",
                        upstream.name,
                        u16::MAX
                    ),
                });
            }

            match (&upstream.policy, &upstream.hash_key) {
                (UpstreamSelectionPolicy::ConsistentHash, _) => {}
                (_, Some(_)) => {
                    return Err(ValidateErr {
                        message: format!(
                            "upstream `{}` hash_key requires policy consistent_hash",
                            upstream.name
                        ),
                    });
                }
                _ => {}
            }

            if let Some(UpstreamHashKey::Header(name)) = &upstream.hash_key {
                http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| ValidateErr {
                    message: format!(
                        "upstream `{}` hash_key has invalid HTTP header name `{name}`",
                        upstream.name
                    ),
                })?;
            }
        }

        for (server_index, server) in http.servers.iter().enumerate() {
            for (location_index, location) in server.locations.iter().enumerate() {
                let mut action_count = 0;
                for directive in &location.directives {
                    match directive {
                        LocationDirective::ProxyPass(_) | LocationDirective::Return { .. } => {
                            action_count += 1;
                        }
                        LocationDirective::Root(_) => {
                            return Err(unsupported_location_directive(
                                server_index,
                                location_index,
                                "root",
                            ));
                        }
                        LocationDirective::TryFiles(_) => {
                            return Err(unsupported_location_directive(
                                server_index,
                                location_index,
                                "try_files",
                            ));
                        }
                        _ => {}
                    }
                }

                if action_count != 1 {
                    return Err(ValidateErr {
                        message: format!(
                            "server {} location {} must contain exactly one proxy_pass or return directive",
                            server_index + 1,
                            location_index + 1
                        ),
                    });
                }
            }
        }

        Ok(())
    }
}

fn unsupported_location_directive(
    server_index: usize,
    location_index: usize,
    directive: &str,
) -> ValidateErr {
    ValidateErr {
        message: format!(
            "server {} location {} uses unsupported directive `{directive}`",
            server_index + 1,
            location_index + 1
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{Http, Location, LocationMatcher, Server};

    fn ir_with_directive(directive: LocationDirective) -> Ir {
        Ir {
            http: Some(Http {
                servers: vec![Server {
                    locations: vec![Location {
                        matcher: LocationMatcher::Prefix("/".into()),
                        directives: vec![directive],
                        access_rules: Vec::new(),
                        plugins: Vec::new(),
                        cache: None,
                    }],
                    ..Server::default()
                }],
                ..Http::default()
            }),
        }
    }

    #[test]
    fn rejects_unsupported_root_without_panicking() {
        let err = ir_with_directive(LocationDirective::Root("/srv/www".into()))
            .validate()
            .expect_err("root must be rejected");
        assert!(err.message.contains("unsupported directive `root`"));
    }

    #[test]
    fn rejects_location_without_an_action() {
        let err = ir_with_directive(LocationDirective::ProxyReadTimeout(
            std::time::Duration::from_secs(1),
        ))
        .validate()
        .expect_err("location without action must be rejected");
        assert!(err.message.contains("exactly one proxy_pass or return"));
    }
}
