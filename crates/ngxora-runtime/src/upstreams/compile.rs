//! Compile and validate listener topology into the runtime router.

use crate::upstreams::types::{
    CompiledRouter, HttpRuntimeOptions, ListenKey, ListenerProtocolConfig, ListenerTlsConfig,
    ListenerTlsSettings, RouteTarget, ServerRoutes,
};
use ngxora_compile::ir::{
    DownstreamTlsOptions, Http, KeepaliveTimeout, Listen, PemSource, Server, SslProvider, Switch,
    TlsIdentity,
};
use routes::compile_locations;
use std::net::IpAddr;
use std::path::PathBuf;
use upstream_groups::compile_upstreams;

mod routes;
mod upstream_groups;

impl CompiledRouter {
    pub fn from_http(http: &Http) -> Result<Self, String> {
        if matches!(http.tcp_nodelay, Switch::Off) {
            return Err(
                "tcp_nodelay off is not supported: Pingora enables TCP_NODELAY on accepted downstream sockets"
                    .into(),
            );
        }

        http.http2.validate()?;
        let mut router = Self {
            upstreams: compile_upstreams(&http.upstreams)?,
            http_options: HttpRuntimeOptions {
                downstream_keepalive_timeout: downstream_keepalive_timeout_secs(
                    &http.keepalive_timeout,
                ),
                keepalive_requests: http.keepalive_requests,
                client_max_body_size: http.client_max_body_size,
                proxy_cache_max_size: http.proxy_cache_max_size,
                tcp_nodelay: matches!(http.tcp_nodelay, Switch::On),
                allow_connect_method_proxying: matches!(
                    http.allow_connect_method_proxying,
                    Switch::On
                ),
                h2c: matches!(http.h2c, Switch::On),
                http2: http.http2,
            },
            le_config: http.ssl_provider.clone(),
            ..Self::default()
        };
        let mut next_route_id = 1;

        for profile in &http.scp_profiles {
            crate::upstreams::scp::validate_profile(profile, &router.upstreams)?;
            if router
                .scp_profiles
                .insert(profile.name.clone(), profile.clone())
                .is_some()
            {
                return Err(format!("duplicate scp profile `{}`", profile.name));
            }
        }

        for server in &http.servers {
            router.add_server(server, &mut next_route_id)?;
        }

        Ok(router)
    }

    fn add_server(&mut self, server: &Server, next_route_id: &mut u64) -> Result<(), String> {
        if matches!(server.tls, Some(SslProvider::LetsEncrypt)) && server.server_names.len() != 1 {
            return Err(
                "ssl listener with LetsEncrypt currently supports exactly one server_name; split aliases into separate server blocks or use a manual certificate"
                    .into(),
            );
        }

        for name in &server.server_names {
            if name.contains('*') {
                let suffix = name
                    .strip_prefix("*.")
                    .ok_or("only leading *. hostnames are supported")?;
                crate::upstreams::http_routes::validate_hostname(suffix.trim_end_matches('.'))?;
            }
        }
        let routes = ServerRoutes {
            locations: compile_locations(&server.locations, &self.upstreams, next_route_id)?,
        };
        for location in &routes.locations {
            if let RouteTarget::Scp { profile } = &location.target {
                if !self.scp_profiles.contains_key(profile) {
                    return Err(format!("scp_pass references unknown profile `{profile}`"));
                }
                if server.listens.iter().any(|listen| {
                    if listen.ssl {
                        !listen.http2
                    } else {
                        !self.http_options.h2c
                    }
                }) {
                    return Err("scp_pass requires an HTTP/2 listener".into());
                }
            }
        }

        for listen in &server.listens {
            let listen_key = ListenKey::from(listen);
            self.merge_listener_protocols(&listen_key, listen)?;
            let listener = self.listeners.entry(listen_key.clone()).or_default();

            for name in &server.server_names {
                listener.named.insert(
                    crate::upstreams::http_routes::normalize_hostname(name),
                    routes.clone(),
                );
            }

            if listen.default_server
                || (server.server_names.is_empty() && listener.default.is_none())
            {
                listener.default = Some(routes.clone());
            }

            if listen.ssl {
                self.merge_listener_tls_settings(&listen_key, &server.tls_options)?;
                let listener_tls =
                    self.listener_tls
                        .entry(listen_key)
                        .or_insert_with(|| ListenerTlsConfig {
                            settings: ListenerTlsSettings::from(&server.tls_options),
                            ..ListenerTlsConfig::default()
                        });

                if let Some(provider) = server.tls.as_ref() {
                    let tls_identity = match provider {
                        SslProvider::Custom(tls) => tls.clone(),
                        SslProvider::LetsEncrypt => {
                            let cache_dir = self
                                .le_config
                                .as_ref()
                                .and_then(|c| c.cache_dir.clone())
                                .unwrap_or_else(|| PathBuf::from("/var/lib/ngxora/certs"));
                            // Use the first server_name as the primary domain.
                            let domain = server.server_names.first().cloned().unwrap_or_default();
                            TlsIdentity {
                                cert: PemSource::Path(
                                    cache_dir.join(&domain).join("fullchain.pem"),
                                ),
                                key: PemSource::Path(cache_dir.join(&domain).join("privkey.pem")),
                            }
                        }
                    };

                    for name in &server.server_names {
                        listener_tls.named.insert(
                            crate::upstreams::http_routes::normalize_hostname(name),
                            tls_identity.clone(),
                        );
                    }

                    if listen.default_server
                        || listener_tls.default.is_none()
                        || server.server_names.is_empty()
                    {
                        listener_tls.default = Some(tls_identity.clone());
                    }
                }
            }
        }

        Ok(())
    }

    fn merge_listener_protocols(&mut self, key: &ListenKey, listen: &Listen) -> Result<(), String> {
        let config = ListenerProtocolConfig {
            http2: listen.http2,
            http2_only: listen.http2_only,
        };
        if let Some(current) = self.listener_protocols.get(key) {
            if current != &config {
                return Err(format!(
                    "listener {} has conflicting protocol settings across server blocks",
                    listen_key_addr(key)
                ));
            }
            return Ok(());
        }

        self.listener_protocols.insert(key.clone(), config);
        Ok(())
    }

    fn merge_listener_tls_settings(
        &mut self,
        key: &ListenKey,
        options: &DownstreamTlsOptions,
    ) -> Result<(), String> {
        let settings = ListenerTlsSettings::from(options);
        if let Some(current) = self.listener_tls.get(key).map(|tls| &tls.settings) {
            if current != &settings {
                return Err(format!(
                    "listener {} has conflicting TLS settings across server blocks",
                    listen_key_addr(key)
                ));
            }
            return Ok(());
        }

        self.listener_tls.insert(
            key.clone(),
            ListenerTlsConfig {
                settings,
                ..ListenerTlsConfig::default()
            },
        );
        Ok(())
    }
}

fn listen_key_addr(key: &ListenKey) -> String {
    std::net::SocketAddr::new(key.addr, key.port).to_string()
}

pub(super) fn proxy_pass_sni(host: &str, tls: bool) -> String {
    if tls && host.parse::<IpAddr>().is_err() {
        host.to_string()
    } else {
        String::new()
    }
}

pub(crate) fn downstream_keepalive_timeout_secs(timeout: &KeepaliveTimeout) -> Option<u64> {
    match timeout {
        KeepaliveTimeout::Off => None,
        KeepaliveTimeout::Timeout { idle, .. } => {
            let millis = idle.as_millis();
            if millis == 0 {
                None
            } else {
                let secs = millis.div_ceil(1_000);
                u64::try_from(secs).ok()
            }
        }
    }
}
