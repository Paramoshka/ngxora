use super::{LowerErr, values};
use crate::ir::GeoIpConfig;
use ngxora_config::{Block, Node};
use std::{net::IpAddr, time::Duration};

pub(super) fn lower_geoip(block: &Block) -> Result<GeoIpConfig, LowerErr> {
    let error = |message: &str| LowerErr {
        message: message.into(),
    };
    if !block.args.is_empty() {
        return Err(error("geoip block takes no arguments"));
    }
    let mut database = None;
    let mut interval = None;
    let mut trusted_proxies = Vec::new();
    for node in &block.children {
        let Node::Directive(d) = node else {
            return Err(error("geoip does not accept nested blocks"));
        };
        let [value] = d.args.as_slice() else {
            return Err(error("geoip directives require exactly one argument"));
        };
        match d.name.as_str() {
            "database" if database.is_none() => database = Some(value.into()),
            "reload_interval" if interval.is_none() => {
                interval = Some(values::parse_single_duration_directive(
                    &d.args,
                    "geoip reload_interval",
                )?);
            }
            "trusted_proxy" => trusted_proxies.push(
                value
                    .parse()
                    .or_else(|_| value.parse::<IpAddr>().map(Into::into))
                    .map_err(|_| error("invalid geoip trusted_proxy: expected IP or CIDR"))?,
            ),
            _ => return Err(error("unknown or duplicate geoip directive")),
        }
    }
    let config = GeoIpConfig {
        database: database.ok_or_else(|| error("geoip requires database"))?,
        reload_interval: interval.unwrap_or(Duration::from_secs(5)),
        trusted_proxies,
    };
    config.validate().map_err(|message| LowerErr { message })?;
    Ok(config)
}
