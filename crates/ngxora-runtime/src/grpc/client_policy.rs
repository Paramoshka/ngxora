use super::proto;
use ipnet::IpNet;
use ngxora_compile::ir::{LocationIpRule, RealIpConfig};
use std::net::IpAddr;

fn network(value: &str) -> Result<IpNet, String> {
    value
        .parse::<IpNet>()
        .or_else(|_| value.parse::<IpAddr>().map(IpNet::from))
        .map_err(|_| format!("invalid IP or CIDR `{value}`"))
}

pub(super) fn access_from_proto(rule: &proto::IpAccessRule) -> Result<LocationIpRule, String> {
    use proto::ip_access_rule::Action;
    match Action::try_from(rule.action) {
        Ok(Action::Allow) if rule.source == "all" => Ok(LocationIpRule::AllowAll),
        Ok(Action::Deny) if rule.source == "all" => Ok(LocationIpRule::DenyAll),
        Ok(Action::Allow) => Ok(LocationIpRule::Allow(network(&rule.source)?)),
        Ok(Action::Deny) => Ok(LocationIpRule::Deny(network(&rule.source)?)),
        _ => Err("IP access rule requires action ALLOW or DENY".into()),
    }
}

pub(super) fn access_to_proto(rule: &LocationIpRule) -> proto::IpAccessRule {
    proto::IpAccessRule {
        action: if rule.is_allow() {
            proto::ip_access_rule::Action::Allow
        } else {
            proto::ip_access_rule::Action::Deny
        } as i32,
        source: match rule {
            LocationIpRule::Allow(n) | LocationIpRule::Deny(n) => n.to_string(),
            LocationIpRule::AllowAll | LocationIpRule::DenyAll => "all".into(),
        },
    }
}

pub(super) fn real_ip_from_proto(config: &proto::RealIpConfig) -> Result<RealIpConfig, String> {
    let config = RealIpConfig {
        trusted_proxies: config
            .trusted_proxies
            .iter()
            .map(|s| network(s))
            .collect::<Result<_, _>>()?,
        header: if config.header.is_empty() {
            "X-Forwarded-For".into()
        } else {
            config.header.clone()
        },
        recursive: config.recursive.unwrap_or(true),
    };
    config.validate()?;
    Ok(config)
}

pub(super) fn real_ip_to_proto(config: &RealIpConfig) -> proto::RealIpConfig {
    proto::RealIpConfig {
        trusted_proxies: config
            .trusted_proxies
            .iter()
            .map(ToString::to_string)
            .collect(),
        header: config.header.clone(),
        recursive: Some(config.recursive),
    }
}
