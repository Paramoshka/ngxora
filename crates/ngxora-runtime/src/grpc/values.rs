//! Scalar and enum conversion for the control-plane wire format.

use super::proto::{
    Switch as ProtoSwitch, UpstreamSelectionPolicy as ProtoUpstreamSelectionPolicy,
};
use ngxora_compile::ir::{KeepaliveTimeout, Switch, UpstreamSelectionPolicy};
use std::time::Duration;

pub(super) fn switch_from_proto(value: i32) -> Switch {
    match ProtoSwitch::try_from(value).unwrap_or(ProtoSwitch::Unspecified) {
        ProtoSwitch::Unspecified | ProtoSwitch::On => Switch::On,
        ProtoSwitch::Off => Switch::Off,
    }
}

pub(super) fn upstream_selection_policy_from_proto(
    value: i32,
) -> Result<UpstreamSelectionPolicy, String> {
    match ProtoUpstreamSelectionPolicy::try_from(value)
        .unwrap_or(ProtoUpstreamSelectionPolicy::Unspecified)
    {
        ProtoUpstreamSelectionPolicy::Unspecified | ProtoUpstreamSelectionPolicy::RoundRobin => {
            Ok(UpstreamSelectionPolicy::RoundRobin)
        }
        ProtoUpstreamSelectionPolicy::Random => Ok(UpstreamSelectionPolicy::Random),
        ProtoUpstreamSelectionPolicy::ConsistentHash => Ok(UpstreamSelectionPolicy::ConsistentHash),
    }
}

pub(super) fn proto_upstream_selection_policy_from_runtime(
    value: UpstreamSelectionPolicy,
) -> ProtoUpstreamSelectionPolicy {
    match value {
        UpstreamSelectionPolicy::RoundRobin => ProtoUpstreamSelectionPolicy::RoundRobin,
        UpstreamSelectionPolicy::Random => ProtoUpstreamSelectionPolicy::Random,
        UpstreamSelectionPolicy::ConsistentHash => ProtoUpstreamSelectionPolicy::ConsistentHash,
    }
}

pub(super) fn keepalive_timeout_from_proto(seconds: u64) -> KeepaliveTimeout {
    if seconds == 0 {
        KeepaliveTimeout::Off
    } else {
        KeepaliveTimeout::Timeout {
            idle: Duration::from_secs(seconds),
            header: None,
        }
    }
}

pub(super) fn duration_from_millis(millis: u64) -> Option<Duration> {
    (millis > 0).then(|| Duration::from_millis(millis))
}

pub(super) fn duration_to_millis(duration: Option<Duration>) -> u64 {
    duration
        .map(|value| u64::try_from(value.as_millis()).unwrap_or(u64::MAX))
        .unwrap_or(0)
}

pub(super) fn switch_from_bool(value: bool) -> Switch {
    if value { Switch::On } else { Switch::Off }
}

pub(super) fn proto_switch_from_runtime(value: Switch) -> ProtoSwitch {
    match value {
        Switch::On => ProtoSwitch::On,
        Switch::Off => ProtoSwitch::Off,
    }
}

pub(super) fn none_if_zero(value: u32) -> Option<u32> {
    (value > 0).then_some(value)
}

pub(super) fn none_if_zero_u64(value: u64) -> Option<u64> {
    (value > 0).then_some(value)
}

pub(super) fn none_if_empty(value: String) -> Option<String> {
    (!value.is_empty()).then_some(value)
}
