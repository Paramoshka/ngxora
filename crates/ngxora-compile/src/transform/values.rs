//! Shared scalar parsing and duplicate-value validation.

use super::LowerErr;
use crate::consts;
use crate::ir::{KeepaliveTimeout, Switch};
use ngxora_config::{Block, Directive, Node};

pub(super) fn parse_exactly_one_argument(
    args: &[String],
    directive: &str,
) -> Result<String, LowerErr> {
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

pub(super) fn parse_positive_usize(args: &[String], directive: &str) -> Result<usize, LowerErr> {
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

pub(super) fn ensure_non_zero_duration(
    value: std::time::Duration,
    directive: &str,
) -> Result<(), LowerErr> {
    if value.is_zero() {
        return Err(LowerErr {
            message: format!("{directive}: value must be greater than zero"),
        });
    }
    Ok(())
}

pub(super) fn set_once<T>(slot: &mut Option<T>, value: T, directive: &str) -> Result<(), LowerErr> {
    if slot.replace(value).is_some() {
        return Err(LowerErr {
            message: format!("{directive}: duplicated directive"),
        });
    }
    Ok(())
}

pub(super) fn parse_basic_auth_single_value(
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

pub(super) fn parse_basic_auth_joined_value(
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

pub(super) fn block_named<'a>(node: &'a Node, name: &'a str) -> Option<&'a Block> {
    match node {
        Node::Block(block) if name == block.name => Some(block),
        _ => None,
    }
}

pub(super) fn get_directive_switch(d: &Directive) -> Result<Switch, LowerErr> {
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

pub(super) fn parse_keepalive_timeout(args: &[String]) -> Result<KeepaliveTimeout, LowerErr> {
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

pub(super) fn parse_keepalive_requests(args: &[String]) -> Result<u32, LowerErr> {
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

pub(super) fn parse_client_max_body_size(args: &[String]) -> Result<Option<u64>, LowerErr> {
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

pub(super) fn parse_single_duration_directive(
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

pub(super) fn parse_size_literal(raw: &str, directive: &str) -> Result<u64, LowerErr> {
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
