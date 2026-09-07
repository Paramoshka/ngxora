//! Structured HTTPRoute match, redirect and rewrite conversion.

use super::proto;
use ngxora_compile::ir as http_ir;

pub(super) fn direct_status(status: u32) -> Result<u16, String> {
    u16::try_from(status).map_err(|_| "direct response status out of range".into())
}

pub(super) fn modifier_from_proto(
    value: &proto::PathModifier,
) -> Result<http_ir::PathModifier, String> {
    Ok(
        match value
            .kind
            .as_ref()
            .ok_or("path modifier kind is required")?
        {
            proto::path_modifier::Kind::ReplaceFullPath(path) => {
                http_ir::PathModifier::ReplaceFullPath(path.clone())
            }
            proto::path_modifier::Kind::ReplacePrefixMatch(path) => {
                http_ir::PathModifier::ReplacePrefixMatch(path.clone())
            }
        },
    )
}

pub(super) fn modifier_to_proto(value: &http_ir::PathModifier) -> proto::PathModifier {
    proto::PathModifier {
        kind: Some(match value {
            http_ir::PathModifier::ReplaceFullPath(path) => {
                proto::path_modifier::Kind::ReplaceFullPath(path.clone())
            }
            http_ir::PathModifier::ReplacePrefixMatch(path) => {
                proto::path_modifier::Kind::ReplacePrefixMatch(path.clone())
            }
        }),
    }
}

pub(super) fn http_redirect_from_proto(
    value: &proto::HttpRedirect,
) -> Result<http_ir::HttpRedirect, String> {
    Ok(http_ir::HttpRedirect {
        status: direct_status(if value.status == 0 { 302 } else { value.status })?,
        scheme: value.scheme.clone(),
        hostname: value.hostname.clone(),
        port: value
            .port
            .map(|p| u16::try_from(p).map_err(|_| "redirect port out of range"))
            .transpose()?,
        path: value.path.as_ref().map(modifier_from_proto).transpose()?,
    })
}

pub(super) fn http_match_from_proto(value: &proto::HttpMatch) -> http_ir::HttpMatch {
    http_ir::HttpMatch {
        path: match &value.path {
            Some(proto::http_match::Path::Exact(path)) => {
                http_ir::HttpPathMatch::Exact(path.clone())
            }
            Some(proto::http_match::Path::PathPrefix(path)) => {
                http_ir::HttpPathMatch::PathPrefix(path.clone())
            }
            None => http_ir::HttpPathMatch::PathPrefix("/".into()),
        },
        method: value.method.clone(),
        headers: value
            .headers
            .iter()
            .map(|c| (c.name.clone(), c.value.clone()))
            .collect(),
        query_params: value
            .query_params
            .iter()
            .map(|c| (c.name.clone(), c.value.clone()))
            .collect(),
    }
}

pub(super) fn http_match_to_proto(value: &http_ir::HttpMatch) -> proto::HttpMatch {
    proto::HttpMatch {
        path: Some(match &value.path {
            http_ir::HttpPathMatch::Exact(path) => proto::http_match::Path::Exact(path.clone()),
            http_ir::HttpPathMatch::PathPrefix(path) => {
                proto::http_match::Path::PathPrefix(path.clone())
            }
        }),
        method: value.method.clone(),
        headers: value
            .headers
            .iter()
            .map(|(name, value)| proto::ExactCondition {
                name: name.clone(),
                value: value.clone(),
            })
            .collect(),
        query_params: value
            .query_params
            .iter()
            .map(|(name, value)| proto::ExactCondition {
                name: name.clone(),
                value: value.clone(),
            })
            .collect(),
    }
}
