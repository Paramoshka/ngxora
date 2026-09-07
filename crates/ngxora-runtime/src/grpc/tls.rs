//! TLS material and protocol conversion; no network or certificate loading.

use super::proto;
use super::proto::{
    LetsEncryptConfig as ProtoLetsEncryptConfig, ListenerTlsOptions as ProtoListenerTlsOptions,
    PemSource as ProtoPemSource, TlsBinding as ProtoTlsBinding,
    TlsProtocolVersion as ProtoTlsProtocolVersion, TlsVerifyClient as ProtoTlsVerifyClient,
    UpstreamTlsOptions as ProtoUpstreamTlsOptions,
};
use super::values::{none_if_empty, proto_switch_from_runtime, switch_from_proto};
use ngxora_compile::ir::{
    DownstreamTlsOptions, LetsEncryptConfig, PemSource, TlsIdentity, TlsProtocolBounds,
    TlsProtocolVersion, TlsVerifyClient, UpstreamSslOptions,
};
use std::path::PathBuf;

pub(super) fn tls_identity_from_proto(value: &ProtoTlsBinding) -> Result<TlsIdentity, String> {
    Ok(TlsIdentity {
        cert: pem_source_from_proto(value.cert.as_ref(), "tls cert")?,
        key: pem_source_from_proto(value.key.as_ref(), "tls key")?,
    })
}

pub(super) fn listener_tls_options_from_proto(
    value: Option<&ProtoListenerTlsOptions>,
) -> Result<DownstreamTlsOptions, String> {
    let Some(value) = value else {
        return Ok(DownstreamTlsOptions::default());
    };

    let min = tls_protocol_version_from_proto(value.min_protocol)?;
    let max = tls_protocol_version_from_proto(value.max_protocol)?;
    let protocols = match (min, max) {
        (None, None) => None,
        (Some(min), Some(max)) if min <= max => Some(TlsProtocolBounds { min, max }),
        (Some(_), Some(_)) => {
            return Err(
                "listener TLS protocol bounds are invalid: min_protocol > max_protocol".into(),
            );
        }
        _ => {
            return Err(
                "listener TLS protocol bounds must set both min_protocol and max_protocol".into(),
            );
        }
    };

    Ok(DownstreamTlsOptions {
        protocols,
        verify_client: tls_verify_client_from_proto(value.verify_client)?,
        client_certificate: value
            .client_certificate
            .as_ref()
            .map(|source| pem_source_from_proto(Some(source), "client certificate"))
            .transpose()?,
    })
}

fn pem_source_from_proto(value: Option<&ProtoPemSource>, field: &str) -> Result<PemSource, String> {
    let source = value.ok_or_else(|| format!("{field} is required"))?;
    let source = source
        .source
        .as_ref()
        .ok_or_else(|| format!("{field} source is required"))?;

    match source {
        proto::pem_source::Source::Path(path) => Ok(PemSource::Path(path.into())),
        proto::pem_source::Source::InlinePem(pem) => Ok(PemSource::InlinePem(pem.clone())),
    }
}

pub(super) fn upstream_tls_options_from_proto(
    value: Option<&ProtoUpstreamTlsOptions>,
) -> Result<Option<UpstreamSslOptions>, String> {
    let Some(value) = value else {
        return Ok(None);
    };

    let client_certificate = value
        .client_certificate
        .as_ref()
        .map(|source| pem_source_from_proto(Some(source), "route upstream client certificate"))
        .transpose()?;
    let client_certificate_key = value
        .client_certificate_key
        .as_ref()
        .map(|source| pem_source_from_proto(Some(source), "route upstream client certificate key"))
        .transpose()?;

    match (
        client_certificate.is_some(),
        client_certificate_key.is_some(),
    ) {
        (true, false) => {
            return Err(
                "UpstreamTlsOptions: client_certificate requires client_certificate_key".into(),
            );
        }
        (false, true) => {
            return Err(
                "UpstreamTlsOptions: client_certificate_key requires client_certificate".into(),
            );
        }
        _ => {}
    }

    Ok(Some(UpstreamSslOptions {
        verify_cert: switch_from_proto(value.verify),
        trusted_certificate: value
            .trusted_certificate
            .as_ref()
            .map(|source| pem_source_from_proto(Some(source), "route upstream trusted certificate"))
            .transpose()?,
        client_certificate,
        client_certificate_key,
    }))
}

// ── LetsEncryptConfig ↔ proto ──

pub(super) fn le_config_from_proto(value: &ProtoLetsEncryptConfig) -> LetsEncryptConfig {
    LetsEncryptConfig {
        acme_directory: none_if_empty(value.acme_directory.clone()),
        email: none_if_empty(value.email.clone()),
        cache_dir: none_if_empty(value.cache_dir.clone()).map(PathBuf::from),
    }
}

pub(super) fn proto_le_config_from_ir(value: &LetsEncryptConfig) -> ProtoLetsEncryptConfig {
    ProtoLetsEncryptConfig {
        acme_directory: value.acme_directory.clone().unwrap_or_default(),
        email: value.email.clone().unwrap_or_default(),
        cache_dir: value
            .cache_dir
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_default(),
    }
}

pub(super) fn proto_upstream_tls_options_from_runtime(
    value: &UpstreamSslOptions,
) -> ProtoUpstreamTlsOptions {
    ProtoUpstreamTlsOptions {
        verify: proto_switch_from_runtime(value.verify_cert) as i32,
        trusted_certificate: value
            .trusted_certificate
            .as_ref()
            .map(proto_pem_source_from_runtime),
        client_certificate: value
            .client_certificate
            .as_ref()
            .map(proto_pem_source_from_runtime),
        client_certificate_key: value
            .client_certificate_key
            .as_ref()
            .map(proto_pem_source_from_runtime),
    }
}

pub(super) fn proto_listener_tls_options_from_runtime(
    value: &crate::upstreams::ListenerTlsSettings,
) -> ProtoListenerTlsOptions {
    let (min_protocol, max_protocol) = value
        .protocols
        .map(|bounds| {
            (
                proto_tls_protocol_version_from_runtime(bounds.min),
                proto_tls_protocol_version_from_runtime(bounds.max),
            )
        })
        .unwrap_or((
            ProtoTlsProtocolVersion::Unspecified as i32,
            ProtoTlsProtocolVersion::Unspecified as i32,
        ));

    ProtoListenerTlsOptions {
        min_protocol,
        max_protocol,
        verify_client: proto_tls_verify_client_from_runtime(value.verify_client) as i32,
        client_certificate: value
            .client_certificate
            .as_ref()
            .map(proto_pem_source_from_runtime),
    }
}

pub(super) fn proto_tls_binding_from_runtime(value: &TlsIdentity) -> ProtoTlsBinding {
    ProtoTlsBinding {
        cert: Some(proto_pem_source_from_runtime(&value.cert)),
        key: Some(proto_pem_source_from_runtime(&value.key)),
    }
}

fn proto_pem_source_from_runtime(value: &PemSource) -> ProtoPemSource {
    let source = match value {
        PemSource::Path(path) => proto::pem_source::Source::Path(path.display().to_string()),
        PemSource::InlinePem(pem) => proto::pem_source::Source::InlinePem(pem.clone()),
    };

    ProtoPemSource {
        source: Some(source),
    }
}

fn proto_tls_protocol_version_from_runtime(value: TlsProtocolVersion) -> i32 {
    match value {
        TlsProtocolVersion::Tls1 => ProtoTlsProtocolVersion::Tls1 as i32,
        TlsProtocolVersion::Tls1_2 => ProtoTlsProtocolVersion::Tls12 as i32,
        TlsProtocolVersion::Tls1_3 => ProtoTlsProtocolVersion::Tls13 as i32,
    }
}

fn proto_tls_verify_client_from_runtime(value: TlsVerifyClient) -> ProtoTlsVerifyClient {
    match value {
        TlsVerifyClient::Off => ProtoTlsVerifyClient::Off,
        TlsVerifyClient::Optional => ProtoTlsVerifyClient::Optional,
        TlsVerifyClient::Required => ProtoTlsVerifyClient::Required,
    }
}

fn tls_protocol_version_from_proto(value: i32) -> Result<Option<TlsProtocolVersion>, String> {
    match ProtoTlsProtocolVersion::try_from(value).unwrap_or(ProtoTlsProtocolVersion::Unspecified) {
        ProtoTlsProtocolVersion::Unspecified => Ok(None),
        ProtoTlsProtocolVersion::Tls1 => Ok(Some(TlsProtocolVersion::Tls1)),
        ProtoTlsProtocolVersion::Tls12 => Ok(Some(TlsProtocolVersion::Tls1_2)),
        ProtoTlsProtocolVersion::Tls13 => Ok(Some(TlsProtocolVersion::Tls1_3)),
    }
}

fn tls_verify_client_from_proto(value: i32) -> Result<TlsVerifyClient, String> {
    match ProtoTlsVerifyClient::try_from(value).unwrap_or(ProtoTlsVerifyClient::Unspecified) {
        ProtoTlsVerifyClient::Unspecified | ProtoTlsVerifyClient::Off => Ok(TlsVerifyClient::Off),
        ProtoTlsVerifyClient::Optional => Ok(TlsVerifyClient::Optional),
        ProtoTlsVerifyClient::Required => Ok(TlsVerifyClient::Required),
    }
}
