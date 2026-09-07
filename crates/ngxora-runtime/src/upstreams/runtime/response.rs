//! Plugin header adapters and local/cached response framing.

use super::{ProxyContext, runtime_config_error};
use ngxora_plugin_api::{HeaderMapMut, LocalResponse, PluginError, PluginFlow, ResponseCtx};
use pingora::Result as PingoraResult;
use pingora::http::{RequestHeader, ResponseHeader};
use pingora_proxy::Session;
use std::fmt::Display;

fn header_editor_error(action: &str, name: &http::HeaderName, err: impl Display) -> PluginError {
    PluginError::new(
        "header-editor",
        format!("failed to {action} header `{name}`: {err}"),
    )
}

pub(super) struct RequestHeaderEditor<'a> {
    pub(super) inner: &'a mut RequestHeader,
}

impl HeaderMapMut for RequestHeaderEditor<'_> {
    fn get(&self, name: &http::HeaderName) -> Option<&http::HeaderValue> {
        self.inner.headers.get(name)
    }

    fn add(
        &mut self,
        name: &http::HeaderName,
        value: http::HeaderValue,
    ) -> Result<(), PluginError> {
        self.inner
            .append_header(name, value)
            .map(|_| ())
            .map_err(|err| header_editor_error("append", name, err))
    }

    fn set(
        &mut self,
        name: &http::HeaderName,
        value: http::HeaderValue,
    ) -> Result<(), PluginError> {
        self.inner
            .insert_header(name, value)
            .map_err(|err| header_editor_error("insert", name, err))
    }

    fn remove(&mut self, name: &http::HeaderName) {
        self.inner.remove_header(name);
    }
}

struct ResponseHeaderEditor<'a> {
    pub(super) inner: &'a mut ResponseHeader,
}

impl HeaderMapMut for ResponseHeaderEditor<'_> {
    fn get(&self, name: &http::HeaderName) -> Option<&http::HeaderValue> {
        self.inner.headers.get(name)
    }

    fn add(
        &mut self,
        name: &http::HeaderName,
        value: http::HeaderValue,
    ) -> Result<(), PluginError> {
        self.inner
            .append_header(name, value)
            .map(|_| ())
            .map_err(|err| header_editor_error("append", name, err))
    }

    fn set(
        &mut self,
        name: &http::HeaderName,
        value: http::HeaderValue,
    ) -> Result<(), PluginError> {
        self.inner
            .insert_header(name, value)
            .map_err(|err| header_editor_error("insert", name, err))
    }

    fn remove(&mut self, name: &http::HeaderName) {
        self.inner.remove_header(name);
    }
}

pub(super) fn respond_from_plugin_flow(flow: PluginFlow, stage: &str) -> PingoraResult<()> {
    match flow {
        PluginFlow::Continue => Ok(()),
        PluginFlow::Respond(_) => Err(pingora::Error::explain(
            pingora::ErrorType::InternalError,
            format!("plugin attempted local response during {stage}, which is not supported"),
        )),
    }
}

pub(super) fn map_plugin_error(stage: &str, err: PluginError) -> Box<pingora::Error> {
    pingora::Error::explain(
        pingora::ErrorType::InternalError,
        format!("plugin hook failed during {stage}: {err}"),
    )
}

fn set_content_length(header: &mut ResponseHeader, value: impl ToString) -> PingoraResult<()> {
    let value = value.to_string();
    header
        .insert_header(http::header::CONTENT_LENGTH, value)
        .map_err(|err| {
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                format!("failed to finalize plugin response: {err}"),
            )
        })
}

// Plugins can short-circuit the request path with a local response, but that
// response is still normalized through Pingora's typed response writer.
pub(super) async fn apply_response_plugins(
    header: &mut ResponseHeader,
    ctx: &mut ProxyContext,
) -> PingoraResult<()> {
    if ctx.response_plugins_applied {
        return Ok(());
    }
    ctx.response_plugins_applied = true;
    let Some(selected) = ctx.selected.clone() else {
        return Ok(());
    };
    let mut status = header.status;
    {
        let mut headers = ResponseHeaderEditor { inner: header };
        for plugin in selected.plugins.iter().rev() {
            let flow = plugin
                .on_response(&mut ResponseCtx {
                    state: &mut ctx.plugin_state,
                    status: &mut status,
                    headers: &mut headers,
                })
                .await
                .map_err(|e| map_plugin_error("response_filter", e))?;
            respond_from_plugin_flow(flow, "response_filter")?;
        }
    }
    header.set_status(status).map_err(runtime_config_error)?;
    Ok(())
}

pub(super) async fn write_route_response(
    session: &mut Session,
    ctx: &mut ProxyContext,
    response: LocalResponse,
) -> PingoraResult<()> {
    let mut header = ResponseHeader::build(response.status, None).map_err(|err| {
        pingora::Error::explain(
            pingora::ErrorType::InternalError,
            format!("failed to build plugin response: {err}"),
        )
    })?;
    for (name, value) in response.headers {
        header.append_header(name, value).map_err(|err| {
            pingora::Error::explain(
                pingora::ErrorType::InternalError,
                format!("failed to insert plugin response header: {err}"),
            )
        })?;
    }

    apply_response_plugins(&mut header, ctx).await?;
    header.remove_header(&http::header::TRANSFER_ENCODING);
    let body_forbidden = header.status.is_informational()
        || header.status == http::StatusCode::NO_CONTENT
        || header.status == http::StatusCode::NOT_MODIFIED;
    if body_forbidden {
        header.remove_header(&http::header::CONTENT_LENGTH);
    } else {
        set_content_length(&mut header, response.body.len().to_string())?;
    }
    if response.body.is_empty()
        || body_forbidden
        || session.req_header().method == http::Method::HEAD
    {
        session
            .write_response_header(Box::new(header), true)
            .await?;
        // Pingora's header EOS flag only reaches modules; explicitly finish H2.
        session.write_response_body(None, true).await
    } else {
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session.write_response_body(Some(response.body), true).await
    }
}

pub(super) async fn write_cached_response(
    session: &mut Session,
    cached: &crate::cache::CachedResponse,
) -> PingoraResult<()> {
    let mut header = ResponseHeader::build(cached.status, None).map_err(|err| {
        pingora::Error::explain(
            pingora::ErrorType::InternalError,
            format!("failed to build cached response header: {err}"),
        )
    })?;
    for (name, value) in cached.headers.iter() {
        header
            .insert_header(name.clone(), value.clone())
            .map_err(|err| {
                pingora::Error::explain(
                    pingora::ErrorType::InternalError,
                    format!("failed to insert cached header `{name}`: {err}"),
                )
            })?;
    }
    if cached.body.is_empty() {
        session
            .write_response_header(Box::new(header), true)
            .await?;
        session.write_response_body(None, true).await
    } else {
        session
            .write_response_header(Box::new(header), false)
            .await?;
        session
            .write_response_body(Some(cached.body.clone()), true)
            .await
    }
}
