use bytes::Bytes;
use http::{Extensions, HeaderName, HeaderValue, Method, StatusCode};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::error::Error;
use std::fmt::{Display, Formatter};
use std::sync::Arc;

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PluginSpec {
    pub name: String,
    #[serde(default)]
    pub config: Value,
}

#[derive(Debug, Default)]
pub struct PluginState {
    pub extensions: Extensions,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginError {
    pub plugin: String,
    pub message: String,
}

impl PluginError {
    pub fn new(plugin: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            plugin: plugin.into(),
            message: message.into(),
        }
    }
}

impl Display for PluginError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.plugin, self.message)
    }
}

impl Error for PluginError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PluginBuildError {
    pub plugin: String,
    pub message: String,
}

impl PluginBuildError {
    pub fn new(plugin: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            plugin: plugin.into(),
            message: message.into(),
        }
    }
}

impl Display for PluginBuildError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.plugin, self.message)
    }
}

impl Error for PluginBuildError {}

pub trait HeaderMapMut {
    fn add(&mut self, name: &HeaderName, value: HeaderValue) -> Result<(), PluginError>;
    fn set(&mut self, name: &HeaderName, value: HeaderValue) -> Result<(), PluginError>;
    fn remove(&mut self, name: &HeaderName);
}

pub struct RequestCtx<'a> {
    pub state: &'a mut PluginState,
    pub path: &'a str,
    pub host: Option<&'a str>,
    pub method: &'a Method,
    pub headers: &'a mut dyn HeaderMapMut,
}

pub struct UpstreamRequestCtx<'a> {
    pub state: &'a mut PluginState,
    pub headers: &'a mut dyn HeaderMapMut,
}

pub struct ResponseCtx<'a> {
    pub state: &'a mut PluginState,
    pub status: &'a mut StatusCode,
    pub headers: &'a mut dyn HeaderMapMut,
}

#[derive(Debug, Clone)]
pub struct LocalResponse {
    pub status: StatusCode,
    pub headers: Vec<(HeaderName, HeaderValue)>,
    pub body: Bytes,
}

impl LocalResponse {
    pub fn new(status: StatusCode, body: impl Into<Bytes>) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.into(),
        }
    }
}

#[derive(Debug, Clone)]
pub enum PluginFlow {
    Continue,
    Respond(LocalResponse),
}

pub type PluginChain = Arc<[Arc<dyn HttpPlugin>]>;

pub fn empty_plugin_chain() -> PluginChain {
    Vec::<Arc<dyn HttpPlugin>>::new().into()
}

pub trait HttpPlugin: Send + Sync {
    fn name(&self) -> &'static str;

    fn on_request(&self, _ctx: &mut RequestCtx<'_>) -> Result<PluginFlow, PluginError> {
        Ok(PluginFlow::Continue)
    }

    fn on_upstream_request(
        &self,
        _ctx: &mut UpstreamRequestCtx<'_>,
    ) -> Result<PluginFlow, PluginError> {
        Ok(PluginFlow::Continue)
    }

    fn on_response(&self, _ctx: &mut ResponseCtx<'_>) -> Result<PluginFlow, PluginError> {
        Ok(PluginFlow::Continue)
    }
}

pub trait PluginFactory: Send + Sync {
    fn name(&self) -> &'static str;
    fn build(&self, spec: &PluginSpec) -> Result<Arc<dyn HttpPlugin>, PluginBuildError>;
}
