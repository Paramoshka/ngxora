use ngxora_plugin_api::{PluginBuildError, PluginChain, PluginFactory, PluginSpec};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Default)]
pub struct PluginRegistry {
    factories: HashMap<&'static str, Arc<dyn PluginFactory>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_builtin_plugins() -> Self {
        let mut registry = Self::new();
        register_builtin_plugins(&mut registry);
        registry
    }

    pub fn register(&mut self, factory: Arc<dyn PluginFactory>) {
        self.factories.insert(factory.name(), factory);
    }

    pub fn build_chain(&self, specs: &[PluginSpec]) -> Result<PluginChain, PluginBuildError> {
        let mut chain = Vec::with_capacity(specs.len());

        for spec in specs {
            let Some(factory) = self.factories.get(spec.name.as_str()) else {
                return Err(PluginBuildError::new(
                    spec.name.clone(),
                    "plugin is not compiled into this binary",
                ));
            };

            chain.push(factory.build(spec)?);
        }

        Ok(chain.into())
    }
}

pub fn register_builtin_plugins(registry: &mut PluginRegistry) {
    #[cfg(feature = "plugin-headers")]
    registry.register(Arc::new(
        ngxora_extension_headers::HeadersPluginFactory,
    ));
}
