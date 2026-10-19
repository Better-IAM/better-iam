//! Port of `packages/server/src/define.ts`: typed deployment configuration for the `better-iam` CLI and servers.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use better_iam_core::IamResult;
use futures::future::BoxFuture;
use serde_json::Value;

use crate::options::BetterIamOptions;

/// `IamConfigContext`: what a configuration factory receives when the CLI (or your code) calls it.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IamConfigContext {
    /// The CLI command being run (`migrate`, `api`, a project command); None when your server calls the factory.
    pub command: Option<String>,
    pub env: Option<HashMap<String, String>>,
    pub cwd: Option<PathBuf>,
}

/// `IamConfigFactory`: a deployment configuration computed on demand.
pub type IamConfigFactory =
    Arc<dyn Fn(IamConfigContext) -> BoxFuture<'static, IamResult<BetterIamOptions>> + Send + Sync>;

/// A `defineConfig` value: options, or a factory of them.
#[derive(Clone)]
pub enum IamConfig {
    Options(Box<BetterIamOptions>),
    Factory(IamConfigFactory),
}

/// `defineConfig(config)`: returns its argument unchanged.
pub fn define_config(config: IamConfig) -> IamConfig {
    config
}

/// `configOptions(config, context)`: a factory is called with `context` (default: this process's environment and
/// working directory), plain options are returned as they are.
pub async fn config_options(
    config: IamConfig,
    context: Option<IamConfigContext>,
) -> IamResult<BetterIamOptions> {
    match config {
        IamConfig::Options(options) => Ok(*options),
        IamConfig::Factory(factory) => {
            let context = context.unwrap_or_else(|| IamConfigContext {
                command: None,
                env: Some(std::env::vars().collect()),
                cwd: std::env::current_dir().ok(),
            });
            factory(context).await
        }
    }
}

/// `TenantConfigFactoryContext`: what a tenant-configuration factory receives from `config-plan` / `config-apply`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TenantConfigFactoryContext {
    pub tenant_id: Option<String>,
    pub env: HashMap<String, String>,
}

/// A tenant's configuration as code (`TenantConfig` of sync.ts), as JSON until sync.ts is ported.
pub type TenantConfig = Value;

/// A tenant configuration factory.
pub type TenantConfigFactory = Arc<
    dyn Fn(TenantConfigFactoryContext) -> BoxFuture<'static, IamResult<TenantConfig>> + Send + Sync,
>;

/// A `defineTenantConfig` value.
#[derive(Clone)]
pub enum TenantConfigDefinition {
    Config(TenantConfig),
    Factory(TenantConfigFactory),
}

/// `defineTenantConfig(config)`: returns its argument unchanged.
pub fn define_tenant_config(config: TenantConfigDefinition) -> TenantConfigDefinition {
    config
}
