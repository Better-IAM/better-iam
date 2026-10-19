//! Port of `packages/server/src/plugins.ts`: plugins are validated once at construction (unique IDs, registered
//! actions, and well-formed POST endpoints).

use std::collections::HashSet;
use std::sync::{Arc, LazyLock};

use better_iam_core::{IamPlugin, IamResult};
use regex::Regex;

use crate::catalog::Catalog;
use crate::js::invalid_config;

static ENDPOINT_PATH: LazyLock<Regex> =
    LazyLock::new(|| Regex::new("^[a-zA-Z0-9_-]+(?:/[a-zA-Z0-9_-]+)*$").expect("regex"));

/// `validatePlugins(plugins, catalog)`. Endpoints are always `POST` with a validator and a handler in Rust (the
/// `PluginEndpoint` trait requires them), so only the path rules remain to check.
pub fn validate_plugins(plugins: &[Arc<dyn IamPlugin>], catalog: &Catalog) -> IamResult<()> {
    let ids: HashSet<&str> = plugins.iter().map(|plugin| plugin.id()).collect();
    if ids.len() != plugins.len() {
        return Err(invalid_config("Duplicate plugin ID"));
    }
    for plugin in plugins {
        plugin.validate_config()?;
        let mut paths = HashSet::new();
        for endpoint in plugin.endpoints() {
            if !catalog.actions.contains(endpoint.action()) {
                return Err(invalid_config("Plugin endpoint action must be registered"));
            }
            let path = endpoint.path();
            let path = path.strip_prefix('/').unwrap_or(path).to_owned();
            if !ENDPOINT_PATH.is_match(&path) || paths.contains(&path) {
                return Err(invalid_config(
                    "Plugin endpoints require unique paths, POST, validation, and a handler",
                ));
            }
            paths.insert(path);
        }
    }
    Ok(())
}
