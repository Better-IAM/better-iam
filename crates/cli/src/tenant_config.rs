//! Tenant configuration files (`tenant-config.ts`): reading, offline checks, and the module form `config-export`
//! writes.

use std::path::Path;

use better_iam_core::js;
use better_iam_server::sync::validate_tenant_config;
use indexmap::IndexSet;
use serde_json::{Map, Value, json};

use crate::errors::{CliError, CliResult, io_error};
use crate::framework::Env;
use crate::output::stringify;

/// What a tenant configuration is planned or applied for (`TenantConfigContext`).
#[derive(Debug, Clone, Default)]
pub struct TenantConfigContext {
    pub tenant_id: Option<String>,
    pub env: Env,
}

const MODULE_EXTENSIONS: [&str; 5] = ["mjs", "js", "cjs", "ts", "mts"];

/// Reads a desired tenant configuration for `config-plan` / `config-apply` / `config-validate` (`loadTenantConfig`).
/// The npm CLI also imports JavaScript/TypeScript modules exporting the configuration (or a factory of it); those run
/// only under Node.js, so this CLI reads `.json` files and refuses modules with a hint.
pub fn load_tenant_config(path: &Path, context: &TenantConfigContext) -> CliResult<Value> {
    let _ = context;
    let extension = path
        .extension()
        .map(|extension| extension.to_string_lossy().to_lowercase())
        .unwrap_or_default();
    if MODULE_EXTENSIONS.contains(&extension.as_str()) {
        return Err(CliError::hinted(
            "INVALID_INPUT",
            format!(
                "{} is a JavaScript/TypeScript module, which only the Node.js CLI can load",
                path.display()
            ),
            "Use a .json configuration (better-iam config-export --output tenant.json writes one).",
        ));
    }
    let text = std::fs::read_to_string(path).map_err(|error| io_error(&error, "open", path))?;
    js::parse(&text).map_err(|error| {
        CliError::new(
            "INVALID_INPUT",
            format!("{} is not valid JSON: {error}", path.display()),
            None,
        )
    })
}

/// `{ valid: true, items, warnings }` (`TenantConfigLint`).
pub type TenantConfigLint = Value;

fn names(items: Option<&Vec<Value>>) -> IndexSet<String> {
    items
        .into_iter()
        .flatten()
        .filter_map(|item| item.get("name").and_then(Value::as_str).map(str::to_owned))
        .collect()
}

fn strings(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| item.as_str().map(str::to_owned))
        .collect()
}

fn name_of(item: &Value) -> String {
    item.get("name")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_owned()
}

/// Offline checks: the shape (`validateTenantConfig`) plus cross-references between the file's own items
/// (`lintTenantConfig`). References to names the file does not define must already exist in the tenant.
pub fn lint_tenant_config(value: &Value) -> CliResult<TenantConfigLint> {
    let config = validate_tenant_config(Some(value))?;
    let policies = names(config.policies.as_ref());
    let roles = names(config.roles.as_ref());
    let groups = names(config.groups.as_ref());
    let mut warnings: Vec<String> = Vec::new();
    let mut expect = |set: &IndexSet<String>, kind: &str, name: Option<&str>, place: &str| {
        if let Some(name) = name
            && !set.contains(name)
        {
            warnings.push(format!(
                "{place} names {kind} \"{name}\", which this file does not define"
            ));
        }
    };
    for role in config.roles.iter().flatten() {
        let place = format!("Role \"{}\"", name_of(role));
        for policy in strings(role.get("policies")) {
            expect(&policies, "policy", Some(&policy), &place);
        }
        for parent in strings(role.get("inherits")) {
            expect(&roles, "role", Some(&parent), &place);
        }
    }
    for binding in config.bindings.iter().flatten() {
        let text = |key: &str| binding.get(key).and_then(Value::as_str);
        let place = format!(
            "Binding {} -> {}",
            better_iam_server::js::js_string(binding.get("group")),
            better_iam_server::js::js_string(binding.get("role"))
        );
        expect(&groups, "group", text("group"), &place);
        expect(&roles, "role", text("role"), &place);
        expect(&groups, "group", text("approverGroup"), &place);
    }
    for item in config.packages.iter().flatten() {
        let place = format!("Package \"{}\"", name_of(item));
        for role in strings(item.get("roles")) {
            expect(&roles, "role", Some(&role), &place);
        }
        for group in strings(item.get("groups")) {
            expect(&groups, "group", Some(&group), &place);
        }
        expect(
            &groups,
            "group",
            item.get("approverGroup").and_then(Value::as_str),
            &place,
        );
    }
    for invariant in config.invariants.iter().flatten() {
        if let Some(Value::Object(subject)) = invariant.get("subject")
            && subject.contains_key("group")
        {
            expect(
                &groups,
                "group",
                subject.get("group").and_then(Value::as_str),
                &format!("Invariant \"{}\"", name_of(invariant)),
            );
        }
    }
    let mut items = Map::new();
    let lists: [(&str, Option<&Vec<Value>>); 8] = [
        ("resourceTypes", config.resource_types.as_ref()),
        ("policies", config.policies.as_ref()),
        ("roles", config.roles.as_ref()),
        ("groups", config.groups.as_ref()),
        ("bindings", config.bindings.as_ref()),
        ("packages", config.packages.as_ref()),
        ("invariants", config.invariants.as_ref()),
        ("agreements", config.agreements.as_ref()),
    ];
    for (key, list) in lists {
        if let Some(list) = list {
            items.insert(key.into(), Value::from(list.len()));
        }
    }
    if config.access_policy.is_some() {
        items.insert("accessPolicy".into(), Value::from(1));
    }
    Ok(json!({ "valid": true, "items": items, "warnings": warnings }))
}

/// `config-export --output tenant.config.ts|mjs`: the configuration as a typed module instead of JSON
/// (`tenantConfigModule`).
pub fn tenant_config_module(config: &Value, path: &str) -> String {
    let body = stringify(config, Some(2));
    let header =
        "// Generated by better-iam config-export. Apply it with: better-iam config-apply --input";
    let file = path.rsplit(['\\', '/']).next().unwrap_or(path);
    let lower = path.to_lowercase();
    if lower.ends_with(".ts") || lower.ends_with(".mts") {
        return format!(
            "{header} {file}\nimport {{ defineTenantConfig }} from 'better-iam/server';\n\nexport default defineTenantConfig({body});\n"
        );
    }
    format!(
        "{header} {file}\n/** @type {{import('better-iam/server').TenantConfig}} */\nexport default {body};\n"
    )
}
