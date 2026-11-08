//! The built-in commands (`commands/index.ts`).

use serde_json::{Map, Value};

use crate::framework::{CommandSpec, FlagSpec, Flags};

pub mod access;
pub mod api;
pub mod audit;
pub mod billing;
pub mod compliance;
pub mod operations;
pub mod session;
pub mod setup;
pub mod shell;
pub mod ssh;
pub mod storage;
pub mod vault;
pub mod vc;

/// Every built-in command, in help order (`builtinCommands`).
pub fn builtin_commands() -> Vec<CommandSpec> {
    let mut commands = Vec::new();
    commands.extend(setup::setup_commands());
    commands.extend(operations::operation_commands());
    commands.extend(billing::billing_commands());
    commands.extend(audit::audit_commands());
    commands.extend(storage::storage_commands());
    commands.extend(access::access_commands());
    commands.extend(ssh::ssh_commands());
    commands.extend(vc::vc_commands());
    commands.extend(compliance::compliance_commands());
    commands.extend(vault::vault_commands());
    commands.extend(api::api_commands());
    commands.extend(session::session_commands());
    commands.extend(shell::shell_commands());
    commands
}

/// An object of the members that are set, in order (`{ ...(x ? { key: x } : {}) }`).
pub(crate) fn object(entries: Vec<(&str, Option<Value>)>) -> Value {
    let mut map = Map::new();
    for (key, value) in entries {
        if let Some(value) = value {
            map.insert(key.to_owned(), value);
        }
    }
    Value::Object(map)
}

/// `{ tenantId }` when `--tenant` is set, else `{}`.
pub(crate) fn tenant_input(flags: &Flags) -> Value {
    object(vec![("tenantId", flags.string("tenant").map(Value::from))])
}

/// The length of an array member (0 when absent).
pub(crate) fn array_len(value: Option<&Value>) -> usize {
    value.and_then(Value::as_array).map_or(0, Vec::len)
}

/// The members of an object value (for `transport.call` inputs).
pub(crate) fn members(value: Value) -> Option<Map<String, Value>> {
    match value {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

/// The tenant a token command acts in: the flag, BETTER_IAM_TENANT, or the saved profile's (`tenantFlag`).
pub fn tenant_flag() -> FlagSpec {
    FlagSpec::string("The tenant to act in")
        .value("TENANT_ID")
        .required()
        .env("BETTER_IAM_TENANT")
        .profile("tenantId")
}

/// A tenant filter of a scheduler job: `{ type: 'string', value: 'TENANT_ID', description: 'Only this tenant' }`.
pub(crate) fn only_tenant() -> FlagSpec {
    FlagSpec::string("Only this tenant").value("TENANT_ID")
}

/// A typed result as the JSON TypeScript returns (JavaScript numbers: `1`, not `1.0`).
pub(crate) fn to_json<T: serde::Serialize>(value: &T) -> crate::errors::CliResult<Value> {
    let value = serde_json::to_value(value).map_err(|_| better_iam_server::js::internal_error())?;
    Ok(js_numbers(value))
}

/// Integral numbers as JSON integers, as `JSON.stringify` writes them.
pub(crate) fn js_numbers(value: Value) -> Value {
    match value {
        Value::Number(number) => {
            better_iam_core::js::number(better_iam_core::js::number_value(&number))
                .unwrap_or(Value::Null)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(js_numbers).collect()),
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(key, item)| (key, js_numbers(item)))
                .collect(),
        ),
        other => other,
    }
}
