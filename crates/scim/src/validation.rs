//! Port of `packages/scim/src/validation.ts`.

use better_iam_core::{IamError, IamResult, IamStore, js as core_js, tenant_tree_active};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::types::ObjectValue;

/// `hash(value)`: SHA-256, lowercase hex.
pub fn hash(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

/// `object(value)`: a JSON object, else `invalidSyntax`.
pub fn object(value: Option<&Value>) -> IamResult<&ObjectValue> {
    match value {
        Some(Value::Object(map)) => Ok(map),
        _ => Err(IamError::new("invalidSyntax", "Expected a JSON object.")),
    }
}

/// `text(value, field, optional)`: a trimmed nonempty string of at most 512 characters (None when optional and
/// absent).
pub fn text(value: Option<&Value>, field: &str, optional: bool) -> IamResult<Option<String>> {
    if optional && value.is_none() {
        return Ok(None);
    }
    match value {
        Some(Value::String(text))
            if !core_js::trim(text).is_empty() && core_js::utf16_len(text) <= 512 =>
        {
            Ok(Some(core_js::trim(text).to_owned()))
        }
        _ => Err(IamError::new(
            "invalidValue",
            format!("{field} must be a nonempty string of at most 512 characters."),
        )),
    }
}

/// `text(value, field)!`: the required form.
pub fn required_text(value: Option<&Value>, field: &str) -> IamResult<String> {
    Ok(text(value, field, false)?.unwrap_or_default())
}

/// `fields(value, allowed)`: rejects attributes outside `allowed`. Resource bodies pass through `withoutIgnored`
/// (attributes.rs) first, so what reaches this is an attribute no supported schema defines (or, with
/// `unsupportedAttributes: 'reject'`, one this service does not store).
pub fn fields(value: &ObjectValue, allowed: &[&str]) -> IamResult<()> {
    if value.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(IamError::new(
            "mutability",
            "An unsupported or immutable attribute was supplied.",
        ));
    }
    Ok(())
}

/// `bool(value, fallback)`.
pub fn bool_value(value: Option<&Value>, fallback: bool) -> IamResult<bool> {
    match value {
        None => Ok(fallback),
        Some(Value::Bool(flag)) => Ok(*flag),
        Some(_) => Err(IamError::new("invalidValue", "active must be a boolean.")),
    }
}

/// `activeTenant(store, id)`: 401 unless the tenant and its ancestors are active.
pub async fn active_tenant(store: &dyn IamStore, id: &str) -> IamResult<()> {
    if !tenant_tree_active(store, id).await? {
        return Err(IamError::with_status(
            "unauthorized",
            "Inactive tenant.",
            401,
        ));
    }
    Ok(())
}
