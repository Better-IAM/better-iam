//! The provisioning API (`packages/server/src/api`): one module per TypeScript file, each creating the API groups
//! [`index::create_api`] assembles. Every route method takes the request body exactly as the TypeScript function
//! receives `input` ([`Body`], validated by the method itself, in the TypeScript order) and answers its result
//! ([`Reply`]). Both are tagged with the generated request and result types of `better-iam-types`.

use std::marker::PhantomData;
use std::ops::Deref;

use better_iam_core::{IamError, IamResult};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

pub mod access_paths;
pub mod access_requests;
pub mod agents;
pub mod agreements;
pub mod analysis;
pub mod applications;
pub mod billing;
pub mod bindings;
pub mod catalog;
pub mod certifications;
pub mod clearances;
pub mod compliance;
pub mod delegations;
pub mod departments;
pub mod devices;
pub mod dispatch;
pub mod domains;
pub mod features;
pub mod filters;
pub mod groups;
pub mod guests;
pub mod hostnames;
pub mod identities;
pub mod impact;
pub mod index;
pub mod inference;
pub mod invariants;
pub mod keys;
pub mod ldap;
pub mod licenses;
pub mod oidc_providers;
pub mod onboarding;
pub mod package_automation;
pub mod packages;
pub mod pki;
pub mod policies;
pub mod privacy;
pub mod protection;
pub mod quotas;
pub mod relationships;
pub mod reports;
pub mod resources;
pub mod role_mining;
pub mod roles;
pub mod security;
pub mod service_accounts;
pub mod signals;
pub mod sod;
pub mod ssh;
pub mod sts;
pub mod teams;
pub mod tenants;
pub mod threats;
pub mod trust;
pub mod vault;
pub mod verifiable_credentials;
pub mod webhooks;
pub mod workflows;

/// A credential given as JSON in a request body or a conformance call: `{"token": ...}` or `{"headers": {...}}` (also
/// tagged `{"$headers": {...}}` or a list of pairs).
pub fn credential_from_json(value: Option<&Value>) -> better_iam_core::CredentialInput {
    let Some(Value::Object(map)) = value else {
        return better_iam_core::CredentialInput::default();
    };
    let headers = match map.get("headers") {
        Some(Value::Object(headers)) => {
            let headers = match headers.get("$headers") {
                Some(Value::Object(inner)) if headers.len() == 1 => inner,
                _ => headers,
            };
            Some(
                headers
                    .iter()
                    .filter_map(|(name, value)| {
                        value.as_str().map(|value| (name.clone(), value.to_owned()))
                    })
                    .collect(),
            )
        }
        Some(Value::Array(pairs)) => Some(
            pairs
                .iter()
                .filter_map(|pair| match pair.as_array().map(Vec::as_slice) {
                    Some([Value::String(name), Value::String(value)]) => {
                        Some((name.clone(), value.clone()))
                    }
                    _ => None,
                })
                .collect(),
        ),
        _ => None,
    };
    better_iam_core::CredentialInput {
        headers,
        token: map.get("token").and_then(Value::as_str).map(str::to_owned),
    }
}

/// A string member of a request body, or "" when it is absent or not a string: the resource ID of operations that
/// authorize on the tenant itself (`operation(credential, input.tenantId, action, input.tenantId, ...)`), where a
/// non-string tenant ID is refused by the envelope before the resource ID is used.
pub fn string_member(input: &Map<String, Value>, key: &str) -> String {
    input
        .get(key)
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// The JSON body a route method receives: exactly the object the TypeScript method gets as `input`, unvalidated
/// (methods validate members themselves, in the TypeScript order, with the TypeScript messages). `I` is the route's
/// generated request type; [`Body::decode`] reads the body as it once validation has passed, where that helps.
pub struct Body<I> {
    raw: Map<String, Value>,
    marker: PhantomData<fn() -> I>,
}

impl<I> Body<I> {
    /// A body from the request's JSON object.
    pub fn new(raw: Map<String, Value>) -> Self {
        Self {
            raw,
            marker: PhantomData,
        }
    }

    /// A body from any JSON value; anything but an object is an empty body (the router only passes objects).
    pub fn from_value(value: Value) -> Self {
        match value {
            Value::Object(raw) => Self::new(raw),
            _ => Self::new(Map::new()),
        }
    }

    /// The members.
    pub fn raw(&self) -> &Map<String, Value> {
        &self.raw
    }

    /// The members, owned.
    pub fn into_inner(self) -> Map<String, Value> {
        self.raw
    }

    /// The body as a JSON object value.
    pub fn value(&self) -> Value {
        Value::Object(self.raw.clone())
    }

    /// The same members tagged with another request type (one method calling another with its input).
    pub fn retype<J>(self) -> Body<J> {
        Body::new(self.raw)
    }
}

impl<I: Serialize> Body<I> {
    /// A body from a typed request (in-process callers).
    pub fn typed(input: &I) -> Self {
        Self::from_value(serde_json::to_value(input).unwrap_or(Value::Null))
    }
}

impl<I: DeserializeOwned> Body<I> {
    /// The body read as its generated request type; INVALID_INPUT when it does not have that shape.
    pub fn decode(&self) -> IamResult<I> {
        serde_json::from_value(self.value())
            .map_err(|error| IamError::new("INVALID_INPUT", format!("Invalid input: {error}")))
    }
}

impl<I> Deref for Body<I> {
    type Target = Map<String, Value>;
    fn deref(&self) -> &Self::Target {
        &self.raw
    }
}

impl<I> Clone for Body<I> {
    fn clone(&self) -> Self {
        Self::new(self.raw.clone())
    }
}

impl<I> std::fmt::Debug for Body<I> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Body").field(&self.raw).finish()
    }
}

/// What a route method answers: its generated result type, or the JSON the TypeScript function returns, built in
/// the TypeScript member order (`Reply::json`). The HTTP layer serializes either with JavaScript number formatting.
#[derive(Debug, Clone)]
pub enum Reply<O> {
    Typed(O),
    Json(Value),
}

impl<O> Reply<O> {
    /// A result given as JSON.
    pub fn json(value: Value) -> Self {
        Self::Json(value)
    }
}

impl<O> From<O> for Reply<O> {
    fn from(value: O) -> Self {
        Self::Typed(value)
    }
}

impl<O: Serialize> Reply<O> {
    /// The result as JSON.
    pub fn into_value(self) -> IamResult<Value> {
        match self {
            Self::Json(value) => Ok(value),
            Self::Typed(value) => serde_json::to_value(value)
                .map_err(|_| IamError::with_status("INTERNAL_ERROR", "Internal server error", 500)),
        }
    }
}

impl<O: DeserializeOwned> Reply<O> {
    /// The result as its generated type (in-process callers).
    pub fn into_typed(self) -> IamResult<O> {
        match self {
            Self::Typed(value) => Ok(value),
            Self::Json(value) => serde_json::from_value(value)
                .map_err(|_| IamError::with_status("INTERNAL_ERROR", "Internal server error", 500)),
        }
    }
}
