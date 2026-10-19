//! Helpers of the Rust port that have no TypeScript counterpart (Rust-only module): the error every skeleton stub
//! returns, the JSON callback type the skeleton uses where TypeScript passes a function, and the details some
//! TypeScript errors carry beside code, message and status (`retryAfterMs`, `WRONG_REGION`'s region and location).

use std::sync::Arc;

use better_iam_core::{IamError, IamResult};
use futures::future::BoxFuture;
use serde_json::Value;

/// The error of a skeleton stub: `NOT_IMPLEMENTED` (501) naming the TypeScript module and member not ported yet.
pub fn not_ported(what: &str) -> IamError {
    IamError::not_implemented(format!("{what} is not implemented in the Rust server yet"))
}

/// A function argument of a skeleton signature (TypeScript passes a callback): JSON arguments in, a JSON result
/// out. A module that needs a typed callback replaces it when it is ported.
pub type Callback = Arc<dyn Fn(Vec<Value>) -> BoxFuture<'static, IamResult<Value>> + Send + Sync>;

/// The tagged encoding of `undefined` (FORMAT.md): what a `call` of a function that returns nothing answers with.
pub fn undefined() -> Value {
    serde_json::json!({ "$undefined": true })
}

/// A stored record as its type: STORAGE_CORRUPT (500) when it does not have the type's shape, as the record helpers of
/// the context and the auth crate report it.
pub fn decode<T: serde::de::DeserializeOwned>(record: better_iam_core::Record) -> IamResult<T> {
    serde_json::from_value(Value::Object(record)).map_err(|_| {
        IamError::with_status("STORAGE_CORRUPT", "Record does not match its type", 500)
    })
}

/// A typed record as the JSON object the store keeps.
pub fn encode<T: serde::Serialize>(value: &T) -> better_iam_core::Record {
    match serde_json::to_value(value) {
        Ok(Value::Object(map)) => map,
        _ => better_iam_core::Record::new(),
    }
}

/// What a TypeScript error carries beyond `IamError`'s code, message and status. The HTTP layer answers with these
/// members (`retryAfterMs` and the `Retry-After` header, `region` and `location` for `WRONG_REGION`). They travel on
/// the error itself ([`IamError::details`]).
pub type ErrorDetails = better_iam_core::IamErrorDetails;

/// Returns `error` carrying `details` for the HTTP answer.
pub fn with_details(error: IamError, details: ErrorDetails) -> IamError {
    error.with_details(details)
}

/// The details an error carries, if any.
pub fn details_of(error: &IamError) -> Option<ErrorDetails> {
    error.details.as_deref().cloned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn details_round_trip() {
        let error = IamError::with_status("QUOTA_EXCEEDED", "port test quota", 429);
        assert_eq!(details_of(&error), None);
        // Details live on the error: another error with the same code, message and status carries none.
        let twin = error.clone();
        let error = with_details(
            error,
            ErrorDetails {
                retry_after_ms: Some(1500.0),
                ..ErrorDetails::default()
            },
        );
        assert_eq!(details_of(&error).unwrap().retry_after_ms, Some(1500.0));
        assert_eq!(details_of(&twin), None);
        assert_eq!(error, twin);
        assert_eq!(not_ported("x.ts y").status, 501);
    }
}
