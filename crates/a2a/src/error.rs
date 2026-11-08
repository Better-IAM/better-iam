//! The errors of the package: the two refusal classes of the TypeScript package (`AgentCardError`,
//! `DelegationTokenError`), the JavaScript `TypeError` its functions throw for programming errors, the `IamError`s of
//! the IAM calls, and the plain errors of network calls and callbacks.

use std::sync::Arc;

use better_iam_core::IamError;
use better_iam_core::js::TypeError;

use crate::cards::AgentCardError;
use crate::delegation_tokens::DelegationTokenError;

/// Every error the package's functions return (what the TypeScript functions throw).
#[derive(Debug, Clone, thiserror::Error)]
pub enum A2aError {
    /// An agent card was refused (`AgentCardError`).
    #[error(transparent)]
    Card(#[from] AgentCardError),
    /// A delegation token was refused (`DelegationTokenError`).
    #[error(transparent)]
    DelegationToken(#[from] DelegationTokenError),
    /// A programming error (a JavaScript `TypeError`): missing options, invalid URLs, out-of-range settings.
    #[error(transparent)]
    Type(#[from] TypeError),
    /// An error of a Better IAM call.
    #[error(transparent)]
    Iam(#[from] IamError),
    /// Any other failure the TypeScript code meets as a plain `Error`: a network failure, a timeout, unparseable JSON.
    #[error("{0}")]
    Message(String),
    /// An error of a caller-supplied function (a signer, a token issuer, a replay check, a task owner store).
    #[error(transparent)]
    Other(Arc<dyn std::error::Error + Send + Sync>),
}

impl A2aError {
    /// A plain error with a message.
    pub fn message(message: impl Into<String>) -> Self {
        A2aError::Message(message.into())
    }

    /// Wraps any error of a caller-supplied function.
    pub fn other(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        A2aError::Other(Arc::new(error))
    }

    /// A `TypeError` with a message.
    pub(crate) fn type_error(message: impl Into<String>) -> Self {
        A2aError::Type(TypeError(message.into()))
    }

    /// The `IamError` this is, directly or wrapped in [`A2aError::Other`] (`error instanceof IamError`).
    pub fn iam(&self) -> Option<&IamError> {
        match self {
            A2aError::Iam(error) => Some(error),
            A2aError::Other(error) => error.downcast_ref::<IamError>(),
            _ => None,
        }
    }

    /// The `AgentCardError` this is (`error instanceof AgentCardError`).
    pub fn card(&self) -> Option<&AgentCardError> {
        match self {
            A2aError::Card(error) => Some(error),
            _ => None,
        }
    }

    /// The `DelegationTokenError` this is (`error instanceof DelegationTokenError`).
    pub fn delegation_token(&self) -> Option<&DelegationTokenError> {
        match self {
            A2aError::DelegationToken(error) => Some(error),
            _ => None,
        }
    }
}
