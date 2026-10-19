//! Delegation tokens (`delegation-tokens.ts`): short-lived signed JWTs with which an AI agent acting for a person
//! shows a service outside Better IAM that it does so. The subject is the person; the actor (`act`, RFC 8693 section
//! 4.1) is the agent acting now, with the agents that handed the work to it nested inside. This module only reads the
//! claims (no cryptography).

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use crate::js::{self, TypeError};

/// The JWT `typ` header of delegation tokens: verifiers refuse any other (`delegationTokenType`).
pub const DELEGATION_TOKEN_TYPE: &str = "biam-delegation+jwt";

/// Lifetimes (seconds) and the longest chain of actors a delegation token carries (`delegationTokenLimits`).
pub mod delegation_token_limits {
    pub const MIN_SECONDS: f64 = 30.0;
    pub const MAX_SECONDS: f64 = 3600.0;
    pub const DEFAULT_SECONDS: f64 = 300.0;
    /// The person's own delegate plus up to three hand-offs.
    pub const MAX_ACTORS: usize = 4;
}

/// An actor (RFC 8693 `act`) (`DelegationActor`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DelegationActor {
    pub sub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub act: Option<Box<DelegationActor>>,
}

/// A delegation token as a verifier reports it (`DelegationTokenSummary`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DelegationTokenSummary {
    pub issuer: String,
    pub person_id: String,
    pub tenant_id: String,
    pub delegation_id: String,
    pub agent_id: String,
    pub chain: Vec<String>,
    pub scopes: Vec<String>,
    pub audience: String,
    pub token_id: String,
    pub issued_at: f64,
    pub expires_at: f64,
    /// The claims object (`DelegationTokenClaims`).
    pub claims: Map<String, Value>,
}

/// Why claims were refused (`DelegationTokenRejection`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DelegationTokenRejection {
    Malformed,
    Issuer,
    Audience,
    Tenant,
    Expired,
    NotYetValid,
    Lifetime,
}

/// The outcome of [`read_delegation_token_claims`]: `{ token }` or `{ rejected, message }`.
#[derive(Debug, Clone, PartialEq)]
pub enum DelegationTokenRead {
    Token(Box<DelegationTokenSummary>),
    Rejected {
        rejected: DelegationTokenRejection,
        message: String,
    },
}

impl DelegationTokenRead {
    /// The TypeScript object form.
    pub fn to_value(&self) -> Value {
        let mut map = Map::new();
        match self {
            DelegationTokenRead::Token(token) => {
                map.insert(
                    "token".into(),
                    serde_json::to_value(token).unwrap_or(Value::Null),
                );
            }
            DelegationTokenRead::Rejected { rejected, message } => {
                map.insert(
                    "rejected".into(),
                    serde_json::to_value(rejected).unwrap_or(Value::Null),
                );
                map.insert("message".into(), Value::String(message.clone()));
            }
        }
        Value::Object(map)
    }
}

/// What the verifier expects (`DelegationTokenExpectations`).
#[derive(Debug, Clone, PartialEq, Default)]
pub struct DelegationTokenExpectations {
    /// The issuers to accept.
    pub issuer: Vec<String>,
    /// The audience the verifier answers to; the token's `aud` must be exactly this.
    pub audience: String,
    /// Accept only tokens of this organization.
    pub tenant_id: Option<String>,
    /// Epoch milliseconds.
    pub now: f64,
    /// Allowed clock difference in seconds (default 30).
    pub clock_tolerance_seconds: Option<f64>,
}

fn id(value: &str) -> bool {
    (1..=128).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

/// `delegationTokenScopePattern`: an action, or an action pattern whose only wildcard is `*`.
pub fn delegation_token_scope(value: &str) -> bool {
    let bytes = value.as_bytes();
    !bytes.is_empty()
        && bytes.len() <= 128
        && (bytes[0].is_ascii_alphanumeric() || bytes[0] == b'*')
        && bytes.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b':' | b'_' | b'*' | b'.' | b'/' | b'-')
        })
}

fn seconds(value: Option<&Value>) -> Option<f64> {
    value
        .and_then(js::as_number)
        .filter(|seconds| js::is_safe_integer(*seconds) && *seconds > 0.0)
}

fn malformed(message: &str) -> DelegationTokenRead {
    DelegationTokenRead::Rejected {
        rejected: DelegationTokenRejection::Malformed,
        message: message.to_owned(),
    }
}

/// Checks the claims of a (signature-verified) delegation token against what the verifier expects
/// (`readDelegationTokenClaims`). Returns a `TypeError` for a clock tolerance outside 0 to 300 seconds or a
/// non-finite clock.
pub fn read_delegation_token_claims(
    claims: &Value,
    expected: &DelegationTokenExpectations,
) -> Result<DelegationTokenRead, TypeError> {
    let Value::Object(value) = claims else {
        return Ok(malformed("The token has no claims object"));
    };
    let string = |field: &str| {
        value
            .get(field)
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
    };
    for field in ["iss", "sub", "aud", "jti", "tenant_id", "delegation_id"] {
        if string(field).is_none() {
            return Ok(malformed(&format!("The token has no {field}")));
        }
    }
    for field in ["sub", "tenant_id", "delegation_id"] {
        if !id(string(field).unwrap_or_default()) {
            return Ok(malformed(&format!("The token's {field} is invalid")));
        }
    }
    let (Some(iat), Some(nbf), Some(exp)) = (
        seconds(value.get("iat")),
        seconds(value.get("nbf")),
        seconds(value.get("exp")),
    ) else {
        return Ok(malformed("The token has no valid iat, nbf and exp"));
    };
    let mut actors: Vec<String> = Vec::new();
    let mut actor = value.get("act");
    while let Some(current) = actor {
        let Value::Object(current) = current else {
            return Ok(malformed("The token has an invalid act claim"));
        };
        let Some(sub) = current
            .get("sub")
            .and_then(Value::as_str)
            .filter(|sub| id(sub))
        else {
            return Ok(malformed("The token has an invalid act claim"));
        };
        actors.push(sub.to_owned());
        if actors.len() > delegation_token_limits::MAX_ACTORS {
            return Ok(malformed("The token names too many actors"));
        }
        actor = current.get("act");
    }
    if actors.is_empty() {
        return Ok(malformed("The token names no actor (act)"));
    }
    let person = string("sub").unwrap_or_default();
    let unique: std::collections::HashSet<&String> = actors.iter().collect();
    if unique.len() != actors.len() || actors.iter().any(|actor| actor == person) {
        return Ok(malformed("The token repeats an actor"));
    }
    let mut scopes: Vec<String> = Vec::new();
    if let Some(scope) = value.get("scope") {
        let Some(scope) = scope.as_str() else {
            return Ok(malformed("The token has an invalid scope"));
        };
        scopes = scope
            .split(' ')
            .filter(|item| !item.is_empty())
            .map(str::to_owned)
            .collect();
        if scopes.len() > 50 || scopes.iter().any(|scope| !delegation_token_scope(scope)) {
            return Ok(malformed("The token has an invalid scope"));
        }
    }
    let issuer = string("iss").unwrap_or_default();
    if !expected.issuer.iter().any(|accepted| accepted == issuer) {
        return Ok(DelegationTokenRead::Rejected {
            rejected: DelegationTokenRejection::Issuer,
            message: format!("The token was issued by {issuer}"),
        });
    }
    let audience = string("aud").unwrap_or_default();
    if audience != expected.audience {
        return Ok(DelegationTokenRead::Rejected {
            rejected: DelegationTokenRejection::Audience,
            message: "The token is for another audience".into(),
        });
    }
    let tenant = string("tenant_id").unwrap_or_default();
    if expected
        .tenant_id
        .as_deref()
        .is_some_and(|expected| expected != tenant)
    {
        return Ok(DelegationTokenRead::Rejected {
            rejected: DelegationTokenRejection::Tenant,
            message: "The token is from another organization".into(),
        });
    }
    if exp <= iat || nbf < iat || exp - iat > delegation_token_limits::MAX_SECONDS {
        return Ok(DelegationTokenRead::Rejected {
            rejected: DelegationTokenRejection::Lifetime,
            message: "The token lives longer than a delegation token may".into(),
        });
    }
    // A NaN or infinite tolerance (or clock) would make every time comparison below false and accept any token.
    let tolerance_seconds = expected.clock_tolerance_seconds.unwrap_or(30.0);
    if !tolerance_seconds.is_finite()
        || !(0.0..=300.0).contains(&tolerance_seconds)
        || !expected.now.is_finite()
    {
        return Err(TypeError(
            "clockToleranceSeconds must be 0 to 300 seconds and now a finite time".into(),
        ));
    }
    let tolerance = tolerance_seconds * 1000.0;
    if exp * 1000.0 <= expected.now - tolerance {
        return Ok(DelegationTokenRead::Rejected {
            rejected: DelegationTokenRejection::Expired,
            message: "The token has expired".into(),
        });
    }
    if nbf * 1000.0 > expected.now + tolerance || iat * 1000.0 > expected.now + tolerance {
        return Ok(DelegationTokenRead::Rejected {
            rejected: DelegationTokenRejection::NotYetValid,
            message: "The token is not valid yet".into(),
        });
    }
    let mut chain = actors.clone();
    chain.reverse();
    Ok(DelegationTokenRead::Token(Box::new(
        DelegationTokenSummary {
            issuer: issuer.to_owned(),
            person_id: person.to_owned(),
            tenant_id: tenant.to_owned(),
            delegation_id: string("delegation_id").unwrap_or_default().to_owned(),
            agent_id: actors[0].clone(),
            chain,
            scopes,
            audience: audience.to_owned(),
            token_id: string("jti").unwrap_or_default().to_owned(),
            issued_at: iat * 1000.0,
            expires_at: exp * 1000.0,
            claims: value.clone(),
        },
    )))
}

/// The `act` claim for a chain of agents, the person's own delegate first and the agent acting now last
/// (`delegationActor`).
pub fn delegation_actor(chain: &[String]) -> Result<DelegationActor, TypeError> {
    let mut actor: Option<DelegationActor> = None;
    for sub in chain {
        actor = Some(DelegationActor {
            sub: sub.clone(),
            act: actor.map(Box::new),
        });
    }
    actor.ok_or_else(|| TypeError("A delegation token needs at least one actor".into()))
}
