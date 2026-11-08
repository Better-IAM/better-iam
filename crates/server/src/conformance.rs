//! The standalone server (`better-iam-server`, spec/conformance/CONFIG.md) and, with `--conformance`, its
//! test-control endpoints (spec/conformance/CONTROL.md): ready, clock, outbox, events, script, reset, call, store and
//! shutdown. Rust-only module; the counterpart of `scripts/conformance/serve.mjs`.
//!
//! The control plane drives the instance only through [`BetterIam`] members, the runtimes' `call` methods and the
//! store contract, so filling a skeleton module in activates its members here without editing this file.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use better_iam_auth::{DeliveryError, DeliveryMessage};
use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, Direction, Filter, FindOptions, IamError, IamResult,
    IamStore, OrderOptions, js as core_js,
};
use bytes::Bytes;
use futures::future::BoxFuture;
use http::{HeaderMap, Method, StatusCode};
use http_body_util::{BodyExt, Full, LengthLimitError, Limited};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use serde_json::{Map, Value, json};
use tokio::sync::RwLock;

use crate::index::{BetterIam, better_iam};
use crate::options::{AuthorizationRequest, BatchAuthorizationRequest, ResourceTarget};
use crate::port::{details_of, undefined};
use crate::standalone_config::{CaptureFn, ConfigRuntime, ScriptedFactory, options_from_config};

// --- arguments and results ----------------------------------------------------------------------------------------

/// A credential argument as the replay runner sends it: `{"token": ...}`, `{"headers": {...}}` (or tagged
/// `{"$headers": {...}}`), possibly with other members (an authorization request carries its credential inline).
pub fn credential_arg(value: Option<&Value>) -> CredentialInput {
    crate::api::credential_from_json(value)
}

/// An `AuthenticatedPrincipal` as the TypeScript object encodes: `{ identity, session, deviceProof? }`.
pub fn principal_json(principal: &AuthenticatedPrincipal) -> Value {
    let mut out = Map::new();
    out.insert(
        "identity".into(),
        serde_json::to_value(&principal.identity).unwrap_or(Value::Null),
    );
    out.insert(
        "session".into(),
        serde_json::to_value(&principal.session).unwrap_or(Value::Null),
    );
    if let Some(proof) = &principal.device_proof {
        out.insert("deviceProof".into(), Value::String(proof.clone()));
    }
    Value::Object(out)
}

/// `errorShape(error)`: `{ code, status, message, retryAfterMs? }`.
pub fn error_shape(error: &IamError) -> Value {
    let mut shape = Map::new();
    shape.insert("code".into(), Value::String(error.code.clone()));
    shape.insert("status".into(), json!(error.status));
    // Anything that is not an IamError: "Internal server error", with the exception in `thrown`.
    if let Some(name) = crate::js::thrown_name(error) {
        shape.insert(
            "message".into(),
            Value::String(crate::js::internal_error().message),
        );
        shape.insert(
            "thrown".into(),
            json!({ "name": name, "message": error.message }),
        );
        return Value::Object(shape);
    }
    shape.insert("message".into(), Value::String(error.message.clone()));
    if let Some(retry) = details_of(error).and_then(|details| details.retry_after_ms)
        && retry > 0.0
    {
        shape.insert("retryAfterMs".into(), crate::js::number(retry));
    }
    if error.code == "INTERNAL_ERROR" && error.status == 500 {
        shape.insert(
            "thrown".into(),
            json!({ "name": "Error", "message": error.message }),
        );
    }
    Value::Object(shape)
}

/// What an in-process `iam.sessionTokens.verify` failure answers: TypeScript throws `SessionTokenError` (a plain
/// `Error` subclass, not an `IamError`) for every failure, so it is INTERNAL_ERROR 500 rather than the HTTP layer's
/// INVALID_SESSION_TOKEN 401.
fn session_token_thrown(error: IamError) -> IamError {
    crate::js::ThrownError::new("SessionTokenError", error.message).into_iam()
}

/// `decodeValue(value)`: the tagged encoding of FORMAT.md back to plain JSON (`$undefined` becomes absent where it is
/// an object member and null elsewhere; dates become their ISO text; numbers their value).
pub fn decode_value(value: &Value) -> Option<Value> {
    match value {
        Value::Array(items) => Some(Value::Array(
            items
                .iter()
                .map(|item| decode_value(item).unwrap_or(Value::Null))
                .collect(),
        )),
        Value::Object(map) => {
            if map.len() == 1 {
                let (key, inner) = map.iter().next().expect("one member");
                match key.as_str() {
                    "$undefined" => return None,
                    "$date" => return Some(inner.clone()),
                    "$number" => {
                        return Some(crate::js::number(core_js::string_to_number(
                            inner.as_str().unwrap_or(""),
                        )));
                    }
                    "$headers" | "$bigint" | "$bytes" | "$map" | "$set" => {
                        return Some(value.clone());
                    }
                    _ => {}
                }
            }
            let mut out = Map::new();
            for (key, item) in map {
                if let Some(decoded) = decode_value(item) {
                    out.insert(key.clone(), decoded);
                }
            }
            Some(Value::Object(out))
        }
        other => Some(other.clone()),
    }
}

/// `encodeValue(result)` of a plain JSON result (an absent result is `{"$undefined": true}`).
fn encode_result(value: Option<Value>) -> Value {
    value.unwrap_or_else(undefined)
}

fn arg(args: &[Value], index: usize) -> Option<&Value> {
    args.get(index).filter(|value| !value.is_null())
}

fn authorization_request(value: Option<&Value>) -> AuthorizationRequest {
    let empty = Value::Object(Map::new());
    let request = value.unwrap_or(&empty);
    let text = |value: Option<&Value>| value.and_then(Value::as_str).unwrap_or_default().to_owned();
    let resource = request.get("resource");
    AuthorizationRequest {
        credential: credential_arg(Some(request)),
        tenant_id: text(request.get("tenantId")),
        action: text(request.get("action")),
        resource: ResourceTarget {
            kind: text(resource.and_then(|resource| resource.get("type"))),
            id: text(resource.and_then(|resource| resource.get("id"))),
        },
    }
}

/// `POST /__conformance/call`: calls an instance member by its TypeScript path (`bootstrap`, `billing.closePeriod`,
/// `auth.settleBookkeeping`, `api.roles.create`). None for a path the Rust instance has no member for.
pub async fn call_member(
    iam: &BetterIam,
    path: &str,
    args: Vec<Value>,
) -> Option<IamResult<Value>> {
    let (head, rest) = match path.split_once('.') {
        Some((head, rest)) => (head, rest),
        None => (path, ""),
    };
    let first = arg(&args, 0).cloned();
    let first_ref = first.as_ref();
    if rest.is_empty() {
        let result = match head {
            "initialize" => iam.initialize().await.map(|()| undefined()),
            "bootstrap" => iam.bootstrap(first_ref.unwrap_or(&Value::Null)).await,
            "recoverRoot" => iam.recover_root(first_ref.unwrap_or(&Value::Null)).await,
            "purgeDeleted" => iam.purge_deleted(first_ref).await,
            "pruneAudit" => iam.prune_audit(first_ref.unwrap_or(&Value::Null)).await,
            "archiveAudit" => iam.archive_audit(first_ref).await,
            "sweepExpired" => iam.sweep_expired(first_ref).await,
            "selfCheck" => iam.self_check(first_ref).await,
            "sendAccessDigest" => iam.send_access_digest(first_ref).await,
            "sendExpiryReminders" => iam.send_expiry_reminders(first_ref).await,
            "reconcilePackages" => iam.reconcile_packages(first_ref).await,
            "closeOverdueCertifications" => iam.close_overdue_certifications(first_ref).await,
            "closeOverdueTeamReviews" => iam.close_overdue_team_reviews(first_ref).await,
            "checkInvariants" => iam.check_invariants(first_ref).await,
            "detectThreats" => iam.detect_threats(first_ref).await,
            "flushAccessUsage" => iam.flush_access_usage().await,
            "dispatchAuditHooks" => iam.dispatch_audit_hooks().await,
            "rotateSecrets" => {
                let options = first_ref.cloned().unwrap_or(json!({}));
                let parsed = crate::secrets::SecretRotationOptions {
                    dry_run: options.get("dryRun") == Some(&Value::Bool(true)),
                    batch_size: options.get("batchSize").and_then(Value::as_f64),
                    limit: options.get("limit").and_then(Value::as_f64),
                };
                iam.rotate_secrets(&parsed).await.and_then(|result| {
                    serde_json::to_value(result).map_err(|_| crate::js::internal_error())
                })
            }
            "assertionKey" => Ok(Value::String(iam.assertion_key())),
            "assertionKeys" => Ok(json!(iam.assertion_keys())),
            "authenticate" => iam
                .authenticate(&credential_arg(first_ref))
                .await
                .map(|principal| principal_json(&principal)),
            "require" => iam
                .require(&authorization_request(first_ref))
                .await
                .map(|()| undefined()),
            "authorize" => iam
                .authorize(&authorization_request(first_ref))
                .await
                .and_then(|decision| {
                    serde_json::to_value(decision).map_err(|_| crate::js::internal_error())
                }),
            "authorizeMany" => {
                let request = first_ref.cloned().unwrap_or(json!({}));
                match crate::operations::parse_checks(request.get("checks")) {
                    Ok(checks) => iam
                        .authorize_many(&BatchAuthorizationRequest {
                            credential: credential_arg(Some(&request)),
                            tenant_id: request
                                .get("tenantId")
                                .and_then(Value::as_str)
                                .unwrap_or_default()
                                .to_owned(),
                            checks,
                        })
                        .await
                        .map(|results| {
                            json!({ "results": results.into_iter().map(|result| json!({
                                "action": result.check.action,
                                "resource": { "type": result.check.resource.kind, "id": result.check.resource.id },
                                "allowed": result.allowed,
                                "reason": result.reason,
                            })).collect::<Vec<_>>() })
                        }),
                    Err(error) => Err(error),
                }
            }
            "callPlugin" => {
                let input = arg(&args, 1).cloned().unwrap_or(json!({}));
                iam.call_plugin(
                    &credential_arg(first_ref),
                    crate::contracts::PluginCall {
                        plugin_id: input.get("pluginId").cloned(),
                        path: input.get("path").cloned(),
                        tenant_id: input.get("tenantId").cloned(),
                        input: input.get("input").cloned(),
                    },
                )
                .await
            }
            "planResources" => return iam.plan_resources.call("", args).await,
            _ => return None,
        };
        return Some(result);
    }
    let rest = rest.to_owned();
    match head {
        "features" => iam.features.call(&rest, args).await,
        "inference" => iam.inference.call(&rest, args).await,
        "a2a" => iam.a2a.call(&rest, args).await,
        "billing" => iam.billing.call(&rest, args).await,
        "kms" => iam.kms.call(&rest, args).await,
        "pki" => iam.pki.call(&rest, args).await,
        "protection" => iam.protection.call(&rest, args).await,
        "vault" => iam.vault.call(&rest, args).await,
        "quotas" => iam.quotas.call(&rest, args).await,
        "privacy" => iam.privacy.call(&rest, args).await,
        "workflows" => iam.workflows.call(&rest, args).await,
        "compliance" => iam.compliance.call(&rest, args).await,
        "applications" => iam.applications.call(&rest, args).await,
        "ssh" => iam.ssh.call(&rest, args).await,
        "verifiableCredentials" => iam.verifiable_credentials.call(&rest, args).await,
        "ldap" => iam.ldap.call(&rest, args).await,
        "signals" => iam.signals.call(&rest, args).await,
        "licenses" => iam.licenses.call(&rest, args).await,
        "guests" => iam.guests.call(&rest, args).await,
        "clearances" => iam.clearances.call(&rest, args).await,
        "protocolHost" => {
            iam.federation
                .call(&format!("protocolHost.{rest}"), args)
                .await
        }
        "sessionTokens" => {
            let tokens = iam.session_tokens.as_ref()?;
            match rest.as_str() {
                "jwks" => Some(Ok(tokens.jwks())),
                "verify" => {
                    let token = first_ref
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned();
                    let audience = arg(&args, 1)
                        .and_then(|options| options.get("audience"))
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    // `iam.sessionTokens.verify` throws `SessionTokenError`, a plain `Error` subclass and not an
                    // `IamError`, so the conformance server answers every failure as INTERNAL_ERROR 500 (the HTTP
                    // layer's INVALID_SESSION_TOKEN 401 mapping does not apply to an in-process call).
                    Some(
                        tokens
                            .verify(&token, audience.as_deref())
                            .await
                            .map_err(session_token_thrown)
                            .and_then(|claims| {
                                serde_json::to_value(claims)
                                    .map_err(|_| crate::js::internal_error())
                            }),
                    )
                }
                _ => None,
            }
        }
        "hosts" => {
            let text = first_ref
                .and_then(Value::as_str)
                .unwrap_or_default()
                .to_owned();
            match rest.as_str() {
                "resolve" => Some(iam.hosts.resolve(&text).await.map(|found| match found {
                    Some(found) => serde_json::to_value(found).unwrap_or(Value::Null),
                    None => undefined(),
                })),
                "signInUrl" => Some(iam.hosts.sign_in_url(&text).await.map(|url| match url {
                    Some(url) => Value::String(url),
                    None => undefined(),
                })),
                "allowed" => Some(iam.hosts.allowed(&text).await.map(Value::Bool)),
                _ => None,
            }
        }
        "events" => match rest.as_str() {
            "dispatch" => Some(iam.dispatch_audit_hooks().await),
            _ => None,
        },
        "metrics" => {
            let metrics = iam.metrics.as_ref()?;
            match rest.as_str() {
                "render" => Some(Ok(Value::String(metrics.render()))),
                "snapshot" => Some(
                    serde_json::to_value(metrics.snapshot())
                        .map_err(|_| crate::js::internal_error()),
                ),
                "reset" => {
                    metrics.reset();
                    Some(Ok(undefined()))
                }
                _ => None,
            }
        }
        "auth" => auth_member(iam, &rest, &args, None).await,
        "api" => {
            let (group, method) = rest.split_once('.')?;
            // `api.auth.<method>`: the authentication API object (`createAuthApi`).
            if group == "auth" {
                if !iam.auth_api.has(method) {
                    return None;
                }
                return Some(iam.auth_api.call(method, auth_args(method, &args, 0)).await);
            }
            let route = format!("{group}/{method}");
            if !crate::api::dispatch::is_route(&route) {
                return None;
            }
            let public = crate::http::PUBLIC_API_METHODS.contains(&route.as_str());
            let (credential, input) = if public {
                (CredentialInput::default(), first_ref.cloned())
            } else {
                (credential_arg(first_ref), arg(&args, 1).cloned())
            };
            let body = match input {
                Some(Value::Object(map)) => map,
                _ => Map::new(),
            };
            crate::api::dispatch::dispatch(&iam.api, &route, body, &credential).await
        }
        _ => None,
    }
}

/// `auth.<method>`: the authentication service's helpers the tests call, with `tx` for calls made inside a store
/// transaction.
async fn auth_member(
    iam: &BetterIam,
    method: &str,
    args: &[Value],
    tx: Option<&Arc<dyn IamStore>>,
) -> Option<IamResult<Value>> {
    let auth = &iam.auth;
    let store = tx.cloned().unwrap_or_else(|| iam.store.clone());
    // In a transaction call the first argument is the transaction itself.
    let offset = usize::from(tx.is_some());
    let input = arg(args, offset).cloned();
    Some(match method {
        "settleBookkeeping" => {
            auth.settle_bookkeeping().await;
            Ok(undefined())
        }
        "dispatchOutbox" => auth
            .dispatch_outbox(input.as_ref().and_then(Value::as_f64))
            .await
            .map(|result| {
                json!({ "delivered": result.delivered, "failed": result.failed, "abandoned": result.abandoned })
            }),
        "createIdentity" => {
            let input = input.unwrap_or(json!({}));
            let flag = |key: &str| input.get(key) == Some(&Value::Bool(true));
            auth.create_identity_raw(
                &store,
                better_iam_auth::service::base::CreateIdentityRaw {
                    tenant_id: input.get("tenantId"),
                    email: input.get("email"),
                    name: input.get("name"),
                    password: input.get("password"),
                    owner: flag("owner"),
                    root_admin: flag("rootAdmin"),
                    email_verified: flag("emailVerified"),
                },
            )
            .await
            .and_then(|identity| serde_json::to_value(identity).map_err(|_| crate::js::internal_error()))
        }
        "limitAttempt" => {
            let text = |index: usize| {
                arg(args, index)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned()
            };
            let options = arg(args, 2).cloned().unwrap_or(json!({}));
            let tier = match options.get("tier").and_then(Value::as_str) {
                Some("sensitive") => Some(better_iam_auth::service::base::RateTier::Sensitive),
                Some(_) => Some(better_iam_auth::service::base::RateTier::Default),
                None => None,
            };
            auth.limit_attempt(
                &text(0),
                &text(1),
                better_iam_auth::service::base::LimitAttemptOptions {
                    tier,
                    limit: options.get("limit").and_then(Value::as_f64),
                    count_client: options.get("countClient").and_then(Value::as_bool),
                },
            )
            .await
            .map(|()| undefined())
        }
        "resetRateLimits" => {
            let identity = match input.map(serde_json::from_value) {
                Some(Ok(identity)) => identity,
                _ => return Some(Err(crate::js::internal_error())),
            };
            auth.reset_rate_limits(&identity)
                .await
                .and_then(|result| serde_json::to_value(result).map_err(|_| crate::js::internal_error()))
        }
        "issueSession" => {
            let identity = match input.map(serde_json::from_value) {
                Some(Ok(identity)) => identity,
                _ => return Some(Err(crate::js::internal_error())),
            };
            let options = arg(args, offset + 1).cloned().unwrap_or(json!({}));
            auth.issue_session(
                &store,
                &identity,
                better_iam_auth::service::base::IssueSessionOptions {
                    mfa: options.get("mfa").and_then(Value::as_bool),
                    authenticated_at: options.get("authenticatedAt").and_then(Value::as_f64),
                    method: options
                        .get("method")
                        .and_then(|method| serde_json::from_value(method.clone()).ok()),
                    trusted_device_id: options
                        .get("trustedDeviceId")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    mfa_authenticated_at: options.get("mfaAuthenticatedAt").and_then(Value::as_f64),
                },
            )
            .await
            .and_then(|result| serde_json::to_value(result).map_err(|_| crate::js::internal_error()))
        }
        "authenticate" => auth
            .authenticate(&credential_arg(input.as_ref()))
            .await
            .map(|principal| principal_json(&principal)),
        "requireRecent" => {
            let principal = match input.as_ref().map(crate::kms::principal_from_json) {
                Some(Ok(principal)) => principal,
                _ => return Some(Err(crate::js::internal_error())),
            };
            auth.require_recent(&principal).map(|()| undefined())
        }
        "verifyStepUpCode" => {
            let identity = match input.map(serde_json::from_value) {
                Some(Ok(identity)) => identity,
                _ => return Some(Err(crate::js::internal_error())),
            };
            let code = arg(args, offset + 1).and_then(Value::as_str).unwrap_or_default();
            auth.verify_step_up_code(&store, &identity, code)
                .await
                .and_then(|result| serde_json::to_value(result).map_err(|_| crate::js::internal_error()))
        }
        "issuePasswordReset" => {
            let identity = match input.map(serde_json::from_value) {
                Some(Ok(identity)) => identity,
                _ => return Some(Err(crate::js::internal_error())),
            };
            auth.issue_password_reset(&store, &identity).await.map(|()| undefined())
        }
        _ => {
            // The authentication API methods (`auth.signIn(body)`, `auth.getSession(credential)`).
            if !iam.auth_api.has(method) {
                return None;
            }
            iam.auth_api.call(method, auth_args(method, args, offset)).await
        }
    })
}

/// The in-process arguments of an authentication API method (`auth.signIn(body)`, `auth.getSession(credential)`,
/// `auth.beginMfa(credentialOrChallenge)`, `auth.confirmMfa({ credential, code, rememberDevice })`).
fn auth_args(method: &str, args: &[Value], offset: usize) -> crate::http::AuthArgs {
    use better_iam_auth::MfaCredential;
    let first = arg(args, offset).cloned().unwrap_or(json!({}));
    let mfa_credential = |value: &Value| match (value.get("tenantId"), value.get("challenge")) {
        (Some(Value::String(tenant_id)), Some(Value::String(challenge))) => {
            MfaCredential::Challenge {
                tenant_id: tenant_id.clone(),
                challenge: challenge.clone(),
            }
        }
        _ => MfaCredential::Credential(credential_arg(Some(value))),
    };
    match method {
        "beginMfa" => crate::http::AuthArgs::BeginMfa(mfa_credential(&first)),
        "confirmMfa" => {
            crate::http::AuthArgs::ConfirmMfa(better_iam_auth::service::mfa::ConfirmMfaInput {
                credential: mfa_credential(first.get("credential").unwrap_or(&Value::Null)),
                code: first
                    .get("code")
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_owned(),
                remember_device: first.get("rememberDevice") == Some(&Value::Bool(true)),
            })
        }
        _ if crate::http::PUBLIC_AUTH_METHODS.contains(&method) => {
            crate::http::AuthArgs::Public(first)
        }
        _ => crate::http::AuthArgs::Authenticated(
            credential_arg(Some(&first)),
            arg(args, offset + 1).cloned().unwrap_or(json!({})),
        ),
    }
}

// --- the store ----------------------------------------------------------------------------------------------------

fn invalid_control(message: impl Into<String>) -> IamError {
    IamError::with_status("INVALID_INPUT", message, 400)
}

fn filter_of(value: Option<&Value>) -> Filter {
    let mut filter = Filter::new();
    if let Some(Value::Object(map)) = value {
        for (key, item) in map {
            match item {
                Value::Object(inner) if inner.len() == 1 && inner.contains_key("$undefined") => {
                    filter = filter.absent(key.clone());
                }
                other => filter = filter.eq(key.clone(), other.clone()),
            }
        }
    }
    filter
}

fn find_options(value: Option<&Value>) -> FindOptions {
    let number = |key: &str| {
        value
            .and_then(|value| value.get(key))
            .and_then(Value::as_f64)
    };
    FindOptions {
        limit: number("limit").map(|limit| limit as i64),
        offset: number("offset").map(|offset| offset as i64),
        after: value
            .and_then(|value| value.get("after"))
            .and_then(Value::as_str)
            .map(str::to_owned),
    }
}

fn order_options(value: Option<&Value>) -> OrderOptions {
    let value = value.cloned().unwrap_or(json!({}));
    let number = |key: &str| value.get(key).and_then(Value::as_f64);
    OrderOptions {
        field: value
            .get("field")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        direction: if value.get("direction").and_then(Value::as_str) == Some("desc") {
            Direction::Desc
        } else {
            Direction::Asc
        },
        from: number("from"),
        to: number("to"),
        offset: number("offset").map(|offset| offset as i64),
        limit: number("limit").map(|limit| limit as i64),
    }
}

fn record_arg(value: Option<&Value>) -> Map<String, Value> {
    match value {
        Some(Value::Object(map)) => map.clone(),
        _ => Map::new(),
    }
}

/// One store operation (`get`, `find`, `findOrdered`, `insert`, `put`, `delete`, `collections`, `describe`).
async fn store_op(
    store: &Arc<dyn IamStore>,
    method: &str,
    args: &[Value],
) -> IamResult<Option<Value>> {
    let text = |index: usize| {
        args.get(index)
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    };
    match method {
        "get" => Ok(Some(
            store
                .get(&text(0), &text(1))
                .await?
                .map(Value::Object)
                .unwrap_or_else(undefined),
        )),
        "find" => Ok(Some(Value::Array(
            store
                .find(
                    &text(0),
                    &filter_of(args.get(1)),
                    &find_options(args.get(2)),
                )
                .await?
                .into_iter()
                .map(Value::Object)
                .collect(),
        ))),
        "findOrdered" => Ok(Some(Value::Array(
            better_iam_core::find_ordered(
                store.as_ref(),
                &text(0),
                &filter_of(args.get(1)),
                &order_options(args.get(2)),
                None,
            )
            .await?
            .into_iter()
            .map(Value::Object)
            .collect(),
        ))),
        "insert" => Ok(Some(Value::Object(
            store.insert(&text(0), &record_arg(args.get(1))).await?,
        ))),
        "put" => Ok(Some(Value::Object(
            store.put(&text(0), &record_arg(args.get(1))).await?,
        ))),
        "delete" => {
            store.delete(&text(0), &text(1)).await?;
            Ok(None)
        }
        "collections" => Ok(Some(json!(store.collections().await?))),
        "describe" => Ok(Some(
            serde_json::to_value(store.describe().await?)
                .map_err(|_| crate::js::internal_error())?,
        )),
        _ => Err(invalid_control(format!("Unknown store method {method}"))),
    }
}

/// `{"$result": [n, ...path]}` references to earlier operations of the same transaction, resolved.
fn with_results(value: &Value, earlier: &[Option<Value>]) -> IamResult<Value> {
    match value {
        Value::Array(items) => Ok(Value::Array(
            items
                .iter()
                .map(|item| with_results(item, earlier))
                .collect::<IamResult<_>>()?,
        )),
        Value::Object(map) => {
            if map.len() == 1
                && let Some(Value::Array(reference)) = map.get("$result")
            {
                let index = reference.first().and_then(Value::as_f64).unwrap_or(-1.0);
                if index < 0.0 || index.fract() != 0.0 || index as usize >= earlier.len() {
                    return Err(invalid_control(format!(
                        "$result names operation {}, which has not run",
                        reference
                            .first()
                            .map(core_js::stringify)
                            .unwrap_or_default()
                    )));
                }
                let mut node = earlier[index as usize].clone();
                for part in &reference[1..] {
                    node = match (node, part) {
                        (Some(Value::Object(map)), Value::String(key)) => map.get(key).cloned(),
                        (Some(Value::Array(items)), Value::Number(index)) => index
                            .as_u64()
                            .and_then(|index| items.get(index as usize).cloned()),
                        _ => None,
                    };
                }
                return Ok(node.unwrap_or(Value::Null));
            }
            Ok(Value::Object(
                map.iter()
                    .map(|(key, item)| Ok((key.clone(), with_results(item, earlier)?)))
                    .collect::<IamResult<_>>()?,
            ))
        }
        other => Ok(other.clone()),
    }
}

// --- the server state -----------------------------------------------------------------------------------------------

struct Clock {
    /// The injected clock's frozen value; None while it follows the wall clock.
    frozen: Option<f64>,
    /// The wall clock's offset from real time.
    wall_offset: f64,
    wall_set: bool,
}

#[derive(Debug, Clone)]
struct ScriptAnswer {
    raw: Map<String, Value>,
    used: bool,
}

struct Instance {
    iam: BetterIam,
    database: Arc<dyn IamStore>,
}

/// The conformance server's state.
pub struct Server {
    conformance: bool,
    config_text: Mutex<String>,
    instance: RwLock<Option<Arc<Instance>>>,
    clock: Arc<Mutex<Clock>>,
    outbox: Arc<Mutex<Vec<Value>>>,
    dispatching: Arc<Mutex<Option<Vec<Value>>>>,
    events: Arc<Mutex<Vec<Value>>>,
    script: Arc<Mutex<Vec<ScriptAnswer>>>,
    script_calls: Arc<Mutex<Vec<Value>>>,
    shutdown: tokio::sync::Notify,
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn real_now() -> f64 {
    // The real clock: the controlled wall clock is built on it, so reading `now_ms` here would recurse.
    core_js::system_now_ms()
}

fn canonical(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(canonical).collect()),
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            Value::Object(
                keys.into_iter()
                    .map(|key| (key.clone(), canonical(&map[key])))
                    .collect(),
            )
        }
        other => other.clone(),
    }
}

/// A value with epoch-millisecond numbers, ISO-8601 instants and password hashes blanked out (`timeless`).
fn timeless(value: &Value) -> Value {
    match value {
        Value::Array(items) => Value::Array(items.iter().map(timeless).collect()),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), timeless(item)))
                .collect(),
        ),
        Value::Number(number) => match number.as_f64() {
            Some(n) if (1e12..1e13).contains(&n) => json!(0),
            _ => value.clone(),
        },
        Value::String(text) => {
            let iso = text.len() >= 20
                && text.ends_with('Z')
                && text.as_bytes().get(4) == Some(&b'-')
                && text.as_bytes().get(10) == Some(&b'T')
                && chrono_like(text);
            if iso || text.starts_with("$argon2") {
                Value::String(String::new())
            } else {
                value.clone()
            }
        }
        other => other.clone(),
    }
}

/// `/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?Z$/`.
fn chrono_like(text: &str) -> bool {
    let bytes = text.as_bytes();
    let digits = |range: std::ops::Range<usize>| {
        bytes
            .get(range)
            .is_some_and(|part| part.iter().all(u8::is_ascii_digit))
    };
    if !(digits(0..4)
        && bytes.get(4) == Some(&b'-')
        && digits(5..7)
        && bytes.get(7) == Some(&b'-')
        && digits(8..10)
        && bytes.get(10) == Some(&b'T')
        && digits(11..13)
        && bytes.get(13) == Some(&b':')
        && digits(14..16)
        && bytes.get(16) == Some(&b':')
        && digits(17..19))
    {
        return false;
    }
    let rest = &text[19..text.len() - 1];
    rest.is_empty()
        || (rest.len() > 1
            && rest.starts_with('.')
            && rest[1..].bytes().all(|b| b.is_ascii_digit()))
}

impl Server {
    /// A server for the configuration text; `start` builds the instance.
    pub fn new(config_text: String, conformance: bool) -> Arc<Self> {
        Arc::new(Self {
            conformance,
            config_text: Mutex::new(config_text),
            instance: RwLock::new(None),
            clock: Arc::new(Mutex::new(Clock {
                frozen: None,
                wall_offset: 0.0,
                wall_set: false,
            })),
            outbox: Arc::default(),
            dispatching: Arc::default(),
            events: Arc::default(),
            script: Arc::default(),
            script_calls: Arc::default(),
            shutdown: tokio::sync::Notify::new(),
        })
    }

    fn wall_now(clock: &Mutex<Clock>) -> f64 {
        real_now() + lock(clock).wall_offset
    }

    fn now(clock: &Mutex<Clock>) -> f64 {
        let frozen = lock(clock).frozen;
        frozen.unwrap_or_else(|| Self::wall_now(clock))
    }

    fn set_wall(&self, value: f64) {
        let mut clock = lock(&self.clock);
        let offset = value - real_now();
        clock.wall_offset = if clock.wall_set {
            clock.wall_offset.max(offset)
        } else {
            offset
        };
        clock.wall_set = true;
    }

    fn runtime(&self) -> ConfigRuntime {
        if !self.conformance {
            return ConfigRuntime::default();
        }
        let clock = self.clock.clone();
        let now: better_iam_auth::NowFn = Arc::new(move || Self::now(&clock));
        let outbox = self.outbox.clone();
        let dispatching = self.dispatching.clone();
        let events = self.events.clone();
        let deliver: CaptureFn = Arc::new(move |kind: String, message: Value| {
            if kind == "events" {
                lock(&events).push(message);
            } else {
                let mut captured = Map::new();
                captured.insert("kind".into(), Value::String(kind));
                if let Value::Object(message) = message {
                    for (key, value) in message {
                        captured.insert(key, value);
                    }
                }
                let captured = Value::Object(captured);
                lock(&outbox).push(captured.clone());
                if let Some(dispatch) = lock(&dispatching).as_mut() {
                    dispatch.push(captured);
                }
            }
            Box::pin(async { Ok::<(), DeliveryError>(()) })
                as BoxFuture<'static, Result<(), DeliveryError>>
        });
        let script = self.script.clone();
        let calls = self.script_calls.clone();
        let scripted: ScriptedFactory = Arc::new(move |name: &str| {
            let name = name.to_owned();
            let script = script.clone();
            let calls = calls.clone();
            Arc::new(move |args: Vec<Value>| {
                let encoded = Value::Array(args);
                let answer = {
                    let mut script = lock(&script);
                    let same = |left: &Value, right: &Value| canonical(left) == canonical(right);
                    let matches = |item: &ScriptAnswer, test: &dyn Fn(&Value) -> bool| {
                        !item.used
                            && item.raw.get("callback").and_then(Value::as_str)
                                == Some(name.as_str())
                            && test(item.raw.get("args").unwrap_or(&Value::Null))
                    };
                    let index = script
                        .iter()
                        .position(|item| matches(item, &|args| same(args, &encoded)))
                        .or_else(|| {
                            script.iter().position(|item| {
                                matches(item, &|args| same(&timeless(args), &timeless(&encoded)))
                            })
                        })
                        .or_else(|| script.iter().position(|item| matches(item, &|_| true)));
                    lock(&calls).push(json!({
                        "callback": name,
                        "args": encoded,
                        "answer": index.and_then(|index| script[index].raw.get("id").cloned()).unwrap_or(Value::Null),
                    }));
                    index.map(|index| {
                        script[index].used = true;
                        script[index].raw.clone()
                    })
                };
                let name = name.clone();
                Box::pin(async move {
                    let Some(answer) = answer else {
                        return Err(crate::js::thrown_error(
                            "ConformanceScriptError",
                            format!("No scripted answer for {name}"),
                        ));
                    };
                    if let Some(error) = answer.get("error") {
                        if error.get("iam") == Some(&Value::Bool(true)) {
                            return Err(IamError::with_status(
                                error
                                    .get("code")
                                    .and_then(Value::as_str)
                                    .unwrap_or("INTERNAL_ERROR"),
                                error.get("message").and_then(Value::as_str).unwrap_or(""),
                                error.get("status").and_then(Value::as_u64).unwrap_or(500) as u16,
                            ));
                        }
                        // `{"name", "message"}`: a plain error carrying its message (serve.mjs `throwScripted`).
                        return Err(crate::js::thrown_error(
                            error.get("name").and_then(Value::as_str).unwrap_or("Error"),
                            error
                                .get("message")
                                .and_then(Value::as_str)
                                .unwrap_or("Scripted callback failed"),
                        ));
                    }
                    Ok(answer
                        .get("result")
                        .and_then(decode_value)
                        .unwrap_or(Value::Null))
                }) as BoxFuture<'static, IamResult<Value>>
            }) as crate::standalone_config::ScriptedFn
        });
        ConfigRuntime {
            now: Some(now),
            deliver: Some(deliver),
            scripted: Some(scripted),
            ..ConfigRuntime::default()
        }
    }

    /// Builds the instance from the configuration text (and runs `initialize()` unless told not to).
    pub async fn start(&self, initialize: bool) -> IamResult<()> {
        let text = lock(&self.config_text).clone();
        let config = crate::js::parse_json(&text)?;
        let options = options_from_config(&config, &self.runtime())?;
        let database = options
            .database
            .clone()
            .ok_or_else(crate::js::internal_error)?;
        let iam = better_iam(options)?;
        if initialize {
            iam.initialize().await?;
        }
        *self.instance.write().await = Some(Arc::new(Instance { iam, database }));
        Ok(())
    }

    async fn stop(&self) {
        let old = self.instance.write().await.take();
        if let Some(old) = old {
            let _ = old.iam.flush_access_usage().await;
            let _ = old.database.close().await;
        }
    }

    async fn instance(&self) -> IamResult<Arc<Instance>> {
        self.instance
            .read()
            .await
            .clone()
            .ok_or_else(crate::js::internal_error)
    }

    /// One control endpoint (`/__conformance/{path}`).
    async fn control(&self, path: &str, method: &Method, body: Option<Value>) -> IamResult<Value> {
        match path {
            "ready" => Ok(json!({ "ready": true, "implementation": "rust", "conformance": 1 })),
            "clock" => {
                if let Some(body) = &body {
                    for key in ["set", "advance", "wall"] {
                        if let Some(value) = body.get(key)
                            && !value.as_f64().is_some_and(f64::is_finite)
                        {
                            return Err(invalid_control(format!("{key} must be a number")));
                        }
                    }
                    if body.get("real") == Some(&Value::Bool(true)) {
                        let mut clock = lock(&self.clock);
                        clock.frozen = None;
                        clock.wall_offset = 0.0;
                        clock.wall_set = false;
                    }
                    let set = body.get("set").and_then(Value::as_f64);
                    let advance = body.get("advance").and_then(Value::as_f64);
                    if let Some(set) = set {
                        lock(&self.clock).frozen = Some(set);
                    } else if let Some(advance) = advance {
                        let current = Self::now(&self.clock);
                        lock(&self.clock).frozen = Some(current + advance);
                    }
                    // Without its own value the wall clock moves with the injected clock.
                    if let Some(wall) = body.get("wall").and_then(Value::as_f64) {
                        self.set_wall(wall);
                    } else if set.is_some() || advance.is_some() {
                        self.set_wall(Self::now(&self.clock));
                    }
                }
                Ok(json!({
                    "now": crate::js::number(Self::now(&self.clock)),
                    "wall": crate::js::number(Self::wall_now(&self.clock)),
                    "frozen": lock(&self.clock).frozen.is_some(),
                }))
            }
            "outbox" => Ok(json!({ "messages": lock(&self.outbox).clone() })),
            "script" => {
                let Some(body) = body.filter(|_| *method == Method::POST) else {
                    return Ok(json!({ "calls": lock(&self.script_calls).clone() }));
                };
                let Some(Value::Array(answers)) = body.get("answers") else {
                    return Err(invalid_control("answers must be an array"));
                };
                let answers: Vec<ScriptAnswer> = answers
                    .iter()
                    .map(|item| ScriptAnswer {
                        raw: item.as_object().cloned().unwrap_or_default(),
                        used: false,
                    })
                    .collect();
                let append = body.get("append") == Some(&Value::Bool(true));
                let mut script = lock(&self.script);
                if append {
                    script.retain(|item| !item.used);
                    script.extend(answers);
                } else {
                    *script = answers;
                    lock(&self.script_calls).clear();
                }
                Ok(json!({ "answers": script.len() }))
            }
            "events" => Ok(json!({ "events": lock(&self.events).clone() })),
            "events/clear" => {
                let cleared = std::mem::take(&mut *lock(&self.events)).len();
                Ok(json!({ "cleared": cleared }))
            }
            "outbox/clear" => {
                let cleared = std::mem::take(&mut *lock(&self.outbox)).len();
                Ok(json!({ "cleared": cleared }))
            }
            "outbox/dispatch" => {
                {
                    let mut dispatching = lock(&self.dispatching);
                    if dispatching.is_some() {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "A dispatch is already running",
                            409,
                        ));
                    }
                    *dispatching = Some(Vec::new());
                }
                let instance = self.instance().await;
                let limit = body
                    .as_ref()
                    .and_then(|body| body.get("limit"))
                    .and_then(Value::as_f64);
                let result = match instance {
                    Ok(instance) => instance.iam.auth.dispatch_outbox(limit).await,
                    Err(error) => Err(error),
                };
                let messages = lock(&self.dispatching).take().unwrap_or_default();
                Ok(match result {
                    Ok(result) => json!({
                        "result": { "delivered": result.delivered, "failed": result.failed, "abandoned": result.abandoned },
                        "messages": messages,
                    }),
                    Err(error) => json!({ "error": error_shape(&error), "messages": messages }),
                })
            }
            "reset" => {
                self.stop().await;
                lock(&self.outbox).clear();
                lock(&self.events).clear();
                lock(&self.script).clear();
                lock(&self.script_calls).clear();
                {
                    let mut clock = lock(&self.clock);
                    clock.frozen = None;
                    clock.wall_offset = 0.0;
                    clock.wall_set = false;
                }
                if let Some(config) = body.as_ref().and_then(|body| body.get("config")) {
                    *lock(&self.config_text) = core_js::stringify(config);
                }
                let initialize = body.as_ref().and_then(|body| body.get("initialize"))
                    != Some(&Value::Bool(false));
                self.start(initialize).await?;
                Ok(json!({ "reset": true }))
            }
            "call" => {
                let body = body.unwrap_or(Value::Null);
                let path = body.get("method").and_then(Value::as_str).unwrap_or("");
                if !valid_member_path(path) {
                    return Err(invalid_control("method must be a dotted member path"));
                }
                let args: Vec<Value> = match body.get("args") {
                    Some(Value::Array(items)) => items
                        .iter()
                        .map(|item| decode_value(item).unwrap_or(Value::Null))
                        .collect(),
                    _ => Vec::new(),
                };
                let instance = self.instance().await?;
                match Box::pin(call_member(&instance.iam, path, args)).await {
                    None => Err(IamError::with_status(
                        "NOT_FOUND",
                        format!("Unknown method {path}"),
                        404,
                    )),
                    Some(Ok(value)) => Ok(json!({ "data": encode_result(Some(value)) })),
                    Some(Err(error)) => Ok(json!({ "error": error_shape(&error) })),
                }
            }
            "store" => {
                let body = body.unwrap_or(Value::Null);
                let instance = self.instance().await?;
                if body.get("method").and_then(Value::as_str) == Some("transaction") {
                    return self.store_transaction(&instance, &body).await;
                }
                let method = body
                    .get("method")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_owned();
                let args: Vec<Value> = match body.get("args") {
                    Some(Value::Array(items)) => items
                        .iter()
                        .map(|item| decode_value(item).unwrap_or(Value::Null))
                        .collect(),
                    _ => Vec::new(),
                };
                if ![
                    "get",
                    "find",
                    "findOrdered",
                    "insert",
                    "put",
                    "delete",
                    "collections",
                    "describe",
                ]
                .contains(&method.as_str())
                {
                    return Err(invalid_control(format!("Unknown store method {method}")));
                }
                Ok(match store_op(&instance.database, &method, &args).await {
                    Ok(value) => json!({ "data": encode_result(value) }),
                    Err(error) => json!({ "error": error_shape(&error) }),
                })
            }
            "shutdown" => {
                self.shutdown.notify_waiters();
                self.shutdown.notify_one();
                Ok(json!({ "shutdown": true }))
            }
            _ => Err(IamError::with_status(
                "NOT_FOUND",
                "Unknown control endpoint",
                404,
            )),
        }
    }

    async fn store_transaction(&self, instance: &Arc<Instance>, body: &Value) -> IamResult<Value> {
        let ops: Vec<Value> = match body.get("ops") {
            Some(Value::Array(ops)) => ops.clone(),
            _ => Vec::new(),
        };
        let rollback = body.get("rollback") == Some(&Value::Bool(true));
        let results: Arc<Mutex<Vec<Value>>> = Arc::default();
        // Distinguishes the deliberate rollbacks from failures.
        let rollback_error = IamError::with_status("CONFORMANCE_ROLLBACK", "rollback", 500);
        let outcome = {
            let results = results.clone();
            let rollback_error = rollback_error.clone();
            let iam = &instance.iam;
            use better_iam_core::IamStoreExt;
            instance
                .database
                .transaction(|tx| async move {
                    let mut earlier: Vec<Option<Value>> = Vec::new();
                    for op in &ops {
                        let method = op
                            .get("method")
                            .and_then(Value::as_str)
                            .unwrap_or("")
                            .to_owned();
                        let raw_args = match op.get("args") {
                            Some(Value::Array(items)) => Value::Array(
                                items
                                    .iter()
                                    .map(|item| decode_value(item).unwrap_or(Value::Null))
                                    .collect(),
                            ),
                            _ => Value::Array(Vec::new()),
                        };
                        let args = match with_results(&raw_args, &earlier)? {
                            Value::Array(items) => items,
                            _ => Vec::new(),
                        };
                        let result = if method == "call" {
                            let path = op.get("path").and_then(Value::as_str).unwrap_or("");
                            call_in_transaction(iam, path, args, &tx).await
                        } else if [
                            "get",
                            "find",
                            "findOrdered",
                            "insert",
                            "put",
                            "delete",
                            "collections",
                            "describe",
                        ]
                        .contains(&method.as_str())
                        {
                            store_op(&tx, &method, &args).await
                        } else {
                            Err(invalid_control(format!("Unknown store method {method}")))
                        };
                        match result {
                            Ok(value) => {
                                lock(&results)
                                    .push(json!({ "data": encode_result(value.clone()) }));
                                earlier.push(value);
                            }
                            Err(error) => {
                                lock(&results).push(json!({ "error": error_shape(&error) }));
                                earlier.push(None);
                                if op.get("propagate") == Some(&Value::Bool(true)) {
                                    return Err(rollback_error.clone());
                                }
                            }
                        }
                    }
                    if rollback {
                        return Err(rollback_error.clone());
                    }
                    Ok(())
                })
                .await
        };
        let results = lock(&results).clone();
        Ok(match outcome {
            Ok(()) => json!({ "data": { "results": results, "rolledBack": false } }),
            Err(error) if error == rollback_error => {
                json!({ "data": { "results": results, "rolledBack": true } })
            }
            Err(error)
                if error.status == 400
                    && error.code == "INVALID_INPUT"
                    && error.message.starts_with("$result") =>
            {
                return Err(error);
            }
            Err(error) => {
                json!({ "error": error_shape(&error), "data": { "results": results, "rolledBack": true } })
            }
        })
    }

    /// Answers one HTTP request.
    pub async fn serve_request(
        self: &Arc<Self>,
        request: http::Request<Incoming>,
    ) -> http::Response<Full<Bytes>> {
        let path = request.uri().path().to_owned();
        if self.conformance
            && let Some(control) = path.strip_prefix("/__conformance/")
        {
            let control = control.to_owned();
            return self.serve_control(&control, request).await;
        }
        let instance = match self.instance().await {
            Ok(instance) => instance,
            Err(error) => return full(crate::http::error_response(&error)),
        };
        let (parts, body) = request.into_parts();
        let http = &instance.iam.http;
        if matches!(parts.method.as_str(), "TRACE" | "CONNECT" | "TRACK") {
            return full(
                http.node_handler(parts.method, "/", parts.headers, Bytes::new())
                    .await,
            );
        }
        let target = parts
            .uri
            .path_and_query()
            .map(|p| p.as_str().to_owned())
            .unwrap_or_else(|| "/".into());
        let url = match http.node_url(&target, &parts.headers) {
            Ok(url) => url,
            Err(_) => {
                return full(
                    http.node_handler(parts.method, &target, parts.headers, Bytes::new())
                        .await,
                );
            }
        };
        let limit = http.body_limit(&url);
        let bytes = match Limited::new(body, limit).collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(error) => {
                let mut response =
                    http::Response::new(Full::new(Bytes::from_static(b"Request too large")));
                if error.downcast_ref::<LengthLimitError>().is_some() {
                    *response.status_mut() = StatusCode::PAYLOAD_TOO_LARGE;
                } else {
                    *response.status_mut() = StatusCode::BAD_REQUEST;
                    *response.body_mut() = Full::new(Bytes::from_static(b"Bad request"));
                }
                return response;
            }
        };
        full(
            http.node_handler(parts.method, url.as_str(), parts.headers, bytes)
                .await,
        )
    }

    async fn serve_control(
        self: &Arc<Self>,
        path: &str,
        request: http::Request<Incoming>,
    ) -> http::Response<Full<Bytes>> {
        let method = request.method().clone();
        let body = if method == Method::POST {
            match request.into_body().collect().await {
                Ok(collected) => {
                    let bytes = collected.to_bytes();
                    let text = String::from_utf8_lossy(&bytes).into_owned();
                    if text.is_empty() {
                        None
                    } else {
                        match core_js::parse(&text) {
                            Ok(value) => Some(value),
                            Err(_) => {
                                return control_json(
                                    400,
                                    &json!({ "error": error_shape(&crate::js::internal_error()) }),
                                );
                            }
                        }
                    }
                }
                Err(_) => None,
            }
        } else {
            None
        };
        if method != Method::POST && method != Method::GET {
            return control_json(
                405,
                &json!({ "error": error_shape(&IamError::with_status("METHOD_NOT_ALLOWED", "Use GET or POST", 405)) }),
            );
        }
        match Box::pin(self.control(path, &method, body)).await {
            Ok(value) => control_json(200, &value),
            Err(error) => control_json(error.status, &json!({ "error": error_shape(&error) })),
        }
    }

    /// Resolves when a `shutdown` control request arrived.
    pub async fn shutdown_requested(&self) {
        self.shutdown.notified().await;
    }

    /// Closes the instance and its database.
    pub async fn close(&self) {
        self.stop().await;
    }
}

/// A transaction `call` operation: `{"$tx": true}` arguments stand for the transaction itself (only `auth.<method>`
/// library calls take one).
async fn call_in_transaction(
    iam: &BetterIam,
    path: &str,
    args: Vec<Value>,
    tx: &Arc<dyn IamStore>,
) -> IamResult<Option<Value>> {
    if !valid_member_path(path) {
        return Err(invalid_control("method must be a dotted member path"));
    }
    let takes_tx = args
        .first()
        .is_some_and(|first| first == &json!({ "$tx": true }));
    let result = match path.strip_prefix("auth.") {
        Some(method) if takes_tx => Box::pin(auth_member(iam, method, &args, Some(tx))).await,
        _ => Box::pin(call_member(iam, path, args)).await,
    };
    match result {
        Some(result) => result.map(Some),
        None => Err(IamError::with_status(
            "NOT_FOUND",
            format!("Unknown method {path}"),
            404,
        )),
    }
}

/// `/^[A-Za-z][\w]*(\.[A-Za-z][\w]*){0,3}$/` without `__proto__`, `prototype` and `constructor`.
fn valid_member_path(path: &str) -> bool {
    let parts: Vec<&str> = path.split('.').collect();
    !path.is_empty()
        && parts.len() <= 4
        && parts.iter().all(|part| {
            part.chars().next().is_some_and(|c| c.is_ascii_alphabetic())
                && part.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
                && !["__proto__", "prototype", "constructor"].contains(part)
        })
}

fn control_json(status: u16, value: &Value) -> http::Response<Full<Bytes>> {
    let mut response = http::Response::new(Full::new(Bytes::from(core_js::stringify(value))));
    *response.status_mut() = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    response.headers_mut().insert(
        "content-type",
        http::HeaderValue::from_static("application/json"),
    );
    response
        .headers_mut()
        .insert("cache-control", http::HeaderValue::from_static("no-store"));
    response
}

fn full(response: crate::options::HttpResponse) -> http::Response<Full<Bytes>> {
    response.map(Full::new)
}

// --- the standalone server ------------------------------------------------------------------------------------------

/// The command line of `better-iam-server`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    pub config: PathBuf,
    pub port: u16,
    pub host: String,
    pub conformance: bool,
}

/// The usage line.
pub const USAGE: &str = "Usage: better-iam-server --config <better-iam.json> --port <port> [--host 127.0.0.1] [--conformance]";

/// Parses `--config`, `--port`, `--host` and `--conformance`; Err(message) for bad arguments, Ok(None) for `--help`.
pub fn parse_args(argv: &[String]) -> Result<Option<Args>, String> {
    let mut config = None;
    let mut port = None;
    let mut host = "127.0.0.1".to_owned();
    let mut conformance = false;
    let mut index = 0;
    while index < argv.len() {
        let arg = &argv[index];
        let mut value = || {
            index += 1;
            argv.get(index)
                .cloned()
                .ok_or_else(|| format!("{arg} needs a value"))
        };
        match arg.as_str() {
            "--config" => config = Some(PathBuf::from(value()?)),
            "--port" => {
                let text = value()?;
                port = Some(text.parse::<u16>().map_err(|_| USAGE.to_owned())?);
            }
            "--host" => host = value()?,
            "--conformance" => conformance = true,
            "--help" | "-h" => return Ok(None),
            other => return Err(format!("Unknown argument {other}")),
        }
        index += 1;
    }
    match (config, port) {
        (Some(config), Some(port)) => Ok(Some(Args {
            config,
            port,
            host,
            conformance,
        })),
        _ => Err(USAGE.to_owned()),
    }
}

/// Runs the standalone server until a signal or a `shutdown` control request. A configuration the server refuses
/// ends the process with status 1 and one JSON line on stderr (`{"error": {code, status, message}}`).
pub async fn run(args: Args) -> std::io::Result<()> {
    let text = match std::fs::read_to_string(&args.config) {
        Ok(text) => text,
        Err(_) => {
            eprintln!(
                "{}",
                core_js::stringify(&json!({ "error": error_shape(&crate::js::internal_error()) }))
            );
            std::process::exit(1);
        }
    };
    let server = Server::new(text, args.conformance);
    if args.conformance {
        let clock = server.clock.clone();
        crate::utils::set_wall_clock(Some(Arc::new(move || Server::wall_now(&clock))));
    }
    if let Err(error) = server.start(true).await {
        eprintln!(
            "{}",
            core_js::stringify(&json!({ "error": error_shape(&error) }))
        );
        std::process::exit(1);
    }
    let address: SocketAddr = format!("{}:{}", args.host, args.port)
        .parse()
        .or_else(|_| {
            use std::net::ToSocketAddrs;
            format!("{}:{}", args.host, args.port)
                .to_socket_addrs()
                .ok()
                .and_then(|mut addresses| addresses.next())
                .ok_or(())
        })
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid --host"))?;
    let listener = tokio::net::TcpListener::bind(address).await?;
    let bound = listener.local_addr()?;
    println!(
        "better-iam (rust) listening on http://{}:{}{}",
        args.host,
        bound.port(),
        if args.conformance {
            " (conformance mode)"
        } else {
            ""
        }
    );
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { continue };
                let server = server.clone();
                tokio::spawn(async move {
                    let service = hyper::service::service_fn(move |request| {
                        let server = server.clone();
                        async move { Ok::<_, std::convert::Infallible>(Box::pin(server.serve_request(request)).await) }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), service)
                        .await;
                });
            }
            () = server.shutdown_requested() => break,
            _ = tokio::signal::ctrl_c() => break,
        }
    }
    server.close().await;
    Ok(())
}

/// The environment `{"env": "NAME"}` values of a configuration read (this process's).
pub fn process_env() -> HashMap<String, String> {
    std::env::vars().collect()
}

/// Header pairs of a header map (for credentials built outside the HTTP layer).
pub fn header_pairs(headers: &HeaderMap) -> Vec<(String, String)> {
    headers
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                String::from_utf8_lossy(value.as_bytes()).into_owned(),
            )
        })
        .collect()
}

/// `DeliveryMessage` as the capture transport records it.
pub fn delivery_json(message: &DeliveryMessage) -> Value {
    serde_json::to_value(message).unwrap_or(Value::Null)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn member_paths() {
        assert!(valid_member_path("bootstrap"));
        assert!(valid_member_path("api.roles.create"));
        assert!(!valid_member_path("a.b.c.d.e"));
        assert!(!valid_member_path("constructor"));
        assert!(!valid_member_path("1abc"));
        assert!(!valid_member_path(""));
    }

    #[test]
    fn arguments() {
        assert_eq!(
            parse_args(&[
                "--config".into(),
                "x.json".into(),
                "--port".into(),
                "4100".into()
            ])
            .unwrap(),
            Some(Args {
                config: "x.json".into(),
                port: 4100,
                host: "127.0.0.1".into(),
                conformance: false
            })
        );
        assert!(parse_args(&["--port".into(), "1".into()]).is_err());
        assert_eq!(parse_args(&["--help".into()]).unwrap(), None);
    }

    #[test]
    fn session_token_verify_failures_are_thrown() {
        let error = session_token_thrown(IamError::from(
            crate::session_tokens::SessionTokenError::new("revoked", None),
        ));
        let shape = error_shape(&error);
        assert_eq!(shape["code"], json!("INTERNAL_ERROR"));
        assert_eq!(shape["status"], json!(500));
        assert_eq!(shape["message"], json!("Internal server error"));
    }

    #[test]
    fn timeless_values() {
        assert_eq!(timeless(&json!(1_700_000_000_000.0_f64)), json!(0));
        assert_eq!(timeless(&json!("2024-01-01T00:00:00.000Z")), json!(""));
        assert_eq!(timeless(&json!("$argon2id$v=19")), json!(""));
        assert_eq!(timeless(&json!("plain")), json!("plain"));
    }

    #[test]
    fn decoding() {
        assert_eq!(
            decode_value(&json!({ "a": { "$undefined": true }, "b": 1 })),
            Some(json!({ "b": 1 }))
        );
        assert_eq!(decode_value(&json!({ "$undefined": true })), None);
        let credential =
            credential_arg(Some(&json!({ "headers": { "authorization": "Bearer x" } })));
        assert_eq!(credential.headers.unwrap()[0].1, "Bearer x");
    }

    /// `auth.authenticate`, `auth.requireRecent`, and inside a store transaction `auth.verifyStepUpCode` and
    /// `auth.issuePasswordReset`, resolve to the authentication service instead of answering `Unknown method`.
    #[test]
    fn auth_service_members() {
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap()
                    .block_on(auth_service_members_body());
            })
            .unwrap()
            .join()
            .unwrap();
    }

    async fn auth_service_members_body() {
        use better_iam_core::IamStoreExt;
        let store = better_iam_adapter_sqlite::sqlite_adapter(
            better_iam_adapter_sqlite::SqliteAdapterOptions::new(":memory:"),
        )
        .expect("sqlite");
        let inbox: Arc<Mutex<Vec<DeliveryMessage>>> = Arc::default();
        let sink = inbox.clone();
        let mut options = crate::options::BetterIamOptions::new(
            store,
            "conformance-auth-test-secret-with-32-chars!!",
            "https://iam.example.com",
        );
        options.authentication = Some(crate::options::ServerAuthOptions {
            send_email: Some(better_iam_auth::delivery_fn(move |message| {
                let sink = sink.clone();
                async move {
                    sink.lock().unwrap().push(message);
                    Ok(())
                }
            })),
            ..Default::default()
        });
        let iam = better_iam(options).expect("valid options");
        iam.initialize().await.expect("initialize");
        let root = iam
            .bootstrap(&json!({ "email": "root@example.test", "name": "Root", "password": "a strong root test password" }))
            .await
            .expect("bootstrap");
        let identity = root["identity"].clone();
        let failure = |result: Option<IamResult<Value>>| {
            let error = result.expect("a known member").expect_err("an error");
            (error.code, error.status)
        };

        let tx_args = |rest: Vec<Value>| {
            let mut args = vec![json!({ "$tx": true })];
            args.extend(rest);
            args
        };
        let issued = {
            let (iam, args) = (
                &iam,
                tx_args(vec![identity.clone(), json!({ "mfa": true })]),
            );
            iam.store
                .transaction(|tx| async move {
                    auth_member(iam, "issueSession", &args, Some(&tx))
                        .await
                        .expect("a known member")
                })
                .await
                .expect("issueSession")
        };

        // authenticate({ token }): { identity, session }.
        let principal = auth_member(
            &iam,
            "authenticate",
            &[json!({ "token": issued["token"] })],
            None,
        )
        .await
        .expect("a known member")
        .expect("authenticate");
        assert_eq!(principal["identity"]["id"], identity["id"]);
        assert_eq!(principal["session"]["id"], issued["session"]["id"]);
        assert_eq!(
            failure(
                auth_member(
                    &iam,
                    "authenticate",
                    &[json!({ "token": "biam_ses_nope" })],
                    None
                )
                .await
            ),
            ("UNAUTHENTICATED".to_owned(), 401)
        );

        // requireRecent(principal): undefined for a fresh user session, RECENT_AUTH_REQUIRED for a temporary one.
        assert_eq!(
            auth_member(
                &iam,
                "requireRecent",
                std::slice::from_ref(&principal),
                None
            )
            .await
            .expect("a known member")
            .expect("fresh"),
            undefined()
        );
        let mut temporary = principal.clone();
        temporary["session"]["kind"] = json!("session-token");
        assert_eq!(
            failure(auth_member(&iam, "requireRecent", &[temporary], None).await),
            ("RECENT_AUTH_REQUIRED".to_owned(), 403)
        );

        // verifyStepUpCode({ $tx }, identity, code) without an enrolled authenticator.
        let not_enrolled = {
            let (iam, args) = (&iam, tx_args(vec![identity.clone(), json!("123456")]));
            iam.store
                .transaction(|tx| async move {
                    Ok(auth_member(iam, "verifyStepUpCode", &args, Some(&tx)).await)
                })
                .await
                .expect("transaction")
        };
        assert_eq!(failure(not_enrolled), ("MFA_NOT_ENROLLED".to_owned(), 403));

        // issuePasswordReset({ $tx }, identity): undefined, and a password-reset email goes out.
        let reset = {
            let (iam, args) = (&iam, tx_args(vec![identity.clone()]));
            iam.store
                .transaction(|tx| async move {
                    auth_member(iam, "issuePasswordReset", &args, Some(&tx))
                        .await
                        .expect("a known member")
                })
                .await
                .expect("issuePasswordReset")
        };
        assert_eq!(reset, undefined());
        auth_member(&iam, "dispatchOutbox", &[], None)
            .await
            .expect("a known member")
            .expect("dispatchOutbox");
        let sent = inbox.lock().unwrap().clone();
        assert!(
            sent.iter()
                .any(|message| message.template == "password-reset"
                    && message.to == "root@example.test"),
            "a password-reset email was delivered: {sent:?}"
        );
    }
}
