//! Port of `packages/server/src/guarded.ts`: the authorization envelope for resources the platform itself owns and
//! describes with attributes (KMS keys, certificate authorities).
//!
//! It is the `operation` envelope of operations.ts, except that the decision sees the resource's attributes
//! (`resource.{name}`), a module may add a fallback allow path (KMS grants), and one call may need several decisions
//! (every name on a certificate). Sessions that view as someone else are refused outright.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use better_iam_core::boxed;
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Decision, IamError, IamResult,
    IamStoreExt, OperationHookInput, Tenant,
};
use futures::future::BoxFuture;
use indexmap::IndexMap;
use serde::Serialize;
use serde_json::{Map, Value};

use crate::context::{ServerContext, Store};
use crate::contracts::{OperationResult, PreparedDecision, decide_on, is_root_override};
use crate::delegations::use_confirmation;
use crate::observe::SpanKind;
use crate::options::ResolvedResource;

/// `GuardTarget`: the audited resource (without the `iam/` prefix) and the attributes policies see.
pub trait GuardTarget: Send + Sync {
    /// `kms/{keyId}`, `pki/{authorityId}`.
    fn resource_id(&self) -> &str;
    /// Presented to policies as `resource.{name}`.
    fn attributes(&self) -> &Map<String, Value>;
}

/// A plain [`GuardTarget`].
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Target {
    pub resource_id: String,
    pub attributes: Map<String, Value>,
}

impl GuardTarget for Target {
    fn resource_id(&self) -> &str {
        &self.resource_id
    }
    fn attributes(&self) -> &Map<String, Value> {
        &self.attributes
    }
}

/// `fallback(tx, principal, action, target)`: audit metadata naming what allowed a call no policy decides, or None.
pub type FallbackFn<T> = Arc<
    dyn Fn(
            Store,
            AuthenticatedPrincipal,
            String,
            T,
        ) -> BoxFuture<'static, IamResult<Option<Map<String, Value>>>>
        + Send
        + Sync,
>;

/// `describe(target)`: audit metadata every allowed call of a target starts with.
pub type DescribeFn<T> = Arc<dyn Fn(&T) -> Map<String, Value> + Send + Sync>;
/// `hookResult(value)`: what plugin `afterOperation` hooks see of a result.
pub type HookResultFn = Arc<dyn Fn(&Value) -> Value + Send + Sync>;

/// `GuardOptions`.
pub struct GuardOptions<T> {
    /// A second way to allow a call, consulted only when the policy decision's reason is `NO_APPLICABLE_GRANT`.
    pub fallback: Option<FallbackFn<T>>,
    /// Audit metadata every allowed call of a target starts with.
    pub describe: Option<DescribeFn<T>>,
    /// Error codes thrown after authorization that are recorded as a denied call (with `reason`).
    pub recorded_failures: IndexMap<String, String>,
    /// What plugin `afterOperation` hooks see of a result (strip plaintexts and tokens).
    pub hook_result: Option<HookResultFn>,
}

impl<T> Default for GuardOptions<T> {
    fn default() -> Self {
        Self {
            fallback: None,
            describe: None,
            recorded_failures: IndexMap::new(),
            hook_result: None,
        }
    }
}

/// A decision, with the fallback's audit note when the fallback allowed it.
#[derive(Debug, Clone, PartialEq)]
pub struct GuardDecision {
    pub decision: Decision,
    pub note: Option<Map<String, Value>>,
}

/// Prepared decisions by action, reused across the several decisions of one call.
type PreparedCache = Arc<Mutex<HashMap<String, PreparedDecision>>>;

/// `GuardCall`: what the guarded function receives.
pub struct GuardCall<T> {
    pub tx: Store,
    pub principal: AuthenticatedPrincipal,
    pub tenant: Tenant,
    /// Added to the call's audit event (the function may add members).
    pub metadata: Arc<Mutex<Map<String, Value>>>,
    guard: Guard<T>,
    prepared: PreparedCache,
}

impl<T: Clone + GuardTarget + 'static> GuardCall<T> {
    /// `allowed(action, target)`: evaluates another action or target for the caller by policy alone (no fallback).
    pub async fn allowed(&self, action: &str, target: &dyn GuardTarget) -> IamResult<bool> {
        Ok(self
            .guard
            .decide_on_target(
                &self.tx,
                &self.principal,
                &self.tenant,
                action,
                target,
                None,
                Some(&self.prepared),
            )
            .await?
            .decision
            .allowed)
    }

    /// Adds a member to the call's audit metadata.
    pub fn note(&self, key: &str, value: Value) {
        self.metadata
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key.to_owned(), value);
    }
}

/// The action of a guarded call: fixed, or derived from the located target (`label` is then `iam:call`).
pub enum GuardAction<T> {
    Fixed(String),
    Of(Arc<dyn Fn(&T) -> String + Send + Sync>),
}

/// `createGuard(ctx, collection, options)`.
pub struct Guard<T> {
    ctx: Arc<ServerContext>,
    /// The tenant-wide resource (`kms`, `pki`): where refusals before any lookup are recorded.
    collection: String,
    options: Arc<GuardOptions<T>>,
}

impl<T> Clone for Guard<T> {
    fn clone(&self) -> Self {
        Self {
            ctx: self.ctx.clone(),
            collection: self.collection.clone(),
            options: self.options.clone(),
        }
    }
}

/// `createGuard(ctx, collection, options = {})`.
pub fn create_guard<T>(
    ctx: Arc<ServerContext>,
    collection: &str,
    options: GuardOptions<T>,
) -> Guard<T> {
    Guard {
        ctx,
        collection: collection.to_owned(),
        options: Arc::new(options),
    }
}

/// The outcome of the guarded transaction.
enum Outcome<R> {
    Denied,
    Allowed { value: R, root_override: bool },
}

/// What the envelope learns inside the transaction, for the bookkeeping after it.
#[derive(Default)]
struct RunState {
    /// The mutation failed with `OperationDenied`.
    denied: bool,
    actor: Option<AuthenticatedPrincipal>,
    resolved_action: String,
    resource_id: String,
}

fn lock<V>(mutex: &Mutex<V>) -> std::sync::MutexGuard<'_, V> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn reason_metadata(reason: &str) -> Map<String, Value> {
    let mut map = Map::new();
    map.insert("reason".into(), Value::String(reason.to_owned()));
    map
}

impl<T: Clone + GuardTarget + 'static> Guard<T> {
    /// `decide(tx, principal, tenant, action, target, useFallback = true, cache?)` for a located target.
    pub async fn decide(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant: &Tenant,
        action: &str,
        target: &T,
        use_fallback: bool,
    ) -> IamResult<GuardDecision> {
        self.decide_on_target(
            tx,
            principal,
            tenant,
            action,
            target,
            use_fallback.then_some(target),
            None,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn decide_on_target(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant: &Tenant,
        action: &str,
        target: &dyn GuardTarget,
        fallback_target: Option<&T>,
        cache: Option<&PreparedCache>,
    ) -> IamResult<GuardDecision> {
        if principal.session.impersonator_id.is_some() {
            return Ok(GuardDecision {
                decision: Decision {
                    allowed: false,
                    reason: "IMPERSONATION_RESTRICTED".into(),
                    matched: Vec::new(),
                },
                note: None,
            });
        }
        let cached = cache.and_then(|cache| lock(cache).get(action).cloned());
        let prepared = match cached {
            Some(prepared) => prepared,
            None => {
                let prepared = self
                    .ctx
                    .decisions()?
                    .prepare_decision(tx, principal, tenant, action)
                    .await?;
                if let Some(cache) = cache {
                    lock(cache).insert(action.to_owned(), prepared.clone());
                }
                prepared
            }
        };
        let resource = ResolvedResource {
            tenant_id: tenant.id.clone(),
            kind: "iam".into(),
            id: target.resource_id().to_owned(),
            attributes: Some(target.attributes().clone()),
            classification: None,
        };
        let decision = decide_on(&prepared, &resource, Some(action))?;
        let (Some(fallback), Some(fallback_target)) = (&self.options.fallback, fallback_target)
        else {
            return Ok(GuardDecision {
                decision,
                note: None,
            });
        };
        if decision.allowed || decision.reason != "NO_APPLICABLE_GRANT" {
            return Ok(GuardDecision {
                decision,
                note: None,
            });
        }
        let note = fallback(
            tx.clone(),
            principal.clone(),
            action.to_owned(),
            fallback_target.clone(),
        )
        .await?;
        Ok(match note {
            Some(note) => GuardDecision {
                decision: Decision {
                    allowed: true,
                    reason: "FALLBACK".into(),
                    matched: Vec::new(),
                },
                note: Some(note),
            },
            None => GuardDecision {
                decision,
                note: None,
            },
        })
    }

    fn describe(&self, target: &T) -> Map<String, Value> {
        self.options
            .describe
            .as_ref()
            .map(|describe| describe(target))
            .unwrap_or_default()
    }

    /// `run(credential, tenantId, action, locate, fn)`: authenticate, locate the target, decide, run, audit. A
    /// denial commits only its audit record; a refusal inside the call (`OperationDenied`) or a recorded failure after
    /// authorization is audited as `deny` once the call's own transaction has rolled back.
    pub async fn run<R, L, F>(
        &self,
        credential: &CredentialInput,
        tenant_id: Option<&Value>,
        action: GuardAction<T>,
        locate: L,
        run: F,
    ) -> IamResult<R>
    where
        R: Serialize + Send + 'static,
        L: FnOnce(Store, AuthenticatedPrincipal) -> BoxFuture<'static, IamResult<T>> + Send,
        F: FnOnce(GuardCall<T>, T) -> BoxFuture<'static, OperationResult<R>> + Send,
    {
        let label = match &action {
            GuardAction::Fixed(action) => action.clone(),
            GuardAction::Of(_) => "iam:call".to_owned(),
        };
        let span_tenant = tenant_id.and_then(Value::as_str).map(str::to_owned);
        let work = async {
            let ctx = &self.ctx;
            let authenticated = ctx.principals()?.authenticate(credential).await?;
            let state = Mutex::new(RunState {
                resolved_action: label.clone(),
                ..RunState::default()
            });
            let state_ref = &state;
            let label_ref = &label;
            let action_ref = &action;
            let authenticated_ref = &authenticated;
            let result = ctx
                .store
                .transaction(move |tx| async move {
                    let inner = async {
                        let principal = ctx
                            .principals()?
                            .current_principal(&tx, authenticated_ref)
                            .await?;
                        let tenant = boxed(|| ctx.tenant_of(&tx, tenant_id)).await?;
                        let events = ctx.events()?;
                        // Callers from another tenant (and "view as" sessions) are refused before anything is looked
                        // up, so they learn nothing about which resources exist.
                        let impersonating = principal.session.impersonator_id.is_some();
                        if impersonating
                            || (principal.session.tenant_id != tenant.id
                                && !boxed(|| ctx.root_principal(&tx, &principal)).await?)
                        {
                            lock(state_ref).resource_id = self.collection.clone();
                            boxed(|| {
                                events.audit(
                                    &tx,
                                    &principal,
                                    label_ref,
                                    &tenant.id,
                                    &self.collection,
                                    AuditOutcome::Deny,
                                    false,
                                    Some(reason_metadata(if impersonating {
                                        "impersonation"
                                    } else {
                                        "tenant"
                                    })),
                                )
                            })
                            .await?;
                            return Ok(Outcome::Denied);
                        }
                        let target = boxed(|| locate(tx.clone(), principal.clone())).await?;
                        let resolved_action = match action_ref {
                            GuardAction::Fixed(action) => action.clone(),
                            GuardAction::Of(of) => of(&target),
                        };
                        {
                            let mut state = lock(state_ref);
                            state.resolved_action = resolved_action.clone();
                            state.resource_id = target.resource_id().to_owned();
                        }
                        let prepared: PreparedCache = Arc::new(Mutex::new(HashMap::new()));
                        let decision = boxed(|| {
                            self.decide_on_target(
                                &tx,
                                &principal,
                                &tenant,
                                &resolved_action,
                                &target,
                                Some(&target),
                                Some(&prepared),
                            )
                        })
                        .await?;
                        if !decision.decision.allowed {
                            // A refusal names what was asked for (a profile, a purpose) as an allowed call would.
                            let mut refused = self.describe(&target);
                            if decision.decision.reason == "IMPERSONATION_RESTRICTED" {
                                refused
                                    .insert("reason".into(), Value::String("impersonation".into()));
                            }
                            boxed(|| {
                                events.audit(
                                    &tx,
                                    &principal,
                                    &resolved_action,
                                    &tenant.id,
                                    target.resource_id(),
                                    AuditOutcome::Deny,
                                    false,
                                    (!refused.is_empty()).then_some(refused),
                                )
                            })
                            .await?;
                            return Ok(Outcome::Denied);
                        }
                        // A call a delegation holds back uses up the person's one confirmation (rolled back if the call
                        // fails).
                        boxed(|| {
                            use_confirmation(
                                &tx,
                                &principal,
                                &resolved_action,
                                "iam",
                                target.resource_id(),
                                ctx.now(),
                            )
                        })
                        .await?;
                        lock(state_ref).actor = Some(principal.clone());
                        let hook = OperationHookInput {
                            store: tx.clone(),
                            principal: principal.clone(),
                            tenant_id: tenant.id.clone(),
                            action: resolved_action.clone(),
                            resource_id: target.resource_id().to_owned(),
                        };
                        for plugin in &ctx.plugins {
                            if let Some(hooks) = plugin.hooks() {
                                boxed(|| hooks.before_operation(&hook)).await?;
                            }
                        }
                        let mut metadata = self.describe(&target);
                        if let Some(note) = &decision.note {
                            for (key, value) in note {
                                metadata.insert(key.clone(), value.clone());
                            }
                        }
                        let metadata = Arc::new(Mutex::new(metadata));
                        let call = GuardCall {
                            tx: tx.clone(),
                            principal: principal.clone(),
                            tenant: tenant.clone(),
                            metadata: metadata.clone(),
                            guard: self.clone(),
                            prepared,
                        };
                        let value = boxed(|| run(call, target.clone())).await?;
                        let raw = serde_json::to_value(&value).unwrap_or(Value::Null);
                        let result = match &self.options.hook_result {
                            Some(hook_result) => hook_result(&raw),
                            None => raw,
                        };
                        for plugin in &ctx.plugins {
                            if let Some(hooks) = plugin.hooks() {
                                boxed(|| hooks.after_operation(&hook, &result)).await?;
                            }
                        }
                        let root_override = decision.decision.reason == "ROOT_OVERRIDE";
                        let metadata = lock(&metadata).clone();
                        boxed(|| {
                            events.audit(
                                &tx,
                                &principal,
                                &resolved_action,
                                &tenant.id,
                                target.resource_id(),
                                AuditOutcome::Allow,
                                root_override,
                                (!metadata.is_empty()).then_some(metadata),
                            )
                        })
                        .await?;
                        Ok::<_, crate::contracts::OperationFailure>(Outcome::Allowed {
                            value,
                            root_override,
                        })
                    };
                    match inner.await {
                        Ok(outcome) => Ok(outcome),
                        Err(failure) => {
                            lock(state_ref).denied = failure.denied;
                            Err(failure.error)
                        }
                    }
                })
                .await;
            let failure = match result {
                Ok(Outcome::Denied) => {
                    return Err(IamError::with_status("ACCESS_DENIED", "Access denied", 403));
                }
                Ok(Outcome::Allowed {
                    value,
                    root_override,
                }) => {
                    if authenticated.session.impersonator_id.is_none()
                        && !root_override
                        && let Ok(usage) = ctx.usage()
                    {
                        let resolved = lock(&state).resolved_action.clone();
                        usage.record(
                            span_tenant.as_deref().unwrap_or(""),
                            &authenticated.identity.id,
                            &resolved,
                        );
                    }
                    return Ok(value);
                }
                Err(failure) => failure,
            };
            let reason = if lock(&state).denied {
                Some("refused".to_owned())
            } else {
                self.options.recorded_failures.get(&failure.code).cloned()
            };
            let (actor, resolved_action, resource_id) = {
                let state = lock(&state);
                (
                    state.actor.clone(),
                    state.resolved_action.clone(),
                    state.resource_id.clone(),
                )
            };
            // `actor` is set only once the call was authorized.
            if let (Some(actor), Some(reason)) = (actor, reason) {
                let tenant = span_tenant.clone().unwrap_or_default();
                let recorded = ctx
                    .store
                    .transaction(|tx| async move {
                        ctx.events()?
                            .audit(
                                &tx,
                                &actor,
                                &resolved_action,
                                &tenant,
                                &resource_id,
                                AuditOutcome::Deny,
                                false,
                                Some(reason_metadata(&reason)),
                            )
                            .await
                    })
                    .await;
                // Bookkeeping never masks the failure.
                let _ = recorded;
            }
            Err(failure)
        };
        boxed(|| {
            self.ctx.observe.span(
                SpanKind::Operation,
                &label,
                span_tenant.as_deref(),
                work,
                None,
                None,
            )
        })
        .await
    }

    /// `visible(credential, tenantId, action, resourceId, load)`: for list pages, the targets the caller may perform
    /// `action` on, decided per target (policies only) with one prepared decision. Refuses (and audits) callers the
    /// tenant refuses outright; otherwise audits one allowed event on `resourceId` with the number listed.
    pub async fn visible<Item, L>(
        &self,
        credential: &CredentialInput,
        tenant_id: Option<&Value>,
        action: &str,
        resource_id: &str,
        load: L,
    ) -> IamResult<Vec<Item>>
    where
        Item: Send + 'static,
        L: FnOnce(Store, Tenant) -> BoxFuture<'static, IamResult<Vec<(Item, Target)>>> + Send,
    {
        let span_tenant = tenant_id.and_then(Value::as_str).map(str::to_owned);
        let work = async {
            let ctx = &self.ctx;
            let authenticated = ctx.principals()?.authenticate(credential).await?;
            let authenticated_ref = &authenticated;
            let outcome = ctx
                .store
                .transaction(move |tx| async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, authenticated_ref)
                        .await?;
                    let tenant = ctx.tenant_of(&tx, tenant_id).await?;
                    let events = ctx.events()?;
                    let refuse = || async {
                        events
                            .audit(
                                &tx,
                                &principal,
                                action,
                                &tenant.id,
                                resource_id,
                                AuditOutcome::Deny,
                                false,
                                None,
                            )
                            .await
                    };
                    if principal.session.impersonator_id.is_some() {
                        refuse().await?;
                        return Ok(None);
                    }
                    let prepared = ctx
                        .decisions()?
                        .prepare_decision(&tx, &principal, &tenant, action)
                        .await?;
                    if let PreparedDecision::Fixed(decision) = &prepared
                        && !decision.allowed
                    {
                        refuse().await?;
                        return Ok(None);
                    }
                    let mut items = Vec::new();
                    for (item, target) in load(tx.clone(), tenant.clone()).await? {
                        let resource = ResolvedResource {
                            tenant_id: tenant.id.clone(),
                            kind: "iam".into(),
                            id: target.resource_id.clone(),
                            attributes: Some(target.attributes.clone()),
                            classification: None,
                        };
                        if decide_on(&prepared, &resource, Some(action))?.allowed {
                            items.push(item);
                        }
                    }
                    let mut listed = Map::new();
                    listed.insert("listed".into(), Value::from(items.len()));
                    events
                        .audit(
                            &tx,
                            &principal,
                            action,
                            &tenant.id,
                            resource_id,
                            AuditOutcome::Allow,
                            is_root_override(&prepared),
                            Some(listed),
                        )
                        .await?;
                    Ok(Some(items))
                })
                .await?;
            outcome.ok_or_else(|| IamError::with_status("ACCESS_DENIED", "Access denied", 403))
        };
        self.ctx
            .observe
            .span(
                SpanKind::Operation,
                action,
                span_tenant.as_deref(),
                work,
                None,
                None,
            )
            .await
    }
}
