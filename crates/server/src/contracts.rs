//! Contracts of the service modules the [`crate::context::ServerContext`] reaches at call time (Rust-only module):
//! the TypeScript interfaces of decisions.ts (`DecisionService`), operations.ts (`OperationService`), principals.ts
//! (`PrincipalService`), flows.ts (`FlowService`), usage.ts (`UsageRecorder`), token-signing.ts
//! (`SessionTokenSigner`), web-identity.ts (`WebIdentityVerifier`), hosts.ts (`HostService`) and billing-service.ts
//! (`BillingHooks`), as traits. The composition root ([`crate::index::better_iam`]) attaches an implementation of each.
//!
//! The shared decision types live here too, so modules can name them without importing the decision engine:
//! [`GrantPath`], [`PreparedDecision`], [`DecisionInputs`], [`EffectiveBinding`], [`OperationDenied`].

use std::sync::Arc;

use async_trait::async_trait;
use better_iam_core::{
    AuthenticatedPrincipal, CredentialInput, Decision, IamError, IamResult, IamStore, Identity,
    PolicyDocument, ResourceRef, Tenant,
};
use futures::future::BoxFuture;
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value};

use crate::clearances::{KnownLabeling, MandatoryAccess};
use crate::context::Store;
use crate::hosts::{HostMatch, WrongRegionError};
use crate::models::{Binding, BindingActivation, Role};
use crate::options::{
    AccessibleResourcesRequest, AuthorizationCheck, AuthorizationRequest,
    BatchAuthorizationRequest, HttpRequest, ResolvedResource,
};
use crate::session_tokens::{PublicSessionJwk, SessionTokenClaims};

// --- decisions.ts ------------------------------------------------------------------------------------------------

/// `GrantPath`: one way a principal receives a policy, the grant plus every ceiling that bounds it.
#[derive(Debug, Clone, PartialEq)]
pub struct GrantPath {
    pub grants: Vec<PolicyDocument>,
    pub boundaries: Vec<PolicyDocument>,
    pub authority_id: String,
}

/// A delegation's per-action confirmation gate: a decision for calls it holds back, None otherwise.
pub type ConfirmGate = Arc<dyn Fn(&str, &str, &str) -> Option<Decision> + Send + Sync>;

/// `DecisionInputs`: what a prepared decision evaluates from (everything but the resource). Read-only.
#[derive(Clone)]
pub struct DecisionInputs {
    /// Principal, request and tenant context keys.
    pub context: Map<String, Value>,
    /// Ceilings over every grant path.
    pub boundaries: Vec<PolicyDocument>,
    /// Grant paths (deny-only paths included).
    pub paths: Vec<GrantPath>,
    /// Deny statements across every path.
    pub denies: Vec<PolicyDocument>,
    /// Relations the principal holds, keyed by `{type}/{id}`.
    pub held: IndexMap<String, IndexSet<String>>,
    /// A delegation's per-action confirmation gate, when the session has one.
    pub confirm: Option<ConfirmGate>,
    /// Mandatory access control (security clearances): the session's clearance against the tenant's scheme, checked
    /// before anything else in `evaluate`. None when clearances are off or the tenant has no scheme.
    pub mandatory: Option<Arc<dyn MandatoryAccess>>,
}

/// Evaluates prepared grants against one resource, for the prepared action or an override. Fails only where
/// `evaluatePolicy` throws (an action or resource name it refuses).
pub type Evaluate =
    Arc<dyn Fn(&ResolvedResource, Option<&str>) -> IamResult<Decision> + Send + Sync>;

/// `PreparedDecision`: a decision for every resource (`fixed`), or an evaluator applied per resource.
#[derive(Clone)]
pub enum PreparedDecision {
    Fixed(Decision),
    Evaluator {
        evaluate: Evaluate,
        /// What `evaluate` decides from, for query planning.
        inputs: Option<Arc<DecisionInputs>>,
        /// The platform's root override under mandatory access control.
        root_override: bool,
    },
}

/// `isRootOverride(prepared)`: the fixed `ROOT_OVERRIDE` form, or the evaluator it becomes under clearances.
pub fn is_root_override(prepared: &PreparedDecision) -> bool {
    match prepared {
        PreparedDecision::Fixed(decision) => decision.reason == "ROOT_OVERRIDE",
        PreparedDecision::Evaluator { root_override, .. } => *root_override,
    }
}

/// `decideOn(prepared, resource, action?)`.
pub fn decide_on(
    prepared: &PreparedDecision,
    resource: &ResolvedResource,
    action: Option<&str>,
) -> IamResult<Decision> {
    match prepared {
        PreparedDecision::Fixed(decision) => Ok(decision.clone()),
        PreparedDecision::Evaluator { evaluate, .. } => evaluate(resource, action),
    }
}

/// `GrantSources`: an identity's group memberships (insertion order) and every live binding that applies to it.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct GrantSources {
    pub group_ids: IndexSet<String>,
    pub bindings: Vec<Binding>,
}

/// `EffectiveBinding.via`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BindingVia {
    Identity,
    Group(String),
}

/// `EffectiveBinding.activation`: `Pick<BindingActivation, 'id' | 'activatedAt' | 'expiresAt'>`.
#[derive(Debug, Clone, PartialEq)]
pub struct ActivationSummary {
    pub id: String,
    pub activated_at: f64,
    pub expires_at: f64,
}

/// `EffectiveBinding.pendingActivation`.
#[derive(Debug, Clone, PartialEq)]
pub struct PendingActivation {
    pub id: String,
    pub requested_at: f64,
    pub expires_at: f64,
}

/// `EffectiveBinding`: a binding that applies to an identity directly or through a group.
#[derive(Debug, Clone, PartialEq)]
pub struct EffectiveBinding {
    pub binding: Binding,
    pub role: Option<Role>,
    pub via: BindingVia,
    pub activation: Option<ActivationSummary>,
    pub pending_activation: Option<PendingActivation>,
    pub in_window: Option<bool>,
}

impl EffectiveBinding {
    /// The TypeScript object: the binding's members, then `role`, `via`, `inWindow`, `activation` and
    /// `pendingActivation` as `effectiveBindings` spreads them.
    pub fn to_json(&self) -> Value {
        let mut out = match serde_json::to_value(&self.binding) {
            Ok(Value::Object(map)) => map,
            _ => Map::new(),
        };
        if let Some(role) = &self.role {
            out.insert(
                "role".into(),
                serde_json::to_value(role).unwrap_or(Value::Null),
            );
        }
        out.insert(
            "via".into(),
            match &self.via {
                BindingVia::Identity => Value::String("identity".into()),
                BindingVia::Group(group_id) => serde_json::json!({ "groupId": group_id }),
            },
        );
        if let Some(in_window) = self.in_window {
            out.insert("inWindow".into(), Value::Bool(in_window));
        }
        if let Some(activation) = &self.activation {
            out.insert(
                "activation".into(),
                serde_json::json!({
                    "id": activation.id,
                    "activatedAt": better_iam_core::js::number(activation.activated_at),
                    "expiresAt": better_iam_core::js::number(activation.expires_at),
                }),
            );
        }
        if let Some(pending) = &self.pending_activation {
            out.insert(
                "pendingActivation".into(),
                serde_json::json!({
                    "id": pending.id,
                    "requestedAt": better_iam_core::js::number(pending.requested_at),
                    "expiresAt": better_iam_core::js::number(pending.expires_at),
                }),
            );
        }
        Value::Object(out)
    }
}

/// `DecisionService` (decisions.ts `createDecisions`).
#[async_trait]
pub trait DecisionService: Send + Sync {
    /// The grant paths of a role: its inline document, its attached policies, and (recursively) the grants of the
    /// roles it inherits, each bounded by every authority ceiling on the way down. `seen` guards against cycles;
    /// `lapsed` receives, as paths that grant nothing, the denies of parts whose authority was revoked.
    #[allow(clippy::too_many_arguments)]
    async fn role_grants(
        &self,
        tx: &Store,
        role: &Role,
        tenant_id: &str,
        ceilings: &[PolicyDocument],
        authority_id: &str,
        seen: Option<&mut IndexSet<String>>,
        lapsed: Option<&mut Vec<GrantPath>>,
    ) -> IamResult<Vec<GrantPath>>;
    /// The identity's group memberships and every live binding that applies to it directly or through a group.
    async fn grant_sources(
        &self,
        tx: &Store,
        identity_id: &str,
        tenant_id: &str,
    ) -> IamResult<GrantSources>;
    /// The identity's live activations of eligible bindings, keyed by binding ID.
    async fn live_activations(
        &self,
        tx: &Store,
        tenant_id: &str,
        identity_id: &str,
    ) -> IamResult<IndexMap<String, BindingActivation>>;
    /// Every live grant path of an identity: direct bindings and bindings inherited through groups.
    async fn identity_grants(
        &self,
        tx: &Store,
        identity_id: &str,
        tenant_id: &str,
        sources: Option<&GrantSources>,
        lapsed: Option<&mut Vec<GrantPath>>,
    ) -> IamResult<Vec<GrantPath>>;
    /// Direct and group-derived role bindings: the effective role set of an identity.
    async fn effective_bindings(
        &self,
        tx: &Store,
        tenant_id: &str,
        identity_id: &str,
    ) -> IamResult<Vec<EffectiveBinding>>;
    /// Loads a resource's trusted attributes from the registry or the application resolver (see decisions.ts).
    async fn resolve(
        &self,
        tx: &Store,
        reference: &ResourceRef,
        internal: bool,
        action: Option<&str>,
        known: Option<&KnownLabeling>,
    ) -> IamResult<ResolvedResource>;
    /// Loads everything a decision needs except the resource.
    async fn prepare_decision(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        target: &Tenant,
        action: &str,
    ) -> IamResult<PreparedDecision>;
    /// One authorization decision; `internal_resource` accepts platform resource types without resolving them.
    async fn decide(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        request: &AuthorizationRequest,
        internal_resource: bool,
    ) -> IamResult<Decision>;
    /// A principal for simulations and reviews: the identity in a synthetic, never-issued session.
    fn simulated_principal(&self, identity: &Identity, mfa: bool) -> AuthenticatedPrincipal;
}

// --- operations.ts -----------------------------------------------------------------------------------------------

/// A failure inside an operation's mutation: an `IamError`, or an [`OperationDenied`] refusal the envelope records
/// as a deny audit event (`error instanceof OperationDenied`). `?` converts an `IamError` into it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OperationFailure {
    pub error: IamError,
    /// Thrown as `OperationDenied`.
    pub denied: bool,
}

impl From<IamError> for OperationFailure {
    fn from(error: IamError) -> Self {
        Self {
            error,
            denied: false,
        }
    }
}

impl From<OperationFailure> for IamError {
    fn from(failure: OperationFailure) -> Self {
        failure.error
    }
}

/// The result of a mutation inside an operation envelope.
pub type OperationResult<T> = Result<T, OperationFailure>;

/// `OperationDenied`: thrown by a mutation to refuse an operation its permission alone does not cover. It rolls back
/// like any failure, is then recorded as a deny audit event, and surfaces as ACCESS_DENIED (403).
pub struct OperationDenied;

impl OperationDenied {
    /// `new OperationDenied(message = 'Access denied')`.
    #[allow(clippy::new_ret_no_self)]
    pub fn new(message: Option<&str>) -> OperationFailure {
        OperationFailure {
            error: IamError::with_status("ACCESS_DENIED", message.unwrap_or("Access denied"), 403),
            denied: true,
        }
    }
}

/// What an operation's mutation receives.
#[derive(Clone)]
pub struct MutationContext {
    pub tx: Arc<dyn IamStore>,
    pub principal: AuthenticatedPrincipal,
    pub tenant: Tenant,
}

/// An operation's mutation; its JSON result is the operation's result. It may borrow from the caller (`'a`).
pub type Mutation<'a> =
    Box<dyn FnOnce(MutationContext) -> BoxFuture<'a, OperationResult<Value>> + Send + 'a>;

/// One answered check of `authorizeMany`.
#[derive(Debug, Clone, PartialEq)]
pub struct BatchResult {
    pub check: AuthorizationCheck,
    pub allowed: bool,
    pub reason: String,
}

/// The answer of `listAccessible`.
#[derive(Debug, Clone, PartialEq)]
pub struct AccessibleResources {
    pub resources: Vec<Value>,
    pub total: f64,
}

/// `callPlugin`'s input: `{ pluginId, path, tenantId, input? }` (the raw values the router read).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PluginCall {
    pub plugin_id: Option<Value>,
    pub path: Option<Value>,
    pub tenant_id: Option<Value>,
    pub input: Option<Value>,
}

/// `OperationService` (operations.ts `createOperations`).
#[async_trait]
pub trait OperationService: Send + Sync {
    /// The transactional envelope of every provisioning call: authenticate, re-validate the principal, authorize
    /// `action` on `iam/{resourceId}`, run the mutation, and append one audit event. A denial commits only its audit
    /// record. `tenant_id` is the value the caller sent (TypeScript passes it unvalidated).
    async fn operation<'m>(
        &self,
        credential: &CredentialInput,
        tenant_id: Option<&Value>,
        action: &str,
        resource_id: &str,
        mutation: Mutation<'m>,
        root_only: bool,
    ) -> IamResult<Value>;
    /// A decision that records denials and root overrides, with matched statements stripped for callers.
    async fn recorded_decision(
        &self,
        tx: &Store,
        current: &AuthenticatedPrincipal,
        request: &AuthorizationRequest,
    ) -> IamResult<Decision>;
    async fn authorize(&self, request: &AuthorizationRequest) -> IamResult<Decision>;
    /// Evaluates up to 50 checks for one tenant in a single transaction.
    async fn authorize_many(
        &self,
        request: &BatchAuthorizationRequest,
    ) -> IamResult<Vec<BatchResult>>;
    /// The batch evaluation behind `authorizeMany`, without the observability span.
    async fn evaluate_many(
        &self,
        request: &BatchAuthorizationRequest,
    ) -> IamResult<Vec<BatchResult>>;
    /// The registered resources of one managed type the caller may perform an action on.
    async fn list_accessible(
        &self,
        request: &AccessibleResourcesRequest,
    ) -> IamResult<AccessibleResources>;
    /// The reverse query behind `listAccessible`, without the observability span.
    async fn query_accessible(
        &self,
        request: &AccessibleResourcesRequest,
    ) -> IamResult<AccessibleResources>;
    async fn require_access(&self, request: &AuthorizationRequest) -> IamResult<()>;
    /// Dispatches a plugin endpoint through the same validated, transactional envelope as built-in operations.
    async fn call_plugin(
        &self,
        credential: &CredentialInput,
        input: PluginCall,
    ) -> IamResult<Value>;
}

// --- principals.ts -----------------------------------------------------------------------------------------------

/// `PrincipalService` (principals.ts `createPrincipals`).
#[async_trait]
pub trait PrincipalService: Send + Sync {
    /// Resolves a credential to its identity and session.
    async fn authenticate(&self, input: &CredentialInput) -> IamResult<AuthenticatedPrincipal>;
    /// Re-reads the principal inside a transaction and re-validates every revocation condition.
    async fn current_principal(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
    ) -> IamResult<AuthenticatedPrincipal>;
}

// --- usage.ts ------------------------------------------------------------------------------------------------------

/// `UsageRecorder` (usage.ts `createUsageRecorder`).
#[async_trait]
pub trait UsageRecorder: Send + Sync {
    fn enabled(&self) -> bool;
    /// Counts one allowed use; a no-op when tracking is off.
    fn record(&self, tenant_id: &str, identity_id: &str, action: &str);
    /// Writes everything buffered; returns the number of rows written (`{ written }`).
    async fn flush(&self) -> IamResult<f64>;
    /// Stops the periodic writer.
    fn stop(&self);
}

/// The recorder used while access usage tracking is off: records nothing.
pub struct DisabledUsage;

#[async_trait]
impl UsageRecorder for DisabledUsage {
    fn enabled(&self) -> bool {
        false
    }
    fn record(&self, _tenant_id: &str, _identity_id: &str, _action: &str) {}
    async fn flush(&self) -> IamResult<f64> {
        Ok(0.0)
    }
    fn stop(&self) {}
}

// --- flows.ts ------------------------------------------------------------------------------------------------------

/// `FlowService` (flows.ts `createFlows`): invitations, identity links, role assumption. Inputs are the raw request
/// members, results the JSON the TypeScript returns.
#[async_trait]
pub trait FlowService: Send + Sync {
    /// Public: redeems an owner invitation, activates the pending tenant, and signs the owner in.
    async fn accept_owner_invitation(&self, input: &Map<String, Value>) -> IamResult<Value>;
    /// Public: redeems a member invitation, applies its bindings, and signs the member in.
    async fn accept_member_invitation(&self, input: &Map<String, Value>) -> IamResult<Value>;
    async fn link_identities(
        &self,
        left: &CredentialInput,
        right: &CredentialInput,
    ) -> IamResult<Value>;
    async fn switch_identity(
        &self,
        credential: &CredentialInput,
        link_id: Option<&Value>,
        target: &CredentialInput,
    ) -> IamResult<Value>;
    /// AssumeRole: exchanges a user session, API key or session token for a role session.
    async fn assume_role(
        &self,
        credential: &CredentialInput,
        input: &Map<String, Value>,
    ) -> IamResult<Value>;
}

// --- token-signing.ts ----------------------------------------------------------------------------------------------

/// `SessionTokenSigner` (token-signing.ts): IAM session JWTs; present only when `sts.jwt` is configured.
#[async_trait]
pub trait SessionTokenSigner: Send + Sync {
    /// The `iss` of every token.
    fn issuer(&self) -> &str;
    /// The audiences tokens may be issued for; always includes the issuer (first).
    fn audiences(&self) -> &[String];
    /// Longest allowed `exp - iat`, in seconds.
    fn max_lifetime_seconds(&self) -> f64;
    /// Signs the claims with the active key.
    async fn sign(&self, claims: &SessionTokenClaims) -> IamResult<String>;
    /// Verifies a token for `audience` (default: the issuer) with a 5 second clock tolerance.
    async fn verify(&self, token: &str, audience: Option<&str>) -> IamResult<SessionTokenClaims>;
    /// The public members of the signing and verification keys, for the JWKS route.
    fn public_jwks(&self) -> Vec<PublicSessionJwk>;
}

// --- web-identity.ts -----------------------------------------------------------------------------------------------

/// `WebIdentityVerifier` (web-identity.ts `createWebIdentityVerifier`); present when `sts.webIdentity` is enabled.
#[async_trait]
pub trait WebIdentityVerifier: Send + Sync {
    /// Verifies an external token against a provider (`WebIdentityProviderConfig` as JSON); the verified identity.
    async fn verify(&self, provider: &Value, token: &str) -> IamResult<Value>;
    /// Drops the cached keys of a provider (after an update or deletion).
    fn forget(&self, provider_id: &str);
}

// --- hosts.ts ------------------------------------------------------------------------------------------------------

/// `HostService` (hosts.ts `createHosts`): organization sign-in addresses and regions.
#[async_trait]
pub trait HostService: Send + Sync {
    /// True when organization addresses are configured, so requests are resolved and may be pinned.
    fn enabled(&self) -> bool;
    /// The organization an address belongs to (see hosts.ts).
    async fn resolve(&self, host: &str, tx: Option<&Store>) -> IamResult<Option<HostMatch>>;
    /// The organization a request is pinned to, from its address and, for cross-origin calls, its Origin.
    async fn request_tenant(&self, request: &HttpRequest) -> IamResult<Option<HostMatch>>;
    /// True for the origin of an active organization address.
    async fn trusts_origin(&self, origin: &str) -> bool;
    /// An organization's canonical sign-in URL (by tenant ID).
    async fn sign_in_url(&self, tenant_id: &str) -> IamResult<Option<String>>;
    /// An organization's canonical sign-in URL for a tenant record.
    async fn sign_in_url_of(
        &self,
        tenant: &Tenant,
        tx: Option<&Store>,
    ) -> IamResult<Option<String>>;
    /// The home region of a tenant: its own `region`, else its nearest ancestor's.
    async fn region_of(&self, tx: &Store, tenant: &Tenant) -> IamResult<Option<String>>;
    /// Throws `WRONG_REGION` when the tenant is served by another region.
    async fn assert_served_here(
        &self,
        tx: &Store,
        tenant: &Tenant,
        host_region: Option<&str>,
    ) -> IamResult<()>;
    /// `assertServedHere` for a tenant ID from a request body; unknown tenants are left to the operation.
    async fn assert_tenant_served_here(&self, tenant_id: &str) -> IamResult<()>;
    /// For an alias this database does not know: the redirect to the region that has it.
    async fn remote_alias(&self, alias: &str) -> Option<WrongRegionError>;
    /// The region a new tenant under `parent` gets.
    async fn region_for_new(
        &self,
        tx: &Store,
        parent: &Tenant,
        requested: Option<&Value>,
    ) -> IamResult<Option<String>>;
    /// Validates a region name.
    fn region(&self, value: Option<&Value>) -> IamResult<String>;
    /// Throws `HOSTNAME_NOT_ALLOWED` for hostnames the deployment itself uses.
    fn assert_claimable(&self, hostname: &str) -> IamResult<()>;
    /// Whether a TLS certificate may be issued for `hostname`.
    async fn allowed(&self, hostname: &str) -> bool;
}

// --- billing-service.ts --------------------------------------------------------------------------------------------

/// `BillingHooks` (billing-service.ts): modules push already-priced usage into the ledger.
#[async_trait]
pub trait BillingHooks: Send + Sync {
    /// Records already-priced usage (`PricedUsageInput` as JSON) in the caller's transaction. Never fails.
    async fn record_priced(&self, tx: &Store, input: &Value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prepared_decisions() {
        let fixed = PreparedDecision::Fixed(Decision {
            allowed: true,
            reason: "ROOT_OVERRIDE".into(),
            matched: Vec::new(),
        });
        assert!(is_root_override(&fixed));
        let evaluator = PreparedDecision::Evaluator {
            evaluate: Arc::new(|resource, action| {
                Ok(Decision {
                    allowed: resource.id == "a",
                    reason: action.unwrap_or("NONE").to_owned(),
                    matched: Vec::new(),
                })
            }),
            inputs: None,
            root_override: false,
        };
        assert!(!is_root_override(&evaluator));
        let resource = ResolvedResource {
            id: "a".into(),
            ..ResolvedResource::default()
        };
        let decision = decide_on(&evaluator, &resource, Some("X")).unwrap();
        assert!(decision.allowed);
        assert_eq!(decision.reason, "X");
        let denied = OperationDenied::new(None);
        assert!(denied.denied);
        assert_eq!(denied.error.status, 403);
        assert_eq!(denied.error.message, "Access denied");
        let plain: OperationFailure = IamError::new("X", "y").into();
        assert!(!plain.denied);
    }
}
