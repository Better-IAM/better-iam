//! Port of `packages/server/src/api/teams.ts`: teams inside an organization (teams.ts). Administrators holding
//! `iam:teams:*` manage every team; a team's maintainers (and those of the teams above it) manage its membership and
//! join requests themselves unless the team's `memberManagement` is `admins`; members see their own team. Give a team
//! access by binding roles to its backing group (`team.groupId`) with `bindings.create`; everyone in the team and in
//! the teams below it then holds them.
//!
//! Teams, memberships, join requests and reviews are handled as the raw records the store keeps (member order and
//! members this port does not know survive a read-modify-write); the helpers of teams.ts that take typed records get
//! them decoded.

use std::future::Future;
use std::sync::{Arc, Mutex, Weak};

use better_iam_auth::outbox::EnqueueInput;
use better_iam_core::{
    AuditOutcome, AuthenticatedPrincipal, CredentialInput, Filter, IamError, IamResult, IamStore,
    IamStoreExt, OperationHookInput, OutboxKind, Record, SessionKind, Tenant,
};
use better_iam_types::api::teams;
use futures::future::BoxFuture;
use indexmap::{IndexMap, IndexSet};
use serde_json::{Map, Value, json};

use crate::api::groups::{assert_may_claim_licenses, create_group_record, delete_group_record};
use crate::api::package_automation::after_identity_change;
use crate::api::roles::find_all;
use crate::api::{Body, Reply, string_member};
use crate::context::{ServerContext, Store};
use crate::contracts::{Mutation, MutationContext, OperationResult};
use crate::departments::load_department;
use crate::invariants::{invariant_snapshot, invariant_verify};
use crate::js::{as_number, cmp_utf16, invalid_input, number, truthy};
use crate::metrics::locale_compare;
use crate::models::{Binding, GroupMember};
use crate::observe::SpanKind;
use crate::options::{AuthorizationRequest, ResourceTarget};
use crate::org_insights::{birthright_options, suggest_birthright};
use crate::org_rules::packages_naming;
use crate::port::decode;
use crate::session_kinds::acts_in_own_right;
use crate::sod::{sod_snapshot, sod_verify};
use crate::team_reviews::{
    DEFAULT_REVIEW_MS, MAX_REVIEW_MS, MIN_REVIEW_MS, TEAM_REVIEW_COLLECTIONS, TeamReview,
    complete_team_review,
};
use crate::teams::{
    MAX_TEAM_DEPTH, MAX_TEAMS, TEAM_COLLECTIONS, Team, TeamMember, is_team_maintainer,
    live_team_member, load_team, role_holds_deny, slug_from_name, sync_team_groups,
    sync_teams_from_groups, team_chain, team_descendants, team_maintainers, team_slug,
    team_sync_groups, teams_of,
};
use crate::utils::id;
use crate::validation::{integer, strings, text};
use better_iam_core::js::iso_string;

/// How long a join request waits for a maintainer (fourteen days).
const JOIN_REQUEST_LIFETIME_MS: f64 = 14.0 * 86_400_000.0;
const MAX_MAINTAINERS_ON_CREATE: usize = 20;
const JOIN_POLICIES: &[&str] = &["closed", "request"];
const MANAGEMENT_MODES: &[&str] = &["maintainers", "admins"];
const TEAM_ROLES: &[&str] = &["maintainer", "member"];
const REVIEW_DECISIONS: &[&str] = &["keep", "remove"];
const REQUEST_STATUSES: &[&str] = &["pending", "approved", "denied", "cancelled", "expired"];
const REVIEW_STATUSES: &[&str] = &["open", "completed", "cancelled"];
const LICENSE_MESSAGE: &str = "This team, or a team above it, carries license seats; adding people to it, changing how long they stay, or appointing its maintainers needs iam:licenses:assign";

fn teams_collection() -> &'static str {
    TEAM_COLLECTIONS["teams"].as_str().unwrap_or("teams")
}
fn members_collection() -> &'static str {
    TEAM_COLLECTIONS["members"]
        .as_str()
        .unwrap_or("teamMembers")
}
fn requests_collection() -> &'static str {
    TEAM_COLLECTIONS["requests"]
        .as_str()
        .unwrap_or("teamJoinRequests")
}
fn reviews_collection() -> &'static str {
    TEAM_REVIEW_COLLECTIONS["reviews"]
        .as_str()
        .unwrap_or("teamReviews")
}
fn items_collection() -> &'static str {
    TEAM_REVIEW_COLLECTIONS["items"]
        .as_str()
        .unwrap_or("teamReviewItems")
}

// --- Record helpers ----------------------------------------------------------------------------------------------

/// A string member of a record, or "" (`record.key` where the type says string).
fn s<'a>(record: &'a Record, key: &str) -> &'a str {
    record.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// A string member that is present (`record.key` of an optional string).
fn opt_s<'a>(record: &'a Record, key: &str) -> Option<&'a str> {
    record.get(key).and_then(Value::as_str)
}

/// A numeric member (`record.key` of an optional number).
fn num(record: &Record, key: &str) -> Option<f64> {
    record.get(key).and_then(as_number)
}

/// A string as a JSON value.
fn v(text: impl Into<String>) -> Value {
    Value::String(text.into())
}

/// `[...new Set(items)]`.
fn unique<I: IntoIterator<Item = String>>(items: I) -> Vec<String> {
    let set: IndexSet<String> = items.into_iter().collect();
    set.into_iter().collect()
}

fn not_found() -> IamError {
    IamError::with_status("NOT_FOUND", "Resource not found", 404)
}

fn access_denied(message: &str) -> IamError {
    IamError::with_status("ACCESS_DENIED", message, 403)
}

/// `choice(value, allowed, name)`.
fn choice(value: Option<&Value>, allowed: &[&str], name: &str) -> IamResult<String> {
    match value {
        Some(Value::String(text)) if allowed.contains(&text.as_str()) => Ok(text.clone()),
        _ => Err(invalid_input(format!(
            "{name} must be one of {}",
            allowed.join(", ")
        ))),
    }
}

/// `ref(team)`.
fn team_ref(team: &Record) -> Value {
    let mut out = Map::new();
    out.insert("id".into(), v(s(team, "id")));
    out.insert("name".into(), v(s(team, "name")));
    out.insert("slug".into(), v(s(team, "slug")));
    Value::Object(out)
}

/// `ref(team)` as a map (to spread into a larger object).
fn team_ref_map(team: &Record) -> Map<String, Value> {
    match team_ref(team) {
        Value::Object(map) => map,
        _ => Map::new(),
    }
}

/// `person(identity)`.
fn person(identity: &Record) -> Value {
    let mut out = Map::new();
    out.insert(
        "id".into(),
        identity.get("id").cloned().unwrap_or(Value::Null),
    );
    out.insert(
        "name".into(),
        identity.get("name").cloned().unwrap_or(Value::Null),
    );
    if truthy(identity.get("email")) {
        out.insert(
            "email".into(),
            identity.get("email").cloned().unwrap_or_default(),
        );
    }
    if let Some(status) = identity.get("status") {
        out.insert("status".into(), status.clone());
    }
    Value::Object(out)
}

/// `unknownPerson(identityId)`.
fn unknown_person(identity_id: &str) -> Value {
    json!({ "id": identity_id, "name": identity_id, "status": "deleted" })
}

/// `person.email ?? person.name` of a person view.
fn sort_name(person: &Value) -> String {
    person
        .get("email")
        .filter(|email| !email.is_null())
        .or_else(|| person.get("name"))
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned()
}

/// `liveTeamMember(member, at)` of a raw membership.
fn live(member: &Record, at: f64) -> IamResult<bool> {
    let typed: TeamMember = decode(member.clone())?;
    live_team_member(&typed, at)
}

/// `ownUserSession(principal, tenantId)`: a person acting for themselves in their own tenant.
fn own_user_session(principal: &AuthenticatedPrincipal, tenant_id: &str) -> bool {
    principal.session.kind == SessionKind::User
        && acts_in_own_right(principal.session.kind)
        && !principal
            .session
            .impersonator_id
            .as_deref()
            .is_some_and(|id| !id.is_empty())
        && principal.session.tenant_id == tenant_id
        && principal.identity.tenant_id == tenant_id
        && principal.identity.kind == better_iam_core::IdentityKind::User
}

/// `requireOwnSession(principal, tenantId)`.
fn require_own_session(principal: &AuthenticatedPrincipal, tenant_id: &str) -> IamResult<()> {
    if principal
        .session
        .impersonator_id
        .as_deref()
        .is_some_and(|id| !id.is_empty())
    {
        return Err(IamError::with_status(
            "IMPERSONATION_RESTRICTED",
            "Teams cannot be joined or left while impersonating",
            403,
        ));
    }
    if !own_user_session(principal, tenant_id) {
        return Err(access_denied(
            "Teams are joined and left from a person’s own session in their organization",
        ));
    }
    Ok(())
}

/// The tenant's teams by ID, as raw records.
type Teams = IndexMap<String, Record>;

/// How the caller acts on a team: through a permission, or as one of its maintainers or members.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Via {
    Permission,
    Maintainer,
    Member,
}

impl Via {
    pub fn as_str(self) -> &'static str {
        match self {
            Via::Permission => "permission",
            Via::Maintainer => "maintainer",
            Via::Member => "member",
        }
    }
}

/// What a team's own people may do without an administrator permission (`TeamLevel`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Level {
    Maintainer,
    Member,
}

/// `TeamMutation`: the operation's transaction and caller, with the team and how the caller reached it.
pub struct TeamMutation {
    pub tx: Store,
    pub principal: AuthenticatedPrincipal,
    pub tenant: Tenant,
    pub team: Record,
    pub via: Via,
}

/// The work of a team-scoped operation.
type TeamWork<'a> =
    Box<dyn FnOnce(TeamMutation) -> BoxFuture<'a, OperationResult<Value>> + Send + 'a>;

fn team_work<'a, F, Fut>(run: F) -> TeamWork<'a>
where
    F: FnOnce(TeamMutation) -> Fut + Send + 'a,
    Fut: Future<Output = OperationResult<Value>> + Send + 'a,
{
    Box::new(move |mutation| Box::pin(run(mutation)))
}

fn mutation<'a, F, Fut>(run: F) -> Mutation<'a>
where
    F: FnOnce(MutationContext) -> Fut + Send + 'a,
    Fut: Future<Output = OperationResult<Value>> + Send + 'a,
{
    Box::new(move |context| Box::pin(run(context)))
}

/// The people a change touched (`reconciling`'s `touch`).
#[derive(Default)]
struct Touched(Mutex<IndexSet<String>>);

impl Touched {
    fn touch<I: IntoIterator<Item = String>>(&self, identity_ids: I) {
        let mut touched = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        for identity_id in identity_ids {
            touched.insert(identity_id);
        }
    }
    fn take(&self) -> Vec<String> {
        let touched = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        touched.iter().cloned().collect()
    }
}

/// The member values of a team update (`TeamUpdate` keys) in their TypeScript order.
const UPDATE_KEYS: &[&str] = &[
    "name",
    "slug",
    "description",
    "parentId",
    "departmentId",
    "joinPolicy",
    "memberManagement",
    "syncGroupIds",
];

/// The callers and team chains one transaction cleared (`clearedLicenses`, a WeakMap keyed by the transaction).
type ClearedLicenses = (Weak<dyn IamStore>, IndexSet<String>);

/// `teamModule(ctx)`: the team API and the transaction-level helpers configuration sync shares.
struct TeamModule {
    ctx: Arc<ServerContext>,
    /// Per transaction: the callers and team chains `assertMayClaimTeamLicenses` already cleared.
    cleared_licenses: Mutex<Vec<ClearedLicenses>>,
}

impl TeamModule {
    fn new(ctx: &Arc<ServerContext>) -> Self {
        Self {
            ctx: ctx.clone(),
            cleared_licenses: Mutex::new(Vec::new()),
        }
    }

    /// Runs after a change committed: re-evaluates the birthright access package rules of the people it touched
    /// (`reconciling`).
    async fn reconciled(
        &self,
        tenant_id: &str,
        touched: &Touched,
        result: Value,
    ) -> IamResult<Value> {
        after_identity_change(&self.ctx, tenant_id, &touched.take(), &result).await
    }

    async fn all_teams(&self, tx: &Store, tenant_id: &str) -> IamResult<Teams> {
        let mut map = IndexMap::new();
        for team in tx
            .find(
                teams_collection(),
                &Filter::new().eq("tenantId", tenant_id),
                &find_all(),
            )
            .await?
        {
            map.insert(s(&team, "id").to_owned(), team);
        }
        Ok(map)
    }

    /// `teamChain(teams, teamId)` over raw records.
    fn chain(&self, teams: &Teams, team_id: &str) -> IamResult<Vec<Record>> {
        let mut typed: IndexMap<String, Team> = IndexMap::new();
        for (key, team) in teams {
            typed.insert(key.clone(), decode(team.clone())?);
        }
        Ok(team_chain(&typed, team_id)?
            .into_iter()
            .filter_map(|team| teams.get(&team.id).cloned())
            .collect())
    }

    /// `teamDescendants(teams.values(), teamId)` over raw records.
    fn descendants(&self, teams: &Teams, team_id: &str) -> IamResult<Vec<Record>> {
        let list = Value::Array(teams.values().cloned().map(Value::Object).collect());
        Ok(team_descendants(&list, team_id)?
            .into_iter()
            .filter_map(|team| teams.get(&team.id).cloned())
            .collect())
    }

    /// `loadTeam(tx, tenantId, teamId)` as the raw record.
    async fn load_team_record(
        &self,
        tx: &Store,
        tenant_id: &str,
        team_id: Option<&Value>,
    ) -> IamResult<Record> {
        let team = load_team(tx, tenant_id, team_id).await?;
        match tx.get(teams_collection(), &team.id).await? {
            Some(record) => Ok(record),
            None => Ok(crate::port::encode(&team)),
        }
    }

    /// The direct members (any expiry or source) of a team and of every team below it.
    async fn members_below(&self, tx: &Store, team: &Record) -> IamResult<Vec<String>> {
        let tenant_id = s(team, "tenantId");
        let teams = self.all_teams(tx, tenant_id).await?;
        let mut scope: IndexSet<String> = IndexSet::new();
        scope.insert(s(team, "id").to_owned());
        for item in self.descendants(&teams, s(team, "id"))? {
            scope.insert(s(&item, "id").to_owned());
        }
        Ok(tx
            .find(
                members_collection(),
                &Filter::new().eq("tenantId", tenant_id),
                &find_all(),
            )
            .await?
            .into_iter()
            .filter(|member| scope.contains(s(member, "teamId")))
            .map(|member| s(&member, "identityId").to_owned())
            .collect())
    }

    async fn people<I: IntoIterator<Item = String>>(
        &self,
        tx: &Store,
        ids: I,
    ) -> IamResult<IndexMap<String, Value>> {
        let mut result = IndexMap::new();
        for identity_id in unique(ids) {
            let found = match tx.get("identities", &identity_id).await? {
                Some(identity) => person(&identity),
                None => unknown_person(&identity_id),
            };
            result.insert(identity_id, found);
        }
        Ok(result)
    }

    /// The person's live maintainer memberships that give standing over `team`: of the team itself or of a team
    /// above it, as long as no team from that one down to `team` takes membership changes from administrators only.
    async fn standing_memberships(
        &self,
        tx: &Store,
        identity_id: &str,
        team: &Record,
        now: f64,
    ) -> IamResult<Vec<Record>> {
        let tenant_id = s(team, "tenantId");
        let teams = self.all_teams(tx, tenant_id).await?;
        let mut scope: IndexSet<String> = IndexSet::new();
        for holder in self.chain(&teams, s(team, "id"))? {
            if s(&holder, "memberManagement") == "admins" {
                break;
            }
            scope.insert(s(&holder, "id").to_owned());
        }
        if scope.is_empty() {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        for member in tx
            .find(
                members_collection(),
                &Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("identityId", identity_id),
                &find_all(),
            )
            .await?
        {
            if s(&member, "role") == "maintainer"
                && live(&member, now)?
                && scope.contains(s(&member, "teamId"))
            {
                out.push(member);
            }
        }
        Ok(out)
    }

    /// Whether the principal may act on the team at `level` through membership rather than a permission.
    async fn team_standing(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        team: &Record,
        level: Level,
    ) -> IamResult<bool> {
        let tenant_id = s(team, "tenantId");
        if !own_user_session(principal, tenant_id) {
            return Ok(false);
        }
        let now = self.ctx.now();
        let maintains = !self
            .standing_memberships(tx, &principal.identity.id, team, now)
            .await?
            .is_empty();
        if maintains || level == Level::Maintainer {
            return Ok(maintains);
        }
        // Members see their team: a direct membership of it or of any team below it.
        let teams = teams_of(
            tx,
            tenant_id,
            &principal.identity.id,
            Some(&json!({ "at": number(now), "includeAncestors": true })),
        )
        .await?;
        Ok(teams.iter().any(|team_id| team_id == s(team, "id")))
    }

    /// The team-scoped envelope. A caller holding `action` on `iam/{teamId}` goes through the ordinary operation; a
    /// maintainer (or, for reads, a member) without it acts through the same transactional steps (separation of
    /// duties, invariants, plugin hooks) and is audited with `via: team-maintainer` / `team-member`.
    async fn team_operation<'a>(
        &'a self,
        credential: &'a CredentialInput,
        tenant_id: Option<&'a Value>,
        team_id_input: Option<&Value>,
        action: &'a str,
        level: Option<Level>,
        work: TeamWork<'a>,
    ) -> IamResult<Value> {
        let ctx = &self.ctx;
        let team_id = text(team_id_input, "teamId", 128)?;
        if let Some(level) = level {
            let authenticated = ctx.principals()?.authenticate(credential).await?;
            let tenant_text = tenant_id.and_then(Value::as_str).map(str::to_owned);
            let by_standing = ctx
                .store
                .transaction(|tx| {
                    let authenticated = &authenticated;
                    let team_id = &team_id;
                    let tenant_text = &tenant_text;
                    async move {
                        let principal = ctx
                            .principals()?
                            .current_principal(&tx, authenticated)
                            .await?;
                        let Some(team) = tx.get(teams_collection(), team_id).await? else {
                            return Ok(false);
                        };
                        let Some(tenant_id) = tenant_text
                            .as_deref()
                            .filter(|tenant_id| s(&team, "tenantId") == *tenant_id)
                        else {
                            return Ok(false);
                        };
                        if !self.team_standing(&tx, &principal, &team, level).await? {
                            return Ok(false);
                        }
                        let decision = match ctx.decisions() {
                            Ok(decisions) => {
                                decisions
                                    .decide(
                                        &tx,
                                        &principal,
                                        &AuthorizationRequest {
                                            credential: CredentialInput::default(),
                                            tenant_id: tenant_id.to_owned(),
                                            action: action.to_owned(),
                                            resource: ResourceTarget {
                                                kind: "iam".into(),
                                                id: s(&team, "id").to_owned(),
                                            },
                                        },
                                        true,
                                    )
                                    .await
                            }
                            Err(error) => Err(error),
                        };
                        // Standing stands in for a missing grant only: an explicit deny, a boundary, or a refused
                        // tenant or credential still refuses a maintainer, through the ordinary operation below.
                        Ok(match decision {
                            Ok(decision) => decision.reason == "NO_APPLICABLE_GRANT",
                            Err(_) => false,
                        })
                    }
                })
                .await?;
            if by_standing {
                let tenant_text = tenant_text.unwrap_or_default();
                return self
                    .standing_operation(authenticated, tenant_text, team_id, action, level, work)
                    .await;
            }
        }
        let team_id_owned = team_id.clone();
        let run = mutation(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| async move {
                let team = self
                    .load_team_record(&tx, &tenant.id, Some(&v(team_id_owned)))
                    .await?;
                work(TeamMutation {
                    tx,
                    principal,
                    tenant,
                    team,
                    via: Via::Permission,
                })
                .await
            },
        );
        ctx.operations()?
            .operation(credential, tenant_id, action, &team_id, run, false)
            .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn standing_operation<'a>(
        &'a self,
        authenticated: AuthenticatedPrincipal,
        tenant_id: String,
        team_id: String,
        action: &'a str,
        level: Level,
        work: TeamWork<'a>,
    ) -> IamResult<Value> {
        let ctx = &self.ctx;
        let authenticated = &authenticated;
        let tenant_ref = &tenant_id;
        let team_ref_id = &team_id;
        let run = async move {
            let outcome = ctx
                .store
                .transaction(move |tx| async move {
                    let principal = ctx
                        .principals()?
                        .current_principal(&tx, authenticated)
                        .await?;
                    let tenant = ctx.tenant(&tx, tenant_ref).await?;
                    let chain = ctx.ancestry(&tx, &tenant).await?;
                    let team = tx.get(teams_collection(), team_ref_id).await?;
                    let standing = match &team {
                        Some(found)
                            if chain.iter().all(|realm| {
                                realm.status == better_iam_core::TenantStatus::Active
                            }) && s(found, "tenantId") == tenant_ref =>
                        {
                            self.team_standing(&tx, &principal, found, level).await?
                        }
                        _ => false,
                    };
                    let Some(team) = team.filter(|_| standing) else {
                        ctx.events()?
                            .audit(
                                &tx,
                                &principal,
                                action,
                                tenant_ref,
                                team_ref_id,
                                AuditOutcome::Deny,
                                false,
                                None,
                            )
                            .await?;
                        return Ok(None);
                    };
                    let via = if level == Level::Maintainer {
                        Via::Maintainer
                    } else {
                        Via::Member
                    };
                    let hook = OperationHookInput {
                        store: tx.clone(),
                        principal: principal.clone(),
                        tenant_id: tenant_ref.clone(),
                        action: action.to_owned(),
                        resource_id: team_ref_id.clone(),
                    };
                    for plugin in &ctx.plugins {
                        if let Some(hooks) = plugin.hooks() {
                            hooks.before_operation(&hook).await?;
                        }
                    }
                    let separation = sod_snapshot(ctx, &tx, tenant_ref, action).await?;
                    let guardrails = invariant_snapshot(ctx, &tx, tenant_ref, action).await?;
                    let value = work(TeamMutation {
                        tx: tx.clone(),
                        principal: principal.clone(),
                        tenant,
                        team,
                        via,
                    })
                    .await
                    .map_err(IamError::from)?;
                    sod_verify(ctx, &tx, tenant_ref, separation.as_ref(), None).await?;
                    invariant_verify(ctx, &tx, tenant_ref, guardrails.as_ref()).await?;
                    for plugin in &ctx.plugins {
                        if let Some(hooks) = plugin.hooks() {
                            hooks.after_operation(&hook, &value).await?;
                        }
                    }
                    let mut metadata = Map::new();
                    metadata.insert("via".into(), v(format!("team-{}", via.as_str())));
                    ctx.events()?
                        .audit(
                            &tx,
                            &principal,
                            action,
                            tenant_ref,
                            team_ref_id,
                            AuditOutcome::Allow,
                            false,
                            Some(metadata),
                        )
                        .await?;
                    Ok(Some(value))
                })
                .await?;
            outcome.ok_or_else(|| access_denied("Access denied"))
        };
        ctx.observe
            .span(
                SpanKind::Operation,
                action,
                Some(&tenant_id),
                run,
                None,
                None,
            )
            .await
    }

    /// Self-service calls: an ordinary session of a person in their own organization.
    async fn self_service<'a, F, Fut>(
        &'a self,
        credential: &CredentialInput,
        tenant_id_input: Option<&Value>,
        run: F,
    ) -> IamResult<Value>
    where
        F: FnOnce(Store, AuthenticatedPrincipal, String) -> Fut + Send + 'a,
        Fut: Future<Output = IamResult<Value>> + Send + 'a,
    {
        let ctx = &self.ctx;
        let tenant_id = text(tenant_id_input, "tenantId", 256)?;
        let authenticated = ctx.principals()?.authenticate(credential).await?;
        let authenticated = &authenticated;
        ctx.store
            .transaction(move |tx| async move {
                let principal = ctx
                    .principals()?
                    .current_principal(&tx, authenticated)
                    .await?;
                require_own_session(&principal, &tenant_id)?;
                let tenant = ctx.tenant(&tx, &tenant_id).await?;
                let chain = ctx.ancestry(&tx, &tenant).await?;
                if chain
                    .iter()
                    .any(|realm| realm.status != better_iam_core::TenantStatus::Active)
                {
                    return Err(IamError::with_status(
                        "TENANT_INACTIVE",
                        "The organization is not active",
                        403,
                    ));
                }
                run(tx, principal, tenant_id).await
            })
            .await
    }

    async fn audit(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        action: &str,
        team: &Record,
        metadata: Map<String, Value>,
    ) -> IamResult<()> {
        let mut out = Map::new();
        out.insert("team".into(), v(s(team, "slug")));
        for (key, value) in metadata {
            out.insert(key, value);
        }
        self.ctx
            .events()?
            .audit(
                tx,
                principal,
                action,
                s(team, "tenantId"),
                s(team, "id"),
                AuditOutcome::Allow,
                false,
                Some(out),
            )
            .await
    }

    async fn email<I: IntoIterator<Item = String>>(
        &self,
        tx: &Store,
        tenant_id: &str,
        identity_ids: I,
        template: &str,
        payload: Map<String, Value>,
    ) -> IamResult<()> {
        let sends_email = self
            .ctx
            .options
            .authentication
            .as_ref()
            .is_some_and(|authentication| authentication.send_email.is_some());
        if !sends_email {
            return Ok(());
        }
        for identity_id in unique(identity_ids) {
            let Some(identity) = tx.get("identities", &identity_id).await? else {
                continue;
            };
            if !truthy(identity.get("email"))
                || s(&identity, "status") != "active"
                || s(&identity, "tenantId") != tenant_id
            {
                continue;
            }
            self.ctx
                .auth
                .enqueue_delivery(
                    tx,
                    EnqueueInput {
                        tenant_id: tenant_id.to_owned(),
                        kind: OutboxKind::Email,
                        to: s(&identity, "email").to_owned(),
                        template: template.to_owned(),
                        payload: payload.clone(),
                        reference: None,
                    },
                )
                .await?;
        }
        Ok(())
    }

    /// Administrators who grant through a team need authority over what the team's backing groups (and those of the
    /// teams above it) are bound to, exactly as adding someone to those groups would. Maintainers act under the
    /// delegation the team's administrators gave them and skip this.
    async fn assert_authority_over(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
        teams: &[Record],
    ) -> IamResult<()> {
        for team in teams {
            for binding in tx
                .find(
                    "bindings",
                    &Filter::new()
                        .eq("tenantId", tenant_id)
                        .eq("subjectType", "group")
                        .eq("subjectId", s(team, "groupId")),
                    &find_all(),
                )
                .await?
            {
                self.ctx
                    .granting_authority(tx, principal, tenant_id, opt_s(&binding, "authorityId"))
                    .await?;
            }
        }
        Ok(())
    }

    /// Whether `key` was already cleared in this transaction (and, with `mark`, records it).
    fn cleared(&self, tx: &Store, key: &str, mark: bool) -> bool {
        let mut cleared = self
            .cleared_licenses
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        cleared.retain(|(weak, _)| weak.strong_count() > 0);
        let position = cleared.iter().position(|(weak, _)| {
            weak.upgrade()
                .is_some_and(|live| std::ptr::addr_eq(Arc::as_ptr(&live), Arc::as_ptr(tx)))
        });
        match (position, mark) {
            (Some(index), true) => {
                cleared[index].1.insert(key.to_owned());
                true
            }
            (Some(index), false) => cleared[index].1.contains(key),
            (None, true) => {
                let mut keys = IndexSet::new();
                keys.insert(key.to_owned());
                cleared.push((Arc::downgrade(tx), keys));
                true
            }
            (None, false) => false,
        }
    }

    /// Administrators who put people into a team, keep them there longer, or appoint its maintainers claim license
    /// seats for them when a product is assigned to the backing group of the team or of a team above it (`teams`:
    /// that chain): that needs iam:licenses:assign, refused with `OperationDenied`. Checked once per caller and chain
    /// in a transaction, so batches ask once.
    async fn assert_may_claim_team_licenses(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
        teams: &[Record],
    ) -> OperationResult<()> {
        let key = format!(
            "{}:{}",
            principal.identity.id,
            teams
                .iter()
                .map(|team| s(team, "id"))
                .collect::<Vec<_>>()
                .join(",")
        );
        if self.cleared(tx, &key, false) {
            return Ok(());
        }
        let group_ids: Vec<Value> = teams.iter().map(|team| v(s(team, "groupId"))).collect();
        assert_may_claim_licenses(
            &self.ctx,
            tx,
            principal,
            tenant_id,
            &Value::Array(group_ids),
            Some(LICENSE_MESSAGE),
        )
        .await?;
        self.cleared(tx, &key, true);
        Ok(())
    }

    fn live_group_member(&self, membership: &Record) -> IamResult<bool> {
        let typed: GroupMember = decode(membership.clone())?;
        Ok(self.ctx.live_membership(&typed))
    }

    /// The backing groups of `team` and of the teams above it that hold the person right now.
    async fn held_chain_groups(
        &self,
        tx: &Store,
        team: &Record,
        identity_id: &str,
    ) -> IamResult<IndexSet<String>> {
        let tenant_id = s(team, "tenantId");
        let mut held = IndexSet::new();
        let teams = self.all_teams(tx, tenant_id).await?;
        for holder in self.chain(&teams, s(team, "id"))? {
            let membership = tx
                .find(
                    "groupMembers",
                    &Filter::new().eq("tenantId", tenant_id).eq(
                        "uniqueKey",
                        format!("{}:{}", s(&holder, "groupId"), identity_id),
                    ),
                    &find_all(),
                )
                .await?
                .into_iter()
                .next();
            if let Some(membership) = membership
                && self.live_group_member(&membership)?
            {
                held.insert(s(&holder, "groupId").to_owned());
            }
        }
        Ok(held)
    }

    /// People ending their own membership drop out of backing groups, and a deny bound to one of those groups stops
    /// applying to them: without the grant authority behind such a binding, an administrator removes the person.
    async fn assert_may_drop_denies<I: IntoIterator<Item = String>>(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
        group_ids: I,
    ) -> IamResult<()> {
        for group_id in unique(group_ids) {
            for binding in tx
                .find(
                    "bindings",
                    &Filter::new()
                        .eq("tenantId", tenant_id)
                        .eq("subjectType", "group")
                        .eq("subjectId", group_id.as_str()),
                    &find_all(),
                )
                .await?
            {
                let typed: Binding = decode(binding.clone())?;
                if self.ctx.expired_binding(&typed) || !role_holds_deny(tx, &typed.role_id).await? {
                    continue;
                }
                if self
                    .ctx
                    .granting_authority(tx, principal, tenant_id, opt_s(&binding, "authorityId"))
                    .await
                    .is_err()
                {
                    return Err(access_denied(
                        "This team carries a restriction (a deny) you cannot lift yourself; ask an administrator to remove you",
                    ));
                }
            }
        }
        Ok(())
    }

    async fn summaries(
        &self,
        tx: &Store,
        teams: &[Record],
        all: &[Record],
    ) -> IamResult<Vec<Map<String, Value>>> {
        let now = self.ctx.now();
        let tenant_ids = unique(teams.iter().map(|team| s(team, "tenantId").to_owned()));
        let mut members: IndexMap<String, Vec<Record>> = IndexMap::new();
        for tenant_id in &tenant_ids {
            for member in tx
                .find(
                    members_collection(),
                    &Filter::new().eq("tenantId", tenant_id.as_str()),
                    &find_all(),
                )
                .await?
            {
                if live(&member, now)? {
                    members
                        .entry(s(&member, "teamId").to_owned())
                        .or_default()
                        .push(member);
                }
            }
        }
        Ok(teams
            .iter()
            .map(|team| {
                summary(
                    team,
                    members.get(s(team, "id")).map(Vec::as_slice).unwrap_or(&[]),
                    all,
                )
            })
            .collect())
    }

    async fn detail(&self, tx: &Store, team: &Record) -> IamResult<Value> {
        let now = self.ctx.now();
        let tenant_id = s(team, "tenantId");
        let teams = self.all_teams(tx, tenant_id).await?;
        let all: Vec<Record> = teams.values().cloned().collect();
        let chain = self.chain(&teams, s(team, "id"))?;
        let mut base = self
            .summaries(tx, std::slice::from_ref(team), &all)
            .await?
            .into_iter()
            .next()
            .unwrap_or_default();
        let mut children: Vec<Record> = all
            .iter()
            .filter(|other| opt_s(other, "parentId") == Some(s(team, "id")))
            .cloned()
            .collect();
        children.sort_by(|a, b| locale_compare(s(a, "name"), s(b, "name")));
        let child_counts = self.summaries(tx, &children, &all).await?;
        let maintainer_ids = team_maintainers(tx, tenant_id, s(team, "id"), Some(now)).await?;
        let maintainers = self.people(tx, maintainer_ids.iter().cloned()).await?;
        let mut department: Option<Value> = None;
        if let Some(department_id) = opt_s(team, "departmentId").filter(|id| !id.is_empty())
            && let Some(found) = tx.get("departments", department_id).await?
            && s(&found, "tenantId") == tenant_id
        {
            let mut out = Map::new();
            out.insert("id".into(), found.get("id").cloned().unwrap_or_default());
            out.insert(
                "name".into(),
                found.get("name").cloned().unwrap_or_default(),
            );
            if truthy(found.get("code")) {
                out.insert(
                    "code".into(),
                    found.get("code").cloned().unwrap_or_default(),
                );
            }
            department = Some(Value::Object(out));
        }
        let mut total = 0usize;
        for member in tx
            .find(
                "groupMembers",
                &Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("groupId", s(team, "groupId")),
                &find_all(),
            )
            .await?
        {
            if self.live_group_member(&member)? {
                total += 1;
            }
        }
        let mut roles: Vec<Value> = Vec::new();
        for holder in &chain {
            for binding in tx
                .find(
                    "bindings",
                    &Filter::new()
                        .eq("tenantId", tenant_id)
                        .eq("subjectType", "group")
                        .eq("subjectId", s(holder, "groupId")),
                    &find_all(),
                )
                .await?
            {
                let typed: Binding = decode(binding.clone())?;
                if self.ctx.expired_binding(&typed) {
                    continue;
                }
                let role = tx.get("roles", &typed.role_id).await?;
                let mut grant = Map::new();
                grant.insert(
                    "bindingId".into(),
                    binding.get("id").cloned().unwrap_or_default(),
                );
                grant.insert(
                    "roleId".into(),
                    binding.get("roleId").cloned().unwrap_or_default(),
                );
                grant.insert(
                    "roleName".into(),
                    role.as_ref()
                        .and_then(|role| role.get("name"))
                        .filter(|name| !name.is_null())
                        .cloned()
                        .unwrap_or_else(|| v(typed.role_id.clone())),
                );
                grant.insert("team".into(), team_ref(holder));
                grant.insert(
                    "inherited".into(),
                    Value::Bool(s(holder, "id") != s(team, "id")),
                );
                if typed.eligible == Some(true) {
                    grant.insert("eligible".into(), Value::Bool(true));
                }
                if let Some(starts_at) = binding.get("startsAt") {
                    grant.insert("startsAt".into(), starts_at.clone());
                }
                if let Some(expires_at) = binding.get("expiresAt") {
                    grant.insert("expiresAt".into(), expires_at.clone());
                }
                roles.push(Value::Object(grant));
            }
        }
        let path: Vec<Value> = chain.iter().skip(1).rev().map(team_ref).collect();
        base.insert("path".into(), Value::Array(path));
        base.insert(
            "children".into(),
            Value::Array(
                children
                    .iter()
                    .enumerate()
                    .map(|(index, child)| {
                        let mut out = team_ref_map(child);
                        out.insert(
                            "memberCount".into(),
                            child_counts
                                .get(index)
                                .and_then(|counts| counts.get("memberCount"))
                                .cloned()
                                .unwrap_or_default(),
                        );
                        Value::Object(out)
                    })
                    .collect(),
            ),
        );
        if let Some(department) = department {
            base.insert("department".into(), department);
        }
        base.insert(
            "maintainers".into(),
            Value::Array(
                maintainer_ids
                    .iter()
                    .map(|identity_id| maintainers.get(identity_id).cloned().unwrap_or_default())
                    .collect(),
            ),
        );
        base.insert("totalMemberCount".into(), number(total as f64));
        base.insert("roles".into(), Value::Array(roles));
        let mut sync_groups = Vec::new();
        for group_id in string_array(team, "syncGroupIds") {
            let name = tx
                .get("groups", &group_id)
                .await?
                .and_then(|group| group.get("name").filter(|name| !name.is_null()).cloned())
                .unwrap_or_else(|| v(group_id.clone()));
            sync_groups.push(json!({ "id": group_id, "name": name }));
        }
        base.insert("syncGroups".into(), Value::Array(sync_groups));
        Ok(Value::Object(base))
    }

    async fn request_view(&self, tx: &Store, request: &Record) -> IamResult<Value> {
        let team = tx.get(teams_collection(), s(request, "teamId")).await?;
        let requester = tx.get("identities", s(request, "identityId")).await?;
        let mut out = request.clone();
        for key in ["uniqueKey", "tenantId", "teamId", "identityId"] {
            out.shift_remove(key);
        }
        out.insert("id".into(), request.get("id").cloned().unwrap_or_default());
        out.insert(
            "team".into(),
            match &team {
                Some(team) => team_ref(team),
                None => {
                    json!({ "id": s(request, "teamId"), "name": s(request, "teamId"), "slug": "" })
                }
            },
        );
        out.insert(
            "requester".into(),
            match &requester {
                Some(identity) => person(identity),
                None => unknown_person(s(request, "identityId")),
            },
        );
        Ok(Value::Object(out))
    }

    /// A slug that no other team of the tenant uses.
    async fn free_slug(
        &self,
        tx: &Store,
        tenant_id: &str,
        slug: &str,
        except_id: Option<&str>,
    ) -> IamResult<String> {
        let taken = tx
            .find(
                teams_collection(),
                &Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("uniqueKey", format!("slug:{slug}")),
                &find_all(),
            )
            .await?
            .iter()
            .any(|team| Some(s(team, "id")) != except_id);
        if taken {
            return Err(IamError::with_status(
                "CONFLICT",
                format!("A team with the slug {slug} exists"),
                409,
            ));
        }
        Ok(slug.to_owned())
    }

    /// A person who can belong to a team: an active person (not a service account or agent) of the tenant.
    async fn team_person(
        &self,
        tx: &Store,
        tenant_id: &str,
        identity_id: Option<&Value>,
    ) -> IamResult<better_iam_core::Identity> {
        let identity = self
            .ctx
            .active_identity(tx, &text(identity_id, "identityId", 128)?, tenant_id)
            .await?;
        if identity.kind != better_iam_core::IdentityKind::User {
            return Err(invalid_input(
                "Teams hold people; service accounts and agents cannot join",
            ));
        }
        if identity.status != better_iam_core::IdentityStatus::Active {
            return Err(invalid_input("Only active people can join a team"));
        }
        Ok(identity)
    }

    /// Adds or re-adds a direct member, then refreshes the backing groups. Shared by add, approve, create and
    /// configuration sync. An administrator (`via: 'permission'`) needs iam:licenses:assign when the team's chain
    /// carries license seats.
    async fn put_member(
        &self,
        mutation: &TeamMutation,
        input: &Map<String, Value>,
        source: &str,
    ) -> OperationResult<Record> {
        let ctx = &self.ctx;
        let TeamMutation {
            tx,
            principal,
            team,
            via,
            ..
        } = mutation;
        let tenant_id = s(team, "tenantId");
        let team_id = s(team, "id");
        let identity = self
            .team_person(tx, tenant_id, input.get("identityId"))
            .await?;
        let role = match input.get("role") {
            None => "member".to_owned(),
            Some(role) => choice(Some(role), TEAM_ROLES, "role")?,
        };
        let expires_at = match input.get("expiresAt") {
            None | Some(Value::Null) => None,
            Some(value) => Some(ctx.binding_expiry(Some(value))?),
        };
        if *via == Via::Permission {
            let teams = self.all_teams(tx, tenant_id).await?;
            self.assert_may_claim_team_licenses(
                tx,
                principal,
                tenant_id,
                &self.chain(&teams, team_id)?,
            )
            .await?;
        }
        let unique_key = format!("{team_id}:{}", identity.id);
        let existing = tx
            .find(
                members_collection(),
                &Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("uniqueKey", unique_key.as_str()),
                &find_all(),
            )
            .await?
            .into_iter()
            .next();
        let now = ctx.now();
        if let Some(existing) = &existing
            && live(existing, now)?
        {
            return Err(IamError::with_status(
                "CONFLICT",
                format!("{} is already in this team", identity.name),
                409,
            )
            .into());
        }
        // A maintainer adding themselves (to a team below the one they maintain) may not outlast their own standing.
        if *via == Via::Maintainer && identity.id == principal.identity.id {
            let standing = self
                .standing_memberships(tx, &identity.id, team, now)
                .await?;
            let ends = if standing
                .iter()
                .any(|member| member.get("expiresAt").is_none())
            {
                None
            } else {
                Some(
                    standing
                        .iter()
                        .map(|member| num(member, "expiresAt").unwrap_or(f64::NAN))
                        .fold(f64::NEG_INFINITY, js_max),
                )
            };
            if let Some(ends) = ends
                && expires_at.is_none_or(|expires_at| expires_at > ends)
            {
                return Err(access_denied(
                    "Maintainers cannot add themselves for longer than they maintain the team; ask an administrator",
                )
                .into());
            }
        }
        let mut record = Map::new();
        record.insert(
            "id".into(),
            existing
                .as_ref()
                .and_then(|existing| existing.get("id").cloned())
                .unwrap_or_else(|| v(id())),
        );
        record.insert("tenantId".into(), v(tenant_id));
        record.insert("uniqueKey".into(), v(unique_key.clone()));
        record.insert("teamId".into(), v(team_id));
        record.insert("identityId".into(), v(identity.id.clone()));
        record.insert("role".into(), v(role.clone()));
        record.insert("addedAt".into(), number(now));
        record.insert("addedBy".into(), v(principal.identity.id.clone()));
        if let Some(expires_at) = expires_at {
            record.insert("expiresAt".into(), number(expires_at));
        }
        if existing.is_some() {
            tx.put(members_collection(), &record).await?;
        } else {
            tx.insert(members_collection(), &record).await?;
        }
        sync_team_groups(tx, tenant_id, &json!([team_id]), now).await?;
        // A pending request of theirs is settled by the membership.
        for request in tx
            .find(
                requests_collection(),
                &Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("teamId", team_id)
                    .eq("identityId", identity.id.as_str())
                    .eq("status", "pending"),
                &find_all(),
            )
            .await?
        {
            if source != "approve" {
                let mut settled = request.clone();
                settled.insert("status".into(), v("approved"));
                settled.insert("decidedBy".into(), v(principal.identity.id.clone()));
                settled.insert("decidedAt".into(), number(now));
                tx.put(requests_collection(), &settled).await?;
            }
        }
        let mut metadata = Map::new();
        metadata.insert("identityId".into(), v(identity.id.clone()));
        metadata.insert("role".into(), v(role));
        metadata.insert("source".into(), v(source));
        if let Some(expires_at) = expires_at {
            metadata.insert("expiresAt".into(), number(expires_at));
        }
        if *via != Via::Permission {
            metadata.insert("via".into(), v(via.as_str()));
        }
        self.audit(tx, principal, "team:member:add", team, metadata)
            .await?;
        Ok(record)
    }

    async fn member_record(
        &self,
        tx: &Store,
        team: &Record,
        identity_id: Option<&Value>,
    ) -> IamResult<Record> {
        let unique_key = format!(
            "{}:{}",
            s(team, "id"),
            text(identity_id, "identityId", 128)?
        );
        let member = tx
            .find(
                members_collection(),
                &Filter::new()
                    .eq("tenantId", s(team, "tenantId"))
                    .eq("uniqueKey", unique_key),
                &find_all(),
            )
            .await?
            .into_iter()
            .next();
        match member {
            Some(member) if live(&member, self.ctx.now())? => Ok(member),
            _ => Err(IamError::with_status(
                "NOT_FOUND",
                "Not a member of this team",
                404,
            )),
        }
    }

    async fn remove_member(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        team: &Record,
        member: &Record,
        action: &str,
        via: Option<&str>,
    ) -> IamResult<()> {
        tx.delete(members_collection(), s(member, "id")).await?;
        sync_team_groups(
            tx,
            s(team, "tenantId"),
            &json!([s(team, "id")]),
            self.ctx.now(),
        )
        .await?;
        let mut metadata = Map::new();
        metadata.insert(
            "identityId".into(),
            member.get("identityId").cloned().unwrap_or_default(),
        );
        metadata.insert(
            "role".into(),
            member.get("role").cloned().unwrap_or_default(),
        );
        if let Some(via) = via.filter(|via| !via.is_empty() && *via != "permission") {
            metadata.insert("via".into(), v(via));
        }
        self.audit(tx, principal, action, team, metadata).await
    }

    /// The chain a parent brings: its own chain, checked for depth against the subtree that moves under it.
    fn parent_chain(
        &self,
        teams: &Teams,
        parent: &Record,
        subtree_height: usize,
    ) -> IamResult<Vec<Record>> {
        let chain = self.chain(teams, s(parent, "id"))?;
        if (chain.len() + subtree_height) as f64 > MAX_TEAM_DEPTH {
            return Err(invalid_input(format!(
                "Teams nest at most {} levels deep",
                crate::js::number_to_string(MAX_TEAM_DEPTH)
            )));
        }
        Ok(chain)
    }

    fn subtree_height(&self, teams: &Teams, team: &Record) -> IamResult<usize> {
        let mut height = 1usize;
        for descendant in self.descendants(teams, s(team, "id"))? {
            let position = self
                .chain(teams, s(&descendant, "id"))?
                .iter()
                .position(|item| s(item, "id") == s(team, "id"));
            // `findIndex(...) + 1`: 0 when the team is not in the chain.
            let depth = position.map_or(0, |index| index + 1);
            height = height.max(depth);
        }
        Ok(height)
    }

    /// Moving a team (or creating one) under a parent: the caller must be able to manage the parent and grant its
    /// access.
    async fn assert_can_nest_under(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
        chain: &[Record],
    ) -> IamResult<()> {
        let parent = chain.first().cloned().unwrap_or_default();
        let decision = self
            .ctx
            .decisions()?
            .decide(
                tx,
                principal,
                &AuthorizationRequest {
                    credential: CredentialInput::default(),
                    tenant_id: tenant_id.to_owned(),
                    action: "iam:teams:update".into(),
                    resource: ResourceTarget {
                        kind: "iam".into(),
                        id: s(&parent, "id").to_owned(),
                    },
                },
                true,
            )
            .await?;
        if !decision.allowed {
            return Err(access_denied(&format!(
                "Placing a team under {} needs iam:teams:update on it",
                s(&parent, "name")
            )));
        }
        // Members of the nested team join the parent's groups, so its bindings must be within the caller's authority.
        self.assert_authority_over(tx, principal, tenant_id, chain)
            .await
    }

    /// Creates a team with its backing group (and maintainers); the caller has authorized `iam:teams:create`.
    async fn create_team(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant: &Tenant,
        input: &Map<String, Value>,
    ) -> OperationResult<Record> {
        let ctx = &self.ctx;
        let name = crate::js::trim(&text(input.get("name"), "name", 100)?).to_owned();
        let existing = self.all_teams(tx, &tenant.id).await?;
        if existing.len() as f64 >= MAX_TEAMS {
            return Err(IamError::with_status(
                "LIMIT_EXCEEDED",
                format!("At most {} teams", crate::js::number_to_string(MAX_TEAMS)),
                409,
            )
            .into());
        }
        let derived = match input.get("slug") {
            None => slug_from_name(&name)?,
            Some(slug) => Some(team_slug(Some(slug))?),
        };
        let Some(derived) = derived.filter(|slug| !slug.is_empty()) else {
            return Err(invalid_input("Choose a slug: the name has no letters or digits").into());
        };
        let slug = self.free_slug(tx, &tenant.id, &derived, None).await?;
        let mut chain: Vec<Record> = Vec::new();
        if let Some(parent_id) = input.get("parentId") {
            let parent = self
                .load_team_record(tx, &tenant.id, Some(parent_id))
                .await?;
            chain = self.parent_chain(&existing, &parent, 1)?;
            self.assert_can_nest_under(tx, principal, &tenant.id, &chain)
                .await?;
        }
        if let Some(department_id) = input.get("departmentId") {
            load_department(tx, &tenant.id, Some(department_id)).await?;
        }
        let maintainer_ids = unique(match input.get("maintainerIds") {
            None => Vec::new(),
            Some(ids) => strings(Some(ids), "maintainerIds")?,
        });
        if maintainer_ids.len() > MAX_MAINTAINERS_ON_CREATE {
            return Err(invalid_input(format!(
                "Name at most {MAX_MAINTAINERS_ON_CREATE} maintainers when creating a team"
            ))
            .into());
        }
        let sync_group_ids = match input.get("syncGroupIds") {
            None => Vec::new(),
            Some(ids) => team_sync_groups(tx, &tenant.id, Some(ids)).await?,
        };
        let now = ctx.now();
        let mut group_input = Map::new();
        group_input.insert("tenantId".into(), v(tenant.id.clone()));
        group_input.insert("name".into(), v(format!("team:{slug}")));
        group_input.insert(
            "description".into(),
            v(format!("Members of team {name} (managed by the team)")),
        );
        let mut group = create_group_record(ctx, tx, tenant, &group_input).await?;
        let mut team = Map::new();
        team.insert("id".into(), v(id()));
        team.insert("tenantId".into(), v(tenant.id.clone()));
        team.insert("uniqueKey".into(), v(format!("slug:{slug}")));
        team.insert("name".into(), v(name.clone()));
        team.insert("slug".into(), v(slug.clone()));
        if let Some(description) = input
            .get("description")
            .filter(|description| description.as_str() != Some(""))
        {
            team.insert(
                "description".into(),
                v(text(Some(description), "description", 512)?),
            );
        }
        if input.get("parentId").is_some() {
            let parent = chain.first().cloned().unwrap_or_default();
            team.insert("parentId".into(), v(s(&parent, "id")));
        }
        if let Some(department_id) = input.get("departmentId") {
            team.insert("departmentId".into(), department_id.clone());
        }
        team.insert(
            "groupId".into(),
            group.get("id").cloned().unwrap_or_default(),
        );
        team.insert(
            "joinPolicy".into(),
            v(match input.get("joinPolicy") {
                None => "closed".to_owned(),
                Some(policy) => choice(Some(policy), JOIN_POLICIES, "joinPolicy")?,
            }),
        );
        team.insert(
            "memberManagement".into(),
            v(match input.get("memberManagement") {
                None => "maintainers".to_owned(),
                Some(mode) => choice(Some(mode), MANAGEMENT_MODES, "memberManagement")?,
            }),
        );
        if !sync_group_ids.is_empty() {
            team.insert("syncGroupIds".into(), json!(sync_group_ids));
        }
        team.insert("createdAt".into(), number(now));
        team.insert("createdBy".into(), v(principal.identity.id.clone()));
        team.insert("updatedAt".into(), number(now));
        group.insert("teamId".into(), team.get("id").cloned().unwrap_or_default());
        tx.put("groups", &group).await?;
        tx.insert(teams_collection(), &team).await?;
        let mutation = TeamMutation {
            tx: tx.clone(),
            principal: principal.clone(),
            tenant: tenant.clone(),
            team: team.clone(),
            via: Via::Permission,
        };
        for identity_id in &maintainer_ids {
            let mut member = Map::new();
            member.insert("identityId".into(), v(identity_id.clone()));
            member.insert("role".into(), v("maintainer"));
            self.put_member(&mutation, &member, "create").await?;
        }
        if !sync_group_ids.is_empty() {
            // Syncing brings the source groups' members into the teams above it too.
            let mut scope = vec![team.clone()];
            scope.extend(chain.iter().cloned());
            self.assert_may_claim_team_licenses(tx, principal, &tenant.id, &scope)
                .await?;
            sync_teams_from_groups(
                ctx,
                tx,
                &tenant.id,
                &json!({ "teamIds": [s(&team, "id")], "actorId": principal.identity.id }),
            )
            .await?;
        }
        let mut metadata = Map::new();
        metadata.insert("name".into(), v(name));
        if truthy(team.get("parentId")) {
            metadata.insert(
                "parentId".into(),
                team.get("parentId").cloned().unwrap_or_default(),
            );
        }
        self.audit(tx, principal, "team:create", &team, metadata)
            .await?;
        Ok(team)
    }

    /// Changes a team's settings or place; the caller has authorized `iam:teams:update` on it.
    async fn update_team(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        team: &Record,
        input: &Map<String, Value>,
    ) -> OperationResult<Record> {
        let ctx = &self.ctx;
        if UPDATE_KEYS.iter().all(|key| input.get(*key).is_none()) {
            return Err(invalid_input("Nothing to update").into());
        }
        let tenant_id = s(team, "tenantId").to_owned();
        let team_id = s(team, "id").to_owned();
        let teams = self.all_teams(tx, &tenant_id).await?;
        let mut next = team.clone();
        next.insert("updatedAt".into(), number(ctx.now()));
        if let Some(name) = input.get("name") {
            next.insert(
                "name".into(),
                v(crate::js::trim(&text(Some(name), "name", 100)?)),
            );
        }
        if let Some(slug) = input.get("slug")
            && slug.as_str() != Some(s(team, "slug"))
        {
            let slug = self
                .free_slug(tx, &tenant_id, &team_slug(Some(slug))?, Some(&team_id))
                .await?;
            next.insert("uniqueKey".into(), v(format!("slug:{slug}")));
            next.insert("slug".into(), v(slug));
        }
        if let Some(description) = input.get("description") {
            next.shift_remove("description");
            if !description.is_null() && description.as_str() != Some("") {
                next.insert(
                    "description".into(),
                    v(text(Some(description), "description", 512)?),
                );
            }
        }
        if let Some(department_id) = input.get("departmentId") {
            next.shift_remove("departmentId");
            if !department_id.is_null() {
                load_department(tx, &tenant_id, Some(department_id)).await?;
                next.insert("departmentId".into(), department_id.clone());
            }
        }
        if let Some(policy) = input.get("joinPolicy") {
            next.insert(
                "joinPolicy".into(),
                v(choice(Some(policy), JOIN_POLICIES, "joinPolicy")?),
            );
        }
        if let Some(mode) = input.get("memberManagement") {
            next.insert(
                "memberManagement".into(),
                v(choice(Some(mode), MANAGEMENT_MODES, "memberManagement")?),
            );
        }
        if let Some(sync) = input.get("syncGroupIds") {
            next.shift_remove("syncGroupIds");
            let sources = if sync.is_null() {
                Vec::new()
            } else {
                team_sync_groups(tx, &tenant_id, Some(sync)).await?
            };
            if !sources.is_empty() {
                next.insert("syncGroupIds".into(), json!(sources));
            }
            // Syncing brings people in, and with them what the team and the teams above it hold.
            let previous = string_array(team, "syncGroupIds");
            if sources.iter().any(|group_id| !previous.contains(group_id)) {
                let chain = self.chain(&teams, &team_id)?;
                self.assert_authority_over(tx, principal, &tenant_id, &chain)
                    .await?;
                self.assert_may_claim_team_licenses(tx, principal, &tenant_id, &chain)
                    .await?;
            }
        }
        let previous_parent = opt_s(team, "parentId").map(str::to_owned);
        if let Some(parent_id) = input.get("parentId") {
            let differs = if parent_id.is_null() {
                team.get("parentId").is_some()
            } else {
                Some(parent_id) != team.get("parentId")
            };
            if differs {
                next.shift_remove("parentId");
                if !parent_id.is_null() {
                    let parent = self
                        .load_team_record(tx, &tenant_id, Some(parent_id))
                        .await?;
                    let below = self.descendants(&teams, &team_id)?;
                    if s(&parent, "id") == team_id
                        || below.iter().any(|item| s(item, "id") == s(&parent, "id"))
                    {
                        return Err(invalid_input(
                            "A team cannot move under itself or its own team",
                        )
                        .into());
                    }
                    let chain =
                        self.parent_chain(&teams, &parent, self.subtree_height(&teams, team)?)?;
                    self.assert_can_nest_under(tx, principal, &tenant_id, &chain)
                        .await?;
                    // The new parent's maintainers gain standing over the moved team and every team below it, so
                    // moving them hands out what those teams hold: it needs the same authority as adding someone
                    // to them.
                    let mut moved = vec![team.clone()];
                    moved.extend(below.iter().cloned());
                    self.assert_authority_over(tx, principal, &tenant_id, &moved)
                        .await?;
                    // Its members claim the seats of the new chain, and the new parent's maintainers hand out the
                    // moved teams'.
                    let mut claimed = chain.clone();
                    claimed.extend(moved.iter().cloned());
                    self.assert_may_claim_team_licenses(tx, principal, &tenant_id, &claimed)
                        .await?;
                    next.insert("parentId".into(), v(s(&parent, "id")));
                }
            }
        }
        // Opening an admins-only team to its maintainers lets them grant what it and the teams above it hold.
        if s(team, "memberManagement") == "admins" && s(&next, "memberManagement") != "admins" {
            let mut opened = vec![team.clone()];
            if let Some(parent_id) = opt_s(&next, "parentId").filter(|id| !id.is_empty()) {
                opened.extend(self.chain(&teams, parent_id)?);
            }
            self.assert_authority_over(tx, principal, &tenant_id, &opened)
                .await?;
            self.assert_may_claim_team_licenses(tx, principal, &tenant_id, &opened)
                .await?;
        }
        tx.put(teams_collection(), &next).await?;
        if (next.get("slug") != team.get("slug") || next.get("name") != team.get("name"))
            && let Some(mut group) = tx.get("groups", s(team, "groupId")).await?
        {
            group.insert("name".into(), v(format!("team:{}", s(&next, "slug"))));
            group.insert(
                "description".into(),
                v(format!(
                    "Members of team {} (managed by the team)",
                    s(&next, "name")
                )),
            );
            tx.put("groups", &group).await?;
        }
        let next_parent = opt_s(&next, "parentId").map(str::to_owned);
        if next_parent != previous_parent {
            let mut ids = vec![team_id.clone()];
            if let Some(previous) = previous_parent.clone().filter(|id| !id.is_empty()) {
                ids.push(previous);
            }
            sync_team_groups(tx, &tenant_id, &json!(ids), ctx.now()).await?;
        }
        if input.get("syncGroupIds").is_some() {
            sync_teams_from_groups(
                ctx,
                tx,
                &tenant_id,
                &json!({ "teamIds": [team_id], "actorId": principal.identity.id }),
            )
            .await?;
        }
        let mut metadata = Map::new();
        metadata.insert(
            "fields".into(),
            json!(
                UPDATE_KEYS
                    .iter()
                    .filter(|key| input.get(**key).is_some())
                    .collect::<Vec<_>>()
            ),
        );
        if next_parent != previous_parent {
            metadata.insert("parentId".into(), json!(next_parent));
            metadata.insert("previousParentId".into(), json!(previous_parent));
        }
        self.audit(tx, principal, "team:update", &next, metadata)
            .await?;
        Ok(next)
    }

    /// Deletes a team with its memberships, requests, and backing group; returns how many members it had.
    async fn delete_team(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        team: &Record,
    ) -> IamResult<usize> {
        let ctx = &self.ctx;
        let tenant_id = s(team, "tenantId");
        let team_id = s(team, "id");
        let children: Vec<String> = tx
            .find(
                teams_collection(),
                &Filter::new().eq("tenantId", tenant_id),
                &find_all(),
            )
            .await?
            .iter()
            .filter(|other| opt_s(other, "parentId") == Some(team_id))
            .map(|other| s(other, "name").to_owned())
            .collect();
        if !children.is_empty() {
            return Err(IamError::with_status(
                "RESOURCE_IN_USE",
                format!(
                    "Move or delete the teams below it first: {}",
                    children.join(", ")
                ),
                409,
            ));
        }
        // A team a birthright rule names stays until the package stops naming it (like groups).
        let naming = packages_naming(
            tx,
            tenant_id,
            "identity.teams",
            &[team_id.to_owned()],
            Some(&[s(team, "groupId").to_owned()]),
        )
        .await?;
        if !naming.is_empty() {
            return Err(IamError::with_status(
                "RESOURCE_IN_USE",
                format!("Access packages name it in a rule: {}", naming.join(", ")),
                409,
            ));
        }
        let members = tx
            .find(
                members_collection(),
                &Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("teamId", team_id),
                &find_all(),
            )
            .await?;
        for member in &members {
            tx.delete(members_collection(), s(member, "id")).await?;
        }
        for request in tx
            .find(
                requests_collection(),
                &Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("teamId", team_id),
                &find_all(),
            )
            .await?
        {
            tx.delete(requests_collection(), s(&request, "id")).await?;
        }
        // Membership reviews go with the team (their outcome stays in the audit trail).
        for collection in [items_collection(), reviews_collection()] {
            for record in tx
                .find(
                    collection,
                    &Filter::new()
                        .eq("tenantId", tenant_id)
                        .eq("teamId", team_id),
                    &find_all(),
                )
                .await?
            {
                tx.delete(collection, s(&record, "id")).await?;
            }
        }
        if let Some(group) = tx.get("groups", s(team, "groupId")).await? {
            delete_group_record(ctx, tx, principal, &group).await?;
        }
        tx.delete(teams_collection(), team_id).await?;
        if let Some(parent_id) = opt_s(team, "parentId").filter(|id| !id.is_empty()) {
            sync_team_groups(tx, tenant_id, &json!([parent_id]), ctx.now()).await?;
        }
        let mut metadata = Map::new();
        metadata.insert("name".into(), team.get("name").cloned().unwrap_or_default());
        metadata.insert("members".into(), number(members.len() as f64));
        self.audit(tx, principal, "team:delete", team, metadata)
            .await?;
        Ok(members.len())
    }

    /// Routing only: the team a review belongs to (the operation re-reads and checks the review under
    /// authorization).
    async fn review_team_id(
        &self,
        tenant_id_input: Option<&Value>,
        review_id_input: Option<&Value>,
    ) -> IamResult<String> {
        let tenant_id = text(tenant_id_input, "tenantId", 256)?;
        let review_id = text(review_id_input, "reviewId", 128)?;
        self.ctx
            .store
            .transaction(move |tx| async move {
                let review = tx.get(reviews_collection(), &review_id).await?;
                Ok(match review {
                    Some(review) if s(&review, "tenantId") == tenant_id => {
                        s(&review, "teamId").to_owned()
                    }
                    _ => review_id,
                })
            })
            .await
    }

    async fn load_review(
        &self,
        tx: &Store,
        team: &Record,
        review_id: Option<&Value>,
    ) -> IamResult<Record> {
        let review = tx
            .get(reviews_collection(), &text(review_id, "reviewId", 128)?)
            .await?;
        match review {
            Some(review)
                if s(&review, "tenantId") == s(team, "tenantId")
                    && s(&review, "teamId") == s(team, "id") =>
            {
                Ok(review)
            }
            _ => Err(not_found()),
        }
    }

    async fn review_view(
        &self,
        tx: &Store,
        review: &Record,
        team: &Record,
        with_items: bool,
    ) -> IamResult<Value> {
        let mut items = tx
            .find(
                items_collection(),
                &Filter::new()
                    .eq("tenantId", s(review, "tenantId"))
                    .eq("reviewId", s(review, "id")),
                &find_all(),
            )
            .await?;
        // `(a.identityId < b.identityId ? -1 : 1)`: identity IDs are unique within a review.
        items.sort_by(|a, b| cmp_utf16(s(a, "identityId"), s(b, "identityId")));
        let mut ids = vec![s(review, "startedBy").to_owned()];
        for item in &items {
            ids.push(s(item, "identityId").to_owned());
            if truthy(item.get("decidedBy")) {
                ids.push(s(item, "decidedBy").to_owned());
            }
        }
        let directory = self.people(tx, ids).await?;
        let mut counts: IndexMap<String, f64> = IndexMap::new();
        counts.insert("total".into(), items.len() as f64);
        counts.insert("keep".into(), 0.0);
        counts.insert("remove".into(), 0.0);
        counts.insert("undecided".into(), 0.0);
        for item in &items {
            let key = match item.get("decision").filter(|decision| !decision.is_null()) {
                Some(decision) => crate::js::js_string(Some(decision)),
                None => "undecided".to_owned(),
            };
            // `counts[key]++`: a key the counts do not have becomes NaN.
            let entry = counts.entry(key).or_insert(f64::NAN);
            *entry += 1.0;
        }
        let mut out = Map::new();
        out.insert("id".into(), review.get("id").cloned().unwrap_or_default());
        out.insert("team".into(), team_ref(team));
        out.insert(
            "status".into(),
            review.get("status").cloned().unwrap_or_default(),
        );
        out.insert(
            "onUndecided".into(),
            review.get("onUndecided").cloned().unwrap_or_default(),
        );
        out.insert(
            "startedAt".into(),
            review.get("startedAt").cloned().unwrap_or_default(),
        );
        out.insert(
            "startedBy".into(),
            directory
                .get(s(review, "startedBy"))
                .cloned()
                .unwrap_or_default(),
        );
        out.insert(
            "dueAt".into(),
            review.get("dueAt").cloned().unwrap_or_default(),
        );
        if truthy(review.get("note")) {
            out.insert(
                "note".into(),
                review.get("note").cloned().unwrap_or_default(),
            );
        }
        if let Some(completed_at) = review.get("completedAt") {
            out.insert("completedAt".into(), completed_at.clone());
        }
        if truthy(review.get("completedBy")) {
            out.insert(
                "completedBy".into(),
                review.get("completedBy").cloned().unwrap_or_default(),
            );
        }
        if truthy(review.get("outcome")) {
            out.insert(
                "outcome".into(),
                review.get("outcome").cloned().unwrap_or_default(),
            );
        }
        out.insert(
            "counts".into(),
            Value::Object(
                counts
                    .into_iter()
                    .map(|(key, count)| (key, number(count)))
                    .collect(),
            ),
        );
        if with_items {
            let mut views: Vec<Value> = items
                .iter()
                .map(|item| {
                    let mut view = Map::new();
                    view.insert(
                        "person".into(),
                        directory
                            .get(s(item, "identityId"))
                            .cloned()
                            .unwrap_or_default(),
                    );
                    view.insert("role".into(), item.get("role").cloned().unwrap_or_default());
                    if truthy(item.get("decision")) {
                        view.insert(
                            "decision".into(),
                            item.get("decision").cloned().unwrap_or_default(),
                        );
                    }
                    if truthy(item.get("decidedBy")) {
                        view.insert(
                            "decidedBy".into(),
                            directory
                                .get(s(item, "decidedBy"))
                                .cloned()
                                .unwrap_or_default(),
                        );
                    }
                    if let Some(decided_at) = item.get("decidedAt") {
                        view.insert("decidedAt".into(), decided_at.clone());
                    }
                    if truthy(item.get("note")) {
                        view.insert("note".into(), item.get("note").cloned().unwrap_or_default());
                    }
                    Value::Object(view)
                })
                .collect();
            views.sort_by(|a, b| by_role_then_name(a, b, view_person));
            out.insert("items".into(), Value::Array(views));
        }
        Ok(Value::Object(out))
    }

    /// A pending request past its lapse time reads as expired.
    fn lapse(&self, request: &Record) -> Record {
        if s(request, "status") == "pending"
            && num(request, "expiresAt").is_some_and(|expires_at| expires_at <= self.ctx.now())
        {
            let mut lapsed = request.clone();
            lapsed.insert("status".into(), v("expired"));
            lapsed
        } else {
            request.clone()
        }
    }

    async fn memberships_of(
        &self,
        tx: &Store,
        tenant_id: &str,
        identity_id: &str,
    ) -> IamResult<Vec<Value>> {
        let now = self.ctx.now();
        let teams = self.all_teams(tx, tenant_id).await?;
        let mut out: Vec<(String, Value)> = Vec::new();
        for member in tx
            .find(
                members_collection(),
                &Filter::new()
                    .eq("tenantId", tenant_id)
                    .eq("identityId", identity_id),
                &find_all(),
            )
            .await?
        {
            if !live(&member, now)? {
                continue;
            }
            let Some(team) = teams.get(s(&member, "teamId")) else {
                continue;
            };
            let mut view = team_ref_map(team);
            if truthy(team.get("description")) {
                view.insert(
                    "description".into(),
                    team.get("description").cloned().unwrap_or_default(),
                );
            }
            view.insert(
                "role".into(),
                member.get("role").cloned().unwrap_or_default(),
            );
            if let Some(expires_at) = member.get("expiresAt") {
                view.insert("expiresAt".into(), expires_at.clone());
            }
            view.insert(
                "parents".into(),
                Value::Array(
                    self.chain(&teams, s(team, "id"))?
                        .iter()
                        .skip(1)
                        .rev()
                        .map(team_ref)
                        .collect(),
                ),
            );
            out.push((s(team, "name").to_owned(), Value::Object(view)));
        }
        out.sort_by(|a, b| locale_compare(&a.0, &b.0));
        Ok(out.into_iter().map(|(_, view)| view).collect())
    }

    /// Approves or denies a join request (`decide`).
    async fn decide_request(
        &self,
        credential: &CredentialInput,
        input: &Map<String, Value>,
        outcome: &'static str,
    ) -> IamResult<Value> {
        let ctx = &self.ctx;
        let tenant_id = text(input.get("tenantId"), "tenantId", 256)?;
        let request_id = text(input.get("requestId"), "requestId", 128)?;
        // Routing only: the operation below re-reads and checks the request under authorization.
        let team_id = {
            let tenant_id = tenant_id.clone();
            let request_id = request_id.clone();
            ctx.store
                .transaction(move |tx| async move {
                    let request = tx.get(requests_collection(), &request_id).await?;
                    Ok(match request {
                        Some(request) if s(&request, "tenantId") == tenant_id => {
                            s(&request, "teamId").to_owned()
                        }
                        _ => request_id,
                    })
                })
                .await?
        };
        let note = match input.get("note") {
            None => None,
            Some(note) if note.as_str() == Some("") => None,
            Some(note) => Some(text(Some(note), "note", 1000)?),
        };
        let touched = Touched::default();
        let tenant_value = v(tenant_id.clone());
        let team_value = v(team_id);
        let module = self;
        let touched_ref = &touched;
        let tenant_ref = &tenant_id;
        let request_ref = &request_id;
        let note_ref = &note;
        let work = team_work(move |mutation: TeamMutation| async move {
            let tx = &mutation.tx;
            let principal = &mutation.principal;
            let team = &mutation.team;
            let request = ctx
                .scoped(
                    tx,
                    requests_collection(),
                    Some(&v(request_ref.clone())),
                    tenant_ref,
                )
                .await?;
            if s(&request, "teamId") != s(team, "id") {
                return Err(not_found().into());
            }
            if s(&module.lapse(&request), "status") != "pending" {
                return Err(IamError::with_status(
                    "INVALID_TRANSITION",
                    "The request is no longer pending",
                    409,
                )
                .into());
            }
            if s(&request, "identityId") == principal.identity.id {
                return Err(access_denied("Nobody decides their own join request").into());
            }
            if outcome == "approved" {
                if mutation.via == Via::Permission {
                    let teams = module.all_teams(tx, s(team, "tenantId")).await?;
                    module
                        .assert_authority_over(
                            tx,
                            principal,
                            s(team, "tenantId"),
                            &module.chain(&teams, s(team, "id"))?,
                        )
                        .await?;
                }
                let mut member = Map::new();
                member.insert(
                    "identityId".into(),
                    request.get("identityId").cloned().unwrap_or_default(),
                );
                if let Some(expires_at) = input.get("expiresAt") {
                    member.insert("expiresAt".into(), expires_at.clone());
                }
                module.put_member(&mutation, &member, "approve").await?;
                touched_ref.touch([s(&request, "identityId").to_owned()]);
            }
            let mut decided = request.clone();
            decided.insert("status".into(), v(outcome));
            decided.insert("decidedBy".into(), v(principal.identity.id.clone()));
            decided.insert("decidedAt".into(), number(ctx.now()));
            if let Some(note) = note_ref {
                decided.insert("note".into(), v(note.clone()));
            }
            let decided = tx.put(requests_collection(), &decided).await?;
            let mut payload = Map::new();
            payload.insert("teamId".into(), v(s(team, "id")));
            payload.insert("teamName".into(), v(s(team, "name")));
            payload.insert("decision".into(), v(outcome));
            if let Some(note) = note_ref {
                payload.insert("note".into(), v(note.clone()));
            }
            module
                .email(
                    tx,
                    tenant_ref,
                    [s(&request, "identityId").to_owned()],
                    "team-join-decided",
                    payload,
                )
                .await?;
            let mut metadata = Map::new();
            metadata.insert(
                "requestId".into(),
                request.get("id").cloned().unwrap_or_default(),
            );
            metadata.insert(
                "identityId".into(),
                request.get("identityId").cloned().unwrap_or_default(),
            );
            if mutation.via != Via::Permission {
                metadata.insert("via".into(), v(mutation.via.as_str()));
            }
            module
                .audit(
                    tx,
                    principal,
                    if outcome == "approved" {
                        "team:join:approve"
                    } else {
                        "team:join:deny"
                    },
                    team,
                    metadata,
                )
                .await?;
            Ok(module.request_view(tx, &decided).await?)
        });
        let result = self
            .team_operation(
                credential,
                Some(&tenant_value),
                Some(&team_value),
                "iam:teams:update",
                Some(Level::Maintainer),
                work,
            )
            .await?;
        self.reconciled(&tenant_id, &touched, result).await
    }
}

/// `summary(team, members, all)`: the team without its `uniqueKey` and `createdBy`, with counts.
fn summary(team: &Record, members: &[Record], all: &[Record]) -> Map<String, Value> {
    let mut out = team.clone();
    out.shift_remove("uniqueKey");
    out.shift_remove("createdBy");
    out.insert("memberCount".into(), number(members.len() as f64));
    out.insert(
        "maintainerCount".into(),
        number(
            members
                .iter()
                .filter(|member| s(member, "role") == "maintainer")
                .count() as f64,
        ),
    );
    out.insert(
        "childCount".into(),
        number(
            all.iter()
                .filter(|other| opt_s(other, "parentId") == Some(s(team, "id")))
                .count() as f64,
        ),
    );
    out
}

/// The strings of an array member (`record.key ?? []`).
fn string_array(record: &Record, key: &str) -> Vec<String> {
    match record.get(key) {
        Some(Value::Array(items)) => items
            .iter()
            .map(|item| crate::js::js_string(Some(item)))
            .collect(),
        _ => Vec::new(),
    }
}

/// `Math.max(a, b)`: NaN wins.
fn js_max(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.max(b)
    }
}

/// Maintainers first, then by `email ?? name` (`Number(b.role === 'maintainer') - Number(a.role === 'maintainer') ||
/// (a.email ?? a.name).localeCompare(b.email ?? b.name)`), with `who` picking the person view.
fn by_role_then_name(
    a: &Value,
    b: &Value,
    who: fn(&Value) -> Option<&Value>,
) -> std::cmp::Ordering {
    let maintainer = |view: &Value| view.get("role").and_then(Value::as_str) == Some("maintainer");
    let rank = maintainer(b) as i32 - maintainer(a) as i32;
    if rank != 0 {
        return if rank < 0 {
            std::cmp::Ordering::Less
        } else {
            std::cmp::Ordering::Greater
        };
    }
    let name = |view: &Value| who(view).map(sort_name).unwrap_or_default();
    locale_compare(&name(a), &name(b))
}

/// The view itself (a member view is the person).
fn view_itself(view: &Value) -> Option<&Value> {
    Some(view)
}

/// The person of a review item view.
fn view_person(view: &Value) -> Option<&Value> {
    view.get("person")
}

/// `a.name.localeCompare(b.name) || (a.id < b.id ? -1 : 1)`.
fn by_name_then_id(a: &Record, b: &Record) -> std::cmp::Ordering {
    // IDs are unique, so the tie-break is a total order.
    locale_compare(s(a, "name"), s(b, "name")).then_with(|| cmp_utf16(s(a, "id"), s(b, "id")))
}

/// The `teams` API group (`createTeamsApi(ctx)`): one method per route `teams/{method}`.
pub struct TeamsApi {
    module: TeamModule,
}

/// `createTeamsApi(ctx)`.
pub fn create_teams_api(ctx: &Arc<ServerContext>) -> IamResult<TeamsApi> {
    Ok(TeamsApi {
        module: TeamModule::new(ctx),
    })
}

impl TeamsApi {
    /// `teams/addMember`: adds a person (`role` member by default, or maintainer; `expiresAt` for a temporary
    /// membership). Maintainers of the team or a team above it may do this without iam:teams:update unless the
    /// team's memberManagement is `admins`.
    pub async fn add_member(
        &self,
        credential: &CredentialInput,
        input: Body<teams::AddMemberInput>,
    ) -> IamResult<Reply<teams::AddMemberOutput>> {
        let module = &self.module;
        let body: &Map<String, Value> = &input;
        let touched = Touched::default();
        let touched_ref = &touched;
        let work = team_work(move |mutation: TeamMutation| async move {
            if mutation.via == Via::Permission {
                let tenant_id = s(&mutation.team, "tenantId");
                let teams = module.all_teams(&mutation.tx, tenant_id).await?;
                module
                    .assert_authority_over(
                        &mutation.tx,
                        &mutation.principal,
                        tenant_id,
                        &module.chain(&teams, s(&mutation.team, "id"))?,
                    )
                    .await?;
            }
            let member = module.put_member(&mutation, body, "add").await?;
            touched_ref.touch([s(&member, "identityId").to_owned()]);
            Ok(Value::Object(member))
        });
        let result = module
            .team_operation(
                credential,
                input.get("tenantId"),
                input.get("teamId"),
                "iam:teams:update",
                Some(Level::Maintainer),
                work,
            )
            .await?;
        Ok(Reply::json(
            module
                .reconciled(&string_member(&input, "tenantId"), &touched, result)
                .await?,
        ))
    }

    /// `teams/addMembers`: adds up to 100 people in one transaction with the same role and expiry; one failure
    /// rejects the batch.
    pub async fn add_members(
        &self,
        credential: &CredentialInput,
        input: Body<teams::AddMembersInput>,
    ) -> IamResult<Reply<teams::AddMembersOutput>> {
        let module = &self.module;
        let body: &Map<String, Value> = &input;
        let touched = Touched::default();
        let touched_ref = &touched;
        let work = team_work(move |mutation: TeamMutation| async move {
            let identity_ids = unique(strings(body.get("identityIds"), "identityIds")?);
            if identity_ids.is_empty() {
                return Err(invalid_input("Provide 1-100 identityIds").into());
            }
            if mutation.via == Via::Permission {
                let tenant_id = s(&mutation.team, "tenantId");
                let teams = module.all_teams(&mutation.tx, tenant_id).await?;
                module
                    .assert_authority_over(
                        &mutation.tx,
                        &mutation.principal,
                        tenant_id,
                        &module.chain(&teams, s(&mutation.team, "id"))?,
                    )
                    .await?;
            }
            let mut members = Vec::new();
            for identity_id in &identity_ids {
                let mut member = Map::new();
                member.insert("identityId".into(), v(identity_id.clone()));
                if let Some(role) = body.get("role") {
                    member.insert("role".into(), role.clone());
                }
                if let Some(expires_at) = body.get("expiresAt") {
                    member.insert("expiresAt".into(), expires_at.clone());
                }
                members.push(Value::Object(
                    module.put_member(&mutation, &member, "add").await?,
                ));
            }
            touched_ref.touch(identity_ids);
            Ok(json!({ "members": members }))
        });
        let result = module
            .team_operation(
                credential,
                input.get("tenantId"),
                input.get("teamId"),
                "iam:teams:update",
                Some(Level::Maintainer),
                work,
            )
            .await?;
        Ok(Reply::json(
            module
                .reconciled(&string_member(&input, "tenantId"), &touched, result)
                .await?,
        ))
    }

    /// `teams/approveRequest`: grants a pending join request: the requester joins as a member (optionally until
    /// `expiresAt`) and is emailed. Nobody decides their own request. Maintainers may decide their team's requests.
    pub async fn approve_request(
        &self,
        credential: &CredentialInput,
        input: Body<teams::ApproveRequestInput>,
    ) -> IamResult<Reply<teams::ApproveRequestOutput>> {
        Ok(Reply::json(
            self.module
                .decide_request(credential, &input, "approved")
                .await?,
        ))
    }

    /// `teams/cancelRequest`: withdraws the caller's own pending request.
    pub async fn cancel_request(
        &self,
        credential: &CredentialInput,
        input: Body<teams::CancelRequestInput>,
    ) -> IamResult<Reply<teams::CancelRequestOutput>> {
        let module = &self.module;
        let ctx = &module.ctx;
        let body: &Map<String, Value> = &input;
        let result = module
            .self_service(
                credential,
                input.get("tenantId"),
                move |tx, principal, tenant_id| async move {
                    let request = ctx
                        .scoped(
                            &tx,
                            requests_collection(),
                            Some(&v(text(body.get("requestId"), "requestId", 128)?)),
                            &tenant_id,
                        )
                        .await?;
                    if s(&request, "identityId") != principal.identity.id {
                        return Err(not_found());
                    }
                    if s(&module.lapse(&request), "status") != "pending" {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "The request is no longer pending",
                            409,
                        ));
                    }
                    let mut cancelled = request.clone();
                    cancelled.insert("status".into(), v("cancelled"));
                    cancelled.insert("decidedAt".into(), number(ctx.now()));
                    let cancelled = tx.put(requests_collection(), &cancelled).await?;
                    if let Some(team) = tx.get(teams_collection(), s(&request, "teamId")).await? {
                        let mut metadata = Map::new();
                        metadata.insert(
                            "requestId".into(),
                            request.get("id").cloned().unwrap_or_default(),
                        );
                        module
                            .audit(&tx, &principal, "team:join:cancel", &team, metadata)
                            .await?;
                    }
                    module.request_view(&tx, &cancelled).await
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `teams/cancelReview`: cancels an open review without changing the team. Administrators only.
    pub async fn cancel_review(
        &self,
        credential: &CredentialInput,
        input: Body<teams::CancelReviewInput>,
    ) -> IamResult<Reply<teams::CancelReviewOutput>> {
        let module = &self.module;
        let ctx = &module.ctx;
        let body: &Map<String, Value> = &input;
        let team_id = module
            .review_team_id(input.get("tenantId"), input.get("reviewId"))
            .await?;
        let work = team_work(move |mutation: TeamMutation| async move {
            let TeamMutation {
                tx,
                principal,
                team,
                ..
            } = &mutation;
            let review = module.load_review(tx, team, body.get("reviewId")).await?;
            if s(&review, "status") != "open" {
                return Err(IamError::with_status(
                    "INVALID_TRANSITION",
                    "The review is no longer open",
                    409,
                )
                .into());
            }
            let mut cancelled = review.clone();
            cancelled.shift_remove("uniqueKey");
            cancelled.insert("status".into(), v("cancelled"));
            cancelled.insert("completedAt".into(), number(ctx.now()));
            cancelled.insert("completedBy".into(), v(principal.identity.id.clone()));
            let cancelled = tx.put(reviews_collection(), &cancelled).await?;
            let mut metadata = Map::new();
            metadata.insert(
                "reviewId".into(),
                review.get("id").cloned().unwrap_or_default(),
            );
            module
                .audit(tx, principal, "team:review:cancel", team, metadata)
                .await?;
            Ok(module.review_view(tx, &cancelled, team, false).await?)
        });
        let result = module
            .team_operation(
                credential,
                input.get("tenantId"),
                Some(&v(team_id)),
                "iam:teams:update",
                None,
                work,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `teams/candidates`: people who could be added to the team: active people of the organization who are not
    /// direct members, matched on name or email by `query` (at most `limit`, default 50). Maintainers may use it to
    /// pick people without iam:identities:read.
    pub async fn candidates(
        &self,
        credential: &CredentialInput,
        input: Body<teams::CandidatesInput>,
    ) -> IamResult<Reply<teams::CandidatesOutput>> {
        let module = &self.module;
        let ctx = &module.ctx;
        let body: &Map<String, Value> = &input;
        let work = team_work(move |mutation: TeamMutation| async move {
            let TeamMutation { tx, team, .. } = &mutation;
            let query = match body.get("query") {
                None => None,
                Some(query) if query.as_str() == Some("") => None,
                Some(query) => Some(text(Some(query), "query", 100)?.to_lowercase()),
            };
            let limit = match body.get("limit") {
                None => 50.0,
                Some(limit) => integer(Some(limit), "limit", 1.0, 200.0)?,
            };
            let now = ctx.now();
            let mut members: IndexSet<String> = IndexSet::new();
            for member in tx
                .find(
                    members_collection(),
                    &Filter::new()
                        .eq("tenantId", s(team, "tenantId"))
                        .eq("teamId", s(team, "id")),
                    &find_all(),
                )
                .await?
            {
                if live(&member, now)? {
                    members.insert(s(&member, "identityId").to_owned());
                }
            }
            let mut found: Vec<Record> = tx
                .find(
                    "identities",
                    &Filter::new().eq("tenantId", s(team, "tenantId")),
                    &find_all(),
                )
                .await?
                .into_iter()
                .filter(|identity| {
                    s(identity, "kind") == "user"
                        && s(identity, "status") == "active"
                        && !num(identity, "expiresAt")
                            .is_some_and(|expires_at| expires_at <= ctx.now())
                        && !members.contains(s(identity, "id"))
                        && query.as_ref().is_none_or(|query| {
                            s(identity, "name").to_lowercase().contains(query.as_str())
                                || opt_s(identity, "email")
                                    .unwrap_or_default()
                                    .to_lowercase()
                                    .contains(query.as_str())
                        })
                })
                .collect();
            let key = |identity: &Record| {
                identity
                    .get("email")
                    .filter(|email| !email.is_null())
                    .and_then(Value::as_str)
                    .unwrap_or_else(|| s(identity, "name"))
                    .to_owned()
            };
            found.sort_by(|a, b| locale_compare(&key(a), &key(b)));
            Ok(Value::Array(
                found.iter().take(limit as usize).map(person).collect(),
            ))
        });
        let result = module
            .team_operation(
                credential,
                input.get("tenantId"),
                input.get("teamId"),
                "iam:teams:update",
                Some(Level::Maintainer),
                work,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `teams/completeReview`: people decided `remove` leave the team (and lose what it gave them), and the people
    /// nobody decided on follow `onUndecided`. Maintainers may complete it once every person is decided;
    /// administrators at any time.
    pub async fn complete_review(
        &self,
        credential: &CredentialInput,
        input: Body<teams::CompleteReviewInput>,
    ) -> IamResult<Reply<teams::CompleteReviewOutput>> {
        let module = &self.module;
        let ctx = &module.ctx;
        let body: &Map<String, Value> = &input;
        let team_id = module
            .review_team_id(input.get("tenantId"), input.get("reviewId"))
            .await?;
        let touched = Touched::default();
        let touched_ref = &touched;
        let work = team_work(move |mutation: TeamMutation| async move {
            let TeamMutation {
                tx,
                principal,
                team,
                via,
                ..
            } = &mutation;
            let review = module.load_review(tx, team, body.get("reviewId")).await?;
            if s(&review, "status") != "open" {
                return Err(IamError::with_status(
                    "INVALID_TRANSITION",
                    "The review is no longer open",
                    409,
                )
                .into());
            }
            if *via != Via::Permission {
                let undecided = tx
                    .find(
                        items_collection(),
                        &Filter::new()
                            .eq("tenantId", s(team, "tenantId"))
                            .eq("reviewId", s(&review, "id")),
                        &find_all(),
                    )
                    .await?
                    .iter()
                    .filter(|item| item.get("decision").is_none())
                    .count();
                if undecided > 0 {
                    return Err(IamError::with_status(
                        "INVALID_TRANSITION",
                        format!(
                            "Decide every person first ({undecided} left); an administrator can complete it early"
                        ),
                        409,
                    )
                    .into());
                }
            }
            let typed: TeamReview = decode(review.clone())?;
            let done = complete_team_review(ctx, tx, &typed, Some(principal)).await?;
            touched_ref.touch(
                done.get("removed")
                    .and_then(Value::as_array)
                    .map(|removed| {
                        removed
                            .iter()
                            .map(|id| crate::js::js_string(Some(id)))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
            );
            let completed = done
                .get("review")
                .and_then(Value::as_object)
                .cloned()
                .unwrap_or_default();
            Ok(module.review_view(tx, &completed, team, true).await?)
        });
        let result = module
            .team_operation(
                credential,
                input.get("tenantId"),
                Some(&v(team_id)),
                "iam:teams:update",
                Some(Level::Maintainer),
                work,
            )
            .await?;
        Ok(Reply::json(
            module
                .reconciled(&string_member(&input, "tenantId"), &touched, result)
                .await?,
        ))
    }

    /// `teams/create`: creates a team with its backing group. `parentId` nests it (its members then also receive the
    /// parent's access; needs iam:teams:update on the parent and authority over what the parent holds);
    /// `maintainerIds` names up to 20 people who manage its membership.
    pub async fn create(
        &self,
        credential: &CredentialInput,
        input: Body<teams::CreateInput>,
    ) -> IamResult<Reply<teams::CreateOutput>> {
        let module = &self.module;
        let body: &Map<String, Value> = &input;
        let touched = Touched::default();
        let touched_ref = &touched;
        let run = mutation(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| async move {
                let team = module.create_team(&tx, &principal, &tenant, body).await?;
                touched_ref.touch(module.members_below(&tx, &team).await?);
                Ok(module.detail(&tx, &team).await?)
            },
        );
        let result = module
            .ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:teams:create",
                &string_member(&input, "tenantId"),
                run,
                false,
            )
            .await?;
        Ok(Reply::json(
            module
                .reconciled(&string_member(&input, "tenantId"), &touched, result)
                .await?,
        ))
    }

    /// `teams/decideReview`: records `keep` or `remove` for up to 200 people under an open review (a later decision
    /// replaces an earlier one). Maintainers of the team or a team above, or administrators; nobody decides on their
    /// own membership. Removals take effect when the review completes.
    pub async fn decide_review(
        &self,
        credential: &CredentialInput,
        input: Body<teams::DecideReviewInput>,
    ) -> IamResult<Reply<teams::DecideReviewOutput>> {
        let module = &self.module;
        let ctx = &module.ctx;
        let body: &Map<String, Value> = &input;
        let team_id = module
            .review_team_id(input.get("tenantId"), input.get("reviewId"))
            .await?;
        let work = team_work(move |mutation: TeamMutation| async move {
            let TeamMutation {
                tx,
                principal,
                team,
                via,
                ..
            } = &mutation;
            let review = module.load_review(tx, team, body.get("reviewId")).await?;
            if s(&review, "status") != "open" {
                return Err(IamError::with_status(
                    "INVALID_TRANSITION",
                    "The review is no longer open",
                    409,
                )
                .into());
            }
            let decisions = match body.get("decisions") {
                Some(Value::Array(decisions))
                    if !decisions.is_empty() && decisions.len() <= 200 =>
                {
                    decisions
                }
                _ => return Err(invalid_input("Provide 1-200 decisions").into()),
            };
            let now = ctx.now();
            let mut keep = 0.0;
            let mut remove = 0.0;
            for entry in decisions {
                if !matches!(entry, Value::Object(_) | Value::Array(_)) {
                    return Err(invalid_input("Each decision needs identityId and decision").into());
                }
                let identity_id = text(entry.get("identityId"), "identityId", 128)?;
                let decision = choice(entry.get("decision"), REVIEW_DECISIONS, "decision")?;
                let note = match entry.get("note") {
                    None => None,
                    Some(note) if note.as_str() == Some("") => None,
                    Some(note) => Some(text(Some(note), "note", 1000)?),
                };
                if identity_id == principal.identity.id {
                    return Err(access_denied("Nobody reviews their own membership").into());
                }
                let item = tx
                    .find(
                        items_collection(),
                        &Filter::new()
                            .eq("tenantId", s(team, "tenantId"))
                            .eq("uniqueKey", format!("{}:{identity_id}", s(&review, "id"))),
                        &find_all(),
                    )
                    .await?
                    .into_iter()
                    .next();
                let Some(item) = item else {
                    return Err(IamError::with_status(
                        "NOT_FOUND",
                        "This person is not under review",
                        404,
                    )
                    .into());
                };
                let mut next = item.clone();
                next.shift_remove("note");
                next.insert("decision".into(), v(decision.clone()));
                next.insert("decidedBy".into(), v(principal.identity.id.clone()));
                next.insert("decidedAt".into(), number(now));
                if let Some(note) = note {
                    next.insert("note".into(), v(note));
                }
                tx.put(items_collection(), &next).await?;
                if decision == "keep" {
                    keep += 1.0;
                } else {
                    remove += 1.0;
                }
            }
            let mut metadata = Map::new();
            metadata.insert(
                "reviewId".into(),
                review.get("id").cloned().unwrap_or_default(),
            );
            metadata.insert("keep".into(), number(keep));
            metadata.insert("remove".into(), number(remove));
            if *via != Via::Permission {
                metadata.insert("via".into(), v(via.as_str()));
            }
            module
                .audit(tx, principal, "team:review:decide", team, metadata)
                .await?;
            Ok(module.review_view(tx, &review, team, true).await?)
        });
        let result = module
            .team_operation(
                credential,
                input.get("tenantId"),
                Some(&v(team_id)),
                "iam:teams:update",
                Some(Level::Maintainer),
                work,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `teams/delete`: deletes a team, its memberships and join requests, and its backing group with the bindings
    /// and relationships on it. Teams below it must be moved or deleted first (RESOURCE_IN_USE).
    pub async fn delete(
        &self,
        credential: &CredentialInput,
        input: Body<teams::DeleteInput>,
    ) -> IamResult<Reply<teams::DeleteOutput>> {
        let module = &self.module;
        let touched = Touched::default();
        let touched_ref = &touched;
        let work = team_work(move |mutation: TeamMutation| async move {
            let TeamMutation {
                tx,
                principal,
                team,
                ..
            } = &mutation;
            touched_ref.touch(module.members_below(tx, team).await?);
            let members = module.delete_team(tx, principal, team).await?;
            Ok(json!({ "deleted": true, "members": number(members as f64) }))
        });
        let result = module
            .team_operation(
                credential,
                input.get("tenantId"),
                input.get("teamId"),
                "iam:teams:delete",
                None,
                work,
            )
            .await?;
        Ok(Reply::json(
            module
                .reconciled(&string_member(&input, "tenantId"), &touched, result)
                .await?,
        ))
    }

    /// `teams/denyRequest`: refuses a pending join request; the requester is emailed with the note.
    pub async fn deny_request(
        &self,
        credential: &CredentialInput,
        input: Body<teams::DenyRequestInput>,
    ) -> IamResult<Reply<teams::DenyRequestOutput>> {
        Ok(Reply::json(
            self.module
                .decide_request(credential, &input, "denied")
                .await?,
        ))
    }

    /// `teams/get`: one team with its place in the tree, maintainers, department, and the roles its members hold
    /// through it. Members may read their own team.
    pub async fn get(
        &self,
        credential: &CredentialInput,
        input: Body<teams::GetInput>,
    ) -> IamResult<Reply<teams::GetOutput>> {
        let module = &self.module;
        let work = team_work(move |mutation: TeamMutation| async move {
            Ok(module.detail(&mutation.tx, &mutation.team).await?)
        });
        let result = module
            .team_operation(
                credential,
                input.get("tenantId"),
                input.get("teamId"),
                "iam:teams:read",
                Some(Level::Member),
                work,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `teams/getReview`: one review with every person under it. Maintainers of the team (or a team above) may read
    /// it.
    pub async fn get_review(
        &self,
        credential: &CredentialInput,
        input: Body<teams::GetReviewInput>,
    ) -> IamResult<Reply<teams::GetReviewOutput>> {
        let module = &self.module;
        let body: &Map<String, Value> = &input;
        let team_id = module
            .review_team_id(input.get("tenantId"), input.get("reviewId"))
            .await?;
        let work = team_work(move |mutation: TeamMutation| async move {
            let review = module
                .load_review(&mutation.tx, &mutation.team, body.get("reviewId"))
                .await?;
            Ok(module
                .review_view(&mutation.tx, &review, &mutation.team, true)
                .await?)
        });
        let result = module
            .team_operation(
                credential,
                input.get("tenantId"),
                Some(&v(team_id)),
                "iam:teams:read",
                Some(Level::Maintainer),
                work,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `teams/leave`: leaves a team the caller belongs to directly. Audited as `team:leave`. Refused (ACCESS_DENIED)
    /// when leaving would take the caller out of a backing group bound to a role with a deny statement whose grant
    /// authority they lack.
    pub async fn leave(
        &self,
        credential: &CredentialInput,
        input: Body<teams::LeaveInput>,
    ) -> IamResult<Reply<teams::LeaveOutput>> {
        let module = &self.module;
        let body: &Map<String, Value> = &input;
        let touched = Touched::default();
        let touched_ref = &touched;
        let result = module
            .self_service(
                credential,
                input.get("tenantId"),
                move |tx, principal, tenant_id| async move {
                    let team = module
                        .load_team_record(&tx, &tenant_id, body.get("teamId"))
                        .await?;
                    let member = module
                        .member_record(&tx, &team, Some(&v(principal.identity.id.clone())))
                        .await?;
                    let identity_id = s(&member, "identityId").to_owned();
                    let held = module.held_chain_groups(&tx, &team, &identity_id).await?;
                    module
                        .remove_member(&tx, &principal, &team, &member, "team:leave", None)
                        .await?;
                    let kept = module.held_chain_groups(&tx, &team, &identity_id).await?;
                    module
                        .assert_may_drop_denies(
                            &tx,
                            &principal,
                            &tenant_id,
                            held.into_iter().filter(|group_id| !kept.contains(group_id)),
                        )
                        .await?;
                    touched_ref.touch([identity_id]);
                    Ok(json!({ "left": true }))
                },
            )
            .await?;
        Ok(Reply::json(
            module
                .reconciled(&string_member(&input, "tenantId"), &touched, result)
                .await?,
        ))
    }

    /// `teams/list`: every team of the organization with member counts, name order. Filters: `parentId` (null for
    /// top-level teams), `departmentId`, and `query` (name or slug, case-insensitive).
    pub async fn list(
        &self,
        credential: &CredentialInput,
        input: Body<teams::ListInput>,
    ) -> IamResult<Reply<teams::ListOutput>> {
        let module = &self.module;
        let body: &Map<String, Value> = &input;
        let run = mutation(move |MutationContext { tx, tenant, .. }| async move {
            let all: Vec<Record> = module
                .all_teams(&tx, &tenant.id)
                .await?
                .into_values()
                .collect();
            let query = match body.get("query") {
                None => None,
                Some(query) => Some(text(Some(query), "query", 100)?.to_lowercase()),
            };
            let mut selected: Vec<Record> =
                all.iter()
                    .filter(|team| {
                        body.get("parentId").is_none_or(|parent_id| {
                            team.get("parentId")
                                .filter(|value| !value.is_null())
                                .cloned()
                                .unwrap_or(Value::Null)
                                == *parent_id
                        }) && body.get("departmentId").is_none_or(|department_id| {
                            team.get("departmentId") == Some(department_id)
                        }) && query.as_ref().is_none_or(|query| {
                            s(team, "name").to_lowercase().contains(query.as_str())
                                || s(team, "slug").contains(query.as_str())
                        })
                    })
                    .cloned()
                    .collect();
            selected.sort_by(by_name_then_id);
            Ok(Value::Array(
                module
                    .summaries(&tx, &selected, &all)
                    .await?
                    .into_iter()
                    .map(Value::Object)
                    .collect(),
            ))
        });
        let result = module
            .ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:teams:read",
                &string_member(&input, "tenantId"),
                run,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `teams/listForIdentity`: the teams a person belongs to directly, with their role and the teams above each
    /// one.
    pub async fn list_for_identity(
        &self,
        credential: &CredentialInput,
        input: Body<teams::ListForIdentityInput>,
    ) -> IamResult<Reply<teams::ListForIdentityOutput>> {
        let module = &self.module;
        let ctx = &module.ctx;
        let body: &Map<String, Value> = &input;
        let run = mutation(move |MutationContext { tx, tenant, .. }| async move {
            ctx.scoped(&tx, "identities", body.get("identityId"), &tenant.id)
                .await?;
            Ok(Value::Array(
                module
                    .memberships_of(&tx, &tenant.id, &string_member(body, "identityId"))
                    .await?,
            ))
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:teams:read",
                &string_member(&input, "identityId"),
                run,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `teams/listMembers`: the team's live direct members with their role; `includeChildTeams` adds the members of
    /// every team below it (each with the team they belong to). Members may read their own team.
    pub async fn list_members(
        &self,
        credential: &CredentialInput,
        input: Body<teams::ListMembersInput>,
    ) -> IamResult<Reply<teams::ListMembersOutput>> {
        let module = &self.module;
        let ctx = &module.ctx;
        let body: &Map<String, Value> = &input;
        let work = team_work(move |mutation: TeamMutation| async move {
            let TeamMutation { tx, team, .. } = &mutation;
            let tenant_id = s(team, "tenantId");
            let teams = module.all_teams(tx, tenant_id).await?;
            let mut scope = vec![team.clone()];
            if truthy(body.get("includeChildTeams")) {
                scope.extend(module.descendants(&teams, s(team, "id"))?);
            }
            let now = ctx.now();
            let mut members: Vec<Record> = Vec::new();
            for item in &scope {
                for member in tx
                    .find(
                        members_collection(),
                        &Filter::new()
                            .eq("tenantId", tenant_id)
                            .eq("teamId", s(item, "id")),
                        &find_all(),
                    )
                    .await?
                {
                    if live(&member, now)? {
                        members.push(member);
                    }
                }
            }
            let directory = module
                .people(
                    tx,
                    members
                        .iter()
                        .map(|member| s(member, "identityId").to_owned()),
                )
                .await?;
            let mut views: Vec<Value> = members
                .iter()
                .map(|member| {
                    let mut view = match directory.get(s(member, "identityId")) {
                        Some(Value::Object(person)) => person.clone(),
                        _ => Map::new(),
                    };
                    view.insert(
                        "role".into(),
                        member.get("role").cloned().unwrap_or_default(),
                    );
                    view.insert(
                        "team".into(),
                        teams
                            .get(s(member, "teamId"))
                            .map(team_ref)
                            .unwrap_or_default(),
                    );
                    view.insert(
                        "addedAt".into(),
                        member.get("addedAt").cloned().unwrap_or_default(),
                    );
                    view.insert(
                        "addedBy".into(),
                        member.get("addedBy").cloned().unwrap_or_default(),
                    );
                    if let Some(expires_at) = member.get("expiresAt") {
                        view.insert("expiresAt".into(), expires_at.clone());
                    }
                    if truthy(member.get("source")) {
                        view.insert(
                            "source".into(),
                            member.get("source").cloned().unwrap_or_default(),
                        );
                    }
                    Value::Object(view)
                })
                .filter(|view| view.get("status").and_then(Value::as_str) != Some("deleted"))
                .collect();
            views.sort_by(|a, b| by_role_then_name(a, b, view_itself));
            Ok(Value::Array(views))
        });
        let result = module
            .team_operation(
                credential,
                input.get("tenantId"),
                input.get("teamId"),
                "iam:teams:read",
                Some(Level::Member),
                work,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `teams/listMine`: the caller's teams, their join requests, and the teams they may ask to join.
    pub async fn list_mine(
        &self,
        credential: &CredentialInput,
        input: Body<teams::ListMineInput>,
    ) -> IamResult<Reply<teams::ListMineOutput>> {
        let module = &self.module;
        let result = module
            .self_service(
                credential,
                input.get("tenantId"),
                move |tx, principal, tenant_id| async move {
                    let identity_id = principal.identity.id.clone();
                    let teams = module.memberships_of(&tx, &tenant_id, &identity_id).await?;
                    let mut requests: Vec<Record> = tx
                        .find(
                            requests_collection(),
                            &Filter::new()
                                .eq("tenantId", tenant_id.as_str())
                                .eq("identityId", identity_id.as_str()),
                            &find_all(),
                        )
                        .await?
                        .iter()
                        .map(|request| module.lapse(request))
                        .collect();
                    requests.sort_by(|a, b| {
                        let a = num(a, "requestedAt").unwrap_or(f64::NAN);
                        let b = num(b, "requestedAt").unwrap_or(f64::NAN);
                        b.partial_cmp(&a).unwrap_or(std::cmp::Ordering::Equal)
                    });
                    requests.truncate(50);
                    let all = module.all_teams(&tx, &tenant_id).await?;
                    let all_list: Vec<Record> = all.values().cloned().collect();
                    let mine: IndexSet<String> = teams
                        .iter()
                        .map(|team| crate::js::js_string(team.get("id")))
                        .collect();
                    let mut joinable: Vec<Record> = all_list
                        .iter()
                        .filter(|team| {
                            s(team, "joinPolicy") == "request" && !mine.contains(s(team, "id"))
                        })
                        .cloned()
                        .collect();
                    joinable.sort_by(|a, b| locale_compare(s(a, "name"), s(b, "name")));
                    let counts = module.summaries(&tx, &joinable, &all_list).await?;
                    // Reviews waiting on the caller as a maintainer (their own membership is someone else's to
                    // decide).
                    let mut reviews: Vec<(f64, Value)> = Vec::new();
                    for review in tx
                        .find(
                            reviews_collection(),
                            &Filter::new()
                                .eq("tenantId", tenant_id.as_str())
                                .eq("status", "open"),
                            &find_all(),
                        )
                        .await?
                    {
                        let Some(team) = all.get(s(&review, "teamId")) else {
                            continue;
                        };
                        if !is_team_maintainer(
                            &tx,
                            &tenant_id,
                            s(team, "id"),
                            &identity_id,
                            Some(&json!({ "includeAncestors": true })),
                        )
                        .await?
                        {
                            continue;
                        }
                        let items = tx
                            .find(
                                items_collection(),
                                &Filter::new()
                                    .eq("tenantId", tenant_id.as_str())
                                    .eq("reviewId", s(&review, "id")),
                                &find_all(),
                            )
                            .await?;
                        let undecided = items
                            .iter()
                            .filter(|item| {
                                item.get("decision").is_none()
                                    && s(item, "identityId") != identity_id
                            })
                            .count();
                        let mut view = Map::new();
                        view.insert("id".into(), review.get("id").cloned().unwrap_or_default());
                        view.insert("team".into(), team_ref(team));
                        view.insert(
                            "dueAt".into(),
                            review.get("dueAt").cloned().unwrap_or_default(),
                        );
                        view.insert("undecided".into(), number(undecided as f64));
                        reviews.push((
                            num(&review, "dueAt").unwrap_or(f64::NAN),
                            Value::Object(view),
                        ));
                    }
                    reviews
                        .sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
                    let mut request_views = Vec::new();
                    for request in &requests {
                        request_views.push(module.request_view(&tx, request).await?);
                    }
                    let joinable_views: Vec<Value> = joinable
                        .iter()
                        .enumerate()
                        .map(|(index, team)| {
                            let mut view = team_ref_map(team);
                            if truthy(team.get("description")) {
                                view.insert(
                                    "description".into(),
                                    team.get("description").cloned().unwrap_or_default(),
                                );
                            }
                            view.insert(
                                "memberCount".into(),
                                counts
                                    .get(index)
                                    .and_then(|counts| counts.get("memberCount"))
                                    .cloned()
                                    .unwrap_or_default(),
                            );
                            Value::Object(view)
                        })
                        .collect();
                    let mut out = Map::new();
                    out.insert(
                        "reviews".into(),
                        Value::Array(reviews.into_iter().map(|(_, view)| view).collect()),
                    );
                    out.insert("teams".into(), Value::Array(teams));
                    out.insert("requests".into(), Value::Array(request_views));
                    out.insert("joinable".into(), Value::Array(joinable_views));
                    Ok(Value::Object(out))
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `teams/listRequests`: join requests for a team (pending by default; `status` picks another state).
    /// Maintainers may list their team's.
    pub async fn list_requests(
        &self,
        credential: &CredentialInput,
        input: Body<teams::ListRequestsInput>,
    ) -> IamResult<Reply<teams::ListRequestsOutput>> {
        let module = &self.module;
        let body: &Map<String, Value> = &input;
        let work = team_work(move |mutation: TeamMutation| async move {
            let TeamMutation { tx, team, .. } = &mutation;
            let status = match body.get("status") {
                None => "pending".to_owned(),
                Some(status) => choice(Some(status), REQUEST_STATUSES, "status")?,
            };
            let mut requests: Vec<Record> = tx
                .find(
                    requests_collection(),
                    &Filter::new()
                        .eq("tenantId", s(team, "tenantId"))
                        .eq("teamId", s(team, "id")),
                    &find_all(),
                )
                .await?
                .iter()
                .map(|request| module.lapse(request))
                .filter(|request| s(request, "status") == status)
                .collect();
            requests.sort_by(|a, b| {
                let a = num(a, "requestedAt").unwrap_or(f64::NAN);
                let b = num(b, "requestedAt").unwrap_or(f64::NAN);
                b.partial_cmp(&a).unwrap_or(std::cmp::Ordering::Equal)
            });
            requests.truncate(200);
            let mut views = Vec::new();
            for request in &requests {
                views.push(module.request_view(tx, request).await?);
            }
            Ok(Value::Array(views))
        });
        let result = module
            .team_operation(
                credential,
                input.get("tenantId"),
                input.get("teamId"),
                "iam:teams:read",
                Some(Level::Maintainer),
                work,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `teams/listReviews`: membership reviews, newest first (at most 100): of one team (`teamId`; its maintainers
    /// may list them) or, for administrators holding iam:teams:read, of every team. `status` filters.
    pub async fn list_reviews(
        &self,
        credential: &CredentialInput,
        input: Body<teams::ListReviewsInput>,
    ) -> IamResult<Reply<teams::ListReviewsOutput>> {
        let module = &self.module;
        let status = match input.get("status") {
            None => None,
            Some(status) => Some(choice(Some(status), REVIEW_STATUSES, "status")?),
        };
        let status_ref = &status;
        let list = move |tx: Store, teams: Vec<Record>| async move {
            let mut views: Vec<(f64, Value)> = Vec::new();
            for team in &teams {
                let mut filter = Filter::new()
                    .eq("tenantId", s(team, "tenantId"))
                    .eq("teamId", s(team, "id"));
                if let Some(status) = status_ref {
                    filter = filter.eq("status", status.as_str());
                }
                for review in tx.find(reviews_collection(), &filter, &find_all()).await? {
                    let started_at = num(&review, "startedAt").unwrap_or(f64::NAN);
                    views.push((
                        started_at,
                        module.review_view(&tx, &review, team, false).await?,
                    ));
                }
            }
            views.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
            views.truncate(100);
            Ok::<Value, IamError>(Value::Array(
                views.into_iter().map(|(_, view)| view).collect(),
            ))
        };
        if input.get("teamId").is_some() {
            let work = team_work(move |mutation: TeamMutation| async move {
                Ok(list(mutation.tx.clone(), vec![mutation.team.clone()]).await?)
            });
            let result = module
                .team_operation(
                    credential,
                    input.get("tenantId"),
                    input.get("teamId"),
                    "iam:teams:read",
                    Some(Level::Maintainer),
                    work,
                )
                .await?;
            return Ok(Reply::json(result));
        }
        let run = mutation(move |MutationContext { tx, tenant, .. }| async move {
            let teams: Vec<Record> = module
                .all_teams(&tx, &tenant.id)
                .await?
                .into_values()
                .collect();
            Ok(list(tx, teams).await?)
        });
        let result = module
            .ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:teams:read",
                &string_member(&input, "tenantId"),
                run,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `teams/reconcile`: runs team sync for every synced team (`synced`), then re-computes every team's backing
    /// group from team membership: how many group memberships were added, removed, and updated.
    pub async fn reconcile(
        &self,
        credential: &CredentialInput,
        input: Body<teams::ReconcileInput>,
    ) -> IamResult<Reply<teams::ReconcileOutput>> {
        let module = &self.module;
        let ctx = &module.ctx;
        let run = mutation(
            move |MutationContext {
                      tx,
                      principal,
                      tenant,
                  }| async move {
                let synced = sync_teams_from_groups(
                    ctx,
                    &tx,
                    &tenant.id,
                    &json!({ "actorId": principal.identity.id }),
                )
                .await?;
                let ids: Vec<String> = module
                    .all_teams(&tx, &tenant.id)
                    .await?
                    .into_keys()
                    .collect();
                let groups = sync_team_groups(&tx, &tenant.id, &json!(ids), ctx.now()).await?;
                let mut out = match serde_json::to_value(&groups) {
                    Ok(Value::Object(map)) => map,
                    _ => Map::new(),
                };
                out.insert(
                    "synced".into(),
                    serde_json::to_value(&synced).unwrap_or(Value::Null),
                );
                Ok(Value::Object(out))
            },
        );
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:teams:update",
                &string_member(&input, "tenantId"),
                run,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `teams/removeMember`: removes a direct member; the backing groups (and their eligible-binding activations)
    /// follow.
    pub async fn remove_member(
        &self,
        credential: &CredentialInput,
        input: Body<teams::RemoveMemberInput>,
    ) -> IamResult<Reply<teams::RemoveMemberOutput>> {
        let module = &self.module;
        let body: &Map<String, Value> = &input;
        let touched = Touched::default();
        let touched_ref = &touched;
        let work = team_work(move |mutation: TeamMutation| async move {
            let TeamMutation {
                tx,
                principal,
                team,
                via,
                ..
            } = &mutation;
            let tenant_id = s(team, "tenantId");
            if *via == Via::Permission {
                let teams = module.all_teams(tx, tenant_id).await?;
                module
                    .assert_authority_over(
                        tx,
                        principal,
                        tenant_id,
                        &module.chain(&teams, s(team, "id"))?,
                    )
                    .await?;
            }
            let member = module
                .member_record(tx, team, body.get("identityId"))
                .await?;
            // Team sync would add them straight back.
            if s(&member, "source") == "sync" {
                return Err(IamError::with_status(
                    "INVALID_TRANSITION",
                    "This person is a member through team sync; remove them from the source group",
                    409,
                )
                .into());
            }
            // A maintainer removing themselves is leaving the team (see leave).
            let identity_id = s(&member, "identityId").to_owned();
            let own = *via != Via::Permission && identity_id == principal.identity.id;
            let held = if own {
                Some(module.held_chain_groups(tx, team, &identity_id).await?)
            } else {
                None
            };
            module
                .remove_member(
                    tx,
                    principal,
                    team,
                    &member,
                    "team:member:remove",
                    Some(via.as_str()),
                )
                .await?;
            if let Some(held) = held {
                let kept = module.held_chain_groups(tx, team, &identity_id).await?;
                module
                    .assert_may_drop_denies(
                        tx,
                        principal,
                        tenant_id,
                        held.into_iter().filter(|group_id| !kept.contains(group_id)),
                    )
                    .await?;
            }
            touched_ref.touch([identity_id]);
            Ok(json!({ "deleted": true }))
        });
        let result = module
            .team_operation(
                credential,
                input.get("tenantId"),
                input.get("teamId"),
                "iam:teams:update",
                Some(Level::Maintainer),
                work,
            )
            .await?;
        Ok(Reply::json(
            module
                .reconciled(&string_member(&input, "tenantId"), &touched, result)
                .await?,
        ))
    }

    /// `teams/requestToJoin`: asks to join a team whose join policy is `request`. Its maintainers (or, when it has
    /// none, those of the teams above it) are emailed; the request lapses after fourteen days.
    pub async fn request_to_join(
        &self,
        credential: &CredentialInput,
        input: Body<teams::RequestToJoinInput>,
    ) -> IamResult<Reply<teams::RequestToJoinOutput>> {
        let module = &self.module;
        let ctx = &module.ctx;
        let body: &Map<String, Value> = &input;
        let result = module
            .self_service(
                credential,
                input.get("tenantId"),
                move |tx, principal, tenant_id| async move {
                    let team = module
                        .load_team_record(&tx, &tenant_id, body.get("teamId"))
                        .await?;
                    if s(&team, "joinPolicy") != "request" {
                        return Err(IamError::with_status(
                            "INVALID_TRANSITION",
                            "This team does not take join requests; ask a maintainer to add you",
                            409,
                        ));
                    }
                    let team_id = s(&team, "id").to_owned();
                    let identity_id = principal.identity.id.clone();
                    let now = ctx.now();
                    let member = tx
                        .find(
                            members_collection(),
                            &Filter::new()
                                .eq("tenantId", tenant_id.as_str())
                                .eq("uniqueKey", format!("{team_id}:{identity_id}")),
                            &find_all(),
                        )
                        .await?
                        .into_iter()
                        .next();
                    if let Some(member) = &member
                        && live(member, now)?
                    {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "You are already in this team",
                            409,
                        ));
                    }
                    let pending = tx
                        .find(
                            requests_collection(),
                            &Filter::new()
                                .eq("tenantId", tenant_id.as_str())
                                .eq("teamId", team_id.as_str())
                                .eq("identityId", identity_id.as_str())
                                .eq("status", "pending"),
                            &find_all(),
                        )
                        .await?
                        .into_iter()
                        .any(|request| num(&request, "expiresAt").is_some_and(|at| at > now));
                    if pending {
                        return Err(IamError::with_status(
                            "CONFLICT",
                            "You already asked to join this team",
                            409,
                        ));
                    }
                    let justification = match body.get("justification") {
                        None => None,
                        Some(justification) if justification.as_str() == Some("") => None,
                        Some(justification) => {
                            Some(text(Some(justification), "justification", 1000)?)
                        }
                    };
                    let mut request = Map::new();
                    request.insert("id".into(), v(id()));
                    request.insert("tenantId".into(), v(tenant_id.clone()));
                    request.insert("teamId".into(), v(team_id.clone()));
                    request.insert("identityId".into(), v(identity_id.clone()));
                    request.insert("status".into(), v("pending"));
                    request.insert("requestedAt".into(), number(now));
                    request.insert("expiresAt".into(), number(now + JOIN_REQUEST_LIFETIME_MS));
                    if let Some(justification) = &justification {
                        request.insert("justification".into(), v(justification.clone()));
                    }
                    tx.insert(requests_collection(), &request).await?;
                    let teams = module.all_teams(&tx, &tenant_id).await?;
                    let mut recipients: Vec<String> = Vec::new();
                    for holder in module.chain(&teams, &team_id)? {
                        recipients =
                            team_maintainers(&tx, &tenant_id, s(&holder, "id"), Some(now)).await?;
                        if !recipients.is_empty() {
                            break;
                        }
                    }
                    let mut payload = Map::new();
                    payload.insert("teamId".into(), v(team_id.clone()));
                    payload.insert("teamName".into(), v(s(&team, "name")));
                    payload.insert(
                        "requestId".into(),
                        request.get("id").cloned().unwrap_or_default(),
                    );
                    payload.insert("requesterName".into(), v(principal.identity.name.clone()));
                    if let Some(email) = principal
                        .identity
                        .email
                        .as_ref()
                        .filter(|email| !email.is_empty())
                    {
                        payload.insert("requesterEmail".into(), v(email.clone()));
                    }
                    if let Some(justification) = &justification {
                        payload.insert("justification".into(), v(justification.clone()));
                    }
                    module
                        .email(
                            &tx,
                            &tenant_id,
                            recipients
                                .into_iter()
                                .filter(|recipient| *recipient != identity_id),
                            "team-join-request",
                            payload,
                        )
                        .await?;
                    let mut metadata = Map::new();
                    metadata.insert(
                        "requestId".into(),
                        request.get("id").cloned().unwrap_or_default(),
                    );
                    if let Some(justification) = &justification {
                        metadata.insert("justification".into(), v(justification.clone()));
                    }
                    module
                        .audit(&tx, &principal, "team:join:request", &team, metadata)
                        .await?;
                    module.request_view(&tx, &request).await
                },
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `teams/startReview`: opens a membership review of the team: every live manual member becomes an item its
    /// maintainers decide `keep` or `remove` by `dueAt` (default in 14 days, one to 90 days ahead). One open review
    /// per team. Administrators only.
    pub async fn start_review(
        &self,
        credential: &CredentialInput,
        input: Body<teams::StartReviewInput>,
    ) -> IamResult<Reply<teams::StartReviewOutput>> {
        let module = &self.module;
        let ctx = &module.ctx;
        let body: &Map<String, Value> = &input;
        let work = team_work(move |mutation: TeamMutation| async move {
            let TeamMutation {
                tx,
                principal,
                team,
                ..
            } = &mutation;
            let tenant_id = s(team, "tenantId");
            let team_id = s(team, "id");
            let now = ctx.now();
            let due_at = match body.get("dueAt") {
                None => now + DEFAULT_REVIEW_MS,
                Some(due_at) => integer(
                    Some(due_at),
                    "dueAt",
                    now + MIN_REVIEW_MS,
                    now + MAX_REVIEW_MS,
                )?,
            };
            let on_undecided = match body.get("onUndecided") {
                None => "keep".to_owned(),
                Some(value) => choice(Some(value), REVIEW_DECISIONS, "onUndecided")?,
            };
            let note = match body.get("note") {
                None => None,
                Some(note) if note.as_str() == Some("") => None,
                Some(note) => Some(text(Some(note), "note", 1000)?),
            };
            let open = tx
                .find(
                    reviews_collection(),
                    &Filter::new()
                        .eq("tenantId", tenant_id)
                        .eq("uniqueKey", format!("open:{team_id}")),
                    &find_all(),
                )
                .await?;
            if !open.is_empty() {
                return Err(IamError::with_status(
                    "CONFLICT",
                    "This team already has an open membership review",
                    409,
                )
                .into());
            }
            let mut members = Vec::new();
            for member in tx
                .find(
                    members_collection(),
                    &Filter::new()
                        .eq("tenantId", tenant_id)
                        .eq("teamId", team_id),
                    &find_all(),
                )
                .await?
            {
                if live(&member, now)? && s(&member, "source") != "sync" {
                    members.push(member);
                }
            }
            if members.is_empty() {
                return Err(IamError::with_status(
                    "INVALID_TRANSITION",
                    "The team has no members to review (members team sync manages are reviewed through their source groups)",
                    409,
                )
                .into());
            }
            let mut review = Map::new();
            review.insert("id".into(), v(id()));
            review.insert("tenantId".into(), v(tenant_id));
            review.insert("uniqueKey".into(), v(format!("open:{team_id}")));
            review.insert("teamId".into(), v(team_id));
            review.insert("status".into(), v("open"));
            review.insert("onUndecided".into(), v(on_undecided.clone()));
            review.insert("startedAt".into(), number(now));
            review.insert("startedBy".into(), v(principal.identity.id.clone()));
            review.insert("dueAt".into(), number(due_at));
            if let Some(note) = &note {
                review.insert("note".into(), v(note.clone()));
            }
            let review = tx.insert(reviews_collection(), &review).await?;
            let review_id = s(&review, "id").to_owned();
            for member in &members {
                let mut item = Map::new();
                item.insert("id".into(), v(id()));
                item.insert("tenantId".into(), v(tenant_id));
                item.insert(
                    "uniqueKey".into(),
                    v(format!("{review_id}:{}", s(member, "identityId"))),
                );
                item.insert("reviewId".into(), v(review_id.clone()));
                item.insert("teamId".into(), v(team_id));
                item.insert(
                    "identityId".into(),
                    member.get("identityId").cloned().unwrap_or_default(),
                );
                item.insert(
                    "role".into(),
                    member.get("role").cloned().unwrap_or_default(),
                );
                tx.insert(items_collection(), &item).await?;
            }
            let teams = module.all_teams(tx, tenant_id).await?;
            let mut recipients: Vec<String> = Vec::new();
            for holder in module.chain(&teams, team_id)? {
                recipients = team_maintainers(tx, tenant_id, s(&holder, "id"), Some(now)).await?;
                if !recipients.is_empty() {
                    break;
                }
            }
            let mut payload = Map::new();
            payload.insert("teamId".into(), v(team_id));
            payload.insert("teamName".into(), v(s(team, "name")));
            payload.insert("reviewId".into(), v(review_id.clone()));
            payload.insert(
                "memberCount".into(),
                v(crate::js::number_to_string(members.len() as f64)),
            );
            payload.insert(
                "dueAt".into(),
                match iso_string(due_at) {
                    Some(iso) => v(iso),
                    None => {
                        return Err(IamError::with_status(
                            "INTERNAL_ERROR",
                            "Internal server error",
                            500,
                        )
                        .into());
                    }
                },
            );
            payload.insert("onUndecided".into(), v(on_undecided.clone()));
            if let Some(note) = &note {
                payload.insert("note".into(), v(note.clone()));
            }
            module
                .email(tx, tenant_id, recipients, "team-review-requested", payload)
                .await?;
            let mut metadata = Map::new();
            metadata.insert("reviewId".into(), v(review_id));
            metadata.insert("members".into(), number(members.len() as f64));
            metadata.insert("dueAt".into(), number(due_at));
            metadata.insert("onUndecided".into(), v(on_undecided));
            module
                .audit(tx, principal, "team:review:start", team, metadata)
                .await?;
            Ok(module.review_view(tx, &review, team, true).await?)
        });
        let result = module
            .team_operation(
                credential,
                input.get("tenantId"),
                input.get("teamId"),
                "iam:teams:update",
                None,
                work,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `teams/suggestBirthright`: roles and groups that most of a team's members hold by hand, as a ready-made
    /// automatic access package whose rule names the team. `teamId` limits the answer to one team. Read-only;
    /// requires iam:analysis:read.
    pub async fn suggest_birthright(
        &self,
        credential: &CredentialInput,
        input: Body<teams::SuggestBirthrightInput>,
    ) -> IamResult<Reply<teams::SuggestBirthrightOutput>> {
        let module = &self.module;
        let ctx = &module.ctx;
        let body: &Map<String, Value> = &input;
        let run = mutation(move |MutationContext { tx, tenant, .. }| async move {
            let options = birthright_options(&Value::Object(body.clone()))?;
            if let Some(team_id) = body.get("teamId") {
                load_team(&tx, &tenant.id, Some(team_id)).await?;
            }
            let mut merged = match options {
                Value::Object(map) => map,
                _ => Map::new(),
            };
            if let Some(team_id) = body.get("teamId") {
                merged.insert("unitId".into(), team_id.clone());
            }
            let suggestions =
                suggest_birthright(ctx, &tx, &tenant.id, "team", &Value::Object(merged)).await?;
            Ok(serde_json::to_value(&suggestions).unwrap_or(Value::Null))
        });
        let result = ctx
            .operations()?
            .operation(
                credential,
                input.get("tenantId"),
                "iam:analysis:read",
                &string_member(&input, "tenantId"),
                run,
                false,
            )
            .await?;
        Ok(Reply::json(result))
    }

    /// `teams/update`: renames, re-slugs, re-describes, moves (`parentId`, null for top level), or re-files
    /// (`departmentId`) a team, or changes its join policy or who manages members.
    pub async fn update(
        &self,
        credential: &CredentialInput,
        input: Body<teams::UpdateInput>,
    ) -> IamResult<Reply<teams::UpdateOutput>> {
        let module = &self.module;
        let body: &Map<String, Value> = &input;
        let touched = Touched::default();
        let touched_ref = &touched;
        let work = team_work(move |mutation: TeamMutation| async move {
            let TeamMutation {
                tx,
                principal,
                team,
                ..
            } = &mutation;
            // A move or a sync change alters identity.teams at or below the team.
            let moving = body.get("parentId").is_some() || body.get("syncGroupIds").is_some();
            if moving {
                touched_ref.touch(module.members_below(tx, team).await?);
            }
            let updated = module.update_team(tx, principal, team, body).await?;
            if moving {
                touched_ref.touch(module.members_below(tx, &updated).await?);
            }
            Ok(module.detail(tx, &updated).await?)
        });
        let result = module
            .team_operation(
                credential,
                input.get("tenantId"),
                input.get("teamId"),
                "iam:teams:update",
                None,
                work,
            )
            .await?;
        Ok(Reply::json(
            module
                .reconciled(&string_member(&input, "tenantId"), &touched, result)
                .await?,
        ))
    }

    /// `teams/updateMember`: changes a member's role or expiry (`expiresAt: null` makes the membership permanent).
    pub async fn update_member(
        &self,
        credential: &CredentialInput,
        input: Body<teams::UpdateMemberInput>,
    ) -> IamResult<Reply<teams::UpdateMemberOutput>> {
        let module = &self.module;
        let ctx = &module.ctx;
        let body: &Map<String, Value> = &input;
        let touched = Touched::default();
        let touched_ref = &touched;
        let work = team_work(move |mutation: TeamMutation| async move {
            let TeamMutation {
                tx,
                principal,
                team,
                via,
                ..
            } = &mutation;
            let tenant_id = s(team, "tenantId");
            if body.get("role").is_none() && body.get("expiresAt").is_none() {
                return Err(invalid_input("Nothing to update").into());
            }
            if *via == Via::Permission {
                let teams = module.all_teams(tx, tenant_id).await?;
                module
                    .assert_authority_over(
                        tx,
                        principal,
                        tenant_id,
                        &module.chain(&teams, s(team, "id"))?,
                    )
                    .await?;
            }
            let member = module
                .member_record(tx, team, body.get("identityId"))
                .await?;
            if s(&member, "source") == "sync" && body.get("expiresAt").is_some() {
                return Err(IamError::with_status(
                    "INVALID_TRANSITION",
                    "A synced membership ends with the source group membership; change it there",
                    409,
                )
                .into());
            }
            let mut next = member.clone();
            if let Some(role) = body.get("role") {
                next.insert("role".into(), v(choice(Some(role), TEAM_ROLES, "role")?));
            }
            if let Some(expires_at) = body.get("expiresAt") {
                next.shift_remove("expiresAt");
                if !expires_at.is_null() {
                    next.insert(
                        "expiresAt".into(),
                        number(ctx.binding_expiry(Some(expires_at))?),
                    );
                }
            }
            let previous_expiry = num(&member, "expiresAt");
            let next_expiry = num(&next, "expiresAt");
            // Maintainers act under the administrators' delegation: they never extend their own membership (a
            // temporary maintainer would make themselves permanent), and ending it early is leaving the team.
            if *via != Via::Permission
                && s(&member, "identityId") == principal.identity.id
                && body.get("expiresAt").is_some()
            {
                if let Some(previous) = previous_expiry
                    && next_expiry.is_none_or(|next| next > previous)
                {
                    return Err(access_denied(
                        "Maintainers cannot extend their own membership; ask an administrator",
                    )
                    .into());
                }
                if next_expiry != previous_expiry {
                    let held = module
                        .held_chain_groups(tx, team, s(&member, "identityId"))
                        .await?;
                    module
                        .assert_may_drop_denies(tx, principal, tenant_id, held)
                        .await?;
                }
            }
            // An administrator keeping someone longer, or appointing a maintainer (who then adds people), claims
            // license seats of a licensed team; shortening or demoting does not.
            let longer = previous_expiry
                .is_some_and(|previous| next_expiry.is_none_or(|next| next > previous));
            if *via == Via::Permission
                && (longer
                    || (s(&next, "role") == "maintainer" && s(&member, "role") != "maintainer"))
            {
                let teams = module.all_teams(tx, tenant_id).await?;
                module
                    .assert_may_claim_team_licenses(
                        tx,
                        principal,
                        tenant_id,
                        &module.chain(&teams, s(team, "id"))?,
                    )
                    .await?;
            }
            tx.put(members_collection(), &next).await?;
            sync_team_groups(tx, tenant_id, &json!([s(team, "id")]), ctx.now()).await?;
            let mut metadata = Map::new();
            metadata.insert(
                "identityId".into(),
                member.get("identityId").cloned().unwrap_or_default(),
            );
            metadata.insert("role".into(), next.get("role").cloned().unwrap_or_default());
            if let Some(expires_at) = next.get("expiresAt") {
                metadata.insert("expiresAt".into(), expires_at.clone());
            }
            if *via != Via::Permission {
                metadata.insert("via".into(), v(via.as_str()));
            }
            module
                .audit(tx, principal, "team:member:update", team, metadata)
                .await?;
            touched_ref.touch([s(&member, "identityId").to_owned()]);
            Ok(Value::Object(next))
        });
        let result = module
            .team_operation(
                credential,
                input.get("tenantId"),
                input.get("teamId"),
                "iam:teams:update",
                Some(Level::Maintainer),
                work,
            )
            .await?;
        Ok(Reply::json(
            module
                .reconciled(&string_member(&input, "tenantId"), &touched, result)
                .await?,
        ))
    }
}

/// Transaction-level team changes for configuration sync (org-sync.ts, `teamMutations(ctx)`): the same validation,
/// backing-group upkeep, and audit events as the API. Callers authorize each change first.
pub struct TeamMutations {
    module: TeamModule,
}

impl TeamMutations {
    /// `createTeam(tx, principal, tenant, input)`.
    pub async fn create_team(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant: &Tenant,
        input: &Map<String, Value>,
    ) -> OperationResult<Record> {
        self.module.create_team(tx, principal, tenant, input).await
    }

    /// `updateTeam(tx, principal, team, input)`.
    pub async fn update_team(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        team: &Record,
        input: &Map<String, Value>,
    ) -> OperationResult<Record> {
        self.module.update_team(tx, principal, team, input).await
    }

    /// `deleteTeam(tx, principal, team)`: the number of members the team had.
    pub async fn delete_team(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        team: &Record,
    ) -> IamResult<usize> {
        self.module.delete_team(tx, principal, team).await
    }

    /// `putMember(mutation, input, source)`.
    pub async fn put_member(
        &self,
        mutation: &TeamMutation,
        input: &Map<String, Value>,
        source: &str,
    ) -> OperationResult<Record> {
        self.module.put_member(mutation, input, source).await
    }

    /// `removeMember(tx, principal, team, member, action, via?)`.
    pub async fn remove_member(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        team: &Record,
        member: &Record,
        action: &str,
        via: Option<&str>,
    ) -> IamResult<()> {
        self.module
            .remove_member(tx, principal, team, member, action, via)
            .await
    }

    /// `memberRecord(tx, team, identityId)`.
    pub async fn member_record(
        &self,
        tx: &Store,
        team: &Record,
        identity_id: Option<&Value>,
    ) -> IamResult<Record> {
        self.module.member_record(tx, team, identity_id).await
    }

    /// `assertAuthorityOver(tx, principal, tenantId, teams)`.
    pub async fn assert_authority_over(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
        teams: &[Record],
    ) -> IamResult<()> {
        self.module
            .assert_authority_over(tx, principal, tenant_id, teams)
            .await
    }

    /// `assertMayClaimTeamLicenses(tx, principal, tenantId, teams)`.
    pub async fn assert_may_claim_team_licenses(
        &self,
        tx: &Store,
        principal: &AuthenticatedPrincipal,
        tenant_id: &str,
        teams: &[Record],
    ) -> OperationResult<()> {
        self.module
            .assert_may_claim_team_licenses(tx, principal, tenant_id, teams)
            .await
    }

    /// `allTeams(tx, tenantId)`: the tenant's teams by ID.
    pub async fn all_teams(
        &self,
        tx: &Store,
        tenant_id: &str,
    ) -> IamResult<IndexMap<String, Record>> {
        self.module.all_teams(tx, tenant_id).await
    }
}

/// Transaction-level team changes for configuration sync (org-sync.ts): the same validation, backing-group upkeep,
/// and audit events as the API. Callers authorize each change first.
pub fn team_mutations(ctx: &Arc<ServerContext>) -> IamResult<TeamMutations> {
    Ok(TeamMutations {
        module: TeamModule::new(ctx),
    })
}
