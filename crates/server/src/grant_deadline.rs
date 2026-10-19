//! Port of `packages/server/src/grant-deadline.ts`: how long something a grant allowed may outlive it.
//!
//! Credentials minted from access (SSH certificates, verifiable credentials) are capped at the earliest end among the
//! time-limited sources that can allow `action`.

use better_iam_core::{
    AuthenticatedPrincipal, Effect, Filter, FindOptions, IamResult, PolicyDocument, SessionKind,
    js as core_js, match_pattern,
};

use crate::context::{ServerContext, Store, inside_window};
use crate::contracts::BindingVia;
use crate::models::AccessWindow;

/// Whether a policy document can allow `action`.
fn grants(documents: &[PolicyDocument], action: &str) -> bool {
    documents.iter().any(|document| {
        document.statements.iter().any(|statement| {
            statement.effect == Effect::Allow
                && statement
                    .actions
                    .iter()
                    .any(|pattern| match_pattern(pattern, action, None))
        })
    })
}

/// `windowClose(window, now, horizon)`: when a recurring window that is open at `now` closes, searched in
/// five-minute steps up to `horizon`.
fn window_close(window: &AccessWindow, now: f64, horizon: f64) -> IamResult<f64> {
    let mut at = now + 5.0 * 60_000.0;
    while at < horizon {
        if !inside_window(window, at)? {
            return Ok(at);
        }
        at += 5.0 * 60_000.0;
    }
    Ok(horizon)
}

/// `Math.min` (NaN wins).
fn min(a: f64, b: f64) -> f64 {
    if a.is_nan() || b.is_nan() {
        f64::NAN
    } else {
        a.min(b)
    }
}

/// `grantDeadline(ctx, tx, principal, tenantId, horizon, action)`: the latest something may stay valid given the
/// caller's time-limited grants of `action` (the earliest end among the bindings, just-in-time activations, group
/// memberships and access windows that can grant it). Assumed roles and temporary sessions are bounded by their
/// session instead.
pub async fn grant_deadline(
    ctx: &ServerContext,
    tx: &Store,
    principal: &AuthenticatedPrincipal,
    tenant_id: &str,
    horizon: f64,
    action: &str,
) -> IamResult<f64> {
    let kind = principal.session.kind;
    if (kind != SessionKind::User && kind != SessionKind::ApiKey)
        || principal.identity.tenant_id != tenant_id
    {
        return Ok(horizon);
    }
    let now = ctx.now();
    let mut deadline = horizon;
    let decisions = ctx.decisions()?;
    for binding in decisions
        .effective_bindings(tx, tenant_id, &principal.identity.id)
        .await?
    {
        let Some(role) = &binding.role else {
            continue;
        };
        if !ctx.live_binding(&binding.binding)
            || (binding.binding.eligible == Some(true) && binding.activation.is_none())
        {
            continue;
        }
        let mut end = binding.binding.expires_at.unwrap_or(f64::INFINITY);
        if let Some(activation) = &binding.activation {
            end = min(end, activation.expires_at);
        }
        if let BindingVia::Group(group_id) = &binding.via {
            let membership = tx
                .find(
                    "groupMembers",
                    &Filter::new()
                        .eq("groupId", group_id.clone())
                        .eq("identityId", principal.identity.id.clone()),
                    &FindOptions::default(),
                )
                .await?
                .into_iter()
                .next();
            // `Math.min(end, membership.expiresAt)` coerces what is stored (null counts as 0).
            if let Some(expires) = membership
                .as_ref()
                .and_then(|member| member.get("expiresAt"))
            {
                end = min(end, core_js::to_number(expires));
            }
        }
        if let Some(window) = &binding.binding.window {
            end = min(end, window_close(window, now, horizon)?);
        }
        if end >= deadline {
            continue;
        }
        let paths = decisions
            .role_grants(
                tx,
                role,
                tenant_id,
                &[],
                &binding.binding.authority_id,
                None,
                None,
            )
            .await?;
        let documents: Vec<PolicyDocument> =
            paths.into_iter().flat_map(|path| path.grants).collect();
        if grants(&documents, action) {
            deadline = end;
        }
    }
    Ok(deadline)
}
