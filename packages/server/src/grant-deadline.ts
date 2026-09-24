import { matchPattern, type AuthenticatedPrincipal, type IamStore, type PolicyDocument } from '@better-iam/core';
import { insideWindow, type ServerContext } from './context.js';
import type { GroupMember } from './models.js';

/**
 * How long something a grant allowed may outlive it: credentials minted from access (SSH certificates, verifiable
 * credentials) are capped at the earliest end among the time-limited sources that can allow `action`.
 */

/** Whether a policy document can allow `action`. */
const grants = (documents: PolicyDocument[], action: string) =>
  documents.some((document) =>
    document.statements.some(
      (statement) => statement.effect === 'allow' && statement.actions.some((pattern) => matchPattern(pattern, action)),
    ),
  );

/** When a recurring window that is open at `now` closes, searched in five-minute steps up to `horizon`. */
function windowClose(window: Parameters<typeof insideWindow>[0], now: number, horizon: number): number {
  for (let at = now + 5 * 60_000; at < horizon; at += 5 * 60_000) if (!insideWindow(window, at)) return at;
  return horizon;
}

/**
 * The latest something may stay valid given the caller's time-limited grants of `action`: the earliest end among the
 * bindings, just-in-time activations, group memberships and access windows that can grant it (a grant that ends takes
 * it along; a standing one sets no limit). Assumed roles and temporary sessions are bounded by their session instead.
 */
export async function grantDeadline(
  ctx: ServerContext,
  tx: IamStore,
  principal: AuthenticatedPrincipal,
  tenantId: string,
  horizon: number,
  action: string,
): Promise<number> {
  const kind = principal.session.kind;
  if ((kind !== 'user' && kind !== 'api-key') || principal.identity.tenantId !== tenantId) return horizon;
  const now = ctx.now();
  let deadline = horizon;
  for (const binding of await ctx.decisions.effectiveBindings(tx, tenantId, principal.identity.id)) {
    if (!binding.role || !ctx.liveBinding(binding) || (binding.eligible && !binding.activation)) continue;
    let end = binding.expiresAt ?? Infinity;
    if (binding.activation) end = Math.min(end, binding.activation.expiresAt);
    if (binding.via !== 'identity') {
      const membership = (
        await tx.find<GroupMember>('groupMembers', {
          groupId: binding.via.groupId,
          identityId: principal.identity.id,
        })
      )[0];
      if (membership?.expiresAt !== undefined) end = Math.min(end, membership.expiresAt);
    }
    if (binding.window) end = Math.min(end, windowClose(binding.window, now, horizon));
    if (end >= deadline) continue;
    const paths = await ctx.decisions.roleGrants(tx, binding.role, tenantId, [], binding.authorityId);
    if (grants(paths.flatMap((path) => path.grants), action)) deadline = end;
  }
  return deadline;
}
