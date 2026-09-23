import 'server-only';
import type { Tenant } from 'better-iam';
import { getIam } from './iam';
import { credential } from './session';

export interface TenantNode {
  tenant: Tenant;
  depth: number;
}

/** Walks the tenant tree through the authenticated service so root override, not raw storage, grants visibility. */
export async function tenantTree(): Promise<TenantNode[]> {
  const iam = await getIam();
  const auth = await credential();
  const roots = await iam.store.find<Tenant>('tenants', { parentId: null });
  const result: TenantNode[] = [];
  const visit = async (tenant: Tenant, depth: number) => {
    result.push({ tenant, depth });
    if (depth >= 8) return;
    const children = await iam.api.tenants.listChildren(auth, { tenantId: tenant.id });
    for (const child of children.sort((a, b) => a.name.localeCompare(b.name)))
      await visit(child, depth + 1);
  };
  for (const root of roots) await visit(root, 0);
  return result;
}

export function joinLink(
  origin: string,
  template: string,
  tenantId: string,
  token: string,
  to?: string,
): string | undefined {
  if (template === 'magic-link' && to)
    return `${origin}/cloud/magic?tenant=${encodeURIComponent(tenantId)}&token=${encodeURIComponent(token)}&to=${encodeURIComponent(to)}`;
  if (template === 'owner-invitation')
    return `${origin}/cloud/join?kind=owner&tenant=${encodeURIComponent(tenantId)}&token=${encodeURIComponent(token)}`;
  if (template === 'member-invitation')
    return `${origin}/cloud/join?kind=member&tenant=${encodeURIComponent(tenantId)}&token=${encodeURIComponent(token)}`;
  if (template === 'password-reset')
    return `${origin}/cloud/reset?tenant=${encodeURIComponent(tenantId)}&token=${encodeURIComponent(token)}`;
  if (template === 'email-change')
    return `${origin}/cloud/confirm-email?tenant=${encodeURIComponent(tenantId)}&token=${encodeURIComponent(token)}`;
  if (template === 'verify-email')
    return `${origin}/cloud/verify-email?tenant=${encodeURIComponent(tenantId)}&token=${encodeURIComponent(token)}`;
  return undefined;
}
