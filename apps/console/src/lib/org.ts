import 'server-only';
import { isIamError } from './errors';
import { getIam } from './iam';
import { credential, requireOrgSession } from './session';

/** Everything an organization page needs: the verified session, the tenant, the IAM instance, and the request credential. */
export async function orgPage(org: string) {
  const context = await requireOrgSession(org);
  const iam = await getIam();
  const auth = await credential();
  return {
    ...context,
    iam,
    auth,
    tenantId: context.tenant.id,
    base: `/cloud/${encodeURIComponent(org)}`,
  };
}

export type OrgPage = Awaited<ReturnType<typeof orgPage>>;

/** Advisory decisions for rendering; the server still enforces each operation when it runs. */
export async function can(
  page: OrgPage,
  checks: { action: string; resource?: { type: string; id: string } }[],
): Promise<Record<string, boolean>> {
  const normalized = checks.map((check) => ({
    action: check.action,
    resource: check.resource ?? { type: 'iam', id: page.tenantId },
  }));
  try {
    const { results } = await page.iam.authorizeMany({
      ...page.auth,
      tenantId: page.tenantId,
      checks: normalized,
    });
    return Object.fromEntries(
      results.map((result) => [
        `${result.action}@${result.resource.type}/${result.resource.id}`,
        result.allowed,
      ]),
    );
  } catch (error) {
    if (isIamError(error))
      return Object.fromEntries(
        normalized.map((check) => [
          `${check.action}@${check.resource.type}/${check.resource.id}`,
          false,
        ]),
      );
    throw error;
  }
}

export const key = (action: string, resource?: { type: string; id: string }, tenantId?: string) =>
  `${action}@${resource ? `${resource.type}/${resource.id}` : `iam/${tenantId}`}`;
