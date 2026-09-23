import 'server-only';
import { headers } from 'next/headers';
import { redirect } from 'next/navigation';
import type { Tenant } from 'better-iam';
import { isIamError } from './errors';
import { getIam } from './iam';

export type CurrentSession = Awaited<
  ReturnType<Awaited<ReturnType<typeof getIam>>['api']['auth']['getSession']>
>;

/** The request's cookies as a Better IAM credential; server components never construct identity claims themselves. */
export async function credential() {
  return { headers: await headers() };
}

export async function currentSession(): Promise<CurrentSession | null> {
  const iam = await getIam();
  try {
    return await iam.api.auth.getSession(await credential());
  } catch {
    return null;
  }
}

export async function rootTenant(): Promise<Tenant | undefined> {
  const iam = await getIam();
  return (await iam.store.find<Tenant>('tenants', { parentId: null }))[0];
}

/** Platform administration requires an authenticated root administrator session. */
export async function requireRootSession(): Promise<CurrentSession> {
  const session = await currentSession();
  if (!session || !session.identity.rootAdmin) redirect('/admin/login');
  return session;
}

/** The cloud console addresses an organization by alias; a raw tenant ID is accepted for tenants without one. */
export async function resolveTenant(org: string): Promise<Tenant | undefined> {
  const iam = await getIam();
  try {
    return await iam.store.get<Tenant>(
      'tenants',
      (await iam.api.tenants.lookup({ slug: org })).tenantId,
    );
  } catch {
    return iam.store.get<Tenant>('tenants', org);
  }
}

export interface OrgContext {
  session: CurrentSession;
  tenant: Tenant;
  org: string;
}

/** The session must belong to the addressed organization; otherwise the member signs in to that organization first. */
export async function requireOrgSession(org: string): Promise<OrgContext> {
  const [session, tenant] = await Promise.all([currentSession(), resolveTenant(org)]);
  if (!tenant || tenant.status !== 'active') redirect('/cloud');
  if (!session || session.session.tenantId !== tenant.id)
    redirect(`/cloud/login?org=${encodeURIComponent(org)}`);
  return { session, tenant, org };
}

/** Reads that a member may lack permission for render as "not available" instead of failing the page. */
export async function tryRead<T>(read: () => Promise<T>): Promise<T | undefined> {
  try {
    return await read();
  } catch (error) {
    if (isIamError(error)) return undefined;
    throw error;
  }
}
