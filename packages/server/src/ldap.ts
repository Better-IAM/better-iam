import {
  IamError,
  type AuthenticatedPrincipal,
  type IamStore,
  type Identity,
  type Json,
  type StoredRecord,
  type Tenant,
} from '@better-iam/core';
import type { ServerContext } from './context.js';
import type { Group, GroupMember } from './models.js';

/**
 * The server side of the LDAP directory gateway (`@better-iam/ldap`): each tenant can publish its directory under a
 * base DN of its own, so applications that only speak LDAP (VPNs, NAS devices, CI servers, wikis) look people and
 * groups up and check passwords against Better IAM. The gateway decodes LDAP; this module holds the settings, the
 * deployment-wide base DN index, and the directory view a bound account may read.
 */

export type LdapUidMode = 'email' | 'localPart' | 'id';

export interface LdapSettings extends StoredRecord {
  enabled: boolean;
  /** As entered (`dc=acme,dc=com`); `normalizedBaseDn` is the lowercased comparison form. */
  baseDn: string;
  normalizedBaseDn: string;
  /** What `uid` (and the people RDN) holds: the email (default), its local part (when unique), or the identity ID. */
  uid: LdapUidMode;
  /** People may bind with their password (default true). */
  peopleBind: boolean;
  /** Service accounts and agents may bind with an API key as the password (default true). */
  serviceBind: boolean;
  /** Binds over a connection without TLS are refused, except from loopback (default true). */
  requireTls: boolean;
  /** With `auto`, a password ending in six digits is also tried as password + one-time code when MFA is required. */
  mfaSuffix: 'auto' | 'never';
  /** List service accounts under `ou=services` (default false; they can always bind). */
  includeServiceAccounts: boolean;
  /** Declared identity attributes published on people's entries (default none: attributes may be sensitive). */
  attributes: string[];
  /** Groups to publish: every group, or `groupIds` only. */
  groups: 'all' | 'selected';
  groupIds: string[];
  updatedAt: number;
  updatedBy: string;
}

/** Deployment-wide index: one tenant per base DN (id = the normalized base DN). */
interface LdapBase extends StoredRecord {
  settingsId: string;
}

export const ldapCollections = ['ldapSettings', 'ldapBases'] as const;

const component = /^\s*([a-zA-Z][a-zA-Z0-9-]{0,31})\s*=\s*([a-zA-Z0-9](?:[a-zA-Z0-9 ._-]{0,126}[a-zA-Z0-9])?)\s*$/;

/**
 * Validates a base DN and returns its comparison form: `attr=value` components of letters, digits, spaces, `.`, `_`
 * and `-` (no escapes), lowercased with spaces collapsed, exactly as `@better-iam/ldap` normalizes DNs.
 */
export function normalizeBaseDn(value: unknown): { baseDn: string; normalized: string } {
  if (typeof value !== 'string' || !value.trim() || value.length > 512)
    throw new IamError('INVALID_INPUT', 'Enter a base DN such as dc=acme,dc=com');
  const parts = value.split(',');
  if (parts.length > 10) throw new IamError('INVALID_INPUT', 'A base DN has at most 10 components');
  const normalized = parts.map((part) => {
    const match = component.exec(part);
    if (!match) throw new IamError('INVALID_INPUT', 'Base DN components are attr=value with letters, digits, spaces, ".", "_" or "-"');
    return `${match[1]!.toLowerCase()}=${match[2]!.replace(/\s+/g, ' ').toLowerCase()}`;
  });
  if (['ou=people', 'ou=groups', 'ou=services'].includes(normalized[0]!))
    throw new IamError('INVALID_INPUT', 'The base DN cannot itself be ou=people, ou=groups or ou=services');
  return { baseDn: parts.map((part) => part.trim()).join(','), normalized: normalized.join(',') };
}

export function defaultLdapSettings(tenant: Tenant): LdapSettings {
  const slug = (tenant.slug ?? tenant.id).toLowerCase().replace(/[^a-z0-9-]/g, '-').replace(/^-+|-+$/g, '') || 'tenant';
  const baseDn = `o=${slug}`;
  return {
    id: tenant.id,
    tenantId: tenant.id,
    enabled: false,
    baseDn,
    normalizedBaseDn: baseDn,
    uid: 'email',
    peopleBind: true,
    serviceBind: true,
    requireTls: true,
    mfaSuffix: 'auto',
    includeServiceAccounts: false,
    attributes: [],
    groups: 'all',
    groupIds: [],
    updatedAt: 0,
    updatedBy: '',
  };
}

export async function loadLdapSettings(tx: IamStore, tenant: Tenant): Promise<LdapSettings> {
  const stored = await tx.get<LdapSettings>('ldapSettings', tenant.id);
  return stored && stored.tenantId === tenant.id ? { ...defaultLdapSettings(tenant), ...stored } : defaultLdapSettings(tenant);
}

/** Stores settings and keeps the base DN index in step (a base DN belongs to one tenant). */
export async function saveLdapSettings(tx: IamStore, settings: LdapSettings, previous?: LdapSettings): Promise<LdapSettings> {
  if (previous && previous.normalizedBaseDn !== settings.normalizedBaseDn) {
    const old = await tx.get<LdapBase>('ldapBases', previous.normalizedBaseDn);
    if (old?.tenantId === settings.tenantId) await tx.delete('ldapBases', old.id);
  }
  if (settings.enabled) {
    const owner = await tx.get<LdapBase>('ldapBases', settings.normalizedBaseDn);
    if (owner && owner.tenantId !== settings.tenantId)
      throw new IamError('LDAP_BASE_TAKEN', 'Another organization publishes its directory under this base DN', 409);
    if (!owner)
      await tx.insert<LdapBase>('ldapBases', {
        id: settings.normalizedBaseDn,
        tenantId: settings.tenantId,
        settingsId: settings.id,
      });
  } else {
    const owner = await tx.get<LdapBase>('ldapBases', settings.normalizedBaseDn);
    if (owner?.tenantId === settings.tenantId) await tx.delete('ldapBases', owner.id);
  }
  return (await tx.get<LdapSettings>('ldapSettings', settings.id))
    ? tx.put<LdapSettings>('ldapSettings', settings)
    : tx.insert<LdapSettings>('ldapSettings', settings);
}

export interface LdapPerson {
  id: string;
  uid: string;
  email?: string;
  name?: string;
  emailVerified: boolean;
  attributes: Record<string, Json>;
  groupIds: string[];
}
export interface LdapGroupView {
  id: string;
  name: string;
  description?: string;
  memberIds: string[];
}
export interface LdapService {
  id: string;
  name: string;
  kind: string;
  groupIds: string[];
}
/** What a bound account may read: everyone (`full`, with `iam:ldap:read`) or only itself (`self`). */
export interface LdapDirectory {
  tenantId: string;
  tenantName: string;
  baseDn: string;
  uid: LdapUidMode;
  scope: 'full' | 'self';
  people: LdapPerson[];
  groups: LdapGroupView[];
  services: LdapService[];
  generatedAt: number;
}

const live = (ctx: ServerContext, identity: Identity) =>
  identity.status === 'active' && !ctx.identityExpired(identity);

/** Each person's `uid`: email, local part (the email where local parts collide), or identity ID. */
function uids(people: Identity[], mode: LdapUidMode): Map<string, string> {
  const result = new Map<string, string>();
  const local = (identity: Identity) => (identity.email ?? identity.id).split('@')[0]!.toLowerCase();
  const counts = new Map<string, number>();
  if (mode === 'localPart') for (const person of people) counts.set(local(person), (counts.get(local(person)) ?? 0) + 1);
  for (const person of people)
    result.set(
      person.id,
      mode === 'id'
        ? person.id
        : mode === 'localPart' && counts.get(local(person)) === 1
          ? local(person)
          : (person.email ?? person.id).toLowerCase(),
    );
  return result;
}

/** Builds the directory view of a tenant: active people, published groups and (optionally) service accounts. */
export async function buildLdapDirectory(
  ctx: ServerContext,
  tx: IamStore,
  tenant: Tenant,
  settings: LdapSettings,
  self?: AuthenticatedPrincipal,
): Promise<LdapDirectory> {
  const identities = (await tx.find<Identity>('identities', { tenantId: tenant.id })).filter((identity) =>
    live(ctx, identity),
  );
  const people = identities.filter((identity) => identity.kind === 'user');
  const machines = identities.filter((identity) => identity.kind !== 'user');
  const uidOf = uids(people, settings.uid);
  let groups = await tx.find<Group>('groups', { tenantId: tenant.id });
  if (settings.groups === 'selected') groups = groups.filter((group) => settings.groupIds.includes(group.id));
  const members = new Map<string, string[]>();
  const memberships = new Map<string, string[]>();
  for (const group of groups) {
    const ids = (await tx.find<GroupMember>('groupMembers', { groupId: group.id }))
      .filter((member) => ctx.liveMembership(member))
      .map((member) => member.identityId);
    members.set(group.id, ids);
    for (const identityId of ids) memberships.set(identityId, [...(memberships.get(identityId) ?? []), group.id]);
  }
  const alive = new Set(identities.map((identity) => identity.id));
  let personViews: LdapPerson[] = people.map((person) => ({
    id: person.id,
    uid: uidOf.get(person.id)!,
    ...(person.email ? { email: person.email } : {}),
    ...(person.name ? { name: person.name } : {}),
    emailVerified: person.emailVerified === true,
    attributes: Object.fromEntries(
      settings.attributes.flatMap((name) => {
        const value = (person.attributes as Record<string, Json> | undefined)?.[name];
        return value === undefined || value === null ? [] : [[name, value]];
      }),
    ),
    groupIds: memberships.get(person.id) ?? [],
  }));
  let groupViews: LdapGroupView[] = groups.map((group) => ({
    id: group.id,
    name: group.name,
    ...(typeof (group as { description?: unknown }).description === 'string'
      ? { description: (group as { description: string }).description }
      : {}),
    memberIds: (members.get(group.id) ?? []).filter((identityId) => alive.has(identityId)),
  }));
  let services: LdapService[] = settings.includeServiceAccounts
    ? machines.map((machine) => ({
        id: machine.id,
        name: machine.name ?? machine.id,
        kind: machine.kind,
        groupIds: memberships.get(machine.id) ?? [],
      }))
    : [];
  if (self) {
    // Only the caller's own entry, and their groups with only themselves as a member.
    const me = self.identity.id;
    personViews = personViews.filter((person) => person.id === me);
    services = services.filter((service) => service.id === me);
    groupViews = groupViews
      .filter((group) => group.memberIds.includes(me))
      .map((group) => ({ ...group, memberIds: [me] }));
  }
  return {
    tenantId: tenant.id,
    tenantName: tenant.name,
    baseDn: settings.baseDn,
    uid: settings.uid,
    scope: self ? 'self' : 'full',
    people: personViews.sort((a, b) => (a.uid < b.uid ? -1 : 1)),
    groups: groupViews.sort((a, b) => (a.name < b.name ? -1 : 1)),
    services: services.sort((a, b) => (a.name < b.name ? -1 : 1)),
    generatedAt: ctx.now(),
  };
}

/** The deployment-side lookups the gateway needs before anyone is bound (no credential; no secrets). */
export function createLdapRuntime(ctx: ServerContext) {
  const tenantFor = async (tx: IamStore, normalizedBaseDn: string) => {
    const base = await tx.get<LdapBase>('ldapBases', normalizedBaseDn);
    if (!base) return undefined;
    const tenant = await tx.get<Tenant>('tenants', base.tenantId);
    if (!tenant) return undefined;
    if ((await ctx.ancestry(tx, tenant)).some((item) => item.status !== 'active')) return undefined;
    const settings = await loadLdapSettings(tx, tenant);
    return settings.enabled && settings.normalizedBaseDn === normalizedBaseDn ? { tenant, settings } : undefined;
  };
  return {
    /**
     * The tenant publishing its directory under a normalized base DN, with its gateway settings; undefined when none
     * does, it is off, or the organization is not active.
     */
    async tenantForBase(normalizedBaseDn: string) {
      const found = await tenantFor(ctx.store, normalizedBaseDn);
      return found
        ? {
            tenantId: found.tenant.id,
            tenantName: found.tenant.name,
            baseDn: found.settings.baseDn,
            normalizedBaseDn: found.settings.normalizedBaseDn,
            uid: found.settings.uid,
            peopleBind: found.settings.peopleBind,
            serviceBind: found.settings.serviceBind,
            requireTls: found.settings.requireTls,
            mfaSuffix: found.settings.mfaSuffix,
          }
        : undefined;
    },
    /**
     * The sign-in email of the person a people RDN value names (`uid` as the tenant configured it), or the service
     * account a name (or, when names collide, an ID) names; undefined when nobody matches. Only active members resolve.
     * `mfa` says how a person's bind must authenticate: `none` (the password), `totp` (the password followed by the
     * current authenticator code) or `unavailable` (MFA is required but no authenticator is enrolled, which LDAP cannot
     * satisfy), so the gateway makes exactly one sign-in attempt per bind.
     */
    async resolveBindName(
      tenantId: string,
      kind: 'person' | 'service',
      value: string,
    ): Promise<{ identityId: string; email?: string; mfa?: 'none' | 'totp' | 'unavailable' } | undefined> {
      const tenant = await ctx.store.get<Tenant>('tenants', tenantId);
      if (!tenant) return undefined;
      const settings = await loadLdapSettings(ctx.store, tenant);
      const wanted = value.toLowerCase();
      const identities = (await ctx.store.find<Identity>('identities', { tenantId })).filter((identity) =>
        live(ctx, identity),
      );
      if (kind === 'service') {
        const machines = identities.filter((identity) => identity.kind !== 'user');
        const named = machines.filter((identity) => (identity.name ?? '').toLowerCase() === wanted);
        if (named.length === 1) return { identityId: named[0]!.id };
        const byId = machines.find((identity) => identity.id.toLowerCase() === wanted);
        return byId ? { identityId: byId.id } : undefined;
      }
      const people = identities.filter((identity) => identity.kind === 'user');
      const uidOf = uids(people, settings.uid);
      const person = people.find((identity) => uidOf.get(identity.id) === wanted);
      if (!person) return undefined;
      let mfa: 'none' | 'totp' | 'unavailable' = 'none';
      if (await ctx.auth.mfaRequired(ctx.store, person))
        mfa = (await ctx.store.get<{ enabled?: boolean } & StoredRecord>('authMfa', person.id))?.enabled ? 'totp' : 'unavailable';
      return { identityId: person.id, ...(person.email ? { email: person.email } : {}), mfa };
    },
  };
}
