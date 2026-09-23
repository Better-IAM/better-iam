import {
  IamError,
  type AuditEvent,
  type AuthenticatedPrincipal,
  type IamPlugin,
  type IamStore,
  type Identity,
  type PolicyDocument,
  type StoredRecord,
  type Tenant,
  type TenantLimits,
} from '@better-iam/core';
import type { AuthService } from '@better-iam/auth';
import type { Catalog } from './catalog.js';
import type {
  AccessWindow,
  Binding,
  GrantAuthority,
  GroupMember,
  Policy,
  Role,
  TenantAlias,
} from './models.js';
import type { BetterIamOptions, ProtocolMount, ServerConfig } from './options.js';
import { all, id } from './utils.js';
import { integer, object, text } from './validation.js';
import type { DecisionService } from './decisions.js';
import type { EventService } from './events.js';
import type { FlowService } from './flows.js';
import type { Observer } from './observe.js';
import type { OperationService } from './operations.js';
import type { PrincipalService } from './principals.js';
import type { UsageRecorder } from './usage.js';
import type { SessionTokenSigner } from './token-signing.js';
import type { WebIdentityVerifier } from './web-identity.js';
import type { HostService } from './hosts.js';

export type EventSubscriber = {
  patterns: string[];
  handler: (event: AuditEvent) => Promise<void> | void;
};

/**
 * Everything the service modules share: configuration, storage, authentication, the catalog, and the
 * record helpers below. Service modules are attached after construction and reached through this object
 * at call time, which keeps the modules free of import cycles.
 */
export interface ServerContext extends RecordHelpers {
  readonly options: BetterIamOptions;
  readonly config: ServerConfig;
  readonly store: IamStore;
  readonly auth: AuthService;
  readonly plugins: IamPlugin[];
  readonly catalog: Catalog;
  readonly subscribers: Set<EventSubscriber>;
  readonly mountedProtocols: ProtocolMount[];
  readonly observe: Observer;
  now(): number;
  events: EventService;
  decisions: DecisionService;
  principals: PrincipalService;
  operations: OperationService;
  flows: FlowService;
  usage: UsageRecorder;
  /** Signs and verifies IAM session JWTs; present only when `sts.jwt` is configured. */
  sessionTokens?: SessionTokenSigner;
  /** Verifies external OIDC tokens for web-identity federation; present when `sts.webIdentity` is enabled. */
  webIdentity?: WebIdentityVerifier;
  /** Organization sign-in addresses and regions (`hosts`, `regions` options). */
  hosts: HostService;
  /** The billing ledger (billing-service.ts): modules push already-priced usage into it (inference). */
  billing?: import('./billing-service.js').BillingHooks;
}

export interface RecordHelpers {
  tenant(tx: IamStore, tenantId: string): Promise<Tenant>;
  /** The tenant and its ancestors up to the root; rejects cycles and excessive depth. */
  ancestry(tx: IamStore, target: Tenant): Promise<Tenant[]>;
  /** Ancestor tenant IDs, tolerant of tenants that no longer exist (events recorded during a purge). */
  ancestorIds(tx: IamStore, tenantId: string): Promise<string[]>;
  /** The protected universal authority: a root-tenant human with the root capability in an MFA user session. */
  rootPrincipal(tx: IamStore, principal: AuthenticatedPrincipal): Promise<boolean>;
  /** The ceilings of an authority and its parents, or undefined when any link is revoked or missing. */
  authorityChain(tx: IamStore, authorityId: string): Promise<PolicyDocument[] | undefined>;
  scoped<T extends StoredRecord>(
    tx: IamStore,
    collection: string,
    recordId: string,
    tenantId: string,
  ): Promise<T>;
  /** A tenant identity that is not deleted; deleted identities remain readable as historical principals only. */
  activeIdentity(tx: IamStore, identityId: string, tenantId: string): Promise<Identity>;
  serviceAccount(tx: IamStore, identityId: string, tenantId: string): Promise<Identity>;
  claimSlug(tx: IamStore, tenantId: string, value: unknown): Promise<string>;
  protectLastOwner(tx: IamStore, identity: Identity): Promise<void>;
  /** Revokes every session an identity holds directly or through role assumption. */
  revokeAll(tx: IamStore, identityId: string): Promise<void>;
  /** The authority a caller grants under: an explicit one they own, a root-issued one, or their active delegated authority. */
  grantingAuthority(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    tenantId: string,
    authorityId?: string,
  ): Promise<GrantAuthority>;
  /** Grant-bearing records (roles, policies) may only be edited by their issuing authority or by root. */
  canEditGrantResource(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    record: StoredRecord,
  ): Promise<void>;
  /** Creates the protected Owner policy, role, and binding for a newly activated tenant. */
  ownerSetup(
    tx: IamStore,
    realm: Tenant,
    identity: Identity,
    authority: GrantAuthority,
  ): Promise<void>;
  /** A binding that grants right now: started (`startsAt`) and not expired. */
  liveBinding(binding: Binding): boolean;
  /** A temporary binding past its end; the purge worker removes it. Future-dated bindings are not expired. */
  expiredBinding(binding: Binding): boolean;
  /** A group membership that counts right now (no expiry, or one still ahead). */
  liveMembership(member: GroupMember): boolean;
  bindingExpiry(value: unknown): number;
  /** Validates a future start (epoch milliseconds, not in the past, within ten years). */
  bindingStart(value: unknown): number;
  /** True once an identity's scheduled deactivation has passed; its credentials are refused until the worker disables it. */
  identityExpired(identity: Identity): boolean;
  /** Validates a recurring access window (days, `HH:MM` bounds, an IANA time zone). */
  accessWindow(value: unknown): AccessWindow;
  /** True when a binding has no window or the current time falls inside it. */
  withinWindow(binding: Binding, at?: number): boolean;
  /** Rejects with LIMIT_EXCEEDED when adding `adding` records would exceed the tenant's plan limit for `key`. */
  enforceLimit(
    tx: IamStore,
    tenant: Tenant,
    key: keyof TenantLimits,
    count: () => Promise<number>,
    adding?: number,
  ): Promise<void>;
}

const weekdays: Record<string, number> = { Sun: 0, Mon: 1, Tue: 2, Wed: 3, Thu: 4, Fri: 5, Sat: 6 };
const clock = /^([01]\d|2[0-3]):([0-5]\d)$/;
const minutesOf = (value: string): number => {
  const match = clock.exec(value);
  if (!match) throw new IamError('INVALID_INPUT', 'Window times must be HH:MM');
  return Number(match[1]) * 60 + Number(match[2]);
};
/** Local weekday and minute of day of an instant in a time zone, through Intl. */
function localTime(at: number, timeZone: string): { day: number; minutes: number } {
  const parts = new Intl.DateTimeFormat('en-US', {
    timeZone,
    weekday: 'short',
    hour: '2-digit',
    minute: '2-digit',
    hourCycle: 'h23',
  }).formatToParts(new Date(at));
  const read = (type: string) => parts.find((part) => part.type === type)?.value ?? '';
  return {
    day: weekdays[read('weekday')] ?? 0,
    minutes: (Number(read('hour')) % 24) * 60 + Number(read('minute')),
  };
}
/** Whether an instant lies inside a recurring window; overnight windows count as the day they start on. */
export function insideWindow(window: AccessWindow, at: number): boolean {
  const { day, minutes } = localTime(at, window.timeZone);
  const from = minutesOf(window.from);
  const to = minutesOf(window.to);
  const days = window.days ?? [0, 1, 2, 3, 4, 5, 6];
  if (from < to) return minutes >= from && minutes < to && days.includes(day);
  // Wraps past midnight: the evening part belongs to today, the early part to the day the window started.
  if (minutes >= from) return days.includes(day);
  if (minutes < to) return days.includes((day + 6) % 7);
  return false;
}

const limitLabels: Record<keyof TenantLimits, string> = {
  identities: 'member',
  serviceAccounts: 'service account',
  agents: 'agent',
  groups: 'group',
  roles: 'role',
  policies: 'policy',
  resources: 'resource',
  webhooks: 'webhook',
};

export function slug(value: unknown): string {
  const result = text(value, 'slug', 63).toLowerCase();
  if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(result))
    throw new IamError('INVALID_INPUT', 'Slug must use 1-63 lowercase letters, digits, or hyphens');
  return result;
}

export function createContext(
  base: Pick<
    ServerContext,
    'options' | 'config' | 'store' | 'auth' | 'plugins' | 'catalog' | 'now' | 'observe'
  >,
): ServerContext {
  const { config, auth } = base;
  const helpers: RecordHelpers = {
    async tenant(tx, tenantId) {
      text(tenantId, 'tenantId');
      const found = await tx.get<Tenant>('tenants', tenantId);
      if (!found) throw new IamError('NOT_FOUND', 'Tenant not found', 404);
      return found;
    },
    async ancestry(tx, target) {
      const list = [target];
      const seen = new Set([target.id]);
      while (list.at(-1)!.parentId) {
        const parent = await helpers.tenant(tx, list.at(-1)!.parentId!);
        if (seen.has(parent.id) || list.length > config.maxDepth)
          throw new IamError('INVALID_HIERARCHY', 'Invalid tenant hierarchy', 500);
        list.push(parent);
        seen.add(parent.id);
      }
      return list;
    },
    async ancestorIds(tx, tenantId) {
      const ids: string[] = [];
      let current: string | null = tenantId;
      while (current && ids.length <= config.maxDepth && !ids.includes(current)) {
        ids.push(current);
        const realm: Tenant | undefined = await tx.get<Tenant>('tenants', current);
        current = realm?.parentId ?? null;
      }
      return ids;
    },
    async rootPrincipal(tx, principal) {
      const realm = await helpers.tenant(tx, principal.identity.tenantId);
      return (
        realm.type === 'root' &&
        realm.parentId === null &&
        principal.identity.rootAdmin &&
        principal.session.kind === 'user' &&
        principal.session.mfa
      );
    },
    async authorityChain(tx, authorityId) {
      const policies: PolicyDocument[] = [];
      const seen = new Set<string>();
      let current: string | undefined = authorityId;
      while (current) {
        if (seen.has(current) || seen.size > 100) return undefined;
        seen.add(current);
        const authority: GrantAuthority | undefined = await tx.get<GrantAuthority>(
          'grantAuthorities',
          current,
        );
        if (!authority || authority.revoked) return undefined;
        policies.push(authority.ceiling);
        current = authority.parentAuthorityId;
      }
      return policies;
    },
    async scoped(tx, collection, recordId, tenantId) {
      const record = await tx.get(collection, text(recordId, 'id'));
      if (!record || record.tenantId !== tenantId)
        throw new IamError('NOT_FOUND', 'Resource not found', 404);
      return record as never;
    },
    async activeIdentity(tx, identityId, tenantId) {
      const identity = await helpers.scoped<Identity>(tx, 'identities', identityId, tenantId);
      if (identity.status === 'deleted')
        throw new IamError('NOT_FOUND', 'Identity has been deleted', 404);
      return identity;
    },
    async serviceAccount(tx, identityId, tenantId) {
      const account = await helpers.scoped<Identity>(tx, 'identities', identityId, tenantId);
      if (account.kind !== 'service')
        throw new IamError('NOT_FOUND', 'Service account not found', 404);
      return account;
    },
    async claimSlug(tx, tenantId, value) {
      const alias = slug(value);
      if (await tx.get<TenantAlias>('tenantAliases', alias))
        throw new IamError('SLUG_TAKEN', 'This slug is already in use', 409);
      await tx.insert<TenantAlias>('tenantAliases', { id: alias, tenantId, createdAt: Date.now() });
      return alias;
    },
    async protectLastOwner(tx, identity) {
      if (identity.status !== 'active') return;
      if (
        identity.owner &&
        (
          await tx.find<Identity>('identities', {
            tenantId: identity.tenantId,
            owner: true,
            status: 'active',
          })
        ).length <= 1
      )
        throw new IamError('LAST_OWNER', 'Cannot remove the final active owner', 409);
      if (
        identity.rootAdmin &&
        (
          await tx.find<Identity>('identities', {
            tenantId: identity.tenantId,
            rootAdmin: true,
            status: 'active',
          })
        ).length <= 1
      )
        throw new IamError('LAST_ROOT_ADMIN', 'Cannot remove the final root administrator', 409);
    },
    async revokeAll(tx, identityId) {
      await auth.revokeIdentity(tx, identityId);
      for (const session of await tx.find('sessions', { originalIdentityId: identityId }))
        await tx.delete('sessions', session.id);
    },
    async grantingAuthority(tx, principal, tenantId, authorityId) {
      if (authorityId) {
        const authority = await helpers.scoped<GrantAuthority>(
          tx,
          'grantAuthorities',
          authorityId,
          tenantId,
        );
        if (
          !authority.revoked &&
          (authority.identityId === principal.identity.id ||
            (await helpers.rootPrincipal(tx, principal))) &&
          (await helpers.authorityChain(tx, authority.id))
        )
          return authority;
        throw new IamError(
          'ACCESS_DENIED',
          'Cannot use another administrator’s grant authority',
          403,
        );
      }
      if (await helpers.rootPrincipal(tx, principal)) {
        let authority = (
          await tx.find<GrantAuthority>('grantAuthorities', {
            tenantId,
            identityId: principal.identity.id,
            rootIssued: true,
          })
        )[0];
        if (!authority)
          authority = await tx.insert('grantAuthorities', {
            id: id(),
            tenantId,
            identityId: principal.identity.id,
            rootIssued: true,
            ceiling: all,
            revoked: false,
          });
        return authority;
      }
      const candidates = await tx.find<GrantAuthority>('grantAuthorities', {
        tenantId,
        identityId: principal.identity.id,
        revoked: false,
      });
      for (const authority of candidates)
        if (await helpers.authorityChain(tx, authority.id)) return authority;
      throw new IamError(
        'GRANT_AUTHORITY_REQUIRED',
        'An active delegated grant authority is required',
        403,
      );
    },
    async canEditGrantResource(tx, principal, record) {
      if (await helpers.rootPrincipal(tx, principal)) return;
      if (typeof record.authorityId !== 'string')
        throw new IamError(
          'PROTECTED_RESOURCE',
          'This resource is controlled by a superior authority',
          403,
        );
      await helpers.grantingAuthority(tx, principal, record.tenantId, record.authorityId);
    },
    async ownerSetup(tx, realm, identity, authority) {
      const policy: Policy = {
        id: id(),
        tenantId: realm.id,
        name: 'Owner',
        uniqueKey: 'system:owner',
        document: all,
        version: 1,
      };
      const role: Role = {
        id: id(),
        tenantId: realm.id,
        name: 'Owner',
        uniqueKey: 'system:owner',
        policyIds: [policy.id],
        protected: true,
      };
      await tx.insert('policies', policy);
      await tx.insert('roles', role);
      await tx.put('grantAuthorities', { ...authority, identityId: identity.id });
      await tx.insert<Binding>('bindings', {
        id: id(),
        tenantId: realm.id,
        subjectType: 'identity',
        subjectId: identity.id,
        roleId: role.id,
        authorityId: authority.id,
      });
    },
    async enforceLimit(tx, tenant, key, count, adding = 1) {
      const limit = tenant.limits?.[key];
      if (limit === undefined) return;
      if ((await count()) + adding > limit)
        throw new IamError(
          'LIMIT_EXCEEDED',
          `This tenant has reached its ${limitLabels[key]} limit (${limit})`,
          409,
        );
    },
    liveBinding: (binding) =>
      (binding.startsAt === undefined || binding.startsAt <= base.now()) &&
      (binding.expiresAt === undefined || binding.expiresAt > base.now()),
    expiredBinding: (binding) => binding.expiresAt !== undefined && binding.expiresAt <= base.now(),
    liveMembership: (member) => member.expiresAt === undefined || member.expiresAt > base.now(),
    bindingStart(value) {
      const startsAt = integer(value, 'startsAt', 0, Number.MAX_SAFE_INTEGER);
      if (startsAt < base.now() - 60_000)
        throw new IamError('INVALID_INPUT', 'startsAt must not be in the past');
      if (startsAt > base.now() + 10 * 365 * 86400000)
        throw new IamError('INVALID_INPUT', 'startsAt must be within ten years');
      return startsAt;
    },
    bindingExpiry(value) {
      const expiresAt = integer(value, 'expiresAt', 0, Number.MAX_SAFE_INTEGER);
      if (expiresAt <= base.now())
        throw new IamError('INVALID_INPUT', 'expiresAt must be in the future');
      if (expiresAt > base.now() + 10 * 365 * 86400000)
        throw new IamError('INVALID_INPUT', 'expiresAt must be within ten years');
      return expiresAt;
    },
    identityExpired: (identity) =>
      typeof identity.expiresAt === 'number' && identity.expiresAt <= base.now(),
    accessWindow(value) {
      const input = object(value);
      const window: AccessWindow = {
        from: text(input.from, 'window.from', 5),
        to: text(input.to, 'window.to', 5),
        timeZone: text(input.timeZone, 'window.timeZone', 64),
      };
      if (minutesOf(window.from) === minutesOf(window.to))
        throw new IamError('INVALID_INPUT', 'Window must not be empty');
      try {
        new Intl.DateTimeFormat('en-US', { timeZone: window.timeZone });
      } catch {
        throw new IamError('INVALID_INPUT', 'Unknown window.timeZone');
      }
      if (input.days !== undefined) {
        if (!Array.isArray(input.days) || input.days.length === 0 || input.days.length > 7)
          throw new IamError('INVALID_INPUT', 'window.days must list 1-7 weekdays');
        const days = [
          ...new Set(input.days.map((day) => integer(day, 'window.days', 0, 6))),
        ].sort();
        window.days = days;
      }
      return window;
    },
    withinWindow: (binding, at = base.now()) =>
      binding.window === undefined || insideWindow(binding.window, at),
  };
  // Service modules are attached by the composition root before any request is served.
  return {
    ...base,
    ...helpers,
    subscribers: new Set<EventSubscriber>(),
    mountedProtocols: [...(base.options.protocols ?? [])],
  } as ServerContext;
}
