import {
  IamError,
  canonicalJson,
  compareIds,
  evaluatePolicy,
  ipCounterKey,
  type AuthenticatedPrincipal,
  type Decision,
  type IamStore,
  type Identity,
  type PolicyDocument,
  type ResourceRef,
  type Session,
  type Tenant,
} from '@better-iam/core';
import { agentDecisionScope } from './agents.js';
import { agreementContext } from './agreements.js';
import { internalResourceTypes, managedResource, resolvedManaged } from './catalog.js';
import { isServerOwnedKey, sessionTagName } from './context-keys.js';
import type { ServerContext } from './context.js';
import {
  enabledFeatureKeys,
  featureContextKey,
  featureState,
  mentionsFeatures,
} from './features.js';
import { trustPassesSourceAttributes } from './flows.js';
import { resolveModelResource } from './inference.js';
import { mentionsOnboarding, onboardingContext } from './onboarding.js';
import { departmentContext } from './departments.js';
import { mentionedOrgKeys, teamContext } from './teams.js';
import { billingServiceOf, mentionsSpend } from './billing-service.js';
import { resolveSecretResource } from './vault.js';
import { consentContext, mentionsConsents } from './privacy.js';
import { resolveSshResource } from './ssh.js';
import { resolveCredentialTypeResource } from './vc.js';
import { mentionsRisk, riskContext } from './threats.js';
import { deviceContext, mentionsDevice, withRequestDevice } from './devices.js';
import type {
  Binding,
  BindingActivation,
  GroupMember,
  OidcProvider,
  Policy,
  PrincipalBoundary,
  Relationship,
  Role,
  Trust,
} from './models.js';
import type { AuthorizationRequest, ResolvedResource } from './options.js';
import { actsInOwnRight } from './session-kinds.js';
import { all } from './utils.js';
import { text } from './validation.js';

/**
 * The administrator behind an impersonation ("view as") session, acting through their own source session; undefined
 * for every other principal. currentPrincipal has already checked that the source session and identity are live.
 */
export async function impersonatingActor(
  tx: IamStore,
  principal: AuthenticatedPrincipal,
): Promise<AuthenticatedPrincipal | undefined> {
  const actorId = principal.session.impersonatorId;
  if (!actorId) return undefined;
  const sourceId = principal.session.impersonatorSessionId;
  const session = sourceId ? await tx.get<Session>('sessions', sourceId) : undefined;
  const identity = await tx.get<Identity>('identities', actorId);
  if (!session || !identity || session.identityId !== identity.id || identity.status !== 'active')
    throw new IamError('UNAUTHENTICATED', 'Impersonation has ended', 401);
  // The administrator's side of the decision sees the device this request proves (bound to the "view as" session),
  // when it is the administrator's own or shared.
  return withRequestDevice({ identity, session }, principal);
}

/**
 * Whether a type only a tenant registered (tenant-defined mode) must not answer for `action` from that tenant's
 * registry. Tenant types answer for their own actions (`{type}:{verb}`); the application's actions on a type it never
 * declared still go to resolveResource, as documented, so a tenant cannot register a type named after an application
 * type and answer for the application's resources (another tenant's documents, say) from its own registry.
 */
export function shadowsApplicationType(
  definition: { source?: string },
  type: string,
  action: string | undefined,
  resolver: boolean,
): boolean {
  return (
    resolver &&
    definition.source === 'tenant' &&
    action !== undefined &&
    !action.startsWith(`${type}:`)
  );
}

/** How deep an inheritance hierarchy is followed: roles.ts refuses writes past 200 roles, so none is cut short. */
const maxInheritedRoles = 256;

/** The deny statements of documents as one path that grants nothing. */
function denyPaths(documents: PolicyDocument[], authorityId: string): GrantPath[] {
  const grants = documents
    .map((document) => ({
      ...document,
      statements: document.statements.filter((statement) => statement.effect === 'deny'),
    }))
    .filter((document) => document.statements.length > 0);
  return grants.length ? [{ grants, boundaries: [], authorityId }] : [];
}

/**
 * Every deny statement a role carries: its inline document, its attached policies, and the roles it inherits. Used
 * where an authority behind the role has been revoked: what it granted lapses, what it forbade does not.
 */
async function roleDenies(
  tx: IamStore,
  role: Role,
  tenantId: string,
  authorityId: string,
  seen: Set<string>,
): Promise<GrantPath[]> {
  const documents: PolicyDocument[] = [];
  seen.add(role.id);
  for (const queue = [role]; queue.length; ) {
    const current = queue.pop()!;
    if (current.tenantId !== tenantId) continue;
    if (current.document) documents.push(current.document);
    for (const policyId of current.policyIds) {
      const policy = await tx.get<Policy>('policies', policyId);
      if (policy?.tenantId === tenantId) documents.push(policy.document);
    }
    for (const inheritedId of current.inherits ?? []) {
      if (seen.has(inheritedId) || seen.size > maxInheritedRoles) continue;
      seen.add(inheritedId);
      const inherited = await tx.get<Role>('roles', inheritedId);
      if (inherited && !inherited.protected) queue.push(inherited);
    }
  }
  return denyPaths(documents, authorityId);
}

/**
 * Every deny statement a role carries (inline, attached policies, inherited roles), as canonical JSON, whatever the
 * authorities behind them: what holders of the role are forbidden.
 */
export async function roleDenyStatements(tx: IamStore, role: Role): Promise<Set<string>> {
  const paths = await roleDenies(tx, role, role.tenantId, '', new Set());
  return new Set(
    paths.flatMap((path) =>
      path.grants.flatMap((document) => document.statements.map(canonicalJson)),
    ),
  );
}

/** The deny statements of a document, as canonical JSON. */
export function documentDenyStatements(document: PolicyDocument | undefined): Set<string> {
  return new Set(
    (document?.statements ?? [])
      .filter((statement) => statement.effect === 'deny')
      .map(canonicalJson),
  );
}

/** One way a principal receives a policy: the grant plus every ceiling that bounds it. */
export interface GrantPath {
  grants: PolicyDocument[];
  boundaries: PolicyDocument[];
  authorityId: string;
}
export type PreparedDecision =
  | { fixed: Decision }
  | {
      /** Evaluates the prepared grants against one resource, for the prepared action or an override. */
      evaluate(resource: ResolvedResource, action?: string): Decision;
      /** What `evaluate` decides from, read-only, for query planning (core `planResources`). */
      inputs?: DecisionInputs;
    };
/** The inputs of a prepared decision: everything but the resource. Treat as read-only. */
export interface DecisionInputs {
  /** Principal, request and tenant context keys. */
  context: Record<string, unknown>;
  /** Ceilings over every grant path. */
  boundaries: PolicyDocument[];
  /** Grant paths (deny-only paths included). */
  paths: GrantPath[];
  /** Deny statements across every path. */
  denies: PolicyDocument[];
  /** Relations the principal holds, keyed by `{type}/{id}`. */
  held: ReadonlyMap<string, ReadonlySet<string>>;
  /** A delegation's per-action confirmation gate, when the session has one. */
  confirm?: (action: string, resourceType: string, resourceId: string) => Decision | undefined;
}
export interface GrantSources {
  groupIds: Set<string>;
  bindings: Binding[];
}
/**
 * A binding that applies to an identity directly or through a group. Eligible bindings are listed whether or not
 * they are activated; `activation` is present only while the identity holds a live activation.
 */
export type EffectiveBinding = Binding & {
  role?: Role;
  via: 'identity' | { groupId: string };
  activation?: Pick<BindingActivation, 'id' | 'activatedAt' | 'expiresAt'>;
  /** An activation request awaiting approval (`expiresAt` is when the request lapses). */
  pendingActivation?: { id: string; requestedAt: number; expiresAt: number };
  /** Present for bindings with an access window: whether the window is open right now. */
  inWindow?: boolean;
};

export interface DecisionService {
  /**
   * The grant paths of a role: its inline document, its attached policies, and (recursively) the grants of the
   * roles it inherits, each bounded by every authority ceiling on the way down. `seen` guards against cycles.
   */
  roleGrants(
    tx: IamStore,
    role: Role,
    tenantId: string,
    ceilings: PolicyDocument[],
    authorityId: string,
    seen?: Set<string>,
    /** Receives, as paths that grant nothing, the denies of parts whose authority was revoked. */
    lapsed?: GrantPath[],
  ): Promise<GrantPath[]>;
  /**
   * The identity's group memberships and every live binding that applies to it directly or through a group.
   * Eligible bindings count only while the identity holds a live activation.
   */
  grantSources(tx: IamStore, identityId: string, tenantId: string): Promise<GrantSources>;
  /** The identity's live activations of eligible bindings, keyed by binding ID. */
  liveActivations(
    tx: IamStore,
    tenantId: string,
    identityId: string,
  ): Promise<Map<string, BindingActivation>>;
  /** Every live grant path of an identity: direct bindings and bindings inherited through groups. */
  identityGrants(
    tx: IamStore,
    identityId: string,
    tenantId: string,
    sources?: GrantSources,
    /** Receives, as paths that grant nothing, the denies of bindings, roles and policies whose authority was revoked. */
    lapsed?: GrantPath[],
  ): Promise<GrantPath[]>;
  /** Direct and group-derived role bindings: the effective role set of an identity. */
  effectiveBindings(
    tx: IamStore,
    tenantId: string,
    identityId: string,
  ): Promise<EffectiveBinding[]>;
  /**
   * Loads a resource's trusted attributes from the registry or the application resolver. With `action`, a type only a
   * tenant registered answers from its registry for that type's own actions alone (see shadowsApplicationType).
   */
  resolve(
    tx: IamStore,
    reference: ResourceRef,
    internal?: boolean,
    action?: string,
  ): Promise<ResolvedResource>;
  /**
   * Loads everything a decision needs except the resource: root override, tenant state, boundaries, and grant paths.
   * The returned evaluator can then be applied to many resources of the same tenant and action without re-reading storage.
   */
  prepareDecision(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    target: Tenant,
    action: string,
  ): Promise<PreparedDecision>;
  /** One authorization decision; `internalResource` accepts platform resource types without resolving them. */
  decide(
    tx: IamStore,
    principal: AuthenticatedPrincipal,
    request: AuthorizationRequest,
    internalResource?: boolean,
  ): Promise<Decision>;
  /** A principal for simulations and reviews: the identity in a synthetic, never-issued session. */
  simulatedPrincipal(identity: Identity, mfa?: boolean): AuthenticatedPrincipal;
}

/** Above this many groups one tenant-wide read is cheaper than a lookup per group. */
const GROUP_LOOKUP_LIMIT = 24;

/**
 * The bindings whose subject is the identity or one of the groups, in id order (the store's
 * order), found through the `subjectId` index instead of reading every binding of the tenant.
 */
async function subjectBindings(
  tx: IamStore,
  tenantId: string,
  identityId: string,
  groupIds: ReadonlySet<string>,
): Promise<Binding[]> {
  if (groupIds.size > GROUP_LOOKUP_LIMIT)
    return (await tx.find<Binding>('bindings', { tenantId })).filter((binding) =>
      binding.subjectType === 'identity'
        ? binding.subjectId === identityId
        : groupIds.has(binding.subjectId),
    );
  const found = await tx.find<Binding>('bindings', {
    tenantId,
    subjectType: 'identity',
    subjectId: identityId,
  });
  for (const groupId of groupIds)
    found.push(
      ...(await tx.find<Binding>('bindings', {
        tenantId,
        subjectType: 'group',
        subjectId: groupId,
      })),
    );
  return found.sort((left, right) => compareIds(left.id, right.id));
}

/** An ISO-8601 timestamp; a value that is not a usable time reads as the epoch, which fails freshness checks closed. */
function isoTime(value: unknown): string {
  return new Date(
    typeof value === 'number' && Math.abs(value) <= 8.64e15 ? value : 0,
  ).toISOString();
}

/**
 * The session-aware context keys (see context-keys.ts): always the session id, token issue and authentication times,
 * and the sorted tag keys; the rest only when their source is present. `principal.mfaTime` needs a first-hand second
 * factor (not a remembered device or impersonation), and `request.sourceIp` a client address the server saw that
 * parses as an IP, never for simulated principals.
 */
function sessionContextKeys(
  session: Session,
  clientIp: string | undefined,
): Record<string, unknown> {
  const tags =
    session.sessionTags && typeof session.sessionTags === 'object'
      ? Object.entries(session.sessionTags)
          .filter(
            (entry): entry is [string, string] =>
              typeof entry[1] === 'string' && sessionTagName(entry[0]) !== undefined,
          )
          .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
      : [];
  const keys: Record<string, unknown> = {
    'principal.sessionId': session.id,
    'principal.tokenIssueTime': isoTime(session.createdAt),
    'principal.authTime': isoTime(session.authenticatedAt),
    'principal.sessionTagKeys': tags.map(([key]) => key),
  };
  if (
    session.mfa === true &&
    typeof session.mfaAuthenticatedAt === 'number' &&
    Number.isFinite(session.mfaAuthenticatedAt) &&
    !session.trustedDeviceId &&
    !session.impersonatorId
  )
    keys['principal.mfaTime'] = isoTime(session.mfaAuthenticatedAt);
  if (session.kind === 'role' && typeof session.sourceTenantId === 'string')
    keys['principal.sourceTenantId'] = session.sourceTenantId;
  if (typeof session.sessionName === 'string') keys['principal.sessionName'] = session.sessionName;
  if (typeof session.sourceIdentity === 'string')
    keys['principal.sourceIdentity'] = session.sourceIdentity;
  for (const [key, value] of tags) keys[sessionTagName(key)!] = value;
  if (typeof session.webIdentity?.providerId === 'string')
    keys['principal.webIdentityProvider'] = session.webIdentity.providerId;
  if (typeof session.webIdentity?.subject === 'string')
    keys['principal.webIdentitySubject'] = session.webIdentity.subject;
  if (session.id !== 'simulation' && clientIp && ipCounterKey(clientIp) !== undefined)
    keys['request.sourceIp'] = clientIp;
  return keys;
}

export function createDecisions(ctx: ServerContext): DecisionService {
  const { options, catalog } = ctx;
  const service: DecisionService = {
    async roleGrants(tx, role, tenantId, ceilings, authorityId, seen = new Set<string>(), lapsed) {
      const paths: GrantPath[] = [];
      // As deep as roles.ts lets a hierarchy grow, so no inherited role (or its denies) is silently left out.
      if (role.tenantId !== tenantId || seen.has(role.id) || seen.size > maxInheritedRoles)
        return paths;
      seen.add(role.id);
      const roleCeilings =
        typeof role.authorityId === 'string'
          ? await ctx.authorityChain(tx, role.authorityId)
          : role.protected
            ? []
            : undefined;
      if (!roleCeilings) {
        if (lapsed) lapsed.push(...(await roleDenies(tx, role, tenantId, authorityId, seen)));
        return paths;
      }
      // Inherited roles are evaluated under this role's ceilings too, so inheriting cannot widen a grant.
      for (const inheritedId of role.inherits ?? []) {
        const inherited = await tx.get<Role>('roles', inheritedId);
        if (!inherited || inherited.protected) continue;
        paths.push(
          ...(await service.roleGrants(
            tx,
            inherited,
            tenantId,
            [...ceilings, ...roleCeilings],
            authorityId,
            seen,
            lapsed,
          )),
        );
      }
      if (role.document)
        paths.push({
          grants: [role.document],
          boundaries: [...ceilings, ...roleCeilings],
          authorityId,
        });
      for (const policyId of role.policyIds) {
        const policy = await tx.get<Policy>('policies', policyId);
        if (!policy || policy.tenantId !== tenantId) continue;
        const policyCeilings =
          typeof policy.authorityId === 'string'
            ? await ctx.authorityChain(tx, policy.authorityId)
            : policy.uniqueKey === 'system:owner'
              ? []
              : undefined;
        if (!policyCeilings) {
          lapsed?.push(...denyPaths([policy.document], authorityId));
          continue;
        }
        // A higher authority attaching a lower authority's mutable policy cannot
        // silently remove the limits under which that policy was created.
        paths.push({
          grants: [policy.document],
          boundaries: [...ceilings, ...roleCeilings, ...policyCeilings],
          authorityId,
        });
      }
      return paths;
    },
    async liveActivations(tx, tenantId, identityId) {
      const result = new Map<string, BindingActivation>();
      for (const activation of await tx.find<BindingActivation>('bindingActivations', {
        tenantId,
        identityId,
      }))
        if (
          activation.expiresAt > ctx.now() &&
          activation.status !== 'pending' &&
          activation.status !== 'denied'
        )
          result.set(activation.bindingId, activation);
      return result;
    },
    async grantSources(tx, identityId, tenantId) {
      const memberships = (
        await tx.find<GroupMember>('groupMembers', { tenantId, identityId })
      ).filter((member) => ctx.liveMembership(member));
      const groupIds = new Set(memberships.map((member) => member.groupId));
      const activations = await service.liveActivations(tx, tenantId, identityId);
      const bindings = (await subjectBindings(tx, tenantId, identityId, groupIds)).filter(
        (binding) =>
          ctx.liveBinding(binding) &&
          ctx.withinWindow(binding) &&
          (binding.eligible !== true || activations.has(binding.id)),
      );
      return { groupIds, bindings };
    },
    async identityGrants(tx, identityId, tenantId, sources, lapsed) {
      const { bindings } = sources ?? (await service.grantSources(tx, identityId, tenantId));
      const paths: GrantPath[] = [];
      for (const binding of bindings) {
        const role = await tx.get<Role>('roles', binding.roleId);
        if (!role || role.tenantId !== tenantId) continue;
        const ceilings = await ctx.authorityChain(tx, binding.authorityId);
        if (!ceilings) {
          if (lapsed)
            lapsed.push(...(await roleDenies(tx, role, tenantId, binding.authorityId, new Set())));
          continue;
        }
        paths.push(
          ...(await service.roleGrants(
            tx,
            role,
            tenantId,
            ceilings,
            binding.authorityId,
            undefined,
            lapsed,
          )),
        );
      }
      return paths;
    },
    async effectiveBindings(tx, tenantId, identityId) {
      const memberships = (
        await tx.find<GroupMember>('groupMembers', { tenantId, identityId })
      ).filter((member) => ctx.liveMembership(member));
      const groupIds = new Set(memberships.map((member) => member.groupId));
      const activations = await service.liveActivations(tx, tenantId, identityId);
      const pending = new Map<string, BindingActivation>();
      for (const activation of await tx.find<BindingActivation>('bindingActivations', {
        tenantId,
        identityId,
      }))
        if (activation.status === 'pending' && activation.expiresAt > ctx.now())
          pending.set(activation.bindingId, activation);
      const result: EffectiveBinding[] = [];
      for (const binding of await subjectBindings(tx, tenantId, identityId, groupIds)) {
        // Future-dated bindings are listed (with their start) but grant nothing until then.
        if (ctx.expiredBinding(binding)) continue;
        const role = await tx.get<Role>('roles', binding.roleId);
        const activation = binding.eligible ? activations.get(binding.id) : undefined;
        const request = binding.eligible ? pending.get(binding.id) : undefined;
        result.push({
          ...binding,
          role: role && role.tenantId === tenantId ? role : undefined,
          via: binding.subjectType === 'identity' ? 'identity' : { groupId: binding.subjectId },
          ...(binding.window ? { inWindow: ctx.withinWindow(binding) } : {}),
          ...(activation
            ? {
                activation: {
                  id: activation.id,
                  activatedAt: activation.activatedAt,
                  expiresAt: activation.expiresAt,
                },
              }
            : {}),
          ...(request
            ? {
                pendingActivation: {
                  id: request.id,
                  requestedAt: request.activatedAt,
                  expiresAt: request.expiresAt,
                },
              }
            : {}),
        });
      }
      return result;
    },
    async resolve(tx, reference, internal = false, action) {
      text(reference.type, 'resource type');
      text(reference.id, 'resource id');
      if (internal && internalResourceTypes.has(reference.type)) {
        // Vault secrets (`iam/vault/secrets/{name}`) carry their tags and settings (vault.ts).
        const secret = await resolveSecretResource(tx, reference);
        if (secret) return secret;
        // `iam/{type}/{id}` naming a registered managed resource carries that resource's owner, parent, and
        // attributes, so administrative actions such as sharing can be conditioned on them and on relations.
        const slash = reference.type === 'iam' ? reference.id.indexOf('/') : -1;
        if (slash > 0) {
          const record = await managedResource(
            tx,
            reference.tenantId,
            reference.id.slice(0, slash),
            reference.id.slice(slash + 1),
          );
          if (record) return { ...reference, attributes: resolvedManaged(record).attributes };
        }
        return reference;
      }
      // AI models (`inference` option) resolve from the inference catalog, inherited down the tenant tree.
      const model = await resolveModelResource(ctx, tx, reference);
      if (model) return model;
      // SSH logins and hosts (`ssh` option): `ssh-login/{host}/{login}` and `ssh-host/{host}` carry the host's labels.
      const ssh = await resolveSshResource(ctx, tx, reference);
      if (ssh) return ssh;
      // Credential types (`verifiableCredentials` option): `credential-type/{name}`.
      const credentialType = await resolveCredentialTypeResource(ctx, tx, reference);
      if (credentialType) return credentialType;
      const definition = await catalog.resourceTypeDefinition(
        tx,
        reference.tenantId,
        reference.type,
      );
      if (
        definition?.managed &&
        !shadowsApplicationType(definition, reference.type, action, !!options.resolveResource)
      ) {
        const record = await managedResource(tx, reference.tenantId, reference.type, reference.id);
        if (!record) throw new IamError('NOT_FOUND', 'Resource is not registered', 404);
        return resolvedManaged(record);
      }
      if (!options.resolveResource)
        throw new IamError(
          'RESOURCE_RESOLVER_REQUIRED',
          'Configure resolveResource for application resources',
        );
      const resolved = await options.resolveResource(reference);
      if (
        !resolved ||
        resolved.tenantId !== reference.tenantId ||
        resolved.id !== reference.id ||
        resolved.type !== reference.type
      )
        throw new IamError('RESOURCE_MISMATCH', 'Resource ownership mismatch', 403);
      return resolved;
    },
    async prepareDecision(tx, principal, target, action) {
      if (await ctx.rootPrincipal(tx, principal))
        return { fixed: { allowed: true, reason: 'ROOT_OVERRIDE', matched: [] } };
      const chain = await ctx.ancestry(tx, target);
      if (chain.some((realm) => realm.status !== 'active'))
        return { fixed: { allowed: false, reason: 'TENANT_INACTIVE', matched: [] } };
      if (principal.session.tenantId !== target.id)
        return { fixed: { allowed: false, reason: 'TENANT_MISMATCH', matched: [] } };
      const sources =
        principal.session.kind === 'role'
          ? { groupIds: new Set<string>(), bindings: [] as Binding[] }
          : await service.grantSources(tx, principal.identity.id, target.id);
      const roleIds =
        principal.session.kind === 'role'
          ? [principal.session.roleId!]
          : [...new Set(sources.bindings.map((binding) => binding.roleId))].sort();
      // A role session's role and trust, read once: the trust decides whether source attributes pass and
      // bounds the role's grants below.
      const role =
        principal.session.kind === 'role'
          ? await tx.get<Role>('roles', principal.session.roleId!)
          : undefined;
      const trust =
        principal.session.kind === 'role'
          ? await tx.get<Trust>('trusts', principal.session.trustId!)
          : undefined;
      // Untrusted or lower-precedence keys first: application context, plugin context, declared
      // identity attributes; the server-derived principal and request keys always win.
      const base: Record<string, unknown> = { ...(await options.resolveContext?.(principal)) };
      for (const plugin of ctx.plugins)
        if (plugin.resolveContext) Object.assign(base, await plugin.resolveContext(principal));
      // Keys only the server may set are removed, including the optional ones it leaves absent, so an
      // application or plugin value can never stand in for them (the bare `principal.sessionTags` too).
      for (const key of Object.keys(base))
        if (isServerOwnedKey(key) || key === 'principal.sessionTags') delete base[key];
      // A trust may keep the source identity's attributes out of its role sessions (new cross-tenant trusts do).
      // The flag is read fail-closed, as at assumption: only `true` or a legacy trust without it passes them, and a
      // role session whose trust cannot be read passes none.
      if (principal.session.kind !== 'role' || (trust ? trustPassesSourceAttributes(trust) : false))
        for (const [key, value] of Object.entries(principal.identity.attributes ?? {}))
          if (!isServerOwnedKey(`principal.${key}`) && key !== 'sessionTags')
            base[`principal.${key}`] = value;
      // Ownership and root status describe the account in its own tenant. An assumed role carries
      // only the role's grants, so a source account's flags must not satisfy the target's conditions.
      const ownTenant =
        principal.session.kind !== 'role' &&
        principal.identity.tenantId === principal.session.tenantId;
      // Only a session acting in the account's own right (a user session or an API key) is ever the
      // owner or a root admin; a session token (or any future temporary kind) never is.
      const ownAccount = ownTenant && actsInOwnRight(principal.session);
      Object.assign(base, {
        'principal.id': principal.identity.id,
        'principal.tenantId': principal.session.tenantId,
        'principal.mfa': principal.session.mfa,
        'principal.kind': principal.identity.kind,
        'principal.owner': ownAccount && principal.identity.owner,
        'principal.rootAdmin': ownAccount && principal.identity.rootAdmin,
        'principal.sessionKind': principal.session.kind,
        ...(principal.session.method ? { 'principal.authMethod': principal.session.method } : {}),
        'principal.impersonated': Boolean(principal.session.impersonatorId),
        ...(principal.session.impersonatorId
          ? { 'principal.impersonatorId': principal.session.impersonatorId }
          : {}),
        'principal.groups': [...sources.groupIds].sort(),
        'principal.roles': roleIds,
        // Terms of use the person accepted (names) and required ones still owed; nothing for assumed roles.
        // A session token keeps its person's agreements, so it cannot escape a pendingAgreements condition.
        ...(ownTenant
          ? await agreementContext(
              tx,
              target.id,
              principal.identity.id,
              principal.identity.kind,
              ctx.now(),
            )
          : { 'principal.agreements': [], 'principal.pendingAgreements': 0 }),
        'request.time': new Date(ctx.now()).toISOString(),
        ...sessionContextKeys(principal.session, ctx.auth.currentClient()?.ip),
      });
      // AI agents (agents.ts): `principal.delegated` always, and for an agent's own credential or a delegated session
      // the agent's keys plus its ceiling and the delegation's scope. A delegated session whose agent or delegation
      // cannot be read is refused.
      const agentScope = await agentDecisionScope(tx, principal, ctx.now());
      if (!agentScope)
        return { fixed: { allowed: false, reason: 'DELEGATION_REVOKED', matched: [] } };
      Object.assign(base, agentScope.keys);
      const boundaries = chain.flatMap((realm) => (realm.boundary ? [realm.boundary] : []));
      boundaries.push(...agentScope.boundaries);
      // Hand-offs (delegations.ts): the key issuers behind the sessions that handed the work on bound it too.
      for (const authorityId of agentScope.authorities ?? []) {
        const ceilings = await ctx.authorityChain(tx, authorityId);
        if (!ceilings)
          return { fixed: { allowed: false, reason: 'CREDENTIAL_AUTHORITY_REVOKED', matched: [] } };
        boundaries.push(...ceilings);
      }
      const principalBoundary = (
        await tx.find<PrincipalBoundary>('principalBoundaries', {
          tenantId: target.id,
          identityId: principal.identity.id,
        })
      )[0];
      if (principalBoundary) boundaries.push(principalBoundary.document);
      if (principal.session.policy) boundaries.push(principal.session.policy);
      // A session token also stays within its source credential's own policy (such as API-key scopes).
      if (principal.session.sourcePolicy) boundaries.push(principal.session.sourcePolicy);
      if (typeof principal.session.credentialAuthorityId === 'string') {
        const credentialCeilings = await ctx.authorityChain(
          tx,
          principal.session.credentialAuthorityId,
        );
        if (!credentialCeilings)
          return { fixed: { allowed: false, reason: 'CREDENTIAL_AUTHORITY_REVOKED', matched: [] } };
        boundaries.push(...credentialCeilings);
      }
      // A web-identity session is bounded by the authority of whoever registered its OIDC provider as well.
      if (principal.session.webIdentity) {
        const provider = await tx.get<OidcProvider>(
          'oidcProviders',
          principal.session.webIdentity.providerId,
        );
        const providerCeilings =
          provider?.tenantId === principal.session.tenantId &&
          typeof provider.authorityId === 'string'
            ? await ctx.authorityChain(tx, provider.authorityId)
            : undefined;
        if (!providerCeilings)
          return { fixed: { allowed: false, reason: 'CREDENTIAL_AUTHORITY_REVOKED', matched: [] } };
        boundaries.push(...providerCeilings);
      }
      let paths: GrantPath[];
      // Denies outlive the authority that issued them: a revoked or offboarded author (of a binding, a role, or an
      // attached policy) takes away what they granted, never what they forbade. Those denies join as paths that grant
      // nothing.
      const lapsed: GrantPath[] = [];
      if (principal.session.kind === 'role') {
        // The role's own grant boundary is attached by the root-created trust.
        const trustCeiling = trust?.ceiling as PolicyDocument | undefined;
        paths =
          role && trust && !trust.revoked
            ? await service.roleGrants(
                tx,
                role,
                target.id,
                trustCeiling ? [trustCeiling] : [],
                '',
                undefined,
                lapsed,
              )
            : [];
      } else
        paths = await service.identityGrants(tx, principal.identity.id, target.id, sources, lapsed);
      paths.push(...lapsed);
      // Feature flags that are on for the tenant, as `tenant.features`: read only when a condition names the key.
      if (
        mentionsFeatures([
          ...boundaries,
          ...paths.flatMap((path) => [...path.grants, ...path.boundaries]),
        ])
      )
        base[featureContextKey] = enabledFeatureKeys(await featureState(tx, chain, ctx.now()));
      // Onboarding flows the person completed and required ones still open (`principal.onboarding` /
      // `principal.pendingOnboarding`), read only when a condition names them; nothing for assumed roles. A session
      // token keeps its person's onboarding, like their agreements.
      if (
        mentionsOnboarding([
          ...boundaries,
          ...paths.flatMap((path) => [...path.grants, ...path.boundaries]),
        ])
      )
        Object.assign(
          base,
          ownTenant
            ? await onboardingContext(tx, chain, principal.identity, ctx.now())
            : { 'principal.onboarding': [], 'principal.pendingOnboarding': 0 },
        );
      // Teams and departments (teams.ts, departments.ts): `principal.teams`, `principal.departments` and
      // `principal.departmentId`, read only when a document names them; nothing for assumed roles.
      const orgKeys = mentionedOrgKeys([
        ...boundaries,
        ...paths.flatMap((path) => [...path.grants, ...path.boundaries]),
      ]);
      if (orgKeys.teams)
        Object.assign(
          base,
          ownTenant
            ? await teamContext(tx, target.id, principal.identity.id, ctx.now())
            : { 'principal.teams': [] },
        );
      if (orgKeys.departments)
        Object.assign(
          base,
          ownTenant
            ? await departmentContext(tx, target.id, principal.identity.id)
            : { 'principal.departments': [] },
        );
      // Spend (billing-service.ts): `principal.spendExceeded` and `principal.budgetsExceeded`, read only when a
      // document names them; an assumed role sees the tenant's budgets only.
      if (
        mentionsSpend([
          ...boundaries,
          ...paths.flatMap((path) => [...path.grants, ...path.boundaries]),
        ])
      )
        Object.assign(
          base,
          await billingServiceOf(ctx).spendContext(
            tx,
            target,
            ownTenant ? principal.identity.id : undefined,
          ),
        );
      // Privacy (privacy.ts): `principal.consents`, the purposes that may be processed for the person right now, read
      // only when a document names it; nothing for assumed roles. A session token keeps its person's consents.
      if (
        mentionsConsents([
          ...boundaries,
          ...paths.flatMap((path) => [...path.grants, ...path.boundaries]),
        ])
      )
        Object.assign(
          base,
          ownTenant
            ? await consentContext(tx, target.id, principal.identity, ctx.now())
            : { 'principal.consents': [] },
        );
      // Threat detection (threats.ts): `principal.riskLevel` and `principal.riskScore`, read only when a document names
      // them. Risk follows the person (an assumed role keeps it, a delegated session takes the higher of person and
      // agent); simulated principals always get `none`.
      if (
        mentionsRisk([
          ...boundaries,
          ...paths.flatMap((path) => [...path.grants, ...path.boundaries]),
        ])
      )
        Object.assign(base, await riskContext(tx, principal, ctx.now()));
      // Device posture (devices.ts): the request's verified device as `request.deviceAssurance`, `request.deviceManaged`
      // and `request.deviceCompliant` (always), `request.deviceId` and `request.devicePlatform` (when one verified),
      // read only when a document names them. A missing or invalid proof means no device; nothing is written here.
      if (
        mentionsDevice([
          ...boundaries,
          ...paths.flatMap((path) => [...path.grants, ...path.boundaries]),
        ])
      )
        Object.assign(base, await deviceContext(tx, principal, ctx.now()));
      // Deny in any applicable identity policy applies across grant paths.
      const denies = paths.flatMap((path) =>
        path.grants.map((document) => ({
          version: 1 as const,
          statements: document.statements.filter((statement) => statement.effect === 'deny'),
        })),
      );
      // Relationship tuples the principal holds directly or through a group, keyed by `type/id`.
      const held = new Map<string, Set<string>>();
      for (const tuple of await tx.find<Relationship>('relationships', { tenantId: target.id })) {
        const applies =
          principal.session.kind !== 'role' &&
          (tuple.expiresAt === undefined || tuple.expiresAt > ctx.now()) &&
          (tuple.subjectType === 'identity'
            ? tuple.subjectId === principal.identity.id
            : sources.groupIds.has(tuple.subjectId));
        if (!applies) continue;
        const key = `${tuple.type}/${tuple.resourceId}`;
        held.set(key, (held.get(key) ?? new Set()).add(tuple.relation));
      }
      const relationsOf = (type: string | undefined, id: unknown) =>
        typeof type === 'string' && typeof id === 'string'
          ? [...(held.get(type === 'iam' ? id : `${type}/${id}`) ?? [])].sort()
          : [];
      return {
        evaluate(resource, evaluated = action) {
          const attributes = resource.attributes ?? {};
          const context = {
            ...base,
            ...Object.fromEntries(
              Object.entries(attributes).map(([key, value]) => [`resource.${key}`, value]),
            ),
            'resource.tenantId': resource.tenantId,
            // Held on the resource itself; for `iam/{type}/{id}` administration, on the named resource.
            'resource.relations': relationsOf(resource.type, resource.id),
            'resource.parentRelations': relationsOf(
              attributes.parentType as string | undefined,
              attributes.parentId,
            ),
          };
          const evaluation = {
            action: evaluated,
            resource: `${resource.type}/${resource.id}`,
            context,
          };
          const denyDecision = evaluatePolicy({
            ...evaluation,
            grants: [all, ...denies],
            boundaries,
          });
          if (!denyDecision.allowed) return denyDecision;
          for (const path of paths) {
            const decision = evaluatePolicy({
              ...evaluation,
              grants: path.grants,
              boundaries: [...boundaries, ...path.boundaries],
            });
            // A delegation may hold back some actions until the person confirms them (delegations.ts).
            if (decision.allowed)
              return agentScope.confirm?.(evaluated, resource.type, resource.id) ?? decision;
          }
          return { allowed: false, reason: 'NO_APPLICABLE_GRANT', matched: [] };
        },
        // Read-only inputs for query planning (core plan.ts), which mirrors `evaluate` over whole resource types.
        inputs: { context: base, boundaries, paths, denies, held, confirm: agentScope.confirm },
      };
    },
    async decide(tx, principal, request, internalResource = false) {
      const target = await ctx.tenant(tx, request.tenantId);
      const action = text(request.action, 'action');
      // Refusals that do not depend on the resource (a principal of another tenant, an inactive tenant) come first,
      // so an outsider learns nothing about the tenant's actions or resources and its resolver never runs for them.
      const prepared = await service.prepareDecision(tx, principal, target, action);
      if ('fixed' in prepared && !prepared.fixed.allowed) return prepared.fixed;
      if (!(await catalog.knownAction(tx, target.id, action)))
        return { allowed: false, reason: 'UNKNOWN_ACTION', matched: [] };
      const resource = await service.resolve(
        tx,
        { tenantId: target.id, type: request.resource.type, id: request.resource.id },
        internalResource || action.startsWith('iam:'),
        action,
      );
      const evaluated = (ready: PreparedDecision) =>
        'fixed' in ready ? ready.fixed : ready.evaluate(resource);
      const decision = evaluated(prepared);
      // "View as" never exceeds the administrator behind it: every check, including the ones an operation makes
      // on the side (may this role be granted, may this group be changed), must pass for both of them.
      const actor = decision.allowed ? await impersonatingActor(tx, principal) : undefined;
      if (!actor || evaluated(await service.prepareDecision(tx, actor, target, action)).allowed)
        return decision;
      return { allowed: false, reason: 'IMPERSONATOR_DENIED', matched: [] };
    },
    simulatedPrincipal(identity, mfa = false) {
      const at = ctx.now();
      return {
        identity,
        session: {
          id: 'simulation',
          tenantId: identity.tenantId,
          identityId: identity.id,
          tokenHash: '',
          // Machine accounts (service accounts and agents) act through API keys.
          kind: identity.kind === 'user' ? 'user' : 'api-key',
          createdAt: at,
          authenticatedAt: at,
          lastSeenAt: at,
          expiresAt: at + 1,
          mfa,
        },
      };
    },
  };
  return service;
}
