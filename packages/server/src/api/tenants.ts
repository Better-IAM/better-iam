import {
  IamError,
  ipMatches,
  type CredentialInput,
  type IamStore,
  type Json,
  type PolicyDocument,
  type Session,
  type Identity,
  type StoredRecord,
  type Tenant,
  type TenantAccessPolicy,
  type TenantAuthPolicy,
  type TenantLimits,
} from '@better-iam/core';
import { encryptSecret, type TrustedDevice } from '@better-iam/auth';
import { tenantAccessPolicy } from '../access-policy.js';
import { slug, type ServerContext } from '../context.js';
import type { GrantAuthority, OwnerInvitation, TenantAlias } from '../models.js';
import { assertNoTenantLegalHold } from '../privacy.js';
import { tenantAuthPolicy, tenantLimits } from '../tenant-policy.js';
import { all, hash, id, token } from '../utils.js';
import { email, text } from '../validation.js';

export { tenantAuthPolicy, tenantLimits } from '../tenant-policy.js';

/** What a sign-in screen learns about an organization from `tenants.lookup`: who it is and where it signs in. */
export interface TenantDiscovery {
  tenantId: string;
  name: string;
  type: string;
  /** The organization's alias; empty only for an organization without one, found by its custom hostname. */
  slug: string;
  /** Its home region, in a multi-region deployment. */
  region?: string;
  /** Its canonical sign-in URL, when organization addresses or regions are configured. */
  signInUrl?: string;
}

/** Per key, the stricter of two sets of plan limits (a key either one sets applies); undefined when neither sets any. */
function stricterLimits(a: TenantLimits = {}, b: TenantLimits = {}): TenantLimits | undefined {
  const merged: TenantLimits = { ...a };
  for (const [key, value] of Object.entries(b) as [keyof TenantLimits, number | undefined][])
    if (value !== undefined && (merged[key] === undefined || value < merged[key]!))
      merged[key] = value;
  return Object.keys(merged).length ? merged : undefined;
}

export function createTenantsApi(ctx: ServerContext) {
  const { store, auth, options, config, catalog } = ctx;
  const { operation } = ctx.operations;
  const { hierarchy, maxDepth } = config;
  const discovery = async (tx: IamStore, realm: Tenant): Promise<TenantDiscovery> => {
    const region = await ctx.hosts.regionOf(tx, realm);
    const signInUrl = await ctx.hosts.signInUrl(realm, tx);
    return {
      tenantId: realm.id,
      name: realm.name,
      type: realm.type,
      slug: realm.slug ?? '',
      ...(region ? { region } : {}),
      ...(signInUrl ? { signInUrl } : {}),
    };
  };
  return {
    /** Creates a pending child tenant and sends its owner an invitation; the creator's grant authority becomes the parent of the owner's. */
    create: (
      credential: CredentialInput,
      input: {
        parentId: string;
        type: string;
        name: string;
        ownerEmail: string;
        slug?: string;
        boundary?: PolicyDocument;
        authorityId?: string;
        /** Home region in a multi-region deployment; defaults to the parent's region (or this deployment's). */
        region?: string;
      },
    ) =>
      operation(
        credential,
        input.parentId,
        'iam:tenants:create',
        input.parentId,
        async ({ tx, principal, tenant: parent }) => {
          auth.requireRecent(principal);
          const type = text(input.type, 'type');
          const name = text(input.name, 'name');
          const ownerEmail = email(input.ownerEmail);
          if (!options.authentication?.sendEmail)
            throw new IamError(
              'DELIVERY_REQUIRED',
              'Organization invitations require an email delivery callback',
            );
          if (!hierarchy.types[parent.type]?.allowedChildren.includes(type))
            throw new IamError('INVALID_HIERARCHY', 'Child type is not permitted');
          if ((await ctx.ancestry(tx, parent)).length >= maxDepth)
            throw new IamError('MAX_DEPTH', 'Maximum tenant depth reached');
          const parentAuthority = await ctx.grantingAuthority(
            tx,
            principal,
            parent.id,
            input.authorityId,
          );
          const realm: Tenant = {
            id: id(),
            tenantId: '',
            name,
            type,
            parentId: parent.id,
            status: 'pending',
            boundary: input.boundary,
            createdAt: Date.now(),
          };
          realm.tenantId = realm.id;
          // Plan defaults for every new tenant, never looser than its parent's own plan (the stricter value wins per
          // key), so an organization cannot escape its limits through child projects. The root tenant's limits are
          // the platform's own and are not passed on. Root can change them per tenant later.
          const limits = stricterLimits(
            config.tenantDefaults.limits,
            parent.parentId !== null ? parent.limits : undefined,
          );
          if (limits) realm.limits = limits;
          if (config.tenantDefaults.authPolicy)
            realm.authPolicy = { ...config.tenantDefaults.authPolicy };
          if (input.boundary) await catalog.validate(tx, realm.id, input.boundary);
          if (input.slug !== undefined) realm.slug = await ctx.claimSlug(tx, realm.id, input.slug);
          const region = await ctx.hosts.regionForNew(tx, parent, input.region);
          if (region) realm.region = region;
          await tx.insert('tenants', realm);
          const authority = await tx.insert<GrantAuthority>('grantAuthorities', {
            id: id(),
            tenantId: realm.id,
            identityId: 'pending',
            parentAuthorityId: parentAuthority.id,
            ceiling: all,
            revoked: false,
          });
          const inviteToken = token();
          const invitation = await tx.insert<OwnerInvitation>('ownerInvitations', {
            id: id(),
            tenantId: realm.id,
            email: ownerEmail,
            tokenHash: hash(inviteToken),
            uniqueKey: hash(inviteToken),
            authorityId: authority.id,
            createdAt: Date.now(),
            expiresAt: Date.now() + config.invitationLifetimeMs,
            consumed: false,
            creatorId: principal.identity.id,
          });
          const outboxId = id();
          await tx.insert('outbox', {
            id: outboxId,
            tenantId: realm.id,
            kind: 'email',
            to: ownerEmail,
            template: 'owner-invitation',
            payload: {
              sealed: encryptSecret(
                JSON.stringify({ token: inviteToken, tenantId: realm.id, tenantName: realm.name }),
                options.secret,
                `outbox:${outboxId}`,
              ),
            },
            createdAt: Date.now(),
            attempts: 0,
          });
          return { tenant: realm, invitationId: invitation.id, ownerEmail };
        },
      ),
    acceptInvitation: (input: {
      tenantId: string;
      token: string;
      name: string;
      password: string;
      linkCredential?: CredentialInput;
    }) => ctx.flows.acceptOwnerInvitation(input),
    /**
     * Public sign-in discovery: resolves an active tenant by its alias, or by an address it signs in at (`host`,
     * such as `acme.signin.example.com` or a verified custom hostname), so login screens need no tenant ID. In a
     * multi-region deployment an organization homed elsewhere answers `WRONG_REGION` with its sign-in URL there.
     */
    lookup: async (input: { slug?: string; host?: string }) => {
      if (input.host !== undefined) {
        const host = text(input.host, 'host', 260);
        return store.transaction(async (tx) => {
          const match = await ctx.hosts.resolve(host, tx);
          if (!match) throw new IamError('NOT_FOUND', 'Organization not found', 404);
          const realm = await ctx.tenant(tx, match.tenantId);
          await ctx.hosts.assertServedHere(tx, realm, match.hostRegion);
          return discovery(tx, realm);
        });
      }
      const alias = slug(input.slug);
      const found = await store.transaction(async (tx) => {
        const record = await tx.get<TenantAlias>('tenantAliases', alias);
        const realm = record ? await tx.get<Tenant>('tenants', record.tenantId) : undefined;
        if (
          !realm ||
          realm.status !== 'active' ||
          (await ctx.ancestry(tx, realm)).some((item) => item.status !== 'active')
        )
          return record ? 'inactive' : undefined;
        await ctx.hosts.assertServedHere(tx, realm);
        return discovery(tx, realm);
      });
      if (typeof found === 'object') return found;
      // An alias this region's database does not know may live in another region (`regions.locate`).
      const elsewhere = found === undefined ? await ctx.hosts.remoteAlias(alias) : undefined;
      if (elsewhere) throw elsewhere;
      throw new IamError('NOT_FOUND', 'Organization not found', 404);
    },
    /**
     * Moves a tenant's home region (root administrators only, recently authenticated). Its sign-in is served by the
     * new region's deployment from then on; descendants without a region of their own follow it. `null` makes it
     * inherit its parent's region again. Moving data between separate regional databases is not part of this call.
     */
    setRegion: (credential: CredentialInput, input: { tenantId: string; region: string | null }) =>
      operation(
        credential,
        input.tenantId,
        'iam:tenants:update',
        input.tenantId,
        async ({ tx, principal, tenant: target }) => {
          auth.requireRecent(principal);
          if (target.status === 'deleted')
            throw new IamError('INVALID_TRANSITION', 'Deleted tenants cannot be updated');
          const from = await ctx.hosts.regionOf(tx, target);
          const { region: _previous, ...rest } = target;
          const next: Tenant = { ...rest };
          if (input.region !== null) next.region = ctx.hosts.region(input.region);
          else if (target.parentId === null)
            throw new IamError(
              'INVALID_INPUT',
              'The root tenant has no parent to inherit a region from',
            );
          const result = await tx.put('tenants', next);
          await ctx.events.audit(
            tx,
            principal,
            'tenant:region',
            target.id,
            target.id,
            'allow',
            false,
            { from: from ?? null, to: (await ctx.hosts.regionOf(tx, next)) ?? null },
          );
          return result;
        },
        true,
      ),
    setSlug: (credential: CredentialInput, input: { tenantId: string; slug: string | null }) =>
      operation(
        credential,
        input.tenantId,
        'iam:tenants:update',
        input.tenantId,
        async ({ tx, principal, tenant: target }) => {
          auth.requireRecent(principal);
          if (target.status === 'deleted')
            throw new IamError('INVALID_TRANSITION', 'Deleted tenants cannot be updated');
          if (target.slug !== undefined) await tx.delete('tenantAliases', target.slug);
          const { slug: _previous, ...updated } = target;
          const next: Tenant = { ...updated };
          if (input.slug !== null) next.slug = await ctx.claimSlug(tx, target.id, input.slug);
          return tx.put('tenants', next);
        },
      ),
    get: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:tenants:read',
        input.tenantId,
        async ({ tenant }) => tenant,
      ),
    listChildren: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, input.tenantId, 'iam:tenants:read', input.tenantId, async ({ tx }) =>
        tx.find<Tenant>('tenants', { parentId: input.tenantId }),
      ),
    /**
     * Sets or clears (null) the tenant's authentication policy: required MFA, allowed sign-in methods, and session
     * lifetimes. Policies only tighten the deployment's configuration. Existing sessions are re-validated against the
     * new policy on their next use, so requiring MFA immediately locks out sessions that did not complete it.
     * `allowedIpRanges` for the caller's own organization must include the caller's address (recorded and current).
     * The root tenant's policy decides whether root administrators can sign in at all, so only root changes it.
     */
    setAuthPolicy: (
      credential: CredentialInput,
      input: { tenantId: string; authPolicy: TenantAuthPolicy | null },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:tenants:update',
        input.tenantId,
        async ({ tx, tenant: target, principal }) => {
          auth.requireRecent(principal);
          if (target.status === 'deleted')
            throw new IamError('INVALID_TRANSITION', 'Deleted tenants cannot be updated');
          // A platform staff member's allowlist or method restriction on the root tenant would lock every root
          // administrator out, and bootstrap recovery signs in there too.
          if (target.parentId === null && !(await ctx.rootPrincipal(tx, principal)))
            throw new IamError(
              'ACCESS_DENIED',
              'The root tenant’s authentication policy is set by root administrators',
              403,
            );
          const { authPolicy: _previous, ...rest } = target;
          const next: Tenant = { ...rest };
          if (input.authPolicy !== null) next.authPolicy = tenantAuthPolicy(input.authPolicy);
          // Like blockNetwork's self-lockout guard: an allowlist that leaves out the address the caller's session was
          // issued from (it would end at once) or the one this request comes from (no way back in, and for the root
          // tenant no parent to undo it) is refused. Only the caller's own organization's allowlist judges them.
          const ranges = next.authPolicy?.allowedIpRanges;
          if (ranges?.length && principal.session.tenantId === target.id)
            for (const ip of [principal.session.client?.ip, auth.currentClient()?.ip])
              if (ip !== undefined && !ranges.some((range) => ipMatches(ip, range)))
                throw new IamError(
                  'INVALID_INPUT',
                  'allowedIpRanges must include your own address',
                );
          const result = await tx.put('tenants', next);
          await ctx.events.audit(
            tx,
            principal,
            'tenant:auth-policy',
            target.id,
            target.id,
            'allow',
            false,
            { authPolicy: (next.authPolicy ?? null) as Json },
          );
          return result;
        },
      ),
    /**
     * Organization-wide floors for just-in-time activation (`maxActivationMs`, `requireJustification`, `requireMfa`,
     * `requireApproval`, `approvalLifetimeMs`): every eligible binding is at least this strict. Replaces the whole
     * policy; `null` clears it. Requires recent authentication and iam:tenants:update; audited as `tenant:access-policy`.
     */
    setAccessPolicy: (
      credential: CredentialInput,
      input: { tenantId: string; accessPolicy: TenantAccessPolicy | null },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:tenants:update',
        input.tenantId,
        async ({ tx, tenant: target, principal }) => {
          auth.requireRecent(principal);
          if (target.status === 'deleted')
            throw new IamError('INVALID_TRANSITION', 'Deleted tenants cannot be updated');
          const { accessPolicy: _previous, ...rest } = target;
          const next: Tenant = { ...rest };
          if (input.accessPolicy !== null) {
            const policy = tenantAccessPolicy(input.accessPolicy);
            if (Object.keys(policy).length) next.accessPolicy = policy;
          }
          const result = await tx.put('tenants', next);
          await ctx.events.audit(
            tx,
            principal,
            'tenant:access-policy',
            target.id,
            target.id,
            'allow',
            false,
            { accessPolicy: (next.accessPolicy ?? null) as Json },
          );
          return result;
        },
      ),
    /**
     * Platform-controlled plan limits (root only): creation past a limit fails with LIMIT_EXCEEDED. `null` clears them.
     * Descendants of an organization are tightened to the new limits per key (they are never looser than their
     * parent, see `create`); loosening or clearing leaves them as they are.
     */
    setLimits: (
      credential: CredentialInput,
      input: { tenantId: string; limits: TenantLimits | null },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:tenants:update',
        input.tenantId,
        async ({ tx, tenant: target, principal }) => {
          if (target.status === 'deleted')
            throw new IamError('INVALID_TRANSITION', 'Deleted tenants cannot be updated');
          const { limits: _previous, ...rest } = target;
          const next: Tenant = { ...rest };
          if (input.limits !== null) next.limits = tenantLimits(input.limits);
          const result = await tx.put('tenants', next);
          if (next.limits && target.parentId !== null) {
            const realms = await tx.find<Tenant>('tenants');
            const below = new Set([target.id]);
            for (let depth = 0; depth < maxDepth; depth++)
              for (const realm of realms)
                if (realm.parentId && below.has(realm.parentId)) below.add(realm.id);
            for (const realm of realms) {
              if (realm.id === target.id || !below.has(realm.id)) continue;
              const limits = stricterLimits(realm.limits, next.limits);
              if (limits && JSON.stringify(limits) !== JSON.stringify(realm.limits ?? {}))
                await tx.put('tenants', { ...realm, limits });
            }
          }
          await ctx.events.audit(
            tx,
            principal,
            'tenant:limits',
            target.id,
            target.id,
            'allow',
            false,
            { limits: (next.limits ?? null) as Json },
          );
          return result;
        },
        true,
      ),
    /** Current record counts against the tenant's plan limits, for dashboards and metering. */
    usage: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:tenants:read',
        input.tenantId,
        async ({ tx, tenant: target }) => {
          const identities = await tx.find<Identity>('identities', { tenantId: target.id });
          const count = async (collection: string) =>
            (await tx.find(collection, { tenantId: target.id })).length;
          const sessions = await tx.find<Session>('sessions', {
            tenantId: target.id,
            kind: 'user',
          });
          const people = identities.filter(
            (identity) => identity.kind === 'user' && identity.status !== 'deleted',
          );
          // MFA adoption: people with an enabled authenticator or at least one passkey.
          const withFactor = new Set<string>();
          for (const record of await tx.find<
            StoredRecord & { identityId: string; enabled?: boolean }
          >('authMfa', { tenantId: target.id }))
            if (record.enabled) withFactor.add(record.identityId);
          for (const key of await tx.find<StoredRecord & { identityId: string }>('authPasskeys', {
            tenantId: target.id,
          }))
            withFactor.add(key.identityId);
          return {
            tenantId: target.id,
            identities: people.length,
            mfaEnrolled: people.filter((identity) => withFactor.has(identity.id)).length,
            serviceAccounts: identities.filter(
              (identity) => identity.kind === 'service' && identity.status !== 'deleted',
            ).length,
            groups: await count('groups'),
            roles: await count('roles'),
            policies: await count('policies'),
            resources: await count('resources'),
            relationships: await count('relationships'),
            webhooks: await count('webhooks'),
            activeSessions: sessions.filter((session) => session.expiresAt > ctx.now()).length,
            limits: target.limits ?? {},
          };
        },
      ),
    /**
     * Incident response: ends every user session in the tenant (the caller's own session is kept unless `includeSelf`).
     * Requires recent authentication and iam:tenants:update; role sessions sourced from this tenant and impersonation
     * sessions opened through an ended session end as well, and the tenant's remembered devices are forgotten (the
     * caller's own are kept unless `includeSelf`), so the next sign-in needs the second factor again. On the root
     * tenant, whose sessions include every root administrator's, only root may.
     */
    revokeSessions: (
      credential: CredentialInput,
      input: { tenantId: string; includeSelf?: boolean },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:tenants:update',
        input.tenantId,
        async ({ tx, principal, tenant: target }) => {
          auth.requireRecent(principal);
          if (target.parentId === null && !(await ctx.rootPrincipal(tx, principal)))
            throw new IamError(
              'ACCESS_DENIED',
              'Only root administrators can sign everyone out of the root tenant',
              403,
            );
          let revoked = 0;
          for (const session of await tx.find<Session>('sessions'))
            if (
              (session.tenantId === target.id || session.sourceTenantId === target.id) &&
              (input.includeSelf === true || session.id !== principal.session.id)
            ) {
              // endSession also removes the impersonation sessions an administrator opened through this one.
              await auth.endSession(tx, session.id);
              revoked++;
            }
          // Remembered devices are forgotten too, or a stolen password plus device cookie would still skip MFA after
          // "sign everyone out". The caller keeps theirs when they keep their own session.
          for (const device of await tx.find<TrustedDevice>('authDevices', { tenantId: target.id }))
            if (input.includeSelf === true || device.identityId !== principal.identity.id)
              await tx.delete('authDevices', device.id);
          await ctx.events.audit(
            tx,
            principal,
            'tenant:revoke-sessions',
            target.id,
            target.id,
            'allow',
            false,
            { revoked, includeSelf: input.includeSelf === true },
          );
          return { revoked };
        },
      ),
    update: (credential: CredentialInput, input: { tenantId: string; name: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:tenants:update',
        input.tenantId,
        async ({ tx, tenant: target, principal }) => {
          auth.requireRecent(principal);
          if (target.status === 'deleted')
            throw new IamError('INVALID_TRANSITION', 'Deleted tenants cannot be updated');
          return tx.put('tenants', { ...target, name: text(input.name, 'name') });
        },
      ),
    /** Moves a tenant under a new parent with hierarchy, depth, cycle, and destination-authority checks. */
    reparent: (
      credential: CredentialInput,
      input: { tenantId: string; parentId: string; authorityId?: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:tenants:update',
        input.tenantId,
        async ({ tx, principal, tenant: target }) => {
          auth.requireRecent(principal);
          const parent = await ctx.tenant(tx, text(input.parentId, 'parentId'));
          if (
            target.parentId === null ||
            target.status === 'pending' ||
            target.status === 'deleted'
          )
            throw new IamError('INVALID_TRANSITION', 'Tenant cannot be moved');
          if (parent.id === target.parentId)
            throw new IamError('INVALID_INPUT', 'Tenant is already under this parent');
          if (
            parent.status !== 'active' ||
            (await ctx.ancestry(tx, parent)).some((item) => item.status !== 'active')
          )
            throw new IamError('TENANT_INACTIVE', 'New parent ancestry must be active');
          if (!hierarchy.types[parent.type]?.allowedChildren.includes(target.type))
            throw new IamError(
              'INVALID_HIERARCHY',
              'Child type is not permitted under the new parent',
            );
          const realms = await tx.find<Tenant>('tenants');
          const subtree = new Set([target.id]);
          let frontier = [target.id];
          let height = 1;
          for (let depth = 0; depth < maxDepth && frontier.length; depth++) {
            const next = realms
              .filter((realm) => realm.parentId && frontier.includes(realm.parentId))
              .map((realm) => realm.id);
            if (next.length) {
              height++;
              for (const child of next) subtree.add(child);
            }
            frontier = next;
          }
          if (subtree.has(parent.id))
            throw new IamError('INVALID_HIERARCHY', 'Cannot move a tenant under its own subtree');
          if ((await ctx.ancestry(tx, parent)).length + height > maxDepth)
            throw new IamError('MAX_DEPTH', 'Maximum tenant depth reached');
          await ctx.grantingAuthority(tx, principal, parent.id, input.authorityId);
          const result = await tx.put('tenants', { ...target, parentId: parent.id });
          await ctx.events.audit(
            tx,
            principal,
            'tenant:reparent',
            target.id,
            target.id,
            'allow',
            false,
            { from: target.parentId, to: parent.id },
          );
          return result;
        },
      ),
    /** Suspension and deletion cascade to descendants and revoke their sessions; deletion starts the retention window. */
    setStatus: (
      credential: CredentialInput,
      input: { tenantId: string; status: 'active' | 'suspended' | 'deleted' },
    ) =>
      operation(
        credential,
        input.tenantId,
        input.status === 'deleted' ? 'iam:tenants:delete' : 'iam:tenants:update',
        input.tenantId,
        async ({ tx, tenant: target, principal }) => {
          auth.requireRecent(principal);
          if (
            !['active', 'suspended', 'deleted'].includes(input.status) ||
            target.parentId === null ||
            target.status === 'deleted' ||
            (target.status === 'pending' && input.status !== 'deleted')
          )
            throw new IamError('INVALID_TRANSITION', 'Tenant cannot make this transition');
          if (
            input.status === 'active' &&
            target.parentId &&
            (await ctx.ancestry(tx, await ctx.tenant(tx, target.parentId))).some(
              (item) => item.status !== 'active',
            )
          )
            throw new IamError('TENANT_INACTIVE', 'Parent must be active');
          // Legal holds (privacy.ts) keep people's data: an organization with an active hold cannot be deleted.
          if (input.status === 'deleted')
            await assertNoTenantLegalHold(tx, target.id, ctx.now(), ctx.config.maxDepth);
          const now = Date.now();
          const result = await tx.put('tenants', {
            ...target,
            status: input.status,
            ...(input.status === 'deleted' ? { deletedAt: target.deletedAt ?? now } : {}),
          });
          if (input.status !== 'active') {
            const realms = await tx.find<Tenant>('tenants');
            const affected = new Set([target.id]);
            for (let depth = 0; depth < maxDepth; depth++)
              for (const realm of realms)
                if (realm.parentId && affected.has(realm.parentId)) affected.add(realm.id);
            for (const session of await tx.find<Session>('sessions'))
              if (
                affected.has(session.tenantId) ||
                (session.sourceTenantId && affected.has(session.sourceTenantId))
              )
                await tx.delete('sessions', session.id);
            if (input.status === 'deleted')
              for (const realm of realms)
                if (affected.has(realm.id) && realm.id !== target.id)
                  await tx.put('tenants', {
                    ...realm,
                    status: 'deleted',
                    deletedAt: realm.deletedAt ?? now,
                  });
          }
          return result;
        },
      ),
    listInvitations: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, input.tenantId, 'iam:tenants:read', input.tenantId, async ({ tx }) =>
        (await tx.find<OwnerInvitation>('ownerInvitations', { tenantId: input.tenantId })).map(
          ({ tokenHash: _hash, uniqueKey: _key, ...safe }) => safe,
        ),
      ),
    revokeInvitation: (
      credential: CredentialInput,
      input: { tenantId: string; invitationId: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:tenants:update',
        input.invitationId,
        async ({ tx, principal }) => {
          auth.requireRecent(principal);
          const invitation = await ctx.scoped<OwnerInvitation>(
            tx,
            'ownerInvitations',
            input.invitationId,
            input.tenantId,
          );
          if (invitation.consumed || invitation.revoked)
            throw new IamError('CONFLICT', 'Invitation is already consumed or revoked', 409);
          const {
            tokenHash: _hash,
            uniqueKey: _key,
            ...safe
          } = await tx.put('ownerInvitations', { ...invitation, revoked: true });
          return safe;
        },
      ),
    /** Re-sends an owner invitation with a fresh token and lifetime; the earlier token stops working. */
    resendInvitation: (
      credential: CredentialInput,
      input: { tenantId: string; invitationId: string },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:tenants:update',
        input.invitationId,
        async ({ tx, principal, tenant: realm }) => {
          auth.requireRecent(principal);
          if (!options.authentication?.sendEmail)
            throw new IamError(
              'DELIVERY_REQUIRED',
              'Organization invitations require an email delivery callback',
            );
          const invitation = await ctx.scoped<OwnerInvitation>(
            tx,
            'ownerInvitations',
            input.invitationId,
            input.tenantId,
          );
          if (invitation.consumed || invitation.revoked)
            throw new IamError('CONFLICT', 'Invitation is already consumed or revoked', 409);
          const inviteToken = token();
          const now = Date.now();
          const renewed = await tx.put('ownerInvitations', {
            ...invitation,
            tokenHash: hash(inviteToken),
            uniqueKey: hash(inviteToken),
            createdAt: now,
            expiresAt: now + config.invitationLifetimeMs,
          });
          const outboxId = id();
          await tx.insert('outbox', {
            id: outboxId,
            tenantId: realm.id,
            kind: 'email',
            to: invitation.email,
            template: 'owner-invitation',
            payload: {
              sealed: encryptSecret(
                JSON.stringify({ token: inviteToken, tenantId: realm.id, tenantName: realm.name }),
                options.secret,
                `outbox:${outboxId}`,
              ),
            },
            createdAt: now,
            attempts: 0,
          });
          return { invitationId: renewed.id, email: renewed.email, expiresAt: renewed.expiresAt };
        },
      ),
    setBoundary: (
      credential: CredentialInput,
      input: { tenantId: string; boundary: PolicyDocument },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:boundaries:update',
        input.tenantId,
        async ({ tx, principal, tenant: target }) => {
          auth.requireRecent(principal);
          await catalog.validate(tx, target.id, input.boundary);
          if (!(await ctx.rootPrincipal(tx, principal)))
            throw new IamError('ACCESS_DENIED', 'Tenant ceilings are platform controlled', 403);
          return tx.put('tenants', { ...target, boundary: input.boundary });
        },
      ),
  };
}
