import { timingSafeEqual } from 'node:crypto';
import { IamError, type CredentialInput, type Session } from '@better-iam/core';
import type { SessionResult, SignInResult } from '@better-iam/auth';
import { clientFromHeaders } from './client-info.js';
import type { ServerContext } from './context.js';
import type {
  Binding,
  GrantAuthority,
  GroupMember,
  IdentityLink,
  MemberInvitation,
  OwnerInvitation,
  Role,
  SourceIdentityMode,
  Trust,
} from './models.js';
import { sodAssertIdentity } from './sod.js';
import {
  audienceValue,
  credentialFormat,
  durationWithin,
  mintCredential,
  roleDurationBounds,
  sessionNameValue,
  sessionTagsValue,
  sourceIdentityValue,
  temporaryCredential,
  type AssumeRoleInput,
  type RoleCredential,
} from './temporary-credentials.js';
import { hash, id, publicIdentity, type PublicIdentity } from './utils.js';
import { text } from './validation.js';

/**
 * Whether a presented external ID matches a trust's stored hash: SHA-256 hex digests compared in constant time (with
 * a length check first). A trust without an external ID matches anything.
 */
function externalIdMatches(expectedHash: string | undefined, provided: unknown): boolean {
  if (!expectedHash) return true;
  if (typeof provided !== 'string') return false;
  const expected = Buffer.from(expectedHash, 'utf8');
  const actual = Buffer.from(hash(provided), 'utf8');
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}

/**
 * The session tag keys a stored trust admits, read fail-closed: a list of strings, where the `*` wildcard counts only
 * as exactly ['*']. Anything malformed (not an array, or holding a non-string) admits no tags; legacy trusts without
 * the field admit none either.
 */
export function trustAllowedTagKeys(trust: Pick<Trust, 'allowedTagKeys'>): {
  any: boolean;
  keys: readonly string[];
} {
  const value: unknown = trust.allowedTagKeys;
  if (!Array.isArray(value) || !value.every((key) => typeof key === 'string'))
    return { any: false, keys: [] };
  if (value.length === 1 && value[0] === '*') return { any: true, keys: [] };
  return { any: false, keys: value as string[] };
}

/** A stored trust's source-identity mode, read fail-closed: any value but the three literals means 'forbidden'. */
export function trustSourceIdentityMode(
  trust: Pick<Trust, 'sourceIdentityMode'>,
): SourceIdentityMode {
  const value: unknown = trust.sourceIdentityMode;
  return value === 'optional' || value === 'required' ? value : 'forbidden';
}

/**
 * Whether a stored trust passes the source identity's attributes into its role sessions, read as a boolean: legacy
 * trusts without the field pass them, and a malformed (non-boolean) value fails closed and passes nothing.
 */
export function trustPassesSourceAttributes(trust: Pick<Trust, 'passSourceAttributes'>): boolean {
  const value: unknown = trust.passSourceAttributes;
  return typeof value === 'boolean' ? value : value === undefined;
}

/**
 * Whether a stored trust requires MFA of the source session, read fail-closed: only the boolean `false` waives it.
 * A missing field means what `trust.create` defaults to (required), and any malformed value requires it too.
 */
export function trustRequiresMfa(trust: Pick<Trust, 'requireMfa'>): boolean {
  const value: unknown = trust.requireMfa;
  return value !== false;
}

/** The outcome of redeeming an invitation: the new identity plus either a session or an MFA challenge. */
export type EnrollmentResult = { identity: PublicIdentity } & SignInResult;

/** Multi-step flows that create sessions or cross tenant boundaries and therefore do not fit the single-tenant `operation` envelope. */
export interface FlowService {
  /** Public: redeems an owner invitation, activates the pending tenant, and signs the owner in. */
  acceptOwnerInvitation(input: {
    tenantId: string;
    token: string;
    name: string;
    password: string;
    linkCredential?: CredentialInput;
  }): Promise<EnrollmentResult>;
  /** Public: redeems a member invitation, applies its bindings under the inviter's authority, and signs the member in. */
  acceptMemberInvitation(input: {
    tenantId: string;
    token: string;
    name?: string;
    password: string;
  }): Promise<EnrollmentResult>;
  linkIdentities(
    leftCredential: CredentialInput,
    rightCredential: CredentialInput,
  ): Promise<IdentityLink>;
  switchIdentity(
    credential: CredentialInput,
    input: { linkId: string; targetCredential: CredentialInput },
  ): Promise<SessionResult>;
  /**
   * AssumeRole: exchanges a user session (not impersonated), API key or session token for a role session of the
   * trust's tenant, with an optional session name, source identity, tags, scope-down policy and JWT format. Role
   * sessions cannot assume roles (ROLE_CHAINING_DISABLED). Audited as `iam:roles:assume` in the source tenant and
   * `role:assumed` in the target tenant. The issuing client is recorded on the session; a `{ headers }` credential
   * with no client scope set gets the client derived from those headers, as `sts.getSessionToken` does.
   */
  assumeRole(credential: CredentialInput, input: AssumeRoleInput): Promise<RoleCredential>;
}

export function createFlows(ctx: ServerContext): FlowService {
  const { store, auth, config, catalog } = ctx;
  const byIdentityId = (a: { id: string }, b: { id: string }) =>
    a.id < b.id ? -1 : a.id > b.id ? 1 : 0;
  return {
    async acceptOwnerInvitation(input) {
      const linkPrincipal = input.linkCredential
        ? await ctx.principals.authenticate(input.linkCredential)
        : undefined;
      if (linkPrincipal) {
        if (!config.linkedOnboarding)
          throw new IamError('LINKING_DISABLED', 'Linked onboarding is disabled');
        auth.requireRecent(linkPrincipal);
        if (linkPrincipal.identity.rootAdmin)
          throw new IamError('PROTECTED_IDENTITY', 'Root identities cannot link');
        if (linkPrincipal.session.kind !== 'user' || linkPrincipal.identity.kind !== 'user')
          throw new IamError('INVALID_LINK', 'Linked onboarding requires an ordinary user session');
      }
      return store.transaction(async (tx) => {
        const realm = await ctx.tenant(tx, input.tenantId);
        if (realm.status !== 'pending')
          throw new IamError('INVITATION_INVALID', 'Invitation is invalid');
        const invitation = (
          await tx.find<OwnerInvitation>('ownerInvitations', {
            tenantId: realm.id,
            tokenHash: hash(text(input.token, 'token')),
          })
        )[0];
        if (
          !invitation ||
          invitation.consumed ||
          invitation.revoked ||
          invitation.expiresAt <= Date.now()
        )
          throw new IamError('INVITATION_INVALID', 'Invitation is invalid');
        if (
          realm.parentId &&
          (await ctx.ancestry(tx, await ctx.tenant(tx, realm.parentId))).some(
            (item) => item.status !== 'active',
          )
        )
          throw new IamError('TENANT_INACTIVE', 'Parent inactive');
        const authority = await ctx.scoped<GrantAuthority>(
          tx,
          'grantAuthorities',
          invitation.authorityId,
          realm.id,
        );
        if (!(await ctx.authorityChain(tx, authority.id)))
          throw new IamError('INVITATION_INVALID', 'Invitation authority revoked');
        const identity = await auth.createIdentity(tx, {
          tenantId: realm.id,
          email: invitation.email,
          name: text(input.name, 'name'),
          password: input.password,
          owner: true,
          emailVerified: true,
        });
        await ctx.ownerSetup(tx, realm, identity, authority);
        await tx.put('tenants', { ...realm, status: 'active' });
        await tx.put('ownerInvitations', { ...invitation, consumed: true });
        const issued = await auth.completeAuthentication(tx, identity);
        if (linkPrincipal) {
          const current = await ctx.principals.currentPrincipal(tx, linkPrincipal);
          if (
            invitation.creatorId !== current.identity.id ||
            current.identity.rootAdmin ||
            current.session.kind !== 'user'
          )
            throw new IamError(
              'ACCESS_DENIED',
              'Only this ordinary user organization creator may link during enrollment',
              403,
            );
          const pair = [current.identity, identity].sort(byIdentityId);
          await tx.insert<IdentityLink>('identityLinks', {
            id: id(),
            tenantId: pair[0]!.tenantId,
            uniqueKey: pair.map((item) => item.id).join(':'),
            leftId: pair[0]!.id,
            rightId: pair[1]!.id,
            revoked: false,
          });
        }
        await ctx.events.recordAudit(tx, {
          id: id(),
          tenantId: realm.id,
          actorId: identity.id,
          action: 'tenant:activate',
          resourceId: realm.id,
          timestamp: Date.now(),
          outcome: 'allow',
        });
        return { identity: publicIdentity(identity), ...issued };
      });
    },
    async acceptMemberInvitation(input) {
      return store.transaction(async (tx) => {
        const realm = await ctx.tenant(tx, input.tenantId);
        await auth.assertTenantActive(tx, realm.id);
        const invitation = (
          await tx.find<MemberInvitation>('memberInvitations', {
            tenantId: realm.id,
            tokenHash: hash(text(input.token, 'token')),
          })
        )[0];
        if (
          !invitation ||
          invitation.consumed ||
          invitation.revoked ||
          invitation.expiresAt <= Date.now()
        )
          throw new IamError('INVITATION_INVALID', 'Invitation is invalid');
        if (
          invitation.authorityId !== undefined &&
          !(await ctx.authorityChain(tx, invitation.authorityId))
        )
          throw new IamError('INVITATION_INVALID', 'Invitation authority revoked');
        const name = input.name !== undefined ? text(input.name, 'name') : invitation.name;
        if (!name) throw new IamError('INVALID_INPUT', 'A name is required');
        const identity = await auth.createIdentity(tx, {
          tenantId: realm.id,
          email: invitation.email,
          name,
          password: input.password,
          emailVerified: true,
        });
        for (const roleId of invitation.roleIds) {
          const role = await ctx.scoped<Role>(tx, 'roles', roleId, realm.id);
          if (role.protected)
            throw new IamError('PROTECTED_RESOURCE', 'Invitation grants a protected role', 403);
          await tx.insert<Binding>('bindings', {
            id: id(),
            tenantId: realm.id,
            uniqueKey: `identity:${identity.id}:${role.id}:${invitation.authorityId}`,
            subjectType: 'identity',
            subjectId: identity.id,
            roleId: role.id,
            authorityId: invitation.authorityId!,
          });
        }
        for (const groupId of invitation.groupIds) {
          await ctx.scoped(tx, 'groups', groupId, realm.id);
          await tx.insert<GroupMember>('groupMembers', {
            id: id(),
            tenantId: realm.id,
            uniqueKey: `${groupId}:${identity.id}`,
            groupId,
            identityId: identity.id,
          });
        }
        await sodAssertIdentity(ctx, tx, realm.id, identity.id);
        await tx.put('memberInvitations', { ...invitation, consumed: true });
        await ctx.events.recordAudit(tx, {
          id: id(),
          tenantId: realm.id,
          actorId: identity.id,
          action: 'identity:invitation:accept',
          resourceId: invitation.id,
          timestamp: Date.now(),
          outcome: 'allow',
          metadata: {
            inviterId: invitation.inviterId,
            roleIds: invitation.roleIds,
            groupIds: invitation.groupIds,
          },
        });
        const issued = await auth.completeAuthentication(tx, identity);
        return { identity: publicIdentity(identity), ...issued };
      });
    },
    async linkIdentities(leftCredential, rightCredential) {
      if (!config.linkedOnboarding)
        throw new IamError('LINKING_DISABLED', 'Account linking disabled');
      const [left, right] = await Promise.all([
        ctx.principals.authenticate(leftCredential),
        ctx.principals.authenticate(rightCredential),
      ]);
      auth.requireRecent(left);
      auth.requireRecent(right);
      if (
        left.identity.rootAdmin ||
        right.identity.rootAdmin ||
        left.session.kind !== 'user' ||
        right.session.kind !== 'user' ||
        left.identity.tenantId === right.identity.tenantId
      )
        throw new IamError('INVALID_LINK', 'Only separate ordinary tenant identities can link');
      return store.transaction(async (tx) => {
        const currentLeft = await ctx.principals.currentPrincipal(tx, left);
        const currentRight = await ctx.principals.currentPrincipal(tx, right);
        if (
          currentLeft.identity.rootAdmin ||
          currentRight.identity.rootAdmin ||
          currentLeft.session.kind !== 'user' ||
          currentRight.session.kind !== 'user'
        )
          throw new IamError('INVALID_LINK', 'Only ordinary user identities can link');
        const identities = [currentLeft.identity, currentRight.identity].sort(byIdentityId);
        const tenantId = identities[0]!.tenantId;
        const uniqueKey = identities.map((identity) => identity.id).join(':');
        const existing = (await tx.find<IdentityLink>('identityLinks', { tenantId, uniqueKey }))[0];
        if (existing && !existing.revoked)
          throw new IamError('CONFLICT', 'These identities are already linked', 409);
        const link = existing
          ? await tx.put<IdentityLink>('identityLinks', { ...existing, revoked: false })
          : await tx.insert<IdentityLink>('identityLinks', {
              id: id(),
              tenantId,
              uniqueKey,
              leftId: identities[0]!.id,
              rightId: identities[1]!.id,
              revoked: false,
            });
        await ctx.events.audit(
          tx,
          currentLeft,
          'identity:link',
          currentLeft.identity.tenantId,
          link.id,
          'allow',
        );
        return link;
      });
    },
    async switchIdentity(credential, input) {
      const [source, target] = await Promise.all([
        ctx.principals.authenticate(credential),
        ctx.principals.authenticate(input.targetCredential),
      ]);
      auth.requireRecent(target);
      return store.transaction(async (tx) => {
        const currentSource = await ctx.principals.currentPrincipal(tx, source);
        const currentTarget = await ctx.principals.currentPrincipal(tx, target);
        const link = await tx.get<IdentityLink>('identityLinks', text(input.linkId, 'linkId'));
        const members = link ? [link.leftId, link.rightId] : [];
        const valid =
          link &&
          !link.revoked &&
          source.identity.id !== target.identity.id &&
          members.includes(source.identity.id) &&
          members.includes(target.identity.id) &&
          !currentSource.identity.rootAdmin &&
          !currentTarget.identity.rootAdmin &&
          currentSource.session.kind === 'user' &&
          currentTarget.session.kind === 'user';
        if (!valid) throw new IamError('INVALID_LINK', 'Invalid identity link', 403);
        const issued = await auth.issueSession(tx, currentTarget.identity, {
          mfa: currentTarget.session.mfa,
          authenticatedAt: currentTarget.session.authenticatedAt,
          method: currentTarget.session.method,
          // principal.mfaTime carries the target's own ceremony forward, never the switch time.
          mfaAuthenticatedAt: currentTarget.session.mfaAuthenticatedAt,
        });
        await ctx.events.audit(
          tx,
          currentSource,
          'identity:switch',
          currentTarget.identity.tenantId,
          currentTarget.identity.id,
          'allow',
        );
        return issued;
      });
    },
    async assumeRole(credential, input) {
      const assume = async (): Promise<RoleCredential> => {
        const principalBefore = await ctx.principals.authenticate(credential);
        if (principalBefore.session.kind === 'role')
          throw new IamError('ROLE_CHAINING_DISABLED', 'Role chaining is disabled');
        if (principalBefore.session.impersonatorId)
          throw new IamError(
            'IMPERSONATION_RESTRICTED',
            'Roles cannot be assumed while impersonating a member',
            403,
          );
        // Input shapes are refused before any lookup; trust-dependent rules run inside the operation.
        const sessionName = sessionNameValue(input.sessionName);
        const sourceIdentity = sourceIdentityValue(input.sourceIdentity);
        const tags = sessionTagsValue(input.tags);
        const format = credentialFormat(input.format);
        const audience = audienceValue(input.audience, format);
        if (format === 'jwt' && !ctx.sessionTokens)
          throw new IamError(
            'FEATURE_DISABLED',
            'Session JWTs are not enabled on this deployment (sts.jwt)',
            403,
          );
        if (input.externalId !== undefined && typeof input.externalId !== 'string')
          throw new IamError('INVALID_INPUT', 'externalId must be a string');
        const requestedTrust = await ctx.scoped<Trust>(
          store,
          'trusts',
          input.trustId,
          input.tenantId,
        );
        return ctx.operations.operation(
          credential,
          principalBefore.identity.tenantId,
          'iam:roles:assume',
          requestedTrust.roleId,
          async ({ tx, principal }) => {
            const trust = await ctx.scoped<Trust>(tx, 'trusts', input.trustId, input.tenantId);
            if (input.policy) await catalog.validate(tx, input.tenantId, input.policy);
            // Tags and a source identity can satisfy ABAC conditions, so both are closed unless the trust opens them.
            // Stored values are read fail-closed: a malformed list admits no tags, an unknown mode forbids.
            const allowedTagKeys = trustAllowedTagKeys(trust);
            const tagKeys = Object.keys(tags ?? {}).sort();
            const tagsAdmitted =
              allowedTagKeys.any || tagKeys.every((key) => allowedTagKeys.keys.includes(key));
            const sourceIdentityMode = trustSourceIdentityMode(trust);
            const permitted =
              !trust.revoked &&
              (trust.kind ?? 'identity') === 'identity' &&
              trust.sourceIdentityId === principal.identity.id &&
              trust.sourceTenantId === principal.identity.tenantId &&
              !(trustRequiresMfa(trust) && principal.session.mfa !== true) &&
              externalIdMatches(trust.externalIdHash, input.externalId) &&
              tagsAdmitted &&
              !(sourceIdentityMode === 'forbidden' && sourceIdentity !== undefined) &&
              !(sourceIdentityMode === 'required' && sourceIdentity === undefined);
            if (!permitted)
              throw new IamError('ACCESS_DENIED', 'Role trust does not permit assumption', 403);
            if (
              (await ctx.ancestry(tx, await ctx.tenant(tx, input.tenantId))).some(
                (item) => item.status !== 'active',
              )
            )
              throw new IamError('TENANT_INACTIVE', 'Target tenant inactive');
            const role = await ctx.scoped<Role>(tx, 'roles', trust.roleId, input.tenantId);
            const durationSeconds = durationWithin(
              input.durationSeconds,
              roleDurationBounds(ctx, trust, format),
            );
            // The injected clock, like user sessions, so validation and issuance agree under a test clock.
            const now = ctx.now();
            const sourceAuthorityIds = (
              await ctx.decisions.identityGrants(
                tx,
                principal.identity.id,
                principal.identity.tenantId,
              )
            ).map((path) => path.authorityId);
            const draft: Session = {
              id: id(),
              tenantId: input.tenantId,
              identityId: principal.identity.id,
              originalIdentityId: principal.identity.id,
              sourceTenantId: principal.identity.tenantId,
              sourceSessionId: principal.session.id,
              sourceAuthorityIds,
              roleId: role.id,
              trustId: trust.id,
              kind: 'role',
              tokenHash: '',
              createdAt: now,
              lastSeenAt: now,
              // The source's authentication carries over; its sign-in method and remembered device do not.
              authenticatedAt: principal.session.authenticatedAt,
              expiresAt: Math.min(principal.session.expiresAt, now + durationSeconds * 1000),
              mfa: principal.session.mfa,
            };
            if (principal.session.mfa && typeof principal.session.mfaAuthenticatedAt === 'number')
              draft.mfaAuthenticatedAt = principal.session.mfaAuthenticatedAt;
            if (input.policy) draft.policy = input.policy;
            if (sessionName !== undefined) draft.sessionName = sessionName;
            if (sourceIdentity !== undefined) draft.sourceIdentity = sourceIdentity;
            if (tags) draft.sessionTags = tags;
            // The issuing address, so the target tenant's allowlist and network blocks judge it on every use.
            const client = auth.currentClient();
            if (client && Object.keys(client).length) draft.client = { ...client };
            const { token, session } = await mintCredential(ctx, tx, {
              identity: principal.identity,
              draft,
              format,
              audience,
            });
            // The target tenant sees who assumed its role, under the new session's context.
            await ctx.events.audit(
              tx,
              { identity: principal.identity, session },
              'role:assumed',
              input.tenantId,
              role.id,
              'allow',
              false,
              {
                trustId: trust.id,
                sourceTenantId: principal.identity.tenantId,
                sourceSessionKind: principal.session.kind,
                durationSeconds,
                format,
                tagKeys,
                // Whether the source identity's attributes reach this session's decisions (read as a boolean).
                passSourceAttributes: trustPassesSourceAttributes(trust),
              },
            );
            return temporaryCredential(token, session, now) as RoleCredential;
          },
        );
      };
      // In-process integrations that pass the incoming request's headers as the credential (with no client scope
      // set) get the client derived from those headers (`http.clientInfo`), as `sts.getSessionToken` does, so the
      // role session records its issuing client and allowlists, network blocks and `bindSessionsToIp` judge it.
      if (!auth.currentClient() && credential?.headers)
        return auth.withClient(
          clientFromHeaders(ctx.options, credential.headers, config.baseURL),
          assume,
        );
      return assume();
    },
  };
}
