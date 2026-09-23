import {
  IamError,
  type CredentialInput,
  type IamStore,
  type Identity,
  type ResourceRef,
  type Session,
} from '@better-iam/core';
import { attributeValues } from './catalog.js';
import type { ServerContext } from './context.js';
import type { Binding } from './models.js';
import { syncTeamsFromGroups } from './teams.js';
import { id } from './utils.js';
import { email } from './validation.js';

export interface FederatedLogin {
  tenantId: string;
  providerId: string;
  issuer: string;
  subject: string;
  email?: string;
  name?: string;
  emailVerified?: boolean;
  linkingSessionId?: string;
  linkingIdentityId?: string;
  /** Identity attributes mapped by the protocol package; validated against `permissions.identityAttributes` and stored on every sign-in. */
  attributes?: Record<string, unknown>;
}
export interface RoleMappingSync {
  tenantId: string;
  connectionId: string;
  groupId: string;
  identityIds: string[];
  roleIds: string[];
  credential?: CredentialInput;
}
/** The minimal binding operations the SCIM mapping sync needs from the provisioning API. */
export interface BindingApi {
  create(
    credential: CredentialInput,
    input: {
      tenantId: string;
      roleId: string;
      subjectType: 'identity' | 'group';
      subjectId: string;
    },
  ): Promise<Binding>;
  delete(
    credential: CredentialInput,
    input: { tenantId: string; bindingId: string },
  ): Promise<unknown>;
}

/** Trusted callbacks handed to protocol packages (OAuth, SAML, SCIM); never HTTP endpoints. */
export function createFederation(ctx: ServerContext, bindings: BindingApi) {
  const { store, auth } = ctx;
  async function completeAuthentication(input: FederatedLogin) {
    return store.transaction(async (tx) => {
      await auth.assertTenantActive(tx, input.tenantId);
      // Directory-driven attributes: the provider's mapped values replace the stored ones on every sign-in.
      const withAttributes = async (record: Identity): Promise<Identity> =>
        input.attributes === undefined
          ? record
          : tx.put('identities', {
              ...record,
              attributes: attributeValues(ctx.catalog.identityAttributes, input.attributes),
            });
      const key = JSON.stringify([input.providerId, input.issuer, input.subject]);
      const mapping = (
        await tx.find('externalIdentities', { tenantId: input.tenantId, uniqueKey: key })
      )[0];
      let identity = mapping
        ? await tx.get<Identity>('identities', String(mapping.identityId))
        : undefined;
      if (input.linkingSessionId) {
        const linkedSession = await tx.get<Session>('sessions', input.linkingSessionId);
        const linkedIdentity = linkedSession
          ? await tx.get<Identity>('identities', linkedSession.identityId)
          : undefined;
        if (
          !linkedSession ||
          !linkedIdentity ||
          linkedIdentity.id !== input.linkingIdentityId ||
          linkedIdentity.tenantId !== input.tenantId ||
          linkedIdentity.rootAdmin ||
          linkedSession.kind !== 'user'
        )
          throw new IamError('INVALID_LINK', 'Invalid verified account-linking proof', 403);
        const verified = await ctx.principals.currentPrincipal(tx, {
          identity: linkedIdentity,
          session: linkedSession,
        });
        auth.requireRecent(verified);
        if (mapping && identity?.id !== linkedIdentity.id)
          throw new IamError(
            'ACCOUNT_LINK_CONFLICT',
            'External identity is already linked to another account',
            409,
          );
        if (!mapping) {
          await tx.insert('externalIdentities', {
            id: id(),
            tenantId: input.tenantId,
            uniqueKey: key,
            identityId: linkedIdentity.id,
            providerId: input.providerId,
            issuer: input.issuer,
            subject: input.subject,
          });
          await ctx.events.audit(
            tx,
            verified,
            'identity:link-provider',
            input.tenantId,
            linkedIdentity.id,
            'allow',
          );
        }
        return auth.completeAuthentication(tx, await withAttributes(linkedIdentity), 'federated');
      }
      if (!identity) {
        if (!input.email || !input.emailVerified)
          throw new IamError(
            'VERIFIED_EMAIL_REQUIRED',
            'Federation enrollment needs a verified email',
          );
        if (
          (
            await tx.find<Identity>('identities', {
              tenantId: input.tenantId,
              email: email(input.email),
            })
          ).length
        )
          throw new IamError(
            'ACCOUNT_LINK_REQUIRED',
            'Authenticate the existing account before linking this provider',
            409,
          );
        identity = await auth.createIdentity(tx, {
          tenantId: input.tenantId,
          email: email(input.email),
          name: input.name ?? input.email,
          emailVerified: true,
        });
        await tx.insert('externalIdentities', {
          id: id(),
          tenantId: input.tenantId,
          uniqueKey: key,
          identityId: identity.id,
          providerId: input.providerId,
          issuer: input.issuer,
          subject: input.subject,
        });
      }
      return auth.completeAuthentication(tx, await withAttributes(identity), 'federated');
    });
  }
  async function syncRoleMappings(tx: IamStore, input: RoleMappingSync): Promise<void> {
    // Teams that sync their members from this directory group follow every push (teams.ts).
    await syncTeamsFromGroups(ctx, tx, input.tenantId, {
      groupId: input.groupId,
      actorId: 'directory-sync',
    });
    // Ongoing directory updates change membership only. Grant configuration requires
    // an actual administrator credential and retains that administrator's ceiling.
    if (!input.credential) return;
    await ctx.scoped(tx, 'groups', input.groupId, input.tenantId);
    const existing = await tx.find<Binding>('bindings', {
      tenantId: input.tenantId,
      subjectType: 'group',
      subjectId: input.groupId,
      scimConnectionId: input.connectionId,
    });
    for (const binding of existing)
      if (!input.roleIds.includes(binding.roleId))
        await bindings.delete(input.credential, {
          tenantId: input.tenantId,
          bindingId: binding.id,
        });
    for (const roleId of input.roleIds) {
      if (existing.some((binding) => binding.roleId === roleId)) continue;
      const binding = await bindings.create(input.credential, {
        tenantId: input.tenantId,
        roleId,
        subjectType: 'group',
        subjectId: input.groupId,
      });
      await tx.put('bindings', { ...binding, scimConnectionId: input.connectionId });
    }
  }
  const protocolHost = {
    store,
    authenticate: (input: CredentialInput) => ctx.principals.authenticate(input),
    /** Validates identity attributes a protocol (SCIM) maps from its payload against `permissions.identityAttributes`. */
    validateIdentityAttributes: (value: unknown) =>
      attributeValues(ctx.catalog.identityAttributes, value),
    validateSession: (sessionId: string) => auth.validateSessionId(sessionId),
    authorize: async (credential: CredentialInput, action: string, resource: ResourceRef) =>
      ctx.operations.requireAccess({
        ...credential,
        tenantId: resource.tenantId,
        action,
        resource,
      }),
    completeAuthentication,
    syncRoleMappings,
  };
  return { completeAuthentication, syncRoleMappings, protocolHost };
}
