import { IamError, type CredentialInput } from '@better-iam/core';
import type { ServerContext } from '../context.js';
import type { Group } from '../models.js';
import {
  buildLdapDirectory,
  loadLdapSettings,
  normalizeBaseDn,
  saveLdapSettings,
  type LdapDirectory,
  type LdapSettings,
  type LdapUidMode,
} from '../ldap.js';
import { text } from '../validation.js';

export interface LdapSettingsView {
  tenantId: string;
  enabled: boolean;
  baseDn: string;
  uid: LdapUidMode;
  peopleBind: boolean;
  serviceBind: boolean;
  requireTls: boolean;
  mfaSuffix: 'auto' | 'never';
  includeServiceAccounts: boolean;
  attributes: string[];
  groups: 'all' | 'selected';
  groupIds: string[];
  updatedAt?: number;
  updatedBy?: string;
}

export interface LdapSettingsInput {
  tenantId: string;
  enabled?: boolean;
  baseDn?: string;
  uid?: LdapUidMode;
  peopleBind?: boolean;
  serviceBind?: boolean;
  requireTls?: boolean;
  mfaSuffix?: 'auto' | 'never';
  includeServiceAccounts?: boolean;
  /** Declared identity attributes to publish on people's entries. */
  attributes?: string[];
  groups?: 'all' | 'selected';
  groupIds?: string[];
}

function view(settings: LdapSettings): LdapSettingsView {
  return {
    tenantId: settings.tenantId,
    enabled: settings.enabled,
    baseDn: settings.baseDn,
    uid: settings.uid,
    peopleBind: settings.peopleBind,
    serviceBind: settings.serviceBind,
    requireTls: settings.requireTls,
    mfaSuffix: settings.mfaSuffix,
    includeServiceAccounts: settings.includeServiceAccounts,
    attributes: settings.attributes,
    groups: settings.groups,
    groupIds: settings.groupIds,
    ...(settings.updatedAt ? { updatedAt: settings.updatedAt, updatedBy: settings.updatedBy } : {}),
  };
}

/**
 * The `ldap` API group: each tenant's LDAP directory gateway. Administrators turn it on under a base DN and choose what
 * it publishes (`iam:ldap:manage`, `iam:ldap:read`); the gateway (`@better-iam/ldap`) reads the directory as the
 * account that bound, which sees everyone with `iam:ldap:read` and otherwise only itself.
 */
export function createLdapApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  const tenantOf = (value: unknown) => text(value, 'tenantId');

  return {
    /** The tenant's gateway settings. Requires iam:ldap:read. */
    getSettings: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, tenantOf(input.tenantId), 'iam:ldap:read', 'ldap/settings', async ({ tx, tenant }) =>
        view(await loadLdapSettings(tx, tenant)),
      ),

    /**
     * Changes the gateway settings (fields left out keep their values). A base DN belongs to one organization
     * (`LDAP_BASE_TAKEN`). Requires iam:ldap:manage.
     */
    updateSettings: (credential: CredentialInput, input: LdapSettingsInput) =>
      operation(credential, tenantOf(input.tenantId), 'iam:ldap:manage', 'ldap/settings', async ({ tx, tenant, principal }) => {
        const current = await loadLdapSettings(tx, tenant);
        const next: LdapSettings = { ...current, updatedAt: ctx.now(), updatedBy: principal.identity.id };
        if (input.baseDn !== undefined) {
          const { baseDn, normalized } = normalizeBaseDn(input.baseDn);
          next.baseDn = baseDn;
          next.normalizedBaseDn = normalized;
        }
        for (const key of ['enabled', 'peopleBind', 'serviceBind', 'requireTls', 'includeServiceAccounts'] as const) {
          if (input[key] === undefined) continue;
          if (typeof input[key] !== 'boolean') throw new IamError('INVALID_INPUT', `${key} must be a boolean`);
          next[key] = input[key];
        }
        if (input.uid !== undefined) {
          if (!['email', 'localPart', 'id'].includes(input.uid))
            throw new IamError('INVALID_INPUT', "uid must be 'email', 'localPart' or 'id'");
          next.uid = input.uid;
        }
        if (input.mfaSuffix !== undefined) {
          if (input.mfaSuffix !== 'auto' && input.mfaSuffix !== 'never')
            throw new IamError('INVALID_INPUT', "mfaSuffix must be 'auto' or 'never'");
          next.mfaSuffix = input.mfaSuffix;
        }
        if (input.attributes !== undefined) {
          if (!Array.isArray(input.attributes) || input.attributes.length > 64)
            throw new IamError('INVALID_INPUT', 'attributes must list at most 64 identity attributes');
          const names = [...new Set(input.attributes.map((name) => text(name, 'attribute', 64)))];
          for (const name of names)
            if (!Object.hasOwn(ctx.catalog.identityAttributes, name) || !/^[a-zA-Z][a-zA-Z0-9-]{0,63}$/.test(name))
              throw new IamError('INVALID_INPUT', `${name} is not a declared identity attribute LDAP can publish`);
          next.attributes = names;
        }
        if (input.groups !== undefined) {
          if (input.groups !== 'all' && input.groups !== 'selected')
            throw new IamError('INVALID_INPUT', "groups must be 'all' or 'selected'");
          next.groups = input.groups;
        }
        if (input.groupIds !== undefined) {
          if (!Array.isArray(input.groupIds) || input.groupIds.length > 500)
            throw new IamError('INVALID_INPUT', 'groupIds must list at most 500 groups');
          const ids = [...new Set(input.groupIds.map((groupId) => text(groupId, 'groupId')))];
          for (const groupId of ids) await ctx.scoped<Group>(tx, 'groups', groupId, tenant.id);
          next.groupIds = ids;
        }
        return view(await saveLdapSettings(tx, next, current));
      }),

    /**
     * The directory as the caller may read it: people, groups (with members) and, when published, service accounts.
     * With iam:ldap:read on `iam/ldap/directory` the whole published directory (audited as `ldap:directory:read`),
     * otherwise only the caller's own entry and groups. What the gateway serves searches from.
     */
    directory: async (credential: CredentialInput, input: { tenantId: string }): Promise<LdapDirectory> => {
      const tenantId = tenantOf(input.tenantId);
      const authenticated = await ctx.principals.authenticate(credential);
      return ctx.store.transaction(async (tx) => {
        const principal = await ctx.principals.currentPrincipal(tx, authenticated);
        const tenant = await ctx.tenant(tx, tenantId);
        const settings = await loadLdapSettings(tx, tenant);
        if (!settings.enabled) throw new IamError('FEATURE_DISABLED', 'The LDAP gateway is off for this organization', 403);
        if (principal.session.tenantId !== tenant.id || principal.session.impersonatorId)
          throw new IamError('ACCESS_DENIED', 'Access denied', 403);
        const decision = await ctx.decisions.decide(
          tx,
          principal,
          { tenantId, action: 'iam:ldap:read', resource: { type: 'iam', id: 'ldap/directory' } },
          true,
        );
        // The platform root override does not read an organization's directory over LDAP.
        const full = decision.allowed && decision.reason !== 'ROOT_OVERRIDE';
        const directory = await buildLdapDirectory(ctx, tx, tenant, settings, full ? undefined : principal);
        if (full)
          await ctx.events.audit(tx, principal, 'ldap:directory:read', tenantId, 'ldap/directory', 'allow', false, {
            people: directory.people.length,
            groups: directory.groups.length,
          });
        return directory;
      });
    },
  };
}
