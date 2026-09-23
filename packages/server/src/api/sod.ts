import { IamError, type CredentialInput, type IamStore, type Identity } from '@better-iam/core';
import type { ServerContext } from '../context.js';
import type { Role } from '../models.js';
import { sodViolations, type SodRule } from '../sod.js';
import { byNewest, id } from '../utils.js';
import { strings, text } from '../validation.js';

const modes = new Set<SodRule['mode']>(['prevent', 'detect']);

/**
 * Separation-of-duties rules (toxic role combinations). A `prevent` rule makes every granting operation — bindings,
 * group membership, bulk onboarding, access-request approval, configuration apply, invitation acceptance — fail with
 * `SOD_CONFLICT` when it would leave someone holding two of its roles; conflicts that predate the rule are reported by
 * `violations` and the access analysis instead of blocking unrelated work.
 */
export function createSodApi(ctx: ServerContext) {
  const { operation } = ctx.operations;
  async function validate(
    tx: IamStore,
    tenantId: string,
    input: { name?: string; description?: string; roleIds?: string[]; mode?: SodRule['mode'] },
    rule: Partial<SodRule>,
  ) {
    if (input.name !== undefined) rule.name = text(input.name, 'name', 200).trim();
    if (input.description !== undefined)
      rule.description = text(input.description, 'description', 1000).trim();
    if (input.mode !== undefined) {
      if (!modes.has(input.mode))
        throw new IamError('INVALID_INPUT', 'mode must be prevent or detect');
      rule.mode = input.mode;
    }
    if (input.roleIds !== undefined) {
      const roleIds = [...new Set(strings(input.roleIds, 'roleIds'))];
      if (roleIds.length < 2 || roleIds.length > 20)
        throw new IamError('INVALID_INPUT', 'A rule names 2 to 20 conflicting roles');
      for (const roleId of roleIds) {
        const role = await ctx.scoped<Role>(tx, 'roles', roleId, tenantId);
        if (role.protected)
          throw new IamError('INVALID_INPUT', 'Owner roles cannot be part of a rule');
      }
      rule.roleIds = roleIds;
    }
  }
  return {
    /** Declares conflicting roles. Requires iam:sod:manage. */
    create: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        name: string;
        roleIds: string[];
        mode?: SodRule['mode'];
        description?: string;
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:sod:manage',
        'sod/*',
        async ({ tx, principal }) => {
          const rule: Partial<SodRule> = { mode: 'prevent' };
          await validate(tx, input.tenantId, input, rule);
          if (!rule.name || !rule.roleIds)
            throw new IamError('INVALID_INPUT', 'name and roleIds are required');
          const saved = await tx.insert<SodRule>('sodRules', {
            ...(rule as SodRule),
            id: id(),
            tenantId: input.tenantId,
            createdAt: ctx.now(),
            createdBy: principal.identity.id,
          });
          const existing = await sodViolations(ctx, tx, input.tenantId, [saved]);
          return { ...saved, existingViolations: existing.length };
        },
      ),
    /** Rules of the tenant, newest first. Requires iam:sod:read. */
    list: (credential: CredentialInput, input: { tenantId: string }) =>
      operation(credential, input.tenantId, 'iam:sod:read', 'sod/*', async ({ tx }) =>
        (await tx.find<SodRule>('sodRules', { tenantId: input.tenantId })).sort(byNewest),
      ),
    /** Changes a rule's name, description, roles, or mode. Requires iam:sod:manage. */
    update: (
      credential: CredentialInput,
      input: {
        tenantId: string;
        ruleId: string;
        name?: string;
        description?: string;
        roleIds?: string[];
        mode?: SodRule['mode'];
      },
    ) =>
      operation(
        credential,
        input.tenantId,
        'iam:sod:manage',
        `sod/${text(input.ruleId, 'ruleId')}`,
        async ({ tx }) => {
          const rule = await ctx.scoped<SodRule>(tx, 'sodRules', input.ruleId, input.tenantId);
          const next = { ...rule };
          await validate(tx, input.tenantId, input, next);
          return tx.put<SodRule>('sodRules', next);
        },
      ),
    /** Removes a rule. Requires iam:sod:manage. */
    delete: (credential: CredentialInput, input: { tenantId: string; ruleId: string }) =>
      operation(
        credential,
        input.tenantId,
        'iam:sod:manage',
        `sod/${text(input.ruleId, 'ruleId')}`,
        async ({ tx }) => {
          await ctx.scoped<SodRule>(tx, 'sodRules', input.ruleId, input.tenantId);
          await tx.delete('sodRules', input.ruleId);
          return { deleted: true };
        },
      ),
    /** Everyone currently holding two or more roles of a rule, with names for review screens. Requires iam:sod:read. */
    violations: (credential: CredentialInput, input: { tenantId: string; ruleId?: string }) =>
      operation(credential, input.tenantId, 'iam:sod:read', 'sod/*', async ({ tx }) => {
        let rules = await tx.find<SodRule>('sodRules', { tenantId: input.tenantId });
        if (input.ruleId !== undefined) rules = rules.filter((rule) => rule.id === input.ruleId);
        const roles = new Map(
          (await tx.find<Role>('roles', { tenantId: input.tenantId })).map((role) => [
            role.id,
            role.name,
          ]),
        );
        const result = [];
        for (const violation of await sodViolations(ctx, tx, input.tenantId, rules)) {
          const identity = await tx.get<Identity>('identities', violation.identityId);
          result.push({
            ...violation,
            identityName: identity?.email ?? identity?.name ?? violation.identityId,
            roleNames: violation.roleIds.map((roleId) => roles.get(roleId) ?? roleId),
          });
        }
        return result;
      }),
  };
}
