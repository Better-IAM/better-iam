import { IamError, type TenantAccessPolicy } from '@better-iam/core';
import type { Binding } from './models.js';
import { integer, object } from './validation.js';

export const defaultActivationMs = 3_600_000;
export const maxActivationMs = 7 * 86400_000;
export const defaultApprovalLifetimeMs = 24 * 3_600_000;

/** Validates a tenant access policy; unknown keys and non-boolean flags are refused, `false` flags are dropped. */
export function tenantAccessPolicy(value: unknown): TenantAccessPolicy {
  const input = object(value);
  const policy: TenantAccessPolicy = {};
  for (const key of Object.keys(input))
    if (
      ![
        'maxActivationMs',
        'requireJustification',
        'requireMfa',
        'requireApproval',
        'approvalLifetimeMs',
      ].includes(key)
    )
      throw new IamError('INVALID_INPUT', `Unknown access policy field ${key}`);
  if (input.maxActivationMs !== undefined)
    policy.maxActivationMs = integer(
      input.maxActivationMs,
      'maxActivationMs',
      60_000,
      maxActivationMs,
    );
  if (input.approvalLifetimeMs !== undefined)
    policy.approvalLifetimeMs = integer(
      input.approvalLifetimeMs,
      'approvalLifetimeMs',
      5 * 60_000,
      30 * 86400_000,
    );
  for (const flag of ['requireJustification', 'requireMfa', 'requireApproval'] as const) {
    if (input[flag] === undefined) continue;
    if (typeof input[flag] !== 'boolean')
      throw new IamError('INVALID_INPUT', `${flag} must be boolean`);
    if (input[flag]) policy[flag] = true;
  }
  return policy;
}

export interface ActivationRules {
  requireJustification: boolean;
  requireMfa: boolean;
  requireApproval: boolean;
  maxActivationMs: number;
  approvalLifetimeMs: number;
}

/** The rules that govern activating one binding: the binding's own settings tightened by the tenant's policy. */
export function activationRules(
  binding: Binding,
  policy: TenantAccessPolicy = {},
): ActivationRules {
  const bindingMax = binding.maxActivationMs ?? defaultActivationMs;
  return {
    requireJustification:
      binding.requireJustification === true || policy.requireJustification === true,
    requireMfa: binding.requireMfa === true || policy.requireMfa === true,
    requireApproval: binding.requireApproval === true || policy.requireApproval === true,
    maxActivationMs:
      policy.maxActivationMs !== undefined
        ? Math.min(bindingMax, policy.maxActivationMs)
        : bindingMax,
    approvalLifetimeMs: policy.approvalLifetimeMs ?? defaultApprovalLifetimeMs,
  };
}
