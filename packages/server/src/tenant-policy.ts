import {
  IamError,
  authMethods,
  isIpRange,
  type AuthMethod,
  type TenantAuthPolicy,
  type TenantLimits,
} from '@better-iam/core';
import { integer, object, strings } from './validation.js';

const authPolicyKeys = new Set([
  'requireMfa',
  'allowedMethods',
  'sessionLifetimeMs',
  'sessionIdleTimeoutMs',
  'maxAttempts',
  'minPasswordLength',
  'maxSessions',
  'allowImpersonation',
  'trustedDeviceDays',
  'passwordHistory',
  'passwordMaxAgeDays',
  'passwordMinClasses',
  'passwordRejectPersonalInfo',
  'notifyNewSignIn',
  'allowedIpRanges',
  'mfaEmailCodes',
  'requireMfaForOwners',
  'bindSessionsToIp',
]);
const thirtyDays = 30 * 24 * 60 * 60_000;

/** Validates a tenant authentication policy; every field is optional but must be well-formed. */
export function tenantAuthPolicy(value: unknown): TenantAuthPolicy {
  const input = object(value);
  const policy: TenantAuthPolicy = {};
  for (const key of Object.keys(input))
    if (!authPolicyKeys.has(key))
      throw new IamError('INVALID_INPUT', `Unknown authentication policy field ${key}`);
  if (input.requireMfa !== undefined) {
    if (typeof input.requireMfa !== 'boolean')
      throw new IamError('INVALID_INPUT', 'requireMfa must be a boolean');
    policy.requireMfa = input.requireMfa;
  }
  if (input.allowedMethods !== undefined) {
    const methods = [...new Set(strings(input.allowedMethods, 'allowedMethods'))];
    if (!methods.length || methods.some((method) => !authMethods.includes(method as AuthMethod)))
      throw new IamError(
        'INVALID_INPUT',
        `allowedMethods must list one or more of ${authMethods.join(', ')}`,
      );
    policy.allowedMethods = methods as AuthMethod[];
  }
  if (input.sessionLifetimeMs !== undefined)
    policy.sessionLifetimeMs = integer(
      input.sessionLifetimeMs,
      'sessionLifetimeMs',
      60_000,
      thirtyDays,
    );
  if (input.sessionIdleTimeoutMs !== undefined)
    policy.sessionIdleTimeoutMs = integer(
      input.sessionIdleTimeoutMs,
      'sessionIdleTimeoutMs',
      60_000,
      thirtyDays,
    );
  if (
    policy.sessionLifetimeMs !== undefined &&
    policy.sessionIdleTimeoutMs !== undefined &&
    policy.sessionIdleTimeoutMs > policy.sessionLifetimeMs
  )
    throw new IamError('INVALID_INPUT', 'sessionIdleTimeoutMs cannot exceed sessionLifetimeMs');
  if (input.maxAttempts !== undefined)
    policy.maxAttempts = integer(input.maxAttempts, 'maxAttempts', 1, 100_000);
  if (input.minPasswordLength !== undefined)
    policy.minPasswordLength = integer(input.minPasswordLength, 'minPasswordLength', 12, 128);
  if (input.maxSessions !== undefined)
    policy.maxSessions = integer(input.maxSessions, 'maxSessions', 1, 100);
  if (input.allowImpersonation !== undefined) {
    if (typeof input.allowImpersonation !== 'boolean')
      throw new IamError('INVALID_INPUT', 'allowImpersonation must be a boolean');
    policy.allowImpersonation = input.allowImpersonation;
  }
  if (input.trustedDeviceDays !== undefined)
    policy.trustedDeviceDays = integer(input.trustedDeviceDays, 'trustedDeviceDays', 0, 365);
  if (input.passwordHistory !== undefined)
    policy.passwordHistory = integer(input.passwordHistory, 'passwordHistory', 1, 24);
  if (input.passwordMaxAgeDays !== undefined)
    policy.passwordMaxAgeDays = integer(input.passwordMaxAgeDays, 'passwordMaxAgeDays', 1, 3650);
  if (input.passwordMinClasses !== undefined)
    policy.passwordMinClasses = integer(input.passwordMinClasses, 'passwordMinClasses', 2, 4);
  if (input.passwordRejectPersonalInfo !== undefined) {
    if (typeof input.passwordRejectPersonalInfo !== 'boolean')
      throw new IamError('INVALID_INPUT', 'passwordRejectPersonalInfo must be a boolean');
    policy.passwordRejectPersonalInfo = input.passwordRejectPersonalInfo;
  }
  if (input.notifyNewSignIn !== undefined) {
    if (typeof input.notifyNewSignIn !== 'boolean')
      throw new IamError('INVALID_INPUT', 'notifyNewSignIn must be a boolean');
    policy.notifyNewSignIn = input.notifyNewSignIn;
  }
  if (input.allowedIpRanges !== undefined) {
    const ranges = [...new Set(strings(input.allowedIpRanges, 'allowedIpRanges'))];
    if (!ranges.length || ranges.some((range) => !isIpRange(range)))
      throw new IamError(
        'INVALID_INPUT',
        'allowedIpRanges must list one or more IPv4/IPv6 addresses or CIDR blocks',
      );
    policy.allowedIpRanges = ranges;
  }
  if (input.mfaEmailCodes !== undefined) {
    if (typeof input.mfaEmailCodes !== 'boolean')
      throw new IamError('INVALID_INPUT', 'mfaEmailCodes must be a boolean');
    policy.mfaEmailCodes = input.mfaEmailCodes;
  }
  if (input.requireMfaForOwners !== undefined) {
    if (typeof input.requireMfaForOwners !== 'boolean')
      throw new IamError('INVALID_INPUT', 'requireMfaForOwners must be a boolean');
    policy.requireMfaForOwners = input.requireMfaForOwners;
  }
  if (input.bindSessionsToIp !== undefined) {
    if (typeof input.bindSessionsToIp !== 'boolean')
      throw new IamError('INVALID_INPUT', 'bindSessionsToIp must be a boolean');
    policy.bindSessionsToIp = input.bindSessionsToIp;
  }
  return policy;
}

const limitKeys: (keyof TenantLimits)[] = [
  'identities',
  'serviceAccounts',
  'agents',
  'groups',
  'roles',
  'policies',
  'resources',
  'webhooks',
];

/** Validates plan limits: known keys only, each a non-negative integer. */
export function tenantLimits(value: unknown): TenantLimits {
  const input = object(value);
  const limits: TenantLimits = {};
  for (const key of Object.keys(input))
    if (!limitKeys.includes(key as keyof TenantLimits))
      throw new IamError('INVALID_INPUT', `Unknown limit ${key}`);
  for (const key of limitKeys)
    if (input[key] !== undefined) limits[key] = integer(input[key], key, 0, 1_000_000_000);
  return limits;
}
