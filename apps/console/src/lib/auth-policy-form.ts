import type { Tenant } from 'better-iam';
import type { FieldSpec } from '@/components/api-form';

type AuthPolicy = NonNullable<Tenant['authPolicy']>;

/**
 * Every authentication policy field the settings form edits. `tenants.setAuthPolicy` replaces the whole policy, so a
 * field the form does not carry is erased by every save; keying this by the policy type makes a new policy field a
 * compile error here until the form below handles it (and `uneditedPolicyKeys` catches stored fields at runtime).
 */
const EDITED: Record<keyof AuthPolicy, true> = {
  requireMfa: true,
  requireMfaForOwners: true,
  bindSessionsToIp: true,
  allowedMethods: true,
  sessionLifetimeMs: true,
  sessionIdleTimeoutMs: true,
  maxAttempts: true,
  minPasswordLength: true,
  maxSessions: true,
  allowImpersonation: true,
  trustedDeviceDays: true,
  notifyNewSignIn: true,
  allowedIpRanges: true,
  mfaEmailCodes: true,
  passwordMinClasses: true,
  passwordHistory: true,
  passwordMaxAgeDays: true,
  passwordRejectPersonalInfo: true,
};

/** Policy fields the form would drop on save (a policy written by a newer server, say); normally empty. */
export function uneditedPolicyKeys(policy: AuthPolicy | undefined): string[] {
  return Object.keys(policy ?? {}).filter((key) => !Object.hasOwn(EDITED, key));
}

const number = (value: number | undefined) => value?.toString() ?? '';

/**
 * The "Set authentication policy" fields, each pre-filled from the stored policy so saving without changes keeps it
 * exactly, including the allowed sign-in methods. `recordsAddresses` adds a warning to the fields that need client IPs.
 */
export function authPolicyFields(
  policy: AuthPolicy | undefined,
  options: { recordsAddresses?: boolean } = {},
): FieldSpec[] {
  const unrecorded = options.recordsAddresses === false;
  const fields: FieldSpec[] = [
    {
      name: 'requireMfa',
      label: 'Require MFA for every member',
      type: 'checkbox',
      defaultValue: policy?.requireMfa ?? false,
    },
    {
      name: 'requireMfaForOwners',
      label: 'Require MFA for owners',
      type: 'checkbox',
      defaultValue: policy?.requireMfaForOwners ?? false,
      help: 'Owners enroll an authenticator on their next sign-in; other members are unaffected.',
    },
    {
      name: 'bindSessionsToIp',
      label: 'Bind sessions to the network they were signed in from',
      type: 'checkbox',
      defaultValue: policy?.bindSessionsToIp ?? false,
      help: unrecorded
        ? 'Not enforced: this deployment does not record client addresses.'
        : 'A session used from another address is refused and the person signs in again there; a stolen cookie is useless elsewhere. People on changing networks sign in more often.',
    },
    {
      name: 'allowedMethods',
      label: 'Allowed sign-in methods',
      type: 'multiselect',
      options: [
        { value: 'password', label: 'Password' },
        { value: 'passwordless-email', label: 'Email magic link or code' },
        { value: 'passwordless-sms', label: 'SMS code' },
        { value: 'passkey', label: 'Passkey' },
        { value: 'federated', label: 'Federated (OAuth/SAML)' },
      ],
      // Pre-selected: an empty selection means "every method", so a save must not silently lift a restriction.
      defaultValue: policy?.allowedMethods ?? [],
      help: 'Leave empty to accept every method the deployment enables.',
    },
    {
      name: 'sessionLifetimeMs',
      label: 'Session lifetime (ms)',
      type: 'number',
      placeholder: '28800000',
      defaultValue: number(policy?.sessionLifetimeMs),
      help: 'One minute to thirty days; never longer than the deployment default.',
    },
    {
      name: 'sessionIdleTimeoutMs',
      label: 'Idle timeout (ms)',
      type: 'number',
      placeholder: '1800000',
      defaultValue: number(policy?.sessionIdleTimeoutMs),
    },
    {
      name: 'maxAttempts',
      label: 'Sign-in attempts per window',
      type: 'number',
      placeholder: '5',
      defaultValue: number(policy?.maxAttempts),
      help: 'Never more than the deployment allows.',
    },
    {
      name: 'minPasswordLength',
      label: 'Minimum password length',
      type: 'number',
      placeholder: '12',
      defaultValue: number(policy?.minPasswordLength),
      help: '12 to 128 characters.',
    },
    {
      name: 'maxSessions',
      label: 'Concurrent sessions per member',
      type: 'number',
      placeholder: 'unlimited',
      defaultValue: number(policy?.maxSessions),
      help: 'Signing in beyond the cap ends the oldest session.',
    },
    {
      name: 'allowImpersonation',
      label: 'Allow administrators to view the console as a member',
      type: 'checkbox',
      defaultValue: policy?.allowImpersonation ?? false,
      help: 'Requires iam:identities:impersonate; owners can never be impersonated and every action is attributed to the administrator.',
    },
    {
      name: 'trustedDeviceDays',
      label: 'Remember devices for (days)',
      type: 'number',
      placeholder: 'deployment default',
      defaultValue: number(policy?.trustedDeviceDays),
      help: 'How long “remember this device” skips the authenticator code; 0 turns it off for this organization.',
    },
    {
      name: 'notifyNewSignIn',
      label: 'Email members when they sign in from a new device',
      type: 'checkbox',
      defaultValue: policy?.notifyNewSignIn ?? false,
      help: 'Sends a “new sign-in” email when no live session or remembered device matches the browser and address.',
    },
    {
      name: 'allowedIpRanges',
      label: 'Allowed networks (comma-separated CIDR blocks)',
      type: 'list',
      placeholder: '203.0.113.0/24, 2001:db8::/32',
      defaultValue: policy?.allowedIpRanges?.join(', ') ?? '',
      help: unrecorded
        ? 'Not enforced: this deployment does not record client addresses. Leave empty to allow any network.'
        : 'Sign-ins and sessions from other addresses are refused. Leave empty to allow any network.',
    },
    {
      name: 'mfaEmailCodes',
      label: 'Offer emailed one-time codes to members without an authenticator',
      type: 'checkbox',
      defaultValue: policy?.mfaEmailCodes ?? false,
      help: 'Weaker than an authenticator app; lets MFA be required without forcing every member to install one. Never applies to root administrators.',
    },
    {
      name: 'passwordMinClasses',
      label: 'Character classes required',
      type: 'number',
      placeholder: 'none',
      defaultValue: number(policy?.passwordMinClasses),
      help: '2 to 4 of lowercase, uppercase, digits, and symbols.',
    },
    {
      name: 'passwordHistory',
      label: 'Passwords remembered',
      type: 'number',
      placeholder: 'none',
      defaultValue: number(policy?.passwordHistory),
      help: 'Refuse reuse of this many recent passwords, including the current one (1 to 24).',
    },
    {
      name: 'passwordMaxAgeDays',
      label: 'Password expiry (days)',
      type: 'number',
      placeholder: 'never',
      defaultValue: number(policy?.passwordMaxAgeDays),
      help: 'Expired passwords stop signing in until the member resets them.',
    },
    {
      name: 'passwordRejectPersonalInfo',
      label: 'Reject passwords containing the member’s name or email',
      type: 'checkbox',
      defaultValue: policy?.passwordRejectPersonalInfo ?? false,
    },
  ];
  return fields.map((field) => ({ ...field, group: 'authPolicy' }));
}

/** The names `authPolicyFields` covers, for tests that hold the form and the policy type together. */
export const editedPolicyKeys = Object.keys(EDITED);
