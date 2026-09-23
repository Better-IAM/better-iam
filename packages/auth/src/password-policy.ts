import { createHash } from 'node:crypto';
import { IamError, type Identity, type TenantAuthPolicy } from '@better-iam/core';

/** Deployment-wide password screening; tenant rules (`TenantAuthPolicy.password*`) add to it. */
export interface PasswordPolicyOptions {
  /**
   * Rejects well-known, keyboard-walk, sequential and low-variety passwords (default true). The list is short and
   * built in; supply `isBreached` for a comprehensive corpus.
   */
  blockCommonPasswords?: boolean;
  /**
   * Returns true when the password appears in a breach corpus. `pwnedPasswords()` provides a k-anonymity
   * Have I Been Pwned client; only a five-character SHA-1 prefix leaves the process.
   */
  isBreached?: (password: string) => Promise<boolean>;
  /** Custom rule: return a message to reject the password, or nothing to accept it. */
  check?: (
    password: string,
    context: { tenantId: string; identity?: Pick<Identity, 'id' | 'email' | 'name'> },
  ) => string | undefined | Promise<string | undefined>;
}

const COMMON = new Set([
  'password1234',
  'password12345',
  'password123456',
  'passw0rd1234',
  'p@ssw0rd1234',
  'p@ssword1234',
  'password!123',
  'passwordpassword',
  'iloveyou1234',
  'letmein12345',
  'welcome12345',
  'welcome123456',
  'changeme1234',
  'changeme12345',
  'administrator',
  'admin1234567',
  'adminadmin123',
  'football1234',
  'baseball1234',
  'princess1234',
  'sunshine1234',
  'superman1234',
  'trustno11234',
  'monkey123456',
  'dragon123456',
  'master123456',
  'correcthorsebatterystaple',
  'correct horse battery staple',
  'thequickbrownfox',
  'letmeinletmein',
  'secretpassword',
  'mypassword123',
  'default12345',
  'computer1234',
  'internet1234',
  'whatever1234',
  'starwars1234',
  'pokemon12345',
  'summer2024!!',
  'winter2024!!',
  'spring2025!!',
  'autumn2025!!',
]);
const SEQUENCES = [
  '01234567890123456789',
  'abcdefghijklmnopqrstuvwxyz',
  'qwertyuiopasdfghjklzxcvbnm',
  'qwertzuiopasdfghjklyxcvbnm',
  'azertyuiopqsdfghjklmwxcvbn',
  '1qaz2wsx3edc4rfv5tgb6yhn',
  '!@#$%^&*()_+',
];

/** Lowercase, uppercase, digit, and everything else. */
export function characterClasses(password: string): number {
  return [/[a-z]/, /[A-Z]/, /[0-9]/, /[^a-zA-Z0-9]/].filter((pattern) => pattern.test(password))
    .length;
}

/** The built-in weak-password screen: common passwords, keyboard walks and sequences, and low variety. */
export function isCommonPassword(password: string): boolean {
  const lower = password.toLowerCase();
  if (COMMON.has(lower) || COMMON.has(lower.replace(/[^a-z0-9 ]/g, ''))) return true;
  if (new Set(lower).size < 5) return true;
  for (const sequence of SEQUENCES) {
    const forward = sequence.repeat(Math.ceil((lower.length * 2) / sequence.length) + 1);
    const reversed = [...forward].reverse().join('');
    if (forward.includes(lower) || reversed.includes(lower)) return true;
  }
  return false;
}

/** Pieces of the identity (email local part, name words) at least four characters long. */
function personalTokens(identity: Pick<Identity, 'email' | 'name'>): string[] {
  const tokens = new Set<string>();
  const local = identity.email?.split('@')[0]?.toLowerCase();
  if (local) {
    tokens.add(local);
    for (const part of local.split(/[^a-z0-9]+/)) tokens.add(part);
  }
  for (const part of identity.name?.toLowerCase().split(/[^\p{L}\p{N}]+/u) ?? []) tokens.add(part);
  return [...tokens].filter((token) => token.length >= 4);
}

/**
 * Enforces the synchronous rules (tenant length, character classes, personal information, the built-in screen).
 * History, breach, and custom checks run in the auth service because they are asynchronous or need storage.
 */
export function assertPasswordRules(
  password: string,
  policy: TenantAuthPolicy | undefined,
  options: PasswordPolicyOptions | undefined,
  identity?: Pick<Identity, 'email' | 'name'>,
): void {
  const minimum = policy?.minPasswordLength;
  if (minimum !== undefined && password.length < minimum)
    throw new IamError(
      'WEAK_PASSWORD',
      `Password must contain at least ${minimum} characters in this organization`,
    );
  const classes = policy?.passwordMinClasses;
  if (classes !== undefined && characterClasses(password) < classes)
    throw new IamError(
      'WEAK_PASSWORD',
      `Password must mix at least ${classes} of: lowercase, uppercase, digits, symbols`,
    );
  if (policy?.passwordRejectPersonalInfo && identity) {
    const lower = password.toLowerCase();
    if (personalTokens(identity).some((token) => lower.includes(token)))
      throw new IamError('WEAK_PASSWORD', 'Password must not contain your name or email address');
  }
  if ((options?.blockCommonPasswords ?? true) && isCommonPassword(password))
    throw new IamError('WEAK_PASSWORD', 'Password is too common or predictable');
}

/**
 * A Have I Been Pwned "range" client (k-anonymity): hashes the password with SHA-1, sends only the first five hex
 * characters, and matches the returned suffixes locally. Network failures accept the password unless `failClosed`.
 */
export function pwnedPasswords(
  options: {
    /** Minimum breach count that rejects a password (default 1). */
    threshold?: number;
    failClosed?: boolean;
    timeoutMs?: number;
    endpoint?: string;
    fetch?: typeof fetch;
  } = {},
): (password: string) => Promise<boolean> {
  const threshold = options.threshold ?? 1;
  const endpoint = (options.endpoint ?? 'https://api.pwnedpasswords.com/range/').replace(
    /\/?$/,
    '/',
  );
  const request = options.fetch ?? fetch;
  return async (password) => {
    const digest = createHash('sha1').update(password).digest('hex').toUpperCase();
    const prefix = digest.slice(0, 5);
    const suffix = digest.slice(5);
    try {
      const response = await request(`${endpoint}${prefix}`, {
        headers: { 'add-padding': 'true' },
        signal: AbortSignal.timeout(options.timeoutMs ?? 3_000),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      for (const line of (await response.text()).split(/\r?\n/)) {
        const [candidate, count] = line.trim().split(':');
        if (candidate?.toUpperCase() === suffix && Number(count) >= threshold) return true;
      }
      return false;
    } catch {
      if (options.failClosed)
        throw new IamError('PASSWORD_CHECK_UNAVAILABLE', 'Password screening is unavailable', 503);
      return false;
    }
  };
}
