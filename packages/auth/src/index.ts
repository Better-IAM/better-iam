import { PasskeyAuth } from './service/passkeys.js';
import type { AuthOptions } from './types.js';

export { decryptSecret, encryptSecret, hashToken, newId, newToken, openSecret } from './crypto.js';
export {
  credentialTokenKinds,
  credentialTokenScanPattern,
  newCredentialToken,
  parseCredentialToken,
} from './crypto.js';
export type { CredentialTokenType } from './crypto.js';
export { createMemoryRateLimiter, createStoreRateLimiter } from './rate-limit.js';
export { renderDeliveryMessage } from './templates.js';
export type { RenderedMessage, TemplateLinks, TemplateOptions } from './templates.js';
export { characterClasses, isCommonPassword, pwnedPasswords } from './password-policy.js';
export type { PasswordPolicyOptions } from './password-policy.js';
export type { DispatchResult } from './outbox.js';
export type {
  AuthOptions,
  DeliveryMessage,
  MfaCredential,
  MfaRequired,
  MfaSessionResult,
  NetworkBlock,
  RateLimitOptions,
  RateLimiter,
  SafeIdentity,
  SafePasskey,
  SafeSession,
  SafeTrustedDevice,
  SessionResult,
  SignInFailureReason,
  SignInLedger,
  SignInResult,
  TrustedDevice,
} from './types.js';

/**
 * Authentication services. The class is assembled from feature modules (sessions, account management,
 * passwordless, MFA, passkeys) over a shared base. Low-level transaction helpers are for trusted server integrations only.
 */
export class AuthService extends PasskeyAuth {}

export function createAuth(options: AuthOptions): AuthService {
  return new AuthService(options);
}
