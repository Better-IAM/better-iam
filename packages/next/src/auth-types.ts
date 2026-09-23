/**
 * Shared contract between the auth server actions (`createAuthActions`) and the client forms in
 * `@better-iam/next/client`. Everything here is serializable: it crosses the server action boundary.
 */

/** Where a multi-step authentication form is. */
export type AuthStep =
  /** Email + password (or the start of any flow). */
  | 'credentials'
  /** A second factor is required: authenticator code, emailed code, recovery code, or passkey. */
  | 'mfa'
  /** The account must enroll an authenticator before its first session (`enrollment` carries the secret). */
  | 'enroll'
  /** An emailed sign-in code was sent (passwordless); the next submission carries the code. */
  | 'code-sent'
  /** An email was sent (password reset, verification, sign-up); nothing else to do in this form. */
  | 'sent'
  /** Finished without a redirect, for example to show recovery codes once after enrollment. */
  | 'done';

export interface AuthFormError {
  /** The server's stable error code (`INVALID_CREDENTIALS`, `RATE_LIMITED`, `WEAK_PASSWORD`, ...). */
  code: string;
  message: string;
  /** The form field the error belongs to, when there is one (`password`, `code`, `email`, `org`, `token`). */
  field?: string;
  /** For `RATE_LIMITED`: how long to wait before trying again. */
  retryAfterMs?: number;
}

/** The pending second factor of a sign-in, carried in hidden fields so forms work without client JavaScript. */
export interface AuthMfaChallenge {
  tenantId: string;
  challenge: string;
  enrollmentRequired: boolean;
  emailCodeAvailable: boolean;
  passkeyAvailable: boolean;
  /** Set while enrolling: the authenticator secret and its `otpauth://` URI for a QR code. */
  enrollment?: { secret: string; uri: string };
}

/** The state every auth action returns; `null` before the first submission (the `useActionState` initial state). */
export interface AuthFormState {
  step: AuthStep;
  error?: AuthFormError;
  mfa?: AuthMfaChallenge;
  /** Shown once after enrolling an authenticator. The session is already set; continue to `next`. */
  recoveryCodes?: string[];
  /** Non-secret inputs echoed back so the form can be re-rendered filled in. Passwords and codes are never echoed. */
  values?: { email?: string; org?: string; tenantId?: string; name?: string };
  /** A safe same-origin path to continue to. */
  next?: string;
  /** The "keep me signed in" choice, echoed so later steps (MFA, enrollment, emailed code) submit it again. */
  keepSignedIn?: boolean;
  /** A short human-readable status, for example "We sent a code to ada@example.com". */
  notice?: string;
}

export type AuthAction = (
  previous: AuthFormState | null,
  form: FormData,
) => Promise<AuthFormState | null>;

/**
 * Form field names shared by the actions and the client forms. `intent` selects the step a submission performs.
 */
export const authFields = {
  intent: 'intent',
  org: 'org',
  tenantId: 'tenantId',
  email: 'email',
  password: 'password',
  name: 'name',
  code: 'code',
  challenge: 'challenge',
  rememberDevice: 'rememberDevice',
  keepSignedIn: 'keepSignedIn',
  token: 'token',
  next: 'next',
  kind: 'kind',
  confirmPassword: 'confirmPassword',
} as const;

/** Values of the `intent` field. */
export type AuthIntent =
  | 'password'
  | 'mfa'
  | 'recovery'
  | 'email-code'
  | 'enroll'
  | 'send-code'
  | 'code'
  | 'cancel';
