import {
  authFields,
  type AuthAction,
  type AuthFormError,
  type AuthFormState,
  type AuthIntent,
  type AuthMfaChallenge,
  type AuthStep,
} from './auth-types.js';
import { safeRedirectPath } from './edge.js';

/** The part of `createIamNext()` the auth actions use. */
export interface AuthActionsHost {
  client(): {
    $request<Output = unknown>(
      path: string,
      input?: unknown,
      options?: { headers?: HeadersInit },
    ): Promise<Output>;
  };
  tenant(slug: string): Promise<{ tenantId: string; slug: string; name: string } | null>;
  /** Clears the session cookie when sign-out finds the session already gone or refused. */
  clearSessionCookie?(): Promise<void>;
}

export interface AuthActionsOptions {
  /** Where a completed sign-in goes when the form carries no safe `next` (default `/`). */
  afterSignIn?: string;
  /** Where `signOut` goes (default `/login`). */
  afterSignOut?: string;
  /** The sign-in page, where password reset, sign-up, and email verification end (default `/login`). */
  loginPath?: string;
  /** Picks a submission's tenant instead of the `tenantId` and `org` fields; null means an unknown organization. */
  resolveTenant?: (form: FormData) => Promise<string | null>;
  /** With no `tenantId` or `org` field, find the tenant from the email's verified domain (`domains/discover`). */
  discover?: boolean;
  /** Performs a redirect; defaults to `redirect()` from `next/navigation`. */
  redirect?: (url: string) => never | Promise<never>;
  /**
   * Replaces messages by error code (`INVALID_CREDENTIALS`, `RATE_LIMITED`, ...) and notices by key
   * (`SIGN_IN_CODE_SENT`, `MFA_CODE_SENT`, `PASSWORD_RESET_SENT`, `VERIFICATION_SENT`, `INVITATION_ACCEPTED`);
   * notices fill in `{email}`.
   */
  messages?: Partial<Record<string, string>>;
}

/** The actions `createAuthActions` returns; every form action suits `useActionState`. */
export interface AuthActions {
  /** Password or emailed-code sign-in and every second-factor step; the `intent` field selects which. */
  signIn: AuthAction;
  /**
   * Step-up for the current session: the password, then MFA when the account has it. Issues a new session and ends
   * the one it replaces. The new cookie lasts for the browser session unless the form posts `keepSignedIn`: the
   * request does not say how long the old cookie was meant to last, so step-up never extends it.
   */
  reauthenticate: AuthAction;
  /**
   * Ends the session and redirects to `afterSignOut`. A session the server refuses (expired, revoked, or unusable
   * from this network) cannot be ended, so it only loses its cookie.
   */
  signOut(form?: FormData): Promise<never>;
  /** Emails a reset link; the answer is the same whether or not the address has an account. */
  requestPasswordReset: AuthAction;
  /** Sets a new password from the emailed link (`tenantId` and `token` fields), then redirects to sign in. */
  resetPassword: AuthAction;
  signUp: AuthAction;
  /** Confirms the emailed verification link (`tenantId` and `token` fields), then redirects to sign in. */
  verifyEmail: AuthAction;
  /**
   * Accepts a member (`kind` `member`, the default) or organization owner (`kind` `owner`) invitation and signs the
   * new account in. When MFA is required the same action takes the `enroll` and `mfa` steps; if that challenge
   * lapses, the account already exists, so the `done` step sends the person to sign in (`next` is the login path).
   */
  acceptInvitation: AuthAction;
}

/**
 * Hidden fields the MFA and enrollment steps post back besides `tenantId`, `challenge`, `next`, and `keepSignedIn`,
 * so a refused code re-renders the same step without client JavaScript. `authHiddenFields(state)` lists them all.
 */
export const authStepFields = {
  enrollmentRequired: 'enrollmentRequired',
  emailCodeAvailable: 'emailCodeAvailable',
  passkeyAvailable: 'passkeyAvailable',
  /** While enrolling: the authenticator secret and `otpauth://` URI already shown on the page. */
  secret: 'secret',
  uri: 'uri',
} as const;

/**
 * The hidden inputs a form renders for `state` so its next submission continues the flow: `next`, the pending
 * challenge on the MFA and enrollment steps, the email and organization on the steps after the credentials, and the
 * "keep me signed in" choice (after the credentials step, which renders its own checkbox).
 */
export function authHiddenFields(state: AuthFormState | null): [name: string, value: string][] {
  if (!state) return [];
  const hidden: [string, string][] = [];
  if (state.next) hidden.push([authFields.next, state.next]);
  if (state.step === 'credentials' || state.step === 'sent' || state.step === 'done') return hidden;
  if (state.keepSignedIn !== undefined)
    hidden.push([authFields.keepSignedIn, state.keepSignedIn ? '1' : '0']);
  if (state.values?.email) hidden.push([authFields.email, state.values.email]);
  if (state.values?.org) hidden.push([authFields.org, state.values.org]);
  const mfa = state.mfa;
  if (state.step === 'code-sent' || !mfa) {
    if (state.values?.tenantId) hidden.push([authFields.tenantId, state.values.tenantId]);
    return hidden;
  }
  hidden.push([authFields.tenantId, mfa.tenantId], [authFields.challenge, mfa.challenge]);
  if (mfa.enrollmentRequired) hidden.push([authStepFields.enrollmentRequired, '1']);
  if (mfa.emailCodeAvailable) hidden.push([authStepFields.emailCodeAvailable, '1']);
  if (mfa.passkeyAvailable) hidden.push([authStepFields.passkeyAvailable, '1']);
  if (mfa.enrollment)
    hidden.push(
      [authStepFields.secret, mfa.enrollment.secret],
      [authStepFields.uri, mfa.enrollment.uri],
    );
  return hidden;
}

interface MfaRequired {
  mfaRequired: true;
  challenge: string;
  enrollmentRequired: boolean;
  emailCodeAvailable?: boolean;
  passkeyAvailable?: boolean;
}
type Outcome<T> = { ok: true; value: T } | { ok: false; error: AuthFormError };
/** A step either renders a new form state or ends with a session whose cookie is already set. */
type StepResult = AuthFormState | 'signed-in';
type Base = Omit<AuthFormState, 'step'>;
type Client = ReturnType<AuthActionsHost['client']>;
type SecondFactorIntent = 'mfa' | 'recovery' | 'email-code' | 'enroll';
type FirstFactor = (
  client: Client,
  intent: AuthIntent,
  form: FormData,
  base: Base,
) => Promise<StepResult>;
/** What a second-factor step renders when its challenge is gone. */
type Lapsed = (base: Base, error: AuthFormError) => AuthFormState;
/** Where sign-in, step-up, and invitations differ once the first factor is done. */
interface FlowRules {
  /** A step-up: the new session replaces the current one, with a browser-session cookie unless the form asks. */
  stepUp?: boolean;
  /** Default: the credentials step with the error. */
  lapsed?: Lapsed;
}

const intents = new Set<string>([
  'password',
  'mfa',
  'recovery',
  'email-code',
  'enroll',
  'send-code',
  'code',
  'cancel',
] satisfies AuthIntent[]);
/**
 * Refusals of the presented session itself: it cannot be used, or ended, from here. Every 401 counts too. Other
 * 403s, such as `CSRF_REJECTED`, refuse the request rather than the session, so sign-out must not hide the session.
 */
const sessionRefusals = new Set([
  'UNAUTHENTICATED',
  'SESSION_NETWORK_MISMATCH',
  'MFA_REQUIRED',
  'EMAIL_UNVERIFIED',
  'TENANT_INACTIVE',
  'TENANT_UNAVAILABLE',
  'INVALID_TENANT_TREE',
  'IP_NOT_ALLOWED',
  'IP_BLOCKED',
]);
const errorFields = new Map<string, string>([
  ['INVALID_CREDENTIALS', authFields.password],
  ['INVALID_MFA', authFields.code],
  ['WEAK_PASSWORD', authFields.password],
  ['BREACHED_PASSWORD', authFields.password],
  ['PASSWORD_REUSED', authFields.password],
  ['PASSWORD_EXPIRED', authFields.password],
  ['INVALID_CHALLENGE', authFields.code],
  ['UNKNOWN_ORGANIZATION', authFields.org],
  ['IDENTITY_EXISTS', authFields.email],
  ['INVITATION_INVALID', authFields.token],
]);
/** Links from emails carry their token in a hidden field: an expired one is the token's fault, not a typed code's. */
const linkFields = { INVALID_CHALLENGE: authFields.token };

function field(form: FormData, name: string): string {
  const value = form.get(name);
  return typeof value === 'string' ? value.trim() : '';
}
/** Passwords are used exactly as typed. */
function rawField(form: FormData, name: string): string {
  const value = form.get(name);
  return typeof value === 'string' ? value : '';
}
/** A checkbox, also when a hidden `0` precedes it so that an unticked box still submits the field. */
function checked(form: FormData, name: string): boolean {
  return form
    .getAll(name)
    .some((value) => typeof value === 'string' && !['', '0', 'false', 'off'].includes(value));
}
function intentOf(form: FormData): AuthIntent {
  const value = field(form, authFields.intent);
  return intents.has(value) ? (value as AuthIntent) : 'password';
}
function isSecondFactor(intent: AuthIntent): intent is SecondFactorIntent {
  return (
    intent === 'mfa' || intent === 'recovery' || intent === 'email-code' || intent === 'enroll'
  );
}
function enrollmentOf(form: FormData): { secret: string; uri: string } | undefined {
  const secret = field(form, authStepFields.secret);
  const uri = field(form, authStepFields.uri);
  return /^[A-Za-z2-7]{16,256}=*$/.test(secret) &&
    uri.startsWith('otpauth://') &&
    uri.length <= 2048
    ? { secret, uri }
    : undefined;
}
function refused(base: Base, error: AuthFormError, step: AuthStep = 'credentials'): AuthFormState {
  return { ...base, step, error };
}
function withParam(path: string, name: string, value: string): string {
  return `${path}${path.includes('?') ? '&' : '?'}${name}=${encodeURIComponent(value)}`;
}
/**
 * A same-origin path, or `''`. Checks the result of `safeRedirectPath` too: it resolves dot segments after its own
 * checks, which turns `/.//host` into `//host`, a URL on another origin.
 */
function safeNext(value: unknown): string {
  const path = safeRedirectPath(value, '');
  return /^\/(?![/\\])/.test(path) ? path : '';
}
/**
 * Refusals meant for the person: the server's `IamError` and the typed client's `IamClientError`, matched by name so
 * duplicate package copies still count. Other errors with a `code`, such as a database or network failure in
 * `resolveTenant`, are outages or bugs: they propagate instead of showing their message on a public form.
 */
function isIamError(error: unknown): error is Error & { code: string; status?: unknown } {
  return (
    error instanceof Error &&
    (error.name === 'IamError' || error.name === 'IamClientError') &&
    typeof (error as { code?: unknown }).code === 'string'
  );
}
function isSessionRefusal(error: unknown): boolean {
  return isIamError(error) && (error.status === 401 || sessionRefusals.has(error.code));
}
function isControlFlow(error: unknown): boolean {
  const digest = error && typeof error === 'object' && 'digest' in error ? error.digest : undefined;
  return typeof digest === 'string' && /^(NEXT_|DYNAMIC_SERVER_USAGE)/.test(digest);
}
function isSessionResult(value: unknown): value is { token: string } {
  return (
    typeof value === 'object' &&
    value !== null &&
    'token' in value &&
    typeof value.token === 'string' &&
    'session' in value
  );
}
function isMfaRequired(value: unknown): value is MfaRequired {
  return (
    typeof value === 'object' &&
    value !== null &&
    'mfaRequired' in value &&
    value.mfaRequired === true &&
    'challenge' in value &&
    typeof value.challenge === 'string'
  );
}

/**
 * Headless server actions for sign-in, MFA, passwordless codes, password reset, sign-up, email verification,
 * invitations, step-up, and sign-out. Pass `createIamNext()`'s result; the actions call the IAM handler in process,
 * so session cookies are written through `cookies()` and forms work without client JavaScript.
 *
 * ```ts
 * // app/login/actions.ts
 * 'use server';
 * const auth = createAuthActions(iamNext, { discover: true });
 * export async function signIn(previous: AuthFormState | null, form: FormData) {
 *   return auth.signIn(previous, form);
 * }
 * ```
 *
 * Fields are named by `authFields`. The tenant comes from `resolveTenant`, else the `tenantId` field, else the `org`
 * slug, else (with `discover`) the email's verified domain. Steps after the first factor post back the fields of
 * `authHiddenFields(state)`. Completed sign-ins redirect to the form's `next` when it is a safe same-origin path.
 * Server refusals come back as `state.error` with the field they belong to; passwords, codes, tokens, and sessions
 * never appear in the returned state. Other errors (bugs, or a database outage in `resolveTenant`) and Next's own
 * control flow propagate.
 */
export function createAuthActions(
  host: AuthActionsHost,
  options: AuthActionsOptions = {},
): AuthActions {
  const afterSignIn = options.afterSignIn ?? '/';
  const loginPath = options.loginPath ?? '/login';
  // Next's entry files are CommonJS; explicit .js specifiers resolve under Node ESM and bundlers alike.
  const redirect =
    options.redirect ??
    (async (url: string): Promise<never> => {
      const mod = (await import('next/navigation.js')) as unknown as Record<string, unknown> & {
        default?: Record<string, unknown>;
      };
      const fn = mod.redirect ?? mod.default?.redirect;
      if (typeof fn !== 'function')
        throw new Error('next/navigation does not provide redirect(); upgrade Next.js');
      (fn as (url: string) => never)(url);
      throw new Error('redirect did not interrupt the action');
    });
  const say = (key: string, fallback: string): string => options.messages?.[key] ?? fallback;
  // A replacer function: a string replacement would expand `$&` and friends, which email addresses may contain.
  const notice = (key: string, fallback: string, email = ''): string =>
    say(key, fallback).replaceAll('{email}', () => email);
  const problem = (
    code: string,
    message: string,
    name?: string,
    retryAfterMs?: number,
  ): AuthFormError => ({
    code,
    message: say(code, message),
    ...(name ? { field: name } : {}),
    ...(retryAfterMs === undefined ? {} : { retryAfterMs }),
  });
  const missing = (name: string, message: string): AuthFormError =>
    problem('INVALID_INPUT', message, name);
  const mismatch = (form: FormData, password: string): AuthFormError | undefined =>
    form.has(authFields.confirmPassword) && rawField(form, authFields.confirmPassword) !== password
      ? problem('PASSWORD_MISMATCH', 'The passwords do not match', authFields.confirmPassword)
      : undefined;
  /** Runs one server call; IAM refusals become form errors, anything else propagates. */
  const attempt = async <T>(
    run: () => Promise<T>,
    fields: Record<string, string> = {},
  ): Promise<Outcome<T>> => {
    try {
      return { ok: true, value: await run() };
    } catch (error) {
      if (isControlFlow(error) || !isIamError(error)) throw error;
      const code = error.code;
      const wait = 'retryAfterMs' in error ? error.retryAfterMs : undefined;
      return {
        ok: false,
        error: problem(
          code,
          error.message,
          Object.hasOwn(fields, code) ? fields[code] : errorFields.get(code),
          typeof wait === 'number' ? wait : undefined,
        ),
      };
    }
  };
  /**
   * `X-Better-IAM-Persistent` for the call that issues the session: the form's "keep me signed in" choice when it
   * offers one, else `fallback`, else nothing (the deployment's default).
   */
  const persistence = (
    form: FormData,
    fallback?: '0',
  ): { headers: Record<string, string> } | undefined => {
    const value = form.has(authFields.keepSignedIn)
      ? checked(form, authFields.keepSignedIn)
        ? '1'
        : '0'
      : fallback;
    return value === undefined ? undefined : { headers: { 'x-better-iam-persistent': value } };
  };
  /** The session the request presents: the one a step-up replaces, and whose tenant its challenge belongs to. */
  const presentedSession = (client: Client) =>
    attempt(
      async () =>
        (await client.$request<{ session: { id: string; tenantId: string } }>('auth/getSession'))
          .session,
    );
  /**
   * Ends the session a step-up replaced, so a copy of its token stops working and a later sign-out, which ends only
   * the cookie's session, leaves nothing behind. Runs as the new session, which is recent enough for `revokeSession`.
   */
  const endReplaced = async (
    client: Client,
    sessionId: string,
    issued: { token: string },
  ): Promise<void> => {
    try {
      await client.$request(
        'auth/revokeSession',
        { sessionId },
        { headers: { authorization: `Bearer ${issued.token}` } },
      );
    } catch (error) {
      // Already ended elsewhere, or by a session cap: nothing is left to end.
      if (!isIamError(error) || error.code !== 'NOT_FOUND') throw error;
    }
  };
  /** Echoed non-secret values, the safe `next`, and the keep-signed-in choice: every returned state starts here. */
  const baseState = (form: FormData): Base => {
    const values: NonNullable<AuthFormState['values']> = {};
    for (const name of ['email', 'org', 'name'] as const) {
      const value = field(form, authFields[name]);
      if (value) values[name] = value;
    }
    // After the first factor the tenantId field belongs to the challenge, not to what the person entered.
    const tenantId = field(form, authFields.tenantId);
    if (tenantId && !form.has(authFields.challenge)) values.tenantId = tenantId;
    const next = safeNext(form.get(authFields.next));
    return {
      values,
      ...(next ? { next } : {}),
      ...(form.has(authFields.keepSignedIn)
        ? { keepSignedIn: checked(form, authFields.keepSignedIn) }
        : {}),
    };
  };
  const unknownOrganization = (message: string): Outcome<string> => ({
    ok: false,
    error: problem('UNKNOWN_ORGANIZATION', message, authFields.org),
  });
  const resolveTenant = async (client: Client, form: FormData): Promise<Outcome<string>> => {
    if (options.resolveTenant) {
      const resolver = options.resolveTenant;
      const resolved = await attempt(() => resolver(form));
      if (!resolved.ok) return resolved;
      return resolved.value
        ? { ok: true, value: resolved.value }
        : unknownOrganization('We could not find that organization');
    }
    const tenantId = field(form, authFields.tenantId);
    if (tenantId) return { ok: true, value: tenantId };
    const org = field(form, authFields.org).toLowerCase();
    if (org) {
      const tenant = await attempt(() => host.tenant(org));
      if (!tenant.ok) return tenant;
      return tenant.value
        ? { ok: true, value: tenant.value.tenantId }
        : unknownOrganization('We could not find that organization');
    }
    const email = field(form, authFields.email);
    if (options.discover && email) {
      const found = await attempt(
        () => client.$request<{ tenantId: string }>('domains/discover', { email }),
        { INVALID_INPUT: authFields.email },
      );
      if (found.ok) return { ok: true, value: found.value.tenantId };
      return found.error.code === 'NOT_FOUND'
        ? unknownOrganization('No organization uses this email domain; enter your organization')
        : found;
    }
    return {
      ok: false,
      error: problem('INVALID_INPUT', 'Enter your organization', authFields.org),
    };
  };
  const beginEnrollment = (client: Client, mfa: AuthMfaChallenge) =>
    attempt(async () => {
      const { secret, uri } = await client.$request<{ secret: string; uri: string }>(
        'auth/beginMfa',
        { tenantId: mfa.tenantId, challenge: mfa.challenge },
      );
      return { secret, uri };
    });

  /** After a first factor (password, emailed code, invitation): a session, an MFA challenge, or enrollment. */
  const afterFirstFactor = async (
    client: Client,
    result: unknown,
    tenantId: string,
    base: Base,
    lapsed: Lapsed = refused,
  ): Promise<StepResult> => {
    if (isSessionResult(result)) return 'signed-in';
    if (!isMfaRequired(result))
      throw new Error('The IAM server returned an unexpected sign-in result');
    const mfa: AuthMfaChallenge = {
      tenantId,
      challenge: result.challenge,
      enrollmentRequired: result.enrollmentRequired === true,
      emailCodeAvailable: result.emailCodeAvailable === true,
      passkeyAvailable: result.passkeyAvailable === true,
    };
    if (!mfa.enrollmentRequired) return { ...base, step: 'mfa', mfa };
    const enrollment = await beginEnrollment(client, mfa);
    if (!enrollment.ok) return lapsed(base, enrollment.error);
    return { ...base, step: 'enroll', mfa: { ...mfa, enrollment: enrollment.value } };
  };

  /** The `mfa`, `recovery`, `email-code`, and `enroll` steps, rebuilt from the hidden fields of the step's form. */
  const secondFactor = async (
    client: Client,
    intent: SecondFactorIntent,
    form: FormData,
    base: Base,
    next: string,
    rules: FlowRules,
  ): Promise<StepResult> => {
    const lapsed = rules.lapsed ?? refused;
    const tenantId = field(form, authFields.tenantId);
    const challenge = field(form, authFields.challenge);
    if (!tenantId || !challenge)
      return lapsed(base, problem('INVALID_CHALLENGE', 'Sign in again to continue'));
    const enrollment = enrollmentOf(form);
    const mfa: AuthMfaChallenge = {
      tenantId,
      challenge,
      enrollmentRequired:
        intent === 'enroll' ||
        enrollment !== undefined ||
        checked(form, authStepFields.enrollmentRequired),
      emailCodeAvailable: checked(form, authStepFields.emailCodeAvailable),
      passkeyAvailable: checked(form, authStepFields.passkeyAvailable),
      ...(enrollment ? { enrollment } : {}),
    };
    const stay: AuthStep =
      intent === 'enroll' || (intent === 'email-code' && enrollment) ? 'enroll' : 'mfa';
    const retry = async (error: AuthFormError): Promise<AuthFormState> => {
      // An expired or spent challenge cannot be retried: start over.
      if (error.code === 'INVALID_CHALLENGE' || error.code === 'UNAUTHENTICATED')
        return lapsed(base, error);
      if (stay === 'enroll' && !mfa.enrollment) {
        const fresh = await beginEnrollment(client, mfa);
        if (!fresh.ok) return lapsed(base, fresh.error);
        mfa.enrollment = fresh.value;
      }
      return { ...refused(base, error, stay), mfa };
    };
    if (intent === 'email-code') {
      const sent = await attempt(() =>
        client.$request('auth/requestMfaCode', { tenantId, challenge }),
      );
      if (!sent.ok) return retry(sent.error);
      return {
        ...base,
        step: 'mfa',
        mfa: { ...mfa, emailCodeAvailable: true },
        notice: notice('MFA_CODE_SENT', 'We emailed you a sign-in code.'),
      };
    }
    const typed = field(form, authFields.code);
    const code =
      intent === 'recovery' ? typed.replace(/[\s-]/g, '').toLowerCase() : typed.replace(/\s/g, '');
    if (!code) return retry(missing(authFields.code, 'Enter the code'));
    const persistent = persistence(form, rules.stepUp ? '0' : undefined);
    if (intent === 'enroll') {
      const enrolled = await attempt(() =>
        client.$request<{ recoveryCodes?: unknown }>(
          'auth/confirmMfa',
          {
            credential: { tenantId, challenge },
            code,
            ...(checked(form, authFields.rememberDevice) ? { rememberDevice: true } : {}),
          },
          persistent,
        ),
      );
      if (!enrolled.ok) return retry(enrolled.error);
      const recoveryCodes = enrolled.value.recoveryCodes;
      if (!Array.isArray(recoveryCodes) || !recoveryCodes.every((item) => typeof item === 'string'))
        throw new Error('The IAM server returned no recovery codes');
      return { ...base, step: 'done', recoveryCodes, next };
    }
    // Read while the cookie still holds the session being stepped up; one that is already gone needs no ending.
    const replaced = rules.stepUp ? await presentedSession(client) : undefined;
    const verified = await attempt(() =>
      intent === 'recovery'
        ? client.$request('auth/recoverMfa', { tenantId, challenge, code }, persistent)
        : client.$request(
            'auth/verifyMfa',
            {
              tenantId,
              challenge,
              code,
              rememberDevice: checked(form, authFields.rememberDevice),
            },
            persistent,
          ),
    );
    if (!verified.ok) return retry(verified.error);
    if (!isSessionResult(verified.value))
      throw new Error('The IAM server returned an unexpected MFA result');
    if (replaced?.ok) await endReplaced(client, replaced.value.id, verified.value);
    return 'signed-in';
  };

  /**
   * Sign-in, step-up, and invitations share one shape: `cancel` starts over, second-factor intents continue the
   * pending challenge, and a finished sign-in redirects to `next` (outside any try block, so Next sees the redirect).
   */
  const flow =
    (firstFactor: FirstFactor, rules: FlowRules = {}): AuthAction =>
    async (_previous, form) => {
      const client = host.client();
      const intent = intentOf(form);
      const base = baseState(form);
      const next = base.next ?? afterSignIn;
      if (intent === 'cancel') return { ...base, step: 'credentials' };
      const result = isSecondFactor(intent)
        ? await secondFactor(client, intent, form, base, next, rules)
        : await firstFactor(client, intent, form, base);
      if (result === 'signed-in') return redirect(next);
      return result;
    };

  const passwordSignIn = async (
    client: Client,
    form: FormData,
    base: Base,
  ): Promise<StepResult> => {
    const email = field(form, authFields.email);
    const password = rawField(form, authFields.password);
    if (!email) return refused(base, missing(authFields.email, 'Enter your email address'));
    if (!password) return refused(base, missing(authFields.password, 'Enter your password'));
    const tenant = await resolveTenant(client, form);
    if (!tenant.ok) return refused(base, tenant.error);
    const result = await attempt(() =>
      client.$request(
        'auth/signIn',
        { tenantId: tenant.value, email, password },
        persistence(form),
      ),
    );
    if (!result.ok) return refused(base, result.error);
    return afterFirstFactor(client, result.value, tenant.value, base);
  };

  const sendCode = async (client: Client, form: FormData, base: Base): Promise<AuthFormState> => {
    const email = field(form, authFields.email);
    if (!email) return refused(base, missing(authFields.email, 'Enter your email address'));
    const tenant = await resolveTenant(client, form);
    if (!tenant.ok) return refused(base, tenant.error);
    const sent = await attempt(() =>
      client.$request('auth/startPasswordless', {
        tenantId: tenant.value,
        destination: email,
        channel: 'email',
        kind: 'code',
      }),
    );
    if (!sent.ok) return refused(base, sent.error);
    return {
      ...base,
      step: 'code-sent',
      notice: notice(
        'SIGN_IN_CODE_SENT',
        'If {email} has an account, we sent it a sign-in code.',
        email,
      ),
    };
  };

  const finishCode = async (client: Client, form: FormData, base: Base): Promise<StepResult> => {
    const email = field(form, authFields.email);
    const code = field(form, authFields.code).replace(/\s/g, '');
    if (!email) return refused(base, missing(authFields.email, 'Enter your email address'));
    if (!code) return refused(base, missing(authFields.code, 'Enter the code'), 'code-sent');
    const tenant = await resolveTenant(client, form);
    if (!tenant.ok) return refused(base, tenant.error);
    const result = await attempt(() =>
      client.$request(
        'auth/finishPasswordless',
        { tenantId: tenant.value, destination: email, token: code },
        persistence(form),
      ),
    );
    if (!result.ok) return refused(base, result.error, 'code-sent');
    return afterFirstFactor(client, result.value, tenant.value, base);
  };

  const signIn = flow((client, intent, form, base) => {
    if (intent === 'send-code') return sendCode(client, form, base);
    if (intent === 'code') return finishCode(client, form, base);
    return passwordSignIn(client, form, base);
  });

  const reauthenticate = flow(
    async (client, _intent, form, base) => {
      const password = rawField(form, authFields.password);
      if (!password) return refused(base, missing(authFields.password, 'Enter your password'));
      const current = await presentedSession(client);
      if (!current.ok) return refused(base, current.error);
      const outcome = await attempt(() =>
        client.$request('auth/reauthenticate', { password }, persistence(form, '0')),
      );
      if (!outcome.ok) return refused(base, outcome.error);
      if (isSessionResult(outcome.value)) {
        await endReplaced(client, current.value.id, outcome.value);
        return 'signed-in';
      }
      // The challenge names no tenant; it is the current session's.
      return afterFirstFactor(client, outcome.value, current.value.tenantId, base);
    },
    { stepUp: true },
  );

  /**
   * Accepting created the account and spent the invitation, so a lapsed MFA step cannot go back to the invitation's
   * form (resubmitting it can only fail): the person finishes at sign-in, which starts a fresh challenge.
   */
  const invitationLapsed = (base: Base): AuthFormState => ({
    ...base,
    step: 'done',
    next: base.next ? withParam(loginPath, authFields.next, base.next) : loginPath,
    notice: notice(
      'INVITATION_ACCEPTED',
      'Your account is ready, but this verification step has expired. Sign in to continue.',
    ),
  });

  const acceptInvitation = flow(
    async (client, _intent, form, base) => {
      const owner = field(form, authFields.kind) === 'owner';
      const token = field(form, authFields.token);
      const name = field(form, authFields.name);
      const password = rawField(form, authFields.password);
      if (!token)
        return refused(
          base,
          problem(
            'INVITATION_INVALID',
            'This invitation is invalid or has expired',
            authFields.token,
          ),
        );
      if (owner && !name) return refused(base, missing(authFields.name, 'Enter your name'));
      if (!password) return refused(base, missing(authFields.password, 'Choose a password'));
      const different = mismatch(form, password);
      if (different) return refused(base, different);
      const tenant = await resolveTenant(client, form);
      if (!tenant.ok) return refused(base, tenant.error);
      const accepted = await attempt(() =>
        client.$request(
          owner ? 'tenants/acceptInvitation' : 'identities/acceptInvitation',
          { tenantId: tenant.value, token, password, ...(name ? { name } : {}) },
          persistence(form),
        ),
      );
      if (!accepted.ok) return refused(base, accepted.error);
      return afterFirstFactor(client, accepted.value, tenant.value, base, invitationLapsed);
    },
    { lapsed: invitationLapsed },
  );

  const signOut = async (_form?: FormData): Promise<never> => {
    try {
      await host.client().$request('auth/signOut');
    } catch (error) {
      if (isControlFlow(error) || !isSessionRefusal(error)) throw error;
      // The server clears the cookie only when sign-out succeeds; a session it refuses would keep failing every page.
      await host.clearSessionCookie?.();
    }
    return redirect(options.afterSignOut ?? '/login');
  };

  const requestPasswordReset: AuthAction = async (_previous, form) => {
    const client = host.client();
    const base = baseState(form);
    const email = field(form, authFields.email);
    if (!email) return refused(base, missing(authFields.email, 'Enter your email address'));
    const tenant = await resolveTenant(client, form);
    if (!tenant.ok) return refused(base, tenant.error);
    const sent = await attempt(() =>
      client.$request('auth/requestPasswordReset', { tenantId: tenant.value, email }),
    );
    if (!sent.ok) return refused(base, sent.error);
    return {
      ...base,
      step: 'sent',
      notice: notice(
        'PASSWORD_RESET_SENT',
        'If {email} has an account, we sent it a link to reset the password.',
        email,
      ),
    };
  };

  const resetPassword: AuthAction = async (_previous, form) => {
    const client = host.client();
    const base = baseState(form);
    const token = field(form, authFields.token);
    const password = rawField(form, authFields.password);
    if (!token)
      return refused(
        base,
        problem('INVALID_CHALLENGE', 'This link is invalid or has expired', authFields.token),
      );
    if (!password) return refused(base, missing(authFields.password, 'Choose a new password'));
    const different = mismatch(form, password);
    if (different) return refused(base, different);
    const tenant = await resolveTenant(client, form);
    if (!tenant.ok) return refused(base, tenant.error);
    const reset = await attempt(
      () => client.$request('auth/resetPassword', { tenantId: tenant.value, token, password }),
      linkFields,
    );
    if (!reset.ok) return refused(base, reset.error);
    return redirect(withParam(loginPath, 'reset', '1'));
  };

  const signUp: AuthAction = async (_previous, form) => {
    const client = host.client();
    const base = baseState(form);
    const email = field(form, authFields.email);
    const name = field(form, authFields.name);
    const password = rawField(form, authFields.password);
    if (!email) return refused(base, missing(authFields.email, 'Enter your email address'));
    if (!name) return refused(base, missing(authFields.name, 'Enter your name'));
    if (!password) return refused(base, missing(authFields.password, 'Choose a password'));
    const different = mismatch(form, password);
    if (different) return refused(base, different);
    const tenant = await resolveTenant(client, form);
    if (!tenant.ok) return refused(base, tenant.error);
    const created = await attempt(() =>
      client.$request<{ verificationRequired?: boolean }>('auth/signUp', {
        tenantId: tenant.value,
        email,
        name,
        password,
      }),
    );
    if (!created.ok) return refused(base, created.error);
    if (created.value.verificationRequired)
      return {
        ...base,
        step: 'sent',
        notice: notice(
          'VERIFICATION_SENT',
          'We sent a link to {email}. Open it to confirm your address, then sign in.',
          email,
        ),
      };
    return redirect(withParam(loginPath, 'registered', '1'));
  };

  const verifyEmail: AuthAction = async (_previous, form) => {
    const client = host.client();
    const base = baseState(form);
    const token = field(form, authFields.token);
    if (!token)
      return refused(
        base,
        problem('INVALID_CHALLENGE', 'This link is invalid or has expired', authFields.token),
      );
    const tenant = await resolveTenant(client, form);
    if (!tenant.ok) return refused(base, tenant.error);
    const verified = await attempt(
      () => client.$request('auth/verifyEmail', { tenantId: tenant.value, token }),
      linkFields,
    );
    if (!verified.ok) return refused(base, verified.error);
    return redirect(withParam(loginPath, 'verified', '1'));
  };

  return {
    signIn,
    reauthenticate,
    signOut,
    requestPasswordReset,
    resetPassword,
    signUp,
    verifyEmail,
    acceptInvitation,
  };
}
