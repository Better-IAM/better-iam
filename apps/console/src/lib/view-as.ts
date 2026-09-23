/**
 * Cookies for the console's "view as member". The impersonation route swaps the browser's session cookie for the
 * member's and parks the administrator's own token beside it; the /api/iam route ends that parked session whenever
 * the browser's session is replaced or signed out. Both write cookies the way Better IAM's handler does: `__Host-`
 * names on HTTPS, the deployment's SameSite, and a browser-session cookie (no Max-Age) when the person did not ask to
 * stay signed in.
 */
export const SESSION_COOKIE = 'better-iam.session';
export const PARKED_COOKIE = 'better-iam.impersonator';
/** Set to `0` by the login page when "Keep me signed in" is unticked; absent means the person chose to stay. */
export const REMEMBER_COOKIE = 'better-iam.remember';

export interface CookiePolicy {
  secure: boolean;
  sameSite: 'Lax' | 'Strict';
  /** The deployment default when neither the request nor the remember cookie decides. */
  persistentByDefault: boolean;
}

/** The handler's cookie settings, from the IAM instance's `endpoint`. */
export function cookiePolicy(endpoint: {
  secure: boolean;
  cookieSameSite?: unknown;
  persistentCookies?: unknown;
}): CookiePolicy {
  return {
    secure: endpoint.secure,
    sameSite: endpoint.cookieSameSite === 'strict' ? 'Strict' : 'Lax',
    persistentByDefault: endpoint.persistentCookies !== false,
  };
}

export function cookieNames(policy: CookiePolicy): { session: string; parked: string } {
  const prefix = policy.secure ? '__Host-' : '';
  return { session: `${prefix}${SESSION_COOKIE}`, parked: `${prefix}${PARKED_COOKIE}` };
}

export function readCookies(header: string | null): Map<string, string> {
  const jar = new Map<string, string>();
  for (const part of header?.split(';') ?? []) {
    const index = part.indexOf('=');
    if (index > 0) jar.set(part.slice(0, index).trim(), part.slice(index + 1).trim());
  }
  return jar;
}

/** A cookie value as the browser sent it; a malformed escape yields nothing rather than an error. */
export function cookieValue(jar: Map<string, string>, name: string): string | undefined {
  const raw = jar.get(name);
  if (!raw) return undefined;
  try {
    return decodeURIComponent(raw);
  } catch {
    return undefined;
  }
}

/**
 * Whether the session cookie should outlive the browser: the server's `X-Better-IAM-Persistent` rule first, then the
 * login page's remember cookie, then the deployment default. A person who unticked "Keep me signed in" keeps a
 * browser-session cookie through view-as start and stop.
 */
export function persistentFor(
  headers: Headers,
  jar: Map<string, string>,
  policy: CookiePolicy,
): boolean {
  const header = headers.get('x-better-iam-persistent');
  if (header === '1') return true;
  if (header === '0') return false;
  if (jar.get(REMEMBER_COOKIE) === '0') return false;
  return policy.persistentByDefault;
}

/** Seconds until `expiresAt` for a persistent cookie; `undefined` (a browser-session cookie) otherwise. */
export function cookieLifetime(
  expiresAt: number,
  now: number,
  persistent: boolean,
): number | undefined {
  return persistent ? Math.max(0, Math.floor((expiresAt - now) / 1000)) : undefined;
}

/** `maxAge` undefined writes a browser-session cookie; `0` deletes the cookie. */
export function setCookie(
  name: string,
  value: string,
  policy: CookiePolicy,
  maxAge: number | undefined,
): string {
  return `${name}=${encodeURIComponent(value)}; HttpOnly; ${policy.secure ? 'Secure; ' : ''}SameSite=${policy.sameSite}; Path=/${maxAge === undefined ? '' : `; Max-Age=${maxAge}`}`;
}

/** Whether a response writes the session cookie: a new session was issued, or a sign-out cleared it. */
export function writesSessionCookie(response: Response, sessionName: string): boolean {
  return response.headers.getSetCookie().some((line) => line.startsWith(`${sessionName}=`));
}
