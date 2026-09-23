// No 'use client': server components import REMEMBER_COOKIE to render the checkbox's initial state.

/**
 * The "Keep me signed in on this browser" choice. The sign-in page asks once, for every method, and keeps the
 * answer in a browser-session cookie (`better-iam.remember=0` when unticked, `1` when ticked; absent means ticked)
 * that every client component can read. Each later call that issues or re-issues a session (MFA steps, passkeys,
 * emailed links and codes, re-authentication) then asks the server for the same kind of session cookie.
 */
export const REMEMBER_COOKIE = 'better-iam.remember';
/** The request header the IAM handler reads to decide between a lasting and a browser-session cookie. */
export const PERSISTENT_HEADER = 'x-better-iam-persistent';

/**
 * Reads the choice from the cookie's value (server components: `cookies().get(REMEMBER_COOKIE)?.value`). Without a
 * recorded choice the `fallback` applies: the deployment's `http.persistentCookies` on the sign-in pages, `true`
 * elsewhere.
 */
export function rememberFromValue(value: string | null | undefined, fallback = true): boolean {
  if (value === '0') return false;
  if (value === '1') return true;
  return fallback;
}

/**
 * The box's initial state on a sign-in page: the choice recorded in this browser, else the deployment default
 * (`iam.endpoint.persistentCookies`), so an operator's `persistentCookies: false` is what people see unticked.
 */
export function initialRemember(
  value: string | null | undefined,
  endpoint: { persistentCookies?: unknown } | undefined,
): boolean {
  return rememberFromValue(value, endpoint?.persistentCookies !== false);
}

/** The recorded choice in a `Cookie` header or `document.cookie`, or `undefined` when none was made. */
export function recordedRemember(cookies: string | null | undefined): boolean | undefined {
  for (const part of (cookies ?? '').split(';')) {
    const separator = part.indexOf('=');
    if (separator < 0 || part.slice(0, separator).trim() !== REMEMBER_COOKIE) continue;
    const value = part.slice(separator + 1).trim();
    if (value === '0' || value === '1') return value === '1';
  }
  return undefined;
}

/** Reads the choice from a `Cookie` header or `document.cookie`; anything but an explicit `0` means "keep". */
export function rememberFromCookies(cookies: string | null | undefined): boolean {
  return recordedRemember(cookies) ?? true;
}

/** The `document.cookie` assignment that records the choice. */
export function rememberCookie(value: boolean, secure: boolean): string {
  // Readable by scripts on purpose (not HttpOnly): it records a preference, never a credential. It has no Max-Age,
  // so the choice ends with the browser session, like the browser-session cookie an unticked box asks for.
  return `${REMEMBER_COOKIE}=${value ? '1' : '0'}; Path=/; SameSite=Lax${secure ? '; Secure' : ''}`;
}

function documentCookies(): string | undefined {
  if (typeof document === 'undefined') return undefined;
  try {
    return document.cookie;
  } catch {
    return undefined;
  }
}

/** Whether new sessions on this browser should outlive it; `true` when nothing was chosen or outside a browser. */
export function rememberBrowser(): boolean {
  return rememberFromCookies(documentCookies());
}

/** The choice recorded in this browser, or `undefined` when none was made (or outside a browser). */
export function recordedRememberBrowser(): boolean | undefined {
  return recordedRemember(documentCookies());
}

/** Records the choice for this browser session. */
export function setRememberBrowser(value: boolean): void {
  if (typeof document === 'undefined') return;
  try {
    document.cookie = rememberCookie(value, window.location.protocol === 'https:');
  } catch {
    /* Cookies are blocked (a sandboxed frame): calls fall back to the explicit `persistent` argument. */
  }
}

/**
 * Call options for a request that issues or re-issues a session. The header is always explicit, `1` or `0`, so the
 * person's choice holds whatever the deployment's `http.persistentCookies` default is. Without an argument the
 * choice remembered for this browser applies.
 */
export function sessionOptions(persistent?: boolean): { headers: Record<string, string> } {
  return { headers: { [PERSISTENT_HEADER]: (persistent ?? rememberBrowser()) ? '1' : '0' } };
}
