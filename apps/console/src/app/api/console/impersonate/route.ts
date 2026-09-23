import { ConsoleError, isIamError } from '@/lib/errors';
import { getIam } from '@/lib/iam';
import {
  cookieLifetime,
  cookieNames,
  cookiePolicy,
  cookieValue,
  persistentFor,
  readCookies,
  setCookie,
} from '@/lib/view-as';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * Starts and stops "view as member" for the console. Better IAM issues the impersonation token without touching
 * cookies; this route swaps the browser's session cookie for it and parks the administrator's own cookie beside it
 * so stopping restores the original session. Both cookies take the handler's attributes (name prefix, SameSite) and
 * the persistence the administrator chose at sign-in: an unticked "Keep me signed in" keeps them browser-session
 * cookies, so neither the member session nor the parked token survives closing the browser.
 */

function guard(request: Request): void {
  const origin = request.headers.get('origin');
  if (
    request.headers.get('x-better-iam') !== '1' ||
    !origin ||
    origin !== new URL(request.url).origin
  )
    throw new ConsoleError('CSRF_REJECTED', 'Same-origin JSON requests require X-Better-IAM', 403);
}

function respond(body: unknown, status = 200, setCookies: string[] = []): Response {
  const headers = new Headers({ 'cache-control': 'no-store' });
  for (const value of setCookies) headers.append('set-cookie', value);
  return Response.json(body, { status, headers });
}

function failure(error: unknown, fallback: string): Response {
  const known = isIamError(error);
  return respond(
    {
      error: {
        code: known ? error.code : 'INTERNAL_ERROR',
        message: known ? error.message : fallback,
      },
    },
    known ? error.status : 500,
  );
}

export async function POST(request: Request): Promise<Response> {
  try {
    guard(request);
    const iam = await getIam();
    const policy = cookiePolicy(iam.endpoint);
    const { session, parked } = cookieNames(policy);
    const jar = readCookies(request.headers.get('cookie'));
    const own = cookieValue(jar, session);
    if (!own) throw new ConsoleError('UNAUTHENTICATED', 'Sign in first', 401);
    if (jar.has(parked))
      throw new ConsoleError('CONFLICT', 'Stop the current impersonation first', 409);
    const body = (await request.json()) as {
      tenantId?: unknown;
      identityId?: unknown;
      reason?: unknown;
    };
    if (
      typeof body.tenantId !== 'string' ||
      typeof body.identityId !== 'string' ||
      typeof body.reason !== 'string'
    )
      throw new ConsoleError('INVALID_INPUT', 'tenantId, identityId, and reason are required');
    const result = await iam.auth.withClient(
      { userAgent: request.headers.get('user-agent') ?? undefined, label: 'console (view as)' },
      () =>
        iam.api.identities.impersonate(
          { headers: request.headers },
          {
            tenantId: body.tenantId as string,
            identityId: body.identityId as string,
            reason: body.reason as string,
          },
        ),
    );
    // Both cookies end with the view-as session when persistent, and with the browser otherwise.
    const maxAge = cookieLifetime(
      result.session.expiresAt,
      Date.now(),
      persistentFor(request.headers, jar, policy),
    );
    return respond(
      { data: { identity: result.identity, expiresAt: result.session.expiresAt } },
      200,
      [setCookie(parked, own, policy, maxAge), setCookie(session, result.token, policy, maxAge)],
    );
  } catch (error) {
    return failure(error, 'Impersonation failed');
  }
}

export async function DELETE(request: Request): Promise<Response> {
  try {
    guard(request);
    const iam = await getIam();
    const policy = cookiePolicy(iam.endpoint);
    const { session, parked } = cookieNames(policy);
    const jar = readCookies(request.headers.get('cookie'));
    if (!jar.has(parked)) throw new ConsoleError('NOT_FOUND', 'No impersonation in progress', 404);
    // End the member session first; a token the administrator no longer holds must not stay valid.
    await iam.api.auth.signOut({ headers: request.headers }).catch(() => undefined);
    const token = cookieValue(jar, parked);
    // The administrator's own session may have ended meanwhile; clearing both cookies then sends them to sign in.
    const own = token
      ? await iam.api.auth.getSession({ token }).then(
          (restored) => ({ token, expiresAt: restored.session.expiresAt }),
          () => undefined,
        )
      : undefined;
    const persistent = persistentFor(request.headers, jar, policy);
    return respond({ data: { restored: own !== undefined } }, 200, [
      setCookie(parked, '', policy, 0),
      own
        ? setCookie(
            session,
            own.token,
            policy,
            cookieLifetime(own.expiresAt, Date.now(), persistent),
          )
        : setCookie(session, '', policy, 0),
    ]);
  } catch (error) {
    return failure(error, 'Could not stop impersonation');
  }
}
