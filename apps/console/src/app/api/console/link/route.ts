import { ConsoleError, isIamError } from '@/lib/errors';
import { getIam, requestClient } from '@/lib/iam';
import { resolveTenant } from '@/lib/session';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * Links the caller's identity with an identity in another organization. The target credentials are verified
 * through the same sign-in service the console uses, the resulting session is consumed only for the link, and it is revoked afterwards.
 */
export async function POST(request: Request): Promise<Response> {
  const iam = await getIam();
  const respond = (body: unknown, status = 200) =>
    Response.json(body, { status, headers: { 'cache-control': 'no-store' } });
  try {
    const origin = request.headers.get('origin');
    if (
      request.headers.get('x-better-iam') !== '1' ||
      !origin ||
      origin !== new URL(request.url).origin
    )
      throw new ConsoleError(
        'CSRF_REJECTED',
        'Same-origin JSON requests require X-Better-IAM',
        403,
      );
    const body = (await request.json()) as {
      org?: unknown;
      email?: unknown;
      password?: unknown;
      code?: unknown;
    };
    if (
      typeof body.org !== 'string' ||
      typeof body.email !== 'string' ||
      typeof body.password !== 'string'
    )
      throw new ConsoleError('INVALID_INPUT', 'org, email, and password are required');
    // Only a signed-in person may try another account's credentials here: without this the route would be a
    // password oracle for every organization.
    await iam.api.auth.getSession({ headers: request.headers });
    const tenant = await resolveTenant(body.org);
    // Platform administrator accounts are never linked (and never signed in from the cloud console).
    if (!tenant || tenant.status !== 'active' || tenant.parentId === null)
      throw new ConsoleError('NOT_FOUND', 'Organization not found', 404);
    const org = tenant;
    const email = body.email;
    const password = body.password;
    const code = body.code;
    // The target account's sign-in is judged by the caller's network like any other sign-in (allowlists, blocks,
    // per-address limits), and recorded with the caller's address.
    const token = await iam.auth.withClient(
      { ...(await requestClient(request)), label: 'console (account link)' },
      async () => {
        const outcome = await iam.api.auth.signIn({ tenantId: org.id, email, password });
        if (!('mfaRequired' in outcome)) return outcome.token;
        if (typeof code !== 'string' || !code)
          throw new ConsoleError('MFA_REQUIRED', 'That account requires an authenticator code', 403);
        return (
          await iam.api.auth.verifyMfa({ tenantId: org.id, challenge: outcome.challenge, code })
        ).token;
      },
    );
    try {
      const link = await iam.api.links.create(
        { headers: request.headers },
        { targetCredential: { token } },
      );
      return respond({ data: { linkId: link.id, tenantName: tenant.name } });
    } finally {
      await iam.api.auth.signOut({ token }).catch(() => undefined);
    }
  } catch (error) {
    const known = isIamError(error);
    return respond(
      {
        error: {
          code: known ? error.code : 'INTERNAL_ERROR',
          message: known ? error.message : 'Linking failed',
        },
      },
      known ? error.status : 500,
    );
  }
}
