import { getIam } from '@/lib/iam';
import {
  cookieNames,
  cookiePolicy,
  cookieValue,
  readCookies,
  setCookie,
  writesSessionCookie,
} from '@/lib/view-as';

export const runtime = 'nodejs';
export const dynamic = 'force-dynamic';

/**
 * Every browser call goes through Better IAM's own handler: CSRF checks, cookies, authorization, and audit records.
 * During "view as" the administrator's own token is parked in a cookie beside the member session. Once the browser's
 * session is signed out or replaced, that parked session is ended on the server and its cookie cleared: otherwise
 * the next person at this browser could restore the administrator's session through the view-as stop endpoint.
 */
async function handle(request: Request): Promise<Response> {
  const iam = await getIam();
  const policy = cookiePolicy(iam.endpoint);
  const names = cookieNames(policy);
  const jar = readCookies(request.headers.get('cookie'));
  const signingOut =
    request.method === 'POST' &&
    new URL(request.url).pathname === `${iam.endpoint.basePath}/auth/signOut`;
  const userAgent = request.headers.get('user-agent') ?? undefined;
  const response = await iam.handler(request);
  if (!jar.has(names.parked)) return response;
  // A 401 sign-out has passed the handler's CSRF checks and found the member session already over.
  const ended =
    writesSessionCookie(response, names.session) || (signingOut && response.status === 401);
  if (!ended) return response;
  const parked = cookieValue(jar, names.parked);
  if (parked)
    await iam.auth
      .withClient({ userAgent }, () => iam.api.auth.signOut({ token: parked }))
      .catch(() => undefined);
  const headers = new Headers(response.headers);
  headers.append('set-cookie', setCookie(names.parked, '', policy, 0));
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

// GET serves the operational endpoints (/health, and /metrics when METRICS_TOKEN is set).
export { handle as POST, handle as OPTIONS, handle as GET };
// Identity providers call the inbound SCIM mount (/api/iam/scim/v2) with PUT, PATCH, and DELETE.
export { handle as PUT, handle as PATCH, handle as DELETE };
