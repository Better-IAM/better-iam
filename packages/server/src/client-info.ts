import type { SessionClientInfo } from '@better-iam/core';
import type { BetterIamOptions } from './options.js';

/**
 * The client details Better IAM records for a request: `http.clientInfo(request)` when the deployment supplies it
 * (IP behind a trusted proxy, user agent, label), otherwise the User-Agent header only. Nothing here is trusted for
 * authorization; the result feeds `auth.withClient`.
 */
export function clientFromRequest(
  options: Pick<BetterIamOptions, 'http'>,
  request: Request,
): SessionClientInfo | undefined {
  if (options.http?.clientInfo) return options.http.clientInfo(request) ?? undefined;
  const userAgent = request.headers.get('user-agent');
  return userAgent ? { userAgent } : undefined;
}

/**
 * The same, for callers that only have the incoming request's headers (framework integrations passing
 * `{ headers }` as the credential). Returns undefined when there are no headers to read.
 */
export function clientFromHeaders(
  options: Pick<BetterIamOptions, 'http'>,
  headers: HeadersInit | undefined,
  baseURL: URL | string,
): SessionClientInfo | undefined {
  if (!headers) return undefined;
  try {
    return clientFromRequest(options, new Request(baseURL, { headers }));
  } catch {
    return undefined;
  }
}
