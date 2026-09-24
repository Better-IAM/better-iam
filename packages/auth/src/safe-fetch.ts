import { lookup as dnsLookup, type LookupAddress, type LookupOptions } from 'node:dns';
import * as http from 'node:http';
import * as https from 'node:https';
import { isIP } from 'node:net';
import { ipCounterKey, ipMatches } from '@better-iam/core';

/**
 * Guarded outbound HTTP for URLs that tenants control (OIDC discovery documents and JWKS, webhook endpoints, SCIM
 * targets, Shared Signals receivers, AI provider base URLs). It refuses anything that could turn the server into a
 * proxy into its own network (SSRF): non-public resolved addresses (checked at connect time, so DNS rebinding cannot
 * swap in a private address after validation), redirects, plain http, non-443 https ports unless allowed, and
 * credentials in the URL.
 */
export interface SafeFetchOptions {
  /** Deadline for the whole request, in milliseconds. */
  timeoutMs: number;
  /** Largest accepted response body, in bytes. */
  maxBytes: number;
  /** Lets requests reach private and reserved addresses. Development and tests only. */
  allowPrivateNetworks?: boolean;
  /** Allows `http://` and any port on loopback hosts (localhost, 127.0.0.1, [::1]). Development and tests only. */
  allowInsecureLocalhost?: boolean;
}

export type SafeFetchFailureReason =
  | 'url'
  | 'address'
  | 'timeout'
  | 'status'
  | 'size'
  | 'content-type'
  | 'redirect'
  | 'json'
  | 'network';

/** A refused or failed guarded fetch; `reason` says which rule stopped it. */
export class SafeFetchError extends Error {
  constructor(
    readonly reason: SafeFetchFailureReason,
    message = `Fetch refused: ${reason}`,
  ) {
    super(message);
    this.name = 'SafeFetchError';
  }
}

/**
 * Networks that are never reachable through a guarded fetch: this-network, RFC 1918, CGNAT, loopback, link-local,
 * IETF protocol assignments, documentation and benchmarking ranges, 6to4 relay, multicast and reserved space, and
 * their IPv6 counterparts including IPv4-translated (::ffff:0:0:0/96), NAT64, discard-only, Teredo/ORCHID (2001::/23),
 * 6to4, ULA and site-local. IPv4-mapped IPv6 addresses are judged by their IPv4 address.
 */
const nonPublicNetworks = [
  '0.0.0.0/8',
  '10.0.0.0/8',
  '100.64.0.0/10',
  '127.0.0.0/8',
  '169.254.0.0/16',
  '172.16.0.0/12',
  '192.0.0.0/24',
  '192.0.2.0/24',
  '192.88.99.0/24',
  '192.168.0.0/16',
  '198.18.0.0/15',
  '198.51.100.0/24',
  '203.0.113.0/24',
  '224.0.0.0/4',
  '240.0.0.0/4',
  '::/128',
  '::1/128',
  // Deprecated IPv4-compatible addresses (::a.b.c.d), which some stacks still route to the embedded IPv4 address.
  '::/96',
  // IPv4-translated addresses (RFC 2765 ::ffff:0:a.b.c.d, the prefix 0:0:0:0:ffff:0::/96). Not `::ffff:0:0/96`: that
  // is the IPv4-mapped prefix, which stands for every IPv4 address.
  '::ffff:0:0:0/96',
  '64:ff9b::/96',
  // Local-use NAT64 (RFC 8215), which translators map to arbitrary, often private, IPv4 space.
  '64:ff9b:1::/48',
  '100::/64',
  '2001::/23',
  '2001:db8::/32',
  '2002::/16',
  'fc00::/7',
  'fe80::/10',
  'fec0::/10',
  'ff00::/8',
];
const loopbackHosts = new Set(['localhost', '127.0.0.1', '[::1]', '::1']);

/** True for a globally routable unicast address; false for private, reserved and malformed values. */
export function isPublicAddress(address: string): boolean {
  if (typeof address !== 'string' || ipCounterKey(address) === undefined) return false;
  const trimmed = address.trim();
  return !nonPublicNetworks.some((network) => ipMatches(trimmed, network));
}

function isLoopbackAddress(address: string): boolean {
  return ipMatches(address, '127.0.0.0/8') || ipMatches(address, '::1/128');
}

function hostOf(url: URL): string {
  return url.hostname.startsWith('[') ? url.hostname.slice(1, -1) : url.hostname;
}

/** The address rules of a guarded request, without the body limits of `fetchJsonSafely`. */
export type SafeFetchAddressOptions = Pick<
  SafeFetchOptions,
  'allowPrivateNetworks' | 'allowInsecureLocalhost'
> & {
  /** Also allows https on ports other than 443 (the address rules still apply). */
  anyPort?: boolean;
};

/**
 * Checks the URL rules: https on port 443 (any port with `anyPort`) without credentials or a fragment (loopback hosts
 * may use http and any port with `allowInsecureLocalhost`), and, for an IP-literal host, a public address. Throws
 * `SafeFetchError` ('url' or 'address') and returns the parsed URL.
 */
export function checkFetchUrl(
  value: string | URL,
  options: SafeFetchAddressOptions & Partial<SafeFetchOptions>,
): URL {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new SafeFetchError('url', 'Not an absolute URL');
  }
  const raw = String(value);
  if (url.username || url.password || url.hash || raw.includes('#'))
    throw new SafeFetchError('url', 'Credentials and fragments are not allowed');
  const loopback = loopbackHosts.has(url.hostname) && options.allowInsecureLocalhost === true;
  if (!loopback && (url.protocol !== 'https:' || (url.port !== '' && options.anyPort !== true)))
    throw new SafeFetchError(
      'url',
      options.anyPort ? 'Only https is allowed' : 'Only https on port 443 is allowed',
    );
  if (loopback && url.protocol !== 'https:' && url.protocol !== 'http:')
    throw new SafeFetchError('url', 'Only http and https are allowed');
  const host = hostOf(url);
  if (isIP(host) && !loopback && !options.allowPrivateNetworks && !isPublicAddress(host))
    throw new SafeFetchError('address', 'The address is not public');
  return url;
}

type LookupCallback = (
  error: NodeJS.ErrnoException | null,
  address: string | LookupAddress[],
  family?: number,
) => void;

/** A DNS lookup that refuses a host when any resolved address is not public (unless the options allow it). */
function guardedLookup(options: SafeFetchAddressOptions, loopbackHost: boolean) {
  return (hostname: string, lookupOptions: LookupOptions, callback: LookupCallback): void => {
    dnsLookup(hostname, { ...lookupOptions, all: true }, (error, addresses) => {
      if (error) return callback(error, '');
      const list = addresses as LookupAddress[];
      const allowed = (entry: LookupAddress) =>
        options.allowPrivateNetworks === true ||
        isPublicAddress(entry.address) ||
        (loopbackHost &&
          options.allowInsecureLocalhost === true &&
          isLoopbackAddress(entry.address));
      if (!list.length || !list.every(allowed))
        return callback(
          new SafeFetchError('address', 'The host resolves to a non-public address'),
          '',
        );
      if (lookupOptions.all) return callback(null, list);
      callback(null, list[0]!.address, list[0]!.family);
    });
  };
}

/**
 * GETs a JSON document under the SSRF rules above. Any status other than 200 fails ('redirect' for 3xx, else
 * 'status'), as do a content type without "json", a body over `maxBytes`, the deadline, and unparseable JSON.
 */
export function fetchJsonSafely(value: string | URL, options: SafeFetchOptions): Promise<unknown> {
  let url: URL;
  try {
    url = checkFetchUrl(value, options);
  } catch (error) {
    return Promise.reject(error);
  }
  const loopbackHost = loopbackHosts.has(url.hostname);
  const transport = url.protocol === 'http:' ? http : https;
  return new Promise<unknown>((resolve, reject) => {
    let settled = false;
    let timer: ReturnType<typeof setTimeout> | undefined;
    const finish = (error: unknown, result?: unknown) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) reject(error instanceof SafeFetchError ? error : new SafeFetchError('network'));
      else resolve(result);
    };
    const request = transport.request(
      url,
      {
        method: 'GET',
        headers: { accept: 'application/json', 'user-agent': 'better-iam' },
        lookup: guardedLookup(options, loopbackHost) as never,
        agent: false,
      },
      (response) => {
        const status = response.statusCode ?? 0;
        const fail = (error: SafeFetchError) => {
          finish(error);
          response.destroy();
          request.destroy();
        };
        if (status >= 300 && status < 400) return fail(new SafeFetchError('redirect'));
        if (status !== 200)
          return fail(new SafeFetchError('status', `Unexpected status ${status}`));
        if (
          !String(response.headers['content-type'] ?? '')
            .toLowerCase()
            .includes('json')
        )
          return fail(new SafeFetchError('content-type'));
        const declared = Number(response.headers['content-length']);
        if (Number.isFinite(declared) && declared > options.maxBytes)
          return fail(new SafeFetchError('size'));
        const chunks: Buffer[] = [];
        let size = 0;
        response.on('data', (chunk: Buffer) => {
          size += chunk.length;
          if (size > options.maxBytes) return fail(new SafeFetchError('size'));
          chunks.push(chunk);
        });
        response.on('error', (error) => finish(error));
        response.on('end', () => {
          if (settled) return;
          try {
            finish(null, JSON.parse(Buffer.concat(chunks).toString('utf8')));
          } catch {
            finish(new SafeFetchError('json'));
          }
        });
      },
    );
    timer = setTimeout(() => {
      finish(new SafeFetchError('timeout'));
      request.destroy();
    }, options.timeoutMs);
    request.on('error', (error) => finish(error));
    request.end();
  });
}

/** What `createGuardedFetch` enforces besides the address rules. */
export interface GuardedFetchOptions extends SafeFetchAddressOptions {
  /** Largest response body a caller may read, in bytes; reading past it fails (default: unlimited). */
  maxBytes?: number;
}

const nullBodyStatuses = new Set([101, 204, 205, 304]);

/**
 * The response body as a web stream, failing once more than `limit` bytes arrive. Written by hand rather than with
 * `Readable.toWeb`: cancelling a `toWeb` stream over a piped size-counting Transform made Node push into the closed
 * controller and raise an uncaught ERR_INVALID_STATE, so any endpoint answering with a body could crash a caller
 * that cancels bodies (the SSF transmitter does after every delivery). Every event here is ignored once the stream
 * has settled, and cancelling destroys the socket.
 */
function webBody(
  source: http.IncomingMessage,
  limit: number | undefined,
): ReadableStream<Uint8Array> {
  let size = 0;
  let settled = false;
  return new ReadableStream<Uint8Array>({
    start(controller) {
      const finish = (error?: unknown) => {
        if (settled) return;
        settled = true;
        if (error === undefined) controller.close();
        else controller.error(error);
      };
      source.on('data', (chunk: Buffer) => {
        if (settled) return;
        size += chunk.length;
        if (limit !== undefined && size > limit) {
          finish(new SafeFetchError('size'));
          source.destroy();
          return;
        }
        controller.enqueue(new Uint8Array(chunk.buffer, chunk.byteOffset, chunk.byteLength));
        if ((controller.desiredSize ?? 0) <= 0) source.pause();
      });
      source.on('end', () => finish());
      source.on('error', (error) => finish(error));
      source.on('close', () => finish(new TypeError('terminated')));
    },
    pull() {
      source.resume();
    },
    cancel() {
      settled = true;
      source.destroy();
    },
  });
}

/**
 * A `fetch` under the SSRF rules: the URL rules of `checkFetchUrl`, and a connect-time DNS check that refuses hosts
 * resolving to non-public addresses. Redirects are never followed: with `redirect: 'error'` a 3xx rejects as `fetch`
 * would, otherwise it is returned as is. Failures reject like `fetch` (a `TypeError` whose `cause` is the
 * `SafeFetchError` or network error, or the signal's reason once `signal` aborts). The response body streams, bounded by
 * `maxBytes` when set.
 */
export function createGuardedFetch(options: GuardedFetchOptions = {}): typeof fetch {
  const guarded = async (input: string | URL | Request, init?: RequestInit): Promise<Response> => {
    const request = new Request(input, init);
    const signal = request.signal;
    signal.throwIfAborted();
    let url: URL;
    try {
      url = checkFetchUrl(request.url, options);
    } catch (error) {
      throw new TypeError('fetch failed', { cause: error });
    }
    const body = request.body ? Buffer.from(await request.arrayBuffer()) : undefined;
    const headers: Record<string, string> = {};
    request.headers.forEach((value, name) => {
      headers[name] = value;
    });
    if (body) headers['content-length'] = String(body.length);
    const transport = url.protocol === 'http:' ? http : https;
    return new Promise<Response>((resolve, reject) => {
      let settled = false;
      let incoming: http.IncomingMessage | undefined;
      const onAbort = () => {
        outgoing.destroy();
        incoming?.destroy(signal.reason);
        if (!settled) {
          settled = true;
          reject(signal.reason);
        }
      };
      const fail = (error: unknown) => {
        if (settled) return;
        settled = true;
        signal.removeEventListener('abort', onAbort);
        reject(new TypeError('fetch failed', { cause: error }));
      };
      const outgoing = transport.request(
        url,
        {
          method: request.method,
          headers,
          lookup: guardedLookup(options, loopbackHosts.has(url.hostname)) as never,
          agent: false,
        },
        (response) => {
          incoming = response;
          const status = response.statusCode ?? 0;
          if (status >= 300 && status < 400 && request.redirect === 'error') {
            response.destroy();
            return fail(new SafeFetchError('redirect'));
          }
          const declared = Number(response.headers['content-length']);
          if (
            options.maxBytes !== undefined &&
            Number.isFinite(declared) &&
            declared > options.maxBytes
          ) {
            response.destroy();
            return fail(new SafeFetchError('size'));
          }
          const responseHeaders = new Headers();
          for (const [name, value] of Object.entries(response.headers)) {
            if (value === undefined) continue;
            if (Array.isArray(value)) for (const item of value) responseHeaders.append(name, item);
            else responseHeaders.set(name, value);
          }
          response.on('close', () => signal.removeEventListener('abort', onAbort));
          const empty = request.method === 'HEAD' || nullBodyStatuses.has(status);
          if (empty) {
            // Nothing reads a bodiless response; a late socket error must not go unhandled.
            response.on('error', () => undefined);
            response.resume();
          }
          let result: Response;
          try {
            result = new Response(empty ? null : webBody(response, options.maxBytes), {
              status,
              statusText: response.statusMessage ?? '',
              headers: responseHeaders,
            });
          } catch (error) {
            response.destroy();
            return fail(error);
          }
          Object.defineProperty(result, 'url', { value: url.href });
          settled = true;
          resolve(result);
        },
      );
      signal.addEventListener('abort', onAbort, { once: true });
      outgoing.on('error', fail);
      outgoing.end(body);
    });
  };
  return guarded as typeof fetch;
}
