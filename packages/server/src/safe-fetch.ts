import { lookup as dnsLookup, type LookupAddress, type LookupOptions } from 'node:dns';
import * as http from 'node:http';
import * as https from 'node:https';
import { isIP } from 'node:net';
import { ipCounterKey, ipMatches } from '@better-iam/core';

/**
 * A guarded JSON fetch for URLs that tenants control (OIDC discovery documents and JWKS). It refuses anything that
 * could turn the server into a proxy into its own network (SSRF): non-public resolved addresses, redirects, non-443
 * https ports, credentials in the URL, slow and oversized responses, and non-JSON content.
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
 * their IPv6 counterparts including NAT64, discard-only, Teredo/ORCHID (2001::/23), 6to4, ULA and site-local.
 * IPv4-mapped IPv6 addresses are judged by their IPv4 address.
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

/**
 * Checks the URL rules: https on port 443 without credentials or a fragment (loopback hosts may use http and any port
 * with `allowInsecureLocalhost`), and, for an IP-literal host, a public address. Throws `SafeFetchError` ('url' or
 * 'address') and returns the parsed URL.
 */
export function checkFetchUrl(value: string | URL, options: SafeFetchOptions): URL {
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
  if (!loopback && (url.protocol !== 'https:' || url.port !== ''))
    throw new SafeFetchError('url', 'Only https on port 443 is allowed');
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
function guardedLookup(options: SafeFetchOptions, loopbackHost: boolean) {
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
