import { createServer, type IncomingMessage, type Server, type ServerResponse } from 'node:http';
import type { AddressInfo } from 'node:net';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import {
  checkFetchUrl,
  fetchJsonSafely,
  isPublicAddress,
  SafeFetchError,
  type SafeFetchFailureReason,
  type SafeFetchOptions,
} from '../packages/server/src/safe-fetch.js';

const strict: SafeFetchOptions = { timeoutMs: 1000, maxBytes: 1024 };
const local: SafeFetchOptions = { ...strict, allowInsecureLocalhost: true };

async function reason(promise: Promise<unknown>): Promise<SafeFetchFailureReason> {
  const error = await promise.then(
    () => undefined,
    (caught: unknown) => caught,
  );
  expect(error).toBeInstanceOf(SafeFetchError);
  return (error as SafeFetchError).reason;
}
function syncReason(run: () => unknown): SafeFetchFailureReason {
  try {
    run();
  } catch (error) {
    expect(error).toBeInstanceOf(SafeFetchError);
    return (error as SafeFetchError).reason;
  }
  throw new Error('expected a SafeFetchError');
}

describe('isPublicAddress', () => {
  it.each([
    '8.8.8.8',
    '1.1.1.1',
    '93.184.216.34',
    '100.63.255.255',
    '100.128.0.1',
    '172.32.0.1',
    '2606:4700:4700::1111',
    '2a00:1450:4001:830::200e',
    '::ffff:8.8.8.8',
  ])('treats %s as public', (address) => {
    expect(isPublicAddress(address)).toBe(true);
  });

  it.each([
    ['this network', '0.0.0.0'],
    ['RFC 1918 10/8', '10.0.0.1'],
    ['CGNAT', '100.64.0.1'],
    ['loopback', '127.0.0.1'],
    ['loopback range', '127.255.0.9'],
    ['link-local / cloud metadata', '169.254.169.254'],
    ['RFC 1918 172.16/12', '172.16.5.4'],
    ['RFC 1918 172.31', '172.31.255.255'],
    ['IETF protocol assignments', '192.0.0.8'],
    ['TEST-NET-1', '192.0.2.10'],
    ['6to4 relay anycast', '192.88.99.1'],
    ['RFC 1918 192.168/16', '192.168.1.1'],
    ['benchmarking', '198.18.0.1'],
    ['TEST-NET-2', '198.51.100.7'],
    ['TEST-NET-3', '203.0.113.9'],
    ['multicast', '224.0.0.1'],
    ['reserved', '240.0.0.1'],
    ['broadcast', '255.255.255.255'],
    ['unspecified IPv6', '::'],
    ['loopback IPv6', '::1'],
    ['IPv4-mapped private', '::ffff:10.0.0.1'],
    ['IPv4-mapped loopback', '::ffff:127.0.0.1'],
    ['IPv4-mapped metadata (hex)', '::ffff:a9fe:a9fe'],
    ['NAT64', '64:ff9b::a00:1'],
    ['local-use NAT64', '64:ff9b:1::a00:1'],
    ['IPv4-compatible loopback', '::127.0.0.1'],
    ['IPv4-compatible private (hex)', '::a00:1'],
    ['IPv4-compatible metadata (hex)', '::a9fe:a9fe'],
    ['discard-only', '100::1'],
    ['Teredo', '2001::1'],
    ['ORCHID', '2001:10::1'],
    ['documentation IPv6', '2001:db8::1'],
    ['6to4', '2002:0a00::'],
    ['6to4 public-looking', '2002:808:808::1'],
    ['unique local', 'fd00::1'],
    ['unique local fc', 'fc00::1'],
    ['link-local IPv6', 'fe80::1'],
    ['site-local', 'fec0::1'],
    ['multicast IPv6', 'ff02::1'],
  ])('refuses %s (%s)', (_name, address) => {
    expect(isPublicAddress(address)).toBe(false);
  });

  it.each([
    '',
    'example.com',
    '1.2.3',
    '01.2.3.4',
    '256.1.1.1',
    'fe80::1%eth0',
    '[::1]',
    '1.2.3.4/32',
  ])('refuses the malformed value %j', (address) => {
    expect(isPublicAddress(address)).toBe(false);
  });
});

describe('checkFetchUrl', () => {
  it('accepts https on the default port', () => {
    expect(checkFetchUrl('https://idp.example.com/.well-known/jwks.json', strict).href).toBe(
      'https://idp.example.com/.well-known/jwks.json',
    );
    expect(checkFetchUrl(new URL('https://idp.example.com:443/keys?x=1'), strict).port).toBe('');
    expect(checkFetchUrl('https://8.8.8.8/keys', strict).hostname).toBe('8.8.8.8');
  });

  it.each([
    ['plain http', 'http://idp.example.com/jwks', 'url'],
    ['another https port', 'https://idp.example.com:8443/jwks', 'url'],
    ['userinfo', 'https://user:secret@idp.example.com/jwks', 'url'],
    ['a fragment', 'https://idp.example.com/jwks#keys', 'url'],
    ['an empty fragment', 'https://idp.example.com/jwks#', 'url'],
    ['a relative URL', '/jwks', 'url'],
    ['another scheme', 'file:///etc/passwd', 'url'],
    ['http localhost without the dev option', 'http://localhost:8080/jwks', 'url'],
    ['a private IP literal', 'https://10.0.0.1/jwks', 'address'],
    ['a metadata IP literal', 'https://169.254.169.254/latest/meta-data', 'address'],
    ['an IPv6 loopback literal', 'https://[::1]/jwks', 'address'],
    ['a mapped private literal', 'https://[::ffff:10.0.0.1]/jwks', 'address'],
    ['a ULA literal', 'https://[fd00::1]/jwks', 'address'],
  ] as const)('refuses %s', (_name, url, expected) => {
    expect(syncReason(() => checkFetchUrl(url, strict))).toBe(expected);
  });

  it('lets private literals through only with allowPrivateNetworks', () => {
    expect(
      checkFetchUrl('https://10.0.0.1/jwks', { ...strict, allowPrivateNetworks: true }).hostname,
    ).toBe('10.0.0.1');
    expect(
      syncReason(() =>
        checkFetchUrl('http://10.0.0.1/jwks', { ...strict, allowPrivateNetworks: true }),
      ),
    ).toBe('url');
  });

  it('allows http and any port on loopback hosts with allowInsecureLocalhost', () => {
    for (const url of [
      'http://127.0.0.1:9000/jwks',
      'http://localhost:9000/jwks',
      'http://[::1]:9000/',
    ])
      expect(checkFetchUrl(url, local).protocol).toBe('http:');
    expect(syncReason(() => checkFetchUrl('http://10.0.0.1:9000/', local))).toBe('url');
    expect(syncReason(() => checkFetchUrl('ftp://127.0.0.1/', local))).toBe('url');
  });
});

describe('fetchJsonSafely', () => {
  let server: Server;
  let base = '';
  const routes: Record<string, (request: IncomingMessage, response: ServerResponse) => void> = {
    '/ok': (_request, response) => {
      response.writeHead(200, { 'content-type': 'application/json; charset=utf-8' });
      response.end(JSON.stringify({ keys: [{ kid: 'a' }] }));
    },
    '/jwk-set': (_request, response) => {
      response.writeHead(200, { 'content-type': 'application/jwk-set+json' });
      response.end('{"keys":[]}');
    },
    '/redirect': (_request, response) => {
      response.writeHead(302, { location: 'http://169.254.169.254/' });
      response.end();
    },
    '/missing': (_request, response) => {
      response.writeHead(404, { 'content-type': 'application/json' });
      response.end('{}');
    },
    '/error': (_request, response) => {
      response.writeHead(500, { 'content-type': 'application/json' });
      response.end('{}');
    },
    '/created': (_request, response) => {
      response.writeHead(201, { 'content-type': 'application/json' });
      response.end('{}');
    },
    '/html': (_request, response) => {
      response.writeHead(200, { 'content-type': 'text/html' });
      response.end('<html></html>');
    },
    '/no-type': (_request, response) => {
      response.writeHead(200);
      response.end('{}');
    },
    '/large-declared': (_request, response) => {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(JSON.stringify({ padding: 'x'.repeat(4096) }));
    },
    '/large-chunked': (_request, response) => {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.write('{"padding":"');
      const timer = setInterval(() => {
        if (response.destroyed) return clearInterval(timer);
        response.write('x'.repeat(512));
      }, 5);
      response.on('close', () => clearInterval(timer));
    },
    '/slow': (_request, response) => {
      const timer = setTimeout(() => {
        response.writeHead(200, { 'content-type': 'application/json' });
        response.end('{}');
      }, 2000);
      response.on('close', () => clearTimeout(timer));
    },
    '/bad-json': (_request, response) => {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end('{"keys":');
    },
  };

  beforeAll(async () => {
    server = createServer((request, response) => {
      const route = routes[request.url ?? ''];
      if (route) return route(request, response);
      response.writeHead(404);
      response.end();
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  });

  it('fetches JSON from a loopback server with allowInsecureLocalhost', async () => {
    await expect(fetchJsonSafely(`${base}/ok`, local)).resolves.toEqual({ keys: [{ kid: 'a' }] });
    await expect(fetchJsonSafely(new URL(`${base}/jwk-set`), local)).resolves.toEqual({ keys: [] });
  });

  it('resolves localhost through the guarded lookup', async () => {
    const port = new URL(base).port;
    await expect(fetchJsonSafely(`http://localhost:${port}/ok`, local)).resolves.toEqual({
      keys: [{ kid: 'a' }],
    });
  });

  it('refuses the loopback server without the dev option', async () => {
    expect(await reason(fetchJsonSafely(`${base}/ok`, strict))).toBe('url');
    // https on the default port passes the URL rules, but localhost resolves to a loopback address.
    expect(await reason(fetchJsonSafely('https://localhost/ok', strict))).toBe('address');
  });

  it.each([
    ['a redirect', '/redirect', 'redirect'],
    ['a 404', '/missing', 'status'],
    ['a 500', '/error', 'status'],
    ['a 201', '/created', 'status'],
    ['an HTML response', '/html', 'content-type'],
    ['a response without a content type', '/no-type', 'content-type'],
    ['a declared oversized body', '/large-declared', 'size'],
    ['a streamed oversized body', '/large-chunked', 'size'],
    ['invalid JSON', '/bad-json', 'json'],
  ] as const)('refuses %s', async (_name, path, expected) => {
    expect(await reason(fetchJsonSafely(`${base}${path}`, local))).toBe(expected);
  });

  it('gives up at the deadline', async () => {
    const started = Date.now();
    expect(await reason(fetchJsonSafely(`${base}/slow`, { ...local, timeoutMs: 200 }))).toBe(
      'timeout',
    );
    expect(Date.now() - started).toBeLessThan(1500);
  });

  it('reports a refused connection as a network failure', async () => {
    const closed = createServer();
    await new Promise<void>((resolve) => closed.listen(0, '127.0.0.1', resolve));
    const port = (closed.address() as AddressInfo).port;
    await new Promise<void>((resolve) => closed.close(() => resolve()));
    expect(await reason(fetchJsonSafely(`http://127.0.0.1:${port}/ok`, local))).toBe('network');
  });
});
