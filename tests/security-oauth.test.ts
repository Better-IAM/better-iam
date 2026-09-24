import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import {
  createAccessTokenVerifier,
  createOAuthProvider,
  type OAuthProviderConfig,
} from '@better-iam/oauth';
import { IamError, type AuthenticatedPrincipal, type IamStore } from '@better-iam/core';

/**
 * The OAuth provider: a client's service account stands behind the client's own tokens only (never a person's), and
 * the dynamic registration gate cannot be sidestepped by spelling the route differently.
 */

const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const signingKey = {
  ...pair.privateKey.export({ format: 'jwk' }),
  kid: 'k',
  alg: 'RS256',
  use: 'sig',
};
const publicKey = { ...pair.publicKey.export({ format: 'jwk' }), kid: 'k', alg: 'RS256', use: 'sig' };
const encryptionKey = randomBytes(32).toString('base64');
const API = 'https://api.example.test';
const REPORTS = 'https://reports.example.test';
const form = { 'content-type': 'application/x-www-form-urlencoded' };
const basic = (id: string, secret: string) =>
  `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}`;
const claimsOf = (jwt: string) =>
  JSON.parse(Buffer.from(jwt.split('.')[1]!, 'base64url').toString()) as Record<string, unknown>;

let store: IamStore;
let servers: Server[];
beforeEach(async () => {
  servers = [];
  store = sqliteAdapter({ filename: ':memory:' });
  await store.migrate();
  await store.transaction(async (tx) => {
    for (const id of ['root', 'a'])
      await tx.insert('tenants', {
        id,
        tenantId: id,
        name: id,
        type: id === 'root' ? 'root' : 'organization',
        parentId: id === 'root' ? null : 'root',
        status: 'active',
        createdAt: Date.now(),
      });
    for (const [id, kind] of [
      ['user-a', 'user'],
      ['service-a', 'service'],
    ] as const)
      await tx.insert('identities', {
        id,
        tenantId: 'a',
        name: id,
        kind,
        ...(kind === 'user' ? { email: `${id}@example.test` } : {}),
        emailVerified: kind === 'user',
        status: 'active',
        rootAdmin: false,
        owner: false,
        createdAt: Date.now(),
      });
  });
});
afterEach(async () => {
  for (const server of servers) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
  }
  await store.close();
});

async function fixture(overrides: Partial<OAuthProviderConfig> = {}) {
  let provider: ReturnType<typeof createOAuthProvider>;
  const server = createServer((request, response) => {
    const action = request.url?.startsWith('/interactions/')
      ? request.method === 'POST'
        ? provider.completeInteraction(request, response, {
            credential: { token: 'admin' },
            consent: true,
          })
        : provider.interactionDetails(request, response).then((details) => {
            response.end(JSON.stringify(details));
          })
      : provider.nodeHandler(request, response);
    void action.catch((error: { status?: number }) => {
      if (!response.headersSent) response.writeHead(error.status ?? 500);
      if (!response.writableEnded) response.end(String(error));
    });
  });
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  const principal: AuthenticatedPrincipal = {
    identity: (await store.get('identities', 'user-a')) as AuthenticatedPrincipal['identity'],
    session: {
      id: 'session-a',
      tenantId: 'a',
      identityId: 'user-a',
      kind: 'user',
      tokenHash: 'x',
      createdAt: Date.now(),
      authenticatedAt: Date.now(),
      lastSeenAt: Date.now(),
      expiresAt: Date.now() + 100000,
      mfa: true,
    },
  };
  await store.transaction((tx) => tx.insert('sessions', principal.session));
  provider = createOAuthProvider({
    store,
    issuer: `${origin}/oidc`,
    jwks: { keys: [signingKey] },
    encryptionKey,
    cookieKeys: ['test-key-with-at-least-32-characters-long'],
    trustedOrigins: [origin],
    allowInsecureLocalhost: true,
    resourceServers: {
      [API]: { scopes: ['invoices:read'] },
      [REPORTS]: { scopes: ['reports:read'] },
    },
    authenticate: async (credential) => {
      if (credential.token !== 'admin') throw new IamError('UNAUTHENTICATED', 'no', 401);
      return principal;
    },
    authorize: async (credential) => {
      if (credential.token !== 'admin') throw new IamError('ACCESS_DENIED', 'no', 403);
    },
    interactionUrl: (uid) => `${origin}/interactions/${uid}`,
    renderDevicePage: ({ form: markup }) => markup,
    renderLogoutPage: ({ form: markup }) => markup,
    ...overrides,
  });
  const token = (body: Record<string, string>, headers: Record<string, string> = {}) =>
    fetch(`${origin}/oidc/token`, {
      method: 'POST',
      headers: { ...form, ...headers },
      body: new URLSearchParams(body),
    });
  const cookies = new Map<string, string>();
  async function visit(url: string, options: RequestInit = {}) {
    const headers = new Headers(options.headers);
    if (cookies.size)
      headers.set(
        'cookie',
        [...cookies].map(([name, value]) => `${name}=${value}`).join('; '),
      );
    const result = await fetch(url, { ...options, headers, redirect: 'manual' });
    for (const cookie of result.headers.getSetCookie()) {
      const part = cookie.split(';')[0]!;
      const index = part.indexOf('=');
      cookies.set(part.slice(0, index), part.slice(index + 1));
    }
    return result;
  }
  /** A person's authorization-code token for `clientId`. */
  async function authorize(clientId: string, secret: string) {
    const verifier = randomBytes(32).toString('base64url');
    const params = new URLSearchParams({
      client_id: clientId,
      response_type: 'code',
      redirect_uri: `${origin}/callback`,
      scope: 'openid invoices:read',
      prompt: 'consent',
      state: 'state',
      resource: API,
      code_challenge: createHash('sha256').update(verifier).digest('base64url'),
      code_challenge_method: 'S256',
    });
    let result = await visit(`${origin}/oidc/auth?${params}`);
    let redirect = result.headers.get('location')!;
    await visit(new URL(redirect, origin).href);
    result = await visit(new URL(redirect, origin).href, { method: 'POST', headers: { origin } });
    redirect = result.headers.get('location')!;
    for (let i = 0; i < 5 && !redirect.includes('/callback?'); i++) {
      result = await visit(new URL(redirect, origin).href);
      redirect = result.headers.get('location')!;
    }
    const code = new URL(redirect, origin).searchParams.get('code')!;
    const response = await token(
      {
        grant_type: 'authorization_code',
        client_id: clientId,
        code,
        code_verifier: verifier,
        redirect_uri: `${origin}/callback`,
        resource: API,
      },
      { authorization: basic(clientId, secret) },
    );
    const body = (await response.json()) as Record<string, unknown>;
    expect(response.status, JSON.stringify(body)).toBe(200);
    return String(body.access_token);
  }
  return { provider, origin, token, authorize };
}

describe('OAuth provider tokens', () => {
  it('names the service account only on the client’s own tokens, never on a person’s, and exchange keeps the person', async () => {
    const { provider, origin, token, authorize } = await fixture();
    const web = await provider.registerClient(
      { token: 'admin' },
      {
        tenantId: 'a',
        clientId: 'web',
        name: 'Web',
        grantTypes: ['authorization_code', 'refresh_token', 'client_credentials'],
        serviceAccountId: 'service-a',
        redirectUris: [`${origin}/callback`],
        scopes: ['openid', 'invoices:read'],
        resources: [API],
      },
    );
    const gateway = await provider.registerClient(
      { token: 'admin' },
      {
        tenantId: 'a',
        clientId: 'gateway',
        name: 'Gateway',
        redirectUris: [],
        grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange'],
        scopes: ['reports:read'],
        resources: [REPORTS],
      },
    );
    const personal = await authorize('web', web.clientSecret!);
    expect(claimsOf(personal)).toMatchObject({ sub: 'user-a' });
    expect(claimsOf(personal).identity_id).toBeUndefined();
    const view = await createAccessTokenVerifier({
      issuer: `${origin}/oidc`,
      audience: API,
      jwks: { keys: [publicKey] },
    }).verify(personal);
    expect(view.identityId).toBeUndefined();

    const exchanged = (await (
      await token(
        {
          grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
          subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          subject_token: personal,
          resource: REPORTS,
        },
        { authorization: basic('gateway', gateway.clientSecret!) },
      )
    ).json()) as { access_token: string };
    expect(claimsOf(exchanged.access_token)).toMatchObject({ sub: 'user-a' });

    // The client's own token still carries its service account.
    const own = (await (
      await token(
        { grant_type: 'client_credentials', resource: API, scope: 'invoices:read' },
        { authorization: basic('web', web.clientSecret!) },
      )
    ).json()) as { access_token: string };
    expect(claimsOf(own.access_token)).toMatchObject({ identity_id: 'service-a' });
  });

  it('refuses to exchange a token once its app is disconnected, and gives DPoP-only clients no bearer token', async () => {
    const { provider, origin, token, authorize } = await fixture();
    const web = await provider.registerClient(
      { token: 'admin' },
      {
        tenantId: 'a',
        clientId: 'web',
        name: 'Web',
        redirectUris: [`${origin}/callback`],
        scopes: ['openid', 'invoices:read'],
        resources: [API],
      },
    );
    const gateway = await provider.registerClient(
      { token: 'admin' },
      {
        tenantId: 'a',
        clientId: 'gateway',
        name: 'Gateway',
        redirectUris: [],
        grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange'],
        scopes: ['reports:read'],
        resources: [REPORTS],
      },
    );
    const strict = await provider.registerClient(
      { token: 'admin' },
      {
        tenantId: 'a',
        clientId: 'strict',
        name: 'Strict',
        redirectUris: [],
        requireDpop: true,
        grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange'],
        scopes: ['reports:read'],
        resources: [REPORTS],
      },
    );
    const personal = await authorize('web', web.clientSecret!);
    const exchange = (clientId: string, secret: string) =>
      token(
        {
          grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
          subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          subject_token: personal,
          resource: REPORTS,
        },
        { authorization: basic(clientId, secret) },
      );
    expect((await exchange('strict', strict.clientSecret!)).status).toBe(400);
    expect((await exchange('gateway', gateway.clientSecret!)).status).toBe(200);
    await provider.revokeGrants({ token: 'admin' }, { tenantId: 'a', clientId: 'web' });
    const refused = await exchange('gateway', gateway.clientSecret!);
    expect(refused.status).toBe(400);
    expect(await refused.json()).toMatchObject({ error: 'invalid_grant' });
  });

  it('does not answer max_age or prompt=login with an older sign-in', async () => {
    const { provider, origin } = await fixture();
    await provider.registerClient(
      { token: 'admin' },
      {
        tenantId: 'a',
        clientId: 'web',
        name: 'Web',
        public: true,
        redirectUris: [`${origin}/callback`],
        scopes: ['openid'],
      },
    );
    const cookies = new Map<string, string>();
    const visit = async (url: string, options: RequestInit = {}) => {
      const headers = new Headers(options.headers);
      if (cookies.size)
        headers.set('cookie', [...cookies].map(([name, value]) => `${name}=${value}`).join('; '));
      const result = await fetch(url, { ...options, headers, redirect: 'manual' });
      for (const cookie of result.headers.getSetCookie()) {
        const part = cookie.split(';')[0]!;
        cookies.set(part.slice(0, part.indexOf('=')), part.slice(part.indexOf('=') + 1));
      }
      return result;
    };
    const verifier = randomBytes(32).toString('base64url');
    const started = await visit(
      `${origin}/oidc/auth?${new URLSearchParams({
        client_id: 'web',
        response_type: 'code',
        redirect_uri: `${origin}/callback`,
        scope: 'openid',
        state: 'state',
        max_age: '0',
        code_challenge: createHash('sha256').update(verifier).digest('base64url'),
        code_challenge_method: 'S256',
      })}`,
    );
    const interaction = new URL(started.headers.get('location')!, origin).href;
    expect(interaction).toContain('/interactions/');
    await new Promise((resolve) => setTimeout(resolve, 5));
    const completed = await visit(interaction, { method: 'POST', headers: { origin } });
    expect(completed.status).toBe(401);
  });

  it('gates dynamic registration however the route is spelled', async () => {
    const { origin } = await fixture({ registration: {} });
    const body = JSON.stringify({
      redirect_uris: ['https://x.example.test/cb'],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code'],
    });
    for (const path of ['/oidc/reg', '/oidc/REG', '/oidc/reg/', '/oidc/Reg', '/oidc/%72eg']) {
      const response = await fetch(`${origin}${path}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body,
      });
      // Refused by the gate itself (401 invalid_token), or not routed at all.
      expect([401, 404], path).toContain(response.status);
      if (response.status === 401)
        expect(response.headers.get('www-authenticate'), path).toContain('invalid_token');
    }
    expect(await store.find('oauthClients', {})).toEqual([]);
  });
});
