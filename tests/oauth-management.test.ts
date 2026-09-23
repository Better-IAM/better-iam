import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createHash, generateKeyPairSync, randomBytes, randomUUID } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { createRequire } from 'node:module';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import {
  createAccessTokenVerifier,
  createOAuthProvider,
  type OAuthProviderConfig,
} from '@better-iam/oauth';
import { IamError, type AuthenticatedPrincipal, type IamStore } from '@better-iam/core';
const require = createRequire(new URL('../packages/oauth/package.json', import.meta.url));
const { SignJWT, generateKeyPair, exportJWK } = require('jose');

const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const signingKey = {
  ...pair.privateKey.export({ format: 'jwk' }),
  kid: 'test-key',
  alg: 'RS256',
  use: 'sig',
};
const publicKey = {
  ...pair.publicKey.export({ format: 'jwk' }),
  kid: 'test-key',
  alg: 'RS256',
  use: 'sig',
};
const encryptionKey = randomBytes(32).toString('base64');
const API = 'https://api.example.test';

async function listen(server: Server) {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No server address');
  return `http://127.0.0.1:${address.port}`;
}
async function close(server: Server) {
  server.closeAllConnections();
  await new Promise<void>((resolve, reject) =>
    server.close((error) => (error ? reject(error) : resolve())),
  );
}
const form = { 'content-type': 'application/x-www-form-urlencoded' };
const basic = (id: string, secret: string) =>
  `Basic ${Buffer.from(`${id}:${secret}`).toString('base64')}`;

/** DPoP proofs (RFC 9449) signed with an ephemeral ES256 key. */
async function dpopKey() {
  const { privateKey, publicKey: pub } = await generateKeyPair('ES256');
  const jwk = await exportJWK(pub);
  return (htm: string, htu: string, accessToken?: string): Promise<string> =>
    new SignJWT({
      htm,
      htu,
      jti: randomUUID(),
      ...(accessToken ? { ath: createHash('sha256').update(accessToken).digest('base64url') } : {}),
    })
      .setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk })
      .setIssuedAt()
      .sign(privateKey);
}

describe('OAuth client management, connected apps, resource servers, DPoP and PAR', () => {
  let store: IamStore;
  let servers: Server[];
  beforeEach(async () => {
    servers = [];
    store = sqliteAdapter({ filename: ':memory:' });
    await store.migrate();
    await store.transaction(async (tx) => {
      for (const id of ['root', 'a', 'b'])
        await tx.insert('tenants', {
          id,
          tenantId: id,
          name: id,
          type: id === 'root' ? 'root' : 'organization',
          parentId: id === 'root' ? null : 'root',
          status: 'active',
          createdAt: Date.now(),
        });
      for (const [id, tenantId, kind] of [
        ['user-a', 'a', 'user'],
        ['user-a2', 'a', 'user'],
        ['user-b', 'b', 'user'],
        ['service-a', 'a', 'service'],
      ] as const)
        await tx.insert('identities', {
          id,
          tenantId,
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
    for (const server of servers) await close(server);
    await store.close();
  });

  /** `admin` may do anything; `member` authenticates as user-a but holds no IAM permissions. */
  async function fixture(overrides: Partial<OAuthProviderConfig> = {}) {
    let provider: ReturnType<typeof createOAuthProvider>;
    const server = createServer((req, res) => {
      const action = req.url?.startsWith('/interactions/')
        ? req.method === 'POST'
          ? provider.completeInteraction(req, res, {
              credential: { token: 'admin' },
              consent: true,
            })
          : provider.interactionDetails(req, res).then((details) => {
              res.setHeader('content-type', 'application/json');
              res.end(JSON.stringify(details));
            })
        : provider.nodeHandler(req, res);
      void action.catch((error) => {
        if (!res.headersSent) res.writeHead(error.status ?? 500);
        if (!res.writableEnded) res.end(String(error));
      });
    });
    servers.push(server);
    const origin = await listen(server);
    const principal: AuthenticatedPrincipal = {
      identity: (await store.get('identities', 'user-a')) as AuthenticatedPrincipal['identity'],
      session: {
        id: 'session-a',
        tenantId: 'a',
        identityId: 'user-a',
        kind: 'user',
        tokenHash: 'irrelevant',
        createdAt: Date.now(),
        authenticatedAt: Date.now(),
        lastSeenAt: Date.now(),
        expiresAt: Date.now() + 100000,
        mfa: true,
      },
    };
    await store.transaction((tx) => tx.insert('sessions', principal.session));
    const denied: string[] = [];
    provider = createOAuthProvider({
      store,
      issuer: `${origin}/oidc`,
      jwks: { keys: [signingKey] },
      encryptionKey,
      cookieKeys: ['test-key-with-at-least-32-characters-long'],
      trustedOrigins: [origin],
      allowInsecureLocalhost: true,
      resourceServers: { [API]: { scopes: ['invoices:read', 'invoices:write'] } },
      authenticate: async (credential) => {
        if (credential.token !== 'admin' && credential.token !== 'member')
          throw new IamError('UNAUTHENTICATED', 'Unauthenticated', 401);
        return principal;
      },
      authorize: async (credential, action) => {
        if (credential.token !== 'admin') {
          denied.push(action);
          throw new IamError('ACCESS_DENIED', 'Forbidden', 403);
        }
      },
      interactionUrl: (uid) => `${origin}/interactions/${uid}`,
      renderDevicePage: ({ form: markup }) => `<html><body>${markup}</body></html>`,
      renderLogoutPage: ({ form: markup }) => `<html><body>${markup}</body></html>`,
      ...overrides,
    });
    const token = (body: Record<string, string>, headers: Record<string, string> = {}) =>
      fetch(`${origin}/oidc/token`, {
        method: 'POST',
        headers: { ...form, ...headers },
        body: new URLSearchParams(body),
      });
    /** A browser: cookies persist across flows, so the provider session (and its consent) carries over. */
    function browser() {
      const cookies = new Map<string, string>();
      async function visit(url: string, options: RequestInit = {}) {
        const headers = new Headers(options.headers);
        if (cookies.size)
          headers.set('cookie', [...cookies].map(([key, value]) => `${key}=${value}`).join('; '));
        const result = await fetch(url, { ...options, headers, redirect: 'manual' });
        for (const cookie of result.headers.getSetCookie()) {
          const part = cookie.split(';')[0]!;
          const idx = part.indexOf('=');
          cookies.set(part.slice(0, idx), part.slice(idx + 1));
        }
        return result;
      }
      /** Authorization code flow with consent, then the code exchange. */
      async function authorize(
        clientId: string,
        scope: string,
        extra: { auth?: Record<string, string>; token?: Record<string, string> } = {},
      ) {
        const verifier = randomBytes(32).toString('base64url');
        const params = new URLSearchParams({
          client_id: clientId,
          response_type: 'code',
          redirect_uri: `${origin}/callback`,
          scope,
          prompt: 'consent',
          state: 'state',
          code_challenge: createHash('sha256').update(verifier).digest('base64url'),
          code_challenge_method: 'S256',
          ...extra.auth,
        });
        let result = await visit(`${origin}/oidc/auth?${params}`);
        let redirect = result.headers.get('location')!;
        expect(redirect).toContain('/interactions/');
        const details = await (await visit(new URL(redirect, origin).href)).json();
        result = await visit(new URL(redirect, origin).href, {
          method: 'POST',
          headers: { origin },
        });
        redirect = result.headers.get('location')!;
        for (let i = 0; i < 5 && !redirect.includes('/callback?'); i++) {
          result = await visit(new URL(redirect, origin).href);
          redirect = result.headers.get('location')!;
        }
        const code = new URL(redirect, origin).searchParams.get('code');
        expect(code).toBeTruthy();
        const response = await token({
          grant_type: 'authorization_code',
          client_id: clientId,
          code: code!,
          code_verifier: verifier,
          redirect_uri: `${origin}/callback`,
          ...extra.token,
        });
        expect(response.status).toBe(200);
        return { details, tokens: await response.json() };
      }
      return { visit, authorize };
    }
    return { provider, origin, token, browser, denied };
  }

  it('lists, reads, updates and rotates clients without exposing secrets', async () => {
    const { provider, token, denied } = await fixture();
    const registered = await provider.registerClient(
      { token: 'admin' },
      {
        tenantId: 'a',
        clientId: 'machine',
        name: 'Machine',
        redirectUris: [],
        grantTypes: ['client_credentials'],
        serviceAccountId: 'service-a',
        scopes: ['profile', 'invoices:read'],
        resources: [API],
      },
    );
    await provider.registerClient(
      { token: 'admin' },
      { tenantId: 'a', clientId: 'spa', name: 'SPA', public: true, redirectUris: [API] },
    );
    const listed = await provider.listClients({ token: 'admin' }, { tenantId: 'a' });
    expect(listed.map((client) => client.clientId)).toEqual(['machine', 'spa']);
    expect(listed[0]).toMatchObject({
      name: 'Machine',
      public: false,
      grantTypes: ['client_credentials'],
      scopes: ['profile', 'invoices:read'],
      resources: [API],
      serviceAccountId: 'service-a',
      requireDpop: false,
      revoked: false,
    });
    expect(listed[0]!.createdAt).toBeGreaterThan(0);
    expect(JSON.stringify(listed)).not.toContain(registered.clientSecret);
    expect(await provider.listClients({ token: 'admin' }, { tenantId: 'b' })).toEqual([]);
    // Listing shows only readable clients; a foreign tenant's client is indistinguishable from a missing one.
    expect(await provider.listClients({ token: 'member' }, { tenantId: 'a' })).toEqual([]);
    expect(denied).toContain('iam:oauth:clients:read');
    await expect(
      provider.getClient({ token: 'admin' }, { tenantId: 'b', clientId: 'machine' }),
    ).rejects.toMatchObject({ status: 404 });
    await expect(
      provider.registerClient(
        { token: 'admin' },
        {
          tenantId: 'a',
          clientId: 'x',
          name: 'X',
          redirectUris: [API],
          resources: ['https://unknown.example.test'],
        },
      ),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    const issue = (secret: string, scope = 'profile') =>
      token(
        { grant_type: 'client_credentials', scope },
        { authorization: basic('machine', secret) },
      );
    expect((await issue(registered.clientSecret!)).status).toBe(200);

    // Rotation: the previous secret stops working at once.
    const rotated = await provider.rotateClientSecret(
      { token: 'admin' },
      { tenantId: 'a', clientId: 'machine' },
    );
    expect(rotated.clientSecret).not.toBe(registered.clientSecret);
    expect((await issue(registered.clientSecret!)).status).toBe(401);
    expect((await issue(rotated.clientSecret)).status).toBe(200);
    expect(
      (await provider.getClient({ token: 'admin' }, { tenantId: 'a', clientId: 'machine' }))
        .secretRotatedAt,
    ).toBeGreaterThan(0);
    expect(JSON.stringify(await store.find('oauthClients'))).not.toContain(rotated.clientSecret);
    await expect(
      provider.rotateClientSecret({ token: 'admin' }, { tenantId: 'a', clientId: 'spa' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      provider.rotateClientSecret({ token: 'member' }, { tenantId: 'a', clientId: 'machine' }),
    ).rejects.toMatchObject({ status: 403 });

    // Renaming keeps tokens; removing a scope revokes everything issued to the client.
    const renamed = await provider.updateClient(
      { token: 'admin' },
      { tenantId: 'a', clientId: 'machine', name: 'Billing sync' },
    );
    expect(renamed).toMatchObject({ name: 'Billing sync', tokensRevoked: false });
    expect((await store.find('oauthArtifacts', { clientId: 'machine' })).length).toBeGreaterThan(0);
    const narrowed = await provider.updateClient(
      { token: 'admin' },
      { tenantId: 'a', clientId: 'machine', scopes: ['invoices:read'] },
    );
    expect(narrowed).toMatchObject({ scopes: ['invoices:read'], tokensRevoked: true });
    expect(await store.find('oauthArtifacts', { clientId: 'machine' })).toHaveLength(0);
    expect((await issue(rotated.clientSecret)).status).toBe(400);
    await expect(
      provider.updateClient(
        { token: 'admin' },
        { tenantId: 'a', clientId: 'spa', grantTypes: ['client_credentials'] },
      ),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      provider.updateClient({ token: 'member' }, { tenantId: 'a', clientId: 'spa', name: 'Mine' }),
    ).rejects.toMatchObject({ status: 403 });
    expect(denied).toContain('iam:oauth:clients:update');

    await provider.revokeClient({ token: 'admin' }, { tenantId: 'a', clientId: 'spa' });
    expect(
      (await provider.listClients({ token: 'admin' }, { tenantId: 'a' })).map((c) => c.clientId),
    ).toEqual(['machine']);
    expect(
      await provider.listClients({ token: 'admin' }, { tenantId: 'a', includeRevoked: true }),
    ).toContainEqual(expect.objectContaining({ clientId: 'spa', revoked: true }));
    const actions = (await store.find('audit', { tenantId: 'a' })).map((event) => event.action);
    expect(actions).toEqual(
      expect.arrayContaining([
        'iam:oauth:RegisterClient',
        'iam:oauth:RotateClientSecret',
        'iam:oauth:UpdateClient',
        'iam:oauth:RevokeClient',
      ]),
    );
  });

  it('lists and revokes connected apps, extending one consent per browser session', async () => {
    const { provider, origin, token, browser, denied } = await fixture();
    await provider.registerClient(
      { token: 'admin' },
      {
        tenantId: 'a',
        clientId: 'web',
        name: 'Web app',
        public: true,
        redirectUris: [`${origin}/callback`],
        scopes: ['openid', 'profile', 'email', 'offline_access'],
        logoUri: 'https://app.example.test/logo.png',
        policyUri: 'https://app.example.test/privacy',
        firstParty: true,
      },
    );
    const user = browser();
    const first = await user.authorize('web', 'openid profile offline_access');
    expect(first.details).toMatchObject({
      clientName: 'Web app',
      resources: [],
      client: {
        name: 'Web app',
        logoUri: 'https://app.example.test/logo.png',
        policyUri: 'https://app.example.test/privacy',
        firstParty: true,
      },
    });
    const branded = await provider.updateClient(
      { token: 'admin' },
      { tenantId: 'a', clientId: 'web', logoUri: null, tosUri: 'https://app.example.test/terms' },
    );
    expect(branded).toMatchObject({ tosUri: 'https://app.example.test/terms', firstParty: true });
    expect(branded.logoUri).toBeUndefined();
    await expect(
      provider.updateClient(
        { token: 'admin' },
        { tenantId: 'a', clientId: 'web', clientUri: 'http://app.example.test' },
      ),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    let grants = await provider.listGrants({ token: 'member' }, { tenantId: 'a' });
    expect(grants).toHaveLength(1);
    expect(grants[0]).toMatchObject({
      tenantId: 'a',
      identityId: 'user-a',
      clientId: 'web',
      clientName: 'Web app',
    });
    expect(grants[0]!.scopes).toEqual(expect.arrayContaining(['openid', 'profile']));
    expect(grants[0]!.createdAt).toBeGreaterThan(0);

    // A second consent in the same provider session extends the grant instead of adding one.
    await user.authorize('web', 'openid profile email offline_access');
    grants = await provider.listGrants({ token: 'member' }, { tenantId: 'a' });
    expect(grants).toHaveLength(1);
    expect(grants[0]!.scopes).toContain('email');

    // Other accounts need iam:oauth:grants:read; foreign tenants do not disclose accounts.
    await expect(
      provider.listGrants({ token: 'member' }, { tenantId: 'a', identityId: 'user-a2' }),
    ).rejects.toMatchObject({ status: 403 });
    expect(denied).toContain('iam:oauth:grants:read');
    expect(
      await provider.listGrants({ token: 'admin' }, { tenantId: 'a', identityId: 'user-a2' }),
    ).toEqual([]);
    await expect(
      provider.listGrants({ token: 'admin' }, { tenantId: 'b', identityId: 'user-a' }),
    ).rejects.toMatchObject({ status: 404 });
    await expect(
      provider.revokeGrant({ token: 'member' }, { tenantId: 'a', grantId: 'f'.repeat(64) }),
    ).rejects.toMatchObject({ status: 404 });

    // Revoking the consent kills its refresh tokens.
    const refresh = () =>
      token({
        grant_type: 'refresh_token',
        client_id: 'web',
        refresh_token: first.tokens.refresh_token,
      });
    await provider.revokeGrant({ token: 'member' }, { tenantId: 'a', grantId: grants[0]!.id });
    expect(await provider.listGrants({ token: 'member' }, { tenantId: 'a' })).toEqual([]);
    const refused = await refresh();
    expect(refused.status).toBe(400);
    expect((await refused.json()).error).toBe('invalid_grant');

    // Disconnect: every consent of the account for one client.
    const again = browser();
    const second = await again.authorize('web', 'openid offline_access');
    expect(await provider.listGrants({ token: 'member' }, { tenantId: 'a' })).toHaveLength(1);
    expect(
      await provider.revokeGrants({ token: 'member' }, { tenantId: 'a', clientId: 'other' }),
    ).toEqual({ revoked: 0 });
    expect(
      await provider.revokeGrants({ token: 'member' }, { tenantId: 'a', clientId: 'web' }),
    ).toEqual({ revoked: 1 });
    expect(
      (
        await token({
          grant_type: 'refresh_token',
          client_id: 'web',
          refresh_token: second.tokens.refresh_token,
        })
      ).status,
    ).toBe(400);
    const actions = (await store.find('audit', { tenantId: 'a' })).map((event) => event.action);
    expect(actions.filter((action) => action === 'iam:oauth:RevokeGrant')).toHaveLength(2);
  });

  it('issues audience-restricted JWT access tokens that resource servers verify offline', async () => {
    const { provider, origin, token } = await fixture();
    const machine = await provider.registerClient(
      { token: 'admin' },
      {
        tenantId: 'a',
        clientId: 'machine',
        name: 'Machine',
        redirectUris: [],
        grantTypes: ['client_credentials'],
        serviceAccountId: 'service-a',
        scopes: ['invoices:read'],
        resources: [API],
      },
    );
    const auth = { authorization: basic('machine', machine.clientSecret!) };
    const response = await token(
      { grant_type: 'client_credentials', scope: 'invoices:read', resource: API },
      auth,
    );
    expect(response.status).toBe(200);
    const issued = await response.json();
    expect(issued.token_type).toBe('Bearer');
    expect(String(issued.access_token).split('.')).toHaveLength(3);

    // Keys come from the issuer's JWKS endpoint by default.
    const verifier = createAccessTokenVerifier({ issuer: `${origin}/oidc`, audience: API });
    const verified = await verifier.verify(issued.access_token, { scopes: ['invoices:read'] });
    expect(verified).toMatchObject({
      clientId: 'machine',
      tenantId: 'a',
      identityId: 'service-a',
      scopes: ['invoices:read'],
      audience: [API],
    });
    expect(verified.boundKey).toBeUndefined();
    await expect(
      verifier.verify(issued.access_token, { scopes: ['invoices:write'] }),
    ).rejects.toMatchObject({ code: 'INSUFFICIENT_SCOPE', status: 403 });
    const elsewhere = createAccessTokenVerifier({
      issuer: `${origin}/oidc`,
      audience: 'https://other.example.test',
      jwks: { keys: [publicKey] },
    });
    await expect(elsewhere.verify(issued.access_token)).rejects.toMatchObject({ status: 401 });
    await expect(verifier.verify(`${issued.access_token}x`)).rejects.toMatchObject({
      code: 'INVALID_TOKEN',
    });
    expect(verifier.challenge(new IamError('INSUFFICIENT_SCOPE', 'x', 403), 'api')).toContain(
      'error="insufficient_scope"',
    );

    // Lifetimes: the provider default, then the shorter per-client setting.
    const lifetime = (jwt: string) => {
      const claims = JSON.parse(Buffer.from(jwt.split('.')[1]!, 'base64url').toString('utf8'));
      return claims.exp - claims.iat;
    };
    expect(lifetime(issued.access_token)).toBe(900);
    expect(
      await provider.updateClient(
        { token: 'admin' },
        { tenantId: 'a', clientId: 'machine', accessTokenTtl: 120, refreshTokenTtl: 3600 },
      ),
    ).toMatchObject({ accessTokenTtl: 120, refreshTokenTtl: 3600, tokensRevoked: false });
    const shorter = await (
      await token({ grant_type: 'client_credentials', scope: 'invoices:read', resource: API }, auth)
    ).json();
    expect(lifetime(shorter.access_token)).toBe(120);
    expect(
      (
        await provider.updateClient(
          { token: 'admin' },
          { tenantId: 'a', clientId: 'machine', accessTokenTtl: null },
        )
      ).accessTokenTtl,
    ).toBeUndefined();
    await expect(
      provider.updateClient(
        { token: 'admin' },
        { tenantId: 'a', clientId: 'machine', accessTokenTtl: 5 },
      ),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    // Clients may only target resources they were registered for.
    const other = await provider.registerClient(
      { token: 'admin' },
      {
        tenantId: 'a',
        clientId: 'other',
        name: 'Other',
        redirectUris: [],
        grantTypes: ['client_credentials'],
        serviceAccountId: 'service-a',
        scopes: ['invoices:read'],
      },
    );
    const refused = await token(
      { grant_type: 'client_credentials', scope: 'invoices:read', resource: API },
      { authorization: basic('other', other.clientSecret!) },
    );
    expect(refused.status).toBe(400);
    expect((await refused.json()).error).toBe('invalid_target');
  });

  it("applies a resource server's access token lifetime", async () => {
    const { provider, token } = await fixture({
      resourceServers: { [API]: { scopes: ['invoices:read'], accessTokenTtl: 300 } },
    });
    const client = await provider.registerClient(
      { token: 'admin' },
      {
        tenantId: 'a',
        clientId: 'machine',
        name: 'Machine',
        redirectUris: [],
        grantTypes: ['client_credentials'],
        serviceAccountId: 'service-a',
        scopes: ['invoices:read'],
        resources: [API],
      },
    );
    const issued = await (
      await token(
        { grant_type: 'client_credentials', scope: 'invoices:read', resource: API },
        { authorization: basic('machine', client.clientSecret!) },
      )
    ).json();
    const claims = JSON.parse(
      Buffer.from(String(issued.access_token).split('.')[1]!, 'base64url').toString('utf8'),
    );
    expect(claims.exp - claims.iat).toBe(300);
    expect(issued.expires_in).toBe(300);
  });

  it('binds tokens to DPoP keys and verifies proofs at the resource server', async () => {
    const { provider, origin, token } = await fixture();
    const bound = await provider.registerClient(
      { token: 'admin' },
      {
        tenantId: 'a',
        clientId: 'bound',
        name: 'Bound',
        redirectUris: [],
        grantTypes: ['client_credentials'],
        serviceAccountId: 'service-a',
        scopes: ['invoices:read'],
        resources: [API],
        requireDpop: true,
      },
    );
    const auth = { authorization: basic('bound', bound.clientSecret!) };
    const body = { grant_type: 'client_credentials', scope: 'invoices:read', resource: API };
    expect((await token(body, auth)).status).toBe(400);
    const proof = await dpopKey();
    const response = await token(body, {
      ...auth,
      dpop: await proof('POST', `${origin}/oidc/token`),
    });
    expect(response.status).toBe(200);
    const issued = await response.json();
    expect(issued.token_type).toBe('DPoP');

    const verifier = createAccessTokenVerifier({
      issuer: `${origin}/oidc`,
      audience: API,
      jwks: { keys: [publicKey] },
    });
    // A bound token is useless as a bearer token.
    await expect(verifier.verify(issued.access_token)).rejects.toMatchObject({ status: 401 });
    const request = async (dpop: string | undefined, scheme = 'DPoP') =>
      verifier.verifyRequest({
        authorization: `${scheme} ${issued.access_token}`,
        dpop,
        method: 'get',
        url: `${API}/invoices?page=2`,
      });
    const presented = await proof('GET', `${API}/invoices`, issued.access_token);
    const verified = await request(presented);
    expect(verified.boundKey).toBeTruthy();
    expect(verified.clientId).toBe('bound');
    // Replayed, mis-targeted, foreign-key and bearer-scheme presentations fail.
    await expect(request(presented)).rejects.toMatchObject({ status: 401 });
    await expect(
      request(await proof('POST', `${API}/invoices`, issued.access_token)),
    ).rejects.toMatchObject({ status: 401 });
    await expect(
      request(await (await dpopKey())('GET', `${API}/invoices`, issued.access_token)),
    ).rejects.toMatchObject({ status: 401 });
    await expect(
      request(await proof('GET', `${API}/invoices`, issued.access_token), 'Bearer'),
    ).rejects.toMatchObject({ status: 401 });
    await expect(request(undefined)).rejects.toMatchObject({ status: 401 });

    // Turning on DPoP for an existing client revokes its outstanding bearer tokens.
    await provider.updateClient(
      { token: 'admin' },
      { tenantId: 'a', clientId: 'bound', requireDpop: false },
    );
    expect(
      (
        await provider.updateClient(
          { token: 'admin' },
          { tenantId: 'a', clientId: 'bound', requireDpop: true },
        )
      ).tokensRevoked,
    ).toBe(true);
  });

  it('supports pushed authorization requests and can require them per client', async () => {
    const { provider, origin } = await fixture();
    const discovery = await (await fetch(`${origin}/oidc/.well-known/openid-configuration`)).json();
    expect(discovery.pushed_authorization_request_endpoint).toBe(`${origin}/oidc/request`);
    expect(discovery.dpop_signing_alg_values_supported).toEqual(expect.arrayContaining(['ES256']));
    await provider.registerClient(
      { token: 'admin' },
      {
        tenantId: 'a',
        clientId: 'par',
        name: 'PAR',
        public: true,
        redirectUris: [`${origin}/callback`],
        requirePushedAuthorization: true,
      },
    );
    const params = {
      client_id: 'par',
      response_type: 'code',
      redirect_uri: `${origin}/callback`,
      scope: 'openid',
      code_challenge: createHash('sha256').update('verifier').digest('base64url'),
      code_challenge_method: 'S256',
    };
    const direct = await fetch(`${origin}/oidc/auth?${new URLSearchParams(params)}`, {
      redirect: 'manual',
    });
    expect(direct.status).toBe(303);
    expect(direct.headers.get('location')).toContain('error=invalid_request');
    const pushed = await fetch(`${origin}/oidc/request`, {
      method: 'POST',
      headers: form,
      body: new URLSearchParams(params),
    });
    expect(pushed.status).toBe(201);
    const { request_uri: requestUri } = await pushed.json();
    expect(requestUri).toMatch(/^urn:ietf:params:oauth:request_uri:/);
    const viaPar = await fetch(
      `${origin}/oidc/auth?${new URLSearchParams({ client_id: 'par', request_uri: requestUri })}`,
      { redirect: 'manual' },
    );
    expect(viaPar.status).toBe(303);
    expect(viaPar.headers.get('location')).toContain('/interactions/');
    expect(
      (await provider.getClient({ token: 'admin' }, { tenantId: 'a', clientId: 'par' }))
        .requirePushedAuthorization,
    ).toBe(true);
  });

  it('authenticates clients with private_key_jwt assertions and rotates their keys', async () => {
    const { provider, origin, token } = await fixture();
    const first = await generateKeyPair('ES256', { extractable: true });
    const second = await generateKeyPair('ES256');
    const jwk = async (key: unknown, kid: string) => ({
      ...(await exportJWK(key)),
      kid,
      alg: 'ES256',
      use: 'sig',
    });
    const registered = await provider.registerClient(
      { token: 'admin' },
      {
        tenantId: 'a',
        clientId: 'signed',
        name: 'Signed',
        redirectUris: [],
        grantTypes: ['client_credentials'],
        serviceAccountId: 'service-a',
        scopes: ['profile'],
        tokenEndpointAuthMethod: 'private_key_jwt',
        jwks: { keys: [await jwk(first.publicKey, 'one')] },
      },
    );
    expect(registered.clientSecret).toBeUndefined();
    expect(
      await provider.getClient({ token: 'admin' }, { tenantId: 'a', clientId: 'signed' }),
    ).toMatchObject({ tokenEndpointAuthMethod: 'private_key_jwt', keyIds: ['one'] });
    const assertion = (key: unknown, kid: string) =>
      new SignJWT({ jti: randomUUID() })
        .setProtectedHeader({ alg: 'ES256', kid })
        .setIssuer('signed')
        .setSubject('signed')
        .setAudience(`${origin}/oidc`)
        .setIssuedAt()
        .setExpirationTime('1m')
        .sign(key) as Promise<string>;
    const exchange = (clientAssertion: string) =>
      token({
        grant_type: 'client_credentials',
        scope: 'profile',
        client_id: 'signed',
        client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer',
        client_assertion: clientAssertion,
      });
    const signed = await assertion(first.privateKey, 'one');
    expect((await exchange(signed)).status).toBe(200);
    // Assertions are single use.
    expect((await exchange(signed)).status).toBe(401);
    expect((await exchange(await assertion(second.privateKey, 'one'))).status).toBe(401);

    // Key rotation: the new key works, the retired one stops working.
    const rotated = await provider.updateClient(
      { token: 'admin' },
      {
        tenantId: 'a',
        clientId: 'signed',
        jwks: { keys: [await jwk(second.publicKey, 'two')] },
      },
    );
    expect(rotated).toMatchObject({ keyIds: ['two'], tokensRevoked: false });
    expect((await exchange(await assertion(second.privateKey, 'two'))).status).toBe(200);
    expect((await exchange(await assertion(first.privateKey, 'one'))).status).toBe(401);

    await expect(
      provider.rotateClientSecret({ token: 'admin' }, { tenantId: 'a', clientId: 'signed' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const base = {
      tenantId: 'a',
      name: 'Bad',
      redirectUris: [],
      grantTypes: ['client_credentials' as const],
      serviceAccountId: 'service-a',
      tokenEndpointAuthMethod: 'private_key_jwt' as const,
    };
    // Private key material, missing keys, and keys on secret clients are refused.
    await expect(
      provider.registerClient(
        { token: 'admin' },
        {
          ...base,
          clientId: 'private',
          jwks: { keys: [{ ...(await exportJWK(first.privateKey)), kid: 'x' }] },
        },
      ),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      provider.registerClient({ token: 'admin' }, { ...base, clientId: 'keyless' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      provider.registerClient(
        { token: 'admin' },
        {
          ...base,
          clientId: 'secret-with-keys',
          tokenEndpointAuthMethod: 'client_secret_basic',
          jwks: { keys: [await jwk(first.publicKey, 'one')] },
        },
      ),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      provider.registerClient(
        { token: 'admin' },
        { ...base, clientId: 'insecure', jwksUri: 'http://keys.example.test/jwks' },
      ),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('sends back-channel logout tokens and revokes consents when IAM sessions end', async () => {
    const received: string[] = [];
    const receiver = createServer(async (req, res) => {
      let raw = '';
      for await (const chunk of req) raw += String(chunk);
      received.push(new URLSearchParams(raw).get('logout_token') ?? '');
      res.writeHead(req.url === '/fail' ? 500 : 204).end();
    });
    servers.push(receiver);
    const rp = await listen(receiver);
    const { provider, origin, token, browser } = await fixture();
    for (const [clientId, path] of [
      ['web', '/logout'],
      ['flaky', '/fail'],
    ] as const)
      await provider.registerClient(
        { token: 'admin' },
        {
          tenantId: 'a',
          clientId,
          name: clientId,
          public: true,
          redirectUris: [`${origin}/callback`],
          scopes: ['openid', 'offline_access'],
          backchannelLogoutUri: `${rp}${path}`,
        },
      );
    expect(
      (await provider.getClient({ token: 'admin' }, { tenantId: 'a', clientId: 'web' }))
        .backchannelLogoutUri,
    ).toBe(`${rp}/logout`);
    const user = browser();
    const web = await user.authorize('web', 'openid offline_access');
    await user.authorize('flaky', 'openid offline_access');
    expect(await provider.listGrants({ token: 'member' }, { tenantId: 'a' })).toHaveLength(2);

    // Nothing happens while the session is live.
    expect(await provider.logoutEndedSessions()).toEqual({
      sessions: 0,
      grants: 0,
      notified: 0,
      failures: [],
    });
    await store.transaction((tx) => tx.delete('sessions', 'session-a'));
    const result = await provider.logoutEndedSessions({ identityId: 'user-a' });
    expect(result).toEqual({
      sessions: 1,
      grants: 2,
      notified: 1,
      failures: [{ clientId: 'flaky', identityId: 'user-a' }],
    });
    expect(received).toHaveLength(2);
    const logout = JSON.parse(
      Buffer.from(received[0]!.split('.')[1]!, 'base64url').toString('utf8'),
    ) as Record<string, unknown>;
    expect(logout).toMatchObject({
      iss: `${origin}/oidc`,
      sub: 'user-a',
      events: { 'http://schemas.openid.net/event/backchannel-logout': {} },
    });
    expect(['web', 'flaky']).toContain(logout.aud);
    expect(logout.nonce).toBeUndefined();
    // Consents and refresh tokens are gone, and a second sweep has nothing left to do.
    await store.transaction((tx) =>
      tx.insert('sessions', {
        id: 'session-a',
        tenantId: 'a',
        identityId: 'user-a',
        kind: 'user',
        tokenHash: 'irrelevant',
        createdAt: Date.now(),
        authenticatedAt: Date.now(),
        lastSeenAt: Date.now(),
        expiresAt: Date.now() + 100000,
        mfa: true,
      }),
    );
    expect(await provider.listGrants({ token: 'member' }, { tenantId: 'a' })).toEqual([]);
    expect(
      (
        await token({
          grant_type: 'refresh_token',
          client_id: 'web',
          refresh_token: web.tokens.refresh_token,
        })
      ).status,
    ).toBe(400);
    expect((await provider.logoutEndedSessions()).sessions).toBe(0);
    await provider.updateClient(
      { token: 'admin' },
      { tenantId: 'a', clientId: 'web', backchannelLogoutUri: null },
    );
    expect(
      (await provider.getClient({ token: 'admin' }, { tenantId: 'a', clientId: 'web' }))
        .backchannelLogoutUri,
    ).toBeUndefined();
  });

  it('exchanges an account token for a narrower delegated token (RFC 8693)', async () => {
    const REPORTS = 'https://reports.example.test';
    const refusedSubjects = new Set<string>();
    const { provider, origin, token, browser } = await fixture({
      resourceServers: {
        [API]: { scopes: ['invoices:read'] },
        [REPORTS]: { scopes: ['reports:read', 'reports:write'] },
      },
      authorizeTokenExchange: (request) => !refusedSubjects.has(request.subjectClientId),
    });
    await provider.registerClient(
      { token: 'admin' },
      {
        tenantId: 'a',
        clientId: 'web',
        name: 'Web',
        public: true,
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
        name: 'Invoice API',
        redirectUris: [],
        grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange'],
        scopes: ['reports:read'],
        resources: [REPORTS],
      },
    );
    await expect(
      provider.registerClient(
        { token: 'admin' },
        {
          tenantId: 'a',
          clientId: 'public-exchange',
          name: 'X',
          public: true,
          redirectUris: [],
          grantTypes: ['urn:ietf:params:oauth:grant-type:token-exchange'],
        },
      ),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const discovery = await (await fetch(`${origin}/oidc/.well-known/openid-configuration`)).json();
    expect(discovery.grant_types_supported).toContain(
      'urn:ietf:params:oauth:grant-type:token-exchange',
    );

    // The user signs in to the web app, which calls the invoice API with a JWT for it.
    const user = browser();
    const { tokens } = await user.authorize('web', 'openid invoices:read', {
      auth: { resource: API },
      token: { resource: API },
    });
    const subject = String(tokens.access_token);
    expect(subject.split('.')).toHaveLength(3);
    const exchange = (body: Record<string, string>) =>
      token(
        {
          grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
          subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
          ...body,
        },
        { authorization: basic('gateway', gateway.clientSecret!) },
      );
    const response = await exchange({ subject_token: subject, resource: REPORTS });
    expect(response.status).toBe(200);
    const exchanged = await response.json();
    expect(exchanged).toMatchObject({
      issued_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      token_type: 'Bearer',
      scope: 'reports:read',
    });
    const verified = await createAccessTokenVerifier({
      issuer: `${origin}/oidc`,
      audience: REPORTS,
      jwks: { keys: [publicKey] },
    }).verify(exchanged.access_token, { scopes: ['reports:read'] });
    expect(verified).toMatchObject({
      subject: 'user-a',
      clientId: 'gateway',
      tenantId: 'a',
      actor: { sub: 'gateway' },
    });
    expect(verified.identityId).toBeUndefined();
    const subjectClaims = JSON.parse(Buffer.from(subject.split('.')[1]!, 'base64url').toString());
    expect(verified.expiresAt).toBeLessThanOrEqual(subjectClaims.exp);

    // Chained delegation keeps the previous actor; opaque (UserInfo) subject tokens work too.
    const chained = await (
      await exchange({ subject_token: exchanged.access_token, resource: REPORTS })
    ).json();
    const chainedClaims = JSON.parse(
      Buffer.from(String(chained.access_token).split('.')[1]!, 'base64url').toString(),
    );
    expect(chainedClaims.act).toEqual({ sub: 'gateway', act: { sub: 'gateway' } });
    const plain = await browser().authorize('web', 'openid');
    expect(
      (await exchange({ subject_token: plain.tokens.access_token, audience: REPORTS })).status,
    ).toBe(200);

    // Scope, target, subject, and policy refusals.
    const failure = async (body: Record<string, string>) => {
      const result = await exchange(body);
      return { status: result.status, error: (await result.json()).error };
    };
    expect(
      await failure({ subject_token: subject, resource: REPORTS, scope: 'reports:write' }),
    ).toEqual({ status: 400, error: 'invalid_scope' });
    expect(await failure({ subject_token: subject, resource: API })).toMatchObject({
      status: 400,
      error: 'invalid_target',
    });
    expect(await failure({ subject_token: 'not-a-token', resource: REPORTS })).toEqual({
      status: 400,
      error: 'invalid_grant',
    });
    expect(
      await failure({
        subject_token: subject,
        resource: REPORTS,
        actor_token: 'x',
        actor_token_type: 'urn:ietf:params:oauth:token-type:access_token',
      }),
    ).toEqual({ status: 400, error: 'invalid_request' });
    refusedSubjects.add('web');
    expect(await failure({ subject_token: subject, resource: REPORTS })).toEqual({
      status: 400,
      error: 'access_denied',
    });
    refusedSubjects.clear();
    // A disabled account can no longer be delegated.
    await store.transaction(async (tx) =>
      tx.put('identities', { ...(await tx.get('identities', 'user-a'))!, status: 'disabled' }),
    );
    expect(await failure({ subject_token: subject, resource: REPORTS })).toEqual({
      status: 400,
      error: 'invalid_grant',
    });
    const actions = (await store.find('audit', { tenantId: 'a' })).map((event) => event.action);
    expect(actions.filter((action) => action === 'iam:oauth:TokenExchange')).toHaveLength(3);
  });

  it('rejects invalid resource server configuration', () => {
    const base = {
      store,
      issuer: 'https://issuer.example.test',
      jwks: { keys: [signingKey] },
      encryptionKey,
      cookieKeys: ['test-key-with-at-least-32-characters-long'],
      trustedOrigins: ['https://issuer.example.test'],
      authenticate: async () => {
        throw new Error('unused');
      },
      authorize: async () => undefined,
      interactionUrl: (uid: string) => uid,
      renderDevicePage: () => '',
      renderLogoutPage: () => '',
    };
    expect(() =>
      createOAuthProvider({ ...base, resourceServers: { 'not a uri': { scopes: ['a'] } } }),
    ).toThrow(/absolute URIs/);
    expect(() =>
      createOAuthProvider({ ...base, resourceServers: { [`${API}#x`]: { scopes: ['a'] } } }),
    ).toThrow(/fragment/);
    expect(() =>
      createOAuthProvider({ ...base, resourceServers: { [API]: { scopes: [] } } }),
    ).toThrow(/scope identifiers/);
    expect(() => createOAuthProvider({ ...base, dpopNonceSecret: 'short' })).toThrow(/32 bytes/);
  });
});
