import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import {
  createAccessTokenVerifier,
  createOAuthProvider,
  createProtectedResourceHandler,
  createResourceGuard,
  protectedResourceMetadata,
  protectedResourceMetadataUrl,
  type OAuthProviderConfig,
} from '@better-iam/oauth';
import { IamError, type AuthenticatedPrincipal, type IamStore } from '@better-iam/core';
import { createRequire } from 'node:module';
const { SignJWT, importJWK } = createRequire(
  new URL('../packages/oauth/package.json', import.meta.url),
)('jose');

const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const signingKey = {
  ...pair.privateKey.export({ format: 'jwk' }),
  kid: 'test-key',
  alg: 'RS256',
  use: 'sig',
};
const encryptionKey = randomBytes(32).toString('base64');
const API = 'https://mcp.example.test/mcp';

async function listen(server: Server) {
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  if (!address || typeof address === 'string') throw new Error('No server address');
  return `http://127.0.0.1:${address.port}`;
}

describe('dynamic client registration and protected resource metadata', () => {
  let store: IamStore;
  let servers: Server[];
  beforeEach(async () => {
    servers = [];
    store = sqliteAdapter({ filename: ':memory:' });
    await store.migrate();
    await store.transaction(async (tx) => {
      for (const id of ['a', 'b'])
        await tx.insert('tenants', {
          id,
          tenantId: id,
          name: id,
          type: 'organization',
          parentId: null,
          status: 'active',
          createdAt: Date.now(),
        });
      await tx.insert('identities', {
        id: 'user-a',
        tenantId: 'a',
        name: 'Ada',
        kind: 'user',
        email: 'ada@example.test',
        emailVerified: true,
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
    provider = createOAuthProvider({
      store,
      issuer: `${origin}/oidc`,
      jwks: { keys: [signingKey] },
      encryptionKey,
      cookieKeys: ['test-key-with-at-least-32-characters-long'],
      trustedOrigins: [origin],
      allowInsecureLocalhost: true,
      resourceServers: { [API]: { scopes: ['mcp:tools'] } },
      registration: {},
      authenticate: async (credential) => {
        if (credential.token !== 'admin') throw new IamError('UNAUTHENTICATED', 'No', 401);
        return principal;
      },
      authorize: async (credential) => {
        if (credential.token !== 'admin') throw new IamError('ACCESS_DENIED', 'Forbidden', 403);
      },
      interactionUrl: (uid) => `${origin}/interactions/${uid}`,
      renderDevicePage: ({ form }) => form,
      renderLogoutPage: ({ form }) => form,
      ...overrides,
    });
    const register = async (
      body: Record<string, unknown>,
      headers: Record<string, string> = {},
    ) => {
      const response = await fetch(`${origin}/oidc/reg`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...headers },
        body: JSON.stringify(body),
      });
      const text = await response.text();
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(text) as Record<string, unknown>;
      } catch {
        parsed = { text };
      }
      return { status: response.status, body: parsed };
    };
    const publicClient = {
      client_name: 'MCP host',
      redirect_uris: [`${origin}/callback`],
      token_endpoint_auth_method: 'none',
      grant_types: ['authorization_code', 'refresh_token'],
      response_types: ['code'],
    };
    return { provider, origin, register, publicClient };
  }

  it('registers public clients with a tenant registration token, bound to that tenant and its limits', async () => {
    const { provider, origin, register, publicClient } = await fixture();
    const discovery = await (await fetch(`${origin}/oidc/.well-known/openid-configuration`)).json();
    expect(discovery.registration_endpoint).toBe(`${origin}/oidc/reg`);
    expect(discovery.code_challenge_methods_supported).toContain('S256');

    const issued = await provider.createRegistrationToken(
      { token: 'admin' },
      {
        tenantId: 'a',
        name: 'Claude',
        scopes: ['openid', 'offline_access', 'mcp:tools'],
        resources: [API],
      },
    );
    expect(issued.token).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(issued).toMatchObject({ maxClients: 1, used: 0, allowConfidential: false });

    expect((await register(publicClient)).status).toBe(401);
    // A client cannot pick its own tenant; the token decides.
    const registered = await register(
      { ...publicClient, tenant_id: 'b' },
      { authorization: `Bearer ${issued.token}` },
    );
    expect(registered.status).toBe(201);
    expect(registered.body).toMatchObject({
      client_name: 'MCP host',
      token_endpoint_auth_method: 'none',
      scope: 'openid offline_access mcp:tools',
      tenant_id: 'a',
    });
    expect(registered.body.client_secret).toBeUndefined();
    const clientId = String(registered.body.client_id);
    expect(await provider.getClient({ token: 'admin' }, { tenantId: 'a', clientId })).toMatchObject(
      { tenantId: 'a', public: true, resources: [API], registeredVia: issued.id },
    );
    await expect(
      provider.getClient({ token: 'admin' }, { tenantId: 'b', clientId }),
    ).rejects.toMatchObject({ status: 404 });

    // One use only.
    expect((await register(publicClient, { authorization: `Bearer ${issued.token}` })).status).toBe(
      401,
    );
    expect(await provider.listRegistrationTokens({ token: 'admin' }, { tenantId: 'a' })).toEqual([
      expect.objectContaining({ id: issued.id, used: 1, name: 'Claude' }),
    ]);
    expect(JSON.stringify(await store.find('oauthRegistrationTokens'))).not.toContain(issued.token);

    // The registered client completes an authorization code flow for an MCP resource token.
    const verifier = randomBytes(32).toString('base64url');
    const cookies = new Map<string, string>();
    const visit = async (url: string, options: RequestInit = {}) => {
      const headers = new Headers(options.headers);
      if (cookies.size) headers.set('cookie', [...cookies].map(([k, v]) => `${k}=${v}`).join('; '));
      const result = await fetch(url, { ...options, headers, redirect: 'manual' });
      for (const cookie of result.headers.getSetCookie()) {
        const part = cookie.split(';')[0]!;
        cookies.set(part.slice(0, part.indexOf('=')), part.slice(part.indexOf('=') + 1));
      }
      return result;
    };
    let result = await visit(
      `${origin}/oidc/auth?${new URLSearchParams({
        client_id: clientId,
        response_type: 'code',
        redirect_uri: `${origin}/callback`,
        scope: 'mcp:tools offline_access',
        resource: API,
        prompt: 'consent',
        code_challenge: createHash('sha256').update(verifier).digest('base64url'),
        code_challenge_method: 'S256',
      })}`,
    );
    let redirect = result.headers.get('location')!;
    result = await visit(new URL(redirect, origin).href, { method: 'POST', headers: { origin } });
    redirect = result.headers.get('location')!;
    for (let i = 0; i < 5 && !redirect.includes('/callback?'); i++) {
      result = await visit(new URL(redirect, origin).href);
      redirect = result.headers.get('location')!;
    }
    const code = new URL(redirect, origin).searchParams.get('code')!;
    const tokens = await (
      await fetch(`${origin}/oidc/token`, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: clientId,
          code,
          code_verifier: verifier,
          redirect_uri: `${origin}/callback`,
          resource: API,
        }),
      })
    ).json();
    const verified = await createAccessTokenVerifier({
      issuer: `${origin}/oidc`,
      audience: API,
      jwks: {
        keys: [{ ...pair.publicKey.export({ format: 'jwk' }), kid: 'test-key', alg: 'RS256' }],
      },
    }).verify(tokens.access_token, { scopes: ['mcp:tools'] });
    expect(verified).toMatchObject({ subject: 'user-a', clientId, tenantId: 'a' });

    const actions = (await store.find('audit', { tenantId: 'a' })).map((event) => event.action);
    expect(actions).toEqual(
      expect.arrayContaining(['iam:oauth:CreateRegistrationToken', 'iam:oauth:RegisterClient']),
    );
  });

  it('refuses registrations outside the token limits', async () => {
    const { provider, register, publicClient } = await fixture();
    const { token } = await provider.createRegistrationToken(
      { token: 'admin' },
      { tenantId: 'a', name: 'Many', maxClients: 20 },
    );
    const auth = { authorization: `Bearer ${token}` };
    const refused = async (body: Record<string, unknown>) => {
      const result = await register(body, auth);
      expect(result.status).toBe(400);
      return result.body.error;
    };
    expect(await refused({ ...publicClient, token_endpoint_auth_method: undefined })).toBe(
      'invalid_client_metadata',
    );
    expect(await refused({ ...publicClient, grant_types: ['client_credentials'] })).toBe(
      'invalid_client_metadata',
    );
    expect(await refused({ ...publicClient, redirect_uris: ['http://evil.example.test/cb'] })).toBe(
      'invalid_client_metadata',
    );
    expect(await refused({ ...publicClient, jwks_uri: 'https://keys.example.test/jwks' })).toBe(
      'invalid_client_metadata',
    );
    expect(await refused({ ...publicClient, scope: 'openid iam' })).toBe('invalid_client_metadata');
    // Native apps may use reverse-domain custom schemes; the default allowance applies without `scope`.
    const native = await register(
      {
        ...publicClient,
        application_type: 'native',
        redirect_uris: ['com.example.desktop:/oauth/callback'],
      },
      auth,
    );
    expect(native.status).toBe(201);
    expect(native.body.scope).toBe('openid profile email offline_access');

    // Revoked or expired tokens stop working; configuration outside the deployment is refused up front.
    const tokens = await provider.listRegistrationTokens({ token: 'admin' }, { tenantId: 'a' });
    await provider.revokeRegistrationToken(
      { token: 'admin' },
      { tenantId: 'a', tokenId: tokens[0]!.id },
    );
    expect((await register(publicClient, auth)).status).toBe(401);
    await expect(
      provider.createRegistrationToken(
        { token: 'admin' },
        { tenantId: 'a', name: 'X', scopes: ['nope'] },
      ),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      provider.createRegistrationToken({ token: 'member' }, { tenantId: 'a', name: 'X' }),
    ).rejects.toMatchObject({ status: 403 });
    await expect(
      provider.revokeRegistrationToken(
        { token: 'admin' },
        { tenantId: 'b', tokenId: tokens[0]!.id },
      ),
    ).rejects.toMatchObject({ status: 404 });
  });

  it('admits anonymous registrations the host maps to a tenant, up to its limit', async () => {
    const { register, publicClient, provider } = await fixture({
      registration: {
        anonymous: ({ headers }) =>
          headers['x-tenant'] === 'a'
            ? { tenantId: 'a', maxClients: 1, scopes: ['openid'] }
            : undefined,
      },
    });
    expect((await register(publicClient)).status).toBe(401);
    const first = await register(publicClient, { 'x-tenant': 'a' });
    expect(first.status).toBe(201);
    expect(first.body).toMatchObject({ tenant_id: 'a', scope: 'openid' });
    const second = await register(publicClient, { 'x-tenant': 'a' });
    expect(second.status).toBe(400);
    expect(second.body.error).toBe('access_denied');
    expect(
      (await provider.listClients({ token: 'admin' }, { tenantId: 'a' })).map(
        (c) => c.registeredVia,
      ),
    ).toEqual(['anonymous']);
  });

  it('keeps registration closed unless configured', async () => {
    const { origin, register, publicClient } = await fixture({ registration: undefined });
    const discovery = await (await fetch(`${origin}/oidc/.well-known/openid-configuration`)).json();
    expect(discovery.registration_endpoint).toBeUndefined();
    expect((await register(publicClient)).status).toBeGreaterThanOrEqual(400);
  });

  it('publishes RFC 9728 protected resource metadata and points challenges at it', async () => {
    const options = {
      resource: API,
      authorizationServers: ['https://id.example.test/oidc'],
      scopes: ['mcp:tools'],
      resourceName: 'Acme MCP',
    };
    expect(protectedResourceMetadataUrl(API)).toBe(
      'https://mcp.example.test/.well-known/oauth-protected-resource/mcp',
    );
    expect(protectedResourceMetadataUrl('https://api.example.test/')).toBe(
      'https://api.example.test/.well-known/oauth-protected-resource',
    );
    expect(protectedResourceMetadata(options)).toMatchObject({
      resource: API,
      authorization_servers: ['https://id.example.test/oidc'],
      scopes_supported: ['mcp:tools'],
      bearer_methods_supported: ['header'],
      resource_name: 'Acme MCP',
    });
    const handler = createProtectedResourceHandler(options);
    const served = handler(new Request(protectedResourceMetadataUrl(API)))!;
    expect(served.status).toBe(200);
    expect(served.headers.get('access-control-allow-origin')).toBe('*');
    expect((await served.json()).resource).toBe(API);
    expect(handler(new Request('https://mcp.example.test/mcp'))).toBeUndefined();
    expect(
      handler(new Request(protectedResourceMetadataUrl(API), { method: 'POST' }))!.status,
    ).toBe(405);
    expect(() => protectedResourceMetadata({ ...options, authorizationServers: [] })).toThrow();

    const challenge = createAccessTokenVerifier({
      issuer: 'https://id.example.test/oidc',
      audience: API,
      jwks: { keys: [] },
    }).challenge(new IamError('INSUFFICIENT_SCOPE', 'x', 403), undefined, {
      resourceMetadata: protectedResourceMetadataUrl(API),
      scopes: ['mcp:tools'],
    });
    expect(challenge).toContain(
      'Bearer error="insufficient_scope", resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource/mcp", scope="mcp:tools"',
    );
  });
  it('guards an API: metadata, challenges without and with errors, scopes, and verified tokens', async () => {
    const issuer = 'https://id.example.test/oidc';
    const guard = createResourceGuard({
      resource: API,
      authorizationServers: [issuer],
      scopes: ['mcp:tools', 'mcp:admin'],
      requiredScopes: ['mcp:tools'],
      jwks: {
        keys: [{ ...pair.publicKey.export({ format: 'jwk' }), kid: 'test-key', alg: 'RS256' }],
      },
    });
    const key = await importJWK(signingKey);
    const sign = (scope: string, audience = API) =>
      new SignJWT({ client_id: 'mcp-host', scope, tenant_id: 'a' })
        .setProtectedHeader({ alg: 'RS256', kid: 'test-key', typ: 'at+jwt' })
        .setIssuer(issuer)
        .setAudience(audience)
        .setSubject('user-a')
        .setIssuedAt()
        .setExpirationTime('5m')
        .sign(key) as Promise<string>;
    const call = (authorization?: string) =>
      guard.check(new Request(API, { headers: authorization ? { authorization } : {} }), {
        scopes: [],
      });

    const metadata = await guard.check(new Request(guard.metadataUrl));
    expect(metadata.response?.status).toBe(200);

    const anonymous = await call();
    expect(anonymous.response?.status).toBe(401);
    expect(anonymous.response?.headers.get('www-authenticate')).toBe(
      `Bearer resource_metadata="${guard.metadataUrl}", scope="mcp:tools"`,
    );

    const forged = await call('Bearer not.a.token');
    expect(forged.response?.status).toBe(401);
    expect(forged.response?.headers.get('www-authenticate')).toContain('error="invalid_token"');
    expect(
      (await call(`Bearer ${await sign('mcp:tools', 'https://other.example.test')}`)).response
        ?.status,
    ).toBe(401);

    const narrow = await guard.check(
      new Request(API, { headers: { authorization: `Bearer ${await sign('mcp:tools')}` } }),
      { scopes: ['mcp:admin'] },
    );
    expect(narrow.response?.status).toBe(403);
    expect(await narrow.response!.json()).toMatchObject({ error: 'insufficient_scope' });
    expect(narrow.response?.headers.get('www-authenticate')).toContain(
      'scope="mcp:tools mcp:admin"',
    );

    const allowed = await call(`Bearer ${await sign('mcp:tools mcp:admin')}`);
    expect(allowed.response).toBeUndefined();
    expect(allowed.token).toMatchObject({ subject: 'user-a', clientId: 'mcp-host', tenantId: 'a' });
  });
});
