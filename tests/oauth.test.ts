import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { createRequire } from 'node:module';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { createOAuthLogin, createOAuthProvider, createProviderAdapter } from '@better-iam/oauth';
import { IamError, type AuthenticatedPrincipal, type IamStore } from '@better-iam/core';
const require = createRequire(new URL('../packages/oauth/package.json', import.meta.url));
const { SignJWT, importJWK } = require('jose');
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

describe('OAuth provider and login', () => {
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
      for (const id of ['a', 'b'])
        await tx.insert('identities', {
          id: `user-${id}`,
          tenantId: id,
          name: id,
          kind: 'user',
          emailVerified: true,
          email: 'same@example.test',
          status: 'active',
          rootAdmin: false,
          owner: false,
          createdAt: Date.now(),
        });
      await tx.insert('identities', {
        id: 'service-a',
        tenantId: 'a',
        name: 'Service A',
        kind: 'service',
        emailVerified: false,
        status: 'active',
        rootAdmin: false,
        owner: false,
        createdAt: Date.now(),
      });
      // Membership and bindings behind the `iam` scope claims.
      await tx.put('identities', {
        ...(await tx.get('identities', 'user-a'))!,
        attributes: { department: 'finance' },
      });
      await tx.insert('groupMembers', {
        id: 'member-a',
        tenantId: 'a',
        groupId: 'group-a',
        identityId: 'user-a',
      });
      await tx.insert('bindings', {
        id: 'binding-direct',
        tenantId: 'a',
        subjectType: 'identity',
        subjectId: 'user-a',
        roleId: 'role-direct',
        authorityId: 'authority-a',
      });
      await tx.insert('bindings', {
        id: 'binding-group',
        tenantId: 'a',
        subjectType: 'group',
        subjectId: 'group-a',
        roleId: 'role-group',
        authorityId: 'authority-a',
      });
      await tx.insert('bindings', {
        id: 'binding-expired',
        tenantId: 'a',
        subjectType: 'identity',
        subjectId: 'user-a',
        roleId: 'role-expired',
        authorityId: 'authority-a',
        expiresAt: Date.now() - 1000,
      });
      await tx.insert('identities', {
        id: 'service-b',
        tenantId: 'b',
        name: 'Service B',
        kind: 'service',
        emailVerified: false,
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
  async function providerFixture() {
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
      authenticate: async (credential) => {
        if (credential.token !== 'admin') throw new IamError('FORBIDDEN', 'Forbidden', 403);
        return principal;
      },
      authorize: async (credential) => {
        if (credential.token !== 'admin') throw new IamError('FORBIDDEN', 'Forbidden', 403);
      },
      interactionUrl: (uid) => `${origin}/interactions/${uid}`,
      renderDevicePage: ({ form }) => `<html><body>${form}</body></html>`,
      renderLogoutPage: ({ form }) => `<html><body>${form}</body></html>`,
    });
    return { provider, origin };
  }
  it('serves discovery and PKCE-only authorization without a development login UI', async () => {
    const { provider, origin } = await providerFixture();
    const discoveryResponse = await fetch(`${origin}/oidc/.well-known/openid-configuration`);
    expect(discoveryResponse.status).toBe(200);
    const discovery = await discoveryResponse.json();
    expect(discovery.issuer).toBe(`${origin}/oidc`);
    expect(discovery.authorization_endpoint).toBe(`${origin}/oidc/auth`);
    expect(discovery.token_endpoint).toBe(`${origin}/oidc/token`);
    expect(discovery.response_types_supported).toEqual(['code']);
    expect(discovery.grant_types_supported).toContain(
      'urn:ietf:params:oauth:grant-type:device_code',
    );
    expect(discovery.registration_endpoint).toBeUndefined();
    await provider.registerClient(
      { token: 'admin' },
      {
        tenantId: 'a',
        clientId: 'web',
        name: 'Web',
        public: true,
        redirectUris: [`${origin}/callback`],
      },
    );
    const authorize = new URL(discovery.authorization_endpoint);
    authorize.search = new URLSearchParams({
      client_id: 'web',
      response_type: 'code',
      redirect_uri: `${origin}/callback`,
      scope: 'openid',
    }).toString();
    const missingPkce = await fetch(authorize, { redirect: 'manual' });
    expect(missingPkce.status).toBe(303);
    expect(missingPkce.headers.get('location')).toContain('error=invalid_request');
  });
  it('issues tenant-bound machine tokens, introspects and immediately revokes clients', async () => {
    const { provider, origin } = await providerFixture();
    const client = await provider.registerClient(
      { token: 'admin' },
      {
        tenantId: 'a',
        clientId: 'machine',
        name: 'Machine',
        redirectUris: [],
        grantTypes: ['client_credentials'],
        serviceAccountId: 'service-a',
        scopes: ['profile'],
      },
    );
    const basic = `Basic ${Buffer.from(`machine:${client.clientSecret}`).toString('base64')}`;
    const tokenResponse = await fetch(`${origin}/oidc/token`, {
      method: 'POST',
      headers: { authorization: basic, 'content-type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials&scope=profile',
    });
    expect(tokenResponse.status).toBe(200);
    const token = await tokenResponse.json();
    expect(token.access_token).toBeTruthy();
    const introspection = await fetch(`${origin}/oidc/token/introspection`, {
      method: 'POST',
      headers: { authorization: basic, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: token.access_token }),
    });
    expect(introspection.status).toBe(200);
    const details = await introspection.json();
    expect(details.active).toBe(true);
    expect(details.tenant_id).toBe('a');
    expect(details.identity_id).toBe('service-a');
    const stored = JSON.stringify(await store.find('oauthArtifacts'));
    expect(stored).not.toContain(token.access_token);
    expect(JSON.stringify(await store.find('oauthClients'))).not.toContain(client.clientSecret);
    await store.transaction(async (tx) => {
      const service = await tx.get('identities', 'service-a');
      await tx.put('identities', { ...service!, status: 'disabled' });
    });
    const disabled = await fetch(`${origin}/oidc/token/introspection`, {
      method: 'POST',
      headers: { authorization: basic, 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({ token: token.access_token }),
    });
    expect(disabled.status).toBe(401);
    await store.transaction(async (tx) => {
      const service = await tx.get('identities', 'service-a');
      await tx.put('identities', { ...service!, status: 'active' });
    });
    await provider.revokeClient({ token: 'admin' }, { tenantId: 'a', clientId: 'machine' });
    const revoked = await fetch(`${origin}/oidc/token`, {
      method: 'POST',
      headers: { authorization: basic, 'content-type': 'application/x-www-form-urlencoded' },
      body: 'grant_type=client_credentials',
    });
    expect(revoked.status).toBe(401);
  });
  it('rejects unauthenticated registration and immutable client tenant rebinding', async () => {
    const { provider } = await providerFixture();
    await expect(
      provider.registerClient(
        { token: 'forged' },
        {
          tenantId: 'a',
          clientId: 'machine',
          name: 'Machine',
          redirectUris: [],
          grantTypes: ['client_credentials'],
          serviceAccountId: 'service-a',
        },
      ),
    ).rejects.toMatchObject({ status: 403 });
    await provider.registerClient(
      { token: 'admin' },
      {
        tenantId: 'a',
        clientId: 'machine',
        name: 'Machine',
        redirectUris: [],
        grantTypes: ['client_credentials'],
        serviceAccountId: 'service-a',
      },
    );
    await expect(
      provider.registerClient(
        { token: 'admin' },
        {
          tenantId: 'b',
          clientId: 'machine',
          name: 'Machine',
          redirectUris: [],
          grantTypes: ['client_credentials'],
          serviceAccountId: 'service-b',
        },
      ),
    ).rejects.toMatchObject({ status: 409 });
    await expect(
      provider.registerClient(
        { token: 'admin' },
        {
          tenantId: 'a',
          clientId: 'bad-public',
          name: 'Bad',
          redirectUris: [],
          public: true,
          grantTypes: ['client_credentials'],
          serviceAccountId: 'service-a',
        },
      ),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
  it.each([false, true])(
    'completes PKCE and invalidates refresh families on replay (concurrent=%s)',
    async (concurrent) => {
      const { provider, origin } = await providerFixture();
      await provider.registerClient(
        { token: 'admin' },
        {
          tenantId: 'a',
          clientId: 'public-web',
          name: 'Web',
          public: true,
          redirectUris: [`${origin}/callback`],
          scopes: ['openid', 'profile', 'offline_access', 'iam'],
        },
      );
      const verifier = randomBytes(32).toString('base64url');
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
      const params = new URLSearchParams({
        client_id: 'public-web',
        response_type: 'code',
        redirect_uri: `${origin}/callback`,
        scope: 'openid profile offline_access iam',
        prompt: 'consent',
        state: 'state',
        code_challenge: createHash('sha256').update(verifier).digest('base64url'),
        code_challenge_method: 'S256',
      });
      let result = await visit(`${origin}/oidc/auth?${params}`);
      let redirect = result.headers.get('location')!;
      expect(redirect).toContain('/interactions/');
      const details = await visit(new URL(redirect, origin).href);
      expect((await details.json()).tenantId).toBe('a');
      const csrf = await visit(new URL(redirect, origin).href, { method: 'POST' });
      expect(csrf.status).toBe(403);
      result = await visit(new URL(redirect, origin).href, { method: 'POST', headers: { origin } });
      redirect = result.headers.get('location')!;
      for (let i = 0; i < 5 && !redirect.includes('/callback?'); i++) {
        result = await visit(new URL(redirect, origin).href);
        redirect = result.headers.get('location')!;
      }
      const code = new URL(redirect, origin).searchParams.get('code');
      expect(code).toBeTruthy();
      const exchange = (body: URLSearchParams) =>
        fetch(`${origin}/oidc/token`, {
          method: 'POST',
          headers: { 'content-type': 'application/x-www-form-urlencoded' },
          body,
        });
      const tokenResponse = await exchange(
        new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: 'public-web',
          code: code!,
          code_verifier: verifier,
          redirect_uri: `${origin}/callback`,
        }),
      );
      expect(tokenResponse.status).toBe(200);
      const tokens = await tokenResponse.json();
      expect(tokens.refresh_token).toBeTruthy();
      // The `iam` scope adds live role and group IDs plus declared attributes through userinfo
      // (ID tokens carry only openid claims while an access token is issued); expired bindings are omitted.
      const idToken = JSON.parse(
        Buffer.from(String(tokens.id_token).split('.')[1]!, 'base64url').toString('utf8'),
      ) as Record<string, unknown>;
      expect(idToken).toMatchObject({ sub: 'user-a', tenant_id: 'a' });
      const userinfo = await fetch(`${origin}/oidc/me`, {
        headers: { authorization: `Bearer ${tokens.access_token}` },
      });
      expect(userinfo.status).toBe(200);
      expect(await userinfo.json()).toMatchObject({
        sub: 'user-a',
        roles: ['role-direct', 'role-group'],
        groups: ['group-a'],
        attributes: { department: 'finance' },
      });
      const rotate = await exchange(
        new URLSearchParams({
          grant_type: 'refresh_token',
          client_id: 'public-web',
          refresh_token: tokens.refresh_token,
        }),
      );
      expect(rotate.status).toBe(200);
      const rotated = await rotate.json();
      expect(rotated.refresh_token).not.toBe(tokens.refresh_token);
      if (concurrent) {
        const raced = await Promise.all([
          exchange(
            new URLSearchParams({
              grant_type: 'refresh_token',
              client_id: 'public-web',
              refresh_token: rotated.refresh_token,
            }),
          ),
          exchange(
            new URLSearchParams({
              grant_type: 'refresh_token',
              client_id: 'public-web',
              refresh_token: rotated.refresh_token,
            }),
          ),
        ]);
        expect(raced.filter((response) => response.status === 200).length).toBeLessThanOrEqual(1);
        expect(raced.some((response) => response.status === 400)).toBe(true);
        for (const response of raced)
          if (response.status === 200) {
            const issued = await response.json();
            const revoked = await exchange(
              new URLSearchParams({
                grant_type: 'refresh_token',
                client_id: 'public-web',
                refresh_token: issued.refresh_token,
              }),
            );
            expect(revoked.status).toBe(400);
          }
      }
      const replay = await exchange(
        new URLSearchParams({
          grant_type: 'refresh_token',
          client_id: 'public-web',
          refresh_token: tokens.refresh_token,
        }),
      );
      expect(replay.status).toBe(400);
      expect((await replay.json()).error).toBe('invalid_grant');
      const family = await exchange(
        new URLSearchParams({
          grant_type: 'refresh_token',
          client_id: 'public-web',
          refresh_token: rotated.refresh_token,
        }),
      );
      expect(family.status).toBe(400);
      expect((await family.json()).error).toBe('invalid_grant');
    },
  );
  it('persists provider artifacts across adapter instances, enforces scope, and consumes atomically', async () => {
    const { provider } = await providerFixture();
    await provider.registerClient(
      { token: 'admin' },
      { tenantId: 'a', clientId: 'web', name: 'Web', redirectUris: ['https://app.test/callback'] },
    );
    const Adapter = createProviderAdapter(store, encryptionKey);
    const first = new Adapter('RefreshToken');
    const second = new Adapter('RefreshToken');
    await store.transaction((tx) =>
      tx.insert('oauthGrantSessions', {
        id: createHash('sha256').update('grant').digest('hex'),
        tenantId: 'a',
        sessionId: 'session-a',
        identityId: 'user-a',
      }),
    );
    await first.upsert(
      'refresh-secret',
      { clientId: 'web', accountId: 'user-a', grantId: 'grant', jti: 'refresh-secret' },
      60,
    );
    expect((await second.find('refresh-secret'))?.accountId).toBe('user-a');
    await expect(
      first.upsert('foreign', { clientId: 'web', accountId: 'user-b' }, 60),
    ).rejects.toMatchObject({ error: 'invalid_grant' });
    const consumed = await Promise.allSettled([
      first.consume('refresh-secret'),
      second.consume('refresh-secret'),
    ]);
    expect(consumed.filter((value) => value.status === 'fulfilled')).toHaveLength(1);
    expect(await first.find('refresh-secret')).toBeUndefined();
    await second.revokeByGrantId('grant');
    expect(await first.find('refresh-secret')).toBeUndefined();
    await store.transaction((tx) =>
      tx.insert('oauthGrantSessions', {
        id: createHash('sha256').update('session-grant').digest('hex'),
        tenantId: 'a',
        sessionId: 'session-a',
        identityId: 'user-a',
      }),
    );
    const session = new Adapter('Session');
    await session.upsert('anonymous', { uid: 'uid' }, 60);
    await session.upsert(
      'anonymous',
      { uid: 'uid', accountId: 'user-a', authorizations: { web: { grantId: 'session-grant' } } },
      60,
    );
    expect((await session.findByUid('uid'))?.accountId).toBe('user-a');
    await expect(
      session.upsert('anonymous', { uid: 'uid', accountId: 'user-b' }, 60),
    ).rejects.toMatchObject({ error: 'invalid_grant' });
    await store.transaction(async (tx) => {
      await tx.insert('oauthGrantSessions', {
        id: createHash('sha256').update('live-grant').digest('hex'),
        tenantId: 'a',
        sessionId: 'session-a',
        identityId: 'user-a',
      });
    });
    await first.upsert(
      'another-refresh',
      { clientId: 'web', accountId: 'user-a', grantId: 'live-grant' },
      60,
    );
    await store.transaction((tx) => tx.delete('sessions', 'session-a'));
    expect(await first.find('another-refresh')).toBeUndefined();
  });
  it('verifies OIDC signatures, nonce and PKCE while preventing callback replay or email linking', async () => {
    let origin = '';
    let nonce = '';
    let challenge = '';
    let badNonce = false;
    let exchanges = 0;
    const server = createServer(async (req, res) => {
      res.setHeader('content-type', 'application/json');
      if (req.url === '/.well-known/openid-configuration')
        return res.end(
          JSON.stringify({
            issuer: origin,
            authorization_endpoint: `${origin}/authorize`,
            token_endpoint: `${origin}/token`,
            jwks_uri: `${origin}/jwks`,
            response_types_supported: ['code'],
            subject_types_supported: ['public'],
            id_token_signing_alg_values_supported: ['RS256'],
          }),
        );
      if (req.url === '/jwks') return res.end(JSON.stringify({ keys: [publicKey] }));
      if (req.url === '/token') {
        let raw = '';
        for await (const chunk of req) raw += String(chunk);
        const input = new URLSearchParams(raw);
        expect(createHash('sha256').update(input.get('code_verifier')!).digest('base64url')).toBe(
          challenge,
        );
        exchanges++;
        const jwt = await new SignJWT({
          nonce: badNonce ? 'wrong' : nonce,
          email: 'same@example.test',
          email_verified: true,
          name: 'Federated',
        })
          .setProtectedHeader({ alg: 'RS256', kid: 'test-key' })
          .setIssuer(origin)
          .setAudience('login')
          .setSubject('stable-subject')
          .setIssuedAt()
          .setExpirationTime('5m')
          .sign(await importJWK(signingKey));
        return res.end(
          JSON.stringify({
            access_token: 'provider-access-token',
            token_type: 'Bearer',
            id_token: jwt,
            expires_in: 300,
          }),
        );
      }
      res.statusCode = 404;
      res.end('{}');
    });
    servers.push(server);
    origin = await listen(server);
    const identities: unknown[] = [];
    const login = createOAuthLogin({
      store,
      connections: [
        {
          id: 'login-a',
          tenantId: 'a',
          kind: 'oidc',
          issuer: origin,
          clientId: 'login',
          redirectUri: `${origin}/callback`,
          mapAttributes: (claims) => ({ upstreamSubject: claims.sub }),
        },
      ],
      allowInsecureLocalhost: true,
      completeAuthentication: async (identity) => {
        identities.push(identity);
        return { verified: true };
      },
    });
    const begin = await login.begin('login-a');
    const authUrl = new URL(begin.url);
    nonce = authUrl.searchParams.get('nonce')!;
    challenge = authUrl.searchParams.get('code_challenge')!;
    const returned = `${origin}/callback?code=valid&state=${encodeURIComponent(begin.state)}`;
    await expect(login.callback('login-a', returned, 'forged')).rejects.toMatchObject({
      code: 'OAUTH_STATE',
    });
    const raced = await Promise.allSettled([
      login.callback('login-a', returned, begin.binding),
      login.callback('login-a', returned, begin.binding),
    ]);
    expect(raced.filter((value) => value.status === 'fulfilled')).toHaveLength(1);
    expect(exchanges).toBe(1);
    expect(identities).toEqual([
      {
        tenantId: 'a',
        providerId: 'login-a',
        issuer: origin,
        subject: 'stable-subject',
        email: 'same@example.test',
        emailVerified: true,
        name: 'Federated',
        attributes: { upstreamSubject: 'stable-subject' },
      },
    ]);
    const again = await login.begin('login-a');
    const anotherUrl = new URL(again.url);
    nonce = anotherUrl.searchParams.get('nonce')!;
    challenge = anotherUrl.searchParams.get('code_challenge')!;
    badNonce = true;
    await expect(
      login.callback(
        'login-a',
        `${origin}/callback?code=valid&state=${again.state}`,
        again.binding,
      ),
    ).rejects.toThrow();
    expect(identities).toHaveLength(1);
  });
  it('supports configured OAuth2 identity mapping and explicit browser-bound account linking', async () => {
    const server = createServer((req, res) => {
      res.setHeader('content-type', 'application/json');
      if (req.url === '/token')
        res.end(JSON.stringify({ access_token: 'verified-token', token_type: 'Bearer' }));
      else if (req.url === '/profile' && req.headers.authorization === 'Bearer verified-token')
        res.end(JSON.stringify({ id: 'provider-subject', mail: 'same@example.test' }));
      else {
        res.statusCode = 401;
        res.end('{}');
      }
    });
    servers.push(server);
    const origin = await listen(server);
    const principal: AuthenticatedPrincipal = {
      identity: (await store.get('identities', 'user-a')) as AuthenticatedPrincipal['identity'],
      session: {
        id: 'link-session',
        tenantId: 'a',
        identityId: 'user-a',
        tokenHash: 'unused',
        createdAt: Date.now(),
        authenticatedAt: Date.now(),
        lastSeenAt: Date.now(),
        expiresAt: Date.now() + 600000,
        mfa: false,
        kind: 'user',
      },
    };
    const completed: unknown[] = [];
    const login = createOAuthLogin({
      store,
      allowInsecureLocalhost: true,
      trustedOrigins: [origin],
      connections: [
        {
          id: 'custom',
          kind: 'oauth2',
          tenantId: 'a',
          clientId: 'custom',
          issuer: origin,
          redirectUri: `${origin}/callback`,
          authorizationEndpoint: `${origin}/authorize`,
          tokenEndpoint: `${origin}/token`,
          userInfoEndpoint: `${origin}/profile`,
          mapProfile: (profile) => ({
            subject: String(profile.id),
            email: String(profile.mail),
            emailVerified: true,
          }),
        },
      ],
      authenticate: async (credential) => {
        if (new Headers(credential.headers).get('authorization') !== 'Bearer local-session')
          throw new IamError('FORBIDDEN', 'Forbidden', 403);
        return principal;
      },
      completeAuthentication: async (identity) => {
        completed.push(identity);
        return { linked: true };
      },
    });
    const forged = await login.handler(
      new Request(`${origin}/oauth/login/custom`, {
        method: 'POST',
        headers: {
          authorization: 'Bearer local-session',
          'content-type': 'application/json',
          'x-better-iam': '1',
        },
      }),
    );
    expect(forged!.status).toBe(403);
    const response = await login.handler(
      new Request(`${origin}/oauth/login/custom`, {
        method: 'POST',
        headers: {
          origin,
          authorization: 'Bearer local-session',
          'content-type': 'application/json',
          'x-better-iam': '1',
        },
      }),
    );
    expect(response!.status).toBe(200);
    const url = new URL((await response!.json()).url);
    const cookie = response!.headers.get('set-cookie')!;
    expect(cookie).not.toContain('__Host-');
    expect(cookie).not.toContain('Secure');
    const binding = cookie.split(';')[0]!.split('=')[1]!;
    await expect(
      login.callback(
        'custom',
        `${origin}/callback?code=verified&state=${url.searchParams.get('state')}`,
        binding,
      ),
    ).resolves.toEqual({ linked: true });
    expect(completed).toEqual([
      {
        tenantId: 'a',
        providerId: 'custom',
        issuer: origin,
        subject: 'provider-subject',
        email: 'same@example.test',
        emailVerified: true,
        name: undefined,
        linkingIdentityId: 'user-a',
        linkingSessionId: 'link-session',
      },
    ]);
    principal.identity.rootAdmin = true;
    await expect(
      login.begin('custom', { headers: { authorization: 'Bearer local-session' } }),
    ).rejects.toMatchObject({ status: 403 });
  });
});
