import { afterEach, describe, expect, it } from 'vitest';
import { createHash, generateKeyPairSync, randomBytes } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { createOAuthProvider, createResourceGuard } from '@better-iam/oauth';
import { closeFixtures, organizationFixture } from './support/organization.js';

const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const signingKey = {
  ...pair.privateKey.export({ format: 'jwk' }),
  kid: 'mcp-key',
  alg: 'RS256',
  use: 'sig',
};

/**
 * The whole Model Context Protocol authorization chain against a real Better IAM server: an MCP server guarded by
 * `createResourceGuard`, a spec-following client that discovers the authorization server from the 401 challenge,
 * registers itself dynamically, runs the authorization code flow with PKCE and a resource indicator for a member
 * who consents, and calls the server — with IAM's own authorization deciding who may manage registration.
 */
describe('MCP authorization end to end', () => {
  const servers: Server[] = [];
  afterEach(async () => {
    for (const server of servers.splice(0)) {
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
    await closeFixtures();
  });

  it('discovers, registers, consents, and calls a guarded MCP server', async () => {
    const fixture = await organizationFixture();
    const { iam, tenantId } = fixture;
    await fixture.member('alice');
    const alice = await fixture.signIn('alice');

    let origin = '';
    let provider: ReturnType<typeof createOAuthProvider>;
    let guard: ReturnType<typeof createResourceGuard>;
    const server = createServer(async (req, res) => {
      try {
        const url = new URL(req.url!, origin);
        if (url.pathname.startsWith('/interactions/')) {
          if (req.method === 'POST')
            return await provider.completeInteraction(req, res, {
              credential: { token: alice.token },
              consent: true,
            });
          res.setHeader('content-type', 'application/json');
          return res.end(JSON.stringify(await provider.interactionDetails(req, res)));
        }
        if (
          url.pathname === '/mcp' ||
          url.pathname.startsWith('/.well-known/oauth-protected-resource')
        ) {
          const headers = new Headers();
          for (const [key, value] of Object.entries(req.headers))
            if (typeof value === 'string') headers.set(key, value);
          const { response, token } = await guard.check(
            new Request(url, { method: req.method, headers }),
          );
          const reply =
            response ??
            Response.json({
              jsonrpc: '2.0',
              result: { user: token!.subject, tenant: token!.tenantId },
            });
          res.writeHead(reply.status, Object.fromEntries(reply.headers));
          return res.end(Buffer.from(await reply.arrayBuffer()));
        }
        await provider.nodeHandler(req, res);
      } catch (error) {
        if (!res.headersSent) res.writeHead((error as { status?: number }).status ?? 500);
        res.end(String(error));
      }
    });
    servers.push(server);
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
    const resource = `${origin}/mcp`;
    provider = createOAuthProvider({
      ...iam.protocolHost,
      issuer: `${origin}/oidc`,
      jwks: { keys: [signingKey] },
      encryptionKey: randomBytes(32).toString('base64'),
      cookieKeys: ['mcp-integration-cookie-key-with-32-characters'],
      trustedOrigins: [origin],
      allowInsecureLocalhost: true,
      resourceServers: { [resource]: { scopes: ['mcp:tools'] } },
      registration: {
        anonymous: () => ({
          tenantId,
          scopes: ['openid', 'offline_access', 'mcp:tools'],
          resources: [resource],
        }),
      },
      interactionUrl: (uid) => `${origin}/interactions/${uid}`,
      renderDevicePage: ({ form }) => form,
      renderLogoutPage: ({ form }) => form,
    });
    guard = createResourceGuard({
      resource,
      authorizationServers: [`${origin}/oidc`],
      scopes: ['mcp:tools'],
      requiredScopes: ['mcp:tools'],
    });

    // 1. Unauthenticated call: the challenge names the protected resource metadata.
    const first = await fetch(resource);
    expect(first.status).toBe(401);
    const metadataUrl = /resource_metadata="([^"]+)"/.exec(
      first.headers.get('www-authenticate')!,
    )![1]!;
    const metadata = await (await fetch(metadataUrl)).json();
    expect(metadata.resource).toBe(resource);

    // 2. Authorization server metadata (RFC 8414 path insertion for an issuer with a path).
    const issuer = new URL(metadata.authorization_servers[0]);
    const server8414 = await (
      await fetch(`${issuer.origin}/.well-known/oauth-authorization-server${issuer.pathname}`)
    ).json();
    expect(server8414.issuer).toBe(`${origin}/oidc`);
    expect(server8414.code_challenge_methods_supported).toContain('S256');

    // 3. Dynamic registration, anonymously, as MCP hosts do.
    const registration = await (
      await fetch(server8414.registration_endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          client_name: 'Example MCP host',
          redirect_uris: [`${origin}/callback`],
          token_endpoint_auth_method: 'none',
          grant_types: ['authorization_code', 'refresh_token'],
          response_types: ['code'],
        }),
      })
    ).json();
    expect(registration.client_id).toBeTruthy();

    // 4. Authorization code with PKCE and the resource; Alice consents.
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
    let step = await visit(
      `${server8414.authorization_endpoint}?${new URLSearchParams({
        client_id: registration.client_id,
        response_type: 'code',
        redirect_uri: `${origin}/callback`,
        scope: 'mcp:tools offline_access',
        resource,
        code_challenge: createHash('sha256').update(verifier).digest('base64url'),
        code_challenge_method: 'S256',
        state: 'xyz',
      })}`,
    );
    let location = step.headers.get('location')!;
    const details = await (await visit(new URL(location, origin).href)).json();
    expect(details).toMatchObject({
      tenantId,
      clientName: 'Example MCP host',
      resources: [resource],
    });
    step = await visit(new URL(location, origin).href, { method: 'POST', headers: { origin } });
    location = step.headers.get('location')!;
    for (let i = 0; i < 5 && !location.includes('/callback?'); i++) {
      step = await visit(new URL(location, origin).href);
      location = step.headers.get('location')!;
    }
    const callback = new URL(location, origin);
    expect(callback.searchParams.get('state')).toBe('xyz');
    const tokens = await (
      await fetch(server8414.token_endpoint, {
        method: 'POST',
        headers: { 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          grant_type: 'authorization_code',
          client_id: registration.client_id,
          code: callback.searchParams.get('code')!,
          code_verifier: verifier,
          redirect_uri: `${origin}/callback`,
          resource,
        }),
      })
    ).json();
    expect(tokens.refresh_token).toBeTruthy();

    // 5. The MCP call succeeds for Alice in her organization.
    const call = await fetch(resource, {
      headers: { authorization: `Bearer ${tokens.access_token}` },
    });
    expect(call.status).toBe(200);
    const aliceId = (await iam.api.auth.getSession({ token: alice.token })).identity.id;
    expect(await call.json()).toMatchObject({ result: { user: aliceId, tenant: tenantId } });

    // 6. IAM authorization governs registration tokens: the owner may issue one, Alice may not.
    const issued = await provider.createRegistrationToken(fixture.ownerCredential, {
      tenantId,
      name: 'IDE plugin',
    });
    expect(issued.token).toBeTruthy();
    await expect(
      provider.createRegistrationToken({ token: alice.token }, { tenantId, name: 'Mine' }),
    ).rejects.toMatchObject({ status: 403 });

    // 7. Signing out ends the grant: the refresh token stops working once ended sessions are swept.
    await iam.api.auth.signOut({ token: alice.token });
    await provider.logoutEndedSessions();
    const refreshed = await fetch(server8414.token_endpoint, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: 'refresh_token',
        client_id: registration.client_id,
        refresh_token: tokens.refresh_token,
      }),
    });
    expect(refreshed.status).toBe(400);
  });
});
