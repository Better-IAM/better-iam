import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import { createRequire } from 'node:module';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { createOAuthLogin, type OAuthLoginConnection } from '@better-iam/oauth';
import type { IamStore } from '@better-iam/core';
const require = createRequire(new URL('../packages/oauth/package.json', import.meta.url));
const { SignJWT, importJWK } = require('jose');

const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
const privateJwk = { ...pair.privateKey.export({ format: 'jwk' }), kid: 'entra', alg: 'RS256' };
const publicJwk = {
  ...pair.publicKey.export({ format: 'jwk' }),
  kid: 'entra',
  alg: 'RS256',
  use: 'sig',
};
const CONTOSO = '72f988bf-86f1-41af-91ab-2d7cd011db47';
const FABRIKAM = '0b6c1f2a-5d3e-4c4f-9a1b-2c3d4e5f6a7b';

describe('Microsoft Entra ID sign-in', () => {
  let store: IamStore;
  let server: Server;
  let origin: string;
  /** What the fake Entra puts into the next ID token. */
  let issued: { tid: string; iss?: string; xms_edov?: boolean };
  let nonce = '';
  beforeEach(async () => {
    store = sqliteAdapter({ filename: ':memory:' });
    await store.migrate();
    await store.transaction((tx) =>
      tx.insert('tenants', {
        id: 'a',
        tenantId: 'a',
        name: 'A',
        type: 'organization',
        parentId: null,
        status: 'active',
        createdAt: Date.now(),
      }),
    );
    issued = { tid: CONTOSO };
    server = createServer(async (req, res) => {
      res.setHeader('content-type', 'application/json');
      const directory = req.url!.split('/')[1]!;
      if (req.url!.endsWith('/v2.0/.well-known/openid-configuration'))
        return res.end(
          JSON.stringify({
            // Multi-tenant documents carry a templated issuer, single-tenant ones the concrete one.
            issuer: `${origin}/${['organizations', 'common'].includes(directory) ? '{tenantid}' : directory}/v2.0`,
            authorization_endpoint: `${origin}/${directory}/oauth2/v2.0/authorize`,
            token_endpoint: `${origin}/${directory}/oauth2/v2.0/token`,
            jwks_uri: `${origin}/${directory}/discovery/v2.0/keys`,
            response_types_supported: ['code'],
            id_token_signing_alg_values_supported: ['RS256'],
          }),
        );
      if (req.url!.endsWith('/discovery/v2.0/keys'))
        return res.end(JSON.stringify({ keys: [publicJwk] }));
      if (req.url!.endsWith('/oauth2/v2.0/token')) {
        for await (const _chunk of req);
        const idToken = await new SignJWT({
          nonce,
          tid: issued.tid,
          email: 'ada@contoso.test',
          name: 'Ada',
          ...(issued.xms_edov !== undefined ? { xms_edov: issued.xms_edov } : {}),
        })
          .setProtectedHeader({ alg: 'RS256', kid: 'entra' })
          .setIssuer(issued.iss ?? `${origin}/${issued.tid}/v2.0`)
          .setAudience('entra-client')
          .setSubject(`pairwise-${issued.tid}`)
          .setIssuedAt()
          .setExpirationTime('5m')
          .sign(await importJWK(privateJwk));
        return res.end(
          JSON.stringify({
            access_token: 'at',
            token_type: 'Bearer',
            id_token: idToken,
            expires_in: 300,
          }),
        );
      }
      res.statusCode = 404;
      res.end('{}');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    origin = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  });
  afterEach(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await store.close();
  });

  function login(connection: Partial<OAuthLoginConnection> = {}) {
    const identities: Record<string, unknown>[] = [];
    const service = createOAuthLogin({
      store,
      allowInsecureLocalhost: true,
      connections: [
        {
          id: 'entra',
          tenantId: 'a',
          kind: 'microsoft',
          issuer: origin,
          clientId: 'entra-client',
          clientSecret: 'entra-secret',
          redirectUri: `${origin}/callback`,
          allowedMicrosoftTenants: [CONTOSO.toUpperCase()],
          ...connection,
        },
      ],
      completeAuthentication: async (identity) => {
        identities.push(identity as unknown as Record<string, unknown>);
        return { ok: true };
      },
    });
    const run = async () => {
      const begin = await service.begin('entra');
      const url = new URL(begin.url);
      nonce = url.searchParams.get('nonce')!;
      return {
        url,
        result: () =>
          service.callback(
            'entra',
            `${origin}/callback?code=c&state=${encodeURIComponent(begin.state)}`,
            begin.binding,
          ),
      };
    };
    return { service, identities, run };
  }

  it('signs in members of allowed directories with the concrete tenant issuer', async () => {
    const { identities, run } = login();
    const flow = await run();
    expect(flow.url.origin + flow.url.pathname).toBe(
      `${origin}/organizations/oauth2/v2.0/authorize`,
    );
    expect(flow.url.searchParams.get('scope')).toBe('openid email profile');
    await expect(flow.result()).resolves.toEqual({ ok: true });
    expect(identities[0]).toMatchObject({
      tenantId: 'a',
      providerId: 'entra',
      issuer: `${origin}/${CONTOSO}/v2.0`,
      subject: `pairwise-${CONTOSO}`,
      email: 'ada@contoso.test',
      // Entra emails are administrator-controlled: unverified unless the domain is verified (xms_edov).
      emailVerified: false,
    });
    issued = { tid: CONTOSO, xms_edov: true };
    await (await run()).result();
    expect(identities[1]).toMatchObject({ emailVerified: true });
  });

  it('refuses directories outside the allowlist and mismatched issuers', async () => {
    const { identities, run } = login();
    issued = { tid: FABRIKAM };
    await expect((await run()).result()).rejects.toMatchObject({
      code: 'OAUTH_TENANT',
      status: 403,
    });
    // An ID token whose issuer names another directory than its tid fails issuer validation.
    issued = { tid: CONTOSO, iss: `${origin}/${FABRIKAM}/v2.0` };
    await expect((await run()).result()).rejects.toThrow();
    expect(identities).toHaveLength(0);
  });

  it('forwards validated sign-in hints to the provider', async () => {
    const { service } = login();
    const begun = await service.begin('entra', undefined, {
      loginHint: 'ada@contoso.test',
      domainHint: 'contoso.test',
      prompt: 'select_account',
    });
    const url = new URL(begun.url);
    expect(url.searchParams.get('login_hint')).toBe('ada@contoso.test');
    expect(url.searchParams.get('domain_hint')).toBe('contoso.test');
    expect(url.searchParams.get('prompt')).toBe('select_account');
    // The HTTP start route takes the same hints as query parameters.
    const redirect = await service.handler(
      new Request(`${origin}/oauth/login/entra?login_hint=bob%40contoso.test&prompt=login`),
    );
    expect(redirect?.status).toBe(302);
    const location = new URL(redirect!.headers.get('location')!);
    expect(location.searchParams.get('login_hint')).toBe('bob@contoso.test');
    expect(location.searchParams.get('prompt')).toBe('login');
    await expect(
      service.begin('entra', undefined, { loginHint: '<script>' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      service.begin('entra', undefined, { prompt: 'always' as never }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const invalid = await service.handler(
      new Request(`${origin}/oauth/login/entra?domain_hint=not%20a%20domain`),
    );
    expect(invalid?.status).toBe(400);
  });

  it('supports single-tenant connections and validates configuration', async () => {
    const { identities, run } = login({
      microsoftTenant: CONTOSO,
      allowedMicrosoftTenants: undefined,
    });
    const flow = await run();
    expect(flow.url.pathname).toBe(`/${CONTOSO}/oauth2/v2.0/authorize`);
    await expect(flow.result()).resolves.toEqual({ ok: true });
    expect(identities).toEqual([expect.objectContaining({ issuer: `${origin}/${CONTOSO}/v2.0` })]);
    // The single-tenant issuer is concrete, so tokens from another directory fail validation.
    issued = { tid: FABRIKAM };
    await expect((await run()).result()).rejects.toThrow();
    expect(identities).toHaveLength(1);
    expect(() => login({ allowedMicrosoftTenants: undefined })).toThrow(/allowedMicrosoftTenants/);
    expect(() => login({ microsoftTenant: '../evil' })).toThrow(/microsoftTenant/);
  });
});
