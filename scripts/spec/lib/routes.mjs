// spec/api/routes.json: the HTTP route table of packages/server/src/http.ts, the live API surface of a betterIam()
// instance with every optional module enabled, the operational GET routes, and the protocol mounts.
import { generateKeyPairSync } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { lineOf, parse, stringSets, ts, visit } from './ts.mjs';
import { codePointCompare, dist, json, root } from './util.mjs';

const httpSource = 'packages/server/src/http.ts';

/** The text of `const name = ...` in a file, failing loudly when the declaration is gone (the spec must follow). */
async function constant(file, name) {
  const text = await readFile(join(root, file), 'utf8');
  const match = new RegExp(`const ${name}\\s*=\\s*([^;]+);`).exec(text);
  if (!match) throw new Error(`${file}: const ${name} not found`);
  return match[1].trim();
}

/** Asserts that a source file still contains a fragment the curated protocol table relies on. */
async function expect(file, fragments) {
  const text = await readFile(join(root, file), 'utf8');
  for (const fragment of fragments)
    if (!text.includes(fragment))
      throw new Error(
        `${file} no longer contains ${JSON.stringify(fragment)}: update scripts/spec/lib/routes.mjs`,
      );
}

/** A betterIam() instance with every optional module switched on (the API surface is the same either way). */
export async function fullInstance() {
  const server = await dist('server');
  const { sqliteAdapter } = await dist('adapter-sqlite');
  const key = (kid) => ({
    ...generateKeyPairSync('ed25519').privateKey.export({ format: 'jwk' }),
    kid,
    alg: 'EdDSA',
  });
  const database = sqliteAdapter({ filename: ':memory:' });
  const iam = server.betterIam({
    database,
    secret: 'spec-generator-secret-with-at-least-32-characters',
    baseURL: 'https://iam.example.com',
    authentication: { sendEmail: async () => {}, sendSms: async () => {}, passwordlessEmail: true },
    inference: true,
    ssh: true,
    verifiableCredentials: true,
    accessUsage: true,
    clearances: {},
    billing: {},
    vault: {},
    signals: {},
    sts: {
      jwt: { signingKeys: [key('spec-session')] },
      webIdentity: { enabled: true, allowedIssuers: ['https://issuer.example.com'] },
    },
    a2a: { signingKeys: [key('spec-card')] },
    observability: { metrics: { bearerToken: 'spec-metrics-token-0123456789abcdef' } },
    hosts: { patterns: ['{tenant}.example.com'] },
  });
  const minimal = server.betterIam({
    database,
    secret: 'spec-generator-secret-with-at-least-32-characters',
    baseURL: 'http://localhost:3000',
  });
  return { server, iam, minimal, close: () => database.close() };
}

const surface = (iam) =>
  Object.fromEntries(
    Object.keys(iam.api)
      .sort(codePointCompare)
      .map((group) => [group, Object.keys(iam.api[group]).sort(codePointCompare)]),
  );

export async function generateRoutes(output, { openapi }) {
  const { server, iam, minimal, close } = await fullInstance();
  const sourceFile = await parse(join(root, httpSource));
  const sets = stringSets(sourceFile);
  const set = (name) => {
    const found = sets.get(name);
    if (!found) throw new Error(`${httpSource}: Set ${name} not found`);
    if (found.values.some((value) => typeof value !== 'string'))
      throw new Error(`${httpSource}: Set ${name} has non-literal members`);
    return { values: [...found.values], line: found.line };
  };
  const publicAuth = set('publicAuthMethods');
  const authenticatedAuth = set('authenticatedAuthMethods');
  const routeGroups = set('routeGroups');
  const publicApi = set('publicApiMethods');
  const tenantBound = set('tenantBoundPublicMethods');
  const cookieRoutes = set('sessionCookieRoutes');
  const deviceRoutes = set('deviceTokenRoutes');
  // The exported sets must agree with what the module actually exports at runtime.
  for (const [name, parsed] of [
    ['publicAuthMethods', publicAuth],
    ['authenticatedAuthMethods', authenticatedAuth],
    ['routeGroups', routeGroups],
    ['publicApiMethods', publicApi],
  ]) {
    const live = [...server[name]];
    if (JSON.stringify(live) !== JSON.stringify(parsed.values))
      throw new Error(`${name}: parsed source and runtime export differ`);
  }

  const live = surface(iam);
  const liveMinimal = surface(minimal);
  if (JSON.stringify(live) !== JSON.stringify(liveMinimal))
    throw new Error('The API surface depends on options; routes.json assumes it does not');
  await close();

  // Every RPC route the handler dispatches.
  const rpc = [];
  const notRouted = [];
  for (const [group, methods] of Object.entries(live)) {
    for (const method of methods) {
      const path = `${group}/${method}`;
      if (group === 'auth') {
        const isPublic = publicAuth.values.includes(method);
        const isAuthenticated = authenticatedAuth.values.includes(method);
        if (!isPublic && !isAuthenticated) {
          notRouted.push(path);
          continue;
        }
        rpc.push({
          path,
          group,
          method,
          credential: isPublic ? 'none' : 'required',
          call:
            method === 'beginMfa' || method === 'confirmMfa'
              ? method
              : isPublic
                ? 'input'
                : 'credential, input',
          tenantBound: isPublic,
          setsSessionCookie: cookieRoutes.values.includes(path),
          readsDeviceCookie: deviceRoutes.values.includes(path),
        });
        continue;
      }
      if (!routeGroups.values.includes(group)) {
        notRouted.push(path);
        continue;
      }
      const isPublic = publicApi.values.includes(path);
      rpc.push({
        path,
        group,
        method,
        credential: isPublic ? 'none' : 'required',
        call: isPublic ? 'input' : 'credential, input',
        tenantBound: isPublic && tenantBound.values.includes(path),
        setsSessionCookie: cookieRoutes.values.includes(path),
        readsDeviceCookie: deviceRoutes.values.includes(path),
      });
    }
  }
  rpc.sort((a, b) => codePointCompare(a.path, b.path));

  // Cross-check against the OpenAPI document generated from the same instance.
  const documented = new Set(
    Object.entries(openapi.paths)
      .filter(([, item]) => item.post)
      .map(([path]) => path.slice(1)),
  );
  const routed = new Set(rpc.map((route) => route.path));
  const missing = [...routed].filter((path) => !documented.has(path));
  const extra = [...documented].filter((path) => !routed.has(path));
  if (missing.length || extra.length)
    throw new Error(
      `routes.json and openapi.json disagree: undocumented ${missing.join(', ') || '-'}; unrouted ${extra.join(', ') || '-'}`,
    );
  for (const route of rpc) {
    const operation = openapi.paths[`/${route.path}`].post;
    const documentedPublic = Array.isArray(operation.security) && operation.security.length === 0;
    if (documentedPublic !== (route.credential === 'none'))
      throw new Error(`${route.path}: credential requirement differs from openapi.json`);
  }
  // Every member of the route sets must name a live route.
  for (const [name, entries] of [
    ['publicApiMethods', publicApi.values],
    ['tenantBoundPublicMethods', tenantBound.values],
    ['sessionCookieRoutes', cookieRoutes.values],
    ['deviceTokenRoutes', deviceRoutes.values],
  ])
    for (const path of entries)
      if (!routed.has(path)) throw new Error(`${name} names ${path}, which is not routed`);

  // Constants of the handler, read from the source so drift fails generation.
  const http = await readFile(join(root, httpSource), 'utf8');
  const need = (pattern, label) => {
    const match = pattern.exec(http);
    if (!match) throw new Error(`${httpSource}: ${label} not found`);
    return match;
  };
  const apiBodyLimit = Number(need(/limitedBody\(request, (\d+)\)/, 'API body limit')[1]);
  const [, nodeApiLimit, nodeOtherLimit] = need(
    /const maxBody = url\.pathname\.startsWith\(`\$\{basePath\}\/`\) \? (\d+) : (\d+);/,
    'node body limits',
  ).map(Number);
  const allowHeaders = need(/'access-control-allow-headers':\s*'([^']+)'/, 'CORS allow headers')[1];
  const allowMethods = need(/'access-control-allow-methods': '([^']+)'/, 'CORS allow methods')[1];
  const exposeHeaders = need(
    /'access-control-expose-headers'\] = '([^']+)'/,
    'CORS expose headers',
  )[1];
  const requestIdPattern = need(/value && (\/\^[^/]+\/)\.test\(value\)/, 'request id pattern')[1];
  const rejectedNodeMethods = need(/\[('TRACE', 'CONNECT', 'TRACK')\]\.includes/, 'node methods')[1]
    .split(',')
    .map((item) => item.trim().slice(1, -1));
  const hardened = {};
  for (const [, key, value] of need(/const hardened = \{([^}]+)\}/, 'hardened headers')[1].matchAll(
    /'([a-z-]+)': '([^']+)'/g,
  ))
    hardened[key] = value;

  const signalsSource = 'packages/server/src/signal-receiver.ts';
  const vcSource = 'packages/server/src/api/verifiable-credentials.ts';
  await expect(vcSource, [
    "const wellKnown = ['openid-credential-issuer', 'jwt-vc-issuer', 'oauth-authorization-server']",
    "if (rest === 'token') return await tokenEndpoint(request, tenantId);",
    "if (rest === 'nonce')",
    "if (rest === 'credential') return await credentialEndpoint(request, tenantId);",
    "if (rest === 'jwks.json')",
    "if (rest.startsWith('types/'))",
    "if (rest.startsWith('status/'))",
  ]);
  await expect('packages/saml/src/index.ts', [
    "const basePath = (config.basePath ?? '/saml')",
    "parts[1] === 'acs' && parts.length === 2",
    "parts[1] === 'metadata' && parts.length === 2",
    "parts[1] !== 'login'",
  ]);
  await expect('packages/scim/src/index.ts', [
    "const basePath = (config.basePath ?? '/scim/v2')",
    "const adminBasePath = (config.adminBasePath ?? '/scim/admin')",
    "'connections/list'",
    "'connections/create'",
    "'connections/rotate'",
    "'connections/revoke'",
    "'connections/groups'",
    "'connections/mappings'",
  ]);
  await expect('packages/oauth/src/client.ts', [
    "const basePath = (config.basePath ?? '/oauth/login')",
  ]);
  await expect('packages/oauth/src/provider.ts', [
    'const oauthDiscovery = `/.well-known/oauth-authorization-server${basePath}`;',
    'devInteractions: { enabled: false }',
    'registrationManagement: { enabled: false }',
  ]);
  await expect('packages/oauth/src/ssf.ts', ['`/.well-known/ssf-configuration${']);
  await expect('packages/oauth/src/resource-server.ts', ['/.well-known/oauth-protected-resource']);
  await expect('packages/ldap/src/server.ts', [
    "listen(port = options.tls ? 636 : 389, host = '127.0.0.1')",
  ]);
  const scimTypes = await readFile(join(root, 'packages/scim/src/types.ts'), 'utf8');
  const scimNumber = (name) => {
    const match = new RegExp(`export const ${name} = ([^;]+);`).exec(scimTypes);
    if (!match) throw new Error(`scim types: ${name} not found`);
    return Function(`return (${match[1]})`)();
  };

  const value = {
    source: httpSource,
    basePath: '/api/iam',
    description:
      'Every route the TypeScript server answers. RPC routes are POST {basePath}/{path} with a JSON object body; `credential: "none"` routes ignore request credentials, others authenticate with a bearer token or the session cookie. Ports must answer exactly this set.',
    request: {
      apiPrefix: '{basePath}/',
      notUnderBasePath: {
        status: 404,
        body: { error: { code: 'NOT_FOUND', message: 'Not found' } },
      },
      requestIdHeader: { name: 'x-request-id', pattern: requestIdPattern, echoed: true },
      cors: {
        trustedOrigins:
          'config.trustedOrigins plus organization hosts (ctx.hosts.trustsOrigin); an untrusted Origin is refused with UNTRUSTED_ORIGIN 403 and no CORS headers',
        responseHeaders: {
          'access-control-allow-origin': '{origin}',
          'access-control-allow-credentials': 'true',
          'access-control-expose-headers': exposeHeaders,
          vary: 'Origin',
        },
        preflight: {
          method: 'OPTIONS',
          status: 204,
          headers: {
            'access-control-allow-methods': allowMethods,
            'access-control-allow-headers': allowHeaders,
          },
        },
      },
      methods: {
        GET: 'operational routes (below)',
        POST: 'RPC routes',
        OPTIONS: 'CORS preflight (204)',
        other: { code: 'METHOD_NOT_ALLOWED', status: 405, message: 'Use POST' },
        rejectedByNodeTransport: rejectedNodeMethods,
      },
      csrf: [
        {
          rule: 'content-type must start with application/json (case-insensitive) and X-Better-IAM must be 1',
          code: 'CSRF_REJECTED',
          status: 403,
          message: 'JSON and X-Better-IAM header required',
        },
        {
          rule: 'a request carrying a Cookie header must carry an Origin header',
          code: 'CSRF_REJECTED',
          status: 403,
          message: 'Cookie requests require Origin',
        },
      ],
      body: {
        limitBytes: apiBodyLimit,
        tooLarge: { code: 'PAYLOAD_TOO_LARGE', status: 413, message: 'Request body too large' },
        invalidJson: { code: 'INVALID_INPUT', status: 400, message: 'Invalid JSON' },
        mustBeObject: true,
        emptyBody: '{}',
      },
      nodeTransport: {
        bodyLimitUnderBasePath: nodeApiLimit,
        bodyLimitElsewhere: nodeOtherLimit,
        tooLarge: { status: 413, body: 'Request too large' },
        invalidTarget: { code: 'INVALID_REQUEST', status: 400, message: 'Invalid request target' },
      },
      hostPinning:
        "Public routes that are tenant-bound (every public auth method and tenantBoundPublicMethods) take the organization of the request's host: a missing tenantId is filled in, a different one fails with HOST_MISMATCH 403 ('This address belongs to another organization'); without a pinned host the named tenant must be served by this region (WRONG_REGION). auth/confirmMfa also pins body.credential.tenantId.",
      bearerPrecedence:
        'A request with an Authorization header on a non-public route never sets or clears the session cookie.',
    },
    response: {
      success: { status: 200, body: '{ "data": <result> }', headers: hardened },
      sessionProjection:
        'A top-level result.session loses tokenHash and uniqueKey before serialization.',
      error: {
        body: '{ "error": { "code", "message", "retryAfterMs"?, "region"?, "location"? } }',
        headers: {
          ...hardened,
          'retry-after': 'ceil(retryAfterMs / 1000), when the error carries retryAfterMs > 0',
        },
        unknownError: { code: 'INTERNAL_ERROR', status: 500, message: 'Internal server error' },
      },
      cookies: {
        session: {
          name: 'better-iam.session (prefixed __Host- when baseURL is https)',
          attributes:
            'HttpOnly; Secure (https only); SameSite=Lax|Strict (http.cookieSameSite); Path=/; Max-Age=<seconds until session.expiresAt> when persistent',
          persistence:
            'X-Better-IAM-Persistent: 1 or 0 on the request decides; otherwise http.persistentCookies (default true)',
          setBy:
            'sessionCookieRoutes (and protocol mounts answering JSON with token and session.expiresAt), unless the request used a bearer credential',
          clearedBy:
            'auth/signOut (Max-Age=0, also when the sign-out fails), unless the request used a bearer credential',
        },
        device: {
          name: 'better-iam.device (prefixed __Host- when baseURL is https)',
          setBy: 'any result with string deviceToken and number deviceExpiresAt',
          readBy: 'deviceTokenRoutes: injected as body.deviceToken when the body has none',
          clearedBy: 'auth/revokeTrustedDevices',
        },
      },
    },
    sets: {
      publicAuthMethods: publicAuth.values,
      authenticatedAuthMethods: authenticatedAuth.values,
      routeGroups: routeGroups.values,
      publicApiMethods: publicApi.values,
      tenantBoundPublicMethods: tenantBound.values,
      sessionCookieRoutes: cookieRoutes.values,
      deviceTokenRoutes: deviceRoutes.values,
    },
    rpc,
    special: [
      {
        path: 'authorize',
        credential: 'required',
        body: {
          tenantId: 'text',
          action: 'text',
          resource: { type: 'text (resource type)', id: 'text (resource id)' },
        },
        calls: 'operations.authorize',
      },
      {
        path: 'authorizeMany',
        credential: 'required',
        body: { tenantId: 'text', checks: 'AuthorizationCheck[]' },
        calls: 'operations.authorizeMany',
      },
      {
        path: 'listAccessible',
        credential: 'required',
        body: {
          tenantId: 'text',
          action: 'text',
          type: 'text, at most 64 (resource type)',
          limit: 'number?',
          offset: 'number?',
        },
        calls: 'operations.listAccessible',
      },
      {
        path: 'plugins/{pluginId}/{endpointPath...}',
        credential: 'required',
        body: { tenantId: 'text', '...': 'passed to the plugin endpoint as input' },
        calls: 'operations.callPlugin({ pluginId, path, tenantId, input: body })',
        spanName: 'plugins/{pluginId}/{path} for a registered POST endpoint, otherwise (unknown)',
      },
    ],
    dispatch: {
      notFound: { code: 'NOT_FOUND', status: 404, message: 'Endpoint not found' },
      rules: [
        'path = pathname without "{basePath}/"; authorize, authorizeMany, listAccessible and plugins/* first',
        'otherwise exactly two segments group/method; more or fewer is NOT_FOUND',
        'auth methods: publicAuthMethods are called with the body, authenticatedAuthMethods with (credential, body); others NOT_FOUND',
        'other groups must be in routeGroups and have an own method of that name; publicApiMethods are called with the body, others with (credential, body)',
        'auth/beginMfa: { tenantId, challenge } when body.challenge is a string, else the request credential',
        'auth/confirmMfa: credential = body.credential { tenantId, challenge } when its challenge is a string, else the request credential; code = text(body.code); rememberDevice = body.rememberDevice === true',
      ],
      spanName: 'the route path when the route table knows it, otherwise (unknown)',
    },
    apiGroupsNotRouted: notRouted.sort(codePointCompare),
    operational: [
      {
        method: 'GET',
        path: '{basePath}/health',
        response: {
          status: 200,
          body: { status: 'ok', database: 'ok', latencyMs: 'number', time: 'epoch ms' },
        },
        failure: {
          status: 503,
          body: { status: 'unavailable', database: 'error', time: 'epoch ms' },
        },
        probe: "store.get('tenants', 'health-probe')",
      },
      {
        method: 'GET',
        path: '{basePath}/.well-known/jwks.json',
        requires: 'sts.jwt',
        headers: {
          'cache-control': 'public, max-age=300',
          'content-type': 'application/jwk-set+json',
        },
        response: '{ keys: PublicSessionJwk[] }',
        absent: { code: 'NOT_FOUND', status: 404, message: 'Endpoint not found' },
      },
      {
        method: 'GET',
        path: '{basePath}/metrics',
        requires: 'observability.metrics.bearerToken',
        auth: 'Authorization: Bearer <bearerToken>, compared as SHA-256 digests',
        refused: {
          code: 'UNAUTHENTICATED',
          status: 401,
          message: 'A metrics bearer token is required',
        },
        headers: { 'content-type': 'text/plain; version=0.0.4; charset=utf-8' },
        gauges:
          'with observability.metrics.gauges: better_iam_outbox_messages{state} and better_iam_sessions_live{kind}',
      },
      {
        method: 'GET',
        path: '{basePath}/*',
        otherwise: { code: 'NOT_FOUND', status: 404, message: 'Endpoint not found' },
      },
    ],
    protocols: [
      {
        name: 'OpenID4VCI issuer (built in)',
        enabledBy: 'verifiableCredentials',
        source: vcSource,
        tenantPattern: '^[A-Za-z0-9_-]{1,128}$',
        routes: [
          { method: 'GET', path: '/.well-known/openid-credential-issuer{basePath}/vc/{tenantId}' },
          { method: 'GET', path: '/.well-known/jwt-vc-issuer{basePath}/vc/{tenantId}' },
          {
            method: 'GET',
            path: '/.well-known/oauth-authorization-server{basePath}/vc/{tenantId}',
          },
          { method: 'GET', path: '{basePath}/vc/{tenantId}/jwks.json' },
          { method: 'GET', path: '{basePath}/vc/{tenantId}/types/{typeName}' },
          {
            method: 'GET',
            path: '{basePath}/vc/{tenantId}/status/{listId}',
            contentType: 'application/statuslist+jwt',
          },
          {
            method: 'POST',
            path: '{basePath}/vc/{tenantId}/token',
            contentType: 'application/x-www-form-urlencoded',
            bodyLimit: 8192,
          },
          { method: 'POST', path: '{basePath}/vc/{tenantId}/nonce' },
          { method: 'POST', path: '{basePath}/vc/{tenantId}/credential', bodyLimit: 16384 },
          { method: 'OPTIONS', path: '{basePath}/vc/{tenantId}/*', status: 204 },
        ],
        errors:
          '404 { error: "not_found" }; IamError -> { error: "invalid_request" | "not_found", error_description }; other -> 500 { error: "server_error" }',
      },
      {
        name: 'Shared Signals push receiver (built in, RFC 8935)',
        enabledBy: 'always mounted',
        source: signalsSource,
        routes: [
          {
            method: 'POST',
            path: '{signals.pushPath}/{sourceId}',
            defaultPushPath: '{basePath}/signals/push',
            sourceIdPattern: (await constant(signalsSource, 'sourceIdShape')).slice(1, -1),
            contentType: 'application/secevent+jwt',
            bodyLimit: Number((await constant(signalsSource, 'MAX_PUSH_BYTES')).replace(/_/g, '')),
            rateLimitPerWindow: Number(
              (await constant(signalsSource, 'PUSHES_PER_WINDOW')).replace(/_/g, ''),
            ),
            responses:
              '202 empty; { err, description } with 400, 401, 403, 404, 405 (allow: POST), 413, 415, 429 (retry-after), 503 (retry-after: 30)',
          },
        ],
      },
      {
        name: 'OAuth 2.1 / OpenID Connect provider (@better-iam/oauth createOAuthProvider, oidc-provider 9)',
        mount: 'iam.useProtocol(provider): Node transport; basePath = issuer pathname',
        source: 'packages/oauth/src/provider.ts',
        routes: [
          {
            method: 'GET',
            path: '/.well-known/oauth-authorization-server{basePath}',
            note: 'rewritten to the provider discovery document',
          },
          { method: 'GET', path: '{basePath}/.well-known/oauth-authorization-server' },
          { method: 'GET', path: '{basePath}/.well-known/openid-configuration' },
          { method: 'GET', path: '{basePath}/auth' },
          { method: 'GET', path: '{basePath}/auth/{uid}', note: 'resume after interaction' },
          { method: 'POST', path: '{basePath}/token' },
          { method: 'GET', path: '{basePath}/jwks' },
          { method: 'GET|POST', path: '{basePath}/me', note: 'userinfo' },
          { method: 'POST', path: '{basePath}/token/revocation' },
          { method: 'POST', path: '{basePath}/token/introspection' },
          { method: 'POST', path: '{basePath}/request', note: 'pushed authorization requests' },
          { method: 'POST', path: '{basePath}/device/auth' },
          {
            method: 'GET|POST',
            path: '{basePath}/device',
            note: 'user code entry and confirmation',
          },
          { method: 'GET', path: '{basePath}/device/{uid}' },
          { method: 'GET', path: '{basePath}/session/end' },
          { method: 'POST', path: '{basePath}/session/end/confirm' },
          { method: 'GET', path: '{basePath}/session/end/success' },
          {
            method: 'POST',
            path: '{basePath}/reg',
            requires: 'registration option (gated by registration tokens / anonymous hook)',
          },
          { method: 'GET', path: '{basePath}/reg/{clientId}', requires: 'registration option' },
          {
            method: 'OPTIONS',
            path: 'CORS preflight on token, jwks, discovery, userinfo, revocation, introspection, device/auth, request',
          },
        ],
        features:
          'clientCredentials, PAR, DPoP, resourceIndicators, introspection, revocation, deviceFlow, backchannelLogout, rpInitiatedLogout; pkce required; responseTypes [code]',
      },
      {
        name: 'OAuth / OIDC federated sign-in (@better-iam/oauth createOAuthLogin)',
        source: 'packages/oauth/src/client.ts',
        defaultBasePath: '/oauth/login',
        routes: [
          {
            method: 'GET',
            path: '{basePath}/{connectionId}',
            response: '302 to the identity provider; sets the binding cookie',
          },
          {
            method: 'POST',
            path: '{basePath}/{connectionId}',
            response: '{ url }; requires trusted Origin, X-Better-IAM: 1 and JSON (CSRF 403)',
          },
          {
            method: 'GET',
            path: '{connection.redirectUri}',
            response: 'the sign-in result as JSON (session cookie set by the IAM handler)',
          },
          {
            method: 'other',
            path: '{basePath}/*',
            response: '405 { error: "METHOD_NOT_ALLOWED" }',
          },
        ],
      },
      {
        name: 'SAML 2.0 service provider (@better-iam/saml createSamlService)',
        source: 'packages/saml/src/index.ts',
        defaultBasePath: '/saml',
        routes: [
          { method: 'POST', path: '{basePath}/{connectionId}/acs' },
          {
            method: 'POST',
            path: '{connection.callbackUrl}',
            note: 'a connection with its own ACS URL',
          },
          {
            method: 'GET',
            path: '{basePath}/{connectionId}/metadata',
            contentType: 'application/samlmetadata+xml',
          },
          { method: 'GET', path: '{basePath}/{connectionId}/login', response: '302 to the IdP' },
          {
            method: 'POST',
            path: '{basePath}/{connectionId}/login',
            response: '{ url }; requires trusted Origin, X-Better-IAM: 1 and JSON (CSRF 403)',
          },
        ],
        errors:
          '404 { error: "NOT_FOUND" }; failures { error: <code> } with the IamError status or 401 SAML_FAILED',
      },
      {
        name: 'SCIM 2.0 server (@better-iam/scim createScimService, RFC 7644)',
        source: 'packages/scim/src/index.ts',
        defaultBasePath: '/scim/v2',
        defaultAdminBasePath: '/scim/admin',
        bodyLimit: scimNumber('MAX_PAYLOAD_SIZE'),
        bulkMaxOperations: scimNumber('BULK_MAX_OPERATIONS'),
        adminBodyLimit: 64 * 1024,
        routes: [
          { method: 'GET', path: '{basePath}/{connectionId}/ServiceProviderConfig' },
          { method: 'GET', path: '{basePath}/{connectionId}/ResourceTypes[/{id}]' },
          { method: 'GET', path: '{basePath}/{connectionId}/Schemas[/{id}]' },
          { method: 'GET', path: '{basePath}/{connectionId}/{Users|Groups}' },
          { method: 'POST', path: '{basePath}/{connectionId}/{Users|Groups}' },
          { method: 'POST', path: '{basePath}/{connectionId}/{Users|Groups}/.search' },
          { method: 'GET|PUT|PATCH|DELETE', path: '{basePath}/{connectionId}/{Users|Groups}/{id}' },
          { method: 'POST', path: '{basePath}/{connectionId}/Bulk' },
          ...['list', 'create', 'rotate', 'revoke', 'groups', 'mappings'].map((name) => ({
            method: 'POST',
            path: `{adminBasePath}/connections/${name}`,
            note: 'JSON admin API: X-Better-IAM: 1, same-origin Origin, { data } / { error: { code, message } }',
          })),
        ],
      },
      {
        name: 'Shared Signals transmitter metadata (@better-iam/oauth createSharedSignalsTransmitter)',
        source: 'packages/oauth/src/ssf.ts',
        routes: [
          {
            method: 'GET|HEAD',
            path: '/.well-known/ssf-configuration{issuer path}',
            other: '405 allow: GET, HEAD',
          },
        ],
      },
      {
        name: 'OAuth protected resource metadata (@better-iam/oauth createProtectedResourceHandler, RFC 9728)',
        source: 'packages/oauth/src/resource-server.ts',
        routes: [
          {
            method: 'GET|HEAD|OPTIONS',
            path: '/.well-known/oauth-protected-resource{resource path}',
          },
        ],
      },
      {
        name: 'LDAP directory gateway (@better-iam/ldap createLdapServer)',
        source: 'packages/ldap/src/server.ts',
        transport: 'LDAPv3 over TCP (default port 389) or TLS (636), default host 127.0.0.1',
        operations: {
          bind: 'simple binds only (SASL: authMethodNotSupported; no password: unwillingToPerform)',
          unbind: 'closes the connection',
          search: 'read-only directory search, paged results control',
          compare: 'supported',
          extended: 'Who am I? (1.3.6.1.4.1.4203.1.11.3) only',
          abandon: 'ignored',
          other: 'unwillingToPerform: "This directory is read-only"',
        },
      },
    ],
  };
  output.add('api/routes.json', json(value));
  return `routes.json (${rpc.length} RPC routes, ${notRouted.length} API methods not routed, ${value.special.length} special, ${value.operational.length} operational, ${value.protocols.length} protocol mounts)`;
}

export { lineOf, ts, visit };
