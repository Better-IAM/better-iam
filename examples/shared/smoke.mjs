import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, createHash, randomUUID } from 'node:crypto';
import { mkdir, writeFile, rm, rmdir } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { request as nodeRequest } from 'node:http';
import { sqliteAdapter } from 'better-iam/adapter-sqlite';
import { postgresAdapter } from 'better-iam/adapter-postgres';

const requireAuth = createRequire(new URL('../../packages/auth/package.json', import.meta.url));
const { authenticator } = requireAuth('otplib');
const keyDirectory = new URL(`../../work/example-smoke-${randomUUID()}/`, import.meta.url);
const keyFile = new URL('oidc-keys.json', keyDirectory);
await mkdir(keyDirectory, { recursive: true });
const pair = generateKeyPairSync('rsa', { modulusLength: 2048 });
await writeFile(
  keyFile,
  JSON.stringify({
    jwks: {
      keys: [
        {
          ...pair.privateKey.export({ format: 'jwk' }),
          use: 'sig',
          alg: 'RS256',
          kid: randomUUID(),
        },
      ],
    },
    cookieKeys: [randomBytes(32).toString('base64url')],
    encryptionKey: randomBytes(32).toString('base64'),
  }),
  { flag: 'wx', mode: 0o600 },
);
process.env.BETTER_IAM_SECRET = randomBytes(32).toString('base64url');
process.env.BETTER_IAM_BASE_URL = 'http://localhost:3000';
process.env.DEMO_DELIVERY = '1';
process.env.OIDC_KEY_FILE = fileURLToPath(keyFile);
const { createExampleConfig, deliveryInbox } = await import('./config.mjs');
const { startExample } = await import('./server.mjs');
const postgresURL = process.env.BETTER_IAM_EXAMPLE_POSTGRES_URL;
const database = postgresURL
  ? postgresAdapter({ connectionString: postgresURL })
  : sqliteAdapter({ filename: ':memory:' });
const app = await startExample(createExampleConfig(database), { port: 0, quiet: true });
const address = app.server.address();
const target = `http://127.0.0.1:${address.port}`;
const cookies = new Map();
async function fetchLocal(
  path,
  { method = 'GET', input, form, bearer, captureCookies = true } = {},
) {
  const headers = { host: 'localhost:3000', origin: 'http://localhost:3000' };
  if (cookies.size)
    headers.cookie = [...cookies].map(([name, value]) => `${name}=${value}`).join('; ');
  if (bearer) headers.authorization = `Bearer ${bearer}`;
  if (input !== undefined) {
    headers['content-type'] = 'application/json';
    headers['x-better-iam'] = '1';
  }
  if (form !== undefined) headers['content-type'] = 'application/x-www-form-urlencoded';
  const response = await new Promise((resolve, reject) => {
    const outgoing = nodeRequest(`${target}${path}`, { method, headers }, (incoming) => {
      const chunks = [];
      incoming.on('data', (chunk) => chunks.push(chunk));
      incoming.on('error', reject);
      incoming.on('end', () => {
        const responseHeaders = new Headers();
        for (let index = 0; index < incoming.rawHeaders.length; index += 2)
          responseHeaders.append(incoming.rawHeaders[index], incoming.rawHeaders[index + 1]);
        resolve(
          new Response([204, 304].includes(incoming.statusCode) ? null : Buffer.concat(chunks), {
            status: incoming.statusCode,
            headers: responseHeaders,
          }),
        );
      });
    });
    outgoing.on('error', reject);
    outgoing.end(input !== undefined ? JSON.stringify(input) : form?.toString());
  });
  if (captureCookies)
    for (const cookie of response.headers.getSetCookie()) {
      const [name, ...value] = cookie.split(';')[0].split('=');
      cookies.set(name, value.join('='));
    }
  return response;
}
async function api(path, input = {}, bearer) {
  const response = await fetchLocal(`/api/iam/${path}`, { method: 'POST', input, bearer });
  const envelope = await response.json();
  assert.equal(response.status, 200, `${path}: ${envelope.error?.code ?? response.status}`);
  return envelope.data;
}
async function endpoint(path, input, bearer) {
  const response = await fetchLocal(path, { method: 'POST', input, bearer });
  const envelope = await response.json();
  assert.ok(response.ok, `${path}: ${envelope.error?.code ?? response.status}`);
  return envelope.data;
}

try {
  const root = await app.iam.bootstrap({
    email: 'root@example.com',
    name: 'Root',
    password: 'example-root-password',
  });
  assert.match(await (await fetchLocal('/')).text(), /Your product\. Your identity platform\./);
  const login = await api('auth/signIn', {
    tenantId: root.tenant.id,
    email: 'root@example.com',
    password: 'example-root-password',
  });
  assert.equal(login.mfaRequired, true);
  const credential = { tenantId: root.tenant.id, challenge: login.challenge };
  const enrollment = await api('auth/beginMfa', credential);
  const rootSession = await api('auth/confirmMfa', {
    credential,
    code: authenticator.generate(enrollment.secret),
  });
  const organization = await api('tenants/create', {
    parentId: root.tenant.id,
    type: 'organization',
    name: 'Smoke organization',
    ownerEmail: 'owner@example.com',
  });
  await app.iam.auth.dispatchOutbox();
  const invitation = [...deliveryInbox.values()].find(
    (message) => message.template === 'owner-invitation',
  );
  assert.ok(invitation);
  const ownerSession = await api('tenants/acceptInvitation', {
    tenantId: organization.tenant.id,
    token: invitation.payload.token,
    name: 'Owner',
    password: 'example-owner-password',
  });
  const tenantId = organization.tenant.id;
  const document = await endpoint('/app/documents', {
    tenantId,
    title: 'Protected smoke document',
  });
  await api('auth/signUp', {
    tenantId,
    email: 'reader@example.com',
    name: 'Reader',
    password: 'example-reader-password',
  });
  await app.iam.auth.dispatchOutbox();
  const verification = [...deliveryInbox.values()].find(
    (message) => message.template === 'verify-email' && message.to === 'reader@example.com',
  );
  assert.ok(verification);
  await api('auth/verifyEmail', { tenantId, token: verification.payload.token });
  const readerSession = await api('auth/signIn', {
    tenantId,
    email: 'reader@example.com',
    password: 'example-reader-password',
  });
  const denied = await fetchLocal(`/app/documents/${document.id}`);
  assert.equal(denied.status, 403);
  const identities = await api('identities/list', { tenantId }, ownerSession.token);
  const reader = identities.find((identity) => identity.email === 'reader@example.com');
  assert.ok(reader);
  const policy = await api(
    'policies/create',
    {
      tenantId,
      name: 'Read documents',
      document: {
        version: 1,
        statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['document/*'] }],
      },
    },
    ownerSession.token,
  );
  const role = await api(
    'roles/create',
    { tenantId, name: 'Reader', policyIds: [policy.id] },
    ownerSession.token,
  );
  await api(
    'bindings/create',
    { tenantId, roleId: role.id, subjectType: 'identity', subjectId: reader.id },
    ownerSession.token,
  );
  const allowed = await fetchLocal(`/app/documents/${document.id}`, {
    bearer: readerSession.token,
  });
  assert.equal(allowed.status, 200);
  // Organization aliases, member invitations, permission-based roles, tenant-defined resource types, managed resources, and batch checks.
  const aliased = await api(
    'tenants/create',
    {
      parentId: root.tenant.id,
      type: 'organization',
      name: 'Aliased organization',
      slug: 'smoke-org',
      ownerEmail: 'alias-owner@example.com',
    },
    rootSession.token,
  );
  assert.equal(
    (await fetchLocal('/api/iam/tenants/lookup', { method: 'POST', input: { slug: 'smoke-org' } }))
      .status,
    404,
  );
  await app.iam.auth.dispatchOutbox();
  const aliasInvitation = [...deliveryInbox.values()].find(
    (message) =>
      message.template === 'owner-invitation' && message.to === 'alias-owner@example.com',
  );
  assert.ok(aliasInvitation);
  const aliasOwner = await api('tenants/acceptInvitation', {
    tenantId: aliased.tenant.id,
    token: aliasInvitation.payload.token,
    name: 'Alias owner',
    password: 'example-alias-owner-password',
  });
  const orgId = (await api('tenants/lookup', { slug: 'smoke-org' })).tenantId;
  assert.equal(orgId, aliased.tenant.id);
  const invoiceType = await api(
    'resourceTypes/register',
    {
      tenantId: orgId,
      name: 'invoice',
      actions: ['read', 'approve'],
      attributes: { amount: 'number' },
    },
    aliasOwner.token,
  );
  assert.deepEqual(invoiceType.actions, ['invoice:read', 'invoice:approve']);
  const editor = await api(
    'roles/create',
    {
      tenantId: orgId,
      name: 'Editor',
      permissions: ['documents:read', 'workspaces:read', 'invoice:read'],
    },
    aliasOwner.token,
  );
  await api(
    'identities/invite',
    { tenantId: orgId, email: 'member@example.com', name: 'Member', roleIds: [editor.id] },
    aliasOwner.token,
  );
  await app.iam.auth.dispatchOutbox();
  const memberInvitation = [...deliveryInbox.values()].find(
    (message) => message.template === 'member-invitation' && message.to === 'member@example.com',
  );
  assert.ok(memberInvitation);
  const memberSession = await api('identities/acceptInvitation', {
    tenantId: orgId,
    token: memberInvitation.payload.token,
    password: 'example-member-password',
  });
  assert.equal(memberSession.identity.email, 'member@example.com');
  const workspace = await endpoint(
    '/app/workspaces',
    { tenantId: orgId, id: 'engineering' },
    aliasOwner.token,
  );
  assert.equal(workspace.resourceId, 'engineering');
  await api(
    'resources/register',
    { tenantId: orgId, type: 'invoice', id: 'inv-1', attributes: { amount: 250 } },
    aliasOwner.token,
  );
  assert.equal(
    (
      await fetchLocal('/app/workspaces', {
        method: 'POST',
        input: { tenantId: orgId, id: 'forbidden' },
        bearer: memberSession.token,
      })
    ).status,
    403,
  );
  const memberWorkspaces = await fetchLocal(`/app/workspaces?tenantId=${orgId}`, {
    bearer: memberSession.token,
  });
  assert.equal(memberWorkspaces.status, 200);
  assert.deepEqual((await memberWorkspaces.json()).data, [
    { id: 'engineering', archived: false, allowed: ['workspaces:read'] },
  ]);
  const batch = await api(
    'authorizeMany',
    {
      tenantId: orgId,
      checks: [
        { action: 'invoice:read', resource: { type: 'invoice', id: 'inv-1' } },
        { action: 'invoice:approve', resource: { type: 'invoice', id: 'inv-1' } },
      ],
    },
    memberSession.token,
  );
  assert.deepEqual(
    batch.results.map((result) => result.allowed),
    [true, false],
  );
  assert.deepEqual(await api('links/list', {}, memberSession.token), []);
  // Restore the ordinary owner cookie for the browser-style OIDC interaction.
  cookies.set('better-iam.session', ownerSession.token);
  await endpoint('/app/oauth/clients', { tenantId, clientId: 'smoke-browser-client' });
  const discoveryResponse = await fetchLocal('/oauth/.well-known/openid-configuration');
  assert.equal(discoveryResponse.status, 200);
  const discovery = await discoveryResponse.json();
  assert.equal(discovery.issuer, 'http://localhost:3000/oauth');
  const verifier = randomBytes(32).toString('base64url');
  const challenge = createHash('sha256').update(verifier).digest('base64url');
  const authorization = new URL(discovery.authorization_endpoint);
  for (const [key, value] of Object.entries({
    client_id: 'smoke-browser-client',
    redirect_uri: 'http://localhost:3000/oidc/callback',
    response_type: 'code',
    scope: 'openid email profile offline_access',
    state: 'smoke-state',
    code_challenge: challenge,
    code_challenge_method: 'S256',
  }))
    authorization.searchParams.set(key, value);
  const start = await fetchLocal(`${authorization.pathname}${authorization.search}`);
  assert.equal(
    start.status,
    303,
    `Authorization endpoint ${authorization.pathname}: ${start.status === 303 ? '' : await start.text()}`,
  );
  const interaction = new URL(start.headers.get('location'), 'http://localhost:3000');
  const interactionPage = await fetchLocal(interaction.pathname);
  assert.equal(interactionPage.status, 200);
  assert.match(await interactionPage.text(), /smoke-browser-client/);
  const consent = await fetchLocal(interaction.pathname, {
    method: 'POST',
    form: new URLSearchParams({ consent: 'yes' }),
  });
  assert.equal(consent.status, 303);
  const resume = new URL(consent.headers.get('location'), 'http://localhost:3000');
  const finished = await fetchLocal(`${resume.pathname}${resume.search}`);
  assert.equal(finished.status, 303);
  const callback = new URL(finished.headers.get('location'), 'http://localhost:3000');
  assert.equal(callback.searchParams.get('state'), 'smoke-state');
  assert.ok(
    callback.searchParams.get('code'),
    `OIDC callback error: ${callback.searchParams.get('error')}`,
  );
  const tokenEndpoint = new URL(discovery.token_endpoint);
  const tokenResponse = await fetchLocal(tokenEndpoint.pathname, {
    method: 'POST',
    form: new URLSearchParams({
      grant_type: 'authorization_code',
      code: callback.searchParams.get('code'),
      redirect_uri: 'http://localhost:3000/oidc/callback',
      client_id: 'smoke-browser-client',
      code_verifier: verifier,
    }),
  });
  const tokens = await tokenResponse.json();
  assert.equal(
    tokenResponse.status,
    200,
    `OIDC token error: ${tokens.error ?? tokenResponse.status}`,
  );
  assert.ok(tokens.access_token);
  assert.ok(tokens.id_token);
  const scim = await endpoint('/app/scim/connections', { tenantId, name: 'Smoke SCIM' });
  const scimCreate = await fetchLocal(`${scim.path}/Users`, {
    method: 'POST',
    bearer: scim.token,
    input: {
      schemas: ['urn:ietf:params:scim:schemas:core:2.0:User'],
      userName: 'provisioned@example.com',
      active: true,
    },
  });
  assert.equal(scimCreate.status, 201);
  const provisioned = await scimCreate.json();
  const scimDeactivate = await fetchLocal(`${scim.path}/Users/${provisioned.id}`, {
    method: 'PATCH',
    bearer: scim.token,
    input: {
      schemas: ['urn:ietf:params:scim:api:messages:2.0:PatchOp'],
      Operations: [{ op: 'replace', path: 'active', value: false }],
    },
  });
  assert.equal(scimDeactivate.status, 200);
  assert.equal((await scimDeactivate.json()).active, false);
  await api(
    'identities/setStatus',
    { tenantId, identityId: reader.id, status: 'disabled' },
    ownerSession.token,
  );
  assert.equal(
    (await fetchLocal(`/app/documents/${document.id}`, { bearer: readerSession.token })).status,
    401,
  );
  assert.ok(rootSession.token);
  console.log(
    `${postgresURL ? 'PostgreSQL' : 'SQLite'} example smoke checks passed: root MFA, owner and member invitations, organization aliases, custom roles, resource types, managed resources, batch checks, document policy enforcement, OAuth PKCE, and SCIM deprovisioning.`,
  );
} finally {
  await app.close();
  await rm(keyFile, { force: true });
  await rmdir(keyDirectory);
}
