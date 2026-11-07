import { afterEach, describe, expect, it } from 'vitest';
import { createScimService, type ScimUserLink } from '@better-iam/scim';
import type { Identity } from '@better-iam/core';
import { closeFixtures, organizationFixture } from './support/organization.js';

const USER = 'urn:ietf:params:scim:schemas:core:2.0:User';
const ENTERPRISE = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
const CUSTOM = 'urn:ietf:params:scim:schemas:extension:acme:2.0:User';
const PATCH = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const ORIGIN = 'http://localhost:3000';

afterEach(closeFixtures);

/** An organization with a SCIM connection whose requests go straight to the SCIM service. */
async function directory(options: { unsupportedAttributes?: 'ignore' | 'reject' } = {}) {
  const f = await organizationFixture();
  const scim = createScimService({ ...f.iam.protocolHost, ...options });
  const connection = await scim.createConnection(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Directory',
  });
  const request = async (resource: string, method = 'GET', body?: unknown) =>
    (await scim.handler(
      new Request(`https://iam.test${connection.path}/${resource}`, {
        method,
        headers: {
          authorization: `Bearer ${connection.token}`,
          'content-type': 'application/scim+json',
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      }),
    ))!;
  const identityOf = async (user: { id: string }) => {
    const link = (await f.database.get<ScimUserLink>('scimUsers', user.id))!;
    return (await f.database.get<Identity>('identities', link.identityId))!;
  };
  return { ...f, scim, connection, request, identityOf };
}

/** What an IdP-backed sign-in hands the server (the SAML/OAuth packages call this with verified claims). */
const federated = (
  f: Awaited<ReturnType<typeof organizationFixture>>,
  input: {
    subject: string;
    email: string;
    emailVerified?: boolean;
    trustScimProvisioned?: boolean | string[];
    providerId?: string;
  },
) =>
  f.iam.protocolHost.completeAuthentication({
    tenantId: f.tenantId,
    providerId: input.providerId ?? 'acme-okta',
    issuer: 'https://acme.okta.test',
    subject: input.subject,
    email: input.email,
    emailVerified: input.emailVerified ?? true,
    ...(input.trustScimProvisioned !== undefined
      ? { trustScimProvisioned: input.trustScimProvisioned }
      : {}),
  }) as Promise<{ token?: string; session?: { identityId: string } }>;

describe('SCIM attributes the service does not store', () => {
  it('ignores read-only and unsupported core attributes and foreign extensions in POST, PUT and PATCH', async () => {
    const d = await directory();
    // An Entra ID style create: defaults Better IAM has no place for, plus read-only attributes echoed back.
    const created = await d.request('Users', 'POST', {
      schemas: [USER, ENTERPRISE, CUSTOM],
      id: 'client-chosen',
      meta: { resourceType: 'User' },
      groups: [{ value: 'g1' }],
      userName: 'ada@acme.test',
      active: true,
      displayName: 'Ada',
      preferredLanguage: 'en-US',
      locale: 'en-US',
      password: 'never stored',
      addresses: [{ type: 'work', formatted: '1 Main St', primary: true }],
      phoneNumbers: [{ type: 'work', value: '+1 555 0100' }],
      emails: [{ value: 'ada@acme.test', type: 'work', primary: true }],
      [ENTERPRISE]: { department: 'Finance' },
      [CUSTOM]: { badge: 'gold' },
    });
    expect(created.status).toBe(201);
    const user = (await created.json()) as Record<string, unknown> & { id: string };
    expect(user.id).not.toBe('client-chosen');
    expect(user).not.toHaveProperty('addresses');
    expect(user).not.toHaveProperty('preferredLanguage');
    expect(user.schemas).not.toContain(CUSTOM);
    expect(user[ENTERPRISE]).toEqual({ department: 'Finance' });
    expect(JSON.stringify(await d.database.get('scimUsers', user.id))).not.toContain(
      'never stored',
    );

    // PUT with the full resource as the IdP last saw it (id and meta included).
    const replaced = await d.request(`Users/${user.id}`, 'PUT', {
      ...user,
      displayName: 'Ada Lovelace',
      phoneNumbers: [{ type: 'mobile', value: '+1 555 0101' }],
    });
    expect(replaced.status).toBe(200);
    expect((await replaced.json()).displayName).toBe('Ada Lovelace');

    // Entra PATCH: unsupported paths (value filters, core-qualified names, pathless values) are skipped, supported
    // ones in the same request still apply.
    const patched = await d.request(`Users/${user.id}`, 'PATCH', {
      schemas: [PATCH],
      Operations: [
        { op: 'replace', path: 'phoneNumbers[type eq "work"].value', value: '+1 555 0199' },
        { op: 'replace', path: 'addresses[type eq "work"].formatted', value: '2 Main St' },
        { op: 'add', path: `${USER}:preferredLanguage`, value: 'fr-FR' },
        { op: 'replace', path: `${CUSTOM}:badge`, value: 'silver' },
        { op: 'replace', value: { title: 'Controller', locale: 'fr-FR', meta: {} } },
        { op: 'replace', path: `${ENTERPRISE}:department`, value: 'Treasury' },
        { op: 'remove', path: 'addresses' },
      ],
    });
    expect(patched.status).toBe(200);
    const after = (await patched.json()) as Record<string, unknown>;
    expect(after.title).toBe('Controller');
    expect(after[ENTERPRISE]).toEqual({ department: 'Treasury' });
    expect(after).not.toHaveProperty('locale');

    // Attributes no supported schema defines are still errors, so typos are not silently dropped.
    for (const body of [
      { userName: 'ada@acme.test', badge: 'gold' },
      { userName: 'ada@acme.test', [ENTERPRISE]: { badge: 'gold' } },
      { userName: 'ada@acme.test', name: { nickname: 'A' } },
    ]) {
      const refused = await d.request(`Users/${user.id}`, 'PUT', body);
      expect(refused.status).toBe(400);
      expect((await refused.json()).scimType).toBe('mutability');
    }
    const badPath = await d.request(`Users/${user.id}`, 'PATCH', {
      schemas: [PATCH],
      Operations: [{ op: 'replace', path: 'badge', value: 'x' }],
    });
    expect(badPath.status).toBe(400);
  });

  it("rejects unsupported attributes with unsupportedAttributes: 'reject', still ignoring read-only ones", async () => {
    const d = await directory({ unsupportedAttributes: 'reject' });
    const refused = await d.request('Users', 'POST', {
      userName: 'ada@acme.test',
      addresses: [{ formatted: '1 Main St' }],
    });
    expect(refused.status).toBe(400);
    expect((await refused.json()).scimType).toBe('mutability');
    const foreign = await d.request('Users', 'POST', {
      schemas: [USER, CUSTOM],
      userName: 'ada@acme.test',
    });
    expect(foreign.status).toBe(400);
    const created = await d.request('Users', 'POST', {
      id: 'ignored',
      meta: { resourceType: 'User' },
      userName: 'ada@acme.test',
    });
    expect(created.status).toBe(201);
    const user = (await created.json()) as { id: string };
    const patch = await d.request(`Users/${user.id}`, 'PATCH', {
      schemas: [PATCH],
      Operations: [{ op: 'replace', path: 'preferredLanguage', value: 'en' }],
    });
    expect(patch.status).toBe(400);
    expect(() =>
      createScimService({
        ...d.iam.protocolHost,
        unsupportedAttributes: 'drop' as unknown as 'ignore',
      }),
    ).toThrow(/unsupportedAttributes/);
  });
});

describe('first SSO sign-in of SCIM-provisioned people', () => {
  it('links to the SCIM account only when the connection trusts that SCIM connection', async () => {
    const d = await directory();
    const created = await d.request('Users', 'POST', {
      userName: 'ada@acme.test',
      emails: [{ value: 'ada@acme.test', primary: true }],
    });
    const user = (await created.json()) as { id: string };
    const identity = await d.identityOf(user);
    expect(identity.emailVerified).toBe(false);

    // Without trust, or with an unverified email, or trusting another SCIM connection: no link.
    await expect(
      federated(d, { subject: 'okta-ada', email: 'ada@acme.test' }),
    ).rejects.toMatchObject({
      code: 'ACCOUNT_LINK_REQUIRED',
    });
    await expect(
      federated(d, {
        subject: 'okta-ada',
        email: 'ada@acme.test',
        emailVerified: false,
        trustScimProvisioned: true,
      }),
    ).rejects.toMatchObject({ code: 'VERIFIED_EMAIL_REQUIRED' });
    await expect(
      federated(d, {
        subject: 'okta-ada',
        email: 'ada@acme.test',
        trustScimProvisioned: ['another-connection'],
      }),
    ).rejects.toMatchObject({ code: 'ACCOUNT_LINK_REQUIRED' });

    // A federated-only tenant: the trusted connection signs Ada in to the provisioned account and links it.
    await d.iam.api.tenants.setAuthPolicy(await d.ownerSignIn(), {
      tenantId: d.tenantId,
      authPolicy: { allowedMethods: ['federated'] },
    });
    const first = await federated(d, {
      subject: 'okta-ada',
      email: 'ADA@acme.test',
      trustScimProvisioned: [d.connection.id],
    });
    expect(first.token).toEqual(expect.any(String));
    expect(first.session?.identityId).toBe(identity.id);
    const linked = (await d.database.get<Identity>('identities', identity.id))!;
    expect(linked.emailVerified).toBe(true);
    expect(await d.database.find('externalIdentities', { identityId: identity.id })).toEqual([
      expect.objectContaining({ providerId: 'acme-okta', subject: 'okta-ada' }),
    ]);
    const audit = await d.database.find('audit', { tenantId: d.tenantId });
    expect(audit).toContainEqual(
      expect.objectContaining({
        action: 'identity:link-provider',
        resourceId: identity.id,
        metadata: { providerId: 'acme-okta', via: 'scim' },
      }),
    );
    // Later sign-ins use the link, whatever the connection's setting.
    const again = await federated(d, { subject: 'okta-ada', email: 'ada@acme.test' });
    expect(again.session?.identityId).toBe(identity.id);
    // Another account at the same IdP claiming the address does not take the linked account over.
    await expect(
      federated(d, { subject: 'okta-mallory', email: 'ada@acme.test', trustScimProvisioned: true }),
    ).rejects.toMatchObject({ code: 'ACCOUNT_LINK_REQUIRED' });
  });

  it('never links accounts SCIM did not provision, nor through a revoked SCIM connection', async () => {
    const d = await directory();
    await d.member('bob');
    await expect(
      federated(d, { subject: 'okta-bob', email: 'bob@acme.test', trustScimProvisioned: true }),
    ).rejects.toMatchObject({ code: 'ACCOUNT_LINK_REQUIRED' });
    // The owner's account is never a target, even if an IdP vouches for its address.
    await expect(
      federated(d, { subject: 'okta-owner', email: 'owner@acme.test', trustScimProvisioned: true }),
    ).rejects.toMatchObject({ code: 'ACCOUNT_LINK_REQUIRED' });
    await d.request('Users', 'POST', { userName: 'cyd@acme.test' });
    await d.scim.revokeConnection(d.ownerCredential, {
      tenantId: d.tenantId,
      connectionId: d.connection.id,
    });
    await expect(
      federated(d, { subject: 'okta-cyd', email: 'cyd@acme.test', trustScimProvisioned: true }),
    ).rejects.toMatchObject({ code: 'ACCOUNT_LINK_REQUIRED' });
  });
});

describe('migration imports', () => {
  it('imports people with verified emails and pre-linked external sign-ins', async () => {
    const f = await organizationFixture();
    const { identities } = await f.iam.api.identities.createMany(f.ownerCredential, {
      tenantId: f.tenantId,
      identities: [
        {
          email: 'ada@acme.test',
          name: 'Ada',
          emailVerified: true,
          providers: [
            { providerId: 'acme-okta', issuer: 'https://acme.okta.test', subject: 'okta-ada' },
            { providerId: 'google', issuer: 'https://accounts.google.com', subject: '1234' },
          ],
        },
        { email: 'bob@acme.test', name: 'Bob' },
      ],
    });
    expect(identities.map((identity) => identity.emailVerified)).toEqual([true, false]);
    // The imported person's first SSO sign-in finds the account: no ACCOUNT_LINK_REQUIRED, no manual link.
    const signedIn = await federated(f, { subject: 'okta-ada', email: 'ada@acme.test' });
    expect(signedIn.session?.identityId).toBe(identities[0]!.id);
    expect(
      (
        await f.iam.api.identities.listProviders(f.ownerCredential, {
          tenantId: f.tenantId,
          identityId: identities[0]!.id,
        })
      ).map((link) => link.providerId),
    ).toEqual(['acme-okta', 'google']);
    // One identity per external account; one link per provider; the batch is atomic.
    await expect(
      f.iam.api.identities.createMany(f.ownerCredential, {
        tenantId: f.tenantId,
        identities: [
          { email: 'cyd@acme.test', name: 'Cyd' },
          {
            email: 'dee@acme.test',
            name: 'Dee',
            providers: [
              { providerId: 'acme-okta', issuer: 'https://acme.okta.test', subject: 'okta-ada' },
            ],
          },
        ],
      }),
    ).rejects.toMatchObject({ code: 'ACCOUNT_LINK_CONFLICT', status: 409 });
    expect(await f.database.find('identities', { email: 'cyd@acme.test' })).toHaveLength(0);
    await expect(
      f.iam.api.identities.create(f.ownerCredential, {
        tenantId: f.tenantId,
        email: 'eve@acme.test',
        name: 'Eve',
        providers: [
          { providerId: 'google', issuer: 'https://accounts.google.com', subject: '1' },
          { providerId: 'google', issuer: 'https://accounts.google.com', subject: '2' },
        ],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.identities.create(f.ownerCredential, {
        tenantId: f.tenantId,
        email: 'eve@acme.test',
        name: 'Eve',
        emailVerified: 'yes' as unknown as boolean,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const eve = await f.iam.api.identities.create(f.ownerCredential, {
      tenantId: f.tenantId,
      email: 'eve@acme.test',
      name: 'Eve',
      emailVerified: true,
    });
    expect(eve.emailVerified).toBe(true);
  });

  it('links and unlinks external sign-ins on existing accounts under account-control rules', async () => {
    const f = await organizationFixture();
    const bob = await f.member('bob');
    const owner = await f.ownerSignIn();
    const okta = { providerId: 'acme-okta', issuer: 'https://acme.okta.test', subject: 'okta-bob' };
    const link = await f.iam.api.identities.linkProvider(owner, {
      tenantId: f.tenantId,
      identityId: bob.id,
      ...okta,
    });
    expect(link).toMatchObject({ ...okta, identityId: bob.id, id: expect.any(String) });
    expect(
      (await federated(f, { subject: 'okta-bob', email: 'bob@acme.test' })).session?.identityId,
    ).toBe(bob.id);
    await expect(
      f.iam.api.identities.linkProvider(owner, {
        tenantId: f.tenantId,
        identityId: bob.id,
        ...okta,
        subject: 'okta-bob-2',
      }),
    ).rejects.toMatchObject({ code: 'ACCOUNT_LINK_CONFLICT' });

    // A member administrator (identities:update) cannot link an IdP account to the owner's account.
    const admin = await f.member('admin');
    const role = await f.iam.api.roles.create(owner, {
      tenantId: f.tenantId,
      name: 'Member admin',
      permissions: ['iam:identities:update', 'iam:identities:read'],
    });
    await f.iam.api.bindings.create(owner, {
      tenantId: f.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: admin.id,
    });
    const adminSession = { token: (await f.signIn('admin')).token };
    await expect(
      f.iam.api.identities.linkProvider(adminSession, {
        tenantId: f.tenantId,
        identityId: f.ownerId,
        providerId: 'acme-okta',
        issuer: 'https://acme.okta.test',
        subject: 'okta-attacker',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      await f.iam.api.identities.listProviders(adminSession, {
        tenantId: f.tenantId,
        identityId: bob.id,
      }),
    ).toHaveLength(1);

    const removed = await f.iam.api.identities.unlinkProvider(owner, {
      tenantId: f.tenantId,
      identityId: bob.id,
      linkId: link.id,
    });
    expect(removed.id).toBe(link.id);
    await expect(
      federated(f, { subject: 'okta-bob', email: 'bob@acme.test' }),
    ).rejects.toMatchObject({
      code: 'ACCOUNT_LINK_REQUIRED',
    });
    await expect(
      f.iam.api.identities.unlinkProvider(owner, {
        tenantId: f.tenantId,
        identityId: bob.id,
        linkId: link.id,
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    const actions = (await f.database.find('audit', { tenantId: f.tenantId })).map(
      (event) => event.action,
    );
    expect(actions).toEqual(
      expect.arrayContaining(['identity:link-provider', 'identity:unlink-provider']),
    );
  });

  it('lets a root principal create an active tenant without an owner invitation', async () => {
    const f = await organizationFixture();
    const before = f.inbox.length;
    const created = await f.iam.api.tenants.create(f.rootCredential, {
      parentId: f.root.tenant.id,
      type: 'organization',
      name: 'Globex',
      ownerEmail: 'Owner@Globex.test',
      ownerName: 'Globex Owner',
      ownerEmailVerified: true,
      activate: true,
    });
    expect(created.tenant.status).toBe('active');
    expect('owner' in created && created.owner).toMatchObject({
      email: 'owner@globex.test',
      name: 'Globex Owner',
      owner: true,
      emailVerified: true,
    });
    expect('invitationId' in created).toBe(false);
    await f.iam.auth.dispatchOutbox();
    expect(f.inbox.slice(before).some((message) => message.template === 'owner-invitation')).toBe(
      false,
    );
    // Members can be imported at once.
    const imported = await f.iam.api.identities.createMany(f.rootCredential, {
      tenantId: created.tenant.id,
      identities: [{ email: 'ada@globex.test', name: 'Ada' }],
    });
    expect(imported.identities).toHaveLength(1);
    // The owner signs in without a password (a reset here) and holds the Owner role.
    const owner = (
      await f.database.find<Identity>('identities', {
        tenantId: created.tenant.id,
        email: 'owner@globex.test',
      })
    )[0]!;
    await f.database.transaction((tx) => f.iam.auth.issuePasswordReset(tx, owner));
    await f.iam.auth.dispatchOutbox();
    const reset = f.inbox.filter((message) => message.template === 'password-reset').at(-1)!;
    await f.iam.api.auth.resetPassword({
      tenantId: created.tenant.id,
      token: reset.payload.token!,
      password: 'a strong globex owner password',
    });
    const session = await f.iam.api.auth.signIn({
      tenantId: created.tenant.id,
      email: 'owner@globex.test',
      password: 'a strong globex owner password',
    });
    if (!('token' in session)) throw new Error('Unexpected MFA');
    const roles = await f.iam.api.roles.list(
      { token: session.token },
      { tenantId: created.tenant.id },
    );
    expect(roles.map((role) => role.name)).toContain('Owner');
    expect(
      (await f.database.find('audit', { tenantId: created.tenant.id })).some(
        (event) => event.action === 'tenant:activate',
      ),
    ).toBe(true);
  });

  it('refuses activation to everyone but root principals and validates the owner fields', async () => {
    const f = await organizationFixture();
    const owner = await f.ownerSignIn();
    const children = await f.database.find('tenants', { parentId: f.tenantId });
    await expect(
      f.iam.api.tenants.create(owner, {
        parentId: f.tenantId,
        type: 'project',
        name: 'Side project',
        ownerEmail: 'lead@acme.test',
        activate: true,
      }),
    ).rejects.toMatchObject({ status: 403 });
    expect(await f.database.find('tenants', { parentId: f.tenantId })).toHaveLength(
      children.length,
    );
    await expect(
      f.iam.api.tenants.create(f.rootCredential, {
        parentId: f.root.tenant.id,
        type: 'organization',
        name: 'Initech',
        ownerEmail: 'owner@initech.test',
        ownerName: 'Peter',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});

describe('protocol redirects through the host', () => {
  it('turns a redirect hint into a 303 with the session cookie, never following untrusted targets', async () => {
    const f = await organizationFixture({ trustedOrigins: ['https://app.example.test'] });
    await f.member('ada');
    const issue = async () => {
      const result = await f.iam.api.auth.signIn({
        tenantId: f.tenantId,
        email: 'ada@acme.test',
        password: 'a strong ada password',
      });
      return result;
    };
    let hint = '/dashboard';
    let status = 200;
    f.iam.useProtocol({
      basePath: '/fake-saml',
      handler: async (request) =>
        new URL(request.url).pathname === '/fake-saml/acs'
          ? Response.json(status === 200 ? await issue() : { error: 'SAML_INVALID' }, {
              status,
              headers: {
                'x-better-iam-redirect': hint,
                'set-cookie': 'binding=; Path=/; Max-Age=0',
              },
            })
          : undefined,
    });
    const acs = () => f.iam.handler(new Request(`${ORIGIN}/fake-saml/acs`, { method: 'POST' }));

    const signedIn = await acs();
    expect(signedIn.status).toBe(303);
    expect(signedIn.headers.get('location')).toBe('/dashboard');
    expect(signedIn.headers.get('x-better-iam-redirect')).toBeNull();
    const cookies = signedIn.headers.getSetCookie();
    expect(cookies).toContain('binding=; Path=/; Max-Age=0');
    const session = cookies.find((cookie) => cookie.startsWith('better-iam.session='))!;
    expect(session).toBeDefined();
    expect(await signedIn.text()).toBe('');
    const token = decodeURIComponent(session.split(';')[0]!.split('=')[1]!);
    expect((await f.iam.api.auth.getSession({ token })).identity.email).toBe('ada@acme.test');

    hint = 'https://app.example.test/welcome';
    expect((await acs()).headers.get('location')).toBe('https://app.example.test/welcome');

    // Untrusted origins and scheme-relative paths are not followed: the JSON answer stands, without the hint.
    for (const target of ['https://evil.example.test/', '//evil.example.test/', '/\\evil']) {
      hint = target;
      const answer = await acs();
      expect(answer.status).toBe(200);
      expect(answer.headers.get('location')).toBeNull();
      expect(answer.headers.get('x-better-iam-redirect')).toBeNull();
      expect(await answer.json()).toHaveProperty('token');
    }

    // A failure with an error page goes there, without any session cookie.
    hint = '/login?error=SAML_INVALID';
    status = 401;
    const failed = await acs();
    expect(failed.status).toBe(303);
    expect(failed.headers.get('location')).toBe('/login?error=SAML_INVALID');
    expect(
      failed.headers.getSetCookie().some((cookie) => cookie.includes('better-iam.session')),
    ).toBe(false);
  });
});
