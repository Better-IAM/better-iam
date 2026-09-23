import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import { betterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import type { IamStore } from '@better-iam/core';
import type { DeliveryMessage } from '@better-iam/auth';

const { authenticator } = createRequire(new URL('../packages/auth/package.json', import.meta.url))(
  'otplib',
);
const databases: IamStore[] = [];
afterEach(async () => {
  for (const database of databases.splice(0)) await database.close();
});

async function fixture() {
  const database = sqliteAdapter({ filename: ':memory:' });
  databases.push(database);
  const inbox: DeliveryMessage[] = [];
  let clock = Date.now();
  const iam = betterIam({
    database,
    secret: 'data-export-test-secret-with-at-least-32-chars',
    baseURL: 'http://localhost:3000',
    authentication: {
      sendEmail: async (message) => {
        inbox.push(message);
      },
      now: () => clock,
    },
    permissions: {
      resourceTypes: {
        folder: { managed: true, actions: ['folders:read'], relations: ['viewer'] },
      },
    },
  });
  await iam.initialize();
  const root = await iam.bootstrap({
    email: 'root@example.test',
    name: 'Root',
    password: 'a strong root test password',
  });
  const challenge = await iam.api.auth.signIn({
    tenantId: root.tenant.id,
    email: 'root@example.test',
    password: 'a strong root test password',
  });
  if (!('mfaRequired' in challenge)) throw new Error('Root must require MFA');
  const enrollment = await iam.api.auth.beginMfa({
    tenantId: root.tenant.id,
    challenge: challenge.challenge,
  });
  const generator = authenticator.clone();
  generator.options = { epoch: clock };
  const session = await iam.api.auth.confirmMfa({
    credential: { tenantId: root.tenant.id, challenge: challenge.challenge },
    code: generator.generate(enrollment.secret),
  });
  const created = await iam.api.tenants.create(
    { token: session.token },
    {
      parentId: root.tenant.id,
      name: 'Acme',
      type: 'organization',
      ownerEmail: 'owner@acme.test',
    },
  );
  await iam.auth.dispatchOutbox();
  const invitation = inbox.find(
    (message) => message.tenantId === created.tenant.id && message.template === 'owner-invitation',
  )!;
  const owner = await iam.api.tenants.acceptInvitation({
    tenantId: created.tenant.id,
    token: invitation.payload.token!,
    name: 'Owner',
    password: 'a strong tenant owner password',
  });
  if (!('token' in owner)) throw new Error('Unexpected owner MFA');
  const tenantId = created.tenant.id;
  const ownerCredential = { token: owner.token };
  const alice = await iam.api.identities.create(ownerCredential, {
    tenantId,
    email: 'alice@acme.test',
    name: 'Alice',
    password: 'a strong alice password',
  });
  const signInAlice = async () => {
    const login = await iam.api.auth.signIn({
      tenantId,
      email: 'alice@acme.test',
      password: 'a strong alice password',
    });
    if (!('token' in login)) throw new Error('Unexpected MFA');
    return login;
  };
  return {
    iam,
    database,
    root,
    tenantId,
    owner,
    ownerCredential,
    alice,
    signInAlice,
    advance: (ms: number) => {
      clock += ms;
    },
  };
}

describe('personal data export and session revocation', () => {
  it('exports everything stored about an identity without secrets and audits the export', async () => {
    const f = await fixture();
    const team = await f.iam.api.groups.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Team',
    });
    await f.iam.api.groups.addMember(f.ownerCredential, {
      tenantId: f.tenantId,
      groupId: team.id,
      identityId: f.alice.id,
    });
    const readers = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Readers',
      permissions: ['folders:read'],
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: readers.id,
      subjectType: 'group',
      subjectId: team.id,
    });
    await f.iam.api.resources.register(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'folder',
      id: 'plans',
    });
    await f.iam.api.relationships.create(f.ownerCredential, {
      tenantId: f.tenantId,
      type: 'folder',
      id: 'plans',
      relation: 'viewer',
      subjectType: 'identity',
      subjectId: f.alice.id,
    });
    const requester = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Requester',
      permissions: ['iam:access-requests:create'],
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: requester.id,
      subjectType: 'identity',
      subjectId: f.alice.id,
    });
    const login = await f.signInAlice();
    await f.iam.api.accessRequests.create(
      { token: login.token },
      { tenantId: f.tenantId, roleIds: [readers.id], justification: 'Need the plans' },
    );
    // Alice can read herself but not export: the export needs recent authentication and read permission; she has neither the permission.
    await expect(
      f.iam.api.identities.export(
        { token: login.token },
        { tenantId: f.tenantId, identityId: f.alice.id },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const exported = await f.iam.api.identities.export(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: f.alice.id,
    });
    expect(exported.identity).toMatchObject({ id: f.alice.id, email: 'alice@acme.test' });
    expect(exported.identity).not.toHaveProperty('passwordHash');
    expect(exported.sessions).toHaveLength(1);
    expect(exported.sessions[0]).not.toHaveProperty('tokenHash');
    expect(exported.sessions[0]).toMatchObject({ method: 'password', mfa: false });
    expect(exported.mfa).toEqual({ enabled: false });
    expect(exported.groups.map((group) => group.name)).toEqual(['Team']);
    expect(exported.bindings.map((binding) => binding.roleId).sort()).toEqual(
      [readers.id, requester.id].sort(),
    );
    expect(exported.bindings.find((binding) => binding.roleId === readers.id)!.via).toEqual({
      groupId: team.id,
    });
    expect(exported.relationships.map((tuple) => tuple.relation)).toEqual(['viewer']);
    expect(exported.accessRequests).toHaveLength(1);
    expect(exported.links).toEqual([]);
    expect(exported.passkeys).toEqual([]);
    expect(exported.auditIncluded).toBe(true);
    expect(exported.audit!.map((event) => event.action)).toEqual(
      expect.arrayContaining(['auth:session:create', 'iam:access-requests:create']),
    );
    expect(JSON.stringify(exported)).not.toContain(login.token);
    const trail = await f.iam.api.audit.list(f.ownerCredential, {
      tenantId: f.tenantId,
      action: 'identity:export',
    });
    expect(trail[0]).toMatchObject({
      resourceId: f.alice.id,
      metadata: { kind: 'user', auditIncluded: true },
    });
    // An exporter without audit permission receives everything except the trail.
    const auditor = await f.iam.api.identities.create(f.ownerCredential, {
      tenantId: f.tenantId,
      email: 'hr@acme.test',
      name: 'HR',
      password: 'a strong hr password',
    });
    const hrRole = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'HR',
      permissions: ['iam:identities:read'],
    });
    await f.iam.api.bindings.create(f.ownerCredential, {
      tenantId: f.tenantId,
      roleId: hrRole.id,
      subjectType: 'identity',
      subjectId: auditor.id,
    });
    const hrLogin = await f.iam.api.auth.signIn({
      tenantId: f.tenantId,
      email: 'hr@acme.test',
      password: 'a strong hr password',
    });
    if (!('token' in hrLogin)) throw new Error('Unexpected MFA');
    const partial = await f.iam.api.identities.export(
      { token: hrLogin.token },
      { tenantId: f.tenantId, identityId: f.alice.id },
    );
    expect(partial.auditIncluded).toBe(false);
    expect(partial.audit).toBeUndefined();
    expect(partial.groups).toHaveLength(1);
    // Recent authentication is required.
    f.advance(6 * 60_000);
    await expect(
      f.iam.api.identities.export(f.ownerCredential, {
        tenantId: f.tenantId,
        identityId: f.alice.id,
      }),
    ).rejects.toMatchObject({ code: 'RECENT_AUTH_REQUIRED' });
  });

  it('revokes one identity’s sessions or every session in the tenant', async () => {
    const f = await fixture();
    const first = await f.signInAlice();
    const second = await f.signInAlice();
    const revoked = await f.iam.api.identities.revokeSessions(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: f.alice.id,
    });
    expect(revoked).toEqual({ revoked: 2 });
    for (const login of [first, second])
      await expect(f.iam.api.auth.getSession({ token: login.token })).rejects.toMatchObject({
        code: 'UNAUTHENTICATED',
      });
    expect(
      (
        await f.iam.api.identities.get(f.ownerCredential, {
          tenantId: f.tenantId,
          identityId: f.alice.id,
        })
      ).status,
    ).toBe('active');
    // A member cannot revoke an administrator's sessions without iam:identities:update.
    const again = await f.signInAlice();
    await expect(
      f.iam.api.identities.revokeSessions(
        { token: again.token },
        { tenantId: f.tenantId, identityId: f.owner.identity.id },
      ),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Tenant-wide revocation keeps the caller signed in unless asked otherwise.
    const tenantWide = await f.iam.api.tenants.revokeSessions(f.ownerCredential, {
      tenantId: f.tenantId,
    });
    expect(tenantWide).toEqual({ revoked: 1 });
    await expect(f.iam.api.auth.getSession({ token: again.token })).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    expect((await f.iam.api.auth.getSession(f.ownerCredential)).session.id).toBe(
      f.owner.session.id,
    );
    const events = await f.iam.api.audit.list(f.ownerCredential, {
      tenantId: f.tenantId,
      action: 'tenant:revoke-sessions',
    });
    expect(events[0]?.metadata).toEqual({ revoked: 1, includeSelf: false });
    const everyone = await f.iam.api.tenants.revokeSessions(f.ownerCredential, {
      tenantId: f.tenantId,
      includeSelf: true,
    });
    expect(everyone).toEqual({ revoked: 1 });
    await expect(f.iam.api.auth.getSession(f.ownerCredential)).rejects.toMatchObject({
      code: 'UNAUTHENTICATED',
    });
    // Root sessions in other tenants are untouched.
    expect(await f.database.find('sessions', { tenantId: f.root.tenant.id })).toHaveLength(1);
  });
});
