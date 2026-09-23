import { afterEach, describe, expect, it } from 'vitest';
import { createScimService, type ScimGroupLink, type ScimUserLink } from '@better-iam/scim';
import type { Identity } from '@better-iam/core';
import { closeFixtures, organizationFixture } from './support/organization.js';

const ENTERPRISE = 'urn:ietf:params:scim:schemas:extension:enterprise:2.0:User';
const PATCH = 'urn:ietf:params:scim:api:messages:2.0:PatchOp';
const BULK = 'urn:ietf:params:scim:api:messages:2.0:BulkRequest';

afterEach(closeFixtures);

async function directory(options: { mapManager?: boolean } = {}) {
  const f = await organizationFixture();
  const service = createScimService({ ...f.iam.protocolHost, ...options });
  const connection = await service.createConnection(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Directory',
  });
  const request = async (resource: string, method = 'GET', body?: unknown) =>
    (await service.handler(
      new Request(`https://iam.test${connection.path}/${resource}`, {
        method,
        headers: {
          authorization: `Bearer ${connection.token}`,
          'content-type': 'application/scim+json',
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      }),
    ))!;
  const create = async (user: Record<string, unknown>) => {
    const response = await request('Users', 'POST', user);
    expect(response.status).toBe(201);
    return (await response.json()) as { id: string };
  };
  const put = async (id: string, user: Record<string, unknown>) => {
    const response = await request(`Users/${id}`, 'PUT', user);
    expect(response.status).toBe(200);
    return response.json();
  };
  const patch = async (id: string, Operations: unknown[]) => {
    const response = await request(`Users/${id}`, 'PATCH', { schemas: [PATCH], Operations });
    expect(response.status).toBe(200);
    return response.json();
  };
  /** The local identity behind a SCIM user. */
  const identityOf = async (user: { id: string }) => {
    const link = await f.database.get<ScimUserLink>('scimUsers', user.id);
    return (await f.database.get<Identity>('identities', link!.identityId))!;
  };
  const managerOf = async (user: { id: string }) => (await identityOf(user)).managerId;
  const managedBy = (id: string) => ({ [ENTERPRISE]: { manager: { value: id } } });
  return { f, request, create, put, patch, identityOf, managerOf, managedBy };
}

describe('SCIM enterprise manager mapping', () => {
  it('sets the manager on create by SCIM ID, case-exact externalId, or userName', async () => {
    const { f, create, patch, identityOf, managerOf, managedBy } = await directory();
    const boss = await create({ userName: 'boss@acme.test', externalId: 'EMP-1' });
    const bossId = (await identityOf(boss)).id;
    const byId = await create({ userName: 'a@acme.test', ...managedBy(boss.id) });
    const byExternalId = await create({ userName: 'b@acme.test', ...managedBy('EMP-1') });
    const byUserName = await create({ userName: 'c@acme.test', ...managedBy('BOSS@acme.test') });
    const wrongCase = await create({ userName: 'd@acme.test', ...managedBy('emp-1') });
    expect(await managerOf(byId)).toBe(bossId);
    expect(await managerOf(byExternalId)).toBe(bossId);
    expect(await managerOf(byUserName)).toBe(bossId);
    expect(await managerOf(wrongCase)).toBeUndefined();
    const reports = await f.iam.api.identities.listReports(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: bossId,
    });
    expect(reports.map((report) => report.id).sort()).toEqual(
      [
        (await identityOf(byId)).id,
        (await identityOf(byExternalId)).id,
        (await identityOf(byUserName)).id,
      ].sort(),
    );

    // Entra ID adds the manager as a bare ID on the manager attribute itself.
    const body = await patch(wrongCase.id, [
      { op: 'Add', path: `${ENTERPRISE}:manager`, value: boss.id },
    ]);
    expect(body[ENTERPRISE]).toEqual({ manager: { value: boss.id } });
    expect(await managerOf(wrongCase)).toBe(bossId);
  });

  it('back-fills reports provisioned before their manager', async () => {
    const { f, create, identityOf, managerOf, managedBy } = await directory();
    const first = await create({ userName: 'first@acme.test', ...managedBy('EMP-9') });
    const second = await create({ userName: 'second@acme.test', ...managedBy('LEAD@acme.test') });
    const assigned = await create({ userName: 'third@acme.test', ...managedBy('EMP-9') });
    expect(await managerOf(first)).toBeUndefined();
    // A manager an administrator set in the meantime is kept.
    const alice = await f.member('alice');
    await f.iam.api.identities.update(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: (await identityOf(assigned)).id,
      managerId: alice.id,
    });

    const lead = await create({ userName: 'lead@acme.test', externalId: 'EMP-9' });
    const leadId = (await identityOf(lead)).id;
    expect(await managerOf(first)).toBe(leadId);
    expect(await managerOf(second)).toBe(leadId);
    expect(await managerOf(assigned)).toBe(alice.id);
  });

  it('follows PATCH and PUT of manager.value and clears the manager SCIM removed', async () => {
    const { create, put, patch, identityOf, managerOf, managedBy } = await directory();
    const first = await create({ userName: 'first-boss@acme.test' });
    const second = await create({ userName: 'second-boss@acme.test', externalId: 'EMP-2' });
    const user = await create({ userName: 'user@acme.test' });
    await patch(user.id, [{ op: 'replace', path: `${ENTERPRISE}:manager.value`, value: first.id }]);
    expect(await managerOf(user)).toBe((await identityOf(first)).id);
    await patch(user.id, [{ op: 'replace', path: `${ENTERPRISE}:manager.value`, value: 'EMP-2' }]);
    expect(await managerOf(user)).toBe((await identityOf(second)).id);
    await patch(user.id, [{ op: 'remove', path: `${ENTERPRISE}:manager` }]);
    expect(await managerOf(user)).toBeUndefined();

    await put(user.id, { userName: 'user@acme.test', ...managedBy(first.id) });
    expect(await managerOf(user)).toBe((await identityOf(first)).id);
    await put(user.id, { userName: 'user@acme.test', title: 'Engineer' });
    expect(await managerOf(user)).toBeUndefined();

    // A SCIM-set manager the IdP replaces with someone not provisioned yet is cleared, then back-filled.
    await patch(user.id, [{ op: 'replace', path: `${ENTERPRISE}:manager.value`, value: first.id }]);
    await patch(user.id, [{ op: 'replace', path: `${ENTERPRISE}:manager.value`, value: 'EMP-3' }]);
    expect(await managerOf(user)).toBeUndefined();
    const third = await create({ userName: 'third-boss@acme.test', externalId: 'EMP-3' });
    expect(await managerOf(user)).toBe((await identityOf(third)).id);
  });

  it('never clears a manager an administrator set', async () => {
    const { f, create, put, patch, identityOf, managerOf } = await directory();
    const alice = await f.member('alice');
    const boss = await create({ userName: 'boss@acme.test' });
    const user = await create({ userName: 'user@acme.test' });
    const setByAdmin = () =>
      identityOf(user).then((identity) =>
        f.iam.api.identities.update(f.ownerCredential, {
          tenantId: f.tenantId,
          identityId: identity.id,
          managerId: alice.id,
        }),
      );
    await setByAdmin();
    await patch(user.id, [{ op: 'replace', path: 'displayName', value: 'User' }]);
    await put(user.id, { userName: 'user@acme.test' });
    expect(await managerOf(user)).toBe(alice.id);

    // The IdP naming a manager wins; once an administrator overrides it, removing it in SCIM keeps theirs.
    await patch(user.id, [{ op: 'add', path: `${ENTERPRISE}:manager.value`, value: boss.id }]);
    expect(await managerOf(user)).toBe((await identityOf(boss)).id);
    await setByAdmin();
    await patch(user.id, [{ op: 'remove', path: `${ENTERPRISE}:manager` }]);
    expect(await managerOf(user)).toBe(alice.id);
  });

  it('ignores circular managers and settles reorganizations sent reports first', async () => {
    const { create, patch, identityOf, managerOf, managedBy } = await directory();
    const managerValue = (id: string) => [
      { op: 'replace', path: `${ENTERPRISE}:manager.value`, value: id },
    ];
    const top = await create({ userName: 'top@acme.test' });
    const a = await create({ userName: 'a@acme.test' });
    const b = await create({ userName: 'b@acme.test', ...managedBy(a.id) });
    const c = await create({ userName: 'c@acme.test', ...managedBy(b.id) });
    const [topId, aId, bId] = [
      (await identityOf(top)).id,
      (await identityOf(a)).id,
      (await identityOf(b)).id,
    ];
    expect(await managerOf(b)).toBe(aId);

    // B (or B's report C) as A's manager would be circular: ignored, not an error.
    const body = await patch(a.id, managerValue(b.id));
    expect(body[ENTERPRISE].manager).toEqual({ value: b.id });
    expect(await managerOf(a)).toBeUndefined();
    await patch(a.id, managerValue(c.id));
    expect(await managerOf(a)).toBeUndefined();
    const solo = await create({ userName: 'solo@acme.test', ...managedBy('solo@acme.test') });
    expect(await managerOf(solo)).toBeUndefined();

    // Reorganization: A moves under B and B under Top, and the IdP sends A first.
    await patch(a.id, managerValue(top.id));
    expect(await managerOf(a)).toBe(topId);
    await patch(a.id, managerValue(b.id));
    expect(await managerOf(a)).toBeUndefined();
    await patch(b.id, managerValue(top.id));
    expect(await managerOf(b)).toBe(topId);
    expect(await managerOf(a)).toBe(bId);
    expect(await managerOf(c)).toBe(bId);
  });

  it('releases reports when SCIM deletes their manager and relinks them when it returns', async () => {
    const { request, create, identityOf, managerOf, managedBy } = await directory();
    const boss = await create({ userName: 'boss@acme.test', externalId: 'EMP-5' });
    const report = await create({ userName: 'report@acme.test', ...managedBy('EMP-5') });
    expect(await managerOf(report)).toBe((await identityOf(boss)).id);
    expect((await request(`Users/${boss.id}`, 'DELETE')).status).toBe(204);
    expect(await managerOf(report)).toBeUndefined();
    const returned = await create({ userName: 'boss-again@acme.test', externalId: 'EMP-5' });
    expect(await managerOf(report)).toBe((await identityOf(returned)).id);
  });

  it('back-fills and releases many reports in one save', async () => {
    const { f, request, create, identityOf, managedBy } = await directory();
    const Operations = Array.from({ length: 60 }, (_, index) => ({
      method: 'POST',
      bulkId: `r${index}`,
      path: '/Users',
      data: {
        userName: `report-${index}@acme.test`,
        ...managedBy(index % 2 ? 'EMP-7' : 'LEAD@acme.test'),
      },
    }));
    const bulk = await (await request('Bulk', 'POST', { schemas: [BULK], Operations })).json();
    expect(bulk.Operations.map((op: { status: string }) => op.status)).toEqual(
      Operations.map(() => '201'),
    );
    const lead = await create({ userName: 'lead@acme.test', externalId: 'EMP-7' });
    const leadId = (await identityOf(lead)).id;
    const reports = () =>
      f.database.find<Identity>('identities', { tenantId: f.tenantId, managerId: leadId });
    expect(await reports()).toHaveLength(60);
    expect((await request(`Users/${lead.id}`, 'DELETE')).status).toBe(204);
    expect(await reports()).toEqual([]);
  });

  it('treats a reference naming the user themself as no manager, never as someone else', async () => {
    const { f, request, create, put, patch, identityOf, managerOf, managedBy } = await directory();
    // A self-managed CEO named by its own externalId, which is also another user's userName.
    const namesake = await create({ userName: 'jdoe' });
    const ceo = await create({
      userName: 'ceo@acme.test',
      externalId: 'jdoe',
      ...managedBy('jdoe'),
    });
    expect(await managerOf(ceo)).toBeUndefined();
    // Back-fill resolves the same way: saving the namesake adopts no one.
    await patch(namesake.id, [{ op: 'replace', path: 'displayName', value: 'J. Doe' }]);
    expect(await managerOf(ceo)).toBeUndefined();
    // Another user's identical reference still follows precedence: externalId (the CEO) before userName.
    const report = await create({ userName: 'report@acme.test', ...managedBy('jdoe') });
    expect(await managerOf(report)).toBe((await identityOf(ceo)).id);
    // SCIM deleting the namesake leaves nobody pointing at its disabled identity.
    const namesakeId = (await identityOf(namesake)).id;
    expect((await request(`Users/${namesake.id}`, 'DELETE')).status).toBe(204);
    expect(
      await f.database.find('identities', { tenantId: f.tenantId, managerId: namesakeId }),
    ).toEqual([]);

    // Updates too: an own externalId that is another userName ignoring case, and an own SCIM ID that is another
    // user's externalId.
    await create({ userName: 'e1' });
    const lead = await create({ userName: 'lead@acme.test' });
    await put(lead.id, { userName: 'lead@acme.test', externalId: 'E1', ...managedBy('E1') });
    expect(await managerOf(lead)).toBeUndefined();
    await create({ userName: 'shadow@acme.test', externalId: lead.id });
    await patch(lead.id, [{ op: 'replace', path: `${ENTERPRISE}:manager.value`, value: lead.id }]);
    expect(await managerOf(lead)).toBeUndefined();
  });

  it('never revives, reassigns, or regroups an identity an administrator deleted', async () => {
    const { f, request, create, identityOf, managedBy } = await directory();
    const boss = await create({ userName: 'boss@acme.test' });
    const user = await create({ userName: 'gone@acme.test', ...managedBy('EMP-8') });
    const created = await request('Groups', 'POST', {
      displayName: 'Staff',
      members: [{ value: user.id }],
    });
    expect(created.status).toBe(201);
    const group = (await created.json()) as { id: string };
    const identityId = (await identityOf(user)).id;
    await f.iam.api.identities.delete(f.ownerCredential, { tenantId: f.tenantId, identityId });

    for (const [method, body] of [
      [
        'PATCH',
        {
          schemas: [PATCH],
          Operations: [{ op: 'replace', path: `${ENTERPRISE}:manager.value`, value: boss.id }],
        },
      ],
      ['PUT', { userName: 'gone@acme.test', active: true, ...managedBy(boss.id) }],
    ] as const) {
      const response = await request(`Users/${user.id}`, method, body);
      expect(response.status, method).toBe(403);
      expect((await response.json()).scimType).toBe('mutability');
    }
    // Back-fill skips it, and the IdP's group updates keep it out of the local group (and its mapped roles).
    await create({ userName: 'lead@acme.test', externalId: 'EMP-8' });
    const renamed = await request(`Groups/${group.id}`, 'PATCH', {
      schemas: [PATCH],
      Operations: [{ op: 'replace', path: 'displayName', value: 'Everyone' }],
    });
    expect(renamed.status).toBe(200);
    const { groupId } = (await f.database.get<ScimGroupLink>('scimGroups', group.id))!;
    expect(await f.database.find('groupMembers', { tenantId: f.tenantId, groupId })).toEqual([]);
    const tombstone = await identityOf(user);
    expect(tombstone).toMatchObject({ status: 'deleted', emailVerified: false });
    expect(tombstone.email).toBeUndefined();
    expect(tombstone.managerId).toBeUndefined();

    // The IdP can still deprovision it; the tombstone stays deleted.
    expect((await request(`Users/${user.id}`, 'DELETE')).status).toBe(204);
    expect((await f.database.get<Identity>('identities', identityId))!.status).toBe('deleted');
  });

  it('leaves managers alone with mapManager: false', async () => {
    const { create, patch, managerOf, managedBy } = await directory({ mapManager: false });
    const early = await create({ userName: 'early@acme.test', ...managedBy('late@acme.test') });
    const boss = await create({ userName: 'boss@acme.test' });
    const report = await create({ userName: 'report@acme.test', ...managedBy(boss.id) });
    await create({ userName: 'late@acme.test' });
    const body = await patch(early.id, [
      { op: 'replace', path: `${ENTERPRISE}:manager.value`, value: boss.id },
    ]);
    expect(body[ENTERPRISE].manager).toEqual({ value: boss.id });
    expect(await managerOf(early)).toBeUndefined();
    expect(await managerOf(report)).toBeUndefined();
  });
});
