import { afterEach, describe, expect, it } from 'vitest';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);
const hour = 3600000;
const day = 24 * hour;

type Fixture = Awaited<ReturnType<typeof organizationFixture>>;

/** A tenant with a Reader role and members who may request packages (through an Everyone group). */
async function setup(names: string[]) {
  const f = await organizationFixture();
  const { tenantId } = f;
  const owner = f.ownerCredential;
  const reader = await f.iam.api.roles.create(owner, {
    tenantId,
    name: 'Reader',
    permissions: ['documents:read'],
  });
  const requester = await f.iam.api.roles.create(owner, {
    tenantId,
    name: 'Requester',
    permissions: ['iam:packages:request'],
  });
  const everyone = await f.iam.api.groups.create(owner, { tenantId, name: 'Everyone' });
  await f.iam.api.bindings.create(owner, {
    tenantId,
    roleId: requester.id,
    subjectType: 'group',
    subjectId: everyone.id,
  });
  const people: Record<string, { id: string; credential: { token: string } }> = {};
  for (const name of names) {
    const identity = await f.member(name);
    await f.iam.api.groups.addMember(owner, {
      tenantId,
      groupId: everyone.id,
      identityId: identity.id,
    });
    people[name] = { id: identity.id, credential: { token: (await f.signIn(name)).token } };
  }
  return { f, tenantId, owner, reader, people };
}

async function failure(promise: Promise<unknown>) {
  return promise.then(
    () => undefined,
    (error: { code?: string; message?: string }) => error,
  );
}

async function storedStatus(f: Fixture, requestId: string) {
  return (await f.database.get<{ id: string; status: string }>('packageRequests', requestId))
    ?.status;
}

describe('package request lapse time', () => {
  it('never lapses later than the end the requester asks for', async () => {
    const { f, tenantId, owner, reader, people } = await setup(['alice', 'bob']);
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [reader.id],
      requestable: true,
    });
    const start = f.now();
    // Control: an end beyond the (default 24h) approval lifetime lapses at the lifetime.
    const long = await f.iam.api.packages.request(people.bob!.credential, {
      tenantId,
      packageId: kit.id,
      expiresAt: start + 3 * day,
    });
    expect(long).toMatchObject({
      status: 'pending',
      desiredExpiresAt: start + 3 * day,
      expiresAt: start + day,
    });
    // An end shorter than the lifetime is the lapse time.
    const short = await f.iam.api.packages.request(people.alice!.credential, {
      tenantId,
      packageId: kit.id,
      expiresAt: start + 4 * hour,
    });
    expect(short).toMatchObject({
      status: 'pending',
      desiredExpiresAt: start + 4 * hour,
      expiresAt: start + 4 * hour,
    });
    expect(
      (await f.database.get<{ id: string; expiresAt: number }>('packageRequests', short.id))
        ?.expiresAt,
    ).toBe(start + 4 * hour);
    // Still awaiting a decision before its end.
    f.advance(3 * hour);
    expect(
      (await f.iam.api.packages.listApprovals(owner, { tenantId })).map((item) => item.id).sort(),
    ).toEqual([long.id, short.id].sort());
    // Past the end it asked for, it no longer waits for anyone.
    f.advance(2 * hour);
    expect(
      (await f.iam.api.packages.listApprovals(owner, { tenantId })).map((item) => item.id),
    ).toEqual([long.id]);
    const approve = await failure(
      f.iam.api.packages.approveRequest(owner, { tenantId, requestId: short.id }),
    );
    expect(approve?.code).toBe('INVALID_TRANSITION');
    const deny = await failure(
      f.iam.api.packages.denyRequest(owner, { tenantId, requestId: short.id }),
    );
    expect(deny?.code).toBe('INVALID_TRANSITION');
    // Nor can the requester withdraw it: it is no longer awaiting a decision.
    const cancel = await failure(
      f.iam.api.packages.cancelRequest(people.alice!.credential, { tenantId, requestId: short.id }),
    );
    expect(cancel?.code).toBe('INVALID_TRANSITION');
    // It is reported as expired (the worker has not run yet), and the requester sees nothing pending.
    expect(await storedStatus(f, short.id)).toBe('pending');
    expect(
      (
        await f.iam.api.packages.listRequests(owner, { tenantId, identityId: people.alice!.id })
      ).map((item) => [item.id, item.status]),
    ).toEqual([[short.id, 'expired']]);
    const mine = await f.iam.api.packages.listMine(people.alice!.credential, { tenantId });
    expect(mine.packages.find((pkg) => pkg.id === kit.id)?.pending).toBeUndefined();
    expect(mine.requests.map((item) => [item.id, item.status])).toEqual([[short.id, 'expired']]);
    // The failed approval granted nothing.
    expect(
      (
        await f.iam.authorize({
          ...people.alice!.credential,
          tenantId,
          action: 'documents:read',
          resource: { type: 'documents', id: 'a' },
        })
      ).allowed,
    ).toBe(false);
    // The requester may ask again.
    const again = await f.iam.api.packages.request(people.alice!.credential, {
      tenantId,
      packageId: kit.id,
      expiresAt: f.now() + 4 * hour,
    });
    expect(again).toMatchObject({ status: 'pending', expiresAt: f.now() + 4 * hour });
    expect(again.id).not.toBe(short.id);
    expect(
      (await f.iam.api.packages.listApprovals(owner, { tenantId })).map((item) => item.id).sort(),
    ).toEqual([long.id, again.id].sort());
    // The worker then marks the lapsed one.
    expect((await f.iam.purgeDeleted()).expiredRequests).toBe(1);
    expect(await storedStatus(f, short.id)).toBe('expired');
  });
});

describe('listRequests and lapsed requests', () => {
  it('reports a lapsed pending request as expired before the worker runs, and filters on that status', async () => {
    const { f, tenantId, owner, reader, people } = await setup(['alice', 'bob']);
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [reader.id],
      requestable: true,
    });
    const lapsing = await f.iam.api.packages.request(people.alice!.credential, {
      tenantId,
      packageId: kit.id,
    });
    expect(lapsing.expiresAt).toBe(f.now() + day);
    // At exactly its lapse time it is expired, as the purge worker and listApprovals count it.
    f.advance(day);
    expect(
      (await f.iam.api.packages.listRequests(owner, { tenantId })).map((item) => [
        item.id,
        item.status,
      ]),
    ).toEqual([[lapsing.id, 'expired']]);
    expect(await f.iam.api.packages.listRequests(owner, { tenantId, status: 'pending' })).toEqual(
      [],
    );
    expect(await f.iam.api.packages.listApprovals(owner, { tenantId })).toEqual([]);
    f.advance(1);
    // A fresh request that is genuinely still pending.
    const fresh = await f.iam.api.packages.request(people.bob!.credential, {
      tenantId,
      packageId: kit.id,
    });
    const admin = await f.ownerSignIn();
    // The store still says pending: the purge worker has not run.
    expect(await storedStatus(f, lapsing.id)).toBe('pending');
    const all = await f.iam.api.packages.listRequests(admin, { tenantId });
    expect(Object.fromEntries(all.map((item) => [item.id, item.status]))).toEqual({
      [lapsing.id]: 'expired',
      [fresh.id]: 'pending',
    });
    expect(
      (await f.iam.api.packages.listRequests(admin, { tenantId, status: 'pending' })).map(
        (item) => item.id,
      ),
    ).toEqual([fresh.id]);
    expect(
      (await f.iam.api.packages.listRequests(admin, { tenantId, status: 'expired' })).map(
        (item) => item.id,
      ),
    ).toEqual([lapsing.id]);
    // The same holds when filtered by package or by identity.
    expect(
      (
        await f.iam.api.packages.listRequests(admin, {
          tenantId,
          packageId: kit.id,
          status: 'pending',
        })
      ).map((item) => item.id),
    ).toEqual([fresh.id]);
    expect(
      (
        await f.iam.api.packages.listRequests(admin, {
          tenantId,
          identityId: people.alice!.id,
          status: 'pending',
        })
      ).map((item) => item.id),
    ).toEqual([]);
    expect(
      (
        await f.iam.api.packages.listRequests(admin, {
          tenantId,
          identityId: people.alice!.id,
          status: 'expired',
        })
      ).map((item) => item.id),
    ).toEqual([lapsing.id]);
    // The requester's own view agrees.
    const mine = await f.iam.api.packages.listMine(people.alice!.credential, { tenantId });
    expect(mine.requests.map((item) => [item.id, item.status])).toEqual([[lapsing.id, 'expired']]);
    expect(mine.packages.find((pkg) => pkg.id === kit.id)?.pending).toBeUndefined();
    // After the worker marks it, the listing is unchanged.
    expect((await f.iam.purgeDeleted()).expiredRequests).toBe(1);
    expect(await storedStatus(f, lapsing.id)).toBe('expired');
    expect(
      (await f.iam.api.packages.listRequests(admin, { tenantId, status: 'expired' })).map(
        (item) => item.id,
      ),
    ).toEqual([lapsing.id]);
    expect(
      (await f.iam.api.packages.listRequests(admin, { tenantId, status: 'pending' })).map(
        (item) => item.id,
      ),
    ).toEqual([fresh.id]);
  });
});

describe('packages.update cancels pending requests that no longer fit', () => {
  it('leaves pending requests alone when the rules are not tightened', async () => {
    const { f, tenantId, owner, reader, people } = await setup(['alice']);
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [reader.id],
      requestable: true,
    });
    const request = await f.iam.api.packages.request(people.alice!.credential, {
      tenantId,
      packageId: kit.id,
    });
    await f.iam.api.packages.update(owner, {
      tenantId,
      packageId: kit.id,
      name: 'Renamed kit',
      description: 'Same rules',
      requestable: true,
      requireJustification: false,
    });
    expect(await storedStatus(f, request.id)).toBe('pending');
    expect(
      (await f.iam.api.packages.listApprovals(owner, { tenantId })).map((item) => item.id),
    ).toEqual([request.id]);
  });

  it('requestable:false cancels every pending request with a note', async () => {
    const { f, tenantId, owner, reader, people } = await setup(['alice', 'bob']);
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [reader.id],
      requestable: true,
    });
    const first = await f.iam.api.packages.request(people.alice!.credential, {
      tenantId,
      packageId: kit.id,
      justification: 'Needed for the audit',
      expiresAt: f.now() + 2 * day,
    });
    const second = await f.iam.api.packages.request(people.bob!.credential, {
      tenantId,
      packageId: kit.id,
    });
    // A request for another package is not touched by this package's change.
    const other = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Other',
      roleIds: [reader.id],
      requestable: true,
    });
    const elsewhere = await f.iam.api.packages.request(people.alice!.credential, {
      tenantId,
      packageId: other.id,
    });
    f.advance(1000);
    await f.iam.api.packages.update(owner, { tenantId, packageId: kit.id, requestable: false });
    const listed = await f.iam.api.packages.listRequests(owner, { tenantId, packageId: kit.id });
    expect(listed).toHaveLength(2);
    for (const item of listed) {
      expect(item.status).toBe('cancelled');
      expect(item.decidedAt).toBe(f.now());
      expect(item.note).toEqual(expect.stringMatching(/requested/i));
    }
    expect(listed.map((item) => item.id).sort()).toEqual([first.id, second.id].sort());
    expect(await storedStatus(f, first.id)).toBe('cancelled');
    expect(await storedStatus(f, second.id)).toBe('cancelled');
    expect(await storedStatus(f, elsewhere.id)).toBe('pending');
    expect(
      (await f.iam.api.packages.listApprovals(owner, { tenantId })).map((item) => item.id),
    ).toEqual([elsewhere.id]);
    for (const cancelled of [first, second]) {
      expect(
        (
          await failure(
            f.iam.api.packages.approveRequest(owner, { tenantId, requestId: cancelled.id }),
          )
        )?.code,
      ).toBe('INVALID_TRANSITION');
      expect(
        (
          await failure(
            f.iam.api.packages.denyRequest(owner, { tenantId, requestId: cancelled.id }),
          )
        )?.code,
      ).toBe('INVALID_TRANSITION');
    }
    // Making it requestable again does not revive them; the requester asks anew.
    await f.iam.api.packages.update(owner, { tenantId, packageId: kit.id, requestable: true });
    expect(await storedStatus(f, first.id)).toBe('cancelled');
    const again = await f.iam.api.packages.request(people.alice!.credential, {
      tenantId,
      packageId: kit.id,
    });
    expect(again.status).toBe('pending');
  });

  it('requireJustification:true cancels only the requests without a justification', async () => {
    const { f, tenantId, owner, reader, people } = await setup(['alice', 'bob']);
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [reader.id],
      requestable: true,
    });
    const justified = await f.iam.api.packages.request(people.alice!.credential, {
      tenantId,
      packageId: kit.id,
      justification: 'On-call rotation',
    });
    const unjustified = await f.iam.api.packages.request(people.bob!.credential, {
      tenantId,
      packageId: kit.id,
    });
    await f.iam.api.packages.update(owner, {
      tenantId,
      packageId: kit.id,
      requireJustification: true,
    });
    const byId = Object.fromEntries(
      (await f.iam.api.packages.listRequests(owner, { tenantId, packageId: kit.id })).map(
        (item) => [item.id, item],
      ),
    );
    expect(byId[justified.id]).toMatchObject({ status: 'pending' });
    expect(byId[justified.id]!.note).toBeUndefined();
    expect(byId[unjustified.id]).toMatchObject({
      status: 'cancelled',
      decidedAt: f.now(),
      note: expect.stringMatching(/justification/i),
    });
    expect(
      (await f.iam.api.packages.listApprovals(owner, { tenantId })).map((item) => item.id),
    ).toEqual([justified.id]);
    // The one that fits can still be approved.
    const approved = await f.iam.api.packages.approveRequest(owner, {
      tenantId,
      requestId: justified.id,
    });
    expect(approved.status).toBe('approved');
    // The cancelled requester may ask again, now with a justification.
    const again = await f.iam.api.packages.request(people.bob!.credential, {
      tenantId,
      packageId: kit.id,
      justification: 'Now justified',
    });
    expect(again.status).toBe('pending');
  });

  it('a new maxDurationMs cancels open-ended requests and those asking to end beyond now + max', async () => {
    const { f, tenantId, owner, reader, people } = await setup(['alice', 'bob', 'carol', 'dave']);
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [reader.id],
      requestable: true,
    });
    const openEnded = await f.iam.api.packages.request(people.alice!.credential, {
      tenantId,
      packageId: kit.id,
    });
    const tooLong = await f.iam.api.packages.request(people.bob!.credential, {
      tenantId,
      packageId: kit.id,
      expiresAt: f.now() + 10 * day,
    });
    const fits = await f.iam.api.packages.request(people.carol!.credential, {
      tenantId,
      packageId: kit.id,
      expiresAt: f.now() + 2 * day,
    });
    // Asks to end 5d + 1h out; the cap arrives an hour later, so the end is exactly now + max: it still fits.
    const edge = await f.iam.api.packages.request(people.dave!.credential, {
      tenantId,
      packageId: kit.id,
      expiresAt: f.now() + 5 * day + hour,
    });
    f.advance(hour);
    await f.iam.api.packages.update(owner, {
      tenantId,
      packageId: kit.id,
      maxDurationMs: 5 * day,
    });
    const byId = Object.fromEntries(
      (await f.iam.api.packages.listRequests(owner, { tenantId, packageId: kit.id })).map(
        (item) => [item.id, item],
      ),
    );
    for (const cancelled of [openEnded, tooLong])
      expect(byId[cancelled.id]).toMatchObject({
        status: 'cancelled',
        decidedAt: f.now(),
        note: expect.any(String),
      });
    expect(byId[openEnded.id]!.note).toBe(byId[tooLong.id]!.note);
    // The note names the end as the reason, not one of the other rules.
    expect(byId[openEnded.id]!.note).toMatch(/end/i);
    expect(byId[openEnded.id]!.note).not.toMatch(/justification|can no longer be requested/i);
    expect(await storedStatus(f, openEnded.id)).toBe('cancelled');
    expect(await storedStatus(f, tooLong.id)).toBe('cancelled');
    for (const kept of [fits, edge]) {
      expect(byId[kept.id]).toMatchObject({ status: 'pending' });
      expect(byId[kept.id]!.note).toBeUndefined();
    }
    expect(
      (await f.iam.api.packages.listApprovals(owner, { tenantId })).map((item) => item.id).sort(),
    ).toEqual([fits.id, edge.id].sort());
    // The fitting ones can be approved as the console sends it (no override end).
    expect(
      (await f.iam.api.packages.approveRequest(owner, { tenantId, requestId: fits.id })).status,
    ).toBe('approved');
    expect(
      (await f.iam.api.packages.approveRequest(owner, { tenantId, requestId: edge.id })).status,
    ).toBe('approved');
    // A cancelled one cannot be.
    expect(
      (await failure(f.iam.api.packages.approveRequest(owner, { tenantId, requestId: tooLong.id })))
        ?.code,
    ).toBe('INVALID_TRANSITION');
  });

  it('lowering an existing maxDurationMs cancels those whose end now exceeds it', async () => {
    const { f, tenantId, owner, reader, people } = await setup(['alice', 'bob']);
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [reader.id],
      requestable: true,
      maxDurationMs: 30 * day,
    });
    const long = await f.iam.api.packages.request(people.alice!.credential, {
      tenantId,
      packageId: kit.id,
      expiresAt: f.now() + 20 * day,
    });
    const short = await f.iam.api.packages.request(people.bob!.credential, {
      tenantId,
      packageId: kit.id,
      expiresAt: f.now() + 3 * day,
    });
    await f.iam.api.packages.update(owner, {
      tenantId,
      packageId: kit.id,
      maxDurationMs: 7 * day,
    });
    expect(await storedStatus(f, long.id)).toBe('cancelled');
    expect(await storedStatus(f, short.id)).toBe('pending');
  });

  it('does not rewrite a request that already lapsed (reported expired) into a cancellation', async () => {
    const { f, tenantId, owner, reader, people } = await setup(['alice', 'bob']);
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [reader.id],
      requestable: true,
    });
    const lapsed = await f.iam.api.packages.request(people.alice!.credential, {
      tenantId,
      packageId: kit.id,
    });
    f.advance(day + hour);
    const live = await f.iam.api.packages.request(people.bob!.credential, {
      tenantId,
      packageId: kit.id,
    });
    expect(
      (await f.iam.api.packages.listRequests(owner, { tenantId, identityId: people.alice!.id }))[0]
        ?.status,
    ).toBe('expired');
    await f.iam.api.packages.update(owner, { tenantId, packageId: kit.id, requestable: false });
    // The live one is cancelled by the change...
    expect(await storedStatus(f, live.id)).toBe('cancelled');
    // ...but the one that had already lapsed stays expired: the change did not end it.
    // STILL FAILING: updatePackage selects stored status 'pending' without the lapse check (pendingRequest), so it
    // overwrites the lapsed request with status 'cancelled', decidedAt = now and the package-change note.
    const reported = (
      await f.iam.api.packages.listRequests(owner, { tenantId, identityId: people.alice!.id })
    )[0];
    expect(reported).toMatchObject({ id: lapsed.id, status: 'expired' });
    expect(reported?.decidedAt).toBeUndefined();
    expect(reported?.note).toBeUndefined();
    expect((await f.iam.purgeDeleted()).expiredRequests).toBe(1);
    expect(await storedStatus(f, lapsed.id)).toBe('expired');
  });
});

describe('deciding on a request for a package that is no longer requestable', () => {
  it('refuses approval with INVALID_TRANSITION but still allows denial', async () => {
    const { f, tenantId, owner, reader, people } = await setup(['alice', 'bob']);
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [reader.id],
      requestable: true,
    });
    const first = await f.iam.api.packages.request(people.alice!.credential, {
      tenantId,
      packageId: kit.id,
    });
    const second = await f.iam.api.packages.request(people.bob!.credential, {
      tenantId,
      packageId: kit.id,
    });
    // Flip requestable off behind the API, so the pending requests are not cancelled by packages.update.
    const stored = await f.database.get<{ id: string; requestable?: boolean }>(
      'accessPackages',
      kit.id,
    );
    expect(stored?.requestable).toBe(true);
    const { requestable: _requestable, ...rest } = stored!;
    await f.database.transaction((tx) => tx.put('accessPackages', rest));
    expect(await storedStatus(f, first.id)).toBe('pending');
    const refused = await failure(
      f.iam.api.packages.approveRequest(owner, { tenantId, requestId: first.id }),
    );
    expect(refused?.code).toBe('INVALID_TRANSITION');
    const refusedWithEnd = await failure(
      f.iam.api.packages.approveRequest(owner, {
        tenantId,
        requestId: first.id,
        expiresAt: f.now() + day,
      }),
    );
    expect(refusedWithEnd?.code).toBe('INVALID_TRANSITION');
    // Nothing was granted and the request is still pending.
    expect(await storedStatus(f, first.id)).toBe('pending');
    expect(
      await f.iam.api.packages.listAssignments(owner, { tenantId, packageId: kit.id }),
    ).toEqual([]);
    expect(
      (
        await f.iam.authorize({
          ...people.alice!.credential,
          tenantId,
          action: 'documents:read',
          resource: { type: 'documents', id: 'a' },
        })
      ).allowed,
    ).toBe(false);
    // Denying still works.
    const denied = await f.iam.api.packages.denyRequest(owner, {
      tenantId,
      requestId: first.id,
      note: 'No longer offered',
    });
    expect(denied).toMatchObject({
      status: 'denied',
      decidedBy: f.ownerId,
      note: 'No longer offered',
    });
    expect(await storedStatus(f, first.id)).toBe('denied');
    expect(
      (await f.iam.api.packages.denyRequest(owner, { tenantId, requestId: second.id })).status,
    ).toBe('denied');
  });
});
