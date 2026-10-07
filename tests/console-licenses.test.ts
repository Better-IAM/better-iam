import { afterEach, describe, expect, it } from 'vitest';
import { maxLicenseFeatureKeys, type LicenseUsage } from '@better-iam/server';
import {
  bodyFrom,
  dateTimeLocalValue,
  selectDefault,
  textDefault,
  type FieldSpec,
} from '../apps/console/src/lib/form-body.js';
import {
  assignableGroups,
  assignablePeople,
  assignableProducts,
  assignFields,
  assignManyFields,
  assignManyLimit,
  featureKeyLimit,
  memberAssignFields,
  poolEditFields,
  poolFields,
  poolState,
  poolTenantOptions,
  productEditFields,
  productFields,
  reclaimDays,
  scopeLabel,
  seatInactive,
  seatLabel,
  settingsFields,
  subscriptionOptions,
  usageRatio,
  usageSummary,
  usageTone,
  usageTotals,
} from '../apps/console/src/lib/licenses.js';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const DAY = 86_400_000;

/**
 * What a browser submits for a form: the typed values, else what each field shows by default (a pre-filled date and
 * time as the browser formats it), read back by the console's own `bodyFrom`.
 */
function submit<T = Record<string, unknown>>(
  fields: FieldSpec[],
  typed: Record<string, string | string[] | boolean> = {},
): T {
  const data = new FormData();
  for (const field of fields) {
    const value =
      field.name in typed
        ? typed[field.name]!
        : field.type === 'checkbox'
          ? Boolean(field.defaultValue)
          : field.type === 'select' || field.type === 'multiselect'
            ? selectDefault(field)
            : field.type === 'datetime' && typeof field.defaultValue === 'number'
              ? dateTimeLocalValue(field.defaultValue)
              : textDefault(field);
    if (value === true) data.append(field.name, 'on');
    else if (value === false) continue;
    else if (Array.isArray(value)) for (const item of value) data.append(field.name, item);
    else data.append(field.name, value);
  }
  return bodyFrom(data, fields) as T;
}

const usage = (figures: Partial<LicenseUsage>): LicenseUsage => ({
  productId: 'p1',
  key: 'pro',
  name: 'Pro',
  scope: 'tenant',
  status: 'active',
  capacity: 10,
  active: 4,
  waiting: 0,
  available: 6,
  pools: 1,
  assignments: 4,
  reclaimable: 0,
  reclaimableThroughGroups: 0,
  ...figures,
});

describe('console licenses helpers', () => {
  it('summarizes usage for the meters and tiles', () => {
    expect(usageRatio(usage({}))).toBe(0.4);
    expect(usageTone(usage({}))).toBe('success');
    expect(usageTone(usage({ active: 9, available: 1 }))).toBe('warning');
    expect(usageTone(usage({ active: 10, available: 0, waiting: 2 }))).toBe('danger');
    // Claims without capacity fill the meter; a product nobody uses leaves it empty.
    expect(usageRatio(usage({ capacity: 0, active: 0, waiting: 3, available: 0 }))).toBe(1);
    expect(usageRatio(usage({ capacity: 0, active: 0, available: 0 }))).toBe(0);
    expect(usageTone(usage({ capacity: 0, active: 0, available: 0 }))).toBe('neutral');
    expect(usageSummary(usage({ waiting: 2, pools: 2, assignments: 1, reclaimable: 1 }))).toBe(
      '6 available · 2 waiting · 2 live pools · 1 assignment · 1 reclaimable',
    );
    expect(
      usageTotals([
        usage({ reclaimable: 2, reclaimableThroughGroups: 1 }),
        usage({ productId: 'p2', capacity: 5, active: 5, available: 0, waiting: 3 }),
        usage({ productId: 'p3', status: 'retired', capacity: 7, active: 0, available: 7 }),
      ]),
    ).toEqual({
      products: 2,
      capacity: 15,
      active: 9,
      waiting: 3,
      available: 6,
      reclaimable: 2,
      reclaimableThroughGroups: 1,
    });
  });

  it('labels products, seats and pools', () => {
    expect(scopeLabel({ scope: 'platform', definedHere: false })).toBe('Platform');
    expect(scopeLabel({ scope: 'tenant', definedHere: true })).toBe('This organization');
    expect(scopeLabel({ scope: 'tenant', definedHere: false })).toBe('Enclosing organization');
    expect(seatLabel({ status: 'active' })).toBe('active');
    expect(seatLabel({ status: 'waiting', position: 3 })).toBe('waiting #3');
    const now = Date.UTC(2026, 8, 24);
    expect(poolState({ live: true }, now)).toBe('live');
    expect(poolState({ live: false, startsAt: now + DAY }, now)).toBe('scheduled');
    expect(poolState({ live: false, startsAt: now - 9 * DAY }, now)).toBe('ended');
    const seat = { status: 'active' as const, assignedAt: now - 60 * DAY };
    expect(seatInactive({ ...seat, lastActivityAt: now - 40 * DAY }, 30, now)).toBe(true);
    expect(seatInactive({ ...seat, lastActivityAt: now - 10 * DAY }, 30, now)).toBe(false);
    // Not yet seen by a reclaim pass, reclaim off, recently assigned, or waiting: never inactive.
    expect(seatInactive(seat, 30, now)).toBe(false);
    expect(seatInactive({ ...seat, lastActivityAt: 0 }, undefined, now)).toBe(false);
    expect(seatInactive({ ...seat, assignedAt: now - 5 * DAY, lastActivityAt: 0 }, 30, now)).toBe(
      false,
    );
    expect(seatInactive({ ...seat, status: 'waiting', lastActivityAt: 0 }, 30, now)).toBe(false);
  });

  it('offers only what can still be given', () => {
    const acme = { id: 't-acme', name: 'Acme' };
    expect(
      poolTenantOptions(acme, [
        { id: 't-zeta', name: 'Zeta', status: 'active' },
        { id: 't-old', name: 'Old', status: 'deleted' },
        { id: 't-apollo', name: 'Apollo', status: 'suspended' },
      ]),
    ).toEqual([
      { value: 't-acme', label: 'Acme (this organization)' },
      { value: 't-apollo', label: 'Apollo' },
      { value: 't-zeta', label: 'Zeta' },
    ]);
    const assigned = [
      { subjectType: 'identity' as const, subjectId: 'bob' },
      { subjectType: 'group' as const, subjectId: 'sales' },
    ];
    expect(
      assignablePeople(
        [
          { id: 'carol', name: 'Carol', email: 'carol@acme.test', status: 'active' },
          { id: 'bob', name: 'Bob', status: 'active' },
          { id: 'dave', name: 'Dave', status: 'disabled' },
          { id: 'sales', name: 'Alice', status: 'active' },
        ],
        assigned,
      ),
    ).toEqual([
      // A group assignment never hides a person, even one whose ID matches.
      { value: 'sales', label: 'Alice' },
      { value: 'carol', label: 'Carol (carol@acme.test)' },
    ]);
    expect(
      assignableGroups(
        [
          { id: 'sales', name: 'Sales' },
          { id: 'eng', name: 'Engineering' },
        ],
        assigned,
      ),
    ).toEqual([{ value: 'eng', label: 'Engineering' }]);
    expect(
      assignableProducts(
        [
          { id: 'p1', key: 'pro', name: 'Pro', status: 'active' },
          { id: 'p2', key: 'basic', name: 'Basic', status: 'active' },
          { id: 'p3', key: 'legacy', name: 'Legacy', status: 'retired' },
        ],
        ['p1'],
      ),
    ).toEqual([{ value: 'p2', label: 'Basic (basic)' }]);
    expect(
      subscriptionOptions([
        { id: 's1', planName: 'Team', accountId: 't-acme', accountName: 'Acme', status: 'active' },
      ]),
    ).toEqual([{ value: 's1', label: 'Team · Acme (active)' }]);
    // The limits the forms mention are the server's.
    expect(featureKeyLimit).toBe(maxLicenseFeatureKeys);
    expect(assignManyLimit).toBe(100);
  });

  it('sends bodies the licenses API accepts', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const licenses = f.iam.api.licenses;

    const created = await licenses.createProduct(
      owner,
      submit(productFields(tenantId), { key: 'pro', name: 'Pro', featureKeys: 'sso, exports ,' }),
    );
    expect(created).toMatchObject({ key: 'pro', name: 'Pro', featureKeys: ['exports', 'sso'] });
    expect(created.description).toBeUndefined();
    const described = await licenses.updateProduct(
      owner,
      submit(productEditFields(tenantId, created), { description: 'Everything in Pro' }),
    );
    expect(described).toMatchObject({
      description: 'Everything in Pro',
      featureKeys: ['exports', 'sso'],
    });
    // An emptied description is cleared; emptied feature keys are kept.
    const pro = await licenses.updateProduct(
      owner,
      submit(productEditFields(tenantId, described), { description: '', featureKeys: '' }),
    );
    expect(pro.description).toBeUndefined();
    expect(pro.featureKeys).toEqual(['exports', 'sso']);

    const configured = await licenses.configure(
      owner,
      submit(settingsFields(tenantId, await licenses.getSettings(owner, { tenantId })), {
        reclaimAfterDays: '30',
        notifyWaiting: true,
      }),
    );
    expect(configured).toMatchObject({ reclaimAfterDays: 30, notifyWaiting: true });
    // Emptying the period turns reclaim off and leaves the email choice as it was.
    const off = await licenses.configure(
      owner,
      submit(settingsFields(tenantId, configured), { reclaimAfterDays: '' }),
    );
    expect(off.reclaimAfterDays).toBeUndefined();
    expect(off.notifyWaiting).toBe(true);
    await expect(
      licenses.configure(
        owner,
        submit(settingsFields(tenantId, off), { reclaimAfterDays: String(reclaimDays.min - 1) }),
      ),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(
      await licenses.configure(
        owner,
        submit(settingsFields(tenantId, off), { reclaimAfterDays: String(reclaimDays.max) }),
      ),
    ).toMatchObject({ reclaimAfterDays: reclaimDays.max });

    const alice = await f.member('alice');
    const bob = await f.member('bob');
    const carol = await f.member('carol');
    const sales = await f.iam.api.groups.create(owner, { tenantId, name: 'Sales' });
    await f.iam.api.groups.addMember(owner, { tenantId, groupId: sales.id, identityId: carol.id });

    // One option (no projects): the consuming tenant is a hidden field.
    const addFields = poolFields(
      tenantId,
      pro.id,
      poolTenantOptions({ id: tenantId, name: 'Acme' }, []),
      [],
    );
    expect(addFields.find((field) => field.name === 'tenantId')?.type).toBe('hidden');
    const added = await licenses.addPool(
      owner,
      submit(addFields, {
        quantity: '1',
        endsAt: dateTimeLocalValue(f.now() + 30 * DAY),
        note: 'PO-1',
      }),
    );
    expect(added.pool).toMatchObject({
      tenantId,
      quantity: 1,
      note: 'PO-1',
      source: 'manual',
      live: true,
    });

    const people = await f.iam.api.identities.list(owner, { tenantId, limit: 1000 });
    f.advance(1000);
    await licenses.assign(
      owner,
      submit(assignFields(tenantId, pro.id, 'identity', assignablePeople(people, [])), {
        subjectId: alice.id,
      }),
    );
    f.advance(1000);
    const many = await licenses.assignMany(
      owner,
      submit(
        assignManyFields(
          tenantId,
          pro.id,
          assignablePeople(
            people,
            (await licenses.listAssignments(owner, { tenantId })).assignments,
          ),
        ),
        { identityIds: [bob.id] },
      ),
    );
    expect(many.assigned.map((assignment) => assignment.subjectId)).toEqual([bob.id]);
    f.advance(1000);
    const groups = await f.iam.api.groups.list(owner, { tenantId });
    await licenses.assign(
      owner,
      submit(assignFields(tenantId, pro.id, 'group', assignableGroups(groups, [])), {
        subjectId: sales.id,
      }),
    );
    f.advance(1000);
    // From Carol's member page: a direct assignment besides the group's.
    const products = (await licenses.listProducts(owner, { tenantId, status: 'active' })).products;
    await licenses.assign(
      owner,
      submit(memberAssignFields(tenantId, carol.id, assignableProducts(products, [])), {
        productId: pro.id,
      }),
    );
    const seats = (await licenses.listSeats(owner, { tenantId, productId: pro.id })).seats;
    expect(seats.map((seat) => `${seat.identityName} ${seatLabel(seat)}`)).toEqual([
      'alice active',
      'bob waiting #1',
      'carol waiting #2',
    ]);
    expect(seats[2]).toMatchObject({ direct: true, groupIds: [sales.id] });

    // Untouched, the end is sent as stored; more seats move the waiting list up.
    const grown = await licenses.updatePool(
      owner,
      submit(poolEditFields(added.pool), { quantity: '3', note: '' }),
    );
    expect(grown.pool.endsAt).toBe(added.pool.endsAt);
    expect(grown.pool.note).toBeUndefined();
    expect(grown.seats.map((change) => change.to)).toEqual(['active', 'active']);
    // An emptied end makes the pool open-ended.
    const open = await licenses.updatePool(
      owner,
      submit(poolEditFields(grown.pool), { endsAt: '' }),
    );
    expect(open.pool.endsAt).toBeUndefined();
    expect(open.pool.quantity).toBe(3);

    const report = await licenses.usage(owner, { tenantId });
    const figures = report.products.find((product) => product.productId === pro.id)!;
    expect(usageSummary(figures)).toBe('0 available · 1 live pool · 4 assignments');
    expect(usageTone(figures)).toBe('warning');
  });
});
