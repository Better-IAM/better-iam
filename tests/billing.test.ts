import { afterEach, describe, expect, it } from 'vitest';
import { renderDeliveryMessage } from '@better-iam/auth';
import { createIamClient } from '@better-iam/client';
import {
  periodBounds,
  periodOf,
  priceQuantity,
  priceSpec,
  routeGroups,
  shiftPeriod,
  type GatewayPermit,
} from '@better-iam/server';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

/** A project under Acme whose owner has accepted the invitation. */
async function project(f: OrganizationFixture, name = 'Apollo') {
  const created = await f.iam.api.tenants.create(f.ownerCredential, {
    parentId: f.tenantId,
    name,
    type: 'project',
    ownerEmail: `${name.toLowerCase()}@acme.test`,
  });
  await f.iam.auth.dispatchOutbox();
  const invitation = f.inbox.find(
    (message) => message.tenantId === created.tenant.id && message.template === 'owner-invitation',
  )!;
  const owner = await f.iam.api.tenants.acceptInvitation({
    tenantId: created.tenant.id,
    token: invitation.payload.token!,
    name: `${name} owner`,
    password: `a strong ${name} owner password`,
  });
  if (!('token' in owner)) throw new Error('Unexpected MFA');
  return { tenantId: created.tenant.id, credential: { token: owner.token } };
}

/** Acme with a platform `api-calls` meter: 1000 free calls a month, then $0.01 each up to 10 000, then $0.005. */
async function setup() {
  const f = await organizationFixture();
  const rootId = f.root.tenant.id;
  await f.iam.api.billing.createMeter(f.rootCredential, {
    tenantId: rootId,
    key: 'api-calls',
    name: 'API calls',
    unit: 'request',
  });
  await f.iam.api.billing.setPrice(f.rootCredential, {
    tenantId: rootId,
    meter: 'api-calls',
    // From last month on, so usage backdated into it is priced too (nothing is invoiced yet).
    effectiveFrom: shiftPeriod(periodOf(f.now(), 'UTC'), -1),
    price: {
      model: 'graduated',
      includedQuantity: 1000,
      tiers: [
        { upTo: 10_000, unitAmount: 0.01 },
        { upTo: null, unitAmount: 0.005 },
      ],
    },
  });
  const alice = await f.member('alice');
  const bob = await f.member('bob');
  const carol = await f.member('carol');
  const record = (identityId: string, quantity: number, extra: Record<string, unknown> = {}) =>
    f.iam.api.billing.record(f.ownerCredential, {
      tenantId: f.tenantId,
      meter: 'api-calls',
      quantity,
      identityId,
      ...extra,
    });
  return { f, rootId, alice, bob, carol, record };
}

const previousPeriodStart = (f: OrganizationFixture) =>
  periodBounds(shiftPeriod(periodOf(f.now(), 'UTC'), -1), 'UTC').start;

describe('pricing', () => {
  it('prices per unit, graduated and volume tiers, packages and included units', () => {
    const graduated = priceSpec({
      model: 'graduated',
      tiers: [
        { upTo: 100, unitAmount: 1 },
        { upTo: null, unitAmount: 0.5, flatAmount: 10 },
      ],
    });
    // 100 × $1 + 50 × $0.50 + $10 flat.
    expect(priceQuantity(graduated, 150)).toBe(135_000_000);
    const volume = priceSpec({
      model: 'volume',
      tiers: [
        { upTo: 100, unitAmount: 1 },
        { upTo: null, unitAmount: 0.5 },
      ],
    });
    expect(priceQuantity(volume, 150)).toBe(75_000_000);
    expect(priceQuantity(volume, 100)).toBe(100_000_000);
    const packaged = priceSpec({ model: 'package', packageSize: 1000, packageAmount: 2 });
    expect(priceQuantity(packaged, 1001)).toBe(4_000_000);
    const included = priceSpec({
      model: 'per-unit',
      unitAmount: 0.000002,
      includedQuantity: 1_000_000,
    });
    expect(priceQuantity(included, 3_500_000)).toBe(5_000_000);
    expect(() => priceSpec({ model: 'graduated', tiers: [{ upTo: 5, unitAmount: 1 }] })).toThrow(
      'Only the last tier has upTo: null',
    );
    expect(routeGroups.has('billing')).toBe(true);
  });
});

describe('billing and spend', () => {
  it('prices the account total once and shares it out by person, meter and project', async () => {
    const { f, rootId, alice, bob, record } = await setup();
    const apollo = await project(f);
    await record(alice.id, 3000);
    await record(bob.id, 500);
    await f.iam.api.billing.record(apollo.credential, {
      tenantId: apollo.tenantId,
      meter: 'api-calls',
      quantity: 500,
    });
    // 4000 calls, 1000 free: 3000 × $0.01 = $30, shared by quantity (75% / 12.5% / 12.5%).
    const byPerson = await f.iam.api.billing.spend(f.ownerCredential, {
      tenantId: f.tenantId,
      groupBy: 'identity',
    });
    expect(byPerson.total).toMatchObject({ costMicros: 30_000_000, amount: 30, events: 3 });
    expect(byPerson.currency).toBe('USD');
    expect(byPerson.rows).toEqual([
      expect.objectContaining({
        key: alice.id,
        costMicros: 22_500_000,
        share: 75,
        label: 'alice <alice@acme.test>',
      }),
      expect.objectContaining({ key: '(unattributed)', costMicros: 3_750_000 }),
      expect.objectContaining({
        key: bob.id,
        costMicros: 3_750_000,
        quantities: { 'api-calls': 500 },
      }),
    ]);
    const byProject = await f.iam.api.billing.spend(f.ownerCredential, {
      tenantId: f.tenantId,
      groupBy: 'tenant',
    });
    expect(byProject.rows.map((row) => [row.label, row.amount])).toEqual([
      ['Acme', 26.25],
      ['Apollo', 3.75],
    ]);
    // The project's own view covers only its subtree, priced within Acme's account.
    const projectView = await f.iam.api.billing.spend(apollo.credential, {
      tenantId: apollo.tenantId,
    });
    expect(projectView.rows).toEqual([
      expect.objectContaining({ key: 'api-calls', label: 'API calls', costMicros: 3_750_000 }),
    ]);
    // The platform sees every organization.
    const platform = await f.iam.api.billing.accounts(f.rootCredential, { tenantId: rootId });
    expect(platform).toEqual([
      expect.objectContaining({
        accountId: f.tenantId,
        name: 'Acme',
        monthToDateMicros: 30_000_000,
      }),
    ]);
    // A negotiated price for Acme wins over the list price from this period on.
    await f.iam.api.billing.setPrice(f.rootCredential, {
      tenantId: rootId,
      meter: 'api-calls',
      targetTenantId: f.tenantId,
      price: { model: 'per-unit', unitAmount: 0.002 },
      note: 'Enterprise agreement',
    });
    const negotiated = await f.iam.api.billing.spend(f.ownerCredential, { tenantId: f.tenantId });
    expect(negotiated.total.costMicros).toBe(8_000_000);
    const card = await f.iam.api.billing.listPrices(f.ownerCredential, {
      tenantId: f.tenantId,
      meter: 'api-calls',
    });
    expect(card.effective).toMatchObject({
      targetTenantId: f.tenantId,
      note: 'Enterprise agreement',
    });
    expect(card.entries).toHaveLength(2);
    expect(
      await f.iam.api.billing.quote(f.ownerCredential, {
        tenantId: f.tenantId,
        meter: 'api-calls',
        quantity: 1000,
      }),
    ).toMatchObject({ amountMicros: 2_000_000, amount: 2 });
    // Organizations cannot price platform meters or define keys the platform owns.
    await expect(
      f.iam.api.billing.setPrice(f.ownerCredential, {
        tenantId: f.tenantId,
        meter: 'api-calls',
        price: { model: 'per-unit', unitAmount: 0 },
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(
      f.iam.api.billing.createMeter(f.ownerCredential, {
        tenantId: f.tenantId,
        key: 'api-calls',
        name: 'Mine',
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('validates usage, stays idempotent, and records through the trusted runtime', async () => {
    const { f, alice, record } = await setup();
    const first = await record(alice.id, 10, {
      idempotencyKey: 'request-1',
      tags: { env: 'prod' },
    });
    const again = await record(alice.id, 10, { idempotencyKey: 'request-1' });
    expect(again).toMatchObject({ id: first.id, duplicate: true });
    await expect(record(alice.id, 1, { cost: 1 })).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.billing.record(f.ownerCredential, { tenantId: f.tenantId, meter: 'nope' }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
    await expect(record(alice.id, -1)).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(record(alice.id, 1, { occurredAt: f.now() + 3_600_000 })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    // The server records without a credential (and without an audit event per call).
    await f.iam.billing.record({
      tenantId: f.tenantId,
      meter: 'api-calls',
      quantity: 5,
      identityId: alice.id,
      tags: { env: 'staging' },
    });
    const byEnv = await f.iam.billing.spend({ tenantId: f.tenantId, groupBy: 'tag:env' });
    expect(byEnv.rows.map((row) => [row.key, row.quantities['api-calls']])).toEqual([
      ['prod', 10],
      ['staging', 5],
    ]);
    const events = await f.iam.api.billing.listUsage(f.ownerCredential, { tenantId: f.tenantId });
    expect(events.events).toHaveLength(2);
    expect(events.events.find((event) => event.quantity === 10)).toMatchObject({
      idempotencyKey: 'request-1',
      recordedBy: f.ownerId,
      tags: { env: 'prod' },
    });
    // Archived meters keep their history but refuse new usage.
    await f.iam.api.billing.updateMeter(f.rootCredential, {
      tenantId: f.root.tenant.id,
      key: 'api-calls',
      archived: true,
    });
    await expect(record(alice.id, 1)).rejects.toMatchObject({ code: 'METER_ARCHIVED' });
    await expect(
      f.iam.api.billing.deleteMeter(f.rootCredential, {
        tenantId: f.root.tenant.id,
        key: 'api-calls',
      }),
    ).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' });
    // Members without billing permissions can read only their own spend.
    const bobSession = { token: (await f.signIn('bob')).token };
    await expect(
      f.iam.api.billing.spend(bobSession, { tenantId: f.tenantId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const aliceSession = { token: (await f.signIn('alice')).token };
    const mine = await f.iam.api.billing.mySpend(aliceSession, { tenantId: f.tenantId });
    expect(mine.rows).toEqual([
      expect.objectContaining({ key: 'api-calls', quantities: { 'api-calls': 15 } }),
    ]);
    const bobs = await f.iam.api.billing.mySpend(bobSession, { tenantId: f.tenantId });
    expect(bobs.rows).toEqual([]);
    await expect(
      f.iam.api.billing.mySpend(bobSession, {
        tenantId: f.tenantId,
        groupBy: 7 as unknown as 'meter',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // The typed client reaches the same routes over HTTP.
    const client = createIamClient<typeof f.iam>({
      baseURL: 'http://localhost:3000',
      token: aliceSession.token,
      fetch: async (input, init) => f.iam.handler(new Request(input, init)),
    });
    expect((await client.billing.mySpend({ tenantId: f.tenantId })).total).toEqual(mine.total);
    expect(await client.billing.check({ tenantId: f.tenantId })).toEqual({
      allowed: true,
      budgets: [],
    });
  });

  it('attributes spend to teams and departments, readable by maintainers and heads', async () => {
    const { f, alice, bob, carol, record } = await setup();
    const engineering = await f.iam.api.departments.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Engineering',
      code: 'ENG',
      headId: carol.id,
      costCenter: 'CC-100',
    });
    await f.iam.api.departments.assign(f.ownerCredential, {
      tenantId: f.tenantId,
      departmentId: engineering.id,
      identityIds: [alice.id, bob.id],
    });
    const platform = await f.iam.api.teams.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Platform',
      departmentId: engineering.id,
      maintainerIds: [alice.id],
    });
    const web = await f.iam.api.teams.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Web',
      parentId: platform.id,
    });
    await f.iam.api.teams.addMember(f.ownerCredential, {
      tenantId: f.tenantId,
      teamId: web.id,
      identityId: bob.id,
    });
    await record(alice.id, 3000);
    await record(bob.id, 1000);
    await record(carol.id, 1000);
    // 5000 calls, 4000 billable at $0.01 = $40: alice 24, bob 8, carol 8.
    const byTeam = await f.iam.api.billing.spend(f.ownerCredential, {
      tenantId: f.tenantId,
      groupBy: 'team',
    });
    expect(byTeam.rows.map((row) => [row.label ?? row.key, row.amount])).toEqual([
      ['Platform', 24],
      ['(no team)', 8],
      ['Web', 8],
    ]);
    // A team's spend includes the teams below it; its maintainers may read it.
    const aliceSession = { token: (await f.signIn('alice')).token };
    const teamView = await f.iam.api.billing.teamSpend(aliceSession, {
      tenantId: f.tenantId,
      teamId: platform.id,
    });
    expect(teamView.total.amount).toBe(32);
    expect(teamView.rows.map((row) => row.key)).toEqual([alice.id, bob.id]);
    const bobSession = { token: (await f.signIn('bob')).token };
    await expect(
      f.iam.api.billing.teamSpend(bobSession, { tenantId: f.tenantId, teamId: platform.id }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Maintaining a team reads it only in the team's own tenant (or below), not from the platform's.
    await expect(
      f.iam.api.billing.teamSpend(aliceSession, {
        tenantId: f.root.tenant.id,
        teamId: platform.id,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Department spend rolls up people in the department; the head reads it.
    const carolSession = { token: (await f.signIn('carol')).token };
    const department = await f.iam.api.billing.departmentSpend(carolSession, {
      tenantId: f.tenantId,
      departmentId: engineering.id,
      groupBy: 'department',
    });
    expect(department.rows).toEqual([
      expect.objectContaining({ key: engineering.id, label: 'Engineering (ENG)', amount: 32 }),
    ]);
    const reads = await f.iam.api.audit.list(f.ownerCredential, {
      tenantId: f.tenantId,
      action: 'iam:billing:read',
    });
    // Reads through a role are audited with it; bob's refused attempt is audited as a denial.
    expect(
      reads
        .map((event) => event.metadata?.via)
        .filter(Boolean)
        .sort(),
    ).toEqual(['department-head', 'team-maintainer']);
    // Alice's attempt against the platform tenant is recorded here too, in her own tenant, naming its target.
    const denials = reads.filter((event) => event.outcome === 'deny');
    expect(denials.filter((event) => !event.metadata?.targetTenantId)).toHaveLength(1);
    expect(denials.filter((event) => event.metadata?.targetTenantId)).toMatchObject([
      { metadata: { targetTenantId: f.root.tenant.id } },
    ]);
  });

  it('alerts on budget thresholds once and enforces spent budgets', async () => {
    const { f, alice, bob, carol, record } = await setup();
    const platform = await f.iam.api.teams.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Platform',
      maintainerIds: [alice.id],
    });
    await f.iam.api.teams.addMember(f.ownerCredential, {
      tenantId: f.tenantId,
      teamId: platform.id,
      identityId: bob.id,
    });
    const budget = await f.iam.api.billing.createBudget(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Platform monthly',
      subjectType: 'team',
      subjectId: platform.id,
      amount: 20,
      thresholds: [50, 100],
      forecastAlerts: false,
      notify: { emails: ['finance@acme.test'] },
      enforce: true,
    });
    expect(budget).toMatchObject({
      spentMicros: 0,
      percent: 0,
      exceeded: false,
      subjectName: 'Platform',
    });
    await record(bob.id, 2500); // 1500 billable: $15 (75%).
    const firstRun = await f.iam.billing.checkBudgets();
    expect(firstRun.alerts).toEqual([
      expect.objectContaining({
        budgetId: budget.budgetId,
        kind: 'actual',
        threshold: 50,
        recipients: 3,
      }),
    ]);
    expect((await f.iam.billing.checkBudgets()).alerts).toEqual([]);
    await record(bob.id, 1000); // $25 in total.
    const secondRun = await f.iam.billing.checkBudgets();
    expect(secondRun.alerts).toEqual([expect.objectContaining({ threshold: 100 })]);
    await f.iam.auth.dispatchOutbox();
    const alerts = f.inbox.filter((message) => message.template === 'spend-alert');
    expect(alerts.map((message) => message.to).sort()).toEqual([
      'alice@acme.test',
      'alice@acme.test',
      'finance@acme.test',
      'finance@acme.test',
      'owner@acme.test',
      'owner@acme.test',
    ]);
    const full = alerts.find((message) => message.payload.threshold === '100')!;
    expect(full.payload).toMatchObject({
      spent: '$25.00',
      amount: '$20.00',
      budgetName: 'Platform monthly',
      subjectName: 'Platform',
    });
    const rendered = renderDeliveryMessage(full, {
      links: { billing: ({ tenantId }) => `https://console.test/cloud/${tenantId}/billing` },
    })!;
    expect(rendered.subject).toBe('Platform monthly has reached 100% of its budget');
    expect(rendered.text).toContain('Platform has spent $25.00 of the $20.00 budget');
    expect(rendered.text).toContain(`https://console.test/cloud/${f.tenantId}/billing`);
    // The spent budget now refuses the team's usage when asked to enforce.
    const bobSession = { token: (await f.signIn('bob')).token };
    const verdict = await f.iam.api.billing.check(bobSession, { tenantId: f.tenantId });
    expect(verdict).toMatchObject({ allowed: false, blockedBy: { name: 'Platform monthly' } });
    await expect(record(bob.id, 1, { enforceBudgets: true })).rejects.toMatchObject({
      code: 'SPEND_LIMIT_REACHED',
      status: 402,
    });
    // People outside the team are not covered by its budget.
    await record(carol.id, 1, { enforceBudgets: true });
    const listed = await f.iam.api.billing.listBudgets(f.ownerCredential, { tenantId: f.tenantId });
    expect(listed[0]).toMatchObject({ reached: [50, 100], exceeded: true });
    await expect(
      f.iam.api.billing.createBudget(f.ownerCredential, {
        tenantId: f.tenantId,
        name: 'platform MONTHLY',
        amount: 1,
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
  });

  it('closes a period into statements with credits, and refuses late usage until voided', async () => {
    const { f, rootId, alice, record } = await setup();
    const lastMonth = shiftPeriod(periodOf(f.now(), 'UTC'), -1);
    await record(alice.id, 6000, { occurredAt: previousPeriodStart(f) + 3_600_000 });
    await f.iam.api.billing.setProfile(f.ownerCredential, {
      tenantId: f.tenantId,
      companyName: 'Acme Corporation',
      billingEmails: ['ap@acme.test'],
      purchaseOrder: 'PO-7',
      paymentTermsDays: 15,
    });
    const credit = await f.iam.api.billing.grantCredit(f.rootCredential, {
      tenantId: f.tenantId,
      amount: 20,
      reason: 'Launch promotion',
    });
    // Only root administrators grant credit or close periods.
    await expect(
      f.iam.api.billing.grantCredit(f.ownerCredential, {
        tenantId: f.tenantId,
        amount: 5,
        reason: 'x',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await expect(
      f.iam.api.billing.closePeriod(f.ownerCredential, { tenantId: f.tenantId }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const draft = await f.iam.api.billing.previewStatement(f.ownerCredential, {
      tenantId: f.tenantId,
      period: lastMonth,
    });
    expect(draft).toMatchObject({
      subtotalMicros: 50_000_000,
      creditsMicros: 20_000_000,
      totalMicros: 30_000_000,
    });

    const closed = await f.iam.api.billing.closePeriod(f.rootCredential, { tenantId: rootId });
    expect(closed).toMatchObject({ period: lastMonth, skipped: { existing: 0, empty: 0 } });
    expect(closed.issued).toEqual([
      expect.objectContaining({ accountId: f.tenantId, totalMicros: 30_000_000, recipients: 1 }),
    ]);
    expect(closed.issued[0]!.number).toBe(`INV-${lastMonth.replace('-', '')}-0001`);
    // Idempotent: a second run skips the invoiced account.
    expect((await f.iam.billing.closePeriod()).skipped.existing).toBe(1);
    await f.iam.auth.dispatchOutbox();
    const mailed = f.inbox.find((message) => message.template === 'billing-statement')!;
    expect(mailed).toMatchObject({
      to: 'ap@acme.test',
      payload: { total: '$30.00', period: lastMonth },
    });
    expect(renderDeliveryMessage(mailed)!.subject).toBe(
      `Your Better IAM statement ${closed.issued[0]!.number} for ${lastMonth}`,
    );

    const statements = await f.iam.api.billing.listStatements(f.ownerCredential, {
      tenantId: f.tenantId,
    });
    expect(statements).toEqual([
      expect.objectContaining({
        status: 'finalized',
        total: 30,
        overdue: false,
        tenantName: 'Acme',
      }),
    ]);
    const statement = await f.iam.api.billing.getStatement(f.ownerCredential, {
      tenantId: f.tenantId,
      statementId: statements[0]!.id,
    });
    expect(statement).toMatchObject({
      verified: true,
      lines: [{ meter: 'api-calls', quantity: 6000, amountMicros: 50_000_000 }],
      billTo: { companyName: 'Acme Corporation', purchaseOrder: 'PO-7', emails: ['ap@acme.test'] },
      breakdown: { identities: [{ id: alice.id, costMicros: 50_000_000 }] },
    });
    expect(statement.dueAt - statement.issuedAt).toBe(15 * 86_400_000);
    const sheet = await f.iam.api.billing.exportStatement(f.ownerCredential, {
      tenantId: f.tenantId,
      statementId: statement.id,
    });
    expect(sheet.filename).toBe(`${statement.number}.csv`);
    expect(sheet.body).toContain('line,api-calls,API calls,6000,request,50.000000,\r\n');
    expect(sheet.body).toContain('credit,,,,,-20.000000,\r\n');
    expect(sheet.body).toContain(`identity,${alice.id},alice,,,50.000000,\r\n`);
    const credits = await f.iam.api.billing.listCredits(f.ownerCredential, {
      tenantId: f.tenantId,
    });
    expect(credits).toMatchObject({
      balanceMicros: 0,
      credits: [{ id: credit.id, remainingMicros: 0 }],
    });

    // The invoiced period is closed to late usage.
    await expect(
      record(alice.id, 1, { occurredAt: previousPeriodStart(f) + 7_200_000 }),
    ).rejects.toMatchObject({ code: 'BILLING_PERIOD_CLOSED' });
    // Voiding restores the credit and reopens the period; closing again issues a new number.
    await f.iam.api.billing.voidStatement(f.rootCredential, {
      tenantId: f.tenantId,
      statementId: statement.id,
      reason: 'Usage correction',
    });
    expect(
      (await f.iam.api.billing.listCredits(f.ownerCredential, { tenantId: f.tenantId }))
        .balanceMicros,
    ).toBe(20_000_000);
    await record(alice.id, 1000, { occurredAt: previousPeriodStart(f) + 7_200_000 });
    const reissued = await f.iam.billing.closePeriod({ period: lastMonth });
    expect(reissued.issued).toEqual([
      expect.objectContaining({
        number: `INV-${lastMonth.replace('-', '')}-0002`,
        totalMicros: 40_000_000,
      }),
    ]);
    const paid = await f.iam.api.billing.markPaid(f.rootCredential, {
      tenantId: f.tenantId,
      statementId: reissued.issued[0]!.statementId,
      reference: 'wire-2231',
    });
    expect(paid).toMatchObject({ status: 'paid' });
    await expect(
      f.iam.api.billing.closePeriod(f.rootCredential, {
        tenantId: rootId,
        period: periodOf(f.now(), 'UTC'),
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });

  it('keeps organization chargeback meters off statements and bills projects with their own profile', async () => {
    const { f, rootId, alice, record } = await setup();
    const apollo = await project(f);
    // An internal meter Acme defines for its own chargeback, with costs reported per event.
    await f.iam.api.billing.createMeter(f.ownerCredential, {
      tenantId: f.tenantId,
      key: 'cloud-compute',
      name: 'Cloud compute',
      unit: 'vCPU-hour',
      pricing: 'reported',
    });
    const lastMonth = shiftPeriod(periodOf(f.now(), 'UTC'), -1);
    const at = previousPeriodStart(f) + 3_600_000;
    await f.iam.api.billing.record(f.ownerCredential, {
      tenantId: f.tenantId,
      meter: 'cloud-compute',
      quantity: 12,
      cost: 7.5,
      identityId: alice.id,
      occurredAt: at,
    });
    await expect(
      f.iam.api.billing.record(f.ownerCredential, {
        tenantId: f.tenantId,
        meter: 'cloud-compute',
        quantity: 1,
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await record(alice.id, 2000, { occurredAt: at });
    // The project becomes its own billing account: its owner alone may not decide that, the organization does.
    await expect(
      f.iam.api.billing.setProfile(apollo.credential, {
        tenantId: apollo.tenantId,
        companyName: 'Apollo',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(
      await f.iam.api.billing.getProfile(apollo.credential, { tenantId: apollo.tenantId }),
    ).toMatchObject({ account: { id: f.tenantId, inherited: true }, profile: null });
    await f.iam.api.billing.setProfile(f.ownerCredential, {
      tenantId: f.tenantId,
      targetTenantId: apollo.tenantId,
      companyName: 'Apollo Ltd',
    });
    // From then on the project's own billing managers keep it up to date.
    const updated = await f.iam.api.billing.setProfile(apollo.credential, {
      tenantId: apollo.tenantId,
      billingEmails: ['billing@apollo.test'],
    });
    expect(updated).toMatchObject({
      account: { id: apollo.tenantId, inherited: false },
      profile: { companyName: 'Apollo Ltd', billingEmails: ['billing@apollo.test'] },
    });
    await f.iam.api.billing.record(apollo.credential, {
      tenantId: apollo.tenantId,
      meter: 'api-calls',
      quantity: 1500,
      occurredAt: at,
    });
    const spend = await f.iam.api.billing.spend(f.ownerCredential, {
      tenantId: f.tenantId,
      period: lastMonth,
      groupBy: 'meter',
    });
    expect(spend.rows.map((row) => [row.key, row.amount])).toEqual([
      ['api-calls', 15],
      ['cloud-compute', 7.5],
    ]);
    // The platform's view of what it bills leaves Acme's chargeback meter out.
    const platform = await f.iam.api.billing.spend(f.rootCredential, {
      tenantId: rootId,
      period: lastMonth,
      billableOnly: true,
    });
    expect(platform.rows.map((row) => row.key)).toEqual(['api-calls']);
    const closed = await f.iam.billing.closePeriod();
    const byAccount = Object.fromEntries(
      closed.issued.map((entry) => [entry.accountId, entry.totalMicros]),
    );
    // Each account gets its own 1000 free calls; the chargeback meter never reaches a statement.
    expect(byAccount).toEqual({ [f.tenantId]: 10_000_000, [apollo.tenantId]: 5_000_000 });
    const all = await f.iam.api.billing.listStatements(f.rootCredential, { tenantId: rootId });
    expect(all).toHaveLength(2);
    const acme = await f.iam.api.billing.getStatement(f.ownerCredential, {
      tenantId: f.tenantId,
      statementId: all.find((entry) => entry.tenantId === f.tenantId)!.id,
    });
    expect(acme.lines.map((line) => line.meter)).toEqual(['api-calls']);
  });

  it('records seats daily for every active person and bills active users', async () => {
    const { f, rootId } = await setup();
    await f.iam.api.billing.createMeter(f.rootCredential, {
      tenantId: rootId,
      key: 'seats',
      name: 'Active seats',
      unit: 'seat',
      aggregation: 'unique',
    });
    await f.iam.api.billing.setPrice(f.rootCredential, {
      tenantId: rootId,
      meter: 'seats',
      price: { model: 'per-unit', unitAmount: 12 },
    });
    const first = await f.iam.billing.recordSeats();
    // The owner, alice, bob and carol.
    expect(first).toMatchObject({ meter: 'seats', recorded: 4, duplicates: 0 });
    expect(await f.iam.billing.recordSeats()).toMatchObject({ recorded: 0, duplicates: 4 });
    const spend = await f.iam.billing.spend({ tenantId: f.tenantId, groupBy: 'meter' });
    expect(spend.rows).toEqual([expect.objectContaining({ key: 'seats', costMicros: 48_000_000 })]);
    const perPerson = await f.iam.billing.spend({ tenantId: f.tenantId, groupBy: 'identity' });
    expect(perPerson.rows.every((row) => row.costMicros === 12_000_000)).toBe(true);
  });

  it('feeds metered inference calls into the ledger as the inference meter', async () => {
    const f = await organizationFixture({ inference: true });
    const provider = await f.iam.api.inference.createProvider(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Anthropic',
      kind: 'anthropic',
      apiKey: 'sk-ant-billing-test-key-0001',
    });
    await f.iam.api.inference.createModel(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'haiku',
      providerId: provider.id,
      upstreamModel: 'claude-haiku-4-5',
      inputPricePerMTok: 1,
      outputPricePerMTok: 5,
    });
    const outcome = await f.iam.inference.authorize(f.ownerCredential, { model: 'haiku' });
    if ('denied' in outcome) throw new Error('denied');
    await f.iam.inference.record(outcome as GatewayPermit, {
      model: 'haiku',
      inputTokens: 1000,
      outputTokens: 200,
    });
    const spend = await f.iam.api.billing.spend(f.ownerCredential, {
      tenantId: f.tenantId,
      groupBy: 'tag:model',
    });
    // 1000 × $1/M + 200 × $5/M = $0.002.
    expect(spend.rows).toEqual([
      expect.objectContaining({ key: 'haiku', costMicros: 2000, quantities: { inference: 1200 } }),
    ]);
    const meters = await f.iam.api.billing.listMeters(f.ownerCredential, { tenantId: f.tenantId });
    expect(meters).toEqual([
      expect.objectContaining({
        key: 'inference',
        pricing: 'reported',
        scope: 'platform',
        inherited: true,
      }),
    ]);
  });
});

describe('billing insights', () => {
  it('finds spend spikes, alerts on them once, and exports CSV', async () => {
    const { f, rootId, alice, bob } = await setup();
    await f.iam.api.billing.createMeter(f.rootCredential, {
      tenantId: rootId,
      key: 'builds',
      name: 'CI builds',
      unit: 'build',
    });
    await f.iam.api.billing.setPrice(f.rootCredential, {
      tenantId: rootId,
      meter: 'builds',
      effectiveFrom: shiftPeriod(periodOf(f.now(), 'UTC'), -1),
      price: { model: 'per-unit', unitAmount: 1 },
    });
    const noonDaysAgo = (days: number) => {
      const today = new Date(f.now());
      return (
        Date.UTC(today.getUTCFullYear(), today.getUTCMonth(), today.getUTCDate() - days) +
        43_200_000
      );
    };
    const build = (identityId: string, quantity: number, daysAgo: number) =>
      f.iam.billing.record({
        tenantId: f.tenantId,
        meter: 'builds',
        quantity,
        identityId,
        occurredAt: noonDaysAgo(daysAgo),
      });
    for (let daysAgo = 2; daysAgo <= 15; daysAgo++) {
      await build(bob.id, 2, daysAgo);
      await build(alice.id, 1, daysAgo);
    }
    await build(bob.id, 40, 1);
    await build(alice.id, 1, 1);
    const found = await f.iam.api.billing.anomalies(f.ownerCredential, { tenantId: f.tenantId });
    expect(found.anomalies).toEqual([
      expect.objectContaining({
        dimension: 'meter',
        key: 'builds',
        label: 'CI builds',
        costMicros: 41_000_000,
        baselineMicros: 3_000_000,
      }),
      expect.objectContaining({
        dimension: 'identity',
        key: bob.id,
        label: 'bob',
        costMicros: 40_000_000,
        baselineMicros: 2_000_000,
        factor: 20,
      }),
    ]);
    // A higher bar reports nothing.
    expect(
      (await f.iam.api.billing.anomalies(f.ownerCredential, { tenantId: f.tenantId, factor: 50 }))
        .anomalies,
    ).toEqual([]);
    await expect(
      f.iam.api.billing.anomalies(f.ownerCredential, { tenantId: f.tenantId, factor: 1 }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });

    // The daily job alerts once per spike.
    const first = await f.iam.billing.detectAnomalies();
    expect(first.anomalies.map((anomaly) => [anomaly.dimension, anomaly.accountId])).toEqual([
      ['meter', f.tenantId],
      ['identity', f.tenantId],
    ]);
    expect((await f.iam.billing.detectAnomalies()).anomalies).toEqual([]);
    await f.iam.auth.dispatchOutbox();
    const mail = f.inbox.find((message) => message.template === 'spend-anomaly')!;
    expect(mail).toMatchObject({ to: 'owner@acme.test', payload: { count: '2' } });
    expect(renderDeliveryMessage(mail)!.text).toContain('Person bob: $40.00 (usually $2.00 a day)');
    const audited = await f.iam.api.audit.list(f.ownerCredential, {
      tenantId: f.tenantId,
      action: 'billing:anomaly',
    });
    expect(audited).toHaveLength(2);

    // CSV of a spend report, guarded against spreadsheet formulas.
    await f.iam.api.identities.update(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.id,
      name: '=HYPERLINK("x")',
    });
    const exported = await f.iam.api.billing.exportSpend(f.ownerCredential, {
      tenantId: f.tenantId,
      groupBy: 'identity',
    });
    expect(exported.contentType).toBe('text/csv; charset=utf-8');
    expect(exported.filename).toMatch(/^spend-.+-\d{4}-\d{2}-identity\.csv$/);
    const lines = exported.body.trim().split('\r\n');
    expect(lines[0]).toBe('identity,label,amount_usd,share_percent,events,quantity_builds');
    expect(lines.some((line) => line.includes(`"'=HYPERLINK(""x"")`))).toBe(true);
    expect(lines.at(-1)).toMatch(/^total,,/);
  });

  it('spreads unattributed spend over teams when asked (showback)', async () => {
    const { f, alice, bob, record } = await setup();
    const platform = await f.iam.api.teams.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Platform',
      maintainerIds: [alice.id],
    });
    const web = await f.iam.api.teams.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Web',
    });
    await f.iam.api.teams.addMember(f.ownerCredential, {
      tenantId: f.tenantId,
      teamId: web.id,
      identityId: bob.id,
    });
    await record(alice.id, 3000);
    await record(bob.id, 1000);
    // Shared usage nobody on a team caused: 1000 calls.
    await f.iam.billing.record({ tenantId: f.tenantId, meter: 'api-calls', quantity: 1000 });
    // 5000 calls, 4000 billable at $0.01 = $40: alice 24, bob 8, shared 8.
    const plain = await f.iam.api.billing.spend(f.ownerCredential, {
      tenantId: f.tenantId,
      groupBy: 'team',
    });
    expect(plain.rows.map((row) => [row.label ?? row.key, row.amount])).toEqual([
      ['Platform', 24],
      ['(no team)', 8],
      ['Web', 8],
    ]);
    const shared = await f.iam.api.billing.spend(f.ownerCredential, {
      tenantId: f.tenantId,
      groupBy: 'team',
      shareUnattributed: true,
    });
    expect(shared.sharedMicros).toBe(8_000_000);
    expect(shared.rows.map((row) => [row.key, row.amount, row.sharedMicros])).toEqual([
      [platform.id, 30, 6_000_000],
      [web.id, 10, 2_000_000],
    ]);
    expect(shared.rows.reduce((sum, row) => sum + row.costMicros, 0)).toBe(shared.total.costMicros);
  });
});

describe('spend in policies', () => {
  it('lets policies refuse actions once an enforced budget covering the person is spent', async () => {
    const { f, bob, alice, record } = await setup();
    const role = await f.iam.api.roles.create(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Writers within budget',
      document: {
        version: 1,
        statements: [
          { effect: 'allow', actions: ['documents:write'], resources: ['*'] },
          {
            effect: 'deny',
            actions: ['documents:write'],
            resources: ['*'],
            conditions: { Bool: { 'principal.spendExceeded': true } },
          },
        ],
      },
    });
    for (const person of [bob, alice])
      await f.iam.api.bindings.create(f.ownerCredential, {
        tenantId: f.tenantId,
        roleId: role.id,
        subjectType: 'identity',
        subjectId: person.id,
      });
    await f.iam.api.billing.createBudget(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Bob monthly',
      subjectType: 'identity',
      subjectId: bob.id,
      amount: 5,
      enforce: true,
    });
    const bobSession = { token: (await f.signIn('bob')).token };
    const aliceSession = { token: (await f.signIn('alice')).token };
    const write = (credential: { token: string }) =>
      f.iam.authorize({
        ...credential,
        tenantId: f.tenantId,
        action: 'documents:write',
        resource: { type: 'document', id: 'plan' },
      });
    expect((await write(bobSession)).allowed).toBe(true);
    // 1500 calls, 1000 free: $5 spent, the whole budget.
    await record(bob.id, 1500);
    // Budget standings are cached for up to 30 seconds.
    f.advance(31_000);
    expect((await write(bobSession)).allowed).toBe(false);
    expect((await write(aliceSession)).allowed).toBe(true);
    // Identity attributes can never supply the keys.
    await expect(
      organizationFixture({
        permissions: {
          actions: ['documents:read'],
          identityAttributes: { spendExceeded: 'boolean' },
        },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_CONFIG' });
  });
});

describe('contract terms', () => {
  it('applies a discount, a minimum commitment, credit and tax to statements', async () => {
    const { f, rootId, alice, record } = await setup();
    const lastMonth = shiftPeriod(periodOf(f.now(), 'UTC'), -1);
    // 6000 calls, 1000 free: $50 of usage.
    await record(alice.id, 6000, { occurredAt: previousPeriodStart(f) + 3_600_000 });
    await expect(
      f.iam.api.billing.setTerms(f.ownerCredential, { tenantId: f.tenantId, discountPercent: 90 }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const terms = await f.iam.api.billing.setTerms(f.rootCredential, {
      tenantId: f.tenantId,
      discountPercent: 10,
      minimumCommitment: 100,
      taxRatePercent: 20,
      taxLabel: 'VAT',
    });
    expect(terms).toMatchObject({ discountPercent: 10, minimumCommitment: 100, taxLabel: 'VAT' });
    expect(
      await f.iam.api.billing.getTerms(f.ownerCredential, { tenantId: f.tenantId }),
    ).toMatchObject({
      inherited: false,
      taxRatePercent: 20,
    });
    await f.iam.api.billing.grantCredit(f.rootCredential, {
      tenantId: f.tenantId,
      amount: 20,
      reason: 'Goodwill',
    });
    // $50 − 10% = $45; the $100 commitment adds $55; $20 credit leaves $80; 20% VAT: $96.
    const closed = await f.iam.api.billing.closePeriod(f.rootCredential, { tenantId: rootId });
    expect(closed.issued).toEqual([expect.objectContaining({ totalMicros: 96_000_000 })]);
    const statement = await f.iam.api.billing.getStatement(f.ownerCredential, {
      tenantId: f.tenantId,
      statementId: closed.issued[0]!.statementId,
    });
    expect(statement).toMatchObject({
      verified: true,
      subtotalMicros: 50_000_000,
      discount: { percent: 10, amountMicros: 5_000_000 },
      commitment: { minimumMicros: 100_000_000, trueUpMicros: 55_000_000 },
      creditsMicros: 20_000_000,
      tax: { label: 'VAT', ratePercent: 20, amountMicros: 16_000_000 },
      totalMicros: 96_000_000,
    });
    const sheet = await f.iam.api.billing.exportStatement(f.ownerCredential, {
      tenantId: f.tenantId,
      statementId: statement.id,
    });
    expect(sheet.body).toContain('discount,,10%,,,-5.000000,');
    expect(sheet.body).toContain('commitment,,minimum commitment true-up,,,55.000000,');
    expect(sheet.body).toContain('tax,,VAT 20%,,,16.000000,');
    // Clearing terms returns to plain statements for later months.
    const cleared = await f.iam.api.billing.setTerms(f.rootCredential, {
      tenantId: f.tenantId,
      discountPercent: null,
      minimumCommitment: null,
      taxRatePercent: null,
      taxLabel: null,
    });
    expect(cleared).toEqual({
      accountId: f.tenantId,
      inherited: false,
      setAt: expect.any(Number),
      setBy: expect.any(String),
    });
    await expect(
      f.iam.api.billing.setTerms(f.rootCredential, { tenantId: f.tenantId, taxRatePercent: 120 }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});
