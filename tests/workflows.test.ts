import { afterEach, describe, expect, it } from 'vitest';
import type { Identity } from '@better-iam/core';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const day = 86_400_000;

async function scenario() {
  const f = await organizationFixture({
    permissions: {
      actions: ['documents:read', 'documents:write'],
      identityAttributes: { department: 'string', startDate: 'string', title: 'string' },
    },
  });
  const { tenantId } = f;
  const owner = f.ownerCredential;
  const engineering = await f.iam.api.groups.create(owner, { tenantId, name: 'Engineering' });
  const everyone = await f.iam.api.groups.create(owner, { tenantId, name: 'Everyone' });
  const workflows = f.iam.api.workflows;
  const person = async (name: string, attributes?: Record<string, string>) => {
    const created = await f.member(name);
    if (attributes)
      await f.iam.api.identities.update(owner, { tenantId, identityId: created.id, attributes });
    return created;
  };
  const groupsOf = async (identityId: string) =>
    (await f.iam.api.identities.listGroups(owner, { tenantId, identityId }))
      .map((group: { name: string }) => group.name)
      .sort();
  const identity = (identityId: string) =>
    f.database.transaction((tx) => tx.get<Identity>('identities', identityId));
  return { f, tenantId, owner, engineering, everyone, workflows, person, groupsOf, identity };
}

describe('lifecycle workflows', () => {
  it('runs joiner steps for people who join after the workflow exists, within its scope', async () => {
    const s = await scenario();
    const existing = await s.person('early', { department: 'Engineering' });
    s.f.advance(1000);
    const workflow = await s.workflows.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Engineering joiners',
      trigger: { kind: 'joiner' },
      scope: { include: [{ StringEquals: { 'principal.department': 'Engineering' } }] },
      steps: [
        { kind: 'add-to-group', groupId: s.engineering.id },
        {
          kind: 'send-email',
          to: 'subject',
          subject: 'Welcome to {organization}, {name}',
          body: 'You joined {attribute.department}.',
        },
        { kind: 'emit-event', name: 'engineer.joined' },
      ],
    });
    expect(workflow).toMatchObject({ enabled: true, version: 1, maxRunsPerDay: 200 });
    const alice = await s.person('alice', { department: 'Engineering' });
    const bob = await s.person('bob', { department: 'Sales' });
    const result = await s.f.iam.workflows.runDue({ tenantId: s.tenantId });
    expect(result).toMatchObject({ started: 1, executed: 1, completed: 1 });
    expect(await s.groupsOf(alice.id)).toEqual(['Engineering']);
    expect(await s.groupsOf(bob.id)).toEqual([]);
    expect(await s.groupsOf(existing.id)).toEqual([]);
    await s.f.iam.auth.dispatchOutbox();
    const welcome = s.f.inbox.find((message) => message.template === 'workflow-message')!;
    expect(welcome.to).toBe('alice@acme.test');
    expect(welcome.payload).toMatchObject({
      subject: 'Welcome to Acme, alice',
      body: 'You joined Engineering.',
    });
    // Each joiner runs once.
    expect((await s.f.iam.workflows.runDue({ tenantId: s.tenantId })).started).toBe(0);
    const runs = await s.workflows.listRuns(s.owner, { tenantId: s.tenantId, workflowId: workflow.id });
    expect(runs.runs[0]).toMatchObject({
      identityId: alice.id,
      status: 'completed',
      results: [
        { kind: 'add-to-group', outcome: 'done', detail: 'Engineering' },
        { kind: 'send-email', outcome: 'done' },
        { kind: 'emit-event', outcome: 'done' },
      ],
    });
    const audit = await s.f.iam.api.audit.list(s.owner, { tenantId: s.tenantId });
    const events = Array.isArray(audit) ? audit : (audit as { events: unknown[] }).events;
    expect(JSON.stringify(events)).toContain('"workflow:event"');
  });

  it('fires mover workflows on watched attribute changes and leaver workflows on disabling', async () => {
    const s = await scenario();
    const carol = await s.person('carol', { department: 'Engineering' });
    await s.f.iam.api.groups.addMember(s.owner, {
      tenantId: s.tenantId,
      groupId: s.engineering.id,
      identityId: carol.id,
    });
    await s.workflows.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Department movers',
      trigger: { kind: 'mover', attributes: ['department'] },
      steps: [{ kind: 'remove-from-group', groupId: s.engineering.id }],
    });
    const leaver = await s.workflows.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Leavers',
      trigger: { kind: 'leaver' },
      steps: [
        { kind: 'remove-from-all-groups' },
        { kind: 'wait', hours: 24 * 30 },
        { kind: 'delete' },
      ],
    });
    expect(leaver.maxRunsPerDay).toBe(25);
    // No change yet: the baselines were taken when the workflows were created.
    expect((await s.f.iam.workflows.runDue({ tenantId: s.tenantId })).started).toBe(0);
    await s.f.iam.api.identities.update(s.owner, {
      tenantId: s.tenantId,
      identityId: carol.id,
      attributes: { department: 'Sales' },
    });
    expect((await s.f.iam.workflows.runDue({ tenantId: s.tenantId })).started).toBe(1);
    expect(await s.groupsOf(carol.id)).toEqual([]);
    // Moving back fires again.
    await s.f.iam.api.groups.addMember(s.owner, {
      tenantId: s.tenantId,
      groupId: s.engineering.id,
      identityId: carol.id,
    });
    await s.f.iam.api.groups.addMember(s.owner, {
      tenantId: s.tenantId,
      groupId: s.everyone.id,
      identityId: carol.id,
    });
    await s.f.iam.api.identities.update(s.owner, {
      tenantId: s.tenantId,
      identityId: carol.id,
      attributes: { department: 'Engineering' },
    });
    expect((await s.f.iam.workflows.runDue({ tenantId: s.tenantId })).started).toBe(1);
    expect(await s.groupsOf(carol.id)).toEqual(['Everyone']);

    // Leaving: groups go now, the account is deleted after the wait.
    const owner = await s.f.ownerSignIn();
    await s.f.iam.api.identities.setStatus(owner, {
      tenantId: s.tenantId,
      identityId: carol.id,
      status: 'disabled',
    });
    const first = await s.f.iam.workflows.runDue({ tenantId: s.tenantId });
    expect(first).toMatchObject({ started: 1, waiting: 1 });
    expect(await s.groupsOf(carol.id)).toEqual([]);
    expect((await s.identity(carol.id))!.status).toBe('disabled');
    s.f.advance(31 * day);
    const later = await s.f.iam.workflows.runDue({ tenantId: s.tenantId });
    expect(later).toMatchObject({ started: 0, completed: 1 });
    expect((await s.identity(carol.id))!.status).toBe('deleted');
  });

  it('runs date workflows relative to a date attribute', async () => {
    const s = await scenario();
    const start = new Date(s.f.now() + 10 * day).toISOString().slice(0, 10);
    const dave = await s.person('dave', { startDate: start });
    await s.workflows.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Before the first day',
      trigger: { kind: 'date', attribute: 'startDate', offsetDays: -7 },
      steps: [{ kind: 'add-to-group', groupId: s.everyone.id, days: 30 }],
    });
    const preview = await s.workflows.preview(s.owner, {
      tenantId: s.tenantId,
      workflowId: (await s.workflows.list(s.owner, { tenantId: s.tenantId }))[0]!.id,
    });
    expect(preview.upcoming.map((item) => item.id)).toEqual([dave.id]);
    expect(preview.wouldStart).toEqual([]);
    expect((await s.f.iam.workflows.runDue({ tenantId: s.tenantId })).started).toBe(0);
    s.f.advance(4 * day);
    expect((await s.f.iam.workflows.runDue({ tenantId: s.tenantId })).started).toBe(1);
    expect(await s.groupsOf(dave.id)).toEqual(['Everyone']);
    expect((await s.f.iam.workflows.runDue({ tenantId: s.tenantId })).started).toBe(0);
  });

  it('refuses to save steps the caller could not do by hand, and fails runs when the owner loses rights', async () => {
    const s = await scenario();
    const manager = await s.person('manager');
    const role = await s.f.iam.api.roles.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Workflow author',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['iam:workflows:*'],
            resources: ['*'],
          },
          { effect: 'allow', actions: ['iam:groups:update'], resources: [`iam/${s.everyone.id}`] },
        ],
      },
    });
    const binding = await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: manager.id,
    });
    const token = { token: (await s.f.signIn('manager')).token };
    await expect(
      s.workflows.create(token, {
        tenantId: s.tenantId,
        name: 'Too much',
        trigger: { kind: 'joiner' },
        steps: [{ kind: 'add-to-group', groupId: s.engineering.id }],
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const workflow = await s.workflows.create(token, {
      tenantId: s.tenantId,
      name: 'Everyone',
      trigger: { kind: 'manual' },
      steps: [{ kind: 'add-to-group', groupId: s.everyone.id }],
    });
    const erin = await s.person('erin');
    const [done] = await s.workflows.run(token, {
      tenantId: s.tenantId,
      workflowId: workflow.id,
      identityIds: [erin.id],
    });
    expect(done).toMatchObject({ status: 'completed' });
    // The author loses the right: the owner's next run fails at the step, and retrying needs the right back.
    await s.f.iam.api.bindings.delete(s.owner, { tenantId: s.tenantId, bindingId: binding.id });
    const frank = await s.person('frank');
    const owner = await s.f.ownerSignIn();
    const [failed] = await s.workflows.run(owner, {
      tenantId: s.tenantId,
      workflowId: workflow.id,
      identityIds: [frank.id],
    });
    expect(failed).toMatchObject({ status: 'failed', error: { code: 'ACCESS_DENIED' } });
    // Saving it again makes the owner the one with the rights.
    await s.workflows.update(owner, { tenantId: s.tenantId, workflowId: workflow.id, name: 'Everyone' });
    const retried = await s.workflows.retryRun(owner, { tenantId: s.tenantId, runId: failed!.id });
    expect(retried.status).toBe('completed');
    expect(await s.groupsOf(frank.id)).toEqual(['Everyone']);
  });

  it('never strips owners and stops at the daily brake', async () => {
    const s = await scenario();
    const workflow = await s.workflows.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Disable',
      trigger: { kind: 'manual' },
      steps: [{ kind: 'disable' }],
    });
    const owner = await s.f.ownerSignIn();
    const other = await s.person('gina');
    await s.f.iam.api.identities.setOwner(owner, {
      tenantId: s.tenantId,
      identityId: other.id,
      owner: true,
    });
    const [run] = await s.workflows.run(owner, {
      tenantId: s.tenantId,
      workflowId: workflow.id,
      identityIds: [other.id],
    });
    expect(run).toMatchObject({ status: 'failed', error: { code: 'PROTECTED_RESOURCE' } });

    const brake = await s.workflows.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Tag everyone',
      trigger: { kind: 'joiner' },
      includeExisting: true,
      maxRunsPerDay: 2,
      steps: [{ kind: 'add-to-group', groupId: s.everyone.id }],
    });
    for (const name of ['h1', 'h2', 'h3']) await s.person(name);
    // Five people qualify: two start today, the rest wait for tomorrow (or a higher limit).
    expect((await s.f.iam.workflows.runDue({ tenantId: s.tenantId })).started).toBe(2);
    expect((await s.f.iam.workflows.runDue({ tenantId: s.tenantId })).started).toBe(0);
    const audit = await s.f.iam.api.audit.list(owner, { tenantId: s.tenantId });
    const events = Array.isArray(audit) ? audit : (audit as { events: unknown[] }).events;
    expect(JSON.stringify(events)).toContain('workflow:brake');
    const raised = await s.workflows.update(owner, {
      tenantId: s.tenantId,
      workflowId: brake.id,
      maxRunsPerDay: 50,
    });
    expect(raised.brakedOn).toBeUndefined();
    expect((await s.f.iam.workflows.runDue({ tenantId: s.tenantId })).started).toBe(3);
  });

  it('reacts to changes through subscribe() when audit hooks are dispatched', async () => {
    const s = await scenario();
    await s.workflows.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Welcome',
      trigger: { kind: 'joiner' },
      steps: [{ kind: 'add-to-group', groupId: s.everyone.id }],
    });
    const stop = s.f.iam.workflows.subscribe();
    try {
      const ivan = await s.person('ivan');
      await s.f.iam.dispatchAuditHooks();
      await s.f.iam.workflows.idle();
      expect(await s.groupsOf(ivan.id)).toEqual(['Everyone']);
    } finally {
      stop();
    }
  });

  it('validates definitions', async () => {
    const s = await scenario();
    const attempt = (input: Record<string, unknown>) =>
      s.workflows.create(s.owner, {
        tenantId: s.tenantId,
        name: 'Bad',
        trigger: { kind: 'joiner' },
        steps: [{ kind: 'emit-event', name: 'x' }],
        ...input,
      } as never);
    await expect(attempt({ trigger: { kind: 'mover', attributes: ['shoeSize'] } })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    await expect(attempt({ trigger: { kind: 'date', attribute: 'title', offsetDays: 400000 } })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    await expect(attempt({ steps: [{ kind: 'wait', hours: 2 }] })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    await expect(
      attempt({ steps: [{ kind: 'delete' }, { kind: 'emit-event', name: 'after' }] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      attempt({ steps: [{ kind: 'send-email', to: 'nobody', subject: 's', body: 'b' }] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      attempt({ scope: { include: [{ StringEquals: { 'principal.unknown': 'x' } }] } }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      attempt({ steps: [{ kind: 'add-to-group', groupId: 'missing' }] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
  });
});

describe('workflow review fixes', () => {
  it('refuses workflows that change the account of whoever runs them', async () => {
    const s = await scenario();
    const admin = await s.person('admin');
    const role = await s.f.iam.api.roles.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Directory admin',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['iam:workflows:*', 'iam:identities:update', 'iam:identities:read'],
            resources: ['*'],
          },
        ],
      },
    });
    await s.f.iam.api.bindings.create(s.owner, {
      tenantId: s.tenantId,
      roleId: role.id,
      subjectType: 'identity',
      subjectId: admin.id,
    });
    const token = { token: (await s.f.signIn('admin')).token };
    const workflow = await s.workflows.create(token, {
      tenantId: s.tenantId,
      name: 'Move to finance',
      trigger: { kind: 'manual' },
      steps: [{ kind: 'set-attributes', attributes: { department: 'Finance' } }],
    });
    await expect(
      s.workflows.run(token, { tenantId: s.tenantId, workflowId: workflow.id, identityIds: [admin.id] }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    // Someone else may run it on the admin, but it still refuses to act on the workflow's own owner.
    const owner = await s.f.ownerSignIn();
    const [run] = await s.workflows.run(owner, {
      tenantId: s.tenantId,
      workflowId: workflow.id,
      identityIds: [admin.id],
    });
    expect(run).toMatchObject({ status: 'failed', error: { code: 'INVALID_INPUT' } });
    expect((await s.identity(admin.id))!.attributes?.department).toBeUndefined();
  });

  it('sends workflow email only inside the organization', async () => {
    const s = await scenario();
    await s.person('hr');
    const email = (to: string) => ({
      tenantId: s.tenantId,
      name: `Notify ${to}`,
      trigger: { kind: 'joiner' as const },
      steps: [{ kind: 'send-email' as const, to, subject: 'New person', body: '{name} {email}' }],
    });
    await expect(s.workflows.create(s.owner, email('collector@evil.example'))).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    expect((await s.workflows.create(s.owner, email('hr@acme.test'))).enabled).toBe(true);
  });

  it('can cancel runs in progress when the workflow changes', async () => {
    const s = await scenario();
    const workflow = await s.workflows.create(s.owner, {
      tenantId: s.tenantId,
      name: 'Grace period',
      trigger: { kind: 'manual' },
      steps: [{ kind: 'wait', hours: 48 }, { kind: 'disable' }],
    });
    const jane = await s.person('jane');
    const [waiting] = await s.workflows.run(s.owner, {
      tenantId: s.tenantId,
      workflowId: workflow.id,
      identityIds: [jane.id],
    });
    expect(waiting!.status).toBe('waiting');
    await s.workflows.update(s.owner, {
      tenantId: s.tenantId,
      workflowId: workflow.id,
      steps: [{ kind: 'emit-event', name: 'kept' }],
      activeRuns: 'cancel',
    });
    s.f.advance(3 * day);
    await s.f.iam.workflows.runDue({ tenantId: s.tenantId });
    expect((await s.identity(jane.id))!.status).toBe('active');
    const owner = await s.f.ownerSignIn();
    const runs = await s.workflows.listRuns(owner, { tenantId: s.tenantId, workflowId: workflow.id });
    expect(runs.runs[0]!.status).toBe('cancelled');
  });
});
