import { afterEach, describe, expect, it } from 'vitest';
import { createIamClient } from '@better-iam/client';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';

afterEach(closeFixtures);

const attributes = {
  permissions: {
    actions: ['documents:read', 'documents:write'],
    identityAttributes: { department: 'string' as const, title: 'string' as const },
  },
};

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

/** A role that reads documents only once every required onboarding flow is complete. */
async function gatedReader(f: OrganizationFixture, identityId: string) {
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Onboarded reader',
    document: {
      version: 1,
      statements: [
        { effect: 'allow', actions: ['documents:read'], resources: ['*'] },
        {
          effect: 'deny',
          actions: ['documents:*'],
          resources: ['*'],
          conditions: { NumericGreaterThan: { 'principal.pendingOnboarding': 0 } },
        },
      ],
    },
  });
  await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId: identityId,
  });
}

describe('onboarding across platform, organization and project', () => {
  it('inherits platform flows, lets the organization customize them, and gates access until done', async () => {
    const f = await organizationFixture(attributes);
    const rootId = f.root.tenant.id;
    const owner = f.ownerCredential;
    // The owner joined before any flow existed; flows ask newcomers only unless includeExisting.
    f.advance(1_000);

    const departmentField = {
      name: 'department',
      label: 'Department',
      type: 'select',
      options: ['Engineering', 'Sales'],
      required: true,
    };
    // A flow that reaches only the tenants below may not write their people's attributes.
    await expect(
      f.iam.api.onboarding.createFlow(f.rootCredential, {
        tenantId: rootId,
        name: 'Platform profile',
        audience: 'member',
        steps: [
          {
            id: 'profile',
            kind: 'form',
            title: 'About you',
            fields: [{ ...departmentField, attribute: 'department' }],
          },
        ],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    const essentials = await f.iam.api.onboarding.createFlow(f.rootCredential, {
      tenantId: rootId,
      name: 'Platform essentials',
      audience: 'member',
      locked: true,
      steps: [
        {
          id: 'conduct',
          kind: 'acknowledge',
          title: 'Code of conduct',
          content: 'Be kind.\n\n1. Report incidents.',
        },
        {
          id: 'profile',
          kind: 'form',
          title: 'About you',
          fields: [departmentField, { name: 'phone', label: 'Desk phone', type: 'text' }],
        },
      ],
    });
    // Flows at the platform root reach the tenants below it by default.
    expect(essentials).toMatchObject({ appliesTo: 'descendants', version: 1, locked: true });
    f.advance(1);
    const tour = await f.iam.api.onboarding.createFlow(f.rootCredential, {
      tenantId: rootId,
      name: 'Product tour',
      audience: 'member',
      required: false,
      steps: [
        { id: 'tour', kind: 'task', title: 'Take the tour', url: 'https://example.test/tour' },
      ],
    });
    await f.iam.api.onboarding.setSettings(f.rootCredential, {
      tenantId: rootId,
      welcomeTitle: 'Welcome to Example Cloud',
      welcomeMessage: 'Platform message',
      supportEmail: 'help@example.test',
    });

    // The organization sees both, may switch off only the unlocked one, and adds its own.
    const effective = await f.iam.api.onboarding.effective(owner, { tenantId: f.tenantId });
    expect(effective.levels.map((level) => level.type)).toEqual(['root', 'organization']);
    expect(
      effective.memberFlows.map((item) => [item.flow.name, item.inherited, item.canDisable]),
    ).toEqual([
      ['Platform essentials', true, false],
      ['Product tour', true, true],
    ]);
    expect(effective.memberFlows[0]!.flow.authorId).toBeUndefined();
    await expect(
      f.iam.api.onboarding.setSettings(owner, {
        tenantId: f.tenantId,
        disabledFlowIds: [essentials.id],
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await f.iam.api.onboarding.setSettings(owner, {
      tenantId: f.tenantId,
      welcomeMessage: 'Welcome to Acme!',
      disabledFlowIds: [tour.id],
    });
    const engineers = await f.iam.api.groups.create(owner, {
      tenantId: f.tenantId,
      name: 'Engineers',
    });
    // Acme's own flow may fill its people's department.
    const team = await f.iam.api.onboarding.createFlow(owner, {
      tenantId: f.tenantId,
      name: 'Acme profile',
      audience: 'member',
      steps: [
        {
          id: 'team',
          kind: 'form',
          title: 'Your team',
          fields: [{ ...departmentField, attribute: 'department' }],
        },
      ],
    });
    f.advance(1);
    const engineering = await f.iam.api.onboarding.createFlow(owner, {
      tenantId: f.tenantId,
      name: 'Engineering onboarding',
      audience: 'member',
      rule: { include: [{ StringEquals: { 'principal.department': 'Engineering' } }] },
      completionGroupIds: [engineers.id],
      steps: [
        {
          id: 'laptop',
          kind: 'task',
          title: 'Collect your laptop',
          verification: 'admin',
        },
      ],
    });
    expect(engineering.appliesTo).toBe('tenant');

    const alice = await f.member('alice');
    await gatedReader(f, alice.id);
    const aliceToken = { token: (await f.signIn('alice')).token };
    const canRead = async () =>
      (
        await f.iam.authorize({
          ...aliceToken,
          tenantId: f.tenantId,
          action: 'documents:read',
          resource: { type: 'document', id: 'd1' },
        })
      ).allowed;

    let mine = await f.iam.api.onboarding.mine(aliceToken, { tenantId: f.tenantId });
    expect(mine.flows.map((flow) => flow.name)).toEqual(['Platform essentials', 'Acme profile']);
    expect(mine).toMatchObject({ pending: 2, complete: false });
    expect(mine.welcome).toMatchObject({
      welcomeTitle: 'Welcome to Example Cloud',
      welcomeMessage: 'Welcome to Acme!',
      supportEmail: 'help@example.test',
      sources: {
        welcomeTitle: { type: 'root' },
        welcomeMessage: { tenantId: f.tenantId },
      },
    });
    // The owner predates the flows.
    expect((await f.iam.api.onboarding.mine(owner, { tenantId: f.tenantId })).flows).toEqual([]);
    expect(await canRead()).toBe(false);

    await expect(
      f.iam.api.onboarding.submitStep(aliceToken, {
        tenantId: f.tenantId,
        flowId: essentials.id,
        stepId: 'conduct',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await f.iam.api.onboarding.submitStep(aliceToken, {
      tenantId: f.tenantId,
      flowId: essentials.id,
      stepId: 'conduct',
      acknowledged: true,
    });
    await expect(
      f.iam.api.onboarding.submitStep(aliceToken, {
        tenantId: f.tenantId,
        flowId: essentials.id,
        stepId: 'profile',
        answers: { department: 'Marketing' },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // The platform's answers stay answers; they never write Acme's identities.
    const profile = await f.iam.api.onboarding.submitStep(aliceToken, {
      tenantId: f.tenantId,
      flowId: essentials.id,
      stepId: 'profile',
      answers: { department: 'Engineering', phone: ' 555-0100 ' },
    });
    expect(profile.attributesFilled).toEqual([]);
    expect(profile.flow).toMatchObject({ complete: true, done: 2, total: 2 });
    expect(profile.flow.steps[1]!.answers).toEqual({
      department: 'Engineering',
      phone: '555-0100',
    });
    const filled = await f.iam.api.onboarding.submitStep(aliceToken, {
      tenantId: f.tenantId,
      flowId: team.id,
      stepId: 'team',
      answers: { department: 'Engineering' },
    });
    expect(filled.attributesFilled).toEqual(['department']);

    // The answer filled her department, so the engineering flow now applies to her.
    mine = await f.iam.api.onboarding.mine(aliceToken, { tenantId: f.tenantId });
    expect(mine.flows.map((flow) => [flow.name, flow.complete])).toEqual([
      ['Platform essentials', true],
      ['Acme profile', true],
      ['Engineering onboarding', false],
    ]);
    expect(await canRead()).toBe(false);

    // Onboarding only fills empty attributes.
    const again = await f.iam.api.onboarding.submitStep(aliceToken, {
      tenantId: f.tenantId,
      flowId: team.id,
      stepId: 'team',
      answers: { department: 'Sales' },
    });
    expect(again.attributesFilled).toEqual([]);
    expect(
      (await f.iam.api.identities.get(owner, { tenantId: f.tenantId, identityId: alice.id }))
        .attributes,
    ).toEqual({ department: 'Engineering' });

    // An administrator-verified task waits for the owner.
    const laptop = await f.iam.api.onboarding.submitStep(aliceToken, {
      tenantId: f.tenantId,
      flowId: engineering.id,
      stepId: 'laptop',
    });
    expect(laptop.flow.steps[0]).toMatchObject({ state: 'submitted' });
    await expect(
      f.iam.api.onboarding.verifyStep(aliceToken, {
        tenantId: f.tenantId,
        flowId: engineering.id,
        subjectId: alice.id,
        stepId: 'laptop',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const report = await f.iam.api.onboarding.progress(owner, {
      tenantId: f.tenantId,
      flowId: engineering.id,
    });
    expect(report.members).toEqual([
      expect.objectContaining({
        identity: expect.objectContaining({ id: alice.id }),
        complete: false,
        awaiting: ['laptop'],
      }),
    ]);
    const verified = await f.iam.api.onboarding.verifyStep(owner, {
      tenantId: f.tenantId,
      flowId: engineering.id,
      subjectId: alice.id,
      stepId: 'laptop',
    });
    expect(verified.flow.complete).toBe(true);
    expect(await canRead()).toBe(true);

    // Completion groups are applied when she next reads her onboarding.
    mine = await f.iam.api.onboarding.mine(aliceToken, { tenantId: f.tenantId });
    expect(mine).toMatchObject({ pending: 0, complete: true });
    expect(
      (
        await f.iam.api.groups.listMembers(owner, { tenantId: f.tenantId, groupId: engineers.id })
      ).map((member) => member.id),
    ).toEqual([alice.id]);
    const audit = await f.iam.api.audit.list(owner, { tenantId: f.tenantId });
    const actions = audit.map((event) => event.action);
    expect(actions).toEqual(
      expect.arrayContaining([
        'onboarding:step',
        'onboarding:complete',
        'onboarding:verify',
        'onboarding:groups',
      ]),
    );

    // The platform's report counts Acme's people without naming them.
    const platformReport = await f.iam.api.onboarding.progress(f.rootCredential, {
      tenantId: rootId,
      flowId: essentials.id,
    });
    expect(platformReport.members).toEqual([]);
    expect(platformReport.descendants).toEqual([
      {
        tenant: { tenantId: f.tenantId, name: 'Acme', type: 'organization' },
        people: 1,
        complete: 1,
      },
    ]);

    // Resetting one step reopens the flow for her.
    await f.iam.api.onboarding.resetProgress(owner, {
      tenantId: f.tenantId,
      flowId: engineering.id,
      subjectId: alice.id,
      stepId: 'laptop',
    });
    expect(await canRead()).toBe(false);
  });

  it('reaches projects through the subtree, with project-level flows and settings', async () => {
    const f = await organizationFixture(attributes);
    const rootId = f.root.tenant.id;
    const owner = f.ownerCredential;
    const step = (id: string) => [{ id, kind: 'acknowledge', title: id, content: `Read ${id}.` }];
    await f.iam.api.onboarding.createFlow(f.rootCredential, {
      tenantId: rootId,
      name: 'Organizations only',
      audience: 'member',
      tenantTypes: ['organization'],
      steps: step('org-only'),
    });
    f.advance(1);
    await f.iam.api.onboarding.createFlow(f.rootCredential, {
      tenantId: rootId,
      name: 'Everyone',
      audience: 'member',
      steps: step('everyone'),
    });
    await f.iam.api.onboarding.setSettings(f.rootCredential, {
      tenantId: rootId,
      welcomeTitle: 'Platform title',
      supportUrl: 'https://help.example.test',
    });
    const basics = await f.iam.api.onboarding.createFlow(owner, {
      tenantId: f.tenantId,
      name: 'Acme basics',
      audience: 'member',
      appliesTo: 'subtree',
      steps: step('basics'),
    });
    const apollo = await project(f);
    await expect(
      f.iam.api.onboarding.createFlow(apollo.credential, {
        tenantId: apollo.tenantId,
        name: 'Below projects',
        audience: 'member',
        appliesTo: 'descendants',
        steps: step('nothing'),
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await f.iam.api.onboarding.createFlow(apollo.credential, {
      tenantId: apollo.tenantId,
      name: 'Project kickoff',
      audience: 'member',
      steps: step('kickoff'),
    });
    await f.iam.api.onboarding.setSettings(apollo.credential, {
      tenantId: apollo.tenantId,
      welcomeTitle: 'Welcome to Apollo',
    });
    const bob = await f.iam.api.identities.create(apollo.credential, {
      tenantId: apollo.tenantId,
      email: 'bob@apollo.test',
      name: 'Bob',
      password: 'a strong bob password',
    });
    const bobSession = await f.iam.api.auth.signIn({
      tenantId: apollo.tenantId,
      email: 'bob@apollo.test',
      password: 'a strong bob password',
    });
    if (!('token' in bobSession)) throw new Error('Unexpected MFA');
    const bobToken = { token: bobSession.token };

    let mine = await f.iam.api.onboarding.mine(bobToken, { tenantId: apollo.tenantId });
    expect(mine.flows.map((flow) => [flow.name, flow.source.type])).toEqual([
      ['Everyone', 'root'],
      ['Acme basics', 'organization'],
      ['Project kickoff', 'project'],
    ]);
    expect(mine.welcome).toMatchObject({
      welcomeTitle: 'Welcome to Apollo',
      supportUrl: 'https://help.example.test',
    });
    expect(mine.pending).toBe(3);

    // The project switches off the organization's unlocked flow for itself...
    await f.iam.api.onboarding.setSettings(apollo.credential, {
      tenantId: apollo.tenantId,
      welcomeTitle: 'Welcome to Apollo',
      disabledFlowIds: [basics.id],
    });
    mine = await f.iam.api.onboarding.mine(bobToken, { tenantId: apollo.tenantId });
    expect(mine.flows.map((flow) => flow.name)).toEqual(['Everyone', 'Project kickoff']);
    const effective = await f.iam.api.onboarding.effective(apollo.credential, {
      tenantId: apollo.tenantId,
    });
    expect(effective.memberFlows.find((item) => item.flow.id === basics.id)).toMatchObject({
      disabledBy: { tenantId: apollo.tenantId },
      canDisable: true,
    });
    // ...until the organization locks it.
    await f.iam.api.onboarding.updateFlow(owner, {
      tenantId: f.tenantId,
      flowId: basics.id,
      locked: true,
    });
    mine = await f.iam.api.onboarding.mine(bobToken, { tenantId: apollo.tenantId });
    expect(mine.flows.map((flow) => flow.name)).toEqual([
      'Everyone',
      'Acme basics',
      'Project kickoff',
    ]);
    // Re-saving the project's settings quietly drops the switch that no longer applies.
    const saved = await f.iam.api.onboarding.setSettings(apollo.credential, {
      tenantId: apollo.tenantId,
      welcomeTitle: 'Welcome to Apollo',
      disabledFlowIds: [basics.id],
    });
    expect(saved.disabledFlowIds).toEqual([]);

    await f.iam.api.onboarding.submitStep(bobToken, {
      tenantId: apollo.tenantId,
      flowId: basics.id,
      stepId: 'basics',
      acknowledged: true,
    });
    const report = await f.iam.api.onboarding.progress(owner, {
      tenantId: f.tenantId,
      flowId: basics.id,
    });
    expect(report.descendants).toEqual([
      {
        tenant: { tenantId: apollo.tenantId, name: 'Apollo', type: 'project' },
        people: 2,
        complete: 1,
      },
    ]);
    // A flow inherited from above is reported at the project for its own people.
    const projectReport = await f.iam.api.onboarding.progress(apollo.credential, {
      tenantId: apollo.tenantId,
      flowId: basics.id,
    });
    expect(projectReport.flow).toMatchObject({ inherited: true, source: { type: 'organization' } });
    expect(
      projectReport.members?.map((row) => [row.identity.id === bob.id, row.complete]),
    ).toContainEqual([true, true]);

    // An organization's subtree flow fills its own people's attributes, never a project member's.
    const directory = await f.iam.api.onboarding.createFlow(owner, {
      tenantId: f.tenantId,
      name: 'Directory profile',
      audience: 'member',
      appliesTo: 'subtree',
      steps: [
        {
          id: 'title',
          kind: 'form',
          title: 'Your title',
          fields: [{ name: 'title', label: 'Title', type: 'text', attribute: 'title' }],
        },
      ],
    });
    const answered = await f.iam.api.onboarding.submitStep(bobToken, {
      tenantId: apollo.tenantId,
      flowId: directory.id,
      stepId: 'title',
      answers: { title: 'Engineer' },
    });
    expect(answered).toMatchObject({ attributesFilled: [], flow: { complete: true } });
    expect(
      (
        await f.iam.api.identities.get(apollo.credential, {
          tenantId: apollo.tenantId,
          identityId: bob.id,
        })
      ).attributes ?? {},
    ).toEqual({});
  });
});

describe('tenant setup checklists', () => {
  it('walks a new organization through setup checks, forms and verified tasks', async () => {
    const f = await organizationFixture();
    const rootId = f.root.tenant.id;
    const owner = f.ownerCredential;
    // Tenants record creation on the wall clock; move the test clock past Acme's creation.
    f.advance(60_000);
    const setup = await f.iam.api.onboarding.createFlow(f.rootCredential, {
      tenantId: rootId,
      name: 'Organization setup',
      audience: 'tenant',
      tenantTypes: ['organization'],
      includeExisting: true,
      steps: [
        { id: 'team', kind: 'check', title: 'Invite your team', check: 'members', minimum: 2 },
        { id: 'alias', kind: 'check', title: 'Choose a sign-in alias', check: 'slug' },
        {
          id: 'company',
          kind: 'form',
          title: 'About your company',
          fields: [
            {
              name: 'size',
              label: 'Company size',
              type: 'select',
              options: ['1-10', '11-50', '51+'],
              required: true,
            },
          ],
        },
        { id: 'kyc', kind: 'task', title: 'Business verification', verification: 'admin' },
        { id: 'sso', kind: 'check', title: 'Connect SSO', check: 'sso', optional: true },
      ],
    });
    // Flows for projects, and flows that ask only organizations created from now on, leave Acme alone.
    await f.iam.api.onboarding.createFlow(f.rootCredential, {
      tenantId: rootId,
      name: 'Project setup',
      audience: 'tenant',
      tenantTypes: ['project'],
      includeExisting: true,
      steps: [{ id: 'p', kind: 'task', title: 'Project task' }],
    });
    await f.iam.api.onboarding.createFlow(f.rootCredential, {
      tenantId: rootId,
      name: 'New organizations',
      audience: 'tenant',
      steps: [{ id: 'n', kind: 'task', title: 'New task' }],
    });

    let state = await f.iam.api.onboarding.setup(owner, { tenantId: f.tenantId });
    expect(state.flows.map((flow) => flow.name)).toEqual(['Organization setup']);
    expect(state.flows[0]!.steps.map((step) => [step.id, step.state, step.detail])).toEqual([
      ['team', 'pending', '1 of 2 members'],
      ['alias', 'pending', 'No sign-in alias yet'],
      ['company', 'pending', undefined],
      ['kyc', 'pending', undefined],
      ['sso', 'pending', '0 of 1 SSO connection'],
    ]);
    expect(state).toMatchObject({ pending: 1, complete: false });

    // Checks follow the organization's real state.
    const alice = await f.member('alice');
    await f.iam.api.tenants.setSlug(owner, { tenantId: f.tenantId, slug: 'acme' });
    await expect(
      f.iam.api.onboarding.submitSetupStep(owner, {
        tenantId: f.tenantId,
        flowId: setup.id,
        stepId: 'team',
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await f.iam.api.onboarding.submitSetupStep(owner, {
      tenantId: f.tenantId,
      flowId: setup.id,
      stepId: 'company',
      answers: { size: '11-50' },
    });
    await f.iam.api.onboarding.submitSetupStep(owner, {
      tenantId: f.tenantId,
      flowId: setup.id,
      stepId: 'kyc',
    });
    // People without iam:onboarding:manage cannot complete setup.
    const aliceToken = { token: (await f.signIn('alice')).token };
    await expect(
      f.iam.api.onboarding.submitSetupStep(aliceToken, {
        tenantId: f.tenantId,
        flowId: setup.id,
        stepId: 'company',
        answers: { size: '1-10' },
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect(alice.id).toBeTruthy();

    // The platform sees every organization's setup, with its answers, and verifies the task.
    const report = await f.iam.api.onboarding.progress(f.rootCredential, {
      tenantId: rootId,
      flowId: setup.id,
    });
    expect(report.tenants).toEqual([
      expect.objectContaining({
        tenant: expect.objectContaining({ tenantId: f.tenantId, name: 'Acme' }),
        complete: false,
        done: 3,
        total: 4,
        awaiting: ['kyc'],
        answers: { company: { size: '11-50' } },
      }),
    ]);
    await f.iam.api.onboarding.verifyStep(f.rootCredential, {
      tenantId: rootId,
      flowId: setup.id,
      subjectId: f.tenantId,
      stepId: 'kyc',
      approve: false,
      note: 'Upload the registration certificate',
    });
    state = await f.iam.api.onboarding.setup(owner, { tenantId: f.tenantId });
    expect(state.flows[0]!.steps.find((step) => step.id === 'kyc')).toMatchObject({
      state: 'rejected',
      note: 'Upload the registration certificate',
    });
    await f.iam.api.onboarding.submitSetupStep(owner, {
      tenantId: f.tenantId,
      flowId: setup.id,
      stepId: 'kyc',
    });
    const verified = await f.iam.api.onboarding.verifyStep(f.rootCredential, {
      tenantId: rootId,
      flowId: setup.id,
      subjectId: f.tenantId,
      stepId: 'kyc',
    });
    expect(verified.flow).toMatchObject({ complete: true, done: 4, total: 4 });
    state = await f.iam.api.onboarding.setup(owner, { tenantId: f.tenantId });
    expect(state).toMatchObject({ pending: 0, complete: true });
    const audit = await f.iam.api.audit.list(owner, { tenantId: f.tenantId });
    expect(audit.some((event) => event.action === 'onboarding:complete')).toBe(true);

    // The organization cannot verify its own setup task: the flow belongs to the platform.
    await expect(
      f.iam.api.onboarding.verifyStep(owner, {
        tenantId: f.tenantId,
        flowId: setup.id,
        subjectId: f.tenantId,
        stepId: 'kyc',
      }),
    ).rejects.toMatchObject({ code: 'NOT_FOUND' });
  });
});

describe('onboarding flow management', () => {
  it('validates flows, versions steps, and cleans up progress', async () => {
    const f = await organizationFixture(attributes);
    const owner = f.ownerCredential;
    const rootId = f.root.tenant.id;
    const tenantId = f.tenantId;
    const alice = await f.member('alice');
    const aliceToken = { token: (await f.signIn('alice')).token };
    const task = [{ id: 'hello', kind: 'task', title: 'Say hello' }];
    await expect(
      f.iam.api.onboarding.createFlow(aliceToken, {
        tenantId,
        name: 'Mine',
        audience: 'member',
        steps: task,
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const invalid = async (input: Record<string, unknown>, credential = owner, at = tenantId) =>
      expect(
        f.iam.api.onboarding.createFlow(credential, {
          tenantId: at,
          name: 'Invalid',
          audience: 'member',
          steps: task,
          ...input,
        } as never),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await invalid({ steps: [{ id: 'c', kind: 'check', title: 'Check', check: 'slug' }] });
    await invalid({
      steps: [
        {
          id: 'f',
          kind: 'form',
          title: 'Form',
          fields: [{ name: 'x', label: 'X', type: 'text', attribute: 'favouriteColour' }],
        },
      ],
    });
    await invalid({
      steps: [
        {
          id: 'f',
          kind: 'form',
          title: 'Form',
          fields: [{ name: 'x', label: 'X', type: 'number', attribute: 'department' }],
        },
      ],
    });
    await invalid({
      steps: [
        {
          id: 'f',
          kind: 'form',
          title: 'Form',
          fields: [{ name: 'x', label: 'X', type: 'textarea', attribute: 'department' }],
        },
      ],
    });
    await invalid({ steps: [{ id: 'Bad Id', kind: 'task', title: 'Task' }] });
    await invalid({ steps: [...task, ...task] });
    await invalid({ audience: 'tenant', appliesTo: 'tenant' });
    await invalid({ tenantTypes: ['project'] });
    await invalid({ appliesTo: 'descendants', tenantTypes: ['organization'] });
    await invalid(
      { appliesTo: 'descendants', completionGroupIds: ['group'] },
      f.rootCredential,
      rootId,
    );
    const group = await f.iam.api.groups.create(owner, { tenantId, name: 'Staff' });
    await invalid({
      appliesTo: 'descendants',
      rule: { include: [{ ArrayContains: { 'identity.groups': group.id } }] },
    });

    const flow = await f.iam.api.onboarding.createFlow(owner, {
      tenantId,
      name: 'Welcome',
      audience: 'member',
      steps: task,
    });
    await expect(
      f.iam.api.onboarding.createFlow(owner, {
        tenantId,
        name: 'welcome',
        audience: 'member',
        steps: task,
      }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    const renamed = await f.iam.api.onboarding.updateFlow(owner, {
      tenantId,
      flowId: flow.id,
      name: 'Welcome aboard',
    });
    expect(renamed.version).toBe(1);
    await f.iam.api.onboarding.submitStep(aliceToken, {
      tenantId,
      flowId: flow.id,
      stepId: 'hello',
    });
    const extended = await f.iam.api.onboarding.updateFlow(owner, {
      tenantId,
      flowId: flow.id,
      steps: [...task, { id: 'coffee', kind: 'task', title: 'Get coffee', optional: true }],
    });
    expect(extended.version).toBe(2);
    // Finished steps stay finished; the new step is optional, so the flow stays complete.
    const mine = await f.iam.api.onboarding.mine(aliceToken, { tenantId });
    expect(mine.flows[0]).toMatchObject({ complete: true, done: 1, total: 1 });

    // Deleting a person removes their progress, which holds their answers.
    const records = async () => f.database.find('onboardingProgress', { tenantId });
    expect((await records()).length).toBe(1);
    await f.iam.api.identities.delete(owner, { tenantId, identityId: alice.id });
    expect(await records()).toEqual([]);
    const second = await f.iam.api.onboarding.deleteFlow(owner, { tenantId, flowId: flow.id });
    expect(second).toEqual({ deleted: true, progressRemoved: 0 });
  });

  it('serves the member routes over HTTP and refuses role sessions and impersonation', async () => {
    const f = await organizationFixture();
    const tenantId = f.tenantId;
    const flow = await f.iam.api.onboarding.createFlow(f.ownerCredential, {
      tenantId,
      name: 'Hello',
      audience: 'member',
      steps: [{ id: 'hello', kind: 'acknowledge', title: 'Hello', content: 'Hi' }],
    });
    const alice = await f.member('alice');
    const token = (await f.signIn('alice')).token;
    const client = createIamClient<typeof f.iam>({
      baseURL: 'http://localhost:3000',
      token,
      fetch: async (input, init) => f.iam.handler(new Request(input, init)),
    });
    const mine = await client.onboarding.mine({ tenantId });
    expect(mine.flows.map((item) => item.name)).toEqual(['Hello']);
    const done = await client.onboarding.submitStep({
      tenantId,
      flowId: flow.id,
      stepId: 'hello',
      acknowledged: true,
    });
    expect(done.flow.complete).toBe(true);

    await f.iam.api.tenants.setAuthPolicy(f.ownerCredential, {
      tenantId,
      authPolicy: { allowImpersonation: true },
    });
    const view = await f.iam.api.identities.impersonate(await f.ownerSignIn(), {
      tenantId,
      identityId: alice.id,
      reason: 'Support ticket 42',
    });
    await expect(
      f.iam.api.onboarding.submitStep(
        { token: view.token },
        { tenantId, flowId: flow.id, stepId: 'hello', acknowledged: true },
      ),
    ).rejects.toMatchObject({ code: 'IMPERSONATION_RESTRICTED' });
    // An administrator viewing as the member sees their checklist.
    expect(
      (await f.iam.api.onboarding.mine({ token: view.token }, { tenantId })).flows[0]!.complete,
    ).toBe(true);
  });
});
