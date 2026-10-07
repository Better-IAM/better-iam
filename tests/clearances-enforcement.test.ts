import { createHash } from 'node:crypto';
import { afterEach, describe, expect, it } from 'vitest';
import {
  classificationTemplates,
  filterMatches,
  type AuditEvent,
  type ClassificationLabel,
  type IamPlugin,
  type Session,
  type StoredRecord,
} from '@better-iam/core';
import type { BetterIamOptions } from '@better-iam/server';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';
import { administrator } from './support/guests.js';
import { sshPublicKey } from './support/ssh.js';

afterEach(closeFixtures);

/**
 * Mandatory access control end to end (security clearances): on a labeled resource every party of a session must
 * dominate the label, whatever roles, policies and relationships say, on every path that decides (authorize, require,
 * HTTP, authorizeMany, listings, data filter plans, simulate, effective actions, who-can, impact previews, invariants
 * and access paths); root keeps its override for `iam:*` administration only; delegated chains, agent keys with their
 * sponsors, session tokens, role sessions and "view as" each bring every party; labels can only be raised (resolver,
 * context, attributes, deletion); missing labels on required types, NOFORN and REL TO fail closed; managed parents pass
 * labels down; and without the option nothing changes.
 */

type Credential = { token: string };
/** What the application's resolver returns for one `{type}/{id}` besides the reference itself. */
type AppRecord = { attributes?: Record<string, unknown>; classification?: unknown };

const resourceTypes = {
  document: { actions: ['documents:read', 'documents:write'] },
  // `reports:read` sorts after every `iam:` action, so reviews that prepare with the first sorted action prepare with
  // an `iam:` one.
  report: { actions: ['reports:read'] },
  folder: { managed: true, actions: ['folders:read'] },
  file: { managed: true, parent: 'folder', actions: ['files:read'] },
  page: { managed: true, parent: 'file', actions: ['pages:read'] },
};

const readerPermissions = [
  'documents:read',
  'documents:write',
  'reports:read',
  'folders:read',
  'files:read',
  'pages:read',
  'iam:resources:read',
  'iam:roles:assume',
  'iam:session-tokens:create',
];
const officerPermissions = [
  'iam:clearances:read',
  'iam:clearances:adjudicate',
  'iam:clearances:suspend',
  'iam:classifications:label',
  'iam:classifications:declassify',
];

const schemeDefinition = () => ({
  ...JSON.parse(JSON.stringify(classificationTemplates.us)),
  compartments: [
    { id: 'GAMMA', name: 'Gamma codeword' },
    { id: 'HCS', name: 'Humint control' },
  ],
});

/** `not(id in ids)`: the plan of a principal who may read everything of the type but `ids`. */
const allBut = (...ids: string[]) => ({
  kind: 'not',
  filter: { kind: 'equals', field: 'id', values: ids },
});

const sha256 = (value: string) => createHash('sha256').update(value).digest('hex');

interface SetupOptions {
  overrides?: Partial<BetterIamOptions>;
  /** Scheme settings besides the definition (`requireLabels`, `defaultLabel`, ...). */
  scheme?: Record<string, unknown>;
  /** Define the scheme at the platform's root tenant (the organization inherits it) instead of the organization. */
  rootScheme?: boolean;
}

/**
 * Acme with the clearances option and a US-style scheme (compartments GAMMA and HCS, unrestricted adjudication so the
 * owner grants anyone but themselves), application types `document` and `report` resolved by a scriptable resolver,
 * managed `folder` > `file` > `page`, readers alice and bob (every application action, plus iam:resources:read,
 * role assumption and session tokens), and an officer.
 */
async function setup(options: SetupOptions = {}) {
  const app = new Map<string, AppRecord>();
  const spoof: Record<string, unknown> = {};
  const f = await organizationFixture({
    clearances: {},
    permissions: { resourceTypes, identityAttributes: { citizenship: 'string' } },
    resolveResource: async (reference) =>
      ({ ...(app.get(`${reference.type}/${reference.id}`) ?? {}), ...reference }) as never,
    resolveContext: async () => ({ ...spoof }),
    ...options.overrides,
  });
  const { tenantId } = f;
  const owner = f.ownerCredential;
  if (options.rootScheme)
    await f.iam.api.clearances.defineScheme(f.rootCredential, {
      tenantId: f.root.tenant.id,
      name: 'Platform',
      definition: schemeDefinition(),
      adjudication: 'unrestricted',
      ...options.scheme,
    });
  else
    await f.iam.api.clearances.defineScheme(owner, {
      tenantId,
      name: 'Acme',
      definition: schemeDefinition(),
      adjudication: 'unrestricted',
      ...options.scheme,
    });
  const readers = await f.iam.api.roles.create(owner, {
    tenantId,
    name: 'Readers',
    permissions: readerPermissions,
  });
  const bind = (roleId: string, identityId: string) =>
    f.iam.api.bindings.create(owner, {
      tenantId,
      roleId,
      subjectType: 'identity',
      subjectId: identityId,
    });
  /** A member holding the readers role, signed in. */
  const person = async (name: string) => {
    const identity = await f.member(name);
    await bind(readers.id, identity.id);
    return { identity, credential: { token: (await f.signIn(name)).token } };
  };
  const alice = await person('alice');
  const bob = await person('bob');
  const officer = await administrator(f, 'officer', officerPermissions);
  /** An AI agent (sponsored by the owner) with an API key and no grants of its own. */
  const agent = async (name: string) => {
    const created = await f.iam.api.agents.create(owner, { tenantId, name });
    const key = await f.iam.api.credentials.create(owner, { tenantId, identityId: created.id });
    return { id: created.id, key: { token: key.token } };
  };
  const clear = (
    identityId: string,
    level: string,
    extra: Record<string, unknown> = {},
    by: Credential = owner,
  ) =>
    f.iam.api.clearances.grant(by, {
      tenantId,
      identityId,
      level,
      citizenship: ['USA'],
      ...extra,
    });
  const relevel = (identityId: string, level: string) =>
    f.iam.api.clearances.update(owner, { tenantId, identityId, level });
  const suspend = (identityId: string, by: Credential = owner) =>
    f.iam.api.clearances.suspend(by, {
      tenantId,
      identityId,
      reason: 'under investigation',
      notifyPerson: false,
    });
  const label = (
    type: string,
    id: string,
    value: ClassificationLabel,
    inheritToChildren?: boolean,
  ) =>
    f.iam.api.clearances.label(owner, {
      tenantId,
      type,
      id,
      label: value,
      ...(inheritToChildren !== undefined ? { inheritToChildren } : {}),
    });
  const register = (type: string, id: string, parentId?: string) =>
    f.iam.api.resources.register(owner, {
      tenantId,
      type,
      id,
      ...(parentId !== undefined ? { parentId } : {}),
    });
  const can = async (credential: Credential, action: string, type: string, id: string) =>
    (await f.iam.authorize({ ...credential, tenantId, action, resource: { type, id } })).allowed;
  const reads = (credential: Credential, id: string) =>
    can(credential, 'documents:read', 'document', id);
  const simulate = (identityId: string, action: string, type: string, id: string) =>
    f.iam.api.policies.simulate(owner, {
      tenantId,
      identityId,
      action,
      resource: { type, id },
    });
  const listed = async (credential: Credential, action: string, type: string) =>
    (await f.iam.listAccessible({ ...credential, tenantId, action, type })).resources.map(
      (item) => item.resourceId,
    );
  const plan = (credential: Credential, action: string, type: string) =>
    f.iam.planResources({ ...credential, tenantId, action, type });
  const http = async (path: string, body: unknown, token: string) => {
    const response = await f.iam.handler(
      new Request(`http://localhost:3000/api/iam/${path}`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'x-better-iam': '1',
          authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(body),
      }),
    );
    return {
      status: response.status,
      body: (await response.json()) as { data?: any; error?: { code: string } },
    };
  };
  return {
    f,
    tenantId,
    owner,
    app,
    spoof,
    readers,
    bind,
    person,
    alice,
    bob,
    officer,
    agent,
    clear,
    relevel,
    suspend,
    label,
    register,
    can,
    reads,
    simulate,
    listed,
    plan,
    http,
  };
}

async function auditEvents(f: OrganizationFixture, tenantId = f.tenantId): Promise<AuditEvent[]> {
  return f.database.transaction((tx) => tx.find<AuditEvent>('audit', { tenantId }));
}

/** A clearance record written straight to the store (for root administrators, whom no officer of a tenant clears). */
async function storeClearance(
  f: OrganizationFixture,
  identity: { id: string; tenantId: string },
  schemeTenantId: string,
  level: string,
) {
  const now = f.now();
  await f.database.transaction(async (tx) => {
    const record = {
      id: identity.id,
      tenantId: identity.tenantId,
      uniqueKey: `identity:${identity.id}`,
      identityId: identity.id,
      schemeTenantId,
      level,
      citizenship: ['USA'],
      status: 'active',
      readIns: [],
      grantedAt: now,
      grantedBy: 'test',
      updatedAt: now,
      updatedBy: 'test',
    };
    if (await tx.get('clearances', identity.id)) await tx.put('clearances', record);
    else await tx.insert('clearances', record);
  });
}

describe('mandatory access control on the decision paths', () => {
  it('refuses reading up on authorize, require, HTTP and authorizeMany, masking the reason', async () => {
    const s = await setup();
    const { f, tenantId, alice } = s;
    await s.label('document', 'secret', { level: 'S' });
    await s.label('document', 'top', { level: 'TS' });
    const check = (id: string) => ({
      action: 'documents:read',
      resource: { type: 'document', id },
    });

    // Uncleared: unlabeled resources only, every refusal told as ACCESS_DENIED.
    expect(await s.reads(alice.credential, 'open')).toBe(true);
    await expect(
      f.iam.require({ ...alice.credential, tenantId, ...check('open') }),
    ).resolves.toBeUndefined();
    for (const id of ['secret', 'top']) {
      expect(await f.iam.authorize({ ...alice.credential, tenantId, ...check(id) })).toEqual({
        allowed: false,
        reason: 'ACCESS_DENIED',
        matched: [],
      });
      await expect(
        f.iam.require({ ...alice.credential, tenantId, ...check(id) }),
      ).rejects.toMatchObject({ code: 'ACCESS_DENIED', status: 403 });
      const overHttp = await s.http(
        'authorize',
        { tenantId, ...check(id) },
        alice.credential.token,
      );
      expect(overHttp.status).toBe(200);
      expect(overHttp.body.data).toEqual({ allowed: false, reason: 'ACCESS_DENIED', matched: [] });
      // Only the officer-facing explanation tools name the mandatory reason.
      expect((await s.simulate(alice.identity.id, 'documents:read', 'document', id)).reason).toBe(
        'CLEARANCE_REQUIRED',
      );
    }
    const checks = ['open', 'secret', 'top'].map(check);
    const batch = await f.iam.authorizeMany({ ...alice.credential, tenantId, checks });
    expect(batch.results.map((item) => [item.resource.id, item.allowed])).toEqual([
      ['open', true],
      ['secret', false],
      ['top', false],
    ]);
    expect(batch.results.filter((item) => !item.allowed).map((item) => item.reason)).toEqual([
      'ACCESS_DENIED',
      'ACCESS_DENIED',
    ]);
    const batchOverHttp = await s.http(
      'authorizeMany',
      { tenantId, checks },
      alice.credential.token,
    );
    expect(
      (batchOverHttp.body.data.results as Array<{ allowed: boolean; reason: string }>).map(
        (item) => (item.allowed ? 'allowed' : item.reason),
      ),
    ).toEqual(['allowed', 'ACCESS_DENIED', 'ACCESS_DENIED']);
    // Every refusal is audited with the mandatory marker and nothing about the label.
    const refusals = (await auditEvents(f)).filter(
      (event) => event.outcome === 'deny' && event.action === 'documents:read',
    );
    expect(refusals.length).toBe(10);
    for (const event of refusals) expect(event.metadata).toEqual({ mandatory: 'clearance' });

    // A clearance never grants: cleared without a role is still no grant (and not a clearance refusal).
    const carol = await f.member('carol');
    await s.clear(carol.id, 'TS');
    expect((await s.simulate(carol.id, 'documents:read', 'document', 'secret')).reason).toBe(
      'NO_APPLICABLE_GRANT',
    );

    // Cleared at SECRET: reads SECRET, not TOP SECRET; then at TOP SECRET, both.
    await s.clear(alice.identity.id, 'S');
    expect(await s.reads(alice.credential, 'secret')).toBe(true);
    expect(await s.reads(alice.credential, 'top')).toBe(false);
    await s.relevel(alice.identity.id, 'TS');
    expect(await s.reads(alice.credential, 'top')).toBe(true);
    // Status is computed at decision time: suspension and expiry take effect at once.
    await s.suspend(alice.identity.id);
    expect(await s.reads(alice.credential, 'secret')).toBe(false);
    expect(await s.reads(alice.credential, 'open')).toBe(true);
    await f.iam.api.clearances.reinstate(s.owner, { tenantId, identityId: alice.identity.id });
    expect(await s.reads(alice.credential, 'top')).toBe(true);
    await f.iam.api.clearances.update(s.owner, {
      tenantId,
      identityId: alice.identity.id,
      expiresAt: f.now() + 3_600_000,
    });
    expect(await s.reads(alice.credential, 'top')).toBe(true);
    f.advance(2 * 3_600_000);
    expect(await s.reads(alice.credential, 'secret')).toBe(false);
    expect(
      (await s.simulate(alice.identity.id, 'documents:read', 'document', 'secret')).reason,
    ).toBe('CLEARANCE_REQUIRED');
  });

  it('limits listings and data filter plans to what the clearance reads, for owners and root too', async () => {
    const s = await setup();
    const { f, tenantId, alice, owner } = s;
    const root = f.rootCredential;
    for (const id of ['f-open', 'f-secret', 'f-top']) await s.register('folder', id);
    await s.label('folder', 'f-secret', { level: 'S' });
    await s.label('folder', 'f-top', { level: 'TS' });
    await s.label('document', 'secret', { level: 'S' });
    await s.label('document', 'top', { level: 'TS' });

    for (const who of [alice.credential, owner, root])
      expect(await s.listed(who, 'folders:read', 'folder')).toEqual(['f-open']);
    const overHttp = await s.http(
      'listAccessible',
      { tenantId, action: 'folders:read', type: 'folder' },
      alice.credential.token,
    );
    expect(
      (overHttp.body.data.resources as Array<{ resourceId: string }>).map(
        (item) => item.resourceId,
      ),
    ).toEqual(['f-open']);
    // Plans: the policies allow every row, the clearance takes the labeled ones away, for root and the owner too.
    for (const who of [alice.credential, owner, root]) {
      expect(await s.plan(who, 'documents:read', 'document')).toMatchObject({
        kind: 'conditional',
        filter: allBut('secret', 'top'),
      });
      expect(await s.plan(who, 'folders:read', 'folder')).toMatchObject({
        kind: 'conditional',
        filter: allBut('f-secret', 'f-top'),
      });
    }
    expect(
      (
        await f.iam.api.filters.planFor(owner, {
          tenantId,
          identityId: alice.identity.id,
          action: 'documents:read',
          type: 'document',
        })
      ).filter,
    ).toEqual(allBut('secret', 'top'));
    // The plan agrees with authorize, row by row.
    const agree = async (credential: Credential) => {
      const { filter } = await s.plan(credential, 'documents:read', 'document');
      for (const id of ['open', 'secret', 'top', 'other'])
        expect([id, filterMatches(filter, { id })]).toEqual([id, await s.reads(credential, id)]);
    };
    await agree(alice.credential);

    await s.clear(alice.identity.id, 'S');
    expect(await s.listed(alice.credential, 'folders:read', 'folder')).toEqual([
      'f-open',
      'f-secret',
    ]);
    expect((await s.plan(alice.credential, 'documents:read', 'document')).filter).toEqual(
      allBut('top'),
    );
    await agree(alice.credential);
    await s.relevel(alice.identity.id, 'TS');
    expect(await s.plan(alice.credential, 'documents:read', 'document')).toMatchObject({
      kind: 'always',
    });
    await agree(alice.credential);

    // A statement conditioned on a label's keys cannot be planned: they are derived per resource, not columns.
    const dan = await f.member('dan');
    const low = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Low reports',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['reports:read'],
            resources: ['report/*'],
            conditions: { NumericLessThan: { 'resource.classificationRank': 2 } },
          },
        ],
      },
    });
    await s.bind(low.id, dan.id);
    const danSession = { token: (await f.signIn('dan')).token };
    await expect(s.plan(danSession, 'reports:read', 'report')).rejects.toMatchObject({
      code: 'UNSUPPORTED_FILTER',
    });
  });

  it('tells reviewers the truth: simulate, effective actions with iam: actions first, who can, impact, invariants, access paths', async () => {
    const s = await setup();
    const { f, tenantId, owner, alice, bob, officer } = s;
    await s.label('report', 'r-secret', { level: 'S' });
    await s.label('report', 'r-top', { level: 'TS' });
    await s.clear(alice.identity.id, 'S');
    const report = (id: string) => ({ type: 'report', id });

    // Effective actions are prepared with the first sorted action (an iam: one here) and still checked per action.
    const effective = await f.iam.api.policies.effectiveActions(owner, {
      tenantId,
      identityId: bob.identity.id,
      resource: report('r-secret'),
      actions: ['reports:read', 'iam:resources:read'],
    });
    expect(effective.results).toEqual([
      { action: 'iam:resources:read', allowed: true, reason: expect.any(String) },
      { action: 'reports:read', allowed: false, reason: 'CLEARANCE_REQUIRED' },
    ]);
    expect(effective.allowed).toEqual(['iam:resources:read']);
    const every = await f.iam.api.policies.effectiveActions(owner, {
      tenantId,
      identityId: bob.identity.id,
      resource: report('r-secret'),
    });
    expect(every.results.some((result) => result.action.startsWith('iam:'))).toBe(true);
    for (const result of every.results)
      if (result.action.startsWith('iam:')) expect(result.reason).not.toBe('CLEARANCE_REQUIRED');
      else expect(result).toMatchObject({ allowed: false, reason: 'CLEARANCE_REQUIRED' });
    const aliceTop = await f.iam.api.policies.effectiveActions(owner, {
      tenantId,
      identityId: alice.identity.id,
      resource: report('r-top'),
      actions: ['iam:resources:read', 'reports:read'],
    });
    expect(aliceTop.allowed).toEqual(['iam:resources:read']);

    // Who can: identities refused by their clearance drop out (the owner included).
    const who = async (id: string) =>
      (
        await f.iam.api.policies.whoCan(owner, {
          tenantId,
          action: 'reports:read',
          resource: report(id),
        })
      ).identities.map((match) => match.identityId);
    expect(await who('r-open')).toEqual(
      expect.arrayContaining([alice.identity.id, bob.identity.id, f.ownerId]),
    );
    expect(await who('r-secret')).toEqual([alice.identity.id]);
    expect(await who('r-top')).toEqual([]);

    // Impact: actions the clearance refuses never show as gained (iam: action first again).
    const dave = await f.member('dave');
    const erin = await f.member('erin');
    const viewers = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Viewers',
      permissions: ['iam:resources:read'],
    });
    await s.bind(viewers.id, dave.id);
    await s.bind(viewers.id, erin.id);
    await s.clear(dave.id, 'S');
    const preview = await f.iam.api.impact.preview(owner, {
      tenantId,
      change: { role: { roleId: viewers.id, permissions: ['iam:resources:read', 'reports:read'] } },
      resources: [report('r-open'), report('r-secret')],
      actions: ['reports:read', 'iam:resources:read'],
    });
    const changes = new Map(preview.identities.map((entry) => [entry.identity.id, entry.changes]));
    expect(changes.get(dave.id)).toEqual([
      { resource: 'report/r-open', gained: ['reports:read'], lost: [] },
      { resource: 'report/r-secret', gained: ['reports:read'], lost: [] },
    ]);
    expect(changes.get(erin.id)).toEqual([
      { resource: 'report/r-open', gained: ['reports:read'], lost: [] },
    ]);
    expect(preview.gainedTotal).toBe(3);

    // Invariants report the clearance refusal as the violation's reason.
    const expectAllow = await f.iam.api.invariants.create(owner, {
      tenantId,
      name: 'Bob reads the secret report',
      subject: { identityId: bob.identity.id },
      action: 'reports:read',
      resource: report('r-secret'),
      expect: 'allow',
    });
    expect(expectAllow.result).toMatchObject({
      passed: false,
      violations: [{ identity: { id: bob.identity.id }, reason: 'CLEARANCE_REQUIRED' }],
    });
    const expectDeny = await f.iam.api.invariants.create(owner, {
      tenantId,
      name: 'Nobody reads the top report',
      subject: { everyone: true },
      action: 'reports:read',
      resource: report('r-top'),
      expect: 'deny',
      mode: 'enforce',
    });
    expect(expectDeny.result.passed).toBe(true);
    expect((await f.iam.api.invariants.run(owner, { tenantId })).summary).toEqual({
      passed: 1,
      failed: 1,
      errors: 0,
    });
    // Labeling only narrows access, so an enforced "expect allow" invariant never blocks it...
    await f.iam.api.invariants.create(owner, {
      tenantId,
      name: 'Alice reads the open report',
      subject: { identityId: alice.identity.id },
      action: 'reports:read',
      resource: report('r-open'),
      expect: 'allow',
      mode: 'enforce',
    });
    await s.label('report', 'r-open', { level: 'TS' });
    expect(await s.can(alice.credential, 'reports:read', 'report', 'r-open')).toBe(false);
    // ... while declassifying widens it and is held to every enforced "expect deny" invariant.
    await s.clear(officer.identity.id, 'TS');
    await expect(
      f.iam.api.clearances.declassify(officer.credential, {
        tenantId,
        type: 'report',
        id: 'r-top',
        label: { level: 'U' },
        reason: 'released',
      }),
    ).rejects.toMatchObject({ code: 'INVARIANT_VIOLATION' });
    expect(await s.can(alice.credential, 'reports:read', 'report', 'r-top')).toBe(false);

    // Access paths: an MFA step-up is offered where it helps, nothing where the clearance refuses.
    const mia = await f.member('mia');
    const stepUp = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Step-up reports',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['reports:read'],
            resources: ['report/*'],
            conditions: { Bool: { 'principal.mfa': true } },
          },
        ],
      },
    });
    await s.bind(stepUp.id, mia.id);
    const miaSession = { token: (await f.signIn('mia')).token };
    const paths = (id: string) =>
      f.iam.api.accessPaths.find(miaSession, {
        tenantId,
        action: 'reports:read',
        resource: report(id),
      });
    expect((await paths('r-plain')).paths).toEqual([{ kind: 'mfa' }]);
    expect(await paths('r-secret')).toEqual({ allowed: false, reason: 'ACCESS_DENIED', paths: [] });
  });

  it('decides an application action on iam/{type}/{id} like the resource it names, in reviews and plugin operations too', async () => {
    const plugin: IamPlugin = {
      id: 'memos',
      actions: ['memos:archive'],
      endpoints: [
        {
          method: 'POST',
          path: 'archive',
          action: 'memos:archive',
          validate: (value) => {
            const input = value as { tenantId?: unknown; id?: unknown };
            return { tenantId: input.tenantId, id: String(input.id) };
          },
          resource: (input) => `document/${String(input.id)}`,
          handler: async (_context, input) => ({ archived: input.id }),
        },
      ],
    };
    const s = await setup({ overrides: { plugins: [plugin] } });
    const { f, tenantId, owner, alice } = s;
    await s.bind(
      (
        await f.iam.api.roles.create(owner, {
          tenantId,
          name: 'Archivists',
          permissions: ['memos:archive'],
        })
      ).id,
      alice.identity.id,
    );
    await s.label('document', 'secret', { level: 'S' });
    const named = { type: 'iam', id: 'document/secret' };
    expect(await s.can(alice.credential, 'documents:read', 'iam', 'document/secret')).toBe(false);
    // What the resolver answers for the alias counts like for the resource: its own label, the parent it reports.
    await s.label('folder', 'vault', { level: 'TS' }, true);
    for (const key of ['document/claimed', 'iam/document/claimed'])
      s.app.set(key, { classification: { level: 'TS' } });
    for (const key of ['document/child', 'iam/document/child'])
      s.app.set(key, { attributes: { parentType: 'folder', parentId: 'vault' } });
    for (const id of ['claimed', 'child']) {
      expect(await s.reads(alice.credential, id)).toBe(false);
      expect(await s.can(alice.credential, 'documents:read', 'iam', `document/${id}`)).toBe(false);
    }
    expect(
      (await s.simulate(alice.identity.id, 'documents:read', 'iam', 'document/secret')).reason,
    ).toBe('CLEARANCE_REQUIRED');
    // Reviews resolve the resource once, then evaluate application and iam: actions alike.
    expect(
      (
        await f.iam.api.policies.effectiveActions(owner, {
          tenantId,
          identityId: alice.identity.id,
          resource: named,
          actions: ['documents:read', 'iam:resources:read'],
        })
      ).results.map((result) => [result.action, result.allowed, result.reason]),
    ).toEqual([
      ['documents:read', false, 'CLEARANCE_REQUIRED'],
      ['iam:resources:read', true, expect.any(String)],
    ]);
    expect(
      (
        await f.iam.api.policies.whoCan(owner, {
          tenantId,
          action: 'documents:read',
          resource: named,
        })
      ).identities,
    ).toEqual([]);
    expect(
      (
        await f.iam.api.policies.whoCan(owner, {
          tenantId,
          action: 'iam:resources:read',
          resource: named,
        })
      ).identities.map((match) => match.identityId),
    ).toEqual(expect.arrayContaining([alice.identity.id, f.ownerId]));
    const invariant = await f.iam.api.invariants.create(owner, {
      tenantId,
      name: 'Alice reads the named memo',
      subject: { identityId: alice.identity.id },
      action: 'documents:read',
      resource: named,
      expect: 'allow',
    });
    expect(invariant.result).toMatchObject({
      passed: false,
      violations: [{ reason: 'CLEARANCE_REQUIRED' }],
    });
    const viewers = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Viewers',
      permissions: ['iam:resources:read'],
    });
    await s.bind(viewers.id, (await f.member('vic')).id);
    const preview = await f.iam.api.impact.preview(owner, {
      tenantId,
      change: {
        role: { roleId: viewers.id, permissions: ['iam:resources:read', 'documents:read'] },
      },
      resources: [named, { type: 'iam', id: 'document/open' }],
      actions: ['documents:read'],
    });
    expect(preview.identities.flatMap((entry) => entry.changes)).toEqual([
      { resource: 'iam/document/open', gained: ['documents:read'], lost: [] },
    ]);
    // A plugin operation with its own action on a record it names is held to the label too (and audited as such).
    const archive = (credential: Credential, id: string) =>
      f.iam.callPlugin(credential, { pluginId: 'memos', path: 'archive', tenantId, input: { id } });
    expect(await archive(alice.credential, 'open')).toEqual({ archived: 'open' });
    await expect(archive(alice.credential, 'secret')).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    const refusal = (await auditEvents(f)).find(
      (event) => event.action === 'memos:archive' && event.outcome === 'deny',
    );
    expect(refusal?.metadata).toEqual({ mandatory: 'clearance' });
    await s.clear(alice.identity.id, 'S');
    expect(await archive(alice.credential, 'secret')).toEqual({ archived: 'secret' });
  });
});

describe('root under mandatory access control', () => {
  it('refuses root on labeled application resources but keeps iam administration', async () => {
    const s = await setup();
    const { f, tenantId } = s;
    const root = f.rootCredential;
    await s.register('folder', 'f-open');
    await s.register('folder', 'f-secret');
    await s.label('folder', 'f-secret', { level: 'S' });
    await s.label('document', 'secret', { level: 'S' });

    expect(await s.reads(root, 'open')).toBe(true);
    expect(await s.reads(root, 'secret')).toBe(false);
    expect(await s.can(root, 'folders:read', 'folder', 'f-secret')).toBe(false);
    // Naming the resource through `iam/{type}/{id}` changes nothing for an application action...
    expect(await s.can(root, 'documents:read', 'iam', 'document/secret')).toBe(false);
    expect(await s.can(root, 'folders:read', 'iam', 'folder/f-secret')).toBe(false);
    // ... while iam:* administration of the same resources stays possible.
    expect(await s.can(root, 'iam:resources:read', 'iam', 'folder/f-secret')).toBe(true);
    expect(
      await f.iam.api.resources.get(root, { tenantId, type: 'folder', id: 'f-secret' }),
    ).toMatchObject({ resourceId: 'f-secret' });
    expect((await f.iam.api.clearances.listLabels(root, { tenantId })).total).toBe(2);
    expect((await f.iam.api.clearances.getScheme(root, { tenantId }))?.name).toBe('Acme');
    const batch = await f.iam.authorizeMany({
      ...root,
      tenantId,
      checks: ['open', 'secret'].map((id) => ({
        action: 'documents:read',
        resource: { type: 'document', id },
      })),
    });
    expect(batch.results.map((item) => [item.allowed, item.reason])).toEqual([
      [true, 'ROOT_OVERRIDE'],
      [false, 'ACCESS_DENIED'],
    ]);
    expect(await s.listed(root, 'folders:read', 'folder')).toEqual(['f-open']);
    expect(await s.plan(root, 'folders:read', 'folder')).toMatchObject({
      kind: 'conditional',
      filter: allBut('f-secret'),
    });
    const refusals = (await auditEvents(f)).filter(
      (event) => event.outcome === 'deny' && event.actorId === f.root.identity.id,
    );
    expect(refusals.length).toBeGreaterThan(0);
    for (const event of refusals) expect(event.metadata).toEqual({ mandatory: 'clearance' });
  });

  it('lets root read only what a clearance of its own under the scheme in force dominates', async () => {
    const s = await setup({ rootScheme: true });
    const { f } = s;
    const root = f.rootCredential;
    await s.label('document', 'secret', { level: 'S' });
    await s.label('document', 'top', { level: 'TS' });
    expect(await s.reads(root, 'secret')).toBe(false);
    await storeClearance(f, f.root.identity, f.root.tenant.id, 'S');
    expect(await s.reads(root, 'secret')).toBe(true);
    expect(await s.reads(root, 'top')).toBe(false);
    expect((await s.plan(root, 'documents:read', 'document')).filter).toEqual(allBut('top'));
    // A record issued under another scheme counts for nothing.
    await storeClearance(f, f.root.identity, 'another-scheme', 'TS');
    expect(await s.reads(root, 'secret')).toBe(false);
  });

  it('keeps the plain override with appliesToRoot: false, for root only', async () => {
    const s = await setup({ overrides: { clearances: { appliesToRoot: false } } });
    const { f } = s;
    const root = f.rootCredential;
    await s.register('folder', 'f-secret');
    await s.label('folder', 'f-secret', { level: 'S' });
    await s.label('document', 'secret', { level: 'S' });
    expect(await s.reads(root, 'secret')).toBe(true);
    expect(await s.listed(root, 'folders:read', 'folder')).toEqual(['f-secret']);
    expect((await s.plan(root, 'documents:read', 'document')).kind).toBe('always');
    expect(await s.reads(s.owner, 'secret')).toBe(false);
    expect(await s.reads(s.alice.credential, 'secret')).toBe(false);
  });

  for (const [name, options, rootLevel] of [
    ['a scheme of the organization', {}, undefined],
    ['the platform scheme with a root clearance', { rootScheme: true }, 'TS'],
    ['appliesToRoot: false', { overrides: { clearances: { appliesToRoot: false } } }, undefined],
  ] as const)
    it(`keeps cross-tenant root out of organization hosts under ${name}`, async () => {
      const txt = new Map<string, string[][]>();
      const s = await setup({
        ...options,
        overrides: {
          ...('overrides' in options ? options.overrides : {}),
          ssh: true,
          domains: { resolveTxt: async (host) => txt.get(host) ?? [] },
        },
      });
      const { f, tenantId, owner, alice } = s;
      if (rootLevel) await storeClearance(f, f.root.identity, f.root.tenant.id, rootLevel);
      const claim = await f.iam.api.domains.add(owner, { tenantId, domain: 'acme.test' });
      txt.set(claim.dnsRecord.name, [[claim.dnsRecord.value]]);
      await f.iam.api.domains.verify(owner, { tenantId, domainId: claim.id });
      await f.iam.api.ssh.setup(owner, { tenantId });
      const web = await f.iam.api.ssh.createHost(owner, {
        tenantId,
        name: 'web-01',
        logins: ['deploy'],
      });
      await f.iam.api.ssh.enrollHost({
        joinToken: web.joinToken,
        publicKey: sshPublicKey('ed25519', 'root@web-01'),
      });
      const deploy = await f.iam.api.roles.create(owner, {
        tenantId,
        name: 'Deploy',
        permissions: ['ssh:login'],
      });
      await s.bind(deploy.id, alice.identity.id);
      await expect(
        f.iam.api.ssh.issueCertificate(f.rootCredential, { tenantId, publicKey: sshPublicKey() }),
      ).rejects.toMatchObject({ code: 'ROOT_SSH_RESTRICTED' });
      expect((await f.iam.api.ssh.myAccess(f.rootCredential, { tenantId })).hosts).toEqual([]);
      // The sweep refuses root's certificates for organization hosts too: alice's certificate, re-attributed to
      // root's session in the store, is revoked.
      const issued = await f.iam.api.ssh.issueCertificate(alice.credential, {
        tenantId,
        publicKey: sshPublicKey('ed25519', 'alice@laptop'),
        ttlMs: 3_600_000,
      });
      expect(issued.principals).toEqual(['deploy@web-01']);
      expect((await f.iam.api.ssh.sweep(owner, { tenantId })).revoked).toBe(0);
      const [rootSession] = await f.iam.store.find<Session>('sessions', {
        tokenHash: sha256(f.rootCredential.token),
      });
      await f.database.transaction(async (tx) => {
        const [certificate] = await tx.find<StoredRecord>('sshCertificates', {
          tenantId,
          kind: 'user',
        });
        await tx.put('sshCertificates', {
          ...certificate!,
          identityId: f.root.identity.id,
          sessionId: rootSession!.id,
        });
      });
      expect(await f.iam.api.ssh.sweep(owner, { tenantId })).toMatchObject({
        revoked: 1,
        byReason: { 'access-changed': 1 },
      });
    });
});

describe('every party of a session dominates the label', () => {
  it('needs every agent of a delegated hand-off chain, and the person', async () => {
    const s = await setup();
    const { f, tenantId, alice } = s;
    const assistant = await s.agent('Assistant');
    const researcher = await s.agent('Researcher');
    await s.label('document', 'secret', { level: 'S' });
    await s.clear(alice.identity.id, 'S');
    const delegation = await f.iam.api.delegations.grant(alice.credential, {
      tenantId,
      agentId: assistant.id,
      scopes: ['documents:*'],
      handoff: { agents: [researcher.id] },
    });
    const acting = await f.iam.api.delegations.assume(assistant.key, {
      tenantId,
      delegationId: delegation.id,
    });
    const handoff = await f.iam.api.delegations.handoff(
      { token: acting.token },
      { tenantId, agentId: researcher.id, scopes: ['documents:read'] },
    );
    const research = await f.iam.api.delegations.assume(researcher.key, {
      tenantId,
      delegationId: handoff.id,
    });
    const assistantSession = { token: acting.token };
    const researchSession = { token: research.token };
    const planned = async (credential: Credential) =>
      filterMatches((await s.plan(credential, 'documents:read', 'document')).filter, {
        id: 'secret',
      });

    expect(await s.reads(alice.credential, 'secret')).toBe(true);
    for (const session of [assistantSession, researchSession]) {
      expect(await s.reads(session, 'open')).toBe(true);
      expect(await s.reads(session, 'secret')).toBe(false);
      expect(await planned(session)).toBe(false);
    }
    // Clearing the agent at the end of the chain is not enough: the assistant that handed the work on takes part.
    await s.clear(researcher.id, 'S');
    expect(await s.reads(researchSession, 'secret')).toBe(false);
    expect(await planned(researchSession)).toBe(false);
    await s.clear(assistant.id, 'S');
    for (const session of [assistantSession, researchSession]) {
      expect(await s.reads(session, 'secret')).toBe(true);
      expect(await planned(session)).toBe(true);
    }
    // Suspending any agent above in the chain, or the person, refuses again.
    await s.suspend(assistant.id);
    expect(await s.reads(researchSession, 'secret')).toBe(false);
    expect(await s.reads(assistantSession, 'secret')).toBe(false);
    await f.iam.api.clearances.reinstate(s.owner, { tenantId, identityId: assistant.id });
    expect(await s.reads(researchSession, 'secret')).toBe(true);
    await s.suspend(alice.identity.id);
    expect(await s.reads(researchSession, 'secret')).toBe(false);
    expect(await s.reads(assistantSession, 'secret')).toBe(false);
  });

  it('needs an agent key’s sponsor too, and carries the source of session tokens', async () => {
    const s = await setup();
    const { f, tenantId, owner, alice, officer } = s;
    await s.label('document', 'secret', { level: 'S' });
    const courier = await s.agent('Courier');
    await s.bind(s.readers.id, courier.id);
    expect(await s.reads(courier.key, 'open')).toBe(true);
    expect(await s.reads(courier.key, 'secret')).toBe(false);
    // The agent is cleared, its sponsor (the owner) is not.
    await s.clear(courier.id, 'S');
    expect(await s.reads(courier.key, 'secret')).toBe(false);
    expect((await s.simulate(courier.id, 'documents:read', 'document', 'secret')).reason).toBe(
      'CLEARANCE_REQUIRED',
    );
    await s.clear(f.ownerId, 'S', {}, officer.credential);
    expect(await s.reads(courier.key, 'secret')).toBe(true);
    expect((await s.simulate(courier.id, 'documents:read', 'document', 'secret')).allowed).toBe(
      true,
    );
    // A session token minted from the key keeps both parties.
    const minted = await f.iam.api.sts.getSessionToken(courier.key);
    expect(await s.reads({ token: minted.token }, 'secret')).toBe(true);
    await s.suspend(f.ownerId, officer.credential);
    expect(await s.reads(courier.key, 'secret')).toBe(false);
    expect(await s.reads({ token: minted.token }, 'secret')).toBe(false);
    expect((await s.simulate(courier.id, 'documents:read', 'document', 'secret')).reason).toBe(
      'CLEARANCE_REQUIRED',
    );
    // A person's own session token carries their clearance; a service account's key its own.
    await s.clear(alice.identity.id, 'S');
    const aliceToken = await f.iam.api.sts.getSessionToken(alice.credential);
    expect(await s.reads({ token: aliceToken.token }, 'secret')).toBe(true);
    const service = await f.iam.api.serviceAccounts.create(owner, { tenantId, name: 'svc-reader' });
    await s.bind(s.readers.id, service.id);
    const serviceKey = await f.iam.api.credentials.create(owner, {
      tenantId,
      identityId: service.id,
    });
    expect(await s.reads({ token: serviceKey.token }, 'secret')).toBe(false);
    await s.clear(service.id, 'S');
    expect(await s.reads({ token: serviceKey.token }, 'secret')).toBe(true);
  });

  it('gives role sessions no clearance, whoever assumed them', async () => {
    const s = await setup();
    const { f, tenantId, owner, alice } = s;
    await s.label('document', 'secret', { level: 'S' });
    await s.clear(alice.identity.id, 'TS');
    const analysts = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Analysts',
      permissions: ['documents:read'],
    });
    const trust = await f.iam.api.trust.create(f.rootCredential, {
      tenantId,
      sourceTenantId: tenantId,
      sourceIdentityId: alice.identity.id,
      roleId: analysts.id,
      requireMfa: false,
    });
    const assumed = await f.iam.api.roles.assume(alice.credential, {
      tenantId,
      trustId: trust.id,
    });
    const role = { token: assumed.token };
    expect(await s.reads(alice.credential, 'secret')).toBe(true);
    expect(await s.reads(role, 'open')).toBe(true);
    expect(await s.reads(role, 'secret')).toBe(false);
    expect((await s.plan(role, 'documents:read', 'document')).filter).toEqual(allBut('secret'));
  });

  it('needs the administrator’s clearance behind a "view as" session too', async () => {
    const s = await setup();
    const { f, tenantId, owner, alice, officer } = s;
    await f.iam.api.tenants.setAuthPolicy(owner, {
      tenantId,
      authPolicy: { allowImpersonation: true },
    });
    await s.register('folder', 'f-open');
    await s.register('folder', 'f-secret');
    await s.label('folder', 'f-secret', { level: 'S' });
    await s.label('document', 'secret', { level: 'S' });
    await s.clear(alice.identity.id, 'S');
    const viewAs = await f.iam.api.identities.impersonate(owner, {
      tenantId,
      identityId: alice.identity.id,
      reason: 'ticket 7',
    });
    const view = { token: viewAs.token };
    const planned = async () =>
      filterMatches((await s.plan(view, 'documents:read', 'document')).filter, { id: 'secret' });
    expect(await s.reads(alice.credential, 'secret')).toBe(true);
    expect(await s.reads(view, 'open')).toBe(true);
    expect(await s.reads(view, 'secret')).toBe(false);
    expect(await s.listed(view, 'folders:read', 'folder')).toEqual(['f-open']);
    expect(await planned()).toBe(false);
    // Once the administrator is cleared as well, the member's view opens.
    await s.clear(f.ownerId, 'S', {}, officer.credential);
    expect(await s.reads(view, 'secret')).toBe(true);
    expect(await s.listed(view, 'folders:read', 'folder')).toEqual(['f-open', 'f-secret']);
    expect(await planned()).toBe(true);
    // The member's own clearance still counts.
    await s.suspend(alice.identity.id, officer.credential);
    expect(await s.reads(view, 'secret')).toBe(false);
    expect(await s.listed(view, 'folders:read', 'folder')).toEqual(['f-open']);
  });

  it('never uses up a delegated confirmation on a clearance refusal', async () => {
    const s = await setup();
    const { f, tenantId, alice } = s;
    const assistant = await s.agent('Assistant');
    await s.label('document', 'secret', { level: 'S' });
    await s.clear(alice.identity.id, 'S');
    const delegation = await f.iam.api.delegations.grant(alice.credential, {
      tenantId,
      agentId: assistant.id,
      scopes: ['documents:*'],
      confirm: ['documents:read'],
    });
    const acting = await f.iam.api.delegations.assume(assistant.key, {
      tenantId,
      delegationId: delegation.id,
    });
    const session = { token: acting.token };
    const request = await f.iam.api.delegations.requestConfirmation(session, {
      tenantId,
      action: 'documents:read',
      resource: { type: 'document', id: 'secret' },
      reason: 'Summarize the memo',
    });
    await f.iam.api.delegations.decideConfirmation(alice.credential, {
      tenantId,
      confirmationId: request.id,
      approve: true,
    });
    const status = async () =>
      (
        await f.database.transaction((tx) =>
          tx.get<StoredRecord & { status: string }>('delegationConfirmations', request.id),
        )
      )?.status;
    // The assistant is not cleared: refused before the confirmation gate, which keeps the approval.
    expect(await s.reads(session, 'secret')).toBe(false);
    expect(await s.reads(session, 'secret')).toBe(false);
    expect(await status()).toBe('approved');
    // Cleared, the approval opens exactly one call.
    await s.clear(assistant.id, 'S');
    expect(await s.reads(session, 'secret')).toBe(true);
    expect(await status()).toBe('used');
    expect(await s.reads(session, 'secret')).toBe(false);
  });
});

describe('labels can only be raised', () => {
  it('lets a resolver raise a label, never lower it; an asserted label the scheme cannot read refuses everyone', async () => {
    const s = await setup();
    const { f, tenantId, owner, alice, bob } = s;
    await s.label('document', 'lowered', { level: 'TS' });
    s.app.set('document/lowered', { classification: { level: 'U' } });
    s.app.set('document/raised', { classification: { level: 'S', compartments: ['GAMMA'] } });
    s.app.set('document/nulled', { classification: null });
    await s.label('document', 'nulled', { level: 'S' });
    await s.label('document', 'both', { level: 'S' });
    s.app.set('document/both', { classification: { level: 'TS' } });
    s.app.set('document/unknown-level', { classification: { level: 'COSMIC' } });
    s.app.set('document/unknown-compartment', {
      classification: { level: 'C', compartments: ['DELTA'] },
    });
    s.app.set('document/malformed', { classification: 'TS' });
    s.app.set('document/extra-field', { classification: { level: 'C', caveat: 'NOFORN' } });
    await s.clear(alice.identity.id, 'S');
    await s.clear(bob.identity.id, 'S');

    expect(await s.reads(alice.credential, 'lowered')).toBe(false);
    expect(await s.reads(alice.credential, 'raised')).toBe(false);
    expect(await s.reads(alice.credential, 'nulled')).toBe(true);
    expect(await s.reads(alice.credential, 'both')).toBe(false);
    await f.iam.api.clearances.readIn(owner, {
      tenantId,
      identityId: alice.identity.id,
      compartmentId: 'GAMMA',
    });
    expect(await s.reads(alice.credential, 'raised')).toBe(true);
    expect(await s.reads(bob.credential, 'raised')).toBe(false);
    await s.relevel(alice.identity.id, 'TS');
    expect(await s.reads(alice.credential, 'lowered')).toBe(true);
    expect(await s.reads(alice.credential, 'both')).toBe(true);
    expect(
      (await s.simulate(bob.identity.id, 'documents:read', 'document', 'lowered')).reason,
    ).toBe('CLEARANCE_REQUIRED');
    for (const id of ['unknown-level', 'unknown-compartment', 'malformed', 'extra-field'])
      for (const who of [alice.credential, owner, f.rootCredential])
        expect([id, await s.reads(who, id)]).toEqual([id, false]);
    // Officers can see why.
    expect(
      await f.iam.api.clearances.explain(owner, {
        tenantId,
        identityId: alice.identity.id,
        type: 'document',
        id: 'unknown-level',
      }),
    ).toMatchObject({ allowed: false, failure: 'invalid-label' });
  });

  it('never takes the classification or clearance keys from resolveContext, attributes or identity attributes', async () => {
    const s = await setup();
    const { f, tenantId, owner } = s;
    Object.assign(s.spoof, {
      'resource.classification': 'U',
      'resource.classificationRank': -1,
      'resource.compartments': [],
      'resource.noforn': false,
      'resource.releasableTo': ['USA'],
      'principal.clearanceLevel': 'TS',
      'principal.clearanceRank': 3,
      'principal.clearanceStatus': 'active',
      'principal.clearanceCompartments': ['GAMMA'],
      'principal.clearanceCitizenship': ['USA'],
    });
    await s.label('report', 'r-u', { level: 'U' });
    await s.label('report', 'r-attr', { level: 'TS' });
    s.app.set('report/r-attr', {
      attributes: {
        classification: 'U',
        classificationRank: -1,
        compartments: [],
        noforn: false,
        releasableTo: ['USA'],
      },
    });
    await s.label('document', 'secret', { level: 'S' });
    s.app.set('document/secret', { attributes: { classification: 'U', classificationRank: -1 } });
    const kim = await f.member('kim');
    const keyed = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Keyed',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['reports:read'],
            resources: ['report/*'],
            conditions: { StringEquals: { 'resource.classification': 'U' } },
          },
          {
            effect: 'allow',
            actions: ['documents:read'],
            resources: ['document/*'],
            conditions: { NumericGreaterThanEquals: { 'principal.clearanceRank': 3 } },
          },
          {
            effect: 'allow',
            actions: ['documents:write'],
            resources: ['document/*'],
            conditions: { ArrayContains: { 'principal.clearanceCompartments': 'GAMMA' } },
          },
        ],
      },
    });
    await s.bind(keyed.id, kim.id);
    const session = { token: (await f.signIn('kim')).token };
    const reason = async (action: string, type: string, id: string) =>
      (await s.simulate(kim.id, action, type, id)).reason;

    // Uncleared, the spoofed keys open nothing: the server's own values stand.
    expect(await s.can(session, 'reports:read', 'report', 'r-plain')).toBe(false);
    expect(await s.can(session, 'documents:read', 'document', 'open')).toBe(false);
    expect(await s.can(session, 'documents:write', 'document', 'open')).toBe(false);
    expect(await reason('reports:read', 'report', 'r-u')).toBe('CLEARANCE_REQUIRED');
    expect(await s.reads(s.alice.credential, 'secret')).toBe(false);
    // Cleared at CONFIDENTIAL, the U report's real level satisfies the condition.
    await s.clear(kim.id, 'C');
    expect(await s.can(session, 'reports:read', 'report', 'r-u')).toBe(true);
    expect(await s.can(session, 'reports:read', 'report', 'r-plain')).toBe(false);
    expect(await s.can(session, 'documents:read', 'document', 'open')).toBe(false);
    // At TOP SECRET the clearance rank does, while the attributes of r-attr do not pass for its TS label.
    await s.relevel(kim.id, 'TS');
    expect(await s.can(session, 'documents:read', 'document', 'open')).toBe(true);
    expect(await s.can(session, 'reports:read', 'report', 'r-attr')).toBe(false);
    expect(await reason('reports:read', 'report', 'r-attr')).toBe('NO_APPLICABLE_GRANT');
    expect(await s.can(session, 'documents:write', 'document', 'open')).toBe(false);
    await f.iam.api.clearances.readIn(owner, {
      tenantId,
      identityId: kim.id,
      compartmentId: 'GAMMA',
    });
    expect(await s.can(session, 'documents:write', 'document', 'open')).toBe(true);

    // A document test (no decision, no mandatory check) starts from an uncleared person and an unlabeled resource.
    const tested = await f.iam.api.policies.test(owner, {
      tenantId,
      action: 'documents:read',
      resource: 'document/x',
      document: {
        version: 1,
        statements: [
          {
            effect: 'allow',
            actions: ['documents:read'],
            resources: ['document/*'],
            conditions: {
              NumericLessThan: {
                'principal.clearanceRank': 0,
                'resource.classificationRank': 0,
              },
            },
          },
        ],
      },
    });
    expect(tested.allowed).toBe(true);

    // Labels are no attributes: the label's names cannot be declared, and managed attributes cannot carry one.
    await s.register('folder', 'f-top');
    await s.label('folder', 'f-top', { level: 'TS' });
    await expect(
      f.iam.api.resources.update(owner, {
        tenantId,
        type: 'folder',
        id: 'f-top',
        attributes: { classification: 'U' },
      }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    expect(await s.can(s.alice.credential, 'folders:read', 'folder', 'f-top')).toBe(false);
    const reserved: NonNullable<BetterIamOptions['permissions']>[] = [
      { resourceTypes: { folder: { managed: true, attributes: { classification: 'string' } } } },
      { resourceTypes: { folder: { managed: true, attributes: { releasableTo: 'string' } } } },
      { identityAttributes: { clearanceRank: 'number' } },
      { identityAttributes: { clearanceCitizenship: 'string' } },
    ];
    for (const permissions of reserved)
      await expect(organizationFixture({ clearances: {}, permissions })).rejects.toMatchObject({
        code: 'INVALID_CONFIG',
      });
  });

  it('keeps what an application parent passes down when a tenant registers a type named like the application’s', async () => {
    const app = new Map<string, AppRecord>();
    const f = await organizationFixture({
      clearances: {},
      permissions: { mode: 'tenant-defined', actions: ['documents:read'] },
      resolveResource: async (reference) =>
        ({ ...(app.get(`${reference.type}/${reference.id}`) ?? {}), ...reference }) as never,
    } as Partial<BetterIamOptions>);
    const { tenantId } = f;
    const owner = f.ownerCredential;
    await f.iam.api.clearances.defineScheme(owner, {
      tenantId,
      name: 'Acme',
      definition: schemeDefinition(),
      adjudication: 'unrestricted',
    });
    // The application reports folder/vault as the handbook's parent; the vault passes TOP SECRET down.
    app.set('document/handbook', { attributes: { parentType: 'folder', parentId: 'vault' } });
    await f.iam.api.clearances.label(owner, {
      tenantId,
      type: 'folder',
      id: 'vault',
      label: { level: 'TS' },
      inheritToChildren: true,
    });
    const builder = await administrator(f, 'builder', [
      'documents:read',
      'iam:resource-types:create',
      'iam:resources:create',
    ]);
    const reads = async () =>
      (
        await f.iam.authorize({
          ...builder.credential,
          tenantId,
          action: 'documents:read',
          resource: { type: 'document', id: 'handbook' },
        })
      ).allowed;
    const plan = () =>
      f.iam.planResources({
        ...builder.credential,
        tenantId,
        action: 'documents:read',
        type: 'document',
      });
    expect(await reads()).toBe(false);
    await expect(plan()).rejects.toMatchObject({ code: 'UNSUPPORTED_FILTER' });
    // Registering a tenant type named like the application's, and a record of the handbook without that parent, is
    // no way to declassify it: the application still answers for its actions, with the parent it reports.
    await f.iam.api.resourceTypes.register(builder.credential, {
      tenantId,
      name: 'document',
      actions: ['share'],
    });
    await f.iam.api.resources.register(builder.credential, {
      tenantId,
      type: 'document',
      id: 'handbook',
    });
    expect(await reads()).toBe(false);
    await expect(plan()).rejects.toMatchObject({ code: 'UNSUPPORTED_FILTER' });
    expect(
      (
        await f.iam.api.policies.simulate(owner, {
          tenantId,
          identityId: builder.identity.id,
          action: 'documents:read',
          resource: { type: 'document', id: 'handbook' },
        })
      ).reason,
    ).toBe('CLEARANCE_REQUIRED');
  });

  it('keeps a label through deleting and re-registering the resource', async () => {
    const s = await setup();
    const { f, tenantId, owner, alice } = s;
    await s.register('folder', 'f-del');
    await s.label('folder', 'f-del', { level: 'TS' });
    await f.iam.api.resources.delete(owner, { tenantId, type: 'folder', id: 'f-del' });
    expect(
      (await f.iam.api.clearances.getLabel(owner, { tenantId, type: 'folder', id: 'f-del' })).label
        ?.label,
    ).toEqual({ level: 'TS' });
    await s.register('folder', 'f-del');
    expect(await s.can(alice.credential, 'folders:read', 'folder', 'f-del')).toBe(false);
    expect(await s.listed(alice.credential, 'folders:read', 'folder')).toEqual([]);
    expect((await s.plan(alice.credential, 'folders:read', 'folder')).filter).toEqual(
      allBut('f-del'),
    );
    // Children registered again under a parent that passes its label down inherit it again.
    await s.register('folder', 'vault');
    await s.label('folder', 'vault', { level: 'TS' }, true);
    await s.register('file', 'a', 'vault');
    await f.iam.api.resources.delete(owner, { tenantId, type: 'file', id: 'a' });
    await s.register('file', 'a', 'vault');
    expect(await s.can(alice.credential, 'files:read', 'file', 'a')).toBe(false);
  });
});

describe('fails closed', () => {
  it('refuses unlabeled resources of types the scheme requires a label on, unless a default label applies', async () => {
    const s = await setup({ scheme: { requireLabels: ['document', 'folder'] } });
    const { f, tenantId, owner, alice, bob } = s;
    await s.register('folder', 'f-unlabeled');
    await s.register('folder', 'f-u');
    await s.label('folder', 'f-u', { level: 'U' });
    await s.label('document', 'd-u', { level: 'U' });
    await s.clear(alice.identity.id, 'TS');

    for (const who of [alice.credential, owner, f.rootCredential]) {
      expect(await s.reads(who, 'unlabeled')).toBe(false);
      expect(await s.can(who, 'documents:read', 'iam', 'document/unlabeled')).toBe(false);
      expect(await s.can(who, 'folders:read', 'folder', 'f-unlabeled')).toBe(false);
    }
    expect(
      (await s.simulate(alice.identity.id, 'documents:read', 'document', 'unlabeled')).reason,
    ).toBe('CLEARANCE_REQUIRED');
    expect(await s.reads(alice.credential, 'd-u')).toBe(true);
    // A type the scheme does not name is unaffected.
    expect(await s.can(alice.credential, 'reports:read', 'report', 'r-plain')).toBe(true);
    expect(await s.listed(alice.credential, 'folders:read', 'folder')).toEqual(['f-u']);
    expect(await s.plan(alice.credential, 'folders:read', 'folder')).toMatchObject({
      kind: 'conditional',
      filter: { kind: 'equals', field: 'id', values: ['f-u'] },
    });
    await expect(s.plan(alice.credential, 'documents:read', 'document')).rejects.toMatchObject({
      code: 'UNSUPPORTED_FILTER',
    });
    // iam administration of them stays possible.
    expect(await s.can(owner, 'iam:resources:read', 'iam', 'folder/f-unlabeled')).toBe(true);

    // A default label stands in for a missing one.
    await f.iam.api.clearances.updateScheme(owner, { tenantId, defaultLabel: { level: 'C' } });
    expect(await s.reads(alice.credential, 'unlabeled')).toBe(true);
    expect(await s.reads(bob.credential, 'unlabeled')).toBe(false);
    expect(await s.listed(alice.credential, 'folders:read', 'folder')).toEqual([
      'f-u',
      'f-unlabeled',
    ]);
    expect(await s.listed(bob.credential, 'folders:read', 'folder')).toEqual([]);
    await s.clear(bob.identity.id, 'C');
    expect(await s.reads(bob.credential, 'unlabeled')).toBe(true);

    // `*` requires labels on every application type.
    await f.iam.api.clearances.updateScheme(owner, {
      tenantId,
      requireLabels: ['*'],
      defaultLabel: null,
    });
    expect(await s.can(alice.credential, 'reports:read', 'report', 'r-plain')).toBe(false);
    expect(await s.reads(alice.credential, 'unlabeled')).toBe(false);
    expect(await s.reads(alice.credential, 'd-u')).toBe(true);
  });

  it('decides NOFORN and REL TO by adjudicated citizenship, never by identity attributes or context', async () => {
    const s = await setup();
    const { f, tenantId, owner, alice, bob } = s;
    const carol = await s.person('carol');
    await s.label('document', 'noforn', { level: 'S', noforn: true });
    await s.label('document', 'rel-gbr', { level: 'S', releasableTo: ['GBR'] });
    await s.label('document', 'owners-only', { level: 'S', releasableTo: [] });
    const citizenship = (identityId: string, value: string) =>
      f.iam.api.identities.update(owner, {
        tenantId,
        identityId,
        attributes: { citizenship: value },
      });
    // Identity attributes and context say the opposite of the adjudicated records.
    await citizenship(alice.identity.id, 'USA');
    await citizenship(bob.identity.id, 'GBR');
    await citizenship(carol.identity.id, 'USA');
    Object.assign(s.spoof, { 'principal.clearanceCitizenship': ['USA'] });
    await s.clear(alice.identity.id, 'S', { citizenship: ['GBR'] });
    await s.clear(bob.identity.id, 'S', { citizenship: ['USA'] });
    await s.clear(carol.identity.id, 'S', { citizenship: ['FRA'] });

    const matrix = async () => {
      const rows: Record<string, boolean[]> = {};
      for (const [name, who] of [
        ['alice', alice],
        ['bob', bob],
        ['carol', carol],
      ] as const) {
        rows[name] = [];
        for (const id of ['noforn', 'rel-gbr', 'owners-only'])
          rows[name]!.push(await s.reads(who.credential, id));
      }
      return rows;
    };
    expect(await matrix()).toEqual({
      alice: [false, true, false],
      bob: [true, true, true],
      carol: [false, false, false],
    });
    expect(
      (await s.simulate(alice.identity.id, 'documents:read', 'document', 'noforn')).reason,
    ).toBe('CLEARANCE_REQUIRED');
    // Adjudicating dual citizenship changes the decision; editing the attribute never does.
    await f.iam.api.clearances.update(owner, {
      tenantId,
      identityId: alice.identity.id,
      citizenship: ['GBR', 'USA'],
    });
    await citizenship(carol.identity.id, 'GBR');
    expect(await matrix()).toEqual({
      alice: [true, true, true],
      bob: [true, true, true],
      carol: [false, false, false],
    });
  });

  it('passes labels down managed parents, as far as they go, decided at the time', async () => {
    const s = await setup();
    const { f, tenantId, owner, alice, officer } = s;
    await s.register('folder', 'vault');
    await s.register('folder', 'plain');
    await s.register('file', 'a', 'vault');
    await s.register('file', 'b', 'plain');
    await s.register('page', 'p', 'a');
    await s.label('folder', 'vault', { level: 'TS' }, true);
    await s.label('folder', 'plain', { level: 'S' });
    await s.label('file', 'b', { level: 'C', compartments: ['HCS'] });
    await s.clear(alice.identity.id, 'S');

    expect(await s.can(alice.credential, 'folders:read', 'folder', 'plain')).toBe(true);
    expect(await s.can(alice.credential, 'files:read', 'file', 'a')).toBe(false);
    expect(await s.can(alice.credential, 'pages:read', 'page', 'p')).toBe(false);
    expect(await s.can(alice.credential, 'pages:read', 'iam', 'page/p')).toBe(false);
    // Not passed down: b carries only its own label (which needs HCS).
    expect(await s.can(alice.credential, 'files:read', 'file', 'b')).toBe(false);
    await f.iam.api.clearances.readIn(owner, {
      tenantId,
      identityId: alice.identity.id,
      compartmentId: 'HCS',
    });
    expect(await s.can(alice.credential, 'files:read', 'file', 'b')).toBe(true);
    expect(await s.listed(alice.credential, 'files:read', 'file')).toEqual(['b']);
    expect(await s.listed(alice.credential, 'pages:read', 'page')).toEqual([]);
    expect((await s.plan(alice.credential, 'files:read', 'file')).filter).toEqual(allBut('a'));
    expect((await s.plan(alice.credential, 'pages:read', 'page')).filter).toEqual(allBut('p'));
    expect((await s.simulate(alice.identity.id, 'pages:read', 'page', 'p')).reason).toBe(
      'CLEARANCE_REQUIRED',
    );
    expect(
      (await f.iam.api.clearances.getLabel(owner, { tenantId, type: 'page', id: 'p' })).inherited,
    ).toEqual({ level: 'TS' });
    for (const who of [owner, f.rootCredential])
      expect(await s.can(who, 'pages:read', 'page', 'p')).toBe(false);
    // Passing down is computed at decision time: stopping it at the folder opens the children at once.
    await s.clear(officer.identity.id, 'TS');
    await f.iam.api.clearances.declassify(officer.credential, {
      tenantId,
      type: 'folder',
      id: 'vault',
      label: { level: 'TS' },
      inheritToChildren: false,
      reason: 'children reviewed',
    });
    expect(await s.can(alice.credential, 'files:read', 'file', 'a')).toBe(true);
    expect(await s.can(alice.credential, 'pages:read', 'page', 'p')).toBe(true);
    expect(await s.can(alice.credential, 'folders:read', 'folder', 'vault')).toBe(false);
    expect(await s.listed(alice.credential, 'pages:read', 'page')).toEqual(['p']);
  });
});

describe('without the clearances option', () => {
  /**
   * The same deployment without `clearances`: once with nothing extra, once with schemes, labels and clearances
   * written straight to the store and a resolver asserting labels. Everything decides the same.
   */
  async function deployment(rows: boolean) {
    const f = await organizationFixture({
      permissions: {
        resourceTypes: {
          ...resourceTypes,
          folder: {
            managed: true,
            actions: ['folders:read'],
            attributes: { classification: 'string' },
          },
        },
        identityAttributes: { clearanceRank: 'number', citizenship: 'string' },
      },
      resolveResource: async (reference) =>
        ({
          ...reference,
          attributes: { classification: 'U' },
          ...(rows ? { classification: { level: 'TS' } } : {}),
        }) as never,
      resolveContext: async () => ({
        'principal.clearanceRank': -1,
        'resource.classificationRank': 0,
      }),
    });
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const readers = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Readers',
      document: {
        version: 1,
        statements: [
          { effect: 'allow', actions: ['folders:read', 'iam:resources:read'], resources: ['*'] },
          {
            effect: 'allow',
            actions: ['documents:read'],
            resources: ['document/*'],
            conditions: {
              NumericLessThan: { 'principal.clearanceRank': 0 },
              StringEquals: { 'resource.classification': 'U' },
            },
          },
          {
            effect: 'allow',
            actions: ['reports:read'],
            resources: ['report/*'],
            conditions: { NumericEquals: { 'resource.classificationRank': 0 } },
          },
        ],
      },
    });
    const alice = await f.member('alice');
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: readers.id,
      subjectType: 'identity',
      subjectId: alice.id,
    });
    for (const id of ['f-open', 'f-secret'])
      await f.iam.api.resources.register(owner, {
        tenantId,
        type: 'folder',
        id,
        attributes: { classification: 'U' },
      });
    if (rows) {
      const now = f.now();
      await f.database.transaction(async (tx) => {
        await tx.insert('classificationSchemes', {
          id: 'scheme-1',
          tenantId,
          uniqueKey: 'scheme',
          name: 'Acme',
          definition: schemeDefinition(),
          requireLabels: ['*'],
          guestCeiling: null,
          interimAllowed: false,
          adjudication: 'unrestricted',
          createdAt: now,
          createdBy: f.ownerId,
          updatedAt: now,
          updatedBy: f.ownerId,
          version: 1,
        });
        for (const [type, id] of [
          ['document', 'secret'],
          ['folder', 'f-secret'],
          ['report', 'r-secret'],
        ] as const)
          await tx.insert('resourceLabels', {
            id: `label-${id}`,
            tenantId,
            uniqueKey: `${type}/${id}`,
            type,
            resourceId: id,
            label: { level: 'TS', noforn: true },
            inheritToChildren: true,
            schemeTenantId: tenantId,
            labeledBy: f.ownerId,
            labeledAt: now,
            version: 1,
          });
        await tx.insert('clearances', {
          id: alice.id,
          tenantId,
          uniqueKey: `identity:${alice.id}`,
          identityId: alice.id,
          schemeTenantId: tenantId,
          level: 'U',
          citizenship: ['FRA'],
          status: 'suspended',
          readIns: [],
          grantedAt: now,
          grantedBy: f.ownerId,
          updatedAt: now,
          updatedBy: f.ownerId,
        });
      });
    }
    const session = { token: (await f.signIn('alice')).token };
    const outcome: Record<string, unknown> = {};
    const check = (action: string, type: string, id: string) => ({
      action,
      resource: { type, id },
    });
    const checks = [
      check('documents:read', 'document', 'open'),
      check('documents:read', 'document', 'secret'),
      check('reports:read', 'report', 'r-secret'),
      check('folders:read', 'folder', 'f-secret'),
      check('documents:read', 'iam', 'document/secret'),
    ];
    for (const [name, credential] of [
      ['alice', session],
      ['owner', owner],
      ['root', f.rootCredential],
    ] as const) {
      outcome[`${name}:authorize`] = [];
      for (const item of checks)
        (outcome[`${name}:authorize`] as unknown[]).push(
          await f.iam.authorize({ ...credential, tenantId, ...item }),
        );
      outcome[`${name}:batch`] = (
        await f.iam.authorizeMany({ ...credential, tenantId, checks })
      ).results;
      outcome[`${name}:listed`] = (
        await f.iam.listAccessible({
          ...credential,
          tenantId,
          action: 'folders:read',
          type: 'folder',
        })
      ).resources.map((item) => item.resourceId);
      for (const [action, type] of [
        ['documents:read', 'document'],
        ['folders:read', 'folder'],
      ] as const)
        outcome[`${name}:plan:${type}`] = await f.iam
          .planResources({ ...credential, tenantId, action, type })
          .then(
            (plan) => ({ kind: plan.kind, filter: plan.filter }),
            (error: { code: string }) => error.code,
          );
    }
    outcome.simulate = [];
    for (const item of checks)
      (outcome.simulate as unknown[]).push(
        await f.iam.api.policies.simulate(owner, { tenantId, identityId: alice.id, ...item }),
      );
    outcome.effective = (
      await f.iam.api.policies.effectiveActions(owner, {
        tenantId,
        identityId: alice.id,
        resource: { type: 'report', id: 'r-secret' },
        actions: ['reports:read', 'iam:resources:read'],
      })
    ).results;
    outcome.whoCan = (
      await f.iam.api.policies.whoCan(owner, {
        tenantId,
        action: 'documents:read',
        resource: { type: 'document', id: 'secret' },
      })
    ).identities
      .map((match) => `${match.name}: ${match.reason}`)
      .sort();
    outcome.paths = await f.iam.api.accessPaths.find(session, {
      tenantId,
      action: 'documents:read',
      resource: { type: 'document', id: 'secret' },
    });
    await expect(f.iam.api.clearances.getScheme(owner, { tenantId })).rejects.toMatchObject({
      code: 'FEATURE_DISABLED',
    });
    return outcome;
  }

  it('decides exactly as before, whatever clearance data the store holds', async () => {
    const without = await deployment(false);
    const withRows = await deployment(true);
    expect(withRows).toEqual(without);
    // And as before means open: the application's own keys and attributes decide.
    expect(
      (without['alice:authorize'] as Array<{ allowed: boolean }>).map((d) => d.allowed),
    ).toEqual([true, true, true, true, false]);
    expect(without['alice:listed']).toEqual(['f-open', 'f-secret']);
    expect(without['root:plan:document']).toEqual({ kind: 'always', filter: { kind: 'true' } });
  });
});
