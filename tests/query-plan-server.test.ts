import { afterEach, describe, expect, it } from 'vitest';
import { describeFilter, filterMatches } from '@better-iam/core';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

/** The application's own documents, which IAM resolves by id when it decides one. */
const documents = new Map<string, Record<string, string>>([
  ['d1', { ownerId: 'alice', classification: 'internal' }],
  ['d2', { ownerId: 'bob', classification: 'internal' }],
  ['d3', { ownerId: 'alice', classification: 'secret' }],
  ['public-faq', { ownerId: 'bob', classification: 'public' }],
  ['public-leak', { ownerId: 'bob', classification: 'secret' }],
  ['d4', {}],
]);

async function setup() {
  const f = await organizationFixture({
    permissions: {
      actions: ['documents:read', 'documents:write'],
      resourceTypes: {
        document: {
          actions: ['documents:read', 'documents:write'],
          attributes: { ownerId: 'string', classification: 'string' },
        },
      },
    },
    resolveResource: async (reference) => ({
      ...reference,
      attributes: documents.get(reference.id) ?? {},
    }),
  });
  const alice = await f.member('alice');
  const role = await f.iam.api.roles.create(f.ownerCredential, {
    tenantId: f.tenantId,
    name: 'Reader',
    document: {
      version: 1,
      statements: [
        {
          effect: 'allow',
          actions: ['documents:read'],
          resources: ['document/*'],
          conditions: { StringEquals: { 'resource.ownerId': 'alice' } },
        },
        { effect: 'allow', actions: ['documents:read'], resources: ['document/public-*'] },
        {
          effect: 'deny',
          actions: ['documents:*'],
          resources: ['document/*'],
          conditions: { StringEquals: { 'resource.classification': 'secret' } },
        },
      ],
    },
  });
  await f.iam.api.bindings.create(f.ownerCredential, {
    tenantId: f.tenantId,
    roleId: role.id,
    subjectType: 'identity',
    subjectId: alice.id,
  });
  const credential = { token: (await f.signIn('alice')).token };
  return { f, alice, credential };
}

describe('query planning on the server', () => {
  it('plans exactly what authorize decides, for the caller and for an administrator preview', async () => {
    const { f, alice, credential } = await setup();
    const plan = await f.iam.api.filters.plan(credential, {
      tenantId: f.tenantId,
      action: 'documents:read',
      type: 'document',
    });
    expect(plan.kind).toBe('conditional');
    expect(describeFilter(plan.filter)).toBe(
      'not (classification = "secret") and (ownerId = "alice" or id like "public-*")',
    );
    for (const [id, attributes] of documents) {
      const decision = await f.iam.authorize({
        ...credential,
        tenantId: f.tenantId,
        action: 'documents:read',
        resource: { type: 'document', id },
      });
      expect(filterMatches(plan.filter, { id, ...attributes }), id).toBe(decision.allowed);
    }
    // The in-process form, with the credential in the request like authorize.
    const inProcess = await f.iam.planResources({
      ...credential,
      tenantId: f.tenantId,
      action: 'documents:read',
      type: 'document',
    });
    expect(inProcess.filter).toEqual(plan.filter);
    // An administrator previews the same plan without a session of alice's.
    const preview = await f.iam.api.filters.planFor(f.ownerCredential, {
      tenantId: f.tenantId,
      identityId: alice.id,
      action: 'documents:read',
      type: 'document',
    });
    expect(preview.filter).toEqual(plan.filter);
    const audit = await f.database.find<{ action: string; resourceId: string }>('audit', {});
    expect(audit.some((event) => event.action === 'iam:policies:simulate' && event.resourceId === alice.id)).toBe(
      true,
    );
  });

  it('answers always, never, and refuses what plans do not cover', async () => {
    const { f, credential } = await setup();
    expect(
      (await f.iam.api.filters.plan(f.ownerCredential, { tenantId: f.tenantId, action: 'documents:write', type: 'document' }))
        .kind,
    ).toBe('always');
    expect(
      (await f.iam.api.filters.plan(credential, { tenantId: f.tenantId, action: 'documents:write', type: 'document' })).kind,
    ).toBe('never');
    expect(
      (await f.iam.api.filters.plan(credential, { tenantId: f.tenantId, action: 'nothing:here', type: 'document' })).kind,
    ).toBe('never');
    // A session of another tenant plans nothing here.
    expect(
      (await f.iam.api.filters.plan(credential, { tenantId: f.root.tenant.id, action: 'documents:read', type: 'document' }))
        .kind,
    ).toBe('never');
    await expect(
      f.iam.api.filters.plan(credential, { tenantId: f.tenantId, action: 'iam:roles:read', type: 'document' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.filters.plan(credential, { tenantId: f.tenantId, action: 'documents:read', type: 'iam' }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      f.iam.api.filters.planFor(credential, {
        tenantId: f.tenantId,
        identityId: 'usr_nobody',
        action: 'documents:read',
        type: 'document',
      }),
    ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });

    const response = await f.iam.handler(
      new Request('http://localhost:3000/api/iam/filters/plan', {
        method: 'POST',
        headers: {
          authorization: `Bearer ${credential.token}`,
          'content-type': 'application/json',
          'x-better-iam': '1',
        },
        body: JSON.stringify({ tenantId: f.tenantId, action: 'documents:read', type: 'document' }),
      }),
    );
    expect(response.status).toBe(200);
    expect(((await response.json()) as { data: { kind: string } }).data.kind).toBe('conditional');
  });
});
