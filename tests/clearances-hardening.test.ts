import { generateKeyPairSync } from 'node:crypto';
import { createRequire } from 'node:module';
import { afterEach, describe, expect, it } from 'vitest';
import type { JWK } from 'jose';
import {
  classificationTemplates,
  type AuditEvent,
  type ClassificationLabel,
  type IamPlugin,
  type IamStore,
} from '@better-iam/core';
import { lintPolicy } from '../packages/server/src/policy-lint.js';
import {
  closeFixtures,
  organizationFixture,
  type OrganizationFixture,
} from './support/organization.js';
import { administrator, otherOrganization } from './support/guests.js';
import { sshPublicKey } from './support/ssh.js';

// jose is a dependency of the server package, not of the workspace root.
const { SignJWT, exportJWK } = createRequire(
  new URL('../packages/server/package.json', import.meta.url),
)('jose') as typeof import('jose');

afterEach(closeFixtures);

/**
 * Security clearances where labels could slip away from what they protect: a tenant moved out from under its scheme
 * (and labels left without one), a registration deleted and registered again under another parent, credentials an
 * administrator offers, SSH logins of a labeled host, models labeled where they are defined, the `iam/{type}/{id}`
 * alias of an application resource, label types that would share a key, levels re-ranked by removing and re-adding
 * them, built-in provider tools under `requireLabels: ['*']`, the policy linter without the option, how often a
 * decision reads the scheme, and who may repair a label left over from another scheme.
 */

type Credential = { token: string };

const can = async (
  f: OrganizationFixture,
  credential: Credential,
  tenantId: string,
  action: string,
  type: string,
  id: string,
) => (await f.iam.authorize({ ...credential, tenantId, action, resource: { type, id } })).allowed;

/** A project below Acme, its owner signed in. */
async function project(f: OrganizationFixture, name: string) {
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
    password: `a strong ${name.toLowerCase()} owner password`,
  });
  if (!('token' in owner)) throw new Error('Unexpected MFA');
  return { tenantId: created.tenant.id, ownerCredential: { token: owner.token } };
}

/** A label written straight to the store, as a scheme that no longer applies (`schemeTenantId`) left it. */
async function storeLabel(
  f: OrganizationFixture,
  tenantId: string,
  type: string,
  resourceId: string,
  label: ClassificationLabel,
  schemeTenantId: string,
  inheritToChildren = false,
) {
  await f.database.transaction((tx) =>
    tx.insert('resourceLabels', {
      id: `label-${tenantId}-${type}-${resourceId}`,
      tenantId,
      uniqueKey: `${type}/${resourceId}`,
      type,
      resourceId,
      label,
      inheritToChildren,
      schemeTenantId,
      labeledBy: 'test',
      labeledAt: f.now(),
      version: 1,
    }),
  );
}

async function auditOf(f: OrganizationFixture, action: string): Promise<AuditEvent[]> {
  return f.database.transaction((tx) =>
    tx.find<AuditEvent>('audit', { tenantId: f.tenantId, action }),
  );
}

describe('a tenant and the scheme its labels were written under', () => {
  it('refuses moving a tenant out from under its scheme while it holds labels or clearances', async () => {
    const f = await organizationFixture({ clearances: {} });
    const api = f.iam.api.clearances;
    await api.defineScheme(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Acme',
      template: 'us',
      adjudication: 'unrestricted',
    });
    const globex = await otherOrganization(f, 'Globex', 'globex');
    const move = (tenantId: string, parentId: string) =>
      f.iam.api.tenants.reparent(f.rootCredential, { tenantId, parentId });

    const apollo = await project(f, 'Apollo');
    await api.label(apollo.ownerCredential, {
      tenantId: apollo.tenantId,
      type: 'document',
      id: 'q3',
      label: { level: 'TS' },
    });
    const rootReads = () =>
      can(f, f.rootCredential, apollo.tenantId, 'documents:read', 'document', 'q3');
    expect(await rootReads()).toBe(false);
    // Globex defines no scheme: below it the label would protect nothing, and root could read up.
    await expect(move(apollo.tenantId, globex.tenantId)).rejects.toMatchObject({
      code: 'RESOURCE_IN_USE',
    });
    expect(await rootReads()).toBe(false);

    // A live clearance holds a project in place too, until it ends.
    const gemini = await project(f, 'Gemini');
    const pat = await f.iam.api.identities.create(gemini.ownerCredential, {
      tenantId: gemini.tenantId,
      email: 'pat@gemini.test',
      name: 'pat',
      password: 'a strong pat password',
    });
    await api.grant(gemini.ownerCredential, {
      tenantId: gemini.tenantId,
      identityId: pat.id,
      level: 'C',
      citizenship: ['USA'],
    });
    await expect(move(gemini.tenantId, globex.tenantId)).rejects.toMatchObject({
      code: 'RESOURCE_IN_USE',
    });
    await api.revoke(gemini.ownerCredential, {
      tenantId: gemini.tenantId,
      identityId: pat.id,
      reason: 'leaving the program',
    });
    expect((await move(gemini.tenantId, globex.tenantId)).parentId).toBe(globex.tenantId);
  });

  it('moves labeled tenants freely while the scheme in force stays the same', async () => {
    const f = await organizationFixture({ clearances: {} });
    await f.iam.api.clearances.defineScheme(f.rootCredential, {
      tenantId: f.root.tenant.id,
      name: 'Platform',
      template: 'us',
    });
    const globex = await otherOrganization(f, 'Globex', 'globex');
    const apollo = await project(f, 'Apollo');
    await f.iam.api.clearances.label(apollo.ownerCredential, {
      tenantId: apollo.tenantId,
      type: 'document',
      id: 'q3',
      label: { level: 'TS' },
    });
    const moved = await f.iam.api.tenants.reparent(f.rootCredential, {
      tenantId: apollo.tenantId,
      parentId: globex.tenantId,
    });
    expect(moved.parentId).toBe(globex.tenantId);
    expect(
      await can(f, apollo.ownerCredential, apollo.tenantId, 'documents:read', 'document', 'q3'),
    ).toBe(false);
  });

  it('refuses everyone, root included, on labels left in a tenant no scheme applies to', async () => {
    const f = await organizationFixture({ clearances: {} });
    const globex = await otherOrganization(f, 'Globex', 'globex');
    await storeLabel(f, globex.tenantId, 'document', 'q3', { level: 'TS' }, f.tenantId);
    const reads = (credential: Credential, id: string) =>
      can(f, credential, globex.tenantId, 'documents:read', 'document', id);
    expect(await reads(globex.ownerCredential, 'q3')).toBe(false);
    expect(await reads(f.rootCredential, 'q3')).toBe(false);
    expect(await reads(globex.ownerCredential, 'open')).toBe(true);
    // Administration stays possible.
    expect(
      await can(
        f,
        globex.ownerCredential,
        globex.tenantId,
        'iam:resources:read',
        'iam',
        'document/q3',
      ),
    ).toBe(true);
    expect(
      (
        await f.iam.planResources({
          ...globex.ownerCredential,
          tenantId: globex.tenantId,
          action: 'documents:read',
          type: 'document',
        })
      ).filter,
    ).toEqual({ kind: 'not', filter: { kind: 'equals', field: 'id', values: ['q3'] } });
  });
});

describe('labels outlive what they were inherited through', () => {
  it('keeps what a registration inherited when it is deleted and registered again elsewhere', async () => {
    const f = await organizationFixture({
      clearances: {},
      permissions: {
        actions: ['documents:read'],
        resourceTypes: {
          folder: { managed: true, actions: ['folders:read'] },
          file: { managed: true, parent: 'folder', actions: ['files:read'] },
        },
      },
    });
    const { tenantId } = f;
    const api = f.iam.api.clearances;
    await api.defineScheme(f.ownerCredential, { tenantId, name: 'Acme', template: 'us' });
    const adam = await administrator(f, 'adam', [
      'iam:resources:create',
      'iam:resources:delete',
      'folders:read',
      'files:read',
    ]);
    const register = (credential: Credential, type: string, id: string, parentId?: string) =>
      f.iam.api.resources.register(credential, {
        tenantId,
        type,
        id,
        ...(parentId ? { parentId } : {}),
      });
    await register(f.ownerCredential, 'folder', 'vault');
    await register(f.ownerCredential, 'file', 'a', 'vault');
    await api.label(f.ownerCredential, {
      tenantId,
      type: 'folder',
      id: 'vault',
      label: { level: 'TS' },
      inheritToChildren: true,
    });
    const reads = () => can(f, adam.credential, tenantId, 'files:read', 'file', 'a');
    expect(await reads()).toBe(false);
    // An uncleared resource administrator "moves" the file to an open folder.
    await register(adam.credential, 'folder', 'open');
    await f.iam.api.resources.delete(adam.credential, { tenantId, type: 'file', id: 'a' });
    await register(adam.credential, 'file', 'a', 'open');
    expect(await reads()).toBe(false);
    expect(
      (
        await f.iam.listAccessible({
          ...adam.credential,
          tenantId,
          action: 'files:read',
          type: 'file',
        })
      ).resources,
    ).toEqual([]);
    expect(
      await api.getLabel(f.ownerCredential, { tenantId, type: 'file', id: 'a' }),
    ).toMatchObject({
      label: { label: { level: 'TS' }, inheritToChildren: false },
      inherited: null,
    });
    const kept = (await auditOf(f, 'classification:label')).find(
      (event) => event.metadata?.reason === 'resource-deleted',
    );
    expect(kept).toMatchObject({
      actorId: adam.identity.id,
      resourceId: 'file/a',
      metadata: { type: 'file', level: 'TS', inheritToChildren: false },
    });
    // What it inherits must be readable under the scheme in force before it can go.
    await register(f.ownerCredential, 'folder', 'stale');
    await storeLabel(f, tenantId, 'folder', 'stale', { level: 'U' }, 'another-scheme', true);
    await register(f.ownerCredential, 'file', 'b', 'stale');
    await expect(
      f.iam.api.resources.delete(adam.credential, { tenantId, type: 'file', id: 'b' }),
    ).rejects.toMatchObject({ code: 'RESOURCE_IN_USE' });
  });
});

/** A wallet: a P-256 holder key that signs OpenID4VCI proofs. */
async function wallet() {
  const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const { kty, crv, x, y } = await exportJWK(publicKey);
  const jwk: JWK = { kty, crv, x, y };
  return (audience: string, nonce: string, at: number) =>
    new SignJWT({ aud: audience, nonce, iat: Math.floor(at / 1000) })
      .setProtectedHeader({ alg: 'ES256', typ: 'openid4vci-proof+jwt', jwk })
      .sign(privateKey);
}

/** Redeems a credential offer the way a wallet does: the pre-authorized code, then the credential request. */
async function redeem(
  f: OrganizationFixture,
  offer: { credentialOffer: { grants: Record<string, Record<string, unknown>> } },
  type: string,
): Promise<Response> {
  const issuer = `http://localhost:3000/api/iam/vc/${f.tenantId}`;
  const grant = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
  const granted = await f.iam.handler(
    new Request(`${issuer}/token`, {
      method: 'POST',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
      body: new URLSearchParams({
        grant_type: grant,
        'pre-authorized_code': offer.credentialOffer.grants[grant]![
          'pre-authorized_code'
        ] as string,
      }),
    }),
  );
  const { access_token } = (await granted.json()) as { access_token: string };
  const { nonce } = await f.iam.api.verifiableCredentials.nonce({ tenantId: f.tenantId });
  const proof = await (await wallet())(issuer, nonce, f.now());
  return f.iam.handler(
    new Request(`${issuer}/credential`, {
      method: 'POST',
      headers: { 'content-type': 'application/json', authorization: `Bearer ${access_token}` },
      body: JSON.stringify({ credential_configuration_id: type, proofs: { jwt: [proof] } }),
    }),
  );
}

describe('artifacts issued for a labeled resource', () => {
  it('needs the holder of an administrator’s credential offer cleared at the offer, the redemption and the sweep', async () => {
    const f = await organizationFixture({ verifiableCredentials: true, clearances: {} });
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const api = f.iam.api.clearances;
    await api.defineScheme(owner, {
      tenantId,
      name: 'Acme',
      template: 'us',
      adjudication: 'unrestricted',
    });
    await f.iam.api.verifiableCredentials.createType(owner, {
      tenantId,
      name: 'facility-badge',
      displayName: 'Facility badge',
      claims: [{ name: 'name', source: 'name', selective: false }],
    });
    await api.label(owner, {
      tenantId,
      type: 'credential-type',
      id: 'facility-badge',
      label: { level: 'TS' },
    });
    const bob = await f.member('bob');
    const offer = () =>
      f.iam.api.verifiableCredentials.createOffer(owner, {
        tenantId,
        type: 'facility-badge',
        identityId: bob.id,
      });
    await expect(offer()).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    await api.grant(owner, { tenantId, identityId: bob.id, level: 'TS', citizenship: ['USA'] });
    const early = await offer();
    const suspend = () =>
      api.suspend(owner, { tenantId, identityId: bob.id, reason: 'review', notifyPerson: false });
    // Suspended before the wallet redeems it: the offer is decided again and refused.
    await suspend();
    expect((await redeem(f, early, 'facility-badge')).status).toBe(403);
    const refusals = (await auditOf(f, 'vc:offer:redeem')).filter(
      (event) => event.outcome === 'deny',
    );
    expect(refusals.map((event) => event.metadata?.reason)).toEqual(['access-changed']);
    await api.reinstate(owner, { tenantId, identityId: bob.id });
    expect((await redeem(f, await offer(), 'facility-badge')).status).toBe(200);
    expect(await f.iam.verifiableCredentials.sweep({ tenantId })).toEqual({
      examined: 1,
      revoked: 0,
    });
    // The sweep revokes it once the holder no longer dominates the type's label.
    await suspend();
    expect(await f.iam.verifiableCredentials.sweep({ tenantId })).toEqual({
      examined: 1,
      revoked: 1,
    });
    const issued = await f.iam.api.verifiableCredentials.listIssued(owner, { tenantId });
    expect(issued.credentials[0]).toMatchObject({
      identityId: bob.id,
      status: 'revoked',
      reason: 'access-changed',
    });
  });

  it('carries an SSH host’s label to every login of the host, added later or not', async () => {
    const txt = new Map<string, string[][]>();
    const f = await organizationFixture({
      ssh: true,
      clearances: {},
      domains: { resolveTxt: async (name) => txt.get(name) ?? [] },
    });
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const claim = await f.iam.api.domains.add(owner, { tenantId, domain: 'acme.test' });
    txt.set(claim.dnsRecord.name, [[claim.dnsRecord.value]]);
    await f.iam.api.domains.verify(owner, { tenantId, domainId: claim.id });
    await f.iam.api.ssh.setup(owner, { tenantId });
    const db = await f.iam.api.ssh.createHost(owner, {
      tenantId,
      name: 'db-01',
      logins: ['deploy'],
    });
    await f.iam.api.ssh.enrollHost({
      joinToken: db.joinToken,
      publicKey: sshPublicKey('ed25519', 'root@db-01'),
    });
    const alice = await administrator(f, 'alice', ['ssh:login']);
    await f.iam.api.clearances.defineScheme(owner, { tenantId, name: 'Acme', template: 'us' });
    const issue = async () =>
      (
        await f.iam.api.ssh.issueCertificate(alice.credential, {
          tenantId,
          publicKey: sshPublicKey('ed25519', 'alice@laptop'),
          ttlMs: 3_600_000,
        })
      ).principals.sort();
    expect(await issue()).toEqual(['deploy@db-01']);
    // The host is labeled (not passed down, and none of its logins): every login of it is taken away.
    await f.iam.api.clearances.label(owner, {
      tenantId,
      type: 'ssh-host',
      id: 'db-01',
      label: { level: 'TS' },
    });
    await expect(issue()).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    expect((await f.iam.api.ssh.myAccess(alice.credential, { tenantId })).hosts).toEqual([]);
    expect(await can(f, alice.credential, tenantId, 'ssh:login', 'ssh-login', 'db-01/deploy')).toBe(
      false,
    );
    expect((await f.iam.api.ssh.sweep(owner, { tenantId })).revoked).toBe(1);
    // A login added afterwards carries it too.
    await f.iam.api.ssh.updateHost(owner, {
      tenantId,
      hostId: db.host.id,
      logins: ['deploy', 'backup'],
    });
    expect(await can(f, alice.credential, tenantId, 'ssh:login', 'ssh-login', 'db-01/backup')).toBe(
      false,
    );
    expect(
      await f.iam.api.clearances.getLabel(owner, {
        tenantId,
        type: 'ssh-login',
        id: 'db-01/backup',
      }),
    ).toMatchObject({ label: null, inherited: { level: 'TS' } });
    await expect(
      f.iam.planResources({
        ...alice.credential,
        tenantId,
        action: 'ssh:login',
        type: 'ssh-login',
      }),
    ).rejects.toMatchObject({ code: 'UNSUPPORTED_FILTER' });
    // Cleared for it, she logs in again.
    await f.iam.api.clearances.grant(owner, {
      tenantId,
      identityId: alice.identity.id,
      level: 'TS',
      citizenship: ['USA'],
    });
    expect(await issue()).toEqual(['backup@db-01', 'deploy@db-01']);
  });

  it('applies a label written where a model is defined in every tenant that inherits it', async () => {
    const f = await organizationFixture({ inference: true, clearances: {} });
    const { tenantId } = f;
    const root = f.rootCredential;
    const rootTenant = f.root.tenant.id;
    // A platform-wide scheme that requires a label on every application type.
    await f.iam.api.clearances.defineScheme(root, {
      tenantId: rootTenant,
      name: 'Platform',
      template: 'us',
      requireLabels: ['*'],
    });
    const provider = await f.iam.api.inference.createProvider(root, {
      tenantId: rootTenant,
      name: 'Anthropic',
      kind: 'anthropic',
      apiKey: 'sk-ant-secret-provider-key-0042',
    });
    for (const name of ['frontier-ts', 'small'])
      await f.iam.api.inference.createModel(root, {
        tenantId: rootTenant,
        name,
        providerId: provider.id,
        upstreamModel: 'claude-opus-5-5',
        tier: 'frontier',
      });
    const alice = await administrator(f, 'alice', ['inference:invoke', 'inference:use-tool']);
    const invokes = (model: string) =>
      can(f, alice.credential, tenantId, 'inference:invoke', 'model', model);
    const listed = async () =>
      (await f.iam.api.inference.listMine(alice.credential, { tenantId }))
        .map((model) => model.name)
        .sort();
    expect(await invokes('frontier-ts')).toBe(true);
    expect(await listed()).toEqual(['frontier-ts', 'small']);
    // Provider tools are built in: '*' does not require a label on them.
    expect(
      await can(f, alice.credential, tenantId, 'inference:use-tool', 'model-tool', 'web_search'),
    ).toBe(true);
    // Labeled where it is defined, the model is refused in the organization that inherits it.
    await f.iam.api.clearances.label(root, {
      tenantId: rootTenant,
      type: 'model',
      id: 'frontier-ts',
      label: { level: 'TS' },
    });
    expect(await invokes('frontier-ts')).toBe(false);
    expect(await listed()).toEqual(['small']);
    expect(
      await f.iam.api.inference.check(alice.credential, { tenantId, model: 'frontier-ts' }),
    ).toMatchObject({ allowed: false });
    expect(
      await f.iam.api.clearances.getLabel(f.ownerCredential, {
        tenantId,
        type: 'model',
        id: 'frontier-ts',
      }),
    ).toMatchObject({ label: null, inherited: { level: 'TS' } });
    // The owner bootstraps alice's clearance under the platform scheme: she invokes it again.
    await f.iam.api.clearances.grant(f.ownerCredential, {
      tenantId,
      identityId: alice.identity.id,
      level: 'TS',
      citizenship: ['USA'],
    });
    expect(await invokes('frontier-ts')).toBe(true);
    expect(await listed()).toEqual(['frontier-ts', 'small']);
  });
});

describe('the iam/{type}/{id} alias', () => {
  it('reads what the application resolves for the resource it names, failing closed', async () => {
    const app = new Map<string, Record<string, unknown>>([
      ['document/q3', { classification: { level: 'S' } }],
      ['document/child', { attributes: { parentType: 'folder', parentId: 'vault' } }],
    ]);
    const plugin: IamPlugin = {
      id: 'exports',
      actions: ['docs:export'],
      endpoints: [
        {
          method: 'POST',
          path: 'export',
          action: 'docs:export',
          validate: (value) => {
            const input = value as { tenantId?: unknown; id?: unknown };
            return { tenantId: input.tenantId, id: String(input.id) };
          },
          resource: (input) => `document/${String(input.id)}`,
          handler: async (_context, input) => ({ exported: input.id }),
        },
      ],
    };
    const f = await organizationFixture({
      clearances: {},
      plugins: [plugin],
      permissions: {
        actions: ['documents:read'],
        resourceTypes: { folder: { managed: true, actions: ['folders:read'] } },
      },
      // Answers for the resource itself only, never for `iam/document/...`.
      resolveResource: async (reference) =>
        reference.type === 'document' && reference.id === 'broken'
          ? { ...reference, id: 'another' }
          : ({ ...(app.get(`${reference.type}/${reference.id}`) ?? {}), ...reference } as never),
    });
    const { tenantId } = f;
    await f.iam.api.clearances.defineScheme(f.ownerCredential, {
      tenantId,
      name: 'Acme',
      template: 'us',
    });
    await f.iam.api.resources.register(f.ownerCredential, {
      tenantId,
      type: 'folder',
      id: 'vault',
    });
    await f.iam.api.clearances.label(f.ownerCredential, {
      tenantId,
      type: 'folder',
      id: 'vault',
      label: { level: 'TS' },
      inheritToChildren: true,
    });
    const alice = await administrator(f, 'alice', ['docs:export']);
    const exportOf = (id: string) =>
      f.iam.callPlugin(alice.credential, {
        pluginId: 'exports',
        path: 'export',
        tenantId,
        input: { id },
      });
    expect(await exportOf('open')).toEqual({ exported: 'open' });
    // The resolver's own label, the parent it reports, and a resolver that cannot answer all refuse.
    for (const id of ['q3', 'child', 'broken'])
      await expect(exportOf(id)).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
    const refusal = (await auditOf(f, 'docs:export')).find((event) => event.outcome === 'deny');
    expect(refusal?.metadata).toEqual({ mandatory: 'clearance' });
    await f.iam.api.clearances.grant(f.ownerCredential, {
      tenantId,
      identityId: alice.identity.id,
      level: 'TS',
      citizenship: ['USA'],
    });
    expect(await exportOf('q3')).toEqual({ exported: 'q3' });
    expect(await exportOf('child')).toEqual({ exported: 'child' });
    await expect(exportOf('broken')).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
  });
});

describe('schemes and labels keep their meaning', () => {
  it('labels only resource type names, so one label key never stands for two resources', async () => {
    const f = await organizationFixture({ clearances: {} });
    const { tenantId } = f;
    const api = f.iam.api.clearances;
    await api.defineScheme(f.ownerCredential, { tenantId, name: 'Acme', template: 'us' });
    const lee = await administrator(f, 'lee', ['documents:read', 'iam:classifications:label']);
    for (const type of ['document/a', 'Document', 'doc_v2', '*'])
      await expect(
        api.label(lee.credential, { tenantId, type, id: 'b', label: { level: 'U' } }),
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(
      api.updateScheme(f.ownerCredential, { tenantId, requireLabels: ['document/a'] }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    // The document whose id holds a slash is labeled, and refused.
    await api.label(f.ownerCredential, {
      tenantId,
      type: 'document',
      id: 'a/b',
      label: { level: 'TS' },
    });
    expect(await can(f, lee.credential, tenantId, 'documents:read', 'document', 'a/b')).toBe(false);
    expect(
      (await api.listLabels(f.ownerCredential, { tenantId })).labels.map((item) => [
        item.type,
        item.id,
      ]),
    ).toEqual([['document', 'a/b']]);
  });

  it('never re-ranks a level, even one only the application’s labels use', async () => {
    const f = await organizationFixture({
      clearances: {},
      resolveResource: async (reference) =>
        `${reference.type}/${reference.id}` === 'document/plans'
          ? { ...reference, classification: { level: 'S' } }
          : reference,
    });
    const { tenantId } = f;
    const api = f.iam.api.clearances;
    await api.defineScheme(f.ownerCredential, {
      tenantId,
      name: 'Acme',
      template: 'us',
      adjudication: 'unrestricted',
    });
    const bob = await administrator(f, 'bob', ['documents:read']);
    await api.grant(f.ownerCredential, {
      tenantId,
      identityId: bob.identity.id,
      level: 'C',
      citizenship: ['USA'],
    });
    const reads = () => can(f, bob.credential, tenantId, 'documents:read', 'document', 'plans');
    const definition = (...levels: Array<[string, number]>) => ({
      ...JSON.parse(JSON.stringify(classificationTemplates.us)),
      levels: levels.map(([id, rank]) => ({ id, name: `Level ${id}`, rank })),
    });
    const update = (...levels: Array<[string, number]>) =>
      api.updateScheme(f.ownerCredential, { tenantId, definition: definition(...levels) });
    expect(await reads()).toBe(false);
    // In one step: SECRET drops below CONFIDENTIAL while the levels IAM sees in use keep theirs.
    await expect(update(['S', 0], ['C', 1], ['U', 2], ['TS', 3])).rejects.toMatchObject({
      code: 'RESOURCE_IN_USE',
    });
    expect(await reads()).toBe(false);
    // In two: removing the levels nothing in IAM uses, then bringing them back swapped.
    await update(['U', 0], ['C', 1]);
    expect(await reads()).toBe(false);
    await expect(update(['U', 0], ['C', 1], ['TS', 2], ['S', 3])).rejects.toMatchObject({
      code: 'RESOURCE_IN_USE',
    });
    await update(['U', 0], ['C', 1], ['S', 2], ['TS', 3]);
    expect(await reads()).toBe(false);
    await api.update(f.ownerCredential, { tenantId, identityId: bob.identity.id, level: 'S' });
    expect(await reads()).toBe(true);
  });

  it('lets only someone cleared for what it says declassify a label left from another scheme', async () => {
    const f = await organizationFixture({ clearances: {} });
    const { tenantId } = f;
    await f.iam.api.clearances.defineScheme(f.ownerCredential, {
      tenantId,
      name: 'Acme',
      template: 'us',
      adjudication: 'unrestricted',
    });
    const permissions = ['documents:read', 'iam:classifications:declassify'];
    const dan = await administrator(f, 'dan', permissions);
    const tess = await administrator(f, 'tess', permissions);
    await f.iam.api.clearances.grant(f.ownerCredential, {
      tenantId,
      identityId: tess.identity.id,
      level: 'TS',
      citizenship: ['USA'],
    });
    await storeLabel(f, tenantId, 'document', 'readable', { level: 'TS' }, 'a-former-scheme');
    await storeLabel(
      f,
      tenantId,
      'document',
      'foreign',
      { level: 'TOP-SECRET' },
      'a-former-scheme',
    );
    const reads = (credential: Credential, id: string) =>
      can(f, credential, tenantId, 'documents:read', 'document', id);
    const declassify = (credential: Credential, id: string) =>
      f.iam.api.clearances.declassify(credential, {
        tenantId,
        type: 'document',
        id,
        label: null,
        reason: 'relabeled after the move',
      });
    // Both refuse everyone until replaced, the cleared included.
    expect(await reads(tess.credential, 'readable')).toBe(false);
    expect(await reads(tess.credential, 'foreign')).toBe(false);
    // TOP SECRET under the scheme in force too: only someone cleared for it declassifies it.
    await expect(declassify(dan.credential, 'readable')).rejects.toMatchObject({
      code: 'ACCESS_DENIED',
    });
    expect(await declassify(tess.credential, 'readable')).toBeNull();
    // A level the scheme in force does not define, which no clearance dominates, anyone permitted repairs.
    expect(await declassify(dan.credential, 'foreign')).toBeNull();
    expect(await reads(dan.credential, 'foreign')).toBe(true);
  });
});

describe('without the option, and the cost with it', () => {
  it('lints the clearance keys as the server’s only when the deployment enables clearances', () => {
    const document = {
      version: 1,
      statements: [
        {
          effect: 'deny',
          actions: ['documents:read'],
          resources: ['document/*'],
          conditions: { StringEquals: { 'principal.clearanceRank': 'high' } },
        },
      ],
    };
    const codes = (code: string, context: Parameters<typeof lintPolicy>[1]) =>
      lintPolicy(document, context).warnings.filter((warning) => warning.code === code);
    // Without the option the key is the application's (of any type), unknown unless it says it supplies it.
    expect(codes('unknown-context-key', {})).toHaveLength(1);
    expect(codes('type-mismatch', {})).toEqual([]);
    expect(codes('unknown-context-key', { contextKeys: ['principal.clearanceRank'] })).toEqual([]);
    // With it the server sets it, as a number.
    expect(codes('unknown-context-key', { clearances: true })).toEqual([]);
    expect(codes('type-mismatch', { clearances: true })).toHaveLength(1);
  });

  it('reads the scheme once per decision, not again to label the resource', async () => {
    const f = await organizationFixture({ clearances: {} });
    const alice = await administrator(f, 'alice', ['documents:read']);
    // Counts the reads of every transaction from here on.
    const reads = new Map<string, number>();
    const store = f.database as unknown as {
      transaction<T>(run: (tx: IamStore) => Promise<T>): Promise<T>;
    };
    const transaction = store.transaction.bind(f.database);
    store.transaction = (run) =>
      transaction((tx) =>
        run(
          new Proxy(tx, {
            get(target, property) {
              const value = Reflect.get(target, property, target) as unknown;
              if (typeof value !== 'function') return value;
              if (property !== 'find' && property !== 'get') return value.bind(target);
              return (collection: string, ...rest: unknown[]) => {
                const key = `${String(property)} ${collection}`;
                reads.set(key, (reads.get(key) ?? 0) + 1);
                return value.call(target, collection, ...rest);
              };
            },
          }),
        ),
      );
    const decide = async () => {
      reads.clear();
      return (
        await f.iam.authorize({
          ...alice.credential,
          tenantId: f.tenantId,
          action: 'documents:read',
          resource: { type: 'document', id: 'x' },
        })
      ).allowed;
    };
    // No scheme: one lookup per tenant of the ancestry (Acme, the root) and one for labels left over.
    expect(await decide()).toBe(true);
    expect(reads.get('find classificationSchemes')).toBe(2);
    expect(reads.get('find resourceLabels')).toBe(1);
    await f.iam.api.clearances.defineScheme(f.ownerCredential, {
      tenantId: f.tenantId,
      name: 'Acme',
      template: 'us',
    });
    expect(await decide()).toBe(true);
    expect(reads.get('find classificationSchemes')).toBe(2);
  });
});
