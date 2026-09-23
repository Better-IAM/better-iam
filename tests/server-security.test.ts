import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { betterIam, type BetterIam } from '@better-iam/server';
import { sqliteAdapter } from '@better-iam/adapter-sqlite';
import { postgresAdapter } from '@better-iam/adapter-postgres';
import { randomUUID } from 'node:crypto';
import {
  IamError,
  type CredentialInput,
  type IamStore,
  type Identity,
  type PolicyDocument,
  type Session,
  type Tenant,
  type IamPlugin,
} from '@better-iam/core';

const full: PolicyDocument = {
  version: 1,
  statements: [{ effect: 'allow', actions: ['*'], resources: ['*'] }],
};
const read: PolicyDocument = {
  version: 1,
  statements: [{ effect: 'allow', actions: ['documents:read'], resources: ['document/*'] }],
};
let store: IamStore;
let iam: BetterIam;
let user: Identity;
let other: Identity;
let root: CredentialInput;
let credential: CredentialInput;

function isolatedPostgres(connectionString: string): IamStore {
  const database = postgresAdapter({ connectionString });
  const prefix = `security-${randomUUID()}:`;
  const collections = new Set<string>();
  const scoped = (name: string) => {
    collections.add(name);
    return `${prefix}${name}`;
  };
  const wrap = (db: IamStore): IamStore => ({
    get: (collection, id) => db.get(scoped(collection), id),
    find: (collection, filter, options) => db.find(scoped(collection), filter, options),
    insert: (collection, record) => db.insert(scoped(collection), record),
    put: (collection, record) => db.put(scoped(collection), record),
    delete: (collection, id) => db.delete(scoped(collection), id),
    transaction: (fn) => db.transaction((tx) => fn(wrap(tx))),
    migrate: () => db.migrate(),
    close: () => db.close(),
  });
  return {
    ...wrap(database),
    close: async () => {
      try {
        await database.transaction(async (tx) => {
          for (const name of collections)
            for (const record of await tx.find(`${prefix}${name}`))
              await tx.delete(`${prefix}${name}`, record.id);
        });
      } finally {
        await database.close();
      }
    },
  };
}

for (const backend of ['SQLite', 'PostgreSQL'] as const) {
  describe.skipIf(backend === 'PostgreSQL' && !process.env.BETTER_IAM_POSTGRES_URL)(
    `${backend} server security boundaries`,
    () => {
      beforeEach(async () => {
        store =
          backend === 'SQLite'
            ? sqliteAdapter({ filename: ':memory:' })
            : isolatedPostgres(process.env.BETTER_IAM_POSTGRES_URL!);
        iam = betterIam({
          database: store,
          secret: 'security-test-secret-32-characters-minimum',
          baseURL: 'https://iam.example.com',
          authentication: { sendEmail: async () => {} },
          permissions: { actions: ['documents:read', 'documents:write'] },
          onboarding: { mode: 'linked' },
          resolveResource: async (reference) => ({
            ...reference,
            tenantId: reference.id.startsWith('b-') ? 'b' : 'a',
          }),
        });
        await iam.initialize();
        await store.transaction(async (tx) => {
          for (const [tenantId, parentId, type] of [
            ['root', null, 'root'],
            ['a', 'root', 'organization'],
            ['b', 'root', 'organization'],
          ] as const)
            await tx.insert<Tenant>('tenants', {
              id: tenantId,
              tenantId,
              parentId,
              type,
              name: tenantId,
              status: 'active',
              createdAt: Date.now(),
            });
          const administrator = await iam.auth.createIdentity(tx, {
            tenantId: 'root',
            email: 'root@example.com',
            name: 'Root',
            rootAdmin: true,
            owner: true,
            emailVerified: true,
          });
          user = await iam.auth.createIdentity(tx, {
            tenantId: 'a',
            email: 'user@example.com',
            name: 'User',
            emailVerified: true,
          });
          other = await iam.auth.createIdentity(tx, {
            tenantId: 'a',
            email: 'superior@example.com',
            name: 'Superior',
            emailVerified: true,
          });
          root = { token: (await iam.auth.issueSession(tx, administrator, { mfa: true })).token };
          credential = { token: (await iam.auth.issueSession(tx, user)).token };
          await tx.insert('grantAuthorities', {
            id: 'user-authority',
            tenantId: 'a',
            identityId: user.id,
            ceiling: full,
            revoked: false,
          });
          await tx.insert('grantAuthorities', {
            id: 'higher-authority',
            tenantId: 'a',
            identityId: other.id,
            ceiling: full,
            revoked: false,
          });
          await tx.insert('policies', {
            id: 'user-policy',
            tenantId: 'a',
            name: 'User permissions',
            document: full,
            version: 1,
            authorityId: 'user-authority',
          });
          await tx.insert('roles', {
            id: 'user-role',
            tenantId: 'a',
            name: 'User role',
            policyIds: ['user-policy'],
            protected: false,
            authorityId: 'user-authority',
          });
          await tx.insert('bindings', {
            id: 'user-binding',
            tenantId: 'a',
            subjectType: 'identity',
            subjectId: user.id,
            roleId: 'user-role',
            authorityId: 'user-authority',
          });
        });
      });
      afterEach(async () => {
        await store.close();
      });

      it('binds credentials to their tenant and rejects resource tenant injection', async () => {
        expect(
          (
            await iam.authorize({
              ...credential,
              tenantId: 'a',
              action: 'documents:read',
              resource: { type: 'document', id: 'a-doc' },
            })
          ).allowed,
        ).toBe(true);
        expect(
          (
            await iam.authorize({
              ...credential,
              tenantId: 'b',
              action: 'documents:read',
              resource: { type: 'document', id: 'b-doc' },
            })
          ).allowed,
        ).toBe(false);
        const forged = { type: 'document', id: 'b-doc', tenantId: 'b' };
        await expect(
          iam.authorize({
            ...credential,
            tenantId: 'a',
            action: 'documents:read',
            resource: forged,
          }),
        ).rejects.toMatchObject({
          code: expect.stringMatching(/RESOURCE_MISMATCH|INVALID_INPUT/u),
        });
      });

      it('applies root override while retaining resource validation and authenticated sessions', async () => {
        await store.transaction(async (tx) => {
          const realm = (await tx.get<Tenant>('tenants', 'b'))!;
          await tx.put('tenants', { ...realm, boundary: { version: 1, statements: [] } });
        });
        expect(
          (
            await iam.authorize({
              ...root,
              tenantId: 'b',
              action: 'documents:read',
              resource: { type: 'document', id: 'b-doc' },
            })
          ).allowed,
        ).toBe(true);
        await expect(
          iam.authorize({
            ...root,
            tenantId: 'a',
            action: 'documents:read',
            resource: { type: 'document', id: 'b-doc' },
          }),
        ).rejects.toMatchObject({ code: 'RESOURCE_MISMATCH' });
        await expect(
          iam.authorize({
            token: 'forged-token',
            tenantId: 'b',
            action: 'documents:read',
            resource: { type: 'document', id: 'b-doc' },
          }),
        ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
        expect(await store.find('audit', { tenantId: 'b', rootOverride: true })).toHaveLength(1);
      });

      it('enforces explicit deny attachments when lower authorities mutate group membership', async () => {
        await store.transaction(async (tx) => {
          await tx.insert('groups', { id: 'restricted-group', tenantId: 'a', name: 'Restricted' });
          await tx.insert('groupMembers', {
            id: 'member',
            tenantId: 'a',
            groupId: 'restricted-group',
            identityId: user.id,
          });
          await tx.insert('policies', {
            id: 'deny-policy',
            tenantId: 'a',
            name: 'Deny reads',
            version: 1,
            authorityId: 'higher-authority',
            document: {
              version: 1,
              statements: [{ effect: 'deny', actions: ['documents:read'], resources: ['*'] }],
            },
          });
          await tx.insert('roles', {
            id: 'deny-role',
            tenantId: 'a',
            name: 'Deny role',
            policyIds: ['deny-policy'],
            protected: false,
            authorityId: 'higher-authority',
          });
          await tx.insert('bindings', {
            id: 'deny-binding',
            tenantId: 'a',
            subjectType: 'group',
            subjectId: 'restricted-group',
            roleId: 'deny-role',
            authorityId: 'higher-authority',
          });
        });
        const request = {
          ...credential,
          tenantId: 'a',
          action: 'documents:read',
          resource: { type: 'document', id: 'a-doc' },
        };
        expect((await iam.authorize(request)).allowed).toBe(false);
        await expect(
          iam.api.groups.removeMember(credential, {
            tenantId: 'a',
            groupId: 'restricted-group',
            identityId: user.id,
          }),
        ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
        await expect(
          iam.api.groups.delete(credential, { tenantId: 'a', groupId: 'restricted-group' }),
        ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
        await expect(
          iam.api.roles.delete(credential, { tenantId: 'a', roleId: 'deny-role' }),
        ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
        expect((await iam.authorize(request)).allowed).toBe(false);
      });

      it('intersects all delegated ceilings and applies authority revocation immediately', async () => {
        await store.transaction(async (tx) => {
          const authority = (await tx.get('grantAuthorities', 'user-authority'))!;
          await tx.put('grantAuthorities', {
            ...authority,
            ceiling: read,
            parentAuthorityId: 'higher-authority',
          });
        });
        const request = {
          ...credential,
          tenantId: 'a',
          resource: { type: 'document', id: 'a-doc' },
        };
        expect((await iam.authorize({ ...request, action: 'documents:read' })).allowed).toBe(true);
        expect((await iam.authorize({ ...request, action: 'documents:write' })).allowed).toBe(
          false,
        );
        await iam.api.authorities.revoke(root, { tenantId: 'a', authorityId: 'higher-authority' });
        expect((await iam.authorize({ ...request, action: 'documents:read' })).allowed).toBe(false);
      });

      it('retains policy creator ceilings when a higher authority later attaches the policy', async () => {
        await store.transaction(async (tx) => {
          const authority = (await tx.get('grantAuthorities', 'user-authority'))!;
          await tx.put('grantAuthorities', {
            ...authority,
            ceiling: {
              version: 1,
              statements: [
                { effect: 'allow', actions: ['iam:*', 'documents:read'], resources: ['*'] },
              ],
            },
          });
        });
        const policy = await iam.api.policies.create(credential, {
          tenantId: 'a',
          name: 'Delegated policy',
          document: full,
        });
        const role = await iam.api.roles.create(root, {
          tenantId: 'a',
          name: 'Root attachment',
          policyIds: [policy.id],
        });
        await iam.api.bindings.create(root, {
          tenantId: 'a',
          roleId: role.id,
          subjectType: 'identity',
          subjectId: other.id,
        });
        const login = await store.transaction((tx) => iam.auth.issueSession(tx, other));
        const request = {
          token: login.token,
          tenantId: 'a',
          resource: { type: 'document', id: 'a-doc' },
        };
        expect((await iam.authorize({ ...request, action: 'documents:read' })).allowed).toBe(true);
        expect((await iam.authorize({ ...request, action: 'documents:write' })).allowed).toBe(
          false,
        );
        await iam.api.policies.update(credential, {
          tenantId: 'a',
          policyId: policy.id,
          version: 1,
          document: full,
        });
        expect((await iam.authorize({ ...request, action: 'documents:write' })).allowed).toBe(
          false,
        );
        await iam.api.authorities.revoke(root, { tenantId: 'a', authorityId: 'user-authority' });
        expect((await iam.authorize({ ...request, action: 'documents:read' })).allowed).toBe(false);
      });

      it('limits service API keys by the issuing authority and rejects revoked authority credentials', async () => {
        const service = await iam.api.serviceAccounts.create(root, {
          tenantId: 'a',
          name: 'Worker',
        });
        const policy = await iam.api.policies.create(root, {
          tenantId: 'a',
          name: 'Worker permissions',
          document: full,
        });
        const role = await iam.api.roles.create(root, {
          tenantId: 'a',
          name: 'Worker role',
          policyIds: [policy.id],
        });
        await iam.api.bindings.create(root, {
          tenantId: 'a',
          roleId: role.id,
          subjectType: 'identity',
          subjectId: service.id,
        });
        await store.transaction(async (tx) => {
          const authority = (await tx.get('grantAuthorities', 'user-authority'))!;
          await tx.put('grantAuthorities', {
            ...authority,
            ceiling: {
              version: 1,
              statements: [
                {
                  effect: 'allow',
                  actions: ['iam:credentials:create', 'documents:read'],
                  resources: ['*'],
                },
              ],
            },
          });
        });
        const key = await iam.api.credentials.create(credential, {
          tenantId: 'a',
          identityId: service.id,
        });
        const request = {
          token: key.token,
          tenantId: 'a',
          resource: { type: 'document', id: 'a-doc' },
        };
        expect((await iam.authorize({ ...request, action: 'documents:read' })).allowed).toBe(true);
        expect((await iam.authorize({ ...request, action: 'documents:write' })).allowed).toBe(
          false,
        );
        await iam.api.authorities.revoke(root, { tenantId: 'a', authorityId: 'user-authority' });
        await expect(iam.authenticate({ token: key.token })).rejects.toMatchObject({
          code: 'UNAUTHENTICATED',
        });
      });

      it('uses role-specific source permissions and current trust for temporary credentials', async () => {
        const policy = await iam.api.policies.create(root, {
          tenantId: 'b',
          name: 'Reader',
          document: read,
        });
        const role = await iam.api.roles.create(root, {
          tenantId: 'b',
          name: 'Reader',
          policyIds: [policy.id],
        });
        const trust = await iam.api.trust.create(root, {
          tenantId: 'b',
          sourceTenantId: 'a',
          sourceIdentityId: user.id,
          roleId: role.id,
          requireMfa: false,
          externalId: 'external-secret',
        });
        await store.transaction(async (tx) => {
          const current = (await tx.get('policies', 'user-policy'))!;
          await tx.put('policies', {
            ...current,
            document: {
              version: 1,
              statements: [
                { effect: 'allow', actions: ['iam:roles:assume'], resources: [`iam/${role.id}`] },
              ],
            },
          });
        });
        await expect(
          iam.api.roles.assume(credential, {
            tenantId: 'b',
            trustId: trust.id,
            externalId: 'wrong',
          }),
        ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
        const assumed = await iam.api.roles.assume(credential, {
          tenantId: 'b',
          trustId: trust.id,
          externalId: 'external-secret',
        });
        expect(
          (
            await iam.authorize({
              token: assumed.token,
              tenantId: 'b',
              action: 'documents:read',
              resource: { type: 'document', id: 'b-doc' },
            })
          ).allowed,
        ).toBe(true);
        expect(
          (
            await iam.authorize({
              token: assumed.token,
              tenantId: 'b',
              action: 'documents:write',
              resource: { type: 'document', id: 'b-doc' },
            })
          ).allowed,
        ).toBe(false);
        await iam.api.trust.revoke(root, { tenantId: 'b', trustId: trust.id });
        await expect(iam.authenticate({ token: assumed.token })).rejects.toMatchObject({
          code: 'UNAUTHENTICATED',
        });
      });

      it('requires user proofs for linking and stores each pair once regardless of proof order', async () => {
        const target = await store.transaction(async (tx) => {
          const identity = await iam.auth.createIdentity(tx, {
            tenantId: 'b',
            email: 'user@example.com',
            name: 'Other tenant user',
            emailVerified: true,
          });
          return iam.auth.issueSession(tx, identity);
        });
        const targetCredential = { token: target.token };
        const link = await iam.api.links.create(credential, { targetCredential });
        await expect(
          iam.api.links.create(targetCredential, { targetCredential: credential }),
        ).rejects.toMatchObject({ code: 'CONFLICT' });
        const switched = await iam.api.links.switch(credential, {
          linkId: link.id,
          targetCredential,
        });
        expect((await iam.authenticate({ token: switched.token })).identity.tenantId).toBe('b');
        await iam.api.links.revoke(credential, { linkId: link.id });
        await expect(
          iam.api.links.switch(credential, { linkId: link.id, targetCredential }),
        ).rejects.toMatchObject({ code: 'INVALID_LINK' });
        const relinked = await iam.api.links.create(targetCredential, {
          targetCredential: credential,
        });
        expect(relinked.id).toBe(link.id);
        await expect(iam.api.links.create(root, { targetCredential })).rejects.toMatchObject({
          code: 'INVALID_LINK',
        });
        const service = await iam.api.serviceAccounts.create(root, {
          tenantId: 'a',
          name: 'Service',
        });
        const key = await iam.api.credentials.create(root, {
          tenantId: 'a',
          identityId: service.id,
        });
        await expect(
          iam.api.links.create({ token: key.token }, { targetCredential }),
        ).rejects.toMatchObject({ code: 'INVALID_LINK' });
      });

      it('does not let HTTP identity fields bypass the verified principal or origin requirements', async () => {
        const call = (origin: string) =>
          iam.handler(
            new Request('https://iam.example.com/api/iam/authorize', {
              method: 'POST',
              headers: {
                'content-type': 'application/json',
                'x-better-iam': '1',
                authorization: `Bearer ${credential.token}`,
                origin,
              },
              body: JSON.stringify({
                tenantId: 'b',
                action: 'documents:read',
                resource: { type: 'document', id: 'b-doc' },
                actor: { rootAdmin: true, tenantId: 'root' },
              }),
            }),
          );
        const response = await call('https://iam.example.com');
        expect(response.status).toBe(200);
        expect((await response.json()).data.allowed).toBe(false);
        expect((await call('https://attacker.example')).status).toBe(403);
      });

      it('uses the same validated, transactional authorization for direct and HTTP plugin calls', async () => {
        const plugin: IamPlugin = {
          id: 'notes',
          actions: ['notes:write'],
          endpoints: [
            {
              method: 'POST',
              path: '/write',
              action: 'notes:write',
              validate(value) {
                if (
                  !value ||
                  typeof value !== 'object' ||
                  Object.keys(value).some((key) => !['tenantId', 'value'].includes(key)) ||
                  typeof (value as { value?: unknown }).value !== 'string'
                )
                  throw new IamError('INVALID_INPUT', 'Unexpected plugin input');
                return value as Record<string, unknown>;
              },
              handler: async (context, input) =>
                context.store.insert('pluginNotes', {
                  id: String(input.value),
                  tenantId: context.tenantId,
                  actorId: context.principal.identity.id,
                }),
            },
          ],
        };
        const pluginIam = betterIam({
          database: store,
          secret: 'security-test-secret-32-characters-minimum',
          baseURL: 'https://iam.example.com',
          authentication: { sendEmail: async () => {} },
          plugins: [plugin],
        });
        const direct = await pluginIam.callPlugin(credential, {
          pluginId: 'notes',
          path: 'write',
          tenantId: 'a',
          input: { value: 'direct' },
        });
        expect(direct).toMatchObject({ id: 'direct', actorId: user.id, tenantId: 'a' });
        await expect(
          pluginIam.callPlugin(credential, {
            pluginId: 'notes',
            path: 'write',
            tenantId: 'b',
            input: { value: 'denied' },
          }),
        ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
        await expect(
          pluginIam.callPlugin(credential, {
            pluginId: 'notes',
            path: 'write',
            tenantId: 'a',
            input: { tenantId: 'b', value: 'forged' },
          }),
        ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
        const response = await pluginIam.handler(
          new Request('https://iam.example.com/api/iam/plugins/notes/write', {
            method: 'POST',
            headers: {
              origin: 'https://iam.example.com',
              authorization: `Bearer ${credential.token}`,
              'content-type': 'application/json',
              'x-better-iam': '1',
            },
            body: JSON.stringify({ tenantId: 'a', value: 'http' }),
          }),
        );
        expect(response.status).toBe(200);
        expect((await response.json()).data).toMatchObject({
          id: 'http',
          actorId: user.id,
          tenantId: 'a',
        });
        expect(await store.find('pluginNotes')).toHaveLength(2);
        expect(() =>
          betterIam({
            database: store,
            secret: 'security-test-secret-32-characters-minimum',
            baseURL: 'https://iam.example.com',
            authentication: { sendEmail: async () => {} },
            plugins: [
              { ...plugin, endpoints: [{ ...plugin.endpoints![0]!, method: 'GET' as 'POST' }] },
            ],
          }),
        ).toThrow(/POST/u);
      });

      it('rejects a session revoked after initial credential lookup but before authorization', async () => {
        const current = await iam.authenticate(credential);
        await store.transaction((tx) => tx.delete('sessions', current.session.id));
        await expect(
          iam.authorize({
            ...credential,
            tenantId: 'a',
            action: 'documents:read',
            resource: { type: 'document', id: 'a-doc' },
          }),
        ).rejects.toMatchObject({ code: 'UNAUTHENTICATED' });
        expect(await store.get<Session>('sessions', current.session.id)).toBeUndefined();
      });

      it('reparents tenants through validated operations and requires destination authority', async () => {
        await store.transaction(async (tx) => {
          await tx.insert<Tenant>('tenants', {
            id: 'project-b',
            tenantId: 'project-b',
            parentId: 'b',
            type: 'project',
            name: 'Project B',
            status: 'active',
            createdAt: Date.now(),
          });
        });
        expect(
          (await iam.api.tenants.reparent(root, { tenantId: 'project-b', parentId: 'a' })).parentId,
        ).toBe('a');
        expect(
          (await iam.api.tenants.update(root, { tenantId: 'project-b', name: 'Renamed' })).name,
        ).toBe('Renamed');
        await expect(
          iam.api.tenants.reparent(root, { tenantId: 'project-b', parentId: 'root' }),
        ).rejects.toMatchObject({ code: 'INVALID_HIERARCHY' });
        await expect(
          iam.api.tenants.reparent(root, { tenantId: 'root', parentId: 'a' }),
        ).rejects.toMatchObject({ code: 'INVALID_TRANSITION' });
        await expect(
          iam.api.tenants.reparent(root, { tenantId: 'project-b', parentId: 'a' }),
        ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
        await expect(
          iam.api.tenants.reparent(credential, { tenantId: 'project-b', parentId: 'a' }),
        ).rejects.toMatchObject({ code: 'ACCESS_DENIED' });
      });

      it('purges soft-deleted tenants after the retention window and keeps audit records', async () => {
        await store.transaction(async (tx) => {
          await tx.insert<Tenant>('tenants', {
            id: 'project-b',
            tenantId: 'project-b',
            parentId: 'b',
            type: 'project',
            name: 'Project B',
            status: 'active',
            createdAt: Date.now(),
          });
        });
        const deleted = await iam.api.tenants.setStatus(root, { tenantId: 'b', status: 'deleted' });
        expect(deleted.status).toBe('deleted');
        expect(await iam.purgeDeleted()).toEqual({
          purgedTenants: [],
          deletedRecords: 0,
          expiredBindings: 0,
          expiredRequests: 0,
          expiredIdentities: 0,
          expiredActivations: 0,
          expiredMemberships: 0,
          expiredAssignments: 0,
        });
        const purged = await iam.purgeDeleted({ retentionMs: 0 });
        expect(purged.purgedTenants).toEqual(['b', 'project-b']);
        expect(purged.deletedRecords).toBeGreaterThan(0);
        expect(await store.get('tenants', 'b')).toBeUndefined();
        expect(await store.get('tenants', 'project-b')).toBeUndefined();
        expect(await store.get('tenants', 'a')).toBeDefined();
        expect(
          (await store.find('audit', { tenantId: 'b' })).some(
            (event) => event.action === 'tenants:purge',
          ),
        ).toBe(true);
        expect(await iam.purgeDeleted({ retentionMs: 0 })).toEqual({
          purgedTenants: [],
          deletedRecords: 0,
          expiredBindings: 0,
          expiredRequests: 0,
          expiredIdentities: 0,
          expiredActivations: 0,
          expiredMemberships: 0,
          expiredAssignments: 0,
        });
      });
    },
  );
}
