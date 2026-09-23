import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runCli } from '@better-iam/cli';
import { closeFixtures, organizationFixture } from './support/organization.js';

afterEach(closeFixtures);

const work = resolve('work');
const created: string[] = [];
afterEach(async () => {
  for (const folder of created.splice(0)) {
    if (!resolve(folder).startsWith(work + sep)) throw new Error('Unsafe test cleanup');
    await rm(folder, { recursive: true, force: true, maxRetries: 10, retryDelay: 50 }).catch(
      () => undefined,
    );
  }
});

type Change = { kind: string; name: string; action: string; fields?: string[] };
const byKind = (plan: { changes: Change[] }, kind: string) =>
  plan.changes.filter((change) => change.kind === kind);

async function setup() {
  const f = await organizationFixture();
  const { tenantId } = f;
  const owner = f.ownerCredential;
  const reader = await f.iam.api.roles.create(owner, {
    tenantId,
    name: 'Reader',
    permissions: ['documents:read'],
  });
  return { f, tenantId, owner, reader };
}

describe('configuration sync: durations', () => {
  it('treats a null package maxDurationMs as no cap and converges', async () => {
    const { f, tenantId, owner, reader } = await setup();
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Kit',
      roleIds: [reader.id],
    });
    const capped = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Capped',
      roleIds: [reader.id],
      maxDurationMs: 30 * 86400000,
    });
    const config = {
      version: 1,
      packages: [
        { name: 'Capped', roles: ['Reader'], maxDurationMs: null },
        { name: 'Fresh', roles: ['Reader'], maxDurationMs: null },
        { name: 'Kit', roles: ['Reader'], maxDurationMs: null },
      ],
    };
    // An uncapped package is unchanged; a capped one loses its cap; a new one is created uncapped.
    const plan = await f.iam.api.config.plan(owner, { tenantId, config });
    expect(plan.summary).toEqual({ create: 1, update: 1, delete: 0, unchanged: 1 });
    expect(byKind(plan, 'package')).toEqual([
      expect.objectContaining({
        name: 'Capped',
        action: 'update',
        fields: ['maxDurationMs'],
      }),
      expect.objectContaining({ name: 'Fresh', action: 'create' }),
      { kind: 'package', name: 'Kit', action: 'unchanged' },
    ]);
    f.advance(1000);
    const applied = await f.iam.api.config.apply(owner, { tenantId, config });
    expect(applied.summary).toEqual(plan.summary);
    const packages = await f.iam.api.packages.list(owner, { tenantId });
    expect(packages.map((pkg) => pkg.name)).toEqual(['Capped', 'Fresh', 'Kit']);
    for (const pkg of packages) expect(pkg.maxDurationMs).toBeUndefined();
    // The unchanged package was not rewritten.
    expect((await f.iam.api.packages.get(owner, { tenantId, packageId: kit.id })).updatedAt).toBe(
      kit.updatedAt,
    );
    expect(
      (await f.iam.api.packages.get(owner, { tenantId, packageId: capped.id })).maxDurationMs,
    ).toBeUndefined();
    // Repeated applies are no-ops.
    for (let round = 0; round < 2; round++) {
      f.advance(1000);
      const again = await f.iam.api.config.apply(owner, { tenantId, config });
      expect(again.summary).toEqual({ create: 0, update: 0, delete: 0, unchanged: 3 });
    }
    const trail = await f.iam.api.audit.list(owner, { tenantId, action: 'config:apply' });
    expect(trail).toHaveLength(3);
    // The first apply changed two packages; the repeats changed nothing.
    expect(
      trail.map((event) => (event.metadata?.changed as string[] | undefined)?.length).sort(),
    ).toEqual([0, 0, 2]);
    expect((await f.iam.api.config.plan(owner, { tenantId, config })).summary).toEqual({
      create: 0,
      update: 0,
      delete: 0,
      unchanged: 3,
    });
  });

  it('rejects a string or out-of-range package maxDurationMs at plan time', async () => {
    const { f, tenantId, owner, reader } = await setup();
    await f.iam.api.packages.create(owner, { tenantId, name: 'Kit', roleIds: [reader.id] });
    for (const maxDurationMs of [
      '2592000000',
      59_999,
      0,
      -1,
      1.5,
      315360000001,
      Number.MAX_SAFE_INTEGER + 2,
      true,
      {},
    ]) {
      for (const name of ['Kit', 'New']) {
        const config = { version: 1, packages: [{ name, roles: ['Reader'], maxDurationMs }] };
        await expect(
          f.iam.api.config.plan(owner, { tenantId, config }),
          `plan ${name} maxDurationMs ${JSON.stringify(maxDurationMs)}`,
        ).rejects.toMatchObject({
          code: 'INVALID_INPUT',
          message: expect.stringContaining('maxDurationMs'),
        });
        await expect(
          f.iam.api.config.apply(owner, { tenantId, config }),
          `apply ${name} maxDurationMs ${JSON.stringify(maxDurationMs)}`,
        ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
      }
    }
    // The bounds themselves are accepted.
    for (const maxDurationMs of [60_000, 315360000000])
      expect(
        (
          await f.iam.api.config.plan(owner, {
            tenantId,
            config: { version: 1, packages: [{ name: 'Kit', roles: ['Reader'], maxDurationMs }] },
          })
        ).summary.update,
      ).toBe(1);
    const packages = await f.iam.api.packages.list(owner, { tenantId });
    expect(packages.map((pkg) => [pkg.name, pkg.maxDurationMs])).toEqual([['Kit', undefined]]);
  });

  it('treats a null binding maxActivationMs as no cap and rejects bad values at plan time', async () => {
    const { f, tenantId, owner, reader } = await setup();
    await f.iam.api.groups.create(owner, { tenantId, name: 'Engineering' });
    const ops = await f.iam.api.groups.create(owner, { tenantId, name: 'Ops' });
    await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: reader.id,
      subjectType: 'group',
      subjectId: ops.id,
      eligible: true,
      maxActivationMs: 600_000,
    });
    const config = {
      version: 1,
      bindings: [
        { group: 'Engineering', role: 'Reader', eligible: true, maxActivationMs: null },
        { group: 'Ops', role: 'Reader', eligible: true, maxActivationMs: null },
      ],
    };
    const plan = await f.iam.api.config.plan(owner, { tenantId, config });
    expect(plan.summary).toEqual({ create: 1, update: 1, delete: 0, unchanged: 0 });
    expect(byKind(plan, 'binding')).toEqual([
      expect.objectContaining({ name: 'Engineering -> Reader', action: 'create' }),
      expect.objectContaining({
        name: 'Ops -> Reader',
        action: 'update',
        fields: ['maxActivationMs'],
      }),
    ]);
    await f.iam.api.config.apply(owner, { tenantId, config });
    const stored = await f.database.find<{
      id: string;
      eligible?: boolean;
      maxActivationMs?: number;
    }>('bindings', { tenantId, subjectType: 'group' });
    expect(stored).toHaveLength(2);
    for (const binding of stored) {
      expect(binding.eligible).toBe(true);
      expect(binding.maxActivationMs).toBeUndefined();
    }
    // Repeated applies are no-ops: the bindings are not replaced.
    for (let round = 0; round < 2; round++) {
      const again = await f.iam.api.config.apply(owner, { tenantId, config });
      expect(again.summary).toEqual({ create: 0, update: 0, delete: 0, unchanged: 2 });
    }
    expect(
      (await f.database.find<{ id: string }>('bindings', { tenantId, subjectType: 'group' }))
        .map((binding) => binding.id)
        .sort(),
    ).toEqual(stored.map((binding) => binding.id).sort());
    // Strings and out-of-range values are refused before anything is planned.
    for (const maxActivationMs of ['600000', 59_999, 0, 1.5, 7 * 86400000 + 1, false, []]) {
      const bad = {
        version: 1,
        bindings: [{ group: 'Ops', role: 'Reader', eligible: true, maxActivationMs }],
      };
      await expect(
        f.iam.api.config.plan(owner, { tenantId, config: bad }),
        `plan maxActivationMs ${JSON.stringify(maxActivationMs)}`,
      ).rejects.toMatchObject({
        code: 'INVALID_INPUT',
        message: expect.stringContaining('maxActivationMs'),
      });
      await expect(
        f.iam.api.config.apply(owner, { tenantId, config: bad }),
        `apply maxActivationMs ${JSON.stringify(maxActivationMs)}`,
      ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    }
    expect(
      (
        await f.iam.api.config.plan(owner, {
          tenantId,
          config: {
            version: 1,
            bindings: [
              { group: 'Ops', role: 'Reader', eligible: true, maxActivationMs: 7 * 86400000 },
            ],
          },
        })
      ).summary.update,
    ).toBe(1);
  });
});

describe('configuration sync: package names', () => {
  it('matches package names regardless of case and renames in place', async () => {
    const { f, tenantId, owner, reader } = await setup();
    const alice = await f.member('alice');
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Engineer Kit',
      roleIds: [reader.id],
    });
    await f.iam.api.packages.assign(owner, { tenantId, packageId: kit.id, identityId: alice.id });
    const config = { version: 1, packages: [{ name: 'Engineer kit', roles: ['Reader'] }] };
    for (const prune of [false, true]) {
      const plan = await f.iam.api.config.plan(owner, { tenantId, config, prune });
      expect(plan.summary).toEqual({ create: 0, update: 1, delete: 0, unchanged: 0 });
      expect(plan.changes).toEqual([
        expect.objectContaining({
          kind: 'package',
          name: 'Engineer kit',
          action: 'update',
          fields: ['name'],
          before: expect.objectContaining({ name: 'Engineer Kit' }),
          after: expect.objectContaining({ name: 'Engineer kit' }),
        }),
      ]);
    }
    // With prune, a create+delete would fail on the held package; a rename keeps it and its holder.
    const applied = await f.iam.api.config.apply(owner, { tenantId, config, prune: true });
    expect(applied.summary).toEqual({ create: 0, update: 1, delete: 0, unchanged: 0 });
    expect(
      (await f.iam.api.packages.list(owner, { tenantId })).map((pkg) => [
        pkg.id,
        pkg.name,
        pkg.assignments,
      ]),
    ).toEqual([[kit.id, 'Engineer kit', 1]]);
    expect(
      (await f.iam.api.packages.listAssignments(owner, { tenantId, packageId: kit.id })).map(
        (assignment) => [assignment.identityId, assignment.packageName],
      ),
    ).toEqual([[alice.id, 'Engineer kit']]);
    expect((await f.iam.api.config.export(owner, { tenantId })).packages).toEqual([
      { name: 'Engineer kit', roles: ['Reader'], groups: [] },
    ]);
    expect((await f.iam.api.config.plan(owner, { tenantId, config, prune: true })).summary).toEqual(
      { create: 0, update: 0, delete: 0, unchanged: 1 },
    );
  });

  it('renames on a case-only difference without prune instead of creating a second package', async () => {
    const { f, tenantId, owner, reader } = await setup();
    const kit = await f.iam.api.packages.create(owner, {
      tenantId,
      name: 'Engineer Kit',
      roleIds: [reader.id],
    });
    const config = { version: 1, packages: [{ name: 'Engineer kit', roles: ['Reader'] }] };
    const applied = await f.iam.api.config.apply(owner, { tenantId, config });
    expect(applied.summary).toEqual({ create: 0, update: 1, delete: 0, unchanged: 0 });
    expect(byKind(applied, 'package')).toEqual([
      expect.objectContaining({ name: 'Engineer kit', action: 'update', fields: ['name'] }),
    ]);
    expect(
      (await f.iam.api.packages.list(owner, { tenantId })).map((pkg) => [pkg.id, pkg.name]),
    ).toEqual([[kit.id, 'Engineer kit']]);
    // The renamed package still owns its name: a direct create with the old casing conflicts.
    await expect(
      f.iam.api.packages.create(owner, { tenantId, name: 'Engineer Kit', roleIds: [reader.id] }),
    ).rejects.toMatchObject({ code: 'CONFLICT' });
    expect((await f.iam.api.config.plan(owner, { tenantId, config })).summary).toEqual({
      create: 0,
      update: 0,
      delete: 0,
      unchanged: 1,
    });
  });

  it('rejects package names that differ only by case as duplicates at plan time', async () => {
    const { f, tenantId, owner, reader } = await setup();
    await f.iam.api.packages.create(owner, { tenantId, name: 'Kit', roleIds: [reader.id] });
    const config = {
      version: 1,
      packages: [
        { name: 'Vendor', roles: ['Reader'] },
        { name: 'vendor', roles: ['Reader'] },
      ],
    };
    await expect(f.iam.api.config.plan(owner, { tenantId, config })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
      message: expect.stringMatching(/duplicate package/i),
    });
    await expect(
      f.iam.api.config.plan(owner, { tenantId, config, prune: true }),
    ).rejects.toMatchObject({ code: 'INVALID_INPUT' });
    await expect(f.iam.api.config.apply(owner, { tenantId, config })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
    expect((await f.iam.api.packages.list(owner, { tenantId })).map((pkg) => pkg.name)).toEqual([
      'Kit',
    ]);
  });
});

describe('bindings.update managerApproval', () => {
  it('accepts managerApproval: false alone and clears it', async () => {
    const f = await organizationFixture();
    const { tenantId } = f;
    const owner = f.ownerCredential;
    const writer = await f.iam.api.roles.create(owner, {
      tenantId,
      name: 'Writer',
      permissions: ['documents:write'],
    });
    const alice = await f.member('alice');
    const binding = await f.iam.api.bindings.create(owner, {
      tenantId,
      roleId: writer.id,
      subjectType: 'identity',
      subjectId: alice.id,
      eligible: true,
      requireApproval: true,
      managerApproval: true,
    });
    expect(binding).toMatchObject({ eligible: true, requireApproval: true, managerApproval: true });
    const updated = await f.iam.api.bindings.update(owner, {
      tenantId,
      bindingId: binding.id,
      managerApproval: false,
    });
    expect(updated.managerApproval).toBeUndefined();
    expect(updated).toMatchObject({ id: binding.id, eligible: true, requireApproval: true });
    const stored = await f.database.get<{
      eligible?: boolean;
      requireApproval?: boolean;
      managerApproval?: boolean;
    }>('bindings', binding.id);
    expect(stored).toMatchObject({ eligible: true, requireApproval: true });
    expect(stored?.managerApproval).toBeUndefined();
    // And alone in the other direction.
    const restored = await f.iam.api.bindings.update(owner, {
      tenantId,
      bindingId: binding.id,
      managerApproval: true,
    });
    expect(restored).toMatchObject({ requireApproval: true, managerApproval: true });
  });
});

describe('remind CLI --within-days', () => {
  it('rejects values outside 1..365 with INVALID_ARGUMENT', async () => {
    await mkdir(work, { recursive: true });
    const folder = await mkdtemp(join(work, 'regress-sync-cli-'));
    created.push(folder);
    const config = join(folder, 'better-iam.config.mjs');
    const filename = join(folder, 'iam.db');
    // A mail transport is configured, so an in-range value runs and an out-of-range one can only fail on the flag.
    await writeFile(
      config,
      `import { sqliteAdapter } from '@better-iam/adapter-sqlite';\nexport default () => ({database:sqliteAdapter({filename:${JSON.stringify(filename)}}),secret:'regress-sync-cli-secret-with-32-chars!!',baseURL:'http://localhost:3000',authentication:{sendEmail: async () => {}},permissions:{actions:['documents:read']}});\n`,
    );
    const output: string[] = [];
    const io = { out: (message: string) => output.push(message), env: {} as NodeJS.ProcessEnv };
    await runCli(['migrate', '--config', config], io);
    for (const value of ['0', '400', '366', '-1']) {
      const before = output.length;
      await expect(
        runCli(['remind', '--config', config, '--within-days', value], io),
        `--within-days ${value}`,
      ).rejects.toMatchObject({
        code: 'INVALID_ARGUMENT',
        message: expect.stringMatching(/--within-days.*\b1\b.*\b365\b/),
      });
      expect(output.length).toBe(before);
    }
    // The bounds themselves run.
    for (const value of ['1', '365']) {
      await runCli(['remind', '--config', config, '--within-days', value], io);
      expect(() => JSON.parse(output.at(-1)!)).not.toThrow();
    }
  });
});
