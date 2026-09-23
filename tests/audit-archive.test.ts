import { mkdir, mkdtemp, readdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join, resolve, sep } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import { runCli } from '@better-iam/cli';
import { verifyAuditChain, type AuditChainHead, type AuditEvent } from '@better-iam/core';
import { createJsonlAuditArchive, type AuditArchiveBatch } from '@better-iam/server';
import { closeFixtures, organizationFixture } from './support/organization.js';

const day = 86_400_000;
const work = resolve('work');
const created: string[] = [];
afterEach(async () => {
  await closeFixtures();
  for (const folder of created.splice(0)) {
    if (!resolve(folder).startsWith(work + sep)) throw new Error('Unsafe test cleanup');
    await rm(folder, { recursive: true, force: true, maxRetries: 4, retryDelay: 50 }).catch(
      () => undefined,
    );
  }
});
async function directory() {
  await mkdir(work, { recursive: true });
  const folder = await mkdtemp(join(work, 'audit-archive-test-'));
  created.push(folder);
  return folder;
}
/** Every archived event of one tenant, read back from the JSON Lines files in name order. */
async function archivedEvents(root: string, tenantId: string): Promise<AuditEvent[]> {
  const folder = join(root, tenantId);
  const files = (await readdir(folder)).filter((name) => name.endsWith('.jsonl')).sort();
  const bySequence = new Map<number, AuditEvent>();
  for (const name of files)
    for (const line of (await readFile(join(folder, name), 'utf8')).trim().split('\n')) {
      const event = JSON.parse(line) as AuditEvent;
      bySequence.set(event.sequence!, event);
    }
  return [...bySequence.values()].sort((a, b) => a.sequence! - b.sequence!);
}

describe('audit archive', () => {
  it('archives every chain verified and in order, incrementally, into JSON Lines files', async () => {
    const root = await directory();
    const f = await organizationFixture({
      auditArchive: createJsonlAuditArchive({ directory: root }),
    });
    const heads = await f.database.find<AuditChainHead>('auditChains');
    const first = await f.iam.archiveAudit();
    expect(first).toMatchObject({ failed: [], gaps: [], truncated: false });
    for (const head of heads) expect(first.archived[head.id]).toBe(head.sequence);

    // Only the new events go out on the next run, and the files add up to the whole chain.
    await f.member('alice');
    const second = await f.iam.archiveAudit();
    const head = (await f.database.get<AuditChainHead>('auditChains', f.tenantId))!;
    const before = heads.find((entry) => entry.id === f.tenantId)!;
    expect(second.archived[f.tenantId]).toBe(head.sequence - before.sequence);
    const events = await archivedEvents(root, f.tenantId);
    expect(await verifyAuditChain(events, { head })).toMatchObject({
      valid: true,
      first: 1,
      last: head.sequence,
    });
    expect(await f.iam.archiveAudit()).toMatchObject({ archived: {}, batches: 0 });
  });

  it('keeps events the archive does not hold yet when pruning', async () => {
    const written: AuditArchiveBatch[] = [];
    let failing = false;
    const f = await organizationFixture({
      auditArchive: {
        batchSize: 3,
        write: async (batch) => {
          if (failing) throw new Error('bucket unavailable');
          written.push(batch);
        },
      },
    });
    // Nothing archived yet: pruning everything older than now deletes nothing.
    expect(await f.iam.pruneAudit({ tenantId: f.tenantId, retentionMs: 0 })).toEqual({
      deleted: 0,
      heldForArchive: true,
    });
    // A failing sink leaves the cursor where it was.
    failing = true;
    const failed = await f.iam.archiveAudit({ tenantId: f.tenantId });
    expect(failed.failed).toEqual([
      { tenantId: f.tenantId, code: 'ARCHIVE_WRITE_FAILED', message: 'bucket unavailable' },
    ]);
    expect(await f.iam.pruneAudit({ tenantId: f.tenantId, retentionMs: 0 })).toMatchObject({
      deleted: 0,
    });
    failing = false;
    // Batches of three, chained to each other.
    const archived = await f.iam.archiveAudit({ tenantId: f.tenantId });
    expect(archived.failed).toEqual([]);
    for (const [index, batch] of written.entries()) {
      expect(batch.events.length).toBeLessThanOrEqual(3);
      if (index) expect(batch.previousHash).toBe(written[index - 1]!.lastHash);
      else expect(batch.fromSequence).toBe(1);
    }
    const through = written.at(-1)!.toSequence;
    // Now pruning removes exactly what the archive holds.
    expect(await f.iam.pruneAudit({ tenantId: f.tenantId, retentionMs: 0 })).toMatchObject({
      deleted: through,
      prunedThroughSequence: through,
    });
    // The prune checkpoint event itself is new, so it is archived next.
    expect((await f.iam.archiveAudit({ tenantId: f.tenantId })).archived[f.tenantId]).toBe(1);
    expect(written.at(-1)!.events[0]!.action).toBe('audit:prune');
  });

  it('refuses to archive a chain that does not verify, and reports gaps it cannot fill', async () => {
    const written: AuditArchiveBatch[] = [];
    const f = await organizationFixture({
      auditArchive: { write: async (batch) => void written.push(batch) },
    });
    const [victim] = await f.database.find<AuditEvent>('audit', {
      tenantId: f.tenantId,
      sequence: 2,
    });
    await f.database.transaction((tx) => tx.put('audit', { ...victim!, action: 'tampered' }));
    const result = await f.iam.archiveAudit({ tenantId: f.tenantId });
    expect(result.failed).toEqual([
      expect.objectContaining({ tenantId: f.tenantId, code: 'AUDIT_CHAIN_BROKEN' }),
    ]);
    expect(written).toEqual([]);
    expect(await f.iam.pruneAudit({ tenantId: f.tenantId, retentionMs: 0 })).toMatchObject({
      deleted: 0,
    });

    // Events deleted outside the archive show up as a gap; the rest is archived from there.
    const g = await organizationFixture({
      auditArchive: { write: async (batch) => void written.push(batch) },
    });
    await g.database.transaction(async (tx) => {
      for (const sequence of [1, 2])
        for (const event of await tx.find<AuditEvent>('audit', { tenantId: g.tenantId, sequence }))
          await tx.delete('audit', event.id);
    });
    const resumed = await g.iam.archiveAudit({ tenantId: g.tenantId });
    expect(resumed.failed).toEqual([]);
    expect(resumed.gaps).toEqual([{ tenantId: g.tenantId, fromSequence: 1, toSequence: 2 }]);
  });

  it('lets one run at a time archive a tenant, so overlapping runs never lose events', async () => {
    const root = await directory();
    const files = createJsonlAuditArchive({ directory: root });
    let release!: () => void;
    let entered!: () => void;
    const blocked = new Promise<void>((resolve) => (release = resolve));
    const started = new Promise<void>((resolve) => (entered = resolve));
    let first = true;
    const f = await organizationFixture({
      auditArchive: {
        batchSize: 2,
        write: async (batch) => {
          if (first) {
            first = false;
            entered();
            await blocked;
          }
          await files.write(batch);
        },
      },
    });
    const slow = f.iam.archiveAudit({ tenantId: f.tenantId });
    await started;
    // New events arrive while the first run is stuck in its sink; a second run must not race it.
    await f.member('alice');
    const second = await f.iam.archiveAudit({ tenantId: f.tenantId });
    expect(second).toMatchObject({ archived: {}, busy: [f.tenantId] });
    release();
    expect((await slow).failed).toEqual([]);
    await f.iam.archiveAudit({ tenantId: f.tenantId });
    const head = (await f.database.get<AuditChainHead>('auditChains', f.tenantId))!;
    // Everything pruned is in the archive: the files hold the whole chain.
    const pruned = await f.iam.pruneAudit({ tenantId: f.tenantId, retentionMs: 0 });
    expect(pruned.prunedThroughSequence).toBe(head.sequence);
    expect(await verifyAuditChain(await archivedEvents(root, f.tenantId), { head })).toMatchObject({
      valid: true,
      first: 1,
      last: head.sequence,
    });
  });

  it('never overwrites an archived file with different events', async () => {
    const root = await directory();
    const files = createJsonlAuditArchive({ directory: root });
    const event = (sequence: number, action: string) =>
      ({ id: `e${sequence}`, tenantId: 't', sequence, action }) as unknown as AuditEvent;
    const batch = (action: string): AuditArchiveBatch => ({
      tenantId: 't',
      fromSequence: 1,
      toSequence: 2,
      previousHash: '0'.repeat(64),
      lastHash: 'x',
      events: [event(1, action), event(2, action)],
    });
    await files.write(batch('original'));
    await files.write(batch('original'));
    await expect(files.write(batch('forged'))).rejects.toMatchObject({ code: 'ARCHIVE_CONFLICT' });
    const [stored] = await archivedEvents(root, 't');
    expect(stored!.action).toBe('original');
    // No temporary files are left behind.
    expect((await readdir(join(root, 't'))).filter((name) => name.endsWith('.tmp'))).toEqual([]);
    await expect(files.write({ ...batch('x'), tenantId: '../escape' })).rejects.toMatchObject({
      code: 'INVALID_INPUT',
    });
  });

  it('keeps unarchived events from a process that does not configure the archive', async () => {
    const written: AuditArchiveBatch[] = [];
    const f = await organizationFixture({
      auditArchive: { batchSize: 2, write: async (batch) => void written.push(batch) },
    });
    await f.iam.archiveAudit({ tenantId: f.tenantId, limit: 2 });
    // Another process, say a retention worker, runs without the auditArchive option.
    const { betterIam } = await import('@better-iam/server');
    const worker = betterIam({
      database: f.database,
      secret: 'organization-fixture-secret-with-32-characters',
      baseURL: 'http://localhost:3000',
    });
    expect(await worker.pruneAudit({ tenantId: f.tenantId, retentionMs: 0 })).toMatchObject({
      deleted: 2,
      prunedThroughSequence: 2,
      heldForArchive: true,
    });
  });

  it('stops at the limit, and the self-check notices an archive that falls behind', async () => {
    const written: AuditArchiveBatch[] = [];
    const f = await organizationFixture({
      auditArchive: { batchSize: 2, write: async (batch) => void written.push(batch) },
    });
    const limited = await f.iam.archiveAudit({ limit: 3 });
    expect(limited.truncated).toBe(true);
    expect(Object.values(limited.archived).reduce((sum, count) => sum + count, 0)).toBe(3);
    expect((await f.iam.selfCheck()).findings.map((finding) => finding.check)).not.toContain(
      'audit-archive-behind',
    );
    f.advance(2 * day);
    const late = await f.iam.selfCheck();
    expect(late.findings).toContainEqual(
      expect.objectContaining({ check: 'audit-archive-behind', severity: 'warning' }),
    );
    expect((await f.iam.archiveAudit()).truncated).toBe(false);
    expect((await f.iam.selfCheck()).findings.map((finding) => finding.check)).not.toContain(
      'audit-archive-behind',
    );
  });

  it('runs from the CLI, and needs an archive configured', async () => {
    const folder = await directory();
    const database = join(folder, 'iam.db');
    const archive = join(folder, 'archive');
    const config = async (name: string, withArchive: boolean) => {
      const path = join(folder, `${name}.config.mjs`);
      await writeFile(
        path,
        `import { sqliteAdapter } from '@better-iam/adapter-sqlite';\nimport { createJsonlAuditArchive } from '@better-iam/server';\nexport default () => ({ database: sqliteAdapter({ filename: ${JSON.stringify(database)} }), secret: 'audit-archive-test-secret-with-plenty-of-characters', baseURL: 'http://localhost:3000'${withArchive ? `, auditArchive: createJsonlAuditArchive({ directory: ${JSON.stringify(archive)} })` : ''} });\n`,
      );
      return path;
    };
    const output: string[] = [];
    const io = {
      out: (line: string) => output.push(line),
      env: {
        BETTER_IAM_ROOT_EMAIL: 'root@example.test',
        BETTER_IAM_ROOT_PASSWORD: 'a strong cli root password',
      },
    };
    const archiving = await config('archiving', true);
    await runCli(['migrate', '--config', archiving], io);
    await runCli(['bootstrap', '--config', archiving], io);
    const tenantId = JSON.parse(output.at(-1)!).tenant.id as string;
    await runCli(['audit-archive', '--config', archiving], io);
    const result = JSON.parse(output.at(-1)!);
    expect(result).toMatchObject({ failed: [], truncated: false });
    expect(result.archived[tenantId]).toBeGreaterThan(0);
    expect((await archivedEvents(archive, tenantId)).length).toBe(result.archived[tenantId]);
    // The archive verifies on its own, without the database.
    await runCli(['audit-verify-archive', '--directory', archive, '--tenant', tenantId], io);
    expect(JSON.parse(output.at(-1)!)).toMatchObject({
      valid: true,
      first: 1,
      last: result.archived[tenantId],
      conflicts: 0,
    });
    // An edited archive file does not.
    const [file] = (await readdir(join(archive, tenantId))).filter((name) =>
      name.endsWith('.jsonl'),
    );
    const path = join(archive, tenantId, file!);
    const text = await readFile(path, 'utf8');
    await writeFile(path, text.replace('"outcome":"allow"', '"outcome":"deny"'));
    await expect(
      runCli(['audit-verify-archive', '--directory', archive, '--tenant', tenantId], io),
    ).rejects.toMatchObject({ code: 'AUDIT_ARCHIVE_INVALID' });
    await expect(
      runCli(['audit-verify-archive', '--directory', archive, '--tenant', '../x'], io),
    ).rejects.toMatchObject({ code: 'INVALID_ARGUMENT' });
    await expect(
      runCli(['audit-archive', '--config', await config('plain', false)], io),
    ).rejects.toMatchObject({ code: 'NO_AUDIT_ARCHIVE' });
    await expect(runCli(['audit-archive', '--limit', '0'], io)).rejects.toMatchObject({
      code: 'INVALID_ARGUMENT',
    });
  });
});
