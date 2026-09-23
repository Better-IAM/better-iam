import { readFile, readdir, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { IamError, verifyAuditChain, type AuditChainHead, type AuditEvent } from '@better-iam/core';
import { defineCommand } from '../framework.js';
import { usageError } from '../errors.js';

const tenant = {
  type: 'string',
  value: 'TENANT_ID',
  required: true,
  description: 'The tenant whose audit chain to read',
} as const;

/** A tenant's chained events in sequence order, straight from storage (no credential, no audit event). */
async function chain(store: import('@better-iam/core').IamStore, tenantId: string) {
  const head = await store.get<AuditChainHead>('auditChains', tenantId);
  const events = (await store.find<AuditEvent>('audit', { tenantId }))
    .filter((event) => typeof event.sequence === 'number')
    .sort((a, b) => a.sequence! - b.sequence!);
  return { head, events };
}

export const auditCommands = [
  defineCommand({
    name: 'audit-verify',
    group: 'Audit',
    summary: "Recompute and check a tenant's audit hash chain",
    description:
      "audit-verify recomputes a tenant's audit hash chain from storage and exits non-zero (AUDIT_CHAIN_BROKEN) when it does not verify; it records nothing.",
    target: 'config',
    flags: { tenant },
    async run({ iam, flags, print }) {
      const tenantId = flags.tenant!;
      const { head, events } = await chain((await iam()).store, tenantId);
      const verification = await verifyAuditChain(events, {
        head: head ? { sequence: head.sequence, hash: head.hash } : undefined,
      });
      print({ tenantId, ...verification, head: head ?? null });
      if (!verification.valid)
        throw new IamError('AUDIT_CHAIN_BROKEN', 'The audit chain does not verify');
    },
  }),
  defineCommand({
    name: 'audit-export',
    // One line, as scripts that read this output by line have always received it.
    defaultFormat: 'compact',
    group: 'Audit',
    summary: "Write a tenant's audit chain as JSON Lines",
    description:
      "audit-export writes a tenant's audit chain as JSON Lines for archiving (never overwriting a file); it records nothing.",
    target: 'config',
    flags: {
      tenant,
      output: {
        type: 'string',
        value: 'PATH',
        required: true,
        description: 'The .jsonl file to create (it must not exist)',
      },
    },
    async run({ iam, flags, path }) {
      const tenantId = flags.tenant!;
      const { head, events } = await chain((await iam()).store, tenantId);
      const output = path(flags.output!);
      await writeFile(output, events.map((event) => JSON.stringify(event)).join('\n') + '\n', {
        flag: 'wx',
      });
      return {
        tenantId,
        output,
        count: events.length,
        firstSequence: events[0]?.sequence ?? null,
        lastSequence: events.at(-1)?.sequence ?? null,
        head: head ? { sequence: head.sequence, hash: head.hash } : null,
      };
    },
  }),
  defineCommand({
    name: 'audit-prune',
    // One line, as scripts that read this output by line have always received it.
    defaultFormat: 'compact',
    group: 'Audit',
    summary: "Delete a tenant's archived audit events past retention",
    description:
      "audit-prune deletes a tenant's events older than --retention-days (365) after you archived them and appends an audit:prune checkpoint so the remaining chain still verifies. With an auditArchive configured, it only deletes events the archive already holds.",
    target: 'config',
    flags: {
      tenant,
      'retention-days': {
        type: 'integer',
        min: 0,
        max: 36500,
        default: 365,
        description: 'Keep events newer than this many days',
      },
    },
    async run({ iam, flags }) {
      return (await iam()).pruneAudit({
        tenantId: flags.tenant!,
        retentionMs: (flags['retention-days'] ?? 365) * 86400000,
      });
    },
  }),
  defineCommand({
    name: 'audit-archive',
    group: 'Audit',
    summary: 'Copy new audit events to the configured archive',
    description:
      'audit-archive copies new audit events, verified and in chain order, to the configured auditArchive; with an archive configured, audit-prune only deletes events it already holds.',
    target: 'config',
    flags: {
      tenant: {
        type: 'string',
        value: 'TENANT_ID',
        description: 'Only this tenant (default: all)',
      },
      limit: { type: 'integer', min: 1, description: 'Most events archived per tenant and run' },
    },
    async run({ iam, flags, print }) {
      const result = await (
        await iam()
      ).archiveAudit({
        ...(flags.tenant ? { tenantId: flags.tenant } : {}),
        ...(flags.limit === undefined ? {} : { limit: flags.limit }),
      });
      print(result);
      if (result.failed.length)
        throw new IamError(
          'AUDIT_ARCHIVE_FAILED',
          `${result.failed.length} tenant(s) could not be archived: ${result.failed.map((failure) => `${failure.tenantId} (${failure.code})`).join(', ')}`,
        );
    },
  }),
  defineCommand({
    name: 'audit-verify-archive',
    group: 'Audit',
    summary: 'Verify an archived audit chain from its files alone',
    description:
      "audit-verify-archive verifies one tenant's archived chain from createJsonlAuditArchive files alone, without the database: every sequence present once, hashes recomputed, links intact.",
    usage:
      'better-iam audit-verify-archive --directory /var/lib/better-iam/audit --tenant TENANT_ID',
    flags: {
      directory: {
        type: 'string',
        value: 'PATH',
        required: true,
        description: 'The archive directory (createJsonlAuditArchive)',
      },
      tenant: { ...tenant, description: 'The tenant whose archive to verify' },
    },
    async run({ flags, path, print }) {
      const tenantId = flags.tenant!;
      if (!/^[\w.-]{1,200}$/.test(tenantId) || tenantId.startsWith('.'))
        throw usageError('Tenant id is not a safe file name');
      const folder = resolve(path(flags.directory!), tenantId);
      const files = (await readdir(folder))
        .filter((name) => /^\d{12}-\d{12}\.jsonl$/.test(name))
        .sort();
      // Files can overlap after a crash; each sequence must then carry the identical event.
      const bySequence = new Map<number, { event: AuditEvent; line: string }>();
      let conflicts = 0;
      for (const name of files)
        for (const line of (await readFile(resolve(folder, name), 'utf8')).split('\n')) {
          if (!line.trim()) continue;
          const event = JSON.parse(line) as AuditEvent;
          const seen = bySequence.get(event.sequence!);
          if (seen && seen.line !== line) conflicts++;
          else bySequence.set(event.sequence!, { event, line });
        }
      const events = [...bySequence.values()].map((entry) => entry.event);
      const verification = await verifyAuditChain(events);
      print({ tenantId, files: files.length, conflicts, ...verification });
      if (!verification.valid || conflicts)
        throw new IamError(
          'AUDIT_ARCHIVE_INVALID',
          conflicts
            ? `${conflicts} archived event(s) disagree with another copy of the same sequence`
            : `The archived chain does not verify (${verification.failure?.reason} at sequence ${verification.failure?.sequence})`,
        );
    },
  }),
];
