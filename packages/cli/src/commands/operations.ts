import { IamError } from '@better-iam/core';
import { defineCommand } from '../framework.js';
import { usageError } from '../errors.js';

const day = 86_400_000;
const tenantFilter = {
  type: 'string',
  value: 'TENANT_ID',
  description: 'Only this organization (default: every active one)',
} as const;

/** Deployment operations for schedulers: no credential, they act on the whole deployment (or one --tenant). */
export const operationCommands = [
  defineCommand({
    name: 'outbox',
    // One line, as scripts that read this output by line have always received it.
    defaultFormat: 'compact',
    group: 'Operations',
    summary: 'Deliver pending emails, SMS, and webhooks from the outbox',
    description:
      'outbox delivers pending transactional messages from the encrypted delivery outbox and then dispatches audit hooks (webhooks); a deployment operation for a scheduler.',
    target: 'config',
    async run({ iam, print }) {
      const instance = await iam();
      print(await instance.auth.dispatchOutbox());
      await instance.dispatchAuditHooks();
    },
  }),
  defineCommand({
    name: 'purge',
    // One line, as scripts that read this output by line have always received it.
    defaultFormat: 'compact',
    group: 'Operations',
    summary: 'Remove deleted tenants past retention and expired grants',
    description:
      'Purge removes tenants deleted more than N days ago (default 30) including their data, and records the action in the audit log. Audit records remain.',
    target: 'config',
    flags: {
      'retention-days': {
        type: 'integer',
        min: 0,
        max: 3650,
        default: 30,
        description: 'Keep deleted tenants this many days',
      },
    },
    async run({ iam, flags }) {
      return (await iam()).purgeDeleted({ retentionMs: (flags['retention-days'] ?? 30) * day });
    },
  }),
  defineCommand({
    name: 'sweep',
    group: 'Operations',
    summary: 'Delete expired sessions, protocol artifacts, and old deliveries',
    description:
      'sweep deletes expired sessions, devices, relationship tuples, OAuth and SAML artifacts, and deliveries older than --retention-days (30) in short batches, at most --limit (10000) records per run; schedule it beside purge.',
    target: 'config',
    flags: {
      limit: {
        type: 'integer',
        min: 1,
        max: 1_000_000,
        default: 10000,
        description: 'Most records deleted per run',
      },
      'retention-days': {
        type: 'integer',
        min: 0,
        max: 3650,
        default: 30,
        description: 'Keep delivered and failed deliveries this many days',
      },
    },
    async run({ iam, flags }) {
      return (await iam()).sweepExpired({
        ...(flags.limit === undefined ? {} : { limit: flags.limit }),
        ...(flags['retention-days'] === undefined
          ? {}
          : { deliveryRetentionMs: flags['retention-days'] * day }),
      });
    },
  }),
  defineCommand({
    name: 'digest',
    group: 'Operations',
    summary: 'Email each organization owner its access report',
    description:
      'digest emails the access report to the owners of every active organization (or one --tenant) that has something to report, at most once a day per organization; a deployment operation for cron, like purge.',
    target: 'config',
    flags: {
      tenant: tenantFilter,
      'within-days': {
        type: 'integer',
        min: 0,
        max: 3650,
        default: 30,
        description: 'Report access ending within this many days',
      },
      'unused-days': {
        type: 'integer',
        min: 0,
        max: 3650,
        default: 30,
        description: 'Report keys unused for this many days',
      },
    },
    async run({ iam, flags }) {
      return (await iam()).sendAccessDigest({
        ...(flags.tenant ? { tenantId: flags.tenant } : {}),
        withinMs: (flags['within-days'] ?? 30) * day,
        unusedForMs: (flags['unused-days'] ?? 30) * day,
      });
    },
  }),
  defineCommand({
    name: 'remind',
    group: 'Operations',
    summary: 'Email people whose access ends soon',
    description:
      'remind emails each person whose account, role bindings, group memberships, or packages end within --within-days (7), once per item and end date; a deployment operation like digest.',
    target: 'config',
    flags: {
      tenant: tenantFilter,
      // Reminders look at most a year ahead (the server's own bound).
      'within-days': {
        type: 'integer',
        min: 1,
        max: 365,
        default: 7,
        description: 'Remind about access ending within this many days',
      },
    },
    async run({ iam, flags }) {
      return (await iam()).sendExpiryReminders({
        ...(flags.tenant ? { tenantId: flags.tenant } : {}),
        withinMs: (flags['within-days'] ?? 7) * day,
      });
    },
  }),
  defineCommand({
    name: 'reconcile',
    group: 'Operations',
    summary: 'Apply access-package rules (birthright access)',
    description:
      "reconcile applies access-package rules (birthright access): identities that match a package's autoAssign rule receive it and automatic holders that stopped matching lose it, at most --limit (1000) changes per organization and run, under each rule owner's grant authority; a deployment operation for cron (run it after purge). Unusually large changes are held back until confirmed with --tenant ID --package ID --confirm; --fail-on-attention exits non-zero when a change failed, was held back, or a rule is suspended.",
    usage:
      'better-iam reconcile --config better-iam.config.mjs [--tenant TENANT_ID [--package PACKAGE_ID [--confirm]]] [--limit N] [--fail-on-attention]',
    target: 'config',
    flags: {
      tenant: tenantFilter,
      package: {
        type: 'string',
        value: 'PACKAGE_ID',
        description: 'Only this package (needs --tenant)',
      },
      confirm: { type: 'boolean', description: 'Apply a held-back large change (needs --package)' },
      limit: {
        type: 'integer',
        min: 1,
        max: 10000,
        default: 1000,
        description: 'Most changes per organization and run',
      },
      'fail-on-attention': {
        type: 'boolean',
        description: 'Exit non-zero when a change failed, was held back, or a rule is suspended',
      },
    },
    validate(flags) {
      if (flags.package && !flags.tenant) throw usageError('--package needs --tenant');
      if (flags.confirm && !flags.package) throw usageError('--confirm needs --package');
    },
    async run({ iam, flags, print }) {
      // Applies package rules under their owners' authority; no credential.
      const result = await (
        await iam()
      ).reconcilePackages({
        ...(flags.tenant ? { tenantId: flags.tenant } : {}),
        ...(flags.package ? { packageId: flags.package } : {}),
        ...(flags.limit !== undefined ? { limit: flags.limit } : {}),
        ...(flags.confirm ? { confirm: true } : {}),
      });
      print(result);
      const attention =
        result.failed.length +
        result.suspended.length +
        result.braked.length +
        result.skipped.failedTenants.length;
      if (flags['fail-on-attention'] && attention)
        throw new IamError(
          'RECONCILE_ATTENTION',
          `${attention} package rule problem(s) need attention`,
        );
    },
  }),
  defineCommand({
    name: 'close-certifications',
    group: 'Operations',
    summary: 'Close and apply overdue auto-closing certification campaigns',
    description:
      "close-certifications closes every access-certification campaign created with autoClose whose due date has passed (or only one --tenant's), applying its decisions under the creator's authority; a deployment operation for cron.",
    target: 'config',
    flags: { tenant: tenantFilter },
    async run({ iam, flags }) {
      return (await iam()).closeOverdueCertifications(
        flags.tenant ? { tenantId: flags.tenant } : {},
      );
    },
  }),
  defineCommand({
    name: 'monitor-invariants',
    group: 'Operations',
    summary: "Evaluate every organization's invariants and audit status changes",
    description:
      "monitor-invariants evaluates every organization's invariants (or one --tenant's) and records invariant:broken / invariant:restored audit events when their status changes, so webhooks can alert; a deployment operation for cron.",
    target: 'config',
    flags: { tenant: tenantFilter },
    async run({ iam, flags }) {
      return (await iam()).checkInvariants(flags.tenant ? { tenantId: flags.tenant } : {});
    },
  }),
  defineCommand({
    name: 'rotate-secrets',
    group: 'Operations',
    summary: 'Re-seal stored secrets with the current deployment secret',
    description:
      'rotate-secrets re-seals authenticator secrets, webhook secrets, and pending deliveries sealed with previousSecrets using the current secret; --dry-run only counts them.',
    target: 'config',
    flags: { 'dry-run': { type: 'boolean', description: 'Only count what would be re-sealed' } },
    async run({ iam, flags, print }) {
      const result = await (await iam()).rotateSecrets({ dryRun: flags['dry-run'] });
      print(result);
      const unreadable = Object.values(result.unreadable).reduce((sum, count) => sum + count, 0);
      if (unreadable)
        throw new IamError(
          'UNREADABLE_SECRETS',
          `${unreadable} stored value(s) open with no configured secret; add the secret that sealed them to previousSecrets`,
        );
    },
  }),
];
