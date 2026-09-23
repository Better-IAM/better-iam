import {
  IamError,
  chainAuditEvent,
  findOrdered,
  type AuditEvent,
  type Identity,
  type Session,
  type StoredRecord,
  type Tenant,
} from '@better-iam/core';
import { reconcilePackageRules } from './api/package-automation.js';
import type { PackageReconcileResult } from './api/packages.js';
import { buildAccessReport, reportHasFindings, reportWindows } from './api/reports.js';
import type { ServerContext } from './context.js';
import type {
  AccessPackage,
  AccessRequest,
  Binding,
  BindingActivation,
  ExpiryReminderMark,
  GrantAuthority,
  Group,
  GroupMember,
  IdentityLink,
  PackageAssignment,
  PackageRequest,
  Role,
  Trust,
} from './models.js';
import { all, id, publicIdentity } from './utils.js';
import { email, integer, text } from './validation.js';

/** Every tenant-scoped collection; purging a tenant sweeps each of them. */
const tenantCollections = [
  'tenants',
  'identities',
  'sessions',
  'grantAuthorities',
  'policies',
  'policyVersions',
  'roles',
  'bindings',
  'groups',
  'groupMembers',
  'accessPackages',
  'packageAssignments',
  'packageRequests',
  'packageRuleIssues',
  'expiryReminderMarks',
  'trusts',
  'ownerInvitations',
  'memberInvitations',
  'principalBoundaries',
  'actions',
  'resourceTypes',
  'resources',
  'tenantAliases',
  'tenantDomains',
  'domainOwners',
  'tenantHostnames',
  'hostnameOwners',
  'analysisSuppressions',
  'certificationCampaigns',
  'certificationItems',
  'sodRules',
  'externalIdentities',
  'authMfa',
  'passwordHistory',
  'authChallenges',
  'authPasskeys',
  'authDevices',
  'authSignIns',
  'authBlocks',
  'authRateLimits',
  'outbox',
  'accessRequests',
  'bindingActivations',
  'webhooks',
  'relationships',
  'scimConnections',
  'scimUsers',
  'scimGroups',
  'oauthClients',
  'oauthArtifacts',
  'oauthGrantSessions',
  'oauthLoginStates',
  'oauthRegistrationTokens',
  'samlRequests',
  'samlRelays',
  'samlConnections',
  'samlAssertions',
  'provisioningTargets',
  'provisioningLinks',
  'provisioningGroupLinks',
  'ssfStreams',
  'ssfDeliveries',
  'accessUsage',
  'accessUsageTracking',
  'accessInvariants',
  'agreements',
  'agreementAcceptances',
  // Web identity federation: the tenant's OIDC providers and its redeemed-token replay records.
  'oidcProviders',
  'webIdentityReplays',
  // Feature flags the tenant defines, and the targets and overrides that apply to it.
  'featureFlags',
  'featureTargets',
  // Onboarding flows the tenant defines, its welcome settings, and progress of its people (or its own setup).
  'onboardingFlows',
  'onboardingSettings',
  'onboardingProgress',
  // Delegations people give AI agents (delegations.ts), and the confirmations they answer one action at a time.
  'delegations',
  'delegationConfirmations',
  'delegationTokens',
  // The latest attested A2A card of each agent, for the agent directory (a2a.ts, api/agents.ts).
  'agentCards',
  // Inference access control (inference.ts): providers, models, budgets, their counters, usage and gateway tickets.
  'inferenceProviders',
  'inferenceModels',
  'inferenceBudgets',
  'inferenceCounters',
  'inferenceUsage',
  'inferenceTickets',
  'inferenceResponses',
  // Teams (teams.ts) and departments (departments.ts).
  'teams',
  'teamMembers',
  'teamJoinRequests',
  'teamReviews',
  'teamReviewItems',
  'departments',
  'departmentMembers',
  // Billing (billing.ts): meters and prices, usage and its daily roll-ups, budgets and alerts, credits, the billing
  // profile, statements, and contract terms; invoice items, credit notes, plans (on the root), subscriptions,
  // coupons (on the root) and redeemed discounts.
  'billingMeters',
  'billingPrices',
  'billingUsage',
  'billingRollups',
  'billingBudgets',
  'billingBudgetAlerts',
  'billingCredits',
  'billingProfiles',
  'billingStatements',
  'billingTerms',
  'billingInvoiceItems',
  'billingCreditNotes',
  'billingPlans',
  'billingSubscriptions',
  'billingCoupons',
  'billingDiscounts',
];

export interface AccessDigestResult {
  /** Tenants whose owners were emailed, with the recipient count and the finding counts. */
  sent: Array<{
    tenantId: string;
    recipients: number;
    expiringIdentities: number;
    expiringBindings: number;
    startingBindings: number;
    expiringMemberships: number;
    activations: number;
    pendingRequests: number;
    unusedKeys: number;
    expiringKeys: number;
  }>;
  /** Tenants left alone: not active, digested within the interval, nothing to report, or no owner with an email. */
  skipped: { inactive: number; recent: number; quiet: number; noOwners: number };
}

export interface ExpiryReminderResult {
  /** One entry per person emailed, with how many of their items end within the window. */
  sent: Array<{ tenantId: string; identityId: string; items: number }>;
  /** Tenants left alone: not active, or with nothing new to remind anyone about. */
  skipped: { inactive: number; quiet: number };
}

export interface PurgeResult {
  purgedTenants: string[];
  deletedRecords: number;
  expiredBindings: number;
  expiredRequests: number;
  /** Identities past their scheduled deactivation that the worker disabled in this run. */
  expiredIdentities: number;
  /** Ended role activations removed in this run. */
  expiredActivations: number;
  /** Temporary group memberships past their end removed in this run. */
  expiredMemberships: number;
  /** Access-package assignments past their end removed in this run (their bindings and memberships expire on their own). */
  expiredAssignments: number;
}

/** Deployment operations: migrations, root bootstrap and recovery, and the retention worker. None are HTTP endpoints. */
export function createLifecycle(ctx: ServerContext) {
  const { store, auth, plugins, config } = ctx;
  return {
    async initialize(): Promise<void> {
      await store.migrate();
      for (const plugin of plugins)
        if (plugin.migrate) await store.transaction((tx) => plugin.migrate!(tx));
      // Tenants deleted before deletedAt existed start their retention window now.
      await store.transaction(async (tx) => {
        for (const realm of await tx.find<Tenant>('tenants', { status: 'deleted' }))
          if (typeof realm.deletedAt !== 'number')
            await tx.put('tenants', { ...realm, deletedAt: Date.now() });
      });
      // Audit events recorded before the hash chain existed are chained once, in timestamp order per tenant.
      await store.transaction(async (tx) => {
        // Filtered in the database: only the (normally zero) unchained events are read at startup.
        const pending = (await tx.find<AuditEvent>('audit', { sequence: undefined }))
          .filter((event) => typeof event.sequence !== 'number')
          .sort(
            (a, b) =>
              (a.tenantId < b.tenantId ? -1 : a.tenantId > b.tenantId ? 1 : 0) ||
              a.timestamp - b.timestamp ||
              (a.id < b.id ? -1 : a.id > b.id ? 1 : 0),
          );
        for (const event of pending) await tx.put('audit', await chainAuditEvent(tx, event));
      });
    },
    async bootstrap(input: {
      email: string;
      name: string;
      password: string;
      rootName?: string;
      slug?: string;
    }) {
      return store.transaction(async (tx) => {
        if ((await tx.find<Tenant>('tenants', { parentId: null })).length)
          throw new IamError('ALREADY_INITIALIZED', 'Root already exists', 409);
        const realm: Tenant = {
          id: id(),
          tenantId: '',
          uniqueKey: 'installation-root',
          name: input.rootName ?? 'Platform',
          type: 'root',
          parentId: null,
          status: 'active',
          createdAt: Date.now(),
        };
        realm.tenantId = realm.id;
        if (input.slug !== undefined) realm.slug = await ctx.claimSlug(tx, realm.id, input.slug);
        await tx.insert('tenants', realm);
        const identity = await auth.createIdentity(tx, {
          tenantId: realm.id,
          email: email(input.email),
          name: text(input.name, 'name'),
          password: input.password,
          owner: true,
          rootAdmin: true,
          emailVerified: true,
        });
        const authority = await tx.insert<GrantAuthority>('grantAuthorities', {
          id: id(),
          tenantId: realm.id,
          identityId: identity.id,
          ceiling: all,
          revoked: false,
        });
        await ctx.ownerSetup(tx, realm, identity, authority);
        await ctx.events.recordAudit(tx, {
          id: id(),
          tenantId: realm.id,
          actorId: 'deployment-operator',
          action: 'root:bootstrap',
          resourceId: identity.id,
          timestamp: Date.now(),
          outcome: 'allow',
        });
        return {
          tenant: realm,
          identity: publicIdentity(identity),
          mfaEnrollmentRequired: true as const,
        };
      });
    },
    async recoverRoot(input: { email: string; name: string; password: string }) {
      return store.transaction(async (tx) => {
        const realm = (await tx.find<Tenant>('tenants', { parentId: null }))[0];
        if (!realm) throw new IamError('NOT_INITIALIZED', 'Bootstrap first');
        const identity = await auth.createIdentity(tx, {
          tenantId: realm.id,
          email: email(input.email),
          name: text(input.name, 'name'),
          password: input.password,
          rootAdmin: true,
          emailVerified: true,
        });
        await ctx.events.recordAudit(tx, {
          id: id(),
          tenantId: realm.id,
          actorId: 'deployment-operator',
          action: 'root:recover',
          resourceId: identity.id,
          timestamp: Date.now(),
          outcome: 'allow',
        });
        return {
          identity: publicIdentity(identity),
          tenantId: realm.id,
          mfaEnrollmentRequired: true as const,
        };
      });
    },
    /**
     * Audit retention: deletes a tenant's oldest chained events (the longest prefix older than the cutoff) and appends
     * an `audit:prune` checkpoint that records the sequence and hash the chain now starts after, so the remaining
     * chain still verifies from its first event. A deployment operation: no credential, runs without a tenant check.
     */
    async pruneAudit(input: { tenantId: string; retentionMs: number }): Promise<{
      deleted: number;
      prunedThroughSequence?: number;
      prunedThroughHash?: string;
      /** Older events were kept because the audit archive has not stored them yet. */
      heldForArchive?: true;
    }> {
      const tenantId = text(input.tenantId, 'tenantId');
      const retentionMs = integer(input.retentionMs, 'retentionMs', 0, 100 * 365 * 86400000);
      const cutoff = Date.now() - retentionMs;
      return store.transaction(async (tx) => {
        let last: AuditEvent | undefined;
        let deleted = 0;
        let held = false;
        // Once a tenant is being archived (a cursor exists), or wherever an archive is configured,
        // only events the archive already holds may leave the database, even in a process that
        // does not configure the archive itself.
        const cursor = await tx.get<{ sequence: number } & StoredRecord>(
          'auditArchiveCursors',
          tenantId,
        );
        const archivedThrough =
          cursor || ctx.options.auditArchive ? (cursor?.sequence ?? 0) : Number.POSITIVE_INFINITY;
        // Oldest first by chain sequence, a page at a time, stopping at the first event to keep.
        for (let from = 1, done = false; !done; ) {
          const page = await findOrdered<AuditEvent>(
            tx,
            'audit',
            { tenantId },
            {
              field: 'sequence',
              from,
              limit: 1000,
            },
          );
          for (const event of page) {
            if (event.timestamp >= cutoff) {
              done = true;
              break;
            }
            if (event.sequence! > archivedThrough) {
              held = true;
              done = true;
              break;
            }
            await tx.delete('audit', event.id);
            last = event;
            deleted++;
          }
          if (page.length < 1000) done = true;
          else from = page.at(-1)!.sequence! + 1;
        }
        if (!last) return { deleted: 0, ...(held ? { heldForArchive: true as const } : {}) };
        await ctx.events.recordAudit(tx, {
          id: id(),
          tenantId,
          actorId: 'deployment-operator',
          action: 'audit:prune',
          resourceId: tenantId,
          timestamp: Date.now(),
          outcome: 'allow',
          metadata: {
            deleted,
            before: cutoff,
            prunedThroughSequence: last.sequence!,
            prunedThroughHash: last.hash!,
          },
        });
        return {
          deleted,
          prunedThroughSequence: last.sequence,
          prunedThroughHash: last.hash,
          ...(held ? { heldForArchive: true as const } : {}),
        };
      });
    },
    /**
     * Access digest: emails the owners of every active tenant (or one `tenantId`) whose access report has findings
     * (`access-digest` template with the counts and the full report as JSON), at most once per `minimumIntervalMs`
     * (20 hours by default) per tenant, recorded as `tenant:access-digest`. A deployment operation for schedulers:
     * no credential, every report section included. Requires an email delivery callback.
     */
    async sendAccessDigest(
      input: {
        tenantId?: string;
        withinMs?: number;
        unusedForMs?: number;
        minimumIntervalMs?: number;
      } = {},
    ): Promise<AccessDigestResult> {
      const windows = reportWindows(input);
      const minimumIntervalMs = integer(
        input.minimumIntervalMs ?? 20 * 3_600_000,
        'minimumIntervalMs',
        0,
        365 * 86400000,
      );
      if (!ctx.options.authentication?.sendEmail)
        throw new IamError(
          'DELIVERY_REQUIRED',
          'The access digest requires an email delivery callback',
        );
      return store.transaction(async (tx) => {
        const tenants = input.tenantId
          ? [await ctx.tenant(tx, text(input.tenantId, 'tenantId'))]
          : (await tx.find<Tenant>('tenants', { status: 'active' })).sort((a, b) =>
              a.id < b.id ? -1 : 1,
            );
        const sent: AccessDigestResult['sent'] = [];
        const skipped = { inactive: 0, recent: 0, quiet: 0, noOwners: 0 };
        for (const tenant of tenants) {
          if (tenant.status !== 'active') {
            skipped.inactive++;
            continue;
          }
          const since = ctx.now() - minimumIntervalMs;
          if (
            (
              await tx.find<AuditEvent>('audit', {
                tenantId: tenant.id,
                action: 'tenant:access-digest',
              })
            ).some((event) => event.timestamp > since)
          ) {
            skipped.recent++;
            continue;
          }
          const report = await buildAccessReport(ctx, tx, tenant.id, windows, {
            bindings: true,
            credentials: true,
          });
          if (!reportHasFindings(report)) {
            skipped.quiet++;
            continue;
          }
          const owners = (
            await tx.find<Identity>('identities', {
              tenantId: tenant.id,
              owner: true,
              status: 'active',
            })
          ).filter((owner): owner is Identity & { email: string } => Boolean(owner.email));
          if (!owners.length) {
            skipped.noOwners++;
            continue;
          }
          const counts = {
            expiringIdentities: report.identities.expiring.length,
            expiringBindings: report.bindings?.expiring.length ?? 0,
            startingBindings: report.bindings?.starting.length ?? 0,
            expiringMemberships: report.bindings?.expiringMemberships.length ?? 0,
            activations: report.bindings?.activations.length ?? 0,
            pendingRequests: report.bindings?.pendingRequests ?? 0,
            unusedKeys: report.credentials?.unused.length ?? 0,
            expiringKeys: report.credentials?.expiring.length ?? 0,
          };
          const payload = {
            tenantId: tenant.id,
            tenantName: tenant.name,
            generatedAt: String(report.generatedAt),
            withinMs: String(windows.withinMs),
            unusedForMs: String(windows.unusedForMs),
            ...Object.fromEntries(
              Object.entries(counts).map(([key, value]) => [key, String(value)]),
            ),
            report: JSON.stringify(report),
          };
          for (const owner of owners)
            await auth.enqueueDelivery(tx, {
              tenantId: tenant.id,
              kind: 'email',
              to: owner.email,
              template: 'access-digest',
              payload,
            });
          await ctx.events.recordAudit(tx, {
            id: id(),
            tenantId: tenant.id,
            actorId: 'deployment-operator',
            action: 'tenant:access-digest',
            resourceId: tenant.id,
            timestamp: ctx.now(),
            outcome: 'allow',
            metadata: { recipients: owners.length, ...counts },
          });
          sent.push({ tenantId: tenant.id, recipients: owners.length, ...counts });
        }
        return { sent, skipped };
      });
    },
    /**
     * Expiry reminders: emails each person whose account, direct role bindings, group memberships, or package
     * assignments end within `withinMs` (seven days by default) one `expiry-reminder` message listing them, once
     * per item and end date (moving the end triggers a fresh reminder), recorded as `identity:expiry-reminder`.
     * Group bindings are left to the owners' digest. A deployment operation for schedulers; requires an email
     * delivery callback.
     */
    async sendExpiryReminders(
      input: { tenantId?: string; withinMs?: number } = {},
    ): Promise<ExpiryReminderResult> {
      const withinMs = integer(input.withinMs ?? 7 * 86400000, 'withinMs', 60_000, 365 * 86400000);
      if (!ctx.options.authentication?.sendEmail)
        throw new IamError(
          'DELIVERY_REQUIRED',
          'Expiry reminders require an email delivery callback',
        );
      return store.transaction(async (tx) => {
        const tenants = input.tenantId
          ? [await ctx.tenant(tx, text(input.tenantId, 'tenantId'))]
          : (await tx.find<Tenant>('tenants', { status: 'active' })).sort((a, b) =>
              a.id < b.id ? -1 : 1,
            );
        const sent: ExpiryReminderResult['sent'] = [];
        const skipped = { inactive: 0, quiet: 0 };
        for (const tenant of tenants) {
          if (tenant.status !== 'active') {
            skipped.inactive++;
            continue;
          }
          const now = ctx.now();
          const horizon = now + withinMs;
          const ending = (expiresAt: number | undefined): expiresAt is number =>
            expiresAt !== undefined && expiresAt > now && expiresAt <= horizon;
          // What was already reminded: marks kept until the item ends (they survive audit pruning), plus the audit
          // trail of runs made before marks existed.
          const reminded = new Set<string>();
          for (const mark of await tx.find<ExpiryReminderMark>('expiryReminderMarks', {
            tenantId: tenant.id,
          }))
            reminded.add(mark.uniqueKey!);
          for (const event of await tx.find<AuditEvent>('audit', {
            tenantId: tenant.id,
            action: 'identity:expiry-reminder',
          }))
            for (const key of (event.metadata?.items as unknown[] | undefined) ?? [])
              if (typeof key === 'string') reminded.add(key);
          const assignments = await tx.find<PackageAssignment>('packageAssignments', {
            tenantId: tenant.id,
          });
          // A package's own bindings and memberships are reminded as the package, while it still exists.
          const assignmentIds = new Set(assignments.map((assignment) => assignment.id));
          const packaged = (record: { packageAssignmentId?: string }) =>
            record.packageAssignmentId !== undefined &&
            assignmentIds.has(record.packageAssignmentId);
          type Item = { key: string; kind: string; name: string; expiresAt: number };
          const items = new Map<string, Item[]>();
          const add = (identityId: string, item: Item) => {
            if (reminded.has(item.key)) return;
            items.set(identityId, [...(items.get(identityId) ?? []), item]);
          };
          const identities = await tx.find<Identity>('identities', {
            tenantId: tenant.id,
            status: 'active',
          });
          const byId = new Map(identities.map((identity) => [identity.id, identity]));
          for (const identity of identities)
            if (ending(identity.expiresAt))
              add(identity.id, {
                key: `identity:${identity.id}:${identity.expiresAt}`,
                kind: 'account',
                name: identity.name,
                expiresAt: identity.expiresAt,
              });
          const roles = new Map(
            (await tx.find<Role>('roles', { tenantId: tenant.id })).map((role) => [
              role.id,
              role.name,
            ]),
          );
          for (const binding of await tx.find<Binding>('bindings', {
            tenantId: tenant.id,
            subjectType: 'identity',
          }))
            if (
              ending(binding.expiresAt) &&
              ctx.liveBinding(binding) &&
              !binding.eligible &&
              !packaged(binding)
            )
              add(binding.subjectId, {
                key: `binding:${binding.id}:${binding.expiresAt}`,
                kind: 'role',
                name: roles.get(binding.roleId) ?? binding.roleId,
                expiresAt: binding.expiresAt,
              });
          const groups = new Map(
            (await tx.find<Group>('groups', { tenantId: tenant.id })).map((group) => [
              group.id,
              group.name,
            ]),
          );
          for (const member of await tx.find<GroupMember>('groupMembers', { tenantId: tenant.id }))
            if (ending(member.expiresAt) && ctx.liveMembership(member) && !packaged(member))
              add(member.identityId, {
                key: `membership:${member.id}:${member.expiresAt}`,
                kind: 'group',
                name: groups.get(member.groupId) ?? member.groupId,
                expiresAt: member.expiresAt,
              });
          const packages = new Map(
            (await tx.find<AccessPackage>('accessPackages', { tenantId: tenant.id })).map((pkg) => [
              pkg.id,
              pkg.name,
            ]),
          );
          for (const assignment of assignments)
            if (ending(assignment.expiresAt))
              add(assignment.identityId, {
                key: `package:${assignment.id}:${assignment.expiresAt}`,
                kind: 'package',
                name: packages.get(assignment.packageId) ?? assignment.packageId,
                expiresAt: assignment.expiresAt,
              });
          let any = false;
          for (const [identityId, list] of [...items].sort(([a], [b]) => (a < b ? -1 : 1))) {
            const identity = byId.get(identityId);
            if (!identity?.email) continue;
            list.sort((a, b) => a.expiresAt - b.expiresAt);
            await auth.enqueueDelivery(tx, {
              tenantId: tenant.id,
              kind: 'email',
              to: identity.email,
              template: 'expiry-reminder',
              payload: {
                tenantId: tenant.id,
                tenantName: tenant.name,
                identityName: identity.name,
                count: String(list.length),
                earliest: String(list[0]!.expiresAt),
                items: JSON.stringify(
                  list.map(({ kind, name, expiresAt }) => ({ kind, name, expiresAt })),
                ),
              },
            });
            await ctx.events.recordAudit(tx, {
              id: id(),
              tenantId: tenant.id,
              actorId: 'deployment-operator',
              action: 'identity:expiry-reminder',
              resourceId: identity.id,
              timestamp: now,
              outcome: 'allow',
              metadata: {
                count: list.length,
                earliest: list[0]!.expiresAt,
                items: list.map((item) => item.key),
              },
            });
            for (const item of list)
              await tx.insert<ExpiryReminderMark>('expiryReminderMarks', {
                id: id(),
                tenantId: tenant.id,
                uniqueKey: item.key,
                identityId,
                expiresAt: item.expiresAt,
              });
            sent.push({ tenantId: tenant.id, identityId, items: list.length });
            any = true;
          }
          if (!any) skipped.quiet++;
        }
        return { sent, skipped };
      });
    },
    /**
     * Birthright access: applies every access-package rule (or one tenant's, or one package's) under its owner's
     * grant authority: identities that match receive the package, automatic holders that stopped matching lose it
     * (after the rule's grace period). At most `limit` changes per organization (1000); `truncated` means run again.
     * Unusually large changes are held back unless `confirm` (with `packageId`). A scheduler job: no credential.
     */
    async reconcilePackages(
      input: { tenantId?: string; packageId?: string; limit?: number; confirm?: boolean } = {},
    ): Promise<PackageReconcileResult> {
      const tenantId = input.tenantId !== undefined ? text(input.tenantId, 'tenantId') : undefined;
      const packageId =
        input.packageId !== undefined ? text(input.packageId, 'packageId') : undefined;
      if (packageId && !tenantId) throw new IamError('INVALID_INPUT', 'packageId needs tenantId');
      if (input.confirm !== undefined && typeof input.confirm !== 'boolean')
        throw new IamError('INVALID_INPUT', 'confirm must be boolean');
      if (input.confirm && !packageId)
        throw new IamError('INVALID_INPUT', 'confirm needs packageId');
      const limit = integer(input.limit ?? 1000, 'limit', 1, 10000);
      return reconcilePackageRules(ctx, {
        ...(tenantId ? { tenantId } : {}),
        ...(packageId ? { packageId } : {}),
        limit,
        trigger: 'schedule',
        ...(input.confirm ? { confirmedBy: 'deployment-operator' as const } : {}),
      });
    },
    /**
     * Retention worker: removes tombstoned tenants past the retention window, deletes expired temporary bindings
     * and ended role activations, marks pending access requests past their lifetime as expired, and disables
     * identities past their scheduled deactivation (`identity:expire`, sessions revoked). Audit records are preserved.
     * It also deletes authentication bookkeeping past its end in every tenant, known or not: rate-limit counters past
     * their window, challenges past their expiry, and lapsed network blocks.
     */
    async purgeDeleted(input: { retentionMs?: number } = {}): Promise<PurgeResult> {
      const retentionMs = integer(input.retentionMs ?? 2592000000, 'retentionMs', 0, 315360000000);
      const cutoff = Date.now() - retentionMs;
      await sweepExpiredAuthRecords(ctx);
      return store.transaction(async (tx) => {
        let expiredBindings = 0;
        let expiredRequests = 0;
        let expiredIdentities = 0;
        let expiredActivations = 0;
        let expiredMemberships = 0;
        let expiredAssignments = 0;
        for (const binding of await tx.find<Binding>('bindings'))
          if (ctx.expiredBinding(binding)) {
            // Activations of a binding that is gone could never grant again.
            for (const activation of await tx.find<BindingActivation>('bindingActivations', {
              tenantId: binding.tenantId,
              bindingId: binding.id,
            })) {
              await tx.delete('bindingActivations', activation.id);
              expiredActivations++;
            }
            await tx.delete('bindings', binding.id);
            expiredBindings++;
          }
        for (const activation of await tx.find<BindingActivation>('bindingActivations'))
          if (activation.expiresAt <= ctx.now()) {
            await tx.delete('bindingActivations', activation.id);
            expiredActivations++;
          }
        // A lapsed membership ends the person's activations of that group's eligible bindings too.
        for (const member of await tx.find<GroupMember>('groupMembers'))
          if (!ctx.liveMembership(member)) {
            for (const binding of await tx.find<Binding>('bindings', {
              tenantId: member.tenantId,
              subjectType: 'group',
              subjectId: member.groupId,
            }))
              for (const activation of await tx.find<BindingActivation>('bindingActivations', {
                tenantId: member.tenantId,
                bindingId: binding.id,
                identityId: member.identityId,
              }))
                await tx.delete('bindingActivations', activation.id);
            await tx.delete('groupMembers', member.id);
            expiredMemberships++;
          }
        for (const assignment of await tx.find<PackageAssignment>('packageAssignments'))
          if (assignment.expiresAt !== undefined && assignment.expiresAt <= ctx.now()) {
            await tx.delete('packageAssignments', assignment.id);
            expiredAssignments++;
          }
        for (const request of await tx.find<AccessRequest>('accessRequests', { status: 'pending' }))
          if (request.expiresAt <= ctx.now()) {
            await tx.put('accessRequests', { ...request, status: 'expired' });
            expiredRequests++;
          }
        for (const request of await tx.find<PackageRequest>('packageRequests', {
          status: 'pending',
        }))
          if (request.expiresAt <= ctx.now()) {
            await tx.put('packageRequests', { ...request, status: 'expired' });
            expiredRequests++;
          }
        // Reminder marks are only needed until the item they remember has ended.
        for (const mark of await tx.find<ExpiryReminderMark>('expiryReminderMarks'))
          if (mark.expiresAt <= ctx.now()) await tx.delete('expiryReminderMarks', mark.id);
        for (const identity of await tx.find<Identity>('identities', { status: 'active' }))
          if (ctx.identityExpired(identity)) {
            await tx.put('identities', { ...identity, status: 'disabled' });
            await ctx.revokeAll(tx, identity.id);
            for (const activation of await tx.find<BindingActivation>('bindingActivations', {
              tenantId: identity.tenantId,
              identityId: identity.id,
            })) {
              await tx.delete('bindingActivations', activation.id);
              expiredActivations++;
            }
            await ctx.events.recordAudit(tx, {
              id: id(),
              tenantId: identity.tenantId,
              actorId: 'deployment-operator',
              action: 'identity:expire',
              resourceId: identity.id,
              timestamp: Date.now(),
              outcome: 'allow',
              metadata: { kind: identity.kind, expiresAt: identity.expiresAt! },
            });
            expiredIdentities++;
          }
        const realms = await tx.find<Tenant>('tenants');
        const roots = realms.filter(
          (realm) =>
            realm.status === 'deleted' &&
            typeof realm.deletedAt === 'number' &&
            realm.deletedAt <= cutoff,
        );
        if (!roots.length)
          return {
            purgedTenants: [],
            deletedRecords: 0,
            expiredBindings,
            expiredRequests,
            expiredIdentities,
            expiredActivations,
            expiredMemberships,
            expiredAssignments,
          };
        const purged = new Set(roots.map((root) => root.id));
        for (let depth = 0; depth < config.maxDepth; depth++)
          for (const realm of realms)
            if (realm.parentId && purged.has(realm.parentId)) purged.add(realm.id);
        const identities = new Set<string>();
        for (const tenantId of purged)
          for (const identity of await tx.find<Identity>('identities', { tenantId }))
            identities.add(identity.id);
        let deletedRecords = 0;
        const sweep = async (collection: string, tenantId: string) => {
          for (const row of await tx.find(collection, { tenantId })) {
            await tx.delete(collection, row.id);
            deletedRecords++;
          }
        };
        for (const tenantId of purged)
          for (const collection of tenantCollections) await sweep(collection, tenantId);
        // Records in surviving tenants that reference purged tenants or identities become dead references.
        for (const session of await tx.find<Session>('sessions'))
          if (session.sourceTenantId && purged.has(session.sourceTenantId)) {
            await tx.delete('sessions', session.id);
            deletedRecords++;
          }
        for (const trust of await tx.find<Trust>('trusts'))
          if (purged.has(trust.sourceTenantId)) {
            await tx.delete('trusts', trust.id);
            deletedRecords++;
          }
        for (const link of await tx.find<IdentityLink>('identityLinks'))
          if (identities.has(link.leftId) || identities.has(link.rightId)) {
            await tx.delete('identityLinks', link.id);
            deletedRecords++;
          }
        for (const artifact of await tx.find<StoredRecord>('oauthArtifacts'))
          if (typeof artifact.accountId === 'string' && identities.has(artifact.accountId)) {
            await tx.delete('oauthArtifacts', artifact.id);
            deletedRecords++;
          }
        for (const plugin of plugins) if (plugin.purge) await plugin.purge(tx, [...purged]);
        // Audit records survive the purge so the deletion trail remains queryable.
        for (const root of roots) {
          const subtree = new Set([root.id]);
          for (let depth = 0; depth < config.maxDepth; depth++)
            for (const realm of realms)
              if (realm.parentId && subtree.has(realm.parentId)) subtree.add(realm.id);
          await ctx.events.recordAudit(tx, {
            id: id(),
            tenantId: root.id,
            actorId: 'deployment-operator',
            action: 'tenants:purge',
            resourceId: root.id,
            timestamp: Date.now(),
            outcome: 'allow',
            metadata: { tenantIds: [...subtree], deletedRecords },
          });
        }
        return {
          purgedTenants: [...purged].sort(),
          deletedRecords,
          expiredBindings,
          expiredRequests,
          expiredIdentities,
          expiredActivations,
          expiredMemberships,
          expiredAssignments,
        };
      });
    },
  };
}

/** Rows deleted per transaction by the sweep below, so the write lock is never held for long. */
const SWEEP_BATCH = 500;

/**
 * Authentication bookkeeping that nothing else removes: rate-limit counters past their window (anonymous requests
 * leave one per email, address, and made-up tenant), challenges past their expiry (unfinished sign-ins, passkey
 * discovery on every login page view), and lapsed network blocks (re-read on every uncached block check). Rows are
 * listed once, then deleted in bounded batches of short transactions; each row is re-read first, so a counter or a
 * block renewed in the meantime survives.
 */
async function sweepExpiredAuthRecords(ctx: ServerContext): Promise<void> {
  const now = ctx.now();
  const ended = (field: string) => (row: StoredRecord) =>
    typeof row[field] === 'number' && (row[field] as number) <= now;
  const sweeps: Array<[collection: string, expired: (row: StoredRecord) => boolean]> = [
    ['authRateLimits', ended('resetAt')],
    ['authChallenges', ended('expiresAt')],
    ['authBlocks', ended('expiresAt')],
  ];
  for (const [collection, expired] of sweeps) {
    const ids = (await ctx.store.find(collection)).filter(expired).map((row) => row.id);
    for (let start = 0; start < ids.length; start += SWEEP_BATCH)
      await ctx.store.transaction(async (tx) => {
        for (const rowId of ids.slice(start, start + SWEEP_BATCH)) {
          const row = await tx.get(collection, rowId);
          if (row && expired(row)) await tx.delete(collection, rowId);
        }
      });
    // Cached block lists may still hold the removed rows; they no longer apply, but need not be kept.
    if (collection === 'authBlocks' && ids.length) ctx.auth.invalidateNetworkBlocks();
  }
}
