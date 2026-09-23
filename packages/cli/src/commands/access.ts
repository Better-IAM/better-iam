import { writeFile } from 'node:fs/promises';
import { IamError } from '@better-iam/core';
import type {
  AccessFinding,
  CallerIdentity,
  ConfigPlan,
  InvariantRunResult,
  TenantConfig,
} from '@better-iam/server';
import { CliError, usageError } from '../errors.js';
import { defineCommand, type CommandContext, type FlagSpecs } from '../framework.js';
import { formatResult } from '../output.js';
import { lintTenantConfig, loadTenantConfig, tenantConfigModule } from '../tenant-config.js';
import type { ApiTransport } from '../transport.js';

const day = 86_400_000;
const severities = ['high', 'medium', 'low'] as const;

/** The tenant a token command acts in: the flag, BETTER_IAM_TENANT, or the saved profile's. */
export const tenantFlag = {
  type: 'string',
  value: 'TENANT_ID',
  required: true,
  env: 'BETTER_IAM_TENANT',
  profile: 'tenantId',
  description: 'The tenant to act in',
} as const;

const inputFlag = {
  type: 'string',
  value: 'PATH',
  required: true,
  description: 'Desired configuration: .json, or a .mjs/.js/.ts module exporting it (or a factory)',
} as const;

/** `project/p1`, `project:p1`, or `iam/roles/r1` (the first separator splits type and id). */
export function parseResource(value: string): { type: string; id: string } {
  const match = /^([^/:]+)[/:](.+)$/.exec(value);
  if (!match) throw usageError(`${value} is not a resource like project/p1 or project:p1`);
  return { type: match[1]!, id: match[2]! };
}

/** An identity ID, or an email looked up in the tenant. */
async function identityId(api: ApiTransport, tenantId: string, value: string): Promise<string> {
  if (!value.includes('@')) return value;
  const found = await api.call<{ id: string; email?: string }[]>('identities/list', {
    tenantId,
    query: value,
    limit: 20,
  });
  const match = found.filter((identity) => identity.email?.toLowerCase() === value.toLowerCase());
  if (match.length !== 1)
    throw new CliError('NOT_FOUND', `No single identity in ${tenantId} has the email ${value}`);
  return match[0]!.id;
}

async function desiredConfig(context: CommandContext<FlagSpecs>, input: string, tenantId?: string) {
  return loadTenantConfig(context.path(input), {
    ...(tenantId ? { tenantId } : {}),
    env: context.env,
  });
}

/** Token commands: they act as BETTER_IAM_TOKEN or a saved session, in process or against --url. */
export const accessCommands = [
  defineCommand({
    name: 'config-export',
    group: 'Access',
    summary: "Print or save a tenant's configuration as code",
    description:
      "config-export writes a tenant's roles, policies, groups, resource types, group bindings, packages, invariants, and agreements as JSON (or as a typed module when --output ends in .ts or .mjs). The config commands act as the session or API key in BETTER_IAM_TOKEN (or the session saved by login) and are authorized and audited like console operations.",
    target: 'token',
    flags: {
      tenant: tenantFlag,
      output: {
        type: 'string',
        value: 'PATH',
        description:
          'Write to this file instead (.json, or .ts/.mjs for a module); never overwrites',
      },
    },
    examples: ['better-iam config-export --tenant ten_123 --output iam/tenant.config.ts'],
    async run(context) {
      const { flags, api, path, io } = context;
      const tenantId = flags.tenant!;
      const exported = await (await api()).call<TenantConfig>('config/export', { tenantId });
      if (!flags.output) return exported;
      const output = path(flags.output);
      const body = /\.(m?[jt]s)$/i.test(output)
        ? tenantConfigModule(exported, output)
        : JSON.stringify(exported, null, 2) + '\n';
      await writeFile(output, body, { flag: 'wx' });
      // The confirmation stays one line, as before; --format json indents it.
      io.out(formatResult({ tenantId, output }, flags.format ?? 'compact', flags.query));
    },
  }),
  ...(['config-plan', 'config-apply'] as const).map((name) =>
    defineCommand({
      name,
      group: 'Access',
      summary:
        name === 'config-plan'
          ? 'Show what applying a configuration would change'
          : 'Apply a configuration to a tenant in one transaction',
      description:
        name === 'config-plan'
          ? 'config-plan shows what config-apply would change (--prune also plans deleting items the file omits); --fail-on-drift exits non-zero when anything would change, for CI. The input can be JSON or a JavaScript/TypeScript module whose default export is the configuration or a factory receiving { tenantId, env }.'
          : 'config-apply applies a configuration in one transaction (--prune also deletes items the file omits), authorized and audited like console operations.',
      target: 'token',
      flags: {
        tenant: tenantFlag,
        input: inputFlag,
        prune: { type: 'boolean', description: 'Also delete items the file omits' },
        ...(name === 'config-plan'
          ? {
              'fail-on-drift': {
                type: 'boolean' as const,
                description: 'Exit non-zero when anything would change (CI)',
              },
            }
          : {}),
      },
      examples:
        name === 'config-plan'
          ? ['better-iam config-plan --tenant ten_123 --input iam/tenant.config.ts --fail-on-drift']
          : ['better-iam config-apply --tenant ten_123 --input iam/tenant.config.ts --prune'],
      async run(context) {
        const { flags, api, print } = context;
        const tenantId = flags.tenant!;
        const config = await desiredConfig(context, flags.input!, tenantId);
        const result = await (
          await api()
        ).call<ConfigPlan>(name === 'config-plan' ? 'config/plan' : 'config/apply', {
          tenantId,
          config,
          prune: flags.prune,
        });
        print(result);
        const drift = result.summary.create + result.summary.update + result.summary.delete;
        if ((flags as { 'fail-on-drift'?: boolean })['fail-on-drift'] && drift > 0)
          throw new IamError(
            'CONFIG_DRIFT',
            `The tenant differs from the configuration in ${drift} item(s)`,
          );
      },
    }),
  ),
  defineCommand({
    name: 'config-validate',
    group: 'Access',
    summary: 'Check a configuration file offline, without a database or token',
    description:
      'config-validate checks a configuration file offline: its shape, and names it refers to that the file does not define (those must already exist in the tenant, or planning fails). --strict exits non-zero on such warnings. It needs no configuration, database, or token, so it fits pre-commit hooks and CI.',
    flags: {
      input: inputFlag,
      tenant: {
        type: 'string',
        value: 'TENANT_ID',
        description: 'Passed to a configuration factory as tenantId',
      },
      strict: {
        type: 'boolean',
        description: 'Exit non-zero when a reference is not defined in the file',
      },
    },
    async run(context) {
      const { flags, print } = context;
      const lint = lintTenantConfig(await desiredConfig(context, flags.input!, flags.tenant));
      print(lint);
      if (flags.strict && lint.warnings.length)
        throw new IamError('CONFIG_WARNINGS', `${lint.warnings.length} unresolved reference(s)`);
    },
  }),
  defineCommand({
    name: 'analyze',
    group: 'Access',
    summary: "Print a tenant's access-analysis findings",
    description:
      "analyze prints the tenant's access-analysis findings (as BETTER_IAM_TOKEN, which needs iam:analysis:read); with --fail-on it exits non-zero when an unsuppressed finding of that severity or higher exists, for CI and cron.",
    target: 'token',
    flags: {
      tenant: tenantFlag,
      'dormant-days': {
        type: 'integer',
        min: 1,
        max: 36500,
        description: 'Days without sign-in after which an identity counts as dormant',
      },
      'fail-on': {
        type: 'string',
        choices: severities,
        description: 'Exit non-zero on a finding of this severity or higher',
      },
    },
    examples: ['better-iam analyze --tenant ten_123 --fail-on high --format table'],
    async run({ flags, api, print }) {
      const report = await (
        await api()
      ).call<{ findings: AccessFinding[] }>('analysis/findings', {
        tenantId: flags.tenant!,
        ...(flags['dormant-days'] === undefined ? {} : { dormantDays: flags['dormant-days'] }),
      });
      print(report);
      const failOn = flags['fail-on'];
      if (failOn) {
        const threshold = severities.indexOf(failOn as (typeof severities)[number]);
        const failing = report.findings.filter(
          (finding) => severities.indexOf(finding.severity) <= threshold,
        );
        if (failing.length)
          throw new IamError(
            'FINDINGS',
            `${failing.length} finding(s) at or above ${failOn} severity`,
          );
      }
    },
  }),
  defineCommand({
    name: 'report',
    group: 'Access',
    summary: "Print a tenant's access report",
    description:
      "report prints the tenant's access report as BETTER_IAM_TOKEN: identities and bindings ending within --within-days (30), keys unused for --unused-days (30) or ending soon, live activations, and pending activation requests.",
    target: 'token',
    flags: {
      tenant: tenantFlag,
      'within-days': {
        type: 'integer',
        min: 0,
        max: 3650,
        default: 30,
        description: 'Access ending within this many days',
      },
      'unused-days': {
        type: 'integer',
        min: 0,
        max: 3650,
        default: 30,
        description: 'Keys unused for this many days',
      },
    },
    async run({ flags, api }) {
      return (await api()).call('reports/access', {
        tenantId: flags.tenant!,
        withinMs: (flags['within-days'] ?? 30) * day,
        unusedForMs: (flags['unused-days'] ?? 30) * day,
      });
    },
  }),
  defineCommand({
    name: 'mine-roles',
    group: 'Access',
    summary: 'Suggest roles from how access is actually held',
    description:
      'mine-roles prints role-mining suggestions (role bundles, roles to bind to a group, redundant direct bindings, duplicate roles) and peer outliers grouped by --peer-by (default manager) as BETTER_IAM_TOKEN, which needs iam:analysis:read.',
    target: 'token',
    flags: {
      tenant: tenantFlag,
      'peer-by': {
        type: 'string',
        value: 'manager|attribute:NAME',
        description: 'How peers are grouped for outliers',
      },
    },
    async run({ flags, api }) {
      const transport = await api();
      const tenantId = flags.tenant!;
      const mining = await transport.call<Record<string, unknown>>('roleMining/suggest', {
        tenantId,
      });
      const peers = await transport.call('roleMining/outliers', {
        tenantId,
        ...(flags['peer-by'] === undefined ? {} : { peerBy: flags['peer-by'] }),
      });
      return { ...mining, peers };
    },
  }),
  defineCommand({
    name: 'check-invariants',
    group: 'Access',
    summary: "Evaluate a tenant's access invariants",
    description:
      "check-invariants evaluates the tenant's access invariants as BETTER_IAM_TOKEN (iam:invariants:read); --fail-on-broken exits non-zero when one is broken or cannot be evaluated, for CI after config-apply.",
    target: 'token',
    flags: {
      tenant: tenantFlag,
      'fail-on-broken': {
        type: 'boolean',
        description: 'Exit non-zero when an invariant is broken or unevaluable',
      },
    },
    async run({ flags, api, print }) {
      const run = await (
        await api()
      ).call<InvariantRunResult>('invariants/run', {
        tenantId: flags.tenant!,
      });
      print(run);
      if (flags['fail-on-broken'] && run.summary.failed + run.summary.errors > 0)
        throw new IamError(
          'INVARIANTS_BROKEN',
          `${run.summary.failed} broken and ${run.summary.errors} unevaluable invariant(s)`,
        );
    },
  }),
  defineCommand({
    name: 'whoami',
    group: 'Access',
    summary: 'Print who the current token acts as',
    description:
      'whoami prints who BETTER_IAM_TOKEN acts as (sts.getCallerIdentity): identity, tenant, session kind and id, format, MFA, expiry, and any role, trust, session name, or web identity; it needs no permission and records nothing, so it also checks that a session, API key, role session, or session token (opaque or JWT) is still valid. Without BETTER_IAM_TOKEN it reports the session saved by login.',
    target: 'token',
    async run({ api }) {
      // sts.getCallerIdentity: no permission, no audit event; an unusable credential fails with UNAUTHENTICATED.
      return (await api()).call<CallerIdentity>('sts/getCallerIdentity');
    },
  }),
  defineCommand({
    name: 'can',
    group: 'Access',
    summary: 'Check whether the current token may perform an action',
    description:
      'can asks whether the token may perform ACTION on RESOURCE (type/id) in the tenant and prints the decision with its reason; it exits non-zero (ACCESS_DENIED) when the answer is no, so scripts can branch on it. The decision is recorded like any authorization check.',
    target: 'token',
    args: [
      { name: 'action', description: 'The action, for example projects:read', required: true },
      {
        name: 'resource',
        description: 'type/id or type:id, for example project/p1',
        required: true,
      },
    ],
    flags: { tenant: tenantFlag },
    examples: ['better-iam can projects:read project/p1 --tenant ten_123'],
    async run({ flags, args, api, print }) {
      const decision = await (
        await api()
      ).call<{ allowed: boolean; reason?: string }>('authorize', {
        tenantId: flags.tenant!,
        action: args[0]!,
        resource: parseResource(args[1]!),
      });
      print(decision);
      if (!decision.allowed)
        throw new IamError(
          'ACCESS_DENIED',
          `Not allowed${decision.reason ? `: ${decision.reason}` : ''}`,
          403,
        );
    },
  }),
  defineCommand({
    name: 'explain',
    group: 'Access',
    summary: 'Explain why an identity is or is not allowed an action',
    description:
      'explain simulates the decision for another identity (by ID or email) without signing in as them: the matching statements, boundaries, and reason (policies.simulate, which needs iam:policies:simulate). --assume-mfa evaluates as if they had used MFA.',
    target: 'token',
    args: [
      { name: 'action', description: 'The action, for example projects:write', required: true },
      { name: 'resource', description: 'type/id or type:id', required: true },
    ],
    flags: {
      tenant: tenantFlag,
      identity: {
        type: 'string',
        value: 'ID|EMAIL',
        required: true,
        description: 'Whose decision to explain',
      },
      'assume-mfa': { type: 'boolean', description: 'Evaluate as an MFA session' },
    },
    examples: ['better-iam explain projects:write project/p1 --identity alice@acme.test'],
    async run({ flags, args, api }) {
      const transport = await api();
      const tenantId = flags.tenant!;
      return transport.call('policies/simulate', {
        tenantId,
        identityId: await identityId(transport, tenantId, flags.identity!),
        action: args[0]!,
        resource: parseResource(args[1]!),
        assumeMfa: flags['assume-mfa'],
      });
    },
  }),
  defineCommand({
    name: 'who-can',
    group: 'Access',
    summary: 'List every identity that may perform an action on a resource',
    description:
      'who-can lists every active identity of the tenant that could perform ACTION on RESOURCE, with the reason (policies.whoCan, which needs iam:policies:simulate); root administrators are not listed because their override applies everywhere.',
    target: 'token',
    args: [
      { name: 'action', description: 'The action', required: true },
      { name: 'resource', description: 'type/id or type:id', required: true },
    ],
    flags: {
      tenant: tenantFlag,
      kind: {
        type: 'string',
        choices: ['user', 'service'],
        description: 'Only people or only service accounts',
      },
      'assume-mfa': { type: 'boolean', description: 'Evaluate as MFA sessions' },
      limit: {
        type: 'integer',
        min: 1,
        max: 1000,
        default: 100,
        description: 'Most identities listed',
      },
    },
    examples: ['better-iam who-can projects:delete project/p1 --format table'],
    async run({ flags, args, api }) {
      return (await api()).call('policies/whoCan', {
        tenantId: flags.tenant!,
        action: args[0]!,
        resource: parseResource(args[1]!),
        ...(flags.kind ? { kind: flags.kind } : {}),
        assumeMfa: flags['assume-mfa'],
        ...(flags.limit === undefined ? {} : { limit: flags.limit }),
      });
    },
  }),
];
