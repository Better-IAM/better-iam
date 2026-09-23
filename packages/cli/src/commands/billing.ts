import { defineCommand } from '../framework.js';
import { tenantFlag } from './access.js';

const periodFlag = {
  type: 'string',
  value: 'YYYY-MM',
  description: 'The billing month',
} as const;
const groupings = ['meter', 'identity', 'agent', 'team', 'department', 'tenant', 'day'] as const;

/** Billing: the scheduler jobs (no credential) and the spend report (as BETTER_IAM_TOKEN). */
export const billingCommands = [
  defineCommand({
    name: 'billing-close',
    group: 'Operations',
    summary: 'Issue billing statements for a month that has ended',
    description:
      'billing-close invoices every billing account with something to bill in --period (default: last month): usage, subscription fees and seats, and pending invoice items. It skips accounts already invoiced, applies coupons and credit, emails the invoices, and deletes raw usage events past their retention; a deployment operation for a daily scheduler. With --draft (or billing.autoFinalize: false) invoices stay drafts, refreshed on each run, until finalized.',
    target: 'config',
    flags: {
      period: periodFlag,
      tenant: {
        type: 'string',
        value: 'TENANT_ID',
        description: 'Only the billing account that pays for this tenant',
      },
      draft: {
        type: 'boolean',
        description: 'Keep the invoices as drafts to review and finalize',
      },
    },
    examples: [
      'better-iam billing-close',
      'better-iam billing-close --period 2026-08',
      'better-iam billing-close --draft',
    ],
    async run({ iam, flags }) {
      return (await iam()).billing.closePeriod({
        ...(flags.period ? { period: flags.period } : {}),
        ...(flags.tenant ? { tenantId: flags.tenant } : {}),
        ...(flags.draft ? { draft: true } : {}),
      });
    },
  }),
  defineCommand({
    name: 'billing-reminders',
    group: 'Operations',
    summary: 'Remind billing contacts of unpaid invoices',
    description:
      'billing-reminders emails the billing contacts of every finalized invoice with an amount due as payment-reminder at the steps of billing.paymentReminderDays (default 3 days before the due date, on it, and 7 and 14 days after), once per step; each is audited as billing:payment-reminder. Run it daily.',
    target: 'config',
    flags: {},
    async run({ iam }) {
      return (await iam()).billing.sendPaymentReminders();
    },
  }),
  defineCommand({
    name: 'billing-alerts',
    group: 'Operations',
    summary: 'Send spend-budget alerts',
    description:
      'billing-alerts checks every spend budget (or those one --tenant owns) and alerts, once per threshold and window, on thresholds reached and projections past the budget: audited as billing:budget-alert and emailed as spend-alert when mail is configured. Run it hourly.',
    target: 'config',
    flags: {
      tenant: {
        type: 'string',
        value: 'TENANT_ID',
        description: 'Only budgets this tenant owns (default: every budget)',
      },
    },
    async run({ iam, flags }) {
      return (await iam()).billing.checkBudgets(flags.tenant ? { tenantId: flags.tenant } : {});
    },
  }),
  defineCommand({
    name: 'billing-anomalies',
    group: 'Operations',
    summary: 'Alert on spend spikes from yesterday',
    description:
      'billing-anomalies checks every billing account (or the one paying for --tenant) for people, teams and meters whose spend on --day (default yesterday) is --factor (3) times their average over the 14 days before and --minimum (10) currency units more; each is audited as billing:anomaly once and emailed as spend-anomaly when mail is configured. Run it daily.',
    target: 'config',
    flags: {
      tenant: {
        type: 'string',
        value: 'TENANT_ID',
        description: 'Only the billing account that pays for this tenant',
      },
      day: { type: 'string', value: 'YYYY-MM-DD', description: 'The day to check' },
      factor: {
        type: 'integer',
        min: 2,
        max: 1000,
        default: 3,
        description: 'Times the usual daily spend that counts as a spike',
      },
      minimum: {
        type: 'integer',
        min: 0,
        max: 1_000_000,
        default: 10,
        description: 'Smallest spend and increase worth reporting, in currency units',
      },
    },
    async run({ iam, flags }) {
      return (await iam()).billing.detectAnomalies({
        ...(flags.tenant ? { tenantId: flags.tenant } : {}),
        ...(flags.day ? { day: flags.day } : {}),
        ...(flags.factor !== undefined ? { factor: flags.factor } : {}),
        ...(flags.minimum !== undefined ? { minimum: flags.minimum } : {}),
      });
    },
  }),
  defineCommand({
    name: 'billing-seats',
    group: 'Operations',
    summary: 'Record one seat per active person for today',
    description:
      'billing-seats records one unit of --meter (default seats) for every active person of every tenant the meter reaches, once per day; a sum meter then counts seat-days and a unique meter active seats per month. Run it daily.',
    target: 'config',
    flags: {
      meter: {
        type: 'string',
        value: 'KEY',
        default: 'seats',
        description: 'The meter seats are recorded on',
      },
      tenant: {
        type: 'string',
        value: 'TENANT_ID',
        description: 'Only this tenant and the tenants below it',
      },
      'include-service-accounts': {
        type: 'boolean',
        description: 'Count service accounts and agents as seats too',
      },
    },
    async run({ iam, flags }) {
      return (await iam()).billing.recordSeats({
        ...(flags.meter ? { meter: flags.meter } : {}),
        ...(flags.tenant ? { tenantId: flags.tenant } : {}),
        ...(flags['include-service-accounts'] ? { kinds: ['user', 'service', 'agent'] } : {}),
      });
    },
  }),
  defineCommand({
    name: 'spend',
    group: 'Access',
    summary: "Print a tenant's spend for a month",
    description:
      'spend prints the spend of the tenant and the tenants below it as BETTER_IAM_TOKEN (iam:billing:read), grouped by --group-by (default meter) and optionally narrowed to a --team, --department, --identity or --meter; the current month also carries a linear forecast.',
    target: 'token',
    flags: {
      tenant: tenantFlag,
      period: periodFlag,
      'group-by': {
        type: 'string',
        choices: groupings,
        default: 'meter',
        description: 'How rows are grouped',
      },
      team: {
        type: 'string',
        value: 'TEAM_ID',
        description: 'Only this team (with its sub-teams)',
      },
      department: {
        type: 'string',
        value: 'DEPARTMENT_ID',
        description: 'Only this department (with those below it)',
      },
      identity: {
        type: 'string',
        value: 'IDENTITY_ID',
        description: 'Only this person or account',
      },
      meter: { type: 'string', value: 'KEY', description: 'Only this meter' },
    },
    examples: [
      'better-iam spend --tenant acme-id --group-by team',
      'better-iam spend --period 2026-08',
    ],
    async run({ flags, api }) {
      return (await api()).call('billing/spend', {
        tenantId: flags.tenant!,
        groupBy: flags['group-by'] ?? 'meter',
        ...(flags.period ? { period: flags.period } : {}),
        ...(flags.team ? { teamId: flags.team } : {}),
        ...(flags.department ? { departmentId: flags.department } : {}),
        ...(flags.identity ? { identityId: flags.identity } : {}),
        ...(flags.meter ? { meter: flags.meter } : {}),
      });
    },
  }),
];
