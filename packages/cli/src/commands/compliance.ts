import { defineCommand } from '../framework.js';

/** Compliance center: the scheduler job (no credential). */
export const complianceCommands = [
  defineCommand({
    name: 'compliance-evaluate',
    group: 'Operations',
    summary: 'Evaluate compliance controls',
    description:
      "compliance-evaluate runs the enabled compliance controls of every active tenant (or one --tenant's), records the results and a run, and audits it as compliance:evaluate. Tenants whose evaluation failed are listed under failed; their controls show as stale after three days. A deployment operation; run it daily.",
    target: 'config',
    flags: {
      tenant: { type: 'string', value: 'TENANT_ID', description: 'Only this tenant' },
    },
    async run({ iam, flags }) {
      return (await iam()).compliance.evaluateAll(flags.tenant ? { tenantId: flags.tenant } : {});
    },
  }),
];
