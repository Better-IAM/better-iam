import { defineCommand } from '../framework.js';

/** Verifiable credentials: the scheduler job (no credential). */
export const vcCommands = [
  defineCommand({
    name: 'vc-sweep',
    group: 'Operations',
    summary: 'Revoke verifiable credentials of people who left',
    description:
      'vc-sweep revokes every valid verifiable credential (or one --tenant\'s) whose holder is no longer an active member, in the Token Status List verifiers read, and audits each as vc:credential:revoke. A deployment operation; run it hourly.',
    target: 'config',
    flags: {
      tenant: { type: 'string', value: 'TENANT_ID', description: 'Only this tenant' },
    },
    async run({ iam, flags }) {
      return (await iam()).verifiableCredentials.sweep(flags.tenant ? { tenantId: flags.tenant } : {});
    },
  }),
];
