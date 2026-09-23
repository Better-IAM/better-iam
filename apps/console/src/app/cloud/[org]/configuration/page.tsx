import { ApiForm } from '@/components/api-form';
import { Alert, Card, Json, PageHeader } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

/** Configuration as code: export the organization's access model, preview a change, and apply it atomically. */
export default async function Configuration({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, tenant } = await orgPage(org);
  const exported = await tryRead(() => iam.api.config.export(auth, { tenantId }));
  const template = JSON.stringify(
    exported ?? {
      version: 1,
      roles: [{ name: 'Reader', permissions: ['workspaces:read'] }],
      groups: [{ name: 'Everyone', members: [] }],
      bindings: [{ group: 'Everyone', role: 'Reader' }],
    },
    null,
    2,
  );
  return (
    <>
      <PageHeader
        title="Configuration"
        description="Roles, policies, groups, resource types, and group bindings as one JSON document, keyed by name. Keep it in version control and apply the same file to staging and production."
      />
      <div className="stack">
        {!exported && (
          <Alert tone="warning">
            Exporting requires <code>iam:config:read</code>; applying also requires{' '}
            <code>iam:config:apply</code> plus the permission for each change.
          </Alert>
        )}
        <div className="grid cols-2">
          <Card
            title="Current configuration"
            description="What config-export returns now. Members and their direct role bindings are runtime state and are not included."
          >
            {exported ? <Json value={exported} /> : <p className="muted">Not available.</p>}
          </Card>
          <div className="stack">
            <Card
              title="Plan"
              description="A dry run: every create, update, and delete the document would cause. Nothing is written."
            >
              <ApiForm
                path="config/plan"
                tenantId={tenantId}
                submitLabel="Plan"
                showResult
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'config',
                    label: 'Configuration',
                    type: 'json',
                    required: true,
                    rows: 14,
                    defaultValue: template,
                  },
                  {
                    name: 'prune',
                    label: 'Prune: delete items of a listed kind that the document omits',
                    type: 'checkbox',
                  },
                ]}
              />
            </Card>
            <Card
              title="Apply"
              description="Applies the document in one transaction. Each change is authorized like the direct operation; one refusal rolls everything back. The apply is recorded as config:apply."
            >
              <ApiForm
                path="config/apply"
                tenantId={tenantId}
                submitLabel="Apply configuration"
                showResult
                successMessage="Applied."
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'config',
                    label: 'Configuration',
                    type: 'json',
                    required: true,
                    rows: 14,
                    defaultValue: template,
                  },
                  {
                    name: 'prune',
                    label: 'Prune: delete items of a listed kind that the document omits',
                    type: 'checkbox',
                  },
                ]}
              />
            </Card>
          </div>
        </div>
        <Card
          title="Elevation defaults"
          description="Floors for every eligible role in this organization: a binding can be stricter, never looser. Replaces the current settings; needs a recent sign-in and iam:tenants:update."
        >
          <ApiForm
            path="tenants/setAccessPolicy"
            tenantId={tenantId}
            submitLabel="Save defaults"
            successMessage="Saved."
            compact
            fields={[
              { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
              {
                name: 'maxActivationMs',
                label: 'Longest activation (minutes)',
                type: 'number',
                multiplier: 60_000,
                group: 'accessPolicy',
                defaultValue: tenant.accessPolicy?.maxActivationMs
                  ? String(Math.round(tenant.accessPolicy.maxActivationMs / 60_000))
                  : '',
                help: 'Caps every binding; empty leaves each binding to its own maximum (one hour by default).',
              },
              {
                name: 'approvalLifetimeMs',
                label: 'Requests lapse after (hours)',
                type: 'number',
                multiplier: 3_600_000,
                group: 'accessPolicy',
                defaultValue: tenant.accessPolicy?.approvalLifetimeMs
                  ? String(Math.round(tenant.accessPolicy.approvalLifetimeMs / 3_600_000))
                  : '',
              },
              {
                name: 'requireJustification',
                label: 'Every activation needs a justification',
                type: 'checkbox',
                group: 'accessPolicy',
                defaultValue: tenant.accessPolicy?.requireJustification === true,
              },
              {
                name: 'requireMfa',
                label: 'Every activation needs an MFA session',
                type: 'checkbox',
                group: 'accessPolicy',
                defaultValue: tenant.accessPolicy?.requireMfa === true,
              },
              {
                name: 'requireApproval',
                label: 'Every activation needs approval',
                type: 'checkbox',
                group: 'accessPolicy',
                defaultValue: tenant.accessPolicy?.requireApproval === true,
              },
            ]}
          />
        </Card>
        <Alert tone="info">
          From a terminal:{' '}
          <code>better-iam config-export --tenant {tenantId} --output tenant.json</code>, then{' '}
          <code>config-plan</code> and <code>config-apply --input tenant.json</code> with{' '}
          <code>BETTER_IAM_TOKEN</code> set to an API key or session token.
        </Alert>
      </div>
    </>
  );
}
