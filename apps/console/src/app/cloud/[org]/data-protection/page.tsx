import Link from 'next/link';
import { ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Table } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const dataTypeLabel: Record<string, string> = {
  card: 'Card numbers',
  ssn: 'Social security numbers',
  email: 'Email addresses',
  phone: 'Phone numbers',
  generic: 'Other values',
};

export default async function DataProtection({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const profiles = await tryRead(() => iam.api.protection.listProfiles(auth, { tenantId }));
  const profileOptions = (profiles ?? []).map((profile) => ({
    value: profile.name,
    label: `${profile.name} (${profile.dataType})`,
  }));
  return (
    <>
      <PageHeader
        title="Data protection"
        description="Replace card numbers, identifiers and personal data with tokens. Values are encrypted under a KMS key; reading one back is decided per profile and purpose, and audited without the value."
      />
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <Card title="Profiles" flush>
          {profiles ? (
            <Table
              head={['Profile', 'Values', 'Format', 'Tokens', 'Mask', 'Key']}
              rows={profiles.map((profile) => [
                <span key="n" className="stack">
                  <code>{profile.name}</code>
                  {profile.description && (
                    <span className="small muted">{profile.description}</span>
                  )}
                </span>,
                dataTypeLabel[profile.dataType] ?? profile.dataType,
                <span key="f" className="stack">
                  <span>{profile.format}</span>
                  {profile.deterministic && <Badge tone="info">deterministic</Badge>}
                  {profile.retentionDays && (
                    <span className="small muted">kept {profile.retentionDays} days</span>
                  )}
                </span>,
                (profile.tokens ?? 0).toLocaleString('en-US'),
                <code key="m" className="small">
                  {profile.mask}
                </code>,
                <Link key="k" href={`${base}/keys/${profile.keyId}`}>
                  KMS key
                </Link>,
              ])}
              empty="No profiles yet."
            />
          ) : (
            <div className="empty">
              Requires <code>iam:protection:read</code>.
            </div>
          )}
        </Card>
        <Card
          title="Create a profile"
          description="Requires iam:protection:manage. A new AES key is created in Keys unless you name one."
        >
          <ApiForm
            path="protection/createProfile"
            tenantId={tenantId}
            submitLabel="Create profile"
            resetOnSuccess
            fields={[
              { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
              { name: 'name', label: 'Name', required: true, placeholder: 'cards' },
              {
                name: 'dataType',
                label: 'Values',
                type: 'select',
                required: true,
                defaultValue: 'card',
                options: Object.entries(dataTypeLabel).map(([value, label]) => ({ value, label })),
              },
              {
                name: 'format',
                label: 'Token format',
                type: 'select',
                options: [
                  { value: 'format-preserving', label: 'Format-preserving' },
                  { value: 'random', label: 'Random (tok_…)' },
                ],
              },
              {
                name: 'deterministic',
                label:
                  'Same value, same token (for joins and counts; required for format-preserving SSNs and phone numbers)',
                type: 'checkbox',
              },
              {
                name: 'retentionDays',
                label: 'Delete tokens after (days)',
                type: 'number',
              },
              { name: 'description', label: 'Description' },
            ]}
          />
        </Card>
      </div>
      {profiles && profiles.length > 0 && (
        <div className="grid cols-2">
          <Card
            title="Tokenize"
            description="Requires iam:protection:tokenize. One value per line."
          >
            <ApiForm
              path="protection/tokenize"
              tenantId={tenantId}
              submitLabel="Tokenize"
              showResult
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                {
                  name: 'profile',
                  label: 'Profile',
                  type: 'select',
                  required: true,
                  options: profileOptions,
                },
                {
                  name: 'values',
                  label: 'Values',
                  type: 'list',
                  required: true,
                  help: 'Comma separated.',
                },
              ]}
            />
          </Card>
          <Card
            title="Read back"
            description="Masking needs iam:protection:mask; detokenizing needs iam:protection:detokenize for the purpose."
          >
            <ApiForm
              path="protection/mask"
              tenantId={tenantId}
              submitLabel="Show masked"
              showResult
              compact
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                {
                  name: 'profile',
                  label: 'Profile',
                  type: 'select',
                  required: true,
                  options: profileOptions,
                },
                { name: 'tokens', label: 'Tokens', type: 'list', required: true },
              ]}
            />
            <ApiForm
              path="protection/detokenize"
              tenantId={tenantId}
              submitLabel="Detokenize"
              showResult
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                {
                  name: 'profile',
                  label: 'Profile',
                  type: 'select',
                  required: true,
                  options: profileOptions,
                },
                { name: 'tokens', label: 'Tokens', type: 'list', required: true },
                {
                  name: 'purpose',
                  label: 'Purpose',
                  required: true,
                  placeholder: 'fraud-review',
                  help: 'Recorded in the audit log and checked by policies (resource.purpose).',
                },
              ]}
            />
          </Card>
        </div>
      )}
      <Alert tone="info">
        Let collecting services tokenize without reading back: grant{' '}
        <code>iam:protection:tokenize</code> to them, and <code>iam:protection:detokenize</code>{' '}
        only where <code>resource.purpose</code> names the purpose that needs the value.
      </Alert>
    </>
  );
}
