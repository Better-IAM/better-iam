import Link from 'next/link';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Certifications({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const [campaigns, roles, members, mine] = await Promise.all([
    tryRead(() => iam.api.certifications.list(auth, { tenantId })),
    tryRead(() => iam.api.roles.list(auth, { tenantId })),
    tryRead(() => iam.api.identities.list(auth, { tenantId })),
    tryRead(() => iam.api.certifications.listMine(auth, { tenantId })),
  ]);
  const assigned = (mine ?? []).filter((campaign) => campaign.items.length);
  const people = (members ?? []).filter(
    (identity) => identity.kind === 'user' && identity.status === 'active',
  );
  return (
    <>
      <PageHeader
        title="Access certifications"
        description="Periodic reviews of who holds which role. Reviewers keep or revoke each binding; closing a campaign removes what was revoked."
      />
      <div className="stack">
        {assigned.map((campaign) => (
          <Card
            key={campaign.id}
            title={`Assigned to you: ${campaign.name}`}
            description={
              <>
                You are the manager of these people. {campaign.progress.decided} of{' '}
                {campaign.progress.total} decided
                {campaign.dueAt ? (
                  <>
                    {' '}
                    · due <Time value={campaign.dueAt} />
                  </>
                ) : null}
                .
              </>
            }
            flush
          >
            <Table
              head={['Person', 'Role', 'Decision', '']}
              rows={campaign.items.map((item) => [
                item.subjectName,
                item.roleName,
                item.decision ? (
                  <Badge key="d" tone={item.decision === 'keep' ? 'success' : 'warning'}>
                    {item.decision}
                  </Badge>
                ) : (
                  <span key="d" className="muted">
                    undecided
                  </span>
                ),
                <span key="a" className="actions">
                  <ApiButton
                    path="certifications/review"
                    body={{
                      tenantId,
                      campaignId: campaign.id,
                      decisions: [{ itemId: item.id, decision: 'keep' }],
                    }}
                    label="Keep"
                    tenantId={tenantId}
                  />
                  <ApiButton
                    path="certifications/review"
                    body={{
                      tenantId,
                      campaignId: campaign.id,
                      decisions: [{ itemId: item.id, decision: 'revoke' }],
                    }}
                    label="Revoke"
                    tone="danger"
                    tenantId={tenantId}
                  />
                </span>,
              ])}
            />
          </Card>
        ))}
        <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
          <Card title="Campaigns" flush>
            {campaigns ? (
              <Table
                head={['Campaign', 'Status', 'Progress', 'Due', 'Created']}
                rows={campaigns.map((campaign) => [
                  <Link key="n" href={`${base}/certifications/${campaign.id}`}>
                    {campaign.name}
                  </Link>,
                  campaign.status === 'open' ? (
                    <Badge key="s" tone="warning">
                      open
                    </Badge>
                  ) : (
                    <Badge key="s" tone="success">
                      closed
                    </Badge>
                  ),
                  `${campaign.progress.decided} / ${campaign.progress.total} decided`,
                  <Time key="d" value={campaign.dueAt} />,
                  <Time key="c" value={campaign.createdAt} />,
                ])}
                empty="No campaigns yet."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:certifications:read</code>.
              </div>
            )}
          </Card>
          <div className="stack">
            <Card
              title="Start a campaign"
              description="Requires iam:certifications:manage. Owner roles are never included."
            >
              <ApiForm
                path="certifications/create"
                tenantId={tenantId}
                submitLabel="Start campaign"
                resetOnSuccess
                successMessage="Campaign started."
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  { name: 'name', label: 'Name', required: true, placeholder: 'Q3 access review' },
                  {
                    name: 'roleIds',
                    label: 'Roles',
                    type: 'multiselect',
                    options: (roles ?? [])
                      .filter((role) => !role.protected)
                      .map((role) => ({ value: role.id, label: role.name })),
                    help: 'Leave empty to review every role.',
                  },
                  {
                    name: 'reviewerMode',
                    label: 'Who reviews',
                    type: 'select',
                    options: [
                      { value: 'named', label: 'The reviewers below' },
                      { value: 'manager', label: "Each person's manager" },
                    ],
                    help: 'With managers, people without a manager (and groups) go to the reviewers below.',
                  },
                  {
                    name: 'reviewerIds',
                    label: 'Reviewers',
                    type: 'multiselect',
                    options: people.map((person) => ({
                      value: person.id,
                      label: person.email ?? person.name,
                    })),
                    help: 'Leave empty to let anyone holding iam:certifications:review decide.',
                  },
                  { name: 'dueAt', label: 'Due', type: 'datetime' },
                  {
                    name: 'autoClose',
                    label: 'Close and apply automatically when due',
                    type: 'checkbox',
                    help: 'Needs a due date and the close-certifications job (CLI or iam.closeOverdueCertifications).',
                  },
                  {
                    name: 'undecided',
                    label: 'When closing, undecided access is',
                    type: 'select',
                    options: [
                      { value: 'keep', label: 'Kept' },
                      { value: 'revoke', label: 'Revoked' },
                    ],
                  },
                ]}
              />
            </Card>
            <Alert tone="info">
              Reviewers never decide on their own access. Revocations run under the closing
              administrator&apos;s authority; bindings a higher authority granted are reported
              instead of removed.
            </Alert>
          </div>
        </div>
      </div>
    </>
  );
}
