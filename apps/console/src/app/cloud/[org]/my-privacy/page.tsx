import { ApiButton, ApiForm } from '@/components/api-form';
import { PrivacyExportButton } from '@/components/privacy-export';
import { Alert, Badge, Card, PageHeader, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import {
  consentReasonLabels,
  legalBasisLabels,
  requestStatusTone,
  requestTypeLabels,
} from '@/lib/privacy';
import { tryRead } from '@/lib/session';

const askOptions = [
  { value: 'access', label: 'Send me a copy of my data' },
  { value: 'portability', label: 'Give me my data in a portable format' },
  { value: 'rectification', label: 'Correct my data' },
  { value: 'erasure', label: 'Delete my account and data' },
  { value: 'restriction', label: 'Pause processing of my data' },
  { value: 'objection', label: 'Object to processing based on legitimate interests' },
  { value: 'opt-out', label: 'Do not sell or share my data' },
];

export default async function MyPrivacy({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId } = await orgPage(org);
  const mine = await tryRead(() => iam.api.privacy.mine(auth, { tenantId }));
  return (
    <>
      <PageHeader
        title="Your privacy"
        description="What this organization uses your personal data for, the choices you have, and requests about your data."
      />
      {!mine ? (
        <Alert tone="warning">Privacy choices are made from your own signed-in session.</Alert>
      ) : (
        <div className="stack">
          {mine.restricted && (
            <Alert tone="info">
              Processing of your data is restricted at your request: only what the law requires
              continues.
            </Alert>
          )}
          <Card
            title="How your data is used"
            description="Turn optional uses on or off at any time. Uses marked as needed to provide the service do not depend on your choice."
            flush
          >
            <Table
              head={['Use', 'Why', 'Status', '']}
              rows={mine.purposes.map((purpose) => [
                <span key="n">
                  <strong>{purpose.name}</strong>
                  <br />
                  <span className="small muted">{purpose.description}</span>
                  {purpose.dataCategories.length > 0 && (
                    <>
                      <br />
                      <span className="small muted">Data: {purpose.dataCategories.join(', ')}</span>
                    </>
                  )}
                </span>,
                <span key="b" className="small">
                  {legalBasisLabels[purpose.legalBasis] ?? purpose.legalBasis}
                  {purpose.retentionDays ? ` · kept ${purpose.retentionDays} days` : ''}
                </span>,
                <Badge key="s" tone={purpose.state.allowed ? 'success' : 'neutral'}>
                  {consentReasonLabels[purpose.state.reason] ?? purpose.state.reason}
                </Badge>,
                purpose.decidable ? (
                  <ApiButton
                    key="a"
                    path="privacy/decide"
                    body={{
                      tenantId,
                      purposeKey: purpose.key,
                      version: purpose.version,
                      granted: !purpose.state.allowed,
                    }}
                    label={
                      purpose.state.allowed
                        ? purpose.legalBasis === 'legitimate-interests'
                          ? 'Object'
                          : 'Turn off'
                        : 'Turn on'
                    }
                    tone={purpose.state.allowed ? 'secondary' : 'primary'}
                  />
                ) : (
                  <span key="a" />
                ),
              ])}
              empty="This organization has not described any uses of personal data yet."
            />
          </Card>

          <Card
            title="Your requests"
            description="Requests about your data are answered within the legal deadline, usually a month."
            flush
          >
            <Table
              head={['Request', 'Status', 'Due', '']}
              rows={mine.requests.map((request) => [
                <span key="n">
                  {requestTypeLabels[request.type] ?? request.type}{' '}
                  <code className="small">{request.number}</code>
                </span>,
                <Badge key="s" tone={requestStatusTone(request.status, false)}>
                  {request.status}
                </Badge>,
                <Time key="d" value={request.dueAt} />,
                request.exportId ? (
                  <PrivacyExportButton key="x" tenantId={tenantId} requestId={request.id} />
                ) : request.status === 'open' || request.status === 'pending-verification' ? (
                  <ApiButton
                    key="x"
                    path="privacy/cancelMyRequest"
                    body={{ tenantId, requestId: request.id }}
                    label="Withdraw"
                    confirm="Withdraw this request?"
                  />
                ) : (
                  <span key="x" />
                ),
              ])}
              empty="You have not made any requests."
            />
            <div className="card-body">
              <ApiForm
                path="privacy/submitRequest"
                tenantId={tenantId}
                submitLabel="Send request"
                resetOnSuccess
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'type',
                    label: 'I would like to…',
                    type: 'select',
                    required: true,
                    options: askOptions,
                  },
                  { name: 'details', label: 'Anything we should know', type: 'textarea', rows: 3 },
                ]}
              />
            </div>
          </Card>
          {mine.contact && (
            <p className="small muted">
              Privacy contact: {mine.contact.name ? `${mine.contact.name}, ` : ''}
              <a href={`mailto:${mine.contact.email}`}>{mine.contact.email}</a>
            </p>
          )}
        </div>
      )}
    </>
  );
}
