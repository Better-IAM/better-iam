import Link from 'next/link';
import { ApiForm } from '@/components/api-form';
import { PrivacyExportButton } from '@/components/privacy-export';
import { Alert, Badge, Card, KeyValues, PageHeader, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import {
  rejectionOptions,
  requestStatusTone,
  requestTypeLabels,
} from '@/lib/privacy';
import { tryRead } from '@/lib/session';

/** What fulfilling each request type does, shown next to the Fulfil button. */
const fulfilment: Record<string, string> = {
  access:
    'Builds an export of everything held about the subject (profile, access, sessions, consents, activity). The subject downloads it from their privacy page; you can download it to send it another way.',
  portability:
    'Builds a machine-readable export of the data the subject provided (profile, answers, consents).',
  erasure:
    'Deletes the account (this also needs permission to delete members) and erases its remaining details, consent evidence, exports and messages. Refused under a legal hold.',
  rectification: 'Correct the data by hand first, then describe what changed in the note.',
  restriction:
    'Restricts processing: only legal-obligation and vital-interest purposes pass until you lift it.',
  objection:
    'Withdraws the named purposes, or every consent and legitimate-interest purpose if none are named.',
  'opt-out':
    'Withdraws the named purposes, or every opt-out (sale or sharing) purpose if none are named.',
};

export default async function PrivacyRequest({
  params,
}: {
  params: Promise<{ org: string; id: string }>;
}) {
  const { org, id } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const [request, people] = await Promise.all([
    tryRead(() => iam.api.privacy.getRequest(auth, { tenantId, requestId: id })),
    tryRead(() => iam.api.identities.list(auth, { tenantId })),
  ]);
  if (!request)
    return (
      <>
        <PageHeader title="Privacy request" />
        <Alert tone="warning">
          Not found, or requires <code>iam:privacy:read</code>.
        </Alert>
      </>
    );
  const nameOf = (identityId?: string) =>
    identityId
      ? ((people ?? []).find((person) => person.id === identityId)?.email ?? identityId)
      : undefined;
  const open = request.status === 'open';
  const closed = !open && request.status !== 'pending-verification';
  const assignees = (people ?? [])
    .filter((person) => person.kind === 'user' && person.status === 'active')
    .map((person) => ({ value: person.id, label: person.email ?? person.name }));
  return (
    <>
      <PageHeader
        title={
          <span className="row">
            <code>{request.number}</code> {requestTypeLabels[request.type] ?? request.type}{' '}
            <Badge tone={requestStatusTone(request.status, request.overdue)}>
              {request.overdue ? 'overdue' : request.status}
            </Badge>
          </span>
        }
        description={<Link href={`${base}/privacy`}>← All privacy requests</Link>}
      />
      <div className="stack">
        {request.legalHold && (
          <Alert tone="danger">
            The subject is under a legal hold: erasure is refused until the hold is released.
          </Alert>
        )}
        <Card title="Request">
          <KeyValues
            items={[
              [
                'Subject',
                request.identityId ? (
                  <Link href={`${base}/members/${request.identityId}`}>
                    {request.subjectName ?? nameOf(request.identityId)}
                  </Link>
                ) : request.externalId !== undefined ? (
                  <code>{request.externalId}</code>
                ) : (
                  <span className="muted">no account</span>
                ),
              ],
              ['Requester', request.requesterEmail ?? (request.redacted ? 'erased' : '—')],
              ['Regulation', request.regulation.toUpperCase()],
              ['Channel', request.channel],
              [
                'Verification',
                request.verification.status === 'verified'
                  ? `verified (${request.verification.method ?? '—'})`
                  : 'not yet verified',
              ],
              ['Submitted', <Time key="s" value={request.submittedAt} />],
              ['Due', <Time key="d" value={request.dueAt} />],
              ...(request.extendedAt
                ? ([['Extended', request.extensionReason ?? '']] as [string, string][])
                : []),
              ...(request.purposeKeys?.length
                ? ([['Purposes', request.purposeKeys.join(', ')]] as [string, string][])
                : []),
              ...(request.assigneeId
                ? ([['Assigned to', nameOf(request.assigneeId) ?? '']] as [string, string][])
                : []),
              ...(request.actions?.length
                ? ([['Done', request.actions.join(', ')]] as [string, string][])
                : []),
              ...(request.restricted
                ? ([['Processing', 'restricted']] as [string, string][])
                : []),
            ]}
          />
          {request.details && (
            <pre className="result" style={{ whiteSpace: 'pre-wrap' }}>
              {request.details}
            </pre>
          )}
          {request.exportId && (
            <div className="row">
              <PrivacyExportButton tenantId={tenantId} requestId={request.id} label="Download export" />
            </div>
          )}
        </Card>

        {request.status === 'pending-verification' && (
          <Card
            title="Verify"
            description="Confirm who is asking before anything else happens; the response window starts when you do."
          >
            <ApiForm
              path="privacy/verifyRequest"
              tenantId={tenantId}
              submitLabel="Mark verified"
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'requestId', label: 'Request', type: 'hidden', defaultValue: request.id },
                {
                  name: 'method',
                  label: 'How you confirmed it',
                  required: true,
                  placeholder: 'Video call; matched photo ID',
                },
                { name: 'note', label: 'Note', type: 'textarea', rows: 2 },
              ]}
            />
          </Card>
        )}

        {!closed && request.subject.startsWith('email:') && (
          <Card
            title="Link to the person it is about"
            description="This request came from an address the intake could not match to an account. Once you know who it is about, link it: access, erasure and consent changes need a linked subject (or decline it as “no personal data held”)."
          >
            <div className="stack">
              <ApiForm
                path="privacy/linkRequest"
                tenantId={tenantId}
                submitLabel="Link to member"
                compact
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  { name: 'requestId', label: 'Request', type: 'hidden', defaultValue: request.id },
                  {
                    name: 'identityId',
                    label: 'Member',
                    type: 'select',
                    required: true,
                    options: assignees,
                    group: 'subject',
                  },
                  { name: 'note', label: 'How you matched them' },
                ]}
              />
              <ApiForm
                path="privacy/linkRequest"
                tenantId={tenantId}
                submitLabel="Link to application subject"
                compact
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  { name: 'requestId', label: 'Request', type: 'hidden', defaultValue: request.id },
                  {
                    name: 'externalId',
                    label: 'Application identifier (customer number, visitor ID)',
                    required: true,
                    group: 'subject',
                  },
                  { name: 'note', label: 'How you matched them' },
                ]}
              />
            </div>
          </Card>
        )}

        {open && (
          <Card title="Fulfil" description={fulfilment[request.type]}>
            <ApiForm
              path="privacy/fulfilRequest"
              tenantId={tenantId}
              submitLabel={request.type === 'erasure' ? 'Erase' : 'Fulfil'}
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'requestId', label: 'Request', type: 'hidden', defaultValue: request.id },
                {
                  name: 'note',
                  label: request.type === 'rectification' ? 'What was corrected' : 'Note',
                  type: 'textarea',
                  rows: 2,
                  required: request.type === 'rectification',
                },
              ]}
            />
          </Card>
        )}

        {!closed && (
          <Card title="Handle">
            <div className="stack">
              <ApiForm
                path="privacy/assignRequest"
                tenantId={tenantId}
                submitLabel="Assign"
                compact
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  { name: 'requestId', label: 'Request', type: 'hidden', defaultValue: request.id },
                  {
                    name: 'assigneeId',
                    label: 'Handler',
                    type: 'select',
                    options: assignees,
                    emptyAsNull: true,
                    defaultValue: request.assigneeId ?? '',
                  },
                ]}
              />
              {open && !request.extendedAt && (
                <ApiForm
                  path="privacy/extendRequest"
                  tenantId={tenantId}
                  submitLabel="Extend deadline"
                  compact
                  fields={[
                    { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                    {
                      name: 'requestId',
                      label: 'Request',
                      type: 'hidden',
                      defaultValue: request.id,
                    },
                    {
                      name: 'reason',
                      label: 'Why more time is needed (the subject is told)',
                      required: true,
                    },
                  ]}
                />
              )}
              <ApiForm
                path="privacy/addNote"
                tenantId={tenantId}
                submitLabel="Add note"
                compact
                resetOnSuccess
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  { name: 'requestId', label: 'Request', type: 'hidden', defaultValue: request.id },
                  { name: 'note', label: 'Internal note', type: 'textarea', rows: 2, required: true },
                ]}
              />
              <details>
                <summary className="small">Decline</summary>
                <ApiForm
                  path="privacy/rejectRequest"
                  tenantId={tenantId}
                  submitLabel="Decline request"
                  fields={[
                    { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                    {
                      name: 'requestId',
                      label: 'Request',
                      type: 'hidden',
                      defaultValue: request.id,
                    },
                    {
                      name: 'reason',
                      label: 'Reason',
                      type: 'select',
                      required: true,
                      options: rejectionOptions,
                    },
                    { name: 'note', label: 'Explanation for the subject', type: 'textarea', rows: 2 },
                  ]}
                />
              </details>
            </div>
          </Card>
        )}

        <Card title="Timeline" flush>
          <Table
            head={['When', 'What', 'By', 'Note']}
            rows={[...request.events].reverse().map((event, index) => [
              <Time key={`t${index}`} value={event.at} />,
              <Badge key={`w${index}`}>{event.what}</Badge>,
              <span key={`b${index}`} className="small">
                {nameOf(event.by) ?? event.by}
              </span>,
              <span key={`n${index}`} className="small">
                {event.note ?? ''}
              </span>,
            ])}
          />
        </Card>
        {closed && (
          <span className="small muted">
            Closed <Time value={request.closedAt} />
            {request.rejectionReason ? ` · declined: ${request.rejectionReason}` : ''}
          </span>
        )}
      </div>
    </>
  );
}
