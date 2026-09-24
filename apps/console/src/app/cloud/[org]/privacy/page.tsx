import Link from 'next/link';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Stat, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import {
  legalBasisLabels as basisLabels,
  regulationOptions,
  requestStatusTone as statusTone,
  requestTypeLabels as typeLabels,
  requestTypeOptions as typeOptions,
} from '@/lib/privacy';
import { tryRead } from '@/lib/session';

export default async function Privacy({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const [summary, requests, purposes, holds, restrictions, settings, people] = await Promise.all([
    tryRead(() => iam.api.privacy.summary(auth, { tenantId })),
    tryRead(() => iam.api.privacy.listRequests(auth, { tenantId, limit: 100 })),
    tryRead(() => iam.api.privacy.listPurposes(auth, { tenantId, includeArchived: true })),
    tryRead(() => iam.api.privacy.listHolds(auth, { tenantId })),
    tryRead(() => iam.api.privacy.listRestrictions(auth, { tenantId })),
    tryRead(() => iam.api.privacy.getSettings(auth, { tenantId })),
    tryRead(() => iam.api.identities.list(auth, { tenantId })),
  ]);
  const personOptions = (people ?? [])
    .filter((person) => person.kind === 'user' && person.status === 'active')
    .map((person) => ({ value: person.id, label: person.email ?? person.name }));
  const nameOf = (identityId?: string) =>
    identityId
      ? ((people ?? []).find((person) => person.id === identityId)?.email ?? identityId)
      : undefined;
  const subjectLabel = (subject: string, identityId?: string, externalId?: string) =>
    identityId ? (
      <Link href={`${base}/members/${identityId}`}>{nameOf(identityId)}</Link>
    ) : externalId !== undefined ? (
      <code>{externalId}</code>
    ) : (
      <span className="muted">{subject.startsWith('email:') ? 'requester (email)' : subject}</span>
    );
  const counts = new Map((summary?.purposes ?? []).map((purpose) => [purpose.id, purpose]));
  return (
    <>
      <PageHeader
        title="Privacy"
        description="What personal data is processed for, on which legal basis, and each person's consent to it; data-subject requests with their statutory deadlines; legal holds that stop erasure. Policies see principal.consents, the purposes that may be processed for the signed-in person."
      />
      {!summary ? (
        <Alert tone="warning">
          Requires <code>iam:privacy:read</code>.
        </Alert>
      ) : (
        <div className="stack">
          <div className="tiles">
            <Stat label="Open requests" value={summary.requests.open} />
            <Stat
              label="Overdue"
              value={summary.requests.overdue}
              hint={summary.requests.overdue ? 'answer these first' : 'none'}
            />
            <Stat label="Due within 7 days" value={summary.requests.dueSoon} />
            <Stat label="Awaiting verification" value={summary.requests.pendingVerification} />
            <Stat
              label="Median days to close"
              value={summary.requests.medianDaysToClose ?? '—'}
              hint="last 90 days"
            />
            <Stat label="Legal holds" value={summary.holds} />
          </div>

          <Card
            title="Data-subject requests"
            description="Open requests first, by deadline. Self-service requests are verified by the person's sign-in; requests you file for someone, or that arrive through the public form, wait until their identity is confirmed."
            flush
          >
            <Table
              head={['Request', 'Type', 'Subject', 'Status', 'Due', 'Submitted']}
              rows={(requests?.requests ?? []).map((request) => [
                <Link key="n" href={`${base}/privacy/requests/${request.id}`}>
                  <code>{request.number}</code>
                </Link>,
                <span key="t">
                  {typeLabels[request.type] ?? request.type}{' '}
                  <span className="small muted">{request.regulation.toUpperCase()}</span>
                </span>,
                <span key="s">
                  {subjectLabel(request.subject, request.identityId, request.externalId)}
                </span>,
                <Badge key="st" tone={statusTone(request.status, request.overdue)}>
                  {request.overdue ? 'overdue' : request.status}
                </Badge>,
                <Time key="d" value={request.dueAt} />,
                <span key="c" className="small">
                  <Time value={request.submittedAt} /> · {request.channel}
                </span>,
              ])}
              empty="No requests yet."
            />
          </Card>

          <Card
            title="File a member's request"
            description="For a request a member made by email, phone or post. Say how you confirmed it is them: the response window starts now."
          >
            <ApiForm
              path="privacy/createRequest"
              tenantId={tenantId}
              submitLabel="File request"
              redirectTo={`${base}/privacy/requests/{id}`}
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'type', label: 'Type', type: 'select', required: true, options: typeOptions },
                {
                  name: 'identityId',
                  label: 'Member',
                  type: 'select',
                  required: true,
                  options: personOptions,
                  group: 'subject',
                },
                {
                  name: 'regulation',
                  label: 'Regulation',
                  type: 'select',
                  options: regulationOptions,
                },
                { name: 'details', label: 'What they asked for', type: 'textarea', rows: 3 },
                {
                  name: 'method',
                  label: 'Identity confirmed by',
                  required: true,
                  group: 'verified',
                  placeholder: 'Replied from the account email; confirmed the last invoice number',
                },
              ]}
            />
          </Card>

          <Card
            title="File a request from someone without an account"
            description="It waits as unverified until you confirm who is asking on its page."
          >
            <ApiForm
              path="privacy/createRequest"
              tenantId={tenantId}
              submitLabel="File request"
              redirectTo={`${base}/privacy/requests/{id}`}
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'type', label: 'Type', type: 'select', required: true, options: typeOptions },
                { name: 'requesterEmail', label: 'Requester email', type: 'email', required: true },
                { name: 'requesterName', label: 'Requester name' },
                {
                  name: 'regulation',
                  label: 'Regulation',
                  type: 'select',
                  options: regulationOptions,
                },
                { name: 'details', label: 'What they asked for', type: 'textarea', rows: 3 },
              ]}
            />
          </Card>

          <Card
            title="Purposes"
            description="Consent purposes need a recorded grant (opt-in) or run until withdrawn (opt-out); legitimate interests run until someone objects; the other bases need no decision. Publishing a new version asks people to consent again."
            flush
          >
            <Table
              head={['Purpose', 'Basis', 'Version', 'Granted', 'Withdrawn', 'Expired / outdated', '']}
              rows={(purposes ?? []).map((purpose) => {
                const count = counts.get(purpose.id);
                return [
                  <span key="p">
                    <strong>{purpose.name}</strong> <code className="small">{purpose.key}</code>
                    {purpose.archived && (
                      <>
                        {' '}
                        <Badge>archived</Badge>
                      </>
                    )}
                    <br />
                    <span className="small muted">{purpose.description}</span>
                  </span>,
                  <span key="b">
                    {basisLabels[purpose.legalBasis] ?? purpose.legalBasis}
                    {purpose.legalBasis === 'consent' && (
                      <span className="small muted"> · {purpose.mode}</span>
                    )}
                  </span>,
                  <span key="v">v{purpose.version}</span>,
                  <span key="g">{count?.granted ?? 0}</span>,
                  <span key="w">{count?.withdrawn ?? 0}</span>,
                  <span key="e">
                    {count?.expired ?? 0} / {count?.outdated ?? 0}
                  </span>,
                  <details key="edit">
                    <summary className="small">Edit</summary>
                    <ApiForm
                      path="privacy/updatePurpose"
                      tenantId={tenantId}
                      compact
                      fields={[
                        { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                        {
                          name: 'purposeId',
                          label: 'Purpose',
                          type: 'hidden',
                          defaultValue: purpose.id,
                        },
                        { name: 'name', label: 'Name', defaultValue: purpose.name },
                        {
                          name: 'description',
                          label: 'Description',
                          type: 'textarea',
                          defaultValue: purpose.description,
                        },
                        {
                          name: 'newVersion',
                          label: 'Publish as a new version (people decide again)',
                          type: 'checkbox',
                        },
                        {
                          name: 'archived',
                          label: 'Archived (no longer processed)',
                          type: 'checkbox',
                          defaultValue: purpose.archived,
                        },
                      ]}
                    />
                  </details>,
                ];
              })}
              empty="No purposes yet. Add what you process personal data for."
            />
          </Card>

          <Card title="New purpose">
            <ApiForm
              path="privacy/createPurpose"
              tenantId={tenantId}
              submitLabel="Add purpose"
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'key', label: 'Key', required: true, placeholder: 'marketing-email' },
                { name: 'name', label: 'Name', required: true, placeholder: 'Marketing email' },
                {
                  name: 'description',
                  label: 'What is processed and why',
                  type: 'textarea',
                  required: true,
                  rows: 3,
                },
                {
                  name: 'legalBasis',
                  label: 'Legal basis',
                  type: 'select',
                  required: true,
                  options: Object.entries(basisLabels).map(([value, label]) => ({ value, label })),
                },
                {
                  name: 'mode',
                  label: 'Consent mode',
                  type: 'select',
                  options: [
                    { value: 'opt-in', label: 'Opt-in (needs a grant)' },
                    { value: 'opt-out', label: 'Opt-out (until withdrawn, e.g. CCPA sale/sharing)' },
                  ],
                },
                {
                  name: 'dataCategories',
                  label: 'Data categories',
                  type: 'list',
                  placeholder: 'contact, usage',
                },
                { name: 'retentionDays', label: 'Kept for (days)', type: 'number' },
                {
                  name: 'consentLifetimeDays',
                  label: 'Consent lapses after (days)',
                  type: 'number',
                },
              ]}
            />
          </Card>

          <Card
            title="Legal holds"
            description="A held person cannot be erased or deleted by any path until the hold is released or lapses."
            flush
          >
            <Table
              head={['Subject', 'Reason', 'Placed', 'Until', '']}
              rows={(holds ?? []).map((hold) => [
                <span key="s">{subjectLabel(hold.subject, hold.identityId, hold.externalId)}</span>,
                <span key="r" className="small">
                  {hold.reason}
                </span>,
                <Time key="p" value={hold.placedAt} />,
                hold.expiresAt ? (
                  <Time key="u" value={hold.expiresAt} />
                ) : (
                  <span key="u" className="muted">
                    until released
                  </span>
                ),
                <ApiButton
                  key="x"
                  path="privacy/releaseHold"
                  body={{ tenantId, holdId: hold.id }}
                  label="Release"
                  tone="danger"
                  confirm="Release this legal hold? Erasure becomes possible again."
                  tenantId={tenantId}
                />,
              ])}
              empty="No legal holds."
            />
            <div className="card-body">
              <ApiForm
                path="privacy/placeHold"
                tenantId={tenantId}
                submitLabel="Place hold"
                resetOnSuccess
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'identityId',
                    label: 'Member',
                    type: 'select',
                    required: true,
                    options: personOptions,
                    group: 'subject',
                  },
                  { name: 'reason', label: 'Reason', required: true, placeholder: 'Litigation 2026-17' },
                  { name: 'expiresAt', label: 'Until', type: 'datetime' },
                ]}
              />
            </div>
          </Card>

          {restrictions && restrictions.length > 0 && (
            <Card
              title="Restricted processing"
              description="Only legal-obligation and vital-interest purposes pass for these subjects."
              flush
            >
              <Table
                head={['Subject', 'Since', '']}
                rows={restrictions.map((restriction) => [
                  <span key="s">
                    {subjectLabel(restriction.subject, restriction.identityId, restriction.externalId)}
                  </span>,
                  <Time key="t" value={restriction.restrictedAt} />,
                  restriction.identityId || restriction.externalId !== undefined ? (
                    <ApiButton
                      key="x"
                      path="privacy/liftRestriction"
                      body={{
                        tenantId,
                        subject: restriction.identityId
                          ? { identityId: restriction.identityId }
                          : { externalId: restriction.externalId },
                      }}
                      label="Lift"
                      confirm="Lift the restriction? Tell the person before processing resumes."
                      tenantId={tenantId}
                    />
                  ) : (
                    <span key="x" />
                  ),
                ])}
              />
            </Card>
          )}

          {settings && (
            <Card
              title="Settings"
              description={`Statutory windows: GDPR ${settings.statutory.gdpr.responseDays} days (+${settings.statutory.gdpr.extensionDays}), CCPA ${settings.statutory.ccpa.responseDays} (+${settings.statutory.ccpa.extensionDays}), LGPD ${settings.statutory.lgpd.responseDays}. Shorter internal windows are allowed, longer ones are not.`}
            >
              <ApiForm
                path="privacy/updateSettings"
                tenantId={tenantId}
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'contactEmail',
                    label: 'Privacy contact email',
                    type: 'email',
                    emptyAsNull: true,
                    defaultValue: settings.contactEmail ?? '',
                    help: 'Emailed about new requests and approaching deadlines.',
                  },
                  {
                    name: 'contactName',
                    label: 'Privacy contact name',
                    emptyAsNull: true,
                    defaultValue: settings.contactName ?? '',
                  },
                  {
                    name: 'defaultRegulation',
                    label: 'Default regulation',
                    type: 'select',
                    required: true,
                    options: regulationOptions,
                    defaultValue: settings.defaultRegulation,
                  },
                  {
                    name: 'exportLifetimeDays',
                    label: 'Exports downloadable for (days)',
                    type: 'number',
                    defaultValue: settings.exportLifetimeDays,
                  },
                  {
                    name: 'publicIntake',
                    label: 'Accept requests from people without an account (confirmed by email)',
                    type: 'checkbox',
                    defaultValue: settings.publicIntake,
                  },
                ]}
              />
            </Card>
          )}
        </div>
      )}
    </>
  );
}
