import Link from 'next/link';
import { notFound } from 'next/navigation';
import type { ReactNode } from 'react';
import { ApiForm } from '@/components/api-form';
import { RespondForm } from '@/components/threat-forms';
import {
  Badge,
  Card,
  Json,
  KeyValues,
  PageHeader,
  StatusBadge,
  Table,
  Time,
} from '@/components/ui';
import { can, key, orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';
import {
  detectionStatusTone,
  identityHref,
  incidentStatusTone,
  resolutionLabels,
  responseKinds,
  responseLabels,
  riskTone,
  severityTone,
  skipReason,
  subjectHref,
  subjectLabel,
  subjectTypeLabels,
} from '@/lib/threats';

const day = 24 * 60 * 60_000;

export default async function Incident({
  params,
}: {
  params: Promise<{ org: string; id: string }>;
}) {
  const { org, id } = await params;
  const page = await orgPage(org);
  const { iam, auth, tenantId, base, session } = page;
  const detail = await tryRead(() =>
    iam.api.threats.getIncident(auth, { tenantId, incidentId: id }),
  );
  if (!detail) notFound();
  const { incident, detections, notes, responses, risk } = detail;
  const identityId = incident.identityId;
  const incidentResource = { type: 'iam', id: `threats/incidents/${incident.id}` };
  const responsesResource = { type: 'iam', id: 'threats/responses' };
  const riskResource = identityId ? { type: 'iam', id: `threats/risk/${identityId}` } : undefined;
  const [allowed, rules, members, playbooks, timeline] = await Promise.all([
    can(page, [
      { action: 'iam:threats:manage', resource: incidentResource },
      { action: 'iam:threats:respond', resource: incidentResource },
      { action: 'iam:threats:respond', resource: responsesResource },
      ...(riskResource ? [{ action: 'iam:threats:respond', resource: riskResource }] : []),
    ]),
    tryRead(() => iam.api.threats.rules(auth, { tenantId })),
    tryRead(() => iam.api.identities.list(auth, { tenantId, limit: 1000 })),
    tryRead(() => iam.api.threats.listPlaybooks(auth, { tenantId })),
    // What the identity did (and what was done to it) from a day before the first detection.
    identityId
      ? tryRead(() =>
          iam.api.threats.timeline(auth, {
            tenantId,
            identityId,
            since: Math.max(0, incident.firstDetectedAt - day),
            limit: 200,
          }),
        )
      : Promise.resolve(undefined),
  ]);
  const mayManage = allowed[key('iam:threats:manage', incidentResource)] === true;
  const mayRespond = allowed[key('iam:threats:respond', incidentResource)] === true;
  const mayRelease = allowed[key('iam:threats:respond', responsesResource)] === true;
  const maySetRisk =
    riskResource !== undefined &&
    allowed[key('iam:threats:respond', riskResource)] === true &&
    identityId !== session.identity.id;
  const resolved = incident.status === 'resolved';
  const ruleTitle = (ruleId: string) => rules?.find((rule) => rule.id === ruleId)?.title ?? ruleId;
  const member = (memberId: string) => members?.find((candidate) => candidate.id === memberId);
  const person = (memberId: string) => {
    if (memberId === 'threat-detection') return 'Threat detection';
    const found = member(memberId);
    return found ? found.name || found.email || found.id : memberId;
  };
  const personLink = (memberId: string) =>
    member(memberId) ? (
      <Link href={identityHref(base, memberId, member(memberId)?.kind)}>{person(memberId)}</Link>
    ) : (
      <code className="small">{person(memberId)}</code>
    );
  const subjectHrefValue = subjectHref(
    base,
    incident.subject,
    incident.subject.type === 'identity' ? member(incident.subject.id)?.kind : undefined,
  );
  const subject = subjectHrefValue ? (
    <Link href={subjectHrefValue}>{subjectLabel(incident.subject)}</Link>
  ) : (
    <code className="small">{subjectLabel(incident.subject)}</code>
  );
  // Identity actions reach the incident's subject, or the identity behind it; blocking needs a network.
  const identityTarget = incident.subject.type === 'identity' || identityId !== undefined;
  const networkTarget = incident.subject.type === 'network' || incident.network !== undefined;
  const kinds = responseKinds.filter((kind) =>
    kind === 'notify' ? true : kind === 'block-network' ? networkTarget : identityTarget,
  );
  const targetName = risk
    ? risk.name || risk.email || risk.identityId
    : subjectLabel(incident.subject);
  return (
    <>
      <PageHeader
        title={
          <>
            {incident.title}{' '}
            <Badge tone={severityTone(incident.severity)}>{incident.severity}</Badge>{' '}
            <Badge tone={incidentStatusTone(incident.status)}>{incident.status}</Badge>
          </>
        }
        description={
          <>
            {subjectTypeLabels[incident.subject.type]} {subject} ·{' '}
            <Link href={`${base}/threats`}>all threats</Link>
          </>
        }
      />
      <div className="stack">
        <div className="grid cols-3">
          <Card title="Incident">
            <KeyValues
              items={[
                ['Subject', subject],
                ...(incident.network
                  ? ([['Network', <code key="n">{incident.network}</code>]] as [
                      string,
                      ReactNode,
                    ][])
                  : []),
                ['Rules', incident.ruleIds.map(ruleTitle).join(', ')],
                ['Detections', String(incident.detectionCount)],
                ['First detected', <Time key="f" value={incident.firstDetectedAt} />],
                ['Last detected', <Time key="l" value={incident.lastDetectedAt} />],
                [
                  'Assignee',
                  incident.assigneeId ? (
                    personLink(incident.assigneeId)
                  ) : (
                    <span className="muted">unassigned</span>
                  ),
                ],
                ...(resolved
                  ? ([
                      [
                        'Resolution',
                        incident.resolution ? resolutionLabels[incident.resolution] : '—',
                      ],
                      [
                        'Resolved',
                        <span key="r">
                          <Time value={incident.resolvedAt} />
                          {incident.resolvedBy && <> by {person(incident.resolvedBy)}</>}
                        </span>,
                      ],
                    ] as [string, ReactNode][])
                  : []),
              ]}
            />
          </Card>
          <Card
            title="Triage"
            description={
              resolved
                ? 'Resolved incidents are closed to changes; a new detection about the same subject opens a new incident.'
                : 'Mark the incident as under investigation, assign it, or change its severity.'
            }
          >
            {resolved ? (
              <p className="muted small">Notes can still be added below.</p>
            ) : mayManage ? (
              <ApiForm
                path="threats/updateIncident"
                tenantId={tenantId}
                submitLabel="Save"
                compact
                successMessage="Saved."
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'incidentId',
                    label: 'Incident',
                    type: 'hidden',
                    defaultValue: incident.id,
                  },
                  {
                    name: 'status',
                    label: 'Status',
                    type: 'select',
                    required: true,
                    defaultValue: incident.status,
                    options: [
                      { value: 'open', label: 'Open' },
                      { value: 'investigating', label: 'Investigating' },
                    ],
                  },
                  {
                    name: 'severity',
                    label: 'Severity',
                    type: 'select',
                    required: true,
                    defaultValue: incident.severity,
                    options: (['low', 'medium', 'high', 'critical'] as const).map((severity) => ({
                      value: severity,
                      label: severity,
                    })),
                  },
                  {
                    name: 'assigneeId',
                    label: 'Assignee',
                    type: 'select',
                    emptyAsNull: true,
                    defaultValue: incident.assigneeId ?? '',
                    options: (members ?? [])
                      .filter(
                        (candidate) =>
                          candidate.status === 'active' &&
                          (candidate.kind === 'user' || candidate.id === incident.assigneeId),
                      )
                      .map((candidate) => ({
                        value: candidate.id,
                        label: candidate.email ?? candidate.name,
                      })),
                    help: 'Leave empty to unassign.',
                  },
                ]}
              />
            ) : (
              <p className="muted small">
                Requires <code>iam:threats:manage</code>.
              </p>
            )}
          </Card>
          <Card
            title="Risk"
            description={
              identityId
                ? 'The risk of the identity this incident is about, as policies see it (principal.riskLevel).'
                : 'This incident is not about an identity.'
            }
          >
            {risk ? (
              <div className="stack">
                <KeyValues
                  items={[
                    [
                      'Identity',
                      <Link key="i" href={identityHref(base, risk.identityId, risk.kind)}>
                        {risk.name || risk.email || risk.identityId}
                      </Link>,
                    ],
                    ['Status', <StatusBadge key="s" status={risk.status} />],
                    [
                      'Level',
                      <span key="l" className="row">
                        <Badge tone={riskTone(risk.level)}>{risk.level}</Badge>
                        <span className="small muted">score {risk.score}</span>
                      </span>,
                    ],
                    ...(risk.override
                      ? ([
                          [
                            'Override',
                            <span key="o" className="small">
                              {risk.override.level} by {person(risk.override.by)}:{' '}
                              {risk.override.reason}
                              {risk.override.expiresAt && (
                                <>
                                  {' '}
                                  (until <Time value={risk.override.expiresAt} />)
                                </>
                              )}
                              {!risk.override.active && ' — expired'}
                            </span>,
                          ],
                        ] as [string, ReactNode][])
                      : []),
                    ...(risk.contained
                      ? ([
                          [
                            'Contained',
                            <span key="c" className="small">
                              <Time value={risk.contained.at} /> by {person(risk.contained.by)}:{' '}
                              {risk.contained.reason}
                            </span>,
                          ],
                        ] as [string, ReactNode][])
                      : []),
                  ]}
                />
                {risk.contained && mayRelease && (
                  <ApiForm
                    path="threats/release"
                    tenantId={tenantId}
                    submitLabel="Release"
                    compact
                    successMessage="Released: the identity is active again and can sign in."
                    fields={[
                      { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                      {
                        name: 'identityId',
                        label: 'Identity',
                        type: 'hidden',
                        defaultValue: risk.identityId,
                      },
                      {
                        name: 'note',
                        label: 'Note',
                        placeholder: 'Password reset with the account holder on a call',
                        help: 'The identity becomes active again; its sessions stay ended and its risk score is kept.',
                      },
                    ]}
                  />
                )}
                {maySetRisk && (
                  <details>
                    <summary className="small">Set risk level</summary>
                    <ApiForm
                      path="threats/setRisk"
                      tenantId={tenantId}
                      submitLabel="Set level"
                      compact
                      successMessage="Risk level set."
                      fields={[
                        {
                          name: 'tenantId',
                          label: 'Tenant',
                          type: 'hidden',
                          defaultValue: tenantId,
                        },
                        {
                          name: 'identityId',
                          label: 'Identity',
                          type: 'hidden',
                          defaultValue: risk.identityId,
                        },
                        {
                          name: 'level',
                          label: 'Level',
                          type: 'select',
                          required: true,
                          defaultValue: 'high',
                          options: [
                            { value: 'high', label: 'high (confirmed compromised)' },
                            { value: 'medium', label: 'medium' },
                            { value: 'low', label: 'low' },
                            { value: 'none', label: 'none (clear every signal)' },
                          ],
                        },
                        { name: 'reason', label: 'Reason', required: true },
                        {
                          name: 'expiresInMs',
                          label: 'For (hours)',
                          type: 'number',
                          multiplier: 3_600_000,
                          help: 'Raised levels only: 1 to 2160 hours; leave empty to keep the floor until changed.',
                        },
                      ]}
                    />
                  </details>
                )}
              </div>
            ) : (
              <p className="muted small">
                {identityId ? (
                  <>
                    Requires <code>iam:threats:read</code> on the identity&apos;s risk.
                  </>
                ) : (
                  'No identity risk applies.'
                )}
              </p>
            )}
          </Card>
        </div>
        {!resolved && (mayRespond || mayManage) && (
          <div className="grid cols-2">
            {mayRespond && (
              <Card
                title="Respond"
                description="Runs now, under your name, against the incident's subject. Actions that do not apply or that protections refuse are skipped with a reason."
              >
                <RespondForm
                  tenantId={tenantId}
                  target={{ incidentId: incident.id }}
                  kinds={kinds}
                  confirmContain={`Contain ${targetName}? The account is disabled and signed out until someone releases it.`}
                />
              </Card>
            )}
            {mayManage && (
              <Card
                title="Resolve"
                description="Closes the incident and its open detections. A false alarm or expected activity also takes their points out of the identity's risk."
              >
                <ApiForm
                  path="threats/resolveIncident"
                  tenantId={tenantId}
                  submitLabel="Resolve"
                  fields={[
                    { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                    {
                      name: 'incidentId',
                      label: 'Incident',
                      type: 'hidden',
                      defaultValue: incident.id,
                    },
                    {
                      name: 'resolution',
                      label: 'Resolution',
                      type: 'select',
                      required: true,
                      options: (['true-positive', 'false-positive', 'benign'] as const).map(
                        (resolution) => ({
                          value: resolution,
                          label: resolutionLabels[resolution],
                        }),
                      ),
                    },
                    {
                      name: 'note',
                      label: 'Closing note',
                      type: 'textarea',
                      rows: 3,
                      placeholder: 'What happened and what was done',
                    },
                  ]}
                />
              </Card>
            )}
          </div>
        )}
        <Card
          title="Detections"
          description="Each detection lists the audit events that raised it (up to 20) and what they involved."
          flush
        >
          <Table
            head={['Severity', 'Detection', 'Evidence', 'Status']}
            rows={detections.map((detection) => [
              <Badge key="s" tone={severityTone(detection.severity)}>
                {detection.severity}
              </Badge>,
              <span key="d" className="stack" style={{ gap: 2 }}>
                <strong>{detection.title}</strong>
                <span className="small muted">{detection.summary}</span>
                <span className="small muted">
                  {ruleTitle(detection.ruleId)} · occurred <Time value={detection.occurredAt} /> ·
                  detected <Time value={detection.detectedAt} />
                </span>
              </span>,
              <span key="e" className="stack small" style={{ gap: 2 }}>
                <span>
                  {detection.evidence.count} event{detection.evidence.count === 1 ? '' : 's'},{' '}
                  <Time value={detection.evidence.firstAt} />
                  {detection.evidence.lastAt !== detection.evidence.firstAt && (
                    <>
                      {' '}
                      – <Time value={detection.evidence.lastAt} />
                    </>
                  )}
                </span>
                {detection.network && (
                  <span>
                    Network <code>{detection.network}</code>
                  </span>
                )}
                {detection.evidence.networks && detection.evidence.networks.length > 0 && (
                  <span>
                    Networks <code>{detection.evidence.networks.join(', ')}</code>
                  </span>
                )}
                {detection.evidence.identityIds && detection.evidence.identityIds.length > 0 && (
                  <span>
                    Identities{' '}
                    {detection.evidence.identityIds.map((evidenceId, index) => (
                      <span key={evidenceId}>
                        {index > 0 && ', '}
                        {personLink(evidenceId)}
                      </span>
                    ))}
                  </span>
                )}
                {detection.evidence.actions && detection.evidence.actions.length > 0 && (
                  <span>
                    Actions <code>{detection.evidence.actions.join(', ')}</code>
                  </span>
                )}
                {(detection.evidence.eventIds.length > 0 || detection.metadata) && (
                  <details>
                    <summary>Details</summary>
                    {detection.evidence.eventIds.length > 0 && (
                      <span className="stack" style={{ gap: 2 }}>
                        <span className="muted">Audit event ids</span>
                        <code className="small">{detection.evidence.eventIds.join(' ')}</code>
                      </span>
                    )}
                    {detection.metadata && <Json value={detection.metadata} />}
                  </details>
                )}
              </span>,
              <span key="t" className="stack" style={{ gap: 2 }}>
                <Badge tone={detectionStatusTone(detection.status)}>{detection.status}</Badge>
                {detection.dismissReason && (
                  <span className="small muted">
                    {detection.dismissedBy ? `${person(detection.dismissedBy)}: ` : ''}
                    {detection.dismissReason}
                  </span>
                )}
                {detection.status === 'open' && mayManage && (
                  <details>
                    <summary className="small">Dismiss</summary>
                    <ApiForm
                      path="threats/dismissDetection"
                      tenantId={tenantId}
                      submitLabel="Dismiss"
                      compact
                      fields={[
                        {
                          name: 'tenantId',
                          label: 'Tenant',
                          type: 'hidden',
                          defaultValue: tenantId,
                        },
                        {
                          name: 'detectionId',
                          label: 'Detection',
                          type: 'hidden',
                          defaultValue: detection.id,
                        },
                        { name: 'reason', label: 'Why it is a false alarm', required: true },
                      ]}
                    />
                  </details>
                )}
              </span>,
            ])}
            empty="No detections."
          />
        </Card>
        {responses.length > 0 && (
          <Card
            title="Responses"
            description="What was done about this incident, automatically by playbooks or by people, newest first."
            flush
          >
            <Table
              head={['When', 'Action', 'Outcome', 'By', 'Details']}
              rows={responses.map((response) => {
                const playbook = response.playbookId
                  ? playbooks?.find((candidate) => candidate.id === response.playbookId)
                  : undefined;
                return [
                  <Time key="w" value={response.createdAt} />,
                  <span key="a" className="stack" style={{ gap: 2 }}>
                    <strong>{responseLabels[response.action]}</strong>
                    <span className="small muted">{subjectLabel(response.subject)}</span>
                  </span>,
                  response.outcome === 'applied' ? (
                    <Badge key="o" tone="success">
                      applied
                    </Badge>
                  ) : (
                    <span key="o" className="stack" style={{ gap: 2 }}>
                      <Badge>skipped</Badge>
                      <span className="small muted">{skipReason(response.reason)}</span>
                    </span>
                  ),
                  <span key="b" className="small">
                    {response.actorId === 'threat-detection'
                      ? `Playbook ${playbook?.name ?? response.playbookId ?? ''}`.trim()
                      : person(response.actorId)}
                  </span>,
                  response.details ? (
                    <code key="d" className="small">
                      {JSON.stringify(response.details)}
                    </code>
                  ) : (
                    ''
                  ),
                ];
              })}
            />
          </Card>
        )}
        <Card
          title="Notes"
          description="The investigation record: what was checked, who was contacted, what was decided."
        >
          <div className="stack">
            {notes.length === 0 && <p className="muted small">No notes yet.</p>}
            {notes.map((note) => (
              <div key={note.id} className="stack" style={{ gap: 2 }}>
                <span className="small muted">
                  {person(note.authorId)} · <Time value={note.createdAt} />
                </span>
                <p style={{ whiteSpace: 'pre-wrap', margin: 0 }}>{note.body}</p>
              </div>
            ))}
            {mayManage && (
              <ApiForm
                path="threats/addNote"
                tenantId={tenantId}
                submitLabel="Add note"
                compact
                resetOnSuccess
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'incidentId',
                    label: 'Incident',
                    type: 'hidden',
                    defaultValue: incident.id,
                  },
                  { name: 'body', label: 'Note', type: 'textarea', rows: 3, required: true },
                ]}
              />
            )}
          </div>
        </Card>
        {identityId && (
          <Card
            title="Identity timeline"
            description={
              <>
                What {targetName} did, and what was done to their account, from a day before the
                first detection (newest first, at most 200 events). The full record is in the{' '}
                <Link href={`${base}/audit`}>audit log</Link>.
              </>
            }
            flush
          >
            {timeline ? (
              <Table
                head={['When', 'Actor', 'Action', 'Resource', 'Outcome', 'Details']}
                rows={timeline.map((event) => [
                  <Time key="w" value={event.timestamp} />,
                  <span key="a" className="small">
                    {person(event.actorId)}
                    {event.impersonatorId && (
                      <>
                        {' '}
                        <Badge tone="warning">via {person(event.impersonatorId)}</Badge>
                      </>
                    )}
                  </span>,
                  <code key="c">{event.action}</code>,
                  <code key="r" className="small truncate">
                    {event.resourceId}
                  </code>,
                  <StatusBadge
                    key="o"
                    status={event.outcome === 'allow' ? 'active' : 'disabled'}
                  />,
                  event.metadata ? (
                    <code key="m" className="small">
                      {JSON.stringify(event.metadata)}
                    </code>
                  ) : (
                    ''
                  ),
                ])}
                empty="No activity in this period."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:threats:read</code> on the identity&apos;s risk.
              </div>
            )}
          </Card>
        )}
      </div>
    </>
  );
}
