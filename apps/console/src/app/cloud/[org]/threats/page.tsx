import Link from 'next/link';
import { ApiForm } from '@/components/api-form';
import { ScanNow } from '@/components/threat-forms';
import { Alert, Badge, Card, PageHeader, Stat, Table, Time } from '@/components/ui';
import { can, key, orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';
import {
  detectionStatusTone,
  identityHref,
  incidentStatusTone,
  riskTone,
  severityTone,
  subjectHref,
  subjectLabel,
  subjectTypeLabels,
} from '@/lib/threats';

const detectionsResource = { type: 'iam', id: 'threats/detections' };

export default async function Threats({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const page = await orgPage(org);
  const { iam, auth, tenantId, base, session } = page;
  // Each read is permission-gated on its own; without iam:threats:read the page explains what it needs.
  const [summary, open, investigating, risky, detections, rules, members, allowed] =
    await Promise.all([
      tryRead(() => iam.api.threats.summary(auth, { tenantId })),
      tryRead(() => iam.api.threats.listIncidents(auth, { tenantId, status: 'open', limit: 50 })),
      tryRead(() =>
        iam.api.threats.listIncidents(auth, { tenantId, status: 'investigating', limit: 50 }),
      ),
      tryRead(() => iam.api.threats.listRisk(auth, { tenantId, limit: 25 })),
      tryRead(() => iam.api.threats.listDetections(auth, { tenantId, limit: 25 })),
      tryRead(() => iam.api.threats.rules(auth, { tenantId })),
      tryRead(() => iam.api.identities.list(auth, { tenantId, limit: 1000 })),
      can(page, [{ action: 'iam:threats:manage', resource: detectionsResource }]),
    ]);
  const mayManage = allowed[key('iam:threats:manage', detectionsResource)] === true;
  const ruleTitle = (ruleId: string) => rules?.find((rule) => rule.id === ruleId)?.title ?? ruleId;
  const person = (identityId: string) => {
    const member = members?.find((candidate) => candidate.id === identityId);
    return member ? member.name || member.email || member.id : identityId;
  };
  const kindOf = (identityId: string) =>
    members?.find((candidate) => candidate.id === identityId)?.kind;
  const active = [...(open?.incidents ?? []), ...(investigating?.incidents ?? [])].sort(
    (a, b) => b.lastDetectedAt - a.lastDetectedAt,
  );
  const openTotal = summary
    ? Object.values(summary.openIncidents).reduce((total, count) => total + count, 0)
    : 0;
  const riskyTotal = summary
    ? summary.riskyIdentities.high + summary.riskyIdentities.medium + summary.riskyIdentities.low
    : 0;
  const busiest = summary
    ? Object.entries(summary.byRule24h)
        .sort(([, a], [, b]) => (b ?? 0) - (a ?? 0))
        .slice(0, 3)
    : [];
  // Sessions carry a client IP only when the deployment derives one (http.clientInfo; the console's
  // TRUSTED_PROXY_HOPS); without it the network rules and network blocks have nothing to work with.
  const recordsAddresses = Boolean(session.session.client?.ip);
  return (
    <>
      <PageHeader
        title="Threats"
        description="Detection rules read the audit trail for attacks on accounts (password spraying, stolen sessions, takeovers, privilege grabs, mass deletions), group what they find into incidents, and keep a risk score per identity that policies can read as principal.riskLevel."
        actions={
          <>
            <Link className="btn small secondary" href={`${base}/threats/incidents`}>
              All incidents
            </Link>
            <Link className="btn small secondary" href={`${base}/threats/settings`}>
              Settings
            </Link>
            {mayManage && summary && <ScanNow tenantId={tenantId} />}
          </>
        }
      />
      {!summary ? (
        <Alert tone="warning">
          Requires <code>iam:threats:read</code>.
        </Alert>
      ) : (
        <div className="stack">
          {!recordsAddresses && (
            <Alert tone="warning">
              This deployment does not record client addresses (your own session has none), so the
              network rules (password spray, sign-ins from new networks, sessions used from another
              network) cannot see where activity comes from, and network blocks are not enforced.
              The operator enables them by running the console behind a reverse proxy they control
              and setting <code>TRUSTED_PROXY_HOPS</code>.
            </Alert>
          )}
          <div className="grid cols-3">
            <Stat
              label="Open incidents"
              value={openTotal}
              hint={
                openTotal
                  ? (['critical', 'high', 'medium', 'low'] as const)
                      .filter((severity) => summary.openIncidents[severity] > 0)
                      .map((severity) => `${summary.openIncidents[severity]} ${severity}`)
                      .join(' · ')
                  : 'Nothing waiting'
              }
            />
            <Stat label="Under investigation" value={summary.investigating} />
            <Stat
              label="Detections, last 24 hours"
              value={summary.detections24h}
              hint={
                busiest.length
                  ? busiest.map(([ruleId, count]) => `${ruleTitle(ruleId)} ${count}`).join(' · ')
                  : undefined
              }
            />
            <Stat
              label="Identities at risk"
              value={riskyTotal}
              hint={`${summary.riskyIdentities.high} high · ${summary.riskyIdentities.medium} medium · ${summary.riskyIdentities.low} low`}
            />
            <Stat
              label="Contained"
              value={summary.contained}
              hint="Disabled by a response until someone releases them"
            />
            <Stat
              label="Last scan"
              value={summary.lastRunAt ? <Time value={summary.lastRunAt} /> : 'never'}
              hint="The scheduled detection job reads each new audit event once"
            />
          </div>
          <Card
            title="Open incidents"
            description="Detections about the same identity, network, or directory connection are grouped into one incident until someone resolves it."
            flush
          >
            <Table
              head={['Severity', 'Incident', 'Status', 'Detections', 'Last activity', 'Assignee']}
              rows={active.map((incident) => {
                const href = subjectHref(
                  base,
                  incident.subject,
                  incident.subject.type === 'identity' ? kindOf(incident.subject.id) : undefined,
                );
                return [
                  <Badge key="s" tone={severityTone(incident.severity)}>
                    {incident.severity}
                  </Badge>,
                  <span key="i" className="stack" style={{ gap: 2 }}>
                    <Link href={`${base}/threats/incidents/${incident.id}`}>
                      <strong>{incident.title}</strong>
                    </Link>
                    <span className="small muted">
                      {subjectTypeLabels[incident.subject.type]}:{' '}
                      {href ? (
                        <Link href={href}>{subjectLabel(incident.subject)}</Link>
                      ) : (
                        <code>{subjectLabel(incident.subject)}</code>
                      )}{' '}
                      · {incident.ruleIds.map(ruleTitle).join(', ')}
                    </span>
                  </span>,
                  <Badge key="t" tone={incidentStatusTone(incident.status)}>
                    {incident.status}
                  </Badge>,
                  incident.detectionCount,
                  <Time key="l" value={incident.lastDetectedAt} />,
                  incident.assigneeId ? (
                    person(incident.assigneeId)
                  ) : (
                    <span key="a" className="muted">
                      unassigned
                    </span>
                  ),
                ];
              })}
              empty={open && investigating ? 'No open incidents.' : 'Incidents are not readable.'}
            />
          </Card>
          <Card
            title="Identities at risk"
            description="Each detection adds points that halve with the risk half-life; an administrator's override sets a floor. Contained identities stay listed until released."
            flush
          >
            {risky ? (
              <Table
                head={['Identity', 'Level', 'Score', 'Signals', 'Updated']}
                rows={risky.identities.map((entry) => [
                  <span key="i" className="stack" style={{ gap: 2 }}>
                    <Link href={identityHref(base, entry.identityId, entry.kind)}>
                      {entry.name || entry.email || entry.identityId}
                    </Link>
                    {entry.email && entry.name && (
                      <span className="small muted">{entry.email}</span>
                    )}
                  </span>,
                  <span key="l" className="row">
                    <Badge tone={riskTone(entry.level)}>{entry.level}</Badge>
                    {entry.contained && <Badge tone="danger">contained</Badge>}
                    {entry.override?.active && <Badge tone="accent">override</Badge>}
                  </span>,
                  <span key="s" className="stack" style={{ gap: 4, minWidth: 90 }}>
                    <span>{entry.score}</span>
                    <div
                      className={`meter ${entry.level === 'high' ? 'danger' : entry.level === 'medium' ? 'warning' : ''}`}
                      role="meter"
                      aria-valuemin={0}
                      aria-valuemax={100}
                      aria-valuenow={entry.score}
                    >
                      <span style={{ width: `${Math.max(2, Math.min(100, entry.score))}%` }} />
                    </div>
                  </span>,
                  <span key="c" className="small">
                    {entry.contributions.length
                      ? entry.contributions
                          .slice(0, 3)
                          .map((item) => `${ruleTitle(item.ruleId)} (${item.current})`)
                          .join(', ')
                      : entry.contained
                        ? `Contained: ${entry.contained.reason}`
                        : '—'}
                  </span>,
                  <Time key="u" value={entry.updatedAt} />,
                ])}
                empty="No identity is at risk."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:threats:read</code> on <code>iam/threats/risk</code>.
              </div>
            )}
          </Card>
          <Card
            title="Recent detections"
            description="The newest detections of any status. Dismissing one marks it a false alarm and takes its points out of the identity's risk; the incident stays open for someone to resolve."
            flush
          >
            {detections ? (
              <Table
                head={['Severity', 'Detection', 'Subject', 'Occurred', 'Status', '']}
                rows={detections.detections.map((detection) => {
                  const href = subjectHref(
                    base,
                    detection.subject,
                    detection.subject.type === 'identity'
                      ? kindOf(detection.subject.id)
                      : undefined,
                  );
                  return [
                    <Badge key="s" tone={severityTone(detection.severity)}>
                      {detection.severity}
                    </Badge>,
                    <span key="d" className="stack" style={{ gap: 2 }}>
                      <strong>{detection.title}</strong>
                      <span className="small muted">{detection.summary}</span>
                      {detection.incidentId && (
                        <Link
                          className="small"
                          href={`${base}/threats/incidents/${detection.incidentId}`}
                        >
                          Incident →
                        </Link>
                      )}
                    </span>,
                    href ? (
                      <Link key="u" href={href}>
                        {subjectLabel(detection.subject)}
                      </Link>
                    ) : (
                      <code key="u" className="small">
                        {subjectLabel(detection.subject)}
                      </code>
                    ),
                    <Time key="o" value={detection.occurredAt} />,
                    <span key="t" className="stack" style={{ gap: 2 }}>
                      <Badge tone={detectionStatusTone(detection.status)}>{detection.status}</Badge>
                      {detection.dismissReason && (
                        <span className="small muted">{detection.dismissReason}</span>
                      )}
                    </span>,
                    detection.status === 'open' && mayManage ? (
                      <details key="a">
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
                            {
                              name: 'reason',
                              label: 'Why it is a false alarm',
                              required: true,
                              placeholder: 'Load test from the office network',
                            },
                          ]}
                        />
                      </details>
                    ) : (
                      ''
                    ),
                  ];
                })}
                empty="Nothing detected yet."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:threats:read</code> on <code>iam/threats/detections</code>.
              </div>
            )}
          </Card>
        </div>
      )}
    </>
  );
}
