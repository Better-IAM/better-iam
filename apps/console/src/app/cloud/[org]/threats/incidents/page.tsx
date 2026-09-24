import Link from 'next/link';
import type { IncidentStatus } from 'better-iam';
import { Alert, Badge, Card, PageHeader, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';
import {
  incidentStatusTone,
  resolutionLabels,
  severities,
  severityTone,
  subjectHref,
  subjectLabel,
  subjectTypeLabels,
} from '@/lib/threats';

const pageSize = 50;
const statuses: readonly IncidentStatus[] = ['open', 'investigating', 'resolved'];

export default async function Incidents({
  params,
  searchParams,
}: {
  params: Promise<{ org: string }>;
  searchParams: Promise<{ status?: string; severity?: string; identityId?: string; page?: string }>;
}) {
  const { org } = await params;
  const query = await searchParams;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const status = statuses.find((candidate) => candidate === query.status);
  const severity = severities.find((candidate) => candidate === query.severity);
  const identityId = query.identityId?.trim() || undefined;
  const page = Math.max(0, Math.floor(Number(query.page) || 0));
  const [result, rules, members] = await Promise.all([
    tryRead(() =>
      iam.api.threats.listIncidents(auth, {
        tenantId,
        ...(status ? { status } : {}),
        ...(severity ? { severity } : {}),
        ...(identityId ? { identityId } : {}),
        limit: pageSize,
        offset: page * pageSize,
      }),
    ),
    tryRead(() => iam.api.threats.rules(auth, { tenantId })),
    tryRead(() => iam.api.identities.list(auth, { tenantId, limit: 1000 })),
  ]);
  const ruleTitle = (ruleId: string) => rules?.find((rule) => rule.id === ruleId)?.title ?? ruleId;
  const member = (memberId: string) => members?.find((candidate) => candidate.id === memberId);
  const person = (memberId: string) => {
    const found = member(memberId);
    return found ? found.name || found.email || found.id : memberId;
  };
  const link = (target: number) => {
    const search = new URLSearchParams({
      ...(status ? { status } : {}),
      ...(severity ? { severity } : {}),
      ...(identityId ? { identityId } : {}),
      ...(target ? { page: String(target) } : {}),
    }).toString();
    return `${base}/threats/incidents${search ? `?${search}` : ''}`;
  };
  const hasMore = result ? (page + 1) * pageSize < result.total : false;
  return (
    <>
      <PageHeader
        title="Incidents"
        description={
          <>
            Every incident, most recently active first, including resolved ones. Back to{' '}
            <Link href={`${base}/threats`}>threats</Link>.
          </>
        }
      />
      {!result ? (
        <Alert tone="warning">
          Requires <code>iam:threats:read</code>.
        </Alert>
      ) : (
        <Card
          title={`${result.total} incident${result.total === 1 ? '' : 's'}`}
          description={
            identityId ? (
              <>
                About <strong>{person(identityId)}</strong> ·{' '}
                <Link href={`${base}/threats/incidents`}>show everyone</Link>
              </>
            ) : undefined
          }
          actions={
            (page > 0 || hasMore) && (
              <span className="row">
                {page > 0 && (
                  <Link className="btn small secondary" href={link(page - 1)}>
                    Newer
                  </Link>
                )}
                {hasMore && (
                  <Link className="btn small secondary" href={link(page + 1)}>
                    Older
                  </Link>
                )}
              </span>
            )
          }
          flush
        >
          <form className="row" method="get" style={{ padding: '0 16px 12px' }}>
            <label className="small muted" htmlFor="incident-status">
              Status
            </label>
            <select
              id="incident-status"
              className="select"
              name="status"
              defaultValue={status ?? ''}
              style={{ width: 'auto' }}
            >
              <option value="">any</option>
              {statuses.map((candidate) => (
                <option key={candidate} value={candidate}>
                  {candidate}
                </option>
              ))}
            </select>
            <label className="small muted" htmlFor="incident-severity">
              Severity
            </label>
            <select
              id="incident-severity"
              className="select"
              name="severity"
              defaultValue={severity ?? ''}
              style={{ width: 'auto' }}
            >
              <option value="">any</option>
              {severities.map((candidate) => (
                <option key={candidate} value={candidate}>
                  {candidate}
                </option>
              ))}
            </select>
            {identityId && <input type="hidden" name="identityId" value={identityId} />}
            <button className="btn secondary">Filter</button>
          </form>
          <Table
            head={['Severity', 'Incident', 'Status', 'Detections', 'Last activity', 'Assignee']}
            rows={result.incidents.map((incident) => {
              const href = subjectHref(
                base,
                incident.subject,
                incident.subject.type === 'identity'
                  ? member(incident.subject.id)?.kind
                  : undefined,
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
                <span key="t" className="stack" style={{ gap: 2 }}>
                  <Badge tone={incidentStatusTone(incident.status)}>{incident.status}</Badge>
                  {incident.resolution && (
                    <span className="small muted">{resolutionLabels[incident.resolution]}</span>
                  )}
                </span>,
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
            empty="No incidents match."
          />
        </Card>
      )}
    </>
  );
}
