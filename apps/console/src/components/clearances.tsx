import Link from 'next/link';
import {
  attempt,
  clearanceAttention,
  compartmentName,
  dueState,
  effectiveStatusLabels,
  levelName,
  statusLabels,
  statusTone,
  valueOf,
} from '@/lib/clearances';
import type { OrgPage } from '@/lib/org';
import { Badge, Card, KeyValues, Time } from './ui';

/**
 * The Clearance card on a member's page (clearances.ts; needs iam:clearances:read on iam/clearances/{id}). Renders
 * nothing when the deployment does not enable clearances, when the viewer may not read clearances (so nobody without
 * the permission learns anything, compartment names least of all), and when no scheme applies and the person holds no
 * clearance record.
 */
export async function MemberClearance({ page, identityId }: { page: OrgPage; identityId: string }) {
  const { iam, auth, tenantId, base } = page;
  const [clearance, scheme] = await Promise.all([
    attempt(() => iam.api.clearances.get(auth, { tenantId, identityId })),
    attempt(() => iam.api.clearances.getScheme(auth, { tenantId })),
  ]);
  if (!clearance.ok) return null;
  const view = clearance.value;
  const current = valueOf(scheme) ?? undefined;
  if (!view && !current) return null;
  const definition = current?.definition;
  const href = `${base}/clearances/${encodeURIComponent(identityId)}`;
  const now = Date.now();
  return (
    <Card
      title="Clearance"
      description="Mandatory access control: on a labeled resource this person (and every agent acting with them) must hold a clearance that dominates the label, whatever their roles allow."
      actions={
        <Link className="btn small secondary" href={href}>
          {view ? 'Clearance page' : 'Grant'}
        </Link>
      }
    >
      {!view ? (
        <p className="muted">
          No clearance: they read only unlabeled resources
          {current ? ` under the ${current.name} scheme` : ''}.
        </p>
      ) : (
        <KeyValues
          items={[
            [
              'Level',
              <span key="l" className="row">
                <strong>{levelName(definition, view.level.id)}</strong>
                {view.effectiveLevel && view.effectiveLevel !== view.level.id && (
                  <span className="small muted">
                    counts as {levelName(definition, view.effectiveLevel)}
                  </span>
                )}
              </span>,
            ],
            [
              'Status',
              <span key="s" className="row">
                <Badge tone={statusTone(view.status)}>{statusLabels[view.status]}</Badge>
                {view.effectiveStatus !== view.status && (
                  <Badge tone={statusTone(view.effectiveStatus)}>
                    {effectiveStatusLabels[view.effectiveStatus]}
                  </Badge>
                )}
                {clearanceAttention(view, now)
                  .filter((item) => item.label !== 'expired' && item.label !== 'not counted')
                  .map((item) => (
                    <Badge key={item.label} tone={item.tone}>
                      {item.label}
                    </Badge>
                  ))}
              </span>,
            ],
            ['Citizenship', view.citizenship.length ? view.citizenship.join(', ') : '—'],
            [
              'Read into',
              view.readIns.length ? (
                <span key="r">
                  {view.readIns
                    .map(
                      (readIn) =>
                        // Both names need iam:clearances:read: the clearance's own, or the scheme's.
                        `${readIn.compartmentName ?? compartmentName(definition, readIn.compartmentId)}${readIn.current ? '' : ' (not current)'}`,
                    )
                    .join(', ')}
                </span>
              ) : (
                '—'
              ),
            ],
            [
              'Reinvestigation due',
              view.reinvestigationDue ? (
                <span key="d" className="row">
                  <Time value={view.reinvestigationDue} />
                  {dueState(view.reinvestigationDue, now) === 'overdue' && (
                    <Badge tone="danger">overdue</Badge>
                  )}
                </span>
              ) : (
                '—'
              ),
            ],
            ['Ends', view.expiresAt ? <Time key="e" value={view.expiresAt} /> : 'never'],
          ]}
        />
      )}
    </Card>
  );
}
