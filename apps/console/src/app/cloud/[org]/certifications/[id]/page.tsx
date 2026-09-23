import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ApiButton } from '@/components/api-form';
import { Badge, Card, KeyValues, PageHeader, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const outcomeTone = {
  kept: 'success',
  revoked: 'warning',
  'already-removed': 'neutral',
  'revocation-failed': 'danger',
} as const;

export default async function Campaign({
  params,
}: {
  params: Promise<{ org: string; id: string }>;
}) {
  const { org, id } = await params;
  const { iam, auth, tenantId, base, session } = await orgPage(org);
  const campaign = await tryRead(() =>
    iam.api.certifications.get(auth, { tenantId, campaignId: id }),
  );
  if (!campaign) notFound();
  const open = campaign.status === 'open';
  const me = session.identity.id;
  const manager = campaign.reviewerMode === 'manager';
  const people = manager ? await tryRead(() => iam.api.identities.list(auth, { tenantId })) : [];
  const nameOf = new Map((people ?? []).map((person) => [person.id, person.email ?? person.name]));
  // Keep/revoke suggestions from usage or sign-ins (needs iam:analysis:read; hidden otherwise).
  const suggestions = open
    ? await tryRead(() =>
        iam.api.roleMining.reviewRecommendations(auth, { tenantId, campaignId: id }),
      )
    : undefined;
  const suggestionFor = new Map(
    (suggestions?.recommendations ?? []).map((entry) => [entry.itemId, entry]),
  );
  return (
    <>
      <PageHeader
        title={campaign.name}
        description={
          <>
            Access certification · <Link href={`${base}/certifications`}>all campaigns</Link>
          </>
        }
        actions={
          open ? (
            <span className="actions">
              <ApiButton
                path="certifications/remind"
                body={{ tenantId, campaignId: id }}
                label="Remind reviewers"
                tenantId={tenantId}
                showResult
              />
              <ApiButton
                path="certifications/close"
                body={{ tenantId, campaignId: id }}
                label="Close and apply"
                tone="danger"
                confirm={`Close the campaign? Revoked${campaign.undecided === 'revoke' ? ' and undecided' : ''} bindings are removed now.`}
                tenantId={tenantId}
                showResult
              />
            </span>
          ) : (
            <ApiButton
              path="certifications/delete"
              body={{ tenantId, campaignId: id }}
              label="Delete"
              tone="danger"
              confirm="Delete this campaign and its record of decisions?"
              redirectTo={`${base}/certifications`}
              tenantId={tenantId}
            />
          )
        }
      />
      <div className="stack">
        <Card>
          <KeyValues
            items={[
              ['Status', open ? 'open' : 'closed'],
              ['Progress', `${campaign.progress.decided} / ${campaign.progress.total} decided`],
              ['Keep / revoke', `${campaign.progress.keep} / ${campaign.progress.revoke}`],
              ['Undecided on close', campaign.undecided === 'revoke' ? 'revoked' : 'kept'],
              ['Reviewed by', manager ? "each person's manager" : 'named reviewers'],
              [
                manager ? 'Fallback reviewers' : 'Reviewers',
                campaign.reviewerIds.length ? campaign.reviewerIds.length : 'anyone',
              ],
              ['Due', <Time key="d" value={campaign.dueAt} />],
              ['Closes automatically', campaign.autoClose ? 'yes, when due' : 'no'],
              ['Closed', <Time key="c" value={campaign.closedAt} />],
            ]}
          />
        </Card>
        <Card title="Bindings under review" flush>
          <Table
            head={[
              'Subject',
              'Role',
              ...(manager ? ['Reviewer'] : []),
              ...(suggestions ? ['Suggested'] : []),
              'Decision',
              open ? '' : 'Outcome',
            ]}
            rows={campaign.items.map((item) => {
              const self = item.subjectType === 'identity' && item.subjectId === me;
              // Managers decide their assigned items through review, which needs no certification permission.
              const decidePath =
                item.reviewerId === me ? 'certifications/review' : 'certifications/decide';
              return [
                <span key="s" className="stack">
                  {item.subjectType === 'identity' ? (
                    <Link href={`${base}/members/${item.subjectId}`}>{item.subjectName}</Link>
                  ) : (
                    <Link href={`${base}/groups/${item.subjectId}`}>
                      {item.subjectName} (group)
                    </Link>
                  )}
                  {item.eligible && <span className="small muted">eligible (just-in-time)</span>}
                </span>,
                <Link key="r" href={`${base}/roles/${item.roleId}`}>
                  {item.roleName}
                </Link>,
                ...(manager
                  ? [
                      item.reviewerId ? (
                        (nameOf.get(item.reviewerId) ?? item.reviewerId)
                      ) : (
                        <span key="v" className="muted">
                          fallback reviewers
                        </span>
                      ),
                    ]
                  : []),
                ...(suggestions
                  ? [
                      (() => {
                        const suggestion = suggestionFor.get(item.id);
                        if (!suggestion || suggestion.recommendation === 'none')
                          return (
                            <span key="g" className="small muted">
                              {suggestion?.reason ?? '—'}
                            </span>
                          );
                        return (
                          <span key="g" className="stack" style={{ alignItems: 'flex-start' }}>
                            <Badge
                              tone={suggestion.recommendation === 'keep' ? 'success' : 'warning'}
                            >
                              {suggestion.recommendation}
                            </Badge>
                            <span className="small muted">{suggestion.reason}</span>
                          </span>
                        );
                      })(),
                    ]
                  : []),
                item.decision ? (
                  <span key="d" className="stack" style={{ alignItems: 'flex-start' }}>
                    <Badge tone={item.decision === 'keep' ? 'success' : 'warning'}>
                      {item.decision}
                    </Badge>
                    {item.note && <span className="small muted">{item.note}</span>}
                  </span>
                ) : (
                  <span key="d" className="muted">
                    undecided
                  </span>
                ),
                open ? (
                  self ? (
                    <span key="a" className="small muted">
                      your own access
                    </span>
                  ) : (
                    <span key="a" className="actions">
                      <ApiButton
                        path={decidePath}
                        body={{
                          tenantId,
                          campaignId: id,
                          decisions: [{ itemId: item.id, decision: 'keep' }],
                        }}
                        label="Keep"
                        tenantId={tenantId}
                      />
                      <ApiButton
                        path={decidePath}
                        body={{
                          tenantId,
                          campaignId: id,
                          decisions: [{ itemId: item.id, decision: 'revoke' }],
                        }}
                        label="Revoke"
                        tone="danger"
                        tenantId={tenantId}
                      />
                    </span>
                  )
                ) : item.outcome ? (
                  <span key="o" className="stack" style={{ alignItems: 'flex-start' }}>
                    <Badge tone={outcomeTone[item.outcome]}>{item.outcome}</Badge>
                    {item.outcomeDetail && (
                      <span className="small muted">{item.outcomeDetail}</span>
                    )}
                  </span>
                ) : (
                  '—'
                ),
              ];
            })}
            empty="This campaign covered no bindings."
          />
        </Card>
      </div>
    </>
  );
}
