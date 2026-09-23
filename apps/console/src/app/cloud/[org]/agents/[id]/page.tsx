import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Badge, Card, KeyValues, PageHeader, StatusBadge, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const standingTone = (standing: string) =>
  standing === 'ok' ? 'success' : standing === 'suspended' ? 'warning' : 'danger';

/** One agent: who answers for it, what it holds, whom it acts for, what it spent, and what it did lately. */
export default async function Agent({ params }: { params: Promise<{ org: string; id: string }> }) {
  const { org, id } = await params;
  const { iam, auth, tenantId, base, session } = await orgPage(org);
  const agent = await tryRead(() => iam.api.agents.get(auth, { tenantId, agentId: id }));
  if (!agent) notFound();
  const [delegations, activity, usage, directory] = await Promise.all([
    tryRead(() => iam.api.delegations.list(auth, { tenantId, agentId: id })),
    tryRead(() => iam.api.agents.activity(auth, { tenantId, agentId: id, limit: 25 })),
    tryRead(() => iam.api.inference.usage(auth, { tenantId, agentId: id, groupBy: 'model' })),
    tryRead(() => iam.api.agents.directory(auth, { tenantId })),
  ]);
  const card = directory?.find((entry) => entry.agentId === id);
  const live = delegations?.filter((item) => item.status === 'active' && !item.expired) ?? [];
  const people = new Map(
    (delegations ?? []).map((item) => [item.subject.id, item.subject.email ?? item.subject.name]),
  );
  const sponsored = agent.sponsor?.id === session.identity.id;
  return (
    <>
      <PageHeader
        title={agent.name}
        description={
          agent.agent.purpose ?? agent.description ?? 'An AI agent of this organization.'
        }
      />
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <div className="stack">
          <Card title="Agent">
            <KeyValues
              items={[
                [
                  'Standing',
                  <Badge key="s" tone={standingTone(agent.standing)}>
                    {agent.standing === 'ok' ? 'active' : agent.standing}
                  </Badge>,
                ],
                [
                  'Sponsor',
                  agent.sponsor ? (
                    <Link key="p" href={`${base}/members/${agent.sponsor.id}`}>
                      {agent.sponsor.email ?? agent.sponsor.name}
                    </Link>
                  ) : (
                    <Badge key="p" tone="danger">
                      none
                    </Badge>
                  ),
                ],
                [
                  'Runs on',
                  [agent.agent.model, agent.agent.provider].filter(Boolean).join(' · ') || '—',
                ],
                ['Endpoint', agent.agent.url ?? '—'],
                ['Protocols', agent.agent.protocols?.join(', ') || '—'],
                ['Delegation', agent.agent.delegable === false ? 'not accepted' : 'accepted'],
                [
                  'Delegation tokens for',
                  agent.agent.tokenAudiences?.join(', ') || 'no outside service',
                ],
                [
                  'Ceiling',
                  agent.agent.boundary
                    ? `${agent.agent.boundary.statements.length} statements`
                    : 'none',
                ],
                ['Created', <Time key="c" value={agent.createdAt} />],
              ]}
            />
            <div className="actions" style={{ marginTop: 12 }}>
              {agent.status === 'active' ? (
                <ApiButton
                  path="agents/suspend"
                  body={{
                    tenantId,
                    agentId: id,
                    reason: sponsored ? 'Suspended by its sponsor' : undefined,
                  }}
                  label="Suspend now"
                  tone="danger"
                  confirm={`Stop ${agent.name} now? Its keys and sessions stop working until it is resumed.`}
                  tenantId={tenantId}
                />
              ) : agent.status === 'disabled' ? (
                <ApiButton
                  path="agents/resume"
                  body={{ tenantId, agentId: id }}
                  label="Resume"
                  tenantId={tenantId}
                />
              ) : null}
              <Link className="btn secondary small" href={`${base}/members/${id}`}>
                Roles and access
              </Link>
            </div>
          </Card>
          <Card
            title="Acting for people"
            description="Delegations to this agent that are active now, and the hand-offs it received from other agents."
            flush
          >
            {delegations ? (
              <Table
                head={['Person', 'May do', 'Via', 'Until', 'Last used']}
                rows={live.map((item) => [
                  item.subject.email ?? item.subject.name,
                  item.scopes?.join(', ') ?? 'custom policy',
                  item.chain?.map((step) => step.name).join(' → ') || '—',
                  <Time key="u" value={item.expiresAt} />,
                  item.lastUsedAt ? <Time key="l" value={item.lastUsedAt} /> : 'never',
                ])}
                empty="No one has delegated to this agent."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:delegations:read</code>.
              </div>
            )}
          </Card>
          <Card
            title="Recent activity"
            description="What it did lately, with its own keys and for the people it acts for."
            flush
          >
            {activity ? (
              <Table
                head={['When', 'Action', 'Resource', 'Outcome', 'For']}
                rows={activity.map((event) => [
                  <Time key="t" value={event.timestamp} />,
                  <code key="a" className="small">
                    {event.action}
                  </code>,
                  event.resourceId ?? '—',
                  <StatusBadge key="o" status={event.outcome === 'allow' ? 'active' : 'denied'} />,
                  event.sessionContext?.agentId === id && event.actorId !== id
                    ? (people.get(event.actorId) ?? event.actorId)
                    : '—',
                ])}
                empty="Nothing yet."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:agents:read</code>, or being its sponsor.
              </div>
            )}
          </Card>
        </div>
        <div className="stack">
          <Card title="Keys" description="Its live API keys (labels only)." flush>
            <Table
              head={['Key', 'Created', 'Expires', 'Last used']}
              rows={agent.keys.map((key) => [
                key.name ?? key.id.slice(0, 8),
                <Time key="c" value={key.createdAt} />,
                <Time key="e" value={key.expiresAt} />,
                key.lastUsedAt ? <Time key="l" value={key.lastUsedAt} /> : 'never',
              ])}
              empty="No keys."
            />
          </Card>
          {usage && (
            <Card
              title="AI usage this month"
              description="Model calls with its own keys and for the people it acts for."
              flush
            >
              <Table
                head={['Model', 'Calls', 'Tokens', 'Cost']}
                rows={usage.rows.map((row) => [
                  row.label ?? row.key,
                  row.requests,
                  (row.inputTokens + row.outputTokens).toLocaleString(),
                  `$${(row.costMicros / 1_000_000).toFixed(2)}`,
                ])}
                empty="No model calls this month."
              />
            </Card>
          )}
          <Card title="A2A card" description="Its current attested card in the agent directory.">
            {card ? (
              <KeyValues
                items={[
                  ['Endpoint', String(card.card.url)],
                  ['Organization', card.attestation.organization],
                  ['Attested until', <Time key="e" value={card.expiresAt} />],
                ]}
              />
            ) : (
              <div className="empty">No current attested card.</div>
            )}
          </Card>
          <Card
            title="Outside services"
            description="Services outside Better IAM this agent may show, with a signed delegation token, that it acts for a person. Requires iam:agents:update."
          >
            <ApiForm
              path="agents/update"
              tenantId={tenantId}
              submitLabel="Save services"
              successMessage="Services saved."
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'agentId', label: 'Agent', type: 'hidden', defaultValue: id },
                {
                  name: 'tokenAudiences',
                  label: 'Audiences',
                  type: 'list',
                  emptyAsNull: true,
                  defaultValue: agent.agent.tokenAudiences ?? [],
                  placeholder: 'https://api.calendar.example, https://*.docs.example',
                  help: 'Absolute URIs; * matches any characters. Clear to stop issuing tokens.',
                },
              ]}
            />
          </Card>
        </div>
      </div>
    </>
  );
}
