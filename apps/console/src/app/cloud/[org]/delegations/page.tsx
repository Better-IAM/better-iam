import Link from 'next/link';
import type { DelegationSummary } from 'better-iam';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, StatusBadge, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

/** The spending cap and what the current window used, such as "$0.42 of $5 today". */
function Spend({ spend }: { spend: NonNullable<DelegationSummary['spend']> }) {
  const window = spend.period === 'day' ? 'today' : `this ${spend.period}`;
  const parts = [
    spend.maxCostUsd !== undefined && `$${spend.usedCostUsd.toFixed(2)} of $${spend.maxCostUsd}`,
    spend.maxTokens !== undefined &&
      `${spend.usedTokens.toLocaleString()} of ${spend.maxTokens.toLocaleString()} tokens`,
    spend.maxRequests !== undefined && `${spend.usedRequests} of ${spend.maxRequests} calls`,
  ].filter(Boolean);
  return (
    <span className="small muted">
      AI spend: {parts.join(', ')} {window}
    </span>
  );
}

function Scope({
  delegation,
}: {
  delegation: Pick<DelegationSummary, 'scopes' | 'policy' | 'confirm' | 'spend'>;
}) {
  const confirm =
    delegation.confirm?.length || delegation.spend ? (
      <>
        {delegation.confirm?.length ? (
          <span className="small muted">confirms each: {delegation.confirm.join(', ')}</span>
        ) : null}
        {delegation.spend && <Spend spend={delegation.spend} />}
      </>
    ) : null;
  if (delegation.scopes)
    return (
      <span className="row">
        {delegation.scopes.map((scope) => (
          <code key={scope} className="small">
            {scope}
          </code>
        ))}
        {confirm}
      </span>
    );
  return (
    <span className="row">
      <span className="small muted" title={JSON.stringify(delegation.policy)}>
        custom policy ({delegation.policy.statements.length} statements)
      </span>
      {confirm}
    </span>
  );
}

function AgentName({ delegation }: { delegation: DelegationSummary }) {
  return (
    <span className="row">
      <strong>{delegation.agent.name}</strong>
      {delegation.agent.model && <code className="small">{delegation.agent.model}</code>}
      {delegation.chain?.length ? (
        <span className="small muted">
          via {delegation.chain.map((agent) => agent.name).join(' → ')}
        </span>
      ) : null}
      {delegation.handoff && (
        <Badge tone="accent">
          may hand on
          {delegation.handoff.depth > 1 ? ` (${delegation.handoff.depth} deep)` : ''}
        </Badge>
      )}
    </span>
  );
}

function state(delegation: DelegationSummary) {
  if (delegation.expired) return <Badge tone="neutral">expired</Badge>;
  return <StatusBadge status={delegation.status} />;
}

export default async function Delegations({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const [mine, catalog, all, confirmations] = await Promise.all([
    tryRead(() => iam.api.delegations.listMine(auth, { tenantId })),
    tryRead(() => iam.api.agents.catalog(auth, { tenantId })),
    tryRead(() => iam.api.delegations.list(auth, { tenantId })),
    tryRead(() => iam.api.delegations.listConfirmations(auth, { tenantId, status: 'pending' })),
  ]);
  const toConfirm = confirmations?.filter((item) => !item.expired) ?? [];
  const waiting = mine?.filter((item) => item.status === 'pending' && !item.expired) ?? [];
  const acting = mine?.filter((item) => item.status === 'active' && !item.expired) ?? [];
  const past = mine?.filter((item) => !waiting.includes(item) && !acting.includes(item)) ?? [];
  return (
    <>
      <PageHeader
        title="Delegations"
        description="Let AI agents act on your behalf. An agent acting for you has your access, never more, and only within what you allow here. Revoking ends its sessions at once."
      />
      {waiting.length > 0 && (
        <Alert tone="warning">
          {waiting.length === 1
            ? 'An agent is asking to act for you.'
            : `${waiting.length} agents are asking to act for you.`}{' '}
          Approve only agents you recognize; you can narrow what they asked for.
        </Alert>
      )}
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <div className="stack">
          {toConfirm.length > 0 && (
            <Card
              title="Actions waiting for your confirmation"
              description="You asked to confirm these actions one at a time. An approval allows exactly this action on this resource for a few minutes."
              flush
            >
              <Table
                head={['Agent', 'Wants to', 'On', 'Reason', 'Expires', '']}
                rows={toConfirm.map((item) => [
                  <strong key="a">{item.agent.name}</strong>,
                  <code key="c" className="small">
                    {item.action}
                  </code>,
                  <code key="r" className="small">
                    {item.resource.type}/{item.resource.id}
                  </code>,
                  item.reason ?? <span className="muted">—</span>,
                  <Time key="e" value={item.expiresAt} />,
                  <span key="x" className="actions">
                    <ApiButton
                      path="delegations/decideConfirmation"
                      body={{ tenantId, confirmationId: item.id, approve: true }}
                      label="Approve"
                      tone="primary"
                      tenantId={tenantId}
                    />
                    <ApiButton
                      path="delegations/decideConfirmation"
                      body={{ tenantId, confirmationId: item.id, approve: false }}
                      label="Reject"
                      tone="danger"
                      tenantId={tenantId}
                    />
                  </span>,
                ])}
              />
            </Card>
          )}
          <Card title="Requests waiting for you" flush>
            <Table
              head={['Agent', 'Asks for', 'Reason', 'For', 'Asked', '']}
              rows={waiting.map((item) => [
                <AgentName key="a" delegation={item} />,
                <Scope key="s" delegation={item} />,
                item.reason ?? <span className="muted">—</span>,
                item.requestedSeconds ? `${Math.round(item.requestedSeconds / 86_400)} days` : '—',
                <Time key="t" value={item.createdAt} />,
                <span key="x" className="actions">
                  <ApiButton
                    path="delegations/approve"
                    body={{ tenantId, delegationId: item.id }}
                    label="Approve"
                    tone="primary"
                    confirm={`Let ${item.agent.name} act for you with ${item.scopes?.join(', ') ?? 'the requested policy'}?`}
                    tenantId={tenantId}
                  />
                  <ApiButton
                    path="delegations/deny"
                    body={{ tenantId, delegationId: item.id }}
                    label="Deny"
                    tone="danger"
                    tenantId={tenantId}
                  />
                </span>,
              ])}
              empty="No agent is waiting for your decision."
            />
          </Card>
          <Card title="Agents acting for you" flush>
            <Table
              head={['Agent', 'May do', 'Until', 'Last used', '']}
              rows={acting.map((item) => [
                <AgentName key="a" delegation={item} />,
                <Scope key="s" delegation={item} />,
                <Time key="e" value={item.expiresAt} />,
                item.lastUsedAt ? <Time key="l" value={item.lastUsedAt} /> : 'never',
                <ApiButton
                  key="r"
                  path="delegations/revoke"
                  body={{ tenantId, delegationId: item.id }}
                  label="Revoke"
                  tone="danger"
                  confirm={`Stop ${item.agent.name} from acting for you? Its sessions end now.`}
                  tenantId={tenantId}
                />,
              ])}
              empty="No agent acts for you."
            />
          </Card>
          {past.length > 0 && (
            <Card title="Earlier delegations" flush>
              <Table
                head={['Agent', 'Scope', 'State', 'Created', 'Ended']}
                rows={past.map((item) => [
                  <AgentName key="a" delegation={item} />,
                  <Scope key="s" delegation={item} />,
                  state(item),
                  <Time key="c" value={item.createdAt} />,
                  <Time key="e" value={item.revokedAt ?? item.decidedAt ?? item.expiresAt} />,
                ])}
              />
            </Card>
          )}
          {all && (
            <Card
              title="All delegations in the organization"
              description="Administrators can revoke any delegation. Requires iam:delegations:read (and iam:delegations:revoke to revoke)."
              flush
            >
              <Table
                head={['Person', 'Agent', 'Scope', 'State', 'Until', '']}
                rows={all.map((item) => [
                  <Link key="p" href={`${base}/members/${item.subject.id}`}>
                    {item.subject.email ?? item.subject.name}
                  </Link>,
                  <AgentName key="a" delegation={item} />,
                  <Scope key="s" delegation={item} />,
                  state(item),
                  <Time key="e" value={item.expiresAt} />,
                  (item.status === 'active' || item.status === 'pending') && !item.expired ? (
                    <ApiButton
                      key="r"
                      path="delegations/revoke"
                      body={{ tenantId, delegationId: item.id }}
                      label="Revoke"
                      tone="danger"
                      confirm="Revoke this delegation? The agent's sessions for this person end now."
                      tenantId={tenantId}
                    />
                  ) : (
                    ''
                  ),
                ])}
                empty="No delegations yet."
              />
            </Card>
          )}
        </div>
        <div className="stack">
          <Card
            title="Let an agent act for you"
            description="Choose what the agent may do. It can never do more than you can yourself. Needs a recent sign-in."
          >
            {catalog && catalog.length > 0 ? (
              <ApiForm
                path="delegations/grant"
                tenantId={tenantId}
                submitLabel="Delegate"
                successMessage="Delegation granted."
                resetOnSuccess
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'agentId',
                    label: 'Agent',
                    type: 'select',
                    required: true,
                    options: catalog.map((agent) => ({
                      value: agent.id,
                      label: `${agent.name}${agent.model ? ` (${agent.model})` : ''}`,
                    })),
                  },
                  {
                    name: 'scopes',
                    label: 'Actions it may take for you',
                    type: 'list',
                    required: true,
                    placeholder: 'documents:read, tickets:*',
                  },
                  {
                    name: 'confirm',
                    label: 'Ask me to confirm these each time',
                    type: 'list',
                    placeholder: 'documents:delete, billing:*',
                    help: 'The agent must ask you before each of these actions, and you approve them one by one.',
                  },
                  {
                    name: 'spend',
                    label: 'AI spending limit (JSON)',
                    type: 'json',
                    rows: 2,
                    placeholder: '{ "period": "day", "maxCostUsd": 5 }',
                    help: 'Caps the AI model calls the agent makes for you (and agents it hands work on to): maxCostUsd, maxTokens and/or maxRequests per minute, hour, day or month.',
                  },
                  {
                    name: 'handoff',
                    label: 'Let it hand work on to other agents (JSON)',
                    type: 'json',
                    rows: 2,
                    placeholder: '{ "depth": 1, "agents": ["<agent id>"] }',
                    help: 'Leave empty to keep the work with this agent. Agents it hands work on to act for you too, never with more than it has; you can revoke each hand-off.',
                  },
                  {
                    name: 'expiresInSeconds',
                    label: 'For how many days',
                    type: 'number',
                    multiplier: 86_400,
                    placeholder: '30',
                  },
                  {
                    name: 'maxSessionSeconds',
                    label: 'Longest single session (minutes)',
                    type: 'number',
                    multiplier: 60,
                    placeholder: '15',
                  },
                ]}
              />
            ) : (
              <div className="empty">No agent accepts delegation in this organization yet.</div>
            )}
          </Card>
          {catalog && catalog.length > 0 && (
            <Card
              title="Agent catalog"
              description="Agents you may delegate to, and who answers for them."
              flush
            >
              <Table
                head={['Agent', 'Purpose', 'Sponsor']}
                rows={catalog.map((agent) => [
                  <span key="n" className="row">
                    <strong>{agent.name}</strong>
                    {agent.provider && <span className="small muted">{agent.provider}</span>}
                  </span>,
                  agent.purpose ?? agent.description ?? <span className="muted">—</span>,
                  agent.sponsorName,
                ])}
              />
            </Card>
          )}
        </div>
      </div>
    </>
  );
}
