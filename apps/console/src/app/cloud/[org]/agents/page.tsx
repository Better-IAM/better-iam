import Link from 'next/link';
import type { AgentSummary } from 'better-iam';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, StatusBadge, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const standingTone = (standing: AgentSummary['standing']) =>
  standing === 'ok' ? 'success' : standing === 'suspended' ? 'warning' : 'danger';

function Standing({ standing }: { standing: AgentSummary['standing'] }) {
  return <Badge tone={standingTone(standing)}>{standing === 'ok' ? 'active' : standing}</Badge>;
}

function Runs({ agent }: { agent: Pick<AgentSummary, 'agent'> }) {
  const { provider, model } = agent.agent;
  if (!provider && !model) return <span className="muted">—</span>;
  return (
    <span className="row">
      {model && <code className="small">{model}</code>}
      {provider && <span className="small muted">{provider}</span>}
    </span>
  );
}

export default async function Agents({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base, session } = await orgPage(org);
  const [agents, mine, people, keys, directory] = await Promise.all([
    tryRead(() => iam.api.agents.list(auth, { tenantId })),
    tryRead(() => iam.api.agents.listMine(auth, { tenantId })),
    tryRead(() => iam.api.identities.list(auth, { tenantId, kind: 'user', status: 'active' })),
    tryRead(() => iam.api.credentials.list(auth, { tenantId })),
    tryRead(() => iam.api.agents.directory(auth, { tenantId })),
  ]);
  const liveKeys = (agentId: string) =>
    keys?.filter((key) => key.identityId === agentId && !key.expired).length;
  // Agents whose A2A card can be attested: card signing is on, and the agent is in good standing with a url.
  const attestable = iam.a2a.enabled
    ? [...(agents ?? []), ...(mine ?? [])].filter(
        (agent, index, all) =>
          agent.standing === 'ok' &&
          !!agent.agent.url &&
          all.findIndex((other) => other.id === agent.id) === index,
      )
    : [];
  return (
    <>
      <PageHeader
        title="AI agents"
        description="Agents are accounts of their own: API keys, roles and policies like a service account, plus a sponsor accountable for each one, a ceiling on everything it does, and delegation when it acts for a person."
      />
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <div className="stack">
          {mine && mine.length > 0 && (
            <Card
              title="Agents you sponsor"
              description="You are accountable for these agents. Suspending one stops every key and every session it holds at once; you can resume it later."
              flush
            >
              <Table
                head={['Agent', 'Runs on', 'Status', 'Delegations', 'Live sessions', 'Keys', '']}
                rows={mine.map((agent) => [
                  <span key="n" className="row">
                    <Link href={`${base}/agents/${agent.id}`}>
                      <strong>{agent.name}</strong>
                    </Link>
                    {agent.agent.purpose && (
                      <span className="small muted">{agent.agent.purpose}</span>
                    )}
                  </span>,
                  <Runs key="r" agent={agent} />,
                  <Standing key="s" standing={agent.standing} />,
                  `${agent.delegations.active} active${agent.delegations.pending ? `, ${agent.delegations.pending} pending` : ''}`,
                  agent.liveDelegatedSessions,
                  agent.keys.length,
                  <span key="a" className="actions">
                    {agent.status === 'active' ? (
                      <ApiButton
                        path="agents/suspend"
                        body={{ tenantId, agentId: agent.id, reason: 'Suspended by its sponsor' }}
                        label="Suspend now"
                        tone="danger"
                        confirm={`Stop ${agent.name} now? Its keys and sessions stop working until it is resumed.`}
                        tenantId={tenantId}
                      />
                    ) : agent.agent.suspended?.by === session.identity.id ? (
                      <ApiButton
                        path="agents/resume"
                        body={{ tenantId, agentId: agent.id }}
                        label="Resume"
                        tenantId={tenantId}
                      />
                    ) : (
                      <span className="small muted">suspended by an administrator</span>
                    )}
                  </span>,
                ])}
              />
            </Card>
          )}
          <Card
            title="All agents"
            description="Every agent of the organization, its sponsor and whether it may act. An agent stops working when its sponsor is disabled or leaves. Requires iam:agents:read."
            flush
          >
            {agents ? (
              <Table
                head={[
                  'Agent',
                  'Sponsor',
                  'Runs on',
                  'Standing',
                  'Delegable',
                  'Keys',
                  'Created',
                  '',
                ]}
                rows={agents.map((agent) => [
                  <span key="n" className="row">
                    <Link href={`${base}/agents/${agent.id}`}>{agent.name}</Link>
                    {agent.agent.boundary && <Badge tone="accent">ceiling</Badge>}
                  </span>,
                  agent.sponsor ? (
                    <span key="sp" className="row">
                      {agent.sponsor.email ?? agent.sponsor.name}
                      {agent.sponsor.status !== 'active' && (
                        <StatusBadge status={agent.sponsor.status} />
                      )}
                    </span>
                  ) : (
                    <Badge tone="danger">none</Badge>
                  ),
                  <Runs key="r" agent={agent} />,
                  <Standing key="s" standing={agent.standing} />,
                  agent.agent.delegable === false ? 'no' : 'yes',
                  liveKeys(agent.id) ?? '—',
                  <Time key="c" value={agent.createdAt} />,
                  <span key="a" className="actions">
                    {agent.standing === 'ok' && (
                      <ApiButton
                        path="credentials/create"
                        body={{
                          tenantId,
                          identityId: agent.id,
                          name: 'agent-runtime',
                          expiresInSeconds: 60 * 60 * 24 * 30,
                        }}
                        label="Issue 30-day key"
                        tone="primary"
                        showResult
                        tenantId={tenantId}
                      />
                    )}
                    {agent.status === 'active' ? (
                      <ApiButton
                        path="agents/suspend"
                        body={{ tenantId, agentId: agent.id }}
                        label="Suspend"
                        confirm={`Suspend ${agent.name}? Its keys and sessions stop working until it is resumed.`}
                        tenantId={tenantId}
                      />
                    ) : agent.status === 'disabled' ? (
                      <ApiButton
                        path="agents/resume"
                        body={{ tenantId, agentId: agent.id }}
                        label="Resume"
                        tenantId={tenantId}
                      />
                    ) : null}
                    {agent.agent.delegable === false ? (
                      <ApiButton
                        path="agents/update"
                        body={{ tenantId, agentId: agent.id, delegable: true }}
                        label="Allow delegation"
                        tenantId={tenantId}
                      />
                    ) : (
                      <ApiButton
                        path="agents/update"
                        body={{ tenantId, agentId: agent.id, delegable: false }}
                        label="Stop delegation"
                        confirm={`Stop ${agent.name} from acting for anyone? Existing delegations pause until you allow it again.`}
                        tenantId={tenantId}
                      />
                    )}
                    <ApiButton
                      path="agents/delete"
                      body={{ tenantId, agentId: agent.id }}
                      label="Delete"
                      tone="danger"
                      confirm={`Delete ${agent.name}? Its keys end and every delegation to it is revoked.`}
                      tenantId={tenantId}
                    />
                  </span>,
                ])}
                empty="No agents yet."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:agents:read</code>. Agents you sponsor are listed above.
              </div>
            )}
          </Card>
          {agents && agents.some((agent) => agent.status === 'active') && (
            <Card
              title="Emergency stop"
              description="Suspends every active agent of the organization at once: their keys and sessions stop working until each is resumed. Requires iam:agents:update."
            >
              <ApiButton
                path="agents/suspendAll"
                body={{ tenantId, reason: 'Emergency stop from the console' }}
                label="Stop all agents now"
                tone="danger"
                confirm="Stop every agent of the organization now? Each one must be resumed on its own afterwards."
                showResult
                tenantId={tenantId}
              />
            </Card>
          )}
          {directory && directory.length > 0 && (
            <Card
              title="Agent directory"
              description="Agents with a current attested A2A card, as other agents find them. Cards leave when their attestation expires."
              flush
            >
              <Table
                head={['Agent', 'Endpoint', 'Skills', 'Attested until']}
                rows={directory.map((entry) => [
                  <strong key="n">{entry.name}</strong>,
                  <code key="u" className="small">
                    {String(entry.card.url)}
                  </code>,
                  (Array.isArray(entry.card.skills) ? (entry.card.skills as { id?: string }[]) : [])
                    .map((skill) => skill.id)
                    .filter(Boolean)
                    .join(', ') || '—',
                  <Time key="e" value={entry.expiresAt} />,
                ])}
              />
            </Card>
          )}
          {agents &&
            agents.some((agent) => agent.standing !== 'ok' && agent.standing !== 'deleted') && (
              <Alert tone="warning">
                Some agents cannot act: their sponsor left or was disabled, or they were suspended.
                Name a new sponsor below to bring an unsponsored agent back.
              </Alert>
            )}
        </div>
        <div className="stack">
          <Card
            title="Register an agent"
            description="Requires iam:agents:create. The sponsor defaults to you. Give the agent roles from its page, issue it a key, and let people delegate to it."
          >
            <ApiForm
              path="agents/create"
              tenantId={tenantId}
              submitLabel="Register agent"
              successMessage="Agent registered."
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'name', label: 'Name', required: true, placeholder: 'Support triage' },
                {
                  name: 'purpose',
                  label: 'Purpose',
                  type: 'textarea',
                  rows: 2,
                  placeholder: 'Labels and routes incoming support tickets',
                  help: 'Shown to people deciding whether to let the agent act for them.',
                },
                ...(people
                  ? [
                      {
                        name: 'sponsorId',
                        label: 'Sponsor',
                        type: 'select' as const,
                        help: 'The person accountable for the agent. Leave empty to sponsor it yourself.',
                        options: people
                          .filter((person) => person.id !== session.identity.id)
                          .map((person) => ({
                            value: person.id,
                            label: person.email ?? person.name,
                          })),
                      },
                    ]
                  : []),
                { name: 'model', label: 'Model', placeholder: 'claude-sonnet-5' },
                { name: 'provider', label: 'Provider', placeholder: 'anthropic' },
                { name: 'url', label: 'Endpoint or documentation URL', placeholder: 'https://…' },
                {
                  name: 'protocols',
                  label: 'Protocols',
                  type: 'list',
                  placeholder: 'mcp, a2a',
                },
                {
                  name: 'delegable',
                  label: 'People may delegate their access to this agent',
                  type: 'checkbox',
                  defaultValue: true,
                },
                {
                  name: 'maxDelegatedSessionSeconds',
                  label: 'Longest delegated session (minutes)',
                  type: 'number',
                  multiplier: 60,
                  placeholder: '60',
                },
                {
                  name: 'tokenAudiences',
                  label: 'Outside services it may present delegations to',
                  type: 'list',
                  placeholder: 'https://api.calendar.example, https://*.docs.example',
                  help: 'Optional: services that get a delegation token showing the agent acts for a person. * matches any characters.',
                },
                {
                  name: 'boundary',
                  label: 'Ceiling policy (JSON)',
                  type: 'json',
                  rows: 6,
                  placeholder:
                    '{ "version": 1, "statements": [{ "effect": "allow", "actions": ["tickets:*"], "resources": ["ticket/*"] }] }',
                  help: 'Optional: caps everything the agent does, whatever its roles and whoever it acts for.',
                },
              ]}
            />
          </Card>
          {agents && agents.length > 0 && people && (
            <Card
              title="Change a sponsor"
              description="Hand an agent to another person, for example after its sponsor left. Requires iam:agents:update."
            >
              <ApiForm
                path="agents/update"
                tenantId={tenantId}
                submitLabel="Change sponsor"
                successMessage="Sponsor changed."
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'agentId',
                    label: 'Agent',
                    type: 'select',
                    required: true,
                    options: agents
                      .filter((agent) => agent.status !== 'deleted')
                      .map((agent) => ({ value: agent.id, label: agent.name })),
                  },
                  {
                    name: 'sponsorId',
                    label: 'New sponsor',
                    type: 'select',
                    required: true,
                    options: people.map((person) => ({
                      value: person.id,
                      label: person.email ?? person.name,
                    })),
                  },
                ]}
              />
            </Card>
          )}
          {attestable.length > 0 && (
            <Card
              title="Attest an A2A agent card"
              description="Signs an agent's Agent2Agent card so other agents can verify that it belongs to this organization and has an accountable sponsor. The card's url must be on the agent's registered origin. Agents usually re-sign their own card with their key; this signs one now. Requires iam:agents:update, or being the sponsor."
            >
              <ApiForm
                path="agents/signCard"
                tenantId={tenantId}
                submitLabel="Sign card"
                showResult
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'agentId',
                    label: 'Agent',
                    type: 'select',
                    required: true,
                    options: attestable.map((agent) => ({
                      value: agent.id,
                      label: `${agent.name} (${new URL(agent.agent.url!).origin})`,
                    })),
                  },
                  {
                    name: 'card',
                    label: 'Agent card (JSON)',
                    type: 'json',
                    rows: 8,
                    required: true,
                    defaultValue: JSON.stringify(
                      {
                        protocolVersion: '0.3.0',
                        name: attestable[0]!.name,
                        url: attestable[0]!.agent.url,
                        version: '1.0.0',
                        capabilities: { streaming: true },
                        defaultInputModes: ['text/plain'],
                        defaultOutputModes: ['text/plain'],
                        skills: [],
                      },
                      null,
                      2,
                    ),
                    help: 'Other agents verify the signed card with the keys at /api/a2a/jwks.json.',
                  },
                ]}
              />
            </Card>
          )}
          <Alert tone="info">
            An agent authenticates with its key as <code>Authorization: Bearer biam_key_…</code>. To
            act for a person it calls <code>delegations/assume</code> and uses the{' '}
            <code>biam_dlg_…</code> token it gets back: that session has the person&apos;s access,
            within the delegation and the agent&apos;s ceiling. People manage delegations on the{' '}
            <Link href={`${base}/delegations`}>Delegations</Link> page.
          </Alert>
        </div>
      </div>
    </>
  );
}
