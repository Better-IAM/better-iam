import type { InferenceBudgetView, UsageRow } from 'better-iam';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Stat, Table } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const usd = (micros: number) =>
  micros >= 1_000_000
    ? `$${(micros / 1_000_000).toFixed(2)}`
    : micros >= 10_000
      ? `$${(micros / 1_000_000).toFixed(3)}`
      : `$${(micros / 1_000_000).toFixed(6)}`;
const count = (value: number) => value.toLocaleString('en-US');
const price = (value: number | undefined) => (value === undefined ? '—' : `$${value}`);

function Limit({ budget }: { budget: InferenceBudgetView }) {
  const parts = [
    budget.maxTokens !== undefined ? `${count(budget.maxTokens)} tokens` : undefined,
    budget.maxCostUsd !== undefined ? `$${budget.maxCostUsd}` : undefined,
    budget.maxRequests !== undefined ? `${count(budget.maxRequests)} calls` : undefined,
  ].filter(Boolean);
  return <>{`${parts.join(' and ')} per ${budget.period}`}</>;
}

function Used({ budget }: { budget: InferenceBudgetView }) {
  const standing = budget.standing;
  if (!standing) return <span className="small muted">per identity</span>;
  const shares = [
    budget.maxTokens ? standing.usedTokens / budget.maxTokens : 0,
    budget.maxCostMicros ? standing.usedCostMicros / budget.maxCostMicros : 0,
    budget.maxRequests ? standing.usedRequests / budget.maxRequests : 0,
  ];
  const share = Math.min(1, Math.max(...shares));
  return (
    <span
      className="row"
      title={`${count(standing.usedTokens)} tokens, ${usd(standing.usedCostMicros)}`}
    >
      <span
        className={`meter ${share >= 1 ? 'danger' : share >= 0.8 ? 'warning' : 'success'}`}
        style={{ width: 80, display: 'inline-block' }}
      >
        <span style={{ width: `${Math.round(share * 100)}%` }} />
      </span>
      <span className="small">{Math.round(share * 100)}%</span>
    </span>
  );
}

function UsageTable({ rows, keyLabel }: { rows: UsageRow[]; keyLabel: string }) {
  return (
    <Table
      head={[keyLabel, 'Requests', 'Input tokens', 'Output tokens', 'Cost']}
      rows={rows.map((row) => [
        row.label ?? row.key,
        count(row.requests),
        count(row.inputTokens + row.cacheReadTokens + row.cacheWriteTokens),
        count(row.outputTokens),
        usd(row.costMicros),
      ])}
      empty="No calls this month."
    />
  );
}

export default async function Inference({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId } = await orgPage(org);
  const [providers, models, budgets, byModel, byIdentity, byAgent, mine, myUsage, groups, people] =
    await Promise.all([
      tryRead(() => iam.api.inference.listProviders(auth, { tenantId })),
      tryRead(() => iam.api.inference.listModels(auth, { tenantId })),
      tryRead(() => iam.api.inference.listBudgets(auth, { tenantId })),
      tryRead(() => iam.api.inference.usage(auth, { tenantId, groupBy: 'model' })),
      tryRead(() => iam.api.inference.usage(auth, { tenantId, groupBy: 'identity' })),
      tryRead(() => iam.api.inference.usage(auth, { tenantId, groupBy: 'agent' })),
      tryRead(() => iam.api.inference.listMine(auth, { tenantId })),
      tryRead(() => iam.api.inference.myUsage(auth, { tenantId })),
      tryRead(() => iam.api.groups.list(auth, { tenantId })),
      tryRead(() => iam.api.identities.list(auth, { tenantId })),
    ]);
  const ownProviders = providers ?? [];
  return (
    <>
      <PageHeader
        title="Models & budgets"
        description="Which people, service accounts and agents may call which AI models, how much they may spend, and what they used. Provider keys are sealed and never leave the server."
      />
      {byModel && (
        <div className="tiles">
          <Stat
            label="Calls this month"
            value={count(byModel.totals.requests)}
            hint={byModel.totals.errors ? `${count(byModel.totals.errors)} failed` : 'none failed'}
          />
          <Stat label="Spend this month" value={usd(byModel.totals.costMicros)} />
          <Stat
            label="Tokens this month"
            value={count(
              byModel.totals.inputTokens +
                byModel.totals.outputTokens +
                byModel.totals.cacheReadTokens +
                byModel.totals.cacheWriteTokens,
            )}
          />
        </div>
      )}
      <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
        <div className="stack">
          <Card
            title="Models"
            description="Access is an ordinary policy decision: grant inference:invoke on model/{name}, with conditions on resource.tier, resource.provider or prices. Models defined above this organization are inherited."
            flush
          >
            {models ? (
              <Table
                head={[
                  'Model',
                  'Provider',
                  'Upstream',
                  'Tier',
                  'Input / output per M',
                  'State',
                  '',
                ]}
                rows={models.map((model) => [
                  <span key="n" className="row">
                    <code>{model.name}</code>
                    {model.displayName && <span className="small muted">{model.displayName}</span>}
                    {model.inherited && <Badge>inherited</Badge>}
                  </span>,
                  model.provider.name,
                  <code key="u" className="small">
                    {model.upstreamModel}
                  </code>,
                  model.tier ?? <span className="muted">—</span>,
                  `${price(model.inputPricePerMTok)} / ${price(model.outputPricePerMTok)}`,
                  <span key="s" className="row">
                    {model.enabled ? (
                      <Badge tone="success">enabled</Badge>
                    ) : (
                      <Badge tone="danger">disabled</Badge>
                    )}
                    {model.providerTools === 'deny' && <Badge>no provider tools</Badge>}
                    {model.providerTools === 'policy' && <Badge>tools by policy</Badge>}
                  </span>,
                  model.inherited ? (
                    ''
                  ) : (
                    <span key="a" className="actions">
                      <ApiButton
                        path="inference/updateModel"
                        body={{ tenantId, name: model.name, enabled: !model.enabled }}
                        label={model.enabled ? 'Disable' : 'Enable'}
                        confirm={
                          model.enabled ? `Stop every call to ${model.name} now?` : undefined
                        }
                        tenantId={tenantId}
                      />
                      <ApiButton
                        path="inference/deleteModel"
                        body={{ tenantId, name: model.name }}
                        label="Delete"
                        tone="danger"
                        confirm={`Delete ${model.name}?`}
                        tenantId={tenantId}
                      />
                    </span>
                  ),
                ])}
                empty="No models yet. Add a provider, then publish a model."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:inference:read</code>.
              </div>
            )}
          </Card>
          <Card
            title="Budgets"
            description="Calls that would exceed a budget are refused until its window resets. An agent's budget covers everything it does, including for people it acts for."
            flush
          >
            {budgets ? (
              <Table
                head={['Budget', 'Covers', 'Limit', 'Used', 'Models', '']}
                rows={budgets.map((budget) => [
                  <strong key="n">{budget.name}</strong>,
                  `${budget.subjectType === 'tenant' ? 'Everyone' : (budget.subjectName ?? budget.subjectId)}${budget.subjectType !== 'identity' ? (budget.scope === 'each' ? ', each' : ', shared') : ''}`,
                  <Limit key="l" budget={budget} />,
                  <Used key="u" budget={budget} />,
                  budget.models?.join(', ') ?? 'all',
                  <ApiButton
                    key="d"
                    path="inference/deleteBudget"
                    body={{ tenantId, budgetId: budget.id }}
                    label="Delete"
                    tone="danger"
                    confirm={`Delete the budget ${budget.name}?`}
                    tenantId={tenantId}
                  />,
                ])}
                empty="No budgets: calls are limited only by access."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:inference:read</code>.
              </div>
            )}
          </Card>
          {byIdentity && (
            <Card title="Usage by caller this month" flush>
              <UsageTable rows={byIdentity.rows} keyLabel="Caller" />
            </Card>
          )}
          {byAgent && byAgent.rows.some((row) => row.key !== '(none)') && (
            <Card
              title="Usage by agent this month"
              description="Calls agents made with their own keys or for the people they act for."
              flush
            >
              <UsageTable
                rows={byAgent.rows.filter((row) => row.key !== '(none)')}
                keyLabel="Agent"
              />
            </Card>
          )}
          {byModel && (
            <Card title="Usage by model this month" flush>
              <UsageTable rows={byModel.rows} keyLabel="Model" />
            </Card>
          )}
          <Card
            title="Providers"
            description="Upstream accounts. Only the key's last four characters are ever shown."
            flush
          >
            {providers ? (
              <Table
                head={['Provider', 'Kind', 'Base URL', 'Key', '']}
                rows={ownProviders.map((provider) => [
                  <span key="n" className="row">
                    <strong>{provider.name}</strong>
                    {provider.inherited && <Badge>inherited</Badge>}
                  </span>,
                  provider.kind,
                  <code key="b" className="small">
                    {provider.baseUrl}
                  </code>,
                  <code key="k" className="small">
                    {provider.keyHint}
                  </code>,
                  provider.inherited ? (
                    ''
                  ) : (
                    <ApiButton
                      key="d"
                      path="inference/deleteProvider"
                      body={{ tenantId, providerId: provider.id }}
                      label="Delete"
                      tone="danger"
                      confirm={`Delete ${provider.name}?`}
                      tenantId={tenantId}
                    />
                  ),
                ])}
                empty="No providers yet."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:inference:read</code>.
              </div>
            )}
          </Card>
        </div>
        <div className="stack">
          <Card title="Your models" description="The models you may call now.">
            {mine && mine.length ? (
              <ul className="small">
                {mine.map((model) => (
                  <li key={model.name}>
                    <code>{model.name}</code> {model.displayName ? `· ${model.displayName}` : ''}
                  </li>
                ))}
              </ul>
            ) : (
              <div className="empty">You may not call any model yet.</div>
            )}
            {myUsage && (
              <p className="small muted">
                This month: {count(myUsage.totals.requests)} calls, {usd(myUsage.totals.costMicros)}
                .
                {myUsage.budgets.map((budget) => (
                  <span key={budget.budgetId}>
                    {' '}
                    {budget.name}:{' '}
                    {budget.remainingTokens !== undefined
                      ? `${count(budget.remainingTokens)} tokens left`
                      : budget.remainingCostMicros !== undefined
                        ? `${usd(budget.remainingCostMicros)} left`
                        : ''}
                    .
                  </span>
                ))}
              </p>
            )}
          </Card>
          <Card
            title="Add a provider"
            description="Requires iam:inference:manage and a recent sign-in. The key is sealed immediately."
          >
            <ApiForm
              path="inference/createProvider"
              tenantId={tenantId}
              submitLabel="Add provider"
              successMessage="Provider added."
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'name', label: 'Name', required: true, placeholder: 'Anthropic' },
                {
                  name: 'kind',
                  label: 'API',
                  type: 'select',
                  required: true,
                  options: [
                    { value: 'anthropic', label: 'Anthropic Messages' },
                    { value: 'openai', label: 'OpenAI Chat Completions' },
                    { value: 'openai-compatible', label: 'OpenAI-compatible (custom URL)' },
                  ],
                },
                { name: 'apiKey', label: 'API key', type: 'password', required: true },
                {
                  name: 'baseUrl',
                  label: 'Base URL',
                  placeholder: 'https://…',
                  help: 'Required for OpenAI-compatible providers; custom URLs need a platform administrator.',
                },
              ]}
            />
          </Card>
          {ownProviders.length > 0 && (
            <Card
              title="Publish a model"
              description="Callers use the public name; the gateway sends the upstream name to the provider."
            >
              <ApiForm
                path="inference/createModel"
                tenantId={tenantId}
                submitLabel="Publish model"
                successMessage="Model published."
                resetOnSuccess
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  { name: 'name', label: 'Public name', required: true, placeholder: 'sonnet' },
                  {
                    name: 'providerId',
                    label: 'Provider',
                    type: 'select',
                    required: true,
                    options: ownProviders.map((provider) => ({
                      value: provider.id,
                      label: provider.name,
                    })),
                  },
                  {
                    name: 'upstreamModel',
                    label: 'Upstream model',
                    required: true,
                    placeholder: 'claude-sonnet-5',
                  },
                  { name: 'displayName', label: 'Display name' },
                  { name: 'tier', label: 'Tier', placeholder: 'frontier, small, …' },
                  {
                    name: 'inputPricePerMTok',
                    label: 'Input price ($ per million tokens)',
                    type: 'number',
                  },
                  {
                    name: 'outputPricePerMTok',
                    label: 'Output price ($ per million tokens)',
                    type: 'number',
                  },
                  { name: 'contextWindow', label: 'Context window (tokens)', type: 'number' },
                  {
                    name: 'providerTools',
                    label: 'Tools the provider runs (web search, code execution, MCP servers, …)',
                    type: 'select',
                    options: [
                      { value: 'allow', label: 'Allow any' },
                      { value: 'policy', label: 'Decide each with inference:use-tool' },
                      { value: 'deny', label: 'Allow none' },
                    ],
                  },
                ]}
              />
            </Card>
          )}
          <Card title="Set a budget" description="Requires iam:inference:manage.">
            <ApiForm
              path="inference/setBudget"
              tenantId={tenantId}
              submitLabel="Save budget"
              successMessage="Budget saved."
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'name', label: 'Name', required: true, placeholder: 'Daily per person' },
                {
                  name: 'subjectType',
                  label: 'Covers',
                  type: 'select',
                  required: true,
                  options: [
                    { value: 'tenant', label: 'Everyone in the organization' },
                    { value: 'group', label: 'A group' },
                    { value: 'identity', label: 'One person, service account or agent' },
                  ],
                },
                {
                  name: 'subjectId',
                  label: 'Group or identity',
                  type: 'select',
                  options: [
                    ...(groups ?? []).map((group) => ({
                      value: group.id,
                      label: `Group: ${group.name}`,
                    })),
                    ...(people ?? [])
                      .filter((person) => person.status === 'active')
                      .map((person) => ({
                        value: person.id,
                        label: `${person.kind === 'agent' ? 'Agent' : person.kind === 'service' ? 'Service' : 'Person'}: ${person.email ?? person.name}`,
                      })),
                  ],
                },
                {
                  name: 'scope',
                  label: 'Pool',
                  type: 'select',
                  options: [
                    { value: 'shared', label: 'One shared pool' },
                    { value: 'each', label: 'The full amount for each identity' },
                  ],
                },
                {
                  name: 'period',
                  label: 'Per',
                  type: 'select',
                  required: true,
                  options: [
                    { value: 'day', label: 'Day' },
                    { value: 'month', label: 'Month' },
                    { value: 'hour', label: 'Hour' },
                    { value: 'minute', label: 'Minute (rate limit)' },
                  ],
                },
                { name: 'maxTokens', label: 'Token limit', type: 'number' },
                { name: 'maxCostUsd', label: 'Cost limit (USD)', type: 'number' },
                {
                  name: 'maxRequests',
                  label: 'Call limit',
                  type: 'number',
                  help: 'The most calls per period, for agents that loop. Per minute, it is a requests-per-minute limit.',
                },
                {
                  name: 'models',
                  label: 'Only these models',
                  type: 'list',
                  placeholder: 'opus, claude-*',
                },
                {
                  name: 'alertAtPercent',
                  label: 'Alert at (%)',
                  type: 'number',
                  placeholder: '80',
                },
              ]}
            />
          </Card>
          <Alert tone="info">
            The gateway is at <code>/api/ai/v1/messages</code> (Anthropic) and{' '}
            <code>/api/ai/v1/chat/completions</code> (OpenAI). Use any Better IAM key or delegated
            agent token as the API key; the provider key never leaves the server.
          </Alert>
        </div>
      </div>
    </>
  );
}
