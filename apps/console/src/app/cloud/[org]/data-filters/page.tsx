import { describeFilter, filterToMongo, filterToPrisma, filterToSql, type ResourceFilter } from 'better-iam/core';
import { Alert, Badge, Card, PageHeader, type Tone } from '@/components/ui';
import { isIamError } from '@/lib/errors';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

interface Query {
  identity?: string;
  action?: string;
  type?: string;
  mfa?: string;
}

const kindTone: Record<string, Tone> = { always: 'success', never: 'danger', conditional: 'accent' };

/** A compiled form of the filter, or why the target cannot express it. */
function compiled(compile: () => string): { text: string; error?: undefined } | { error: string } {
  try {
    return { text: compile() };
  } catch (error) {
    if (isIamError(error)) return { error: error.message };
    throw error;
  }
}

/** Fields as quoted SQL identifiers, the way a table named after the attributes would spell them. */
const quoted = (field: string) => `"${field.replaceAll('"', '""')}"`;

export default async function DataFilters({
  params,
  searchParams,
}: {
  params: Promise<{ org: string }>;
  searchParams: Promise<Query>;
}) {
  const { org } = await params;
  const query = await searchParams;
  const { iam, auth, tenantId } = await orgPage(org);
  const [types, members] = await Promise.all([
    tryRead(() => iam.api.resourceTypes.list(auth, { tenantId })),
    tryRead(() => iam.api.identities.list(auth, { tenantId })),
  ]);
  const ready = Boolean(query.identity && query.action && query.type);
  let plan: { kind: string; filter: ResourceFilter } | { error: string } | undefined;
  if (ready)
    try {
      plan =
        query.identity === 'me'
          ? await iam.api.filters.plan(auth, { tenantId, action: query.action!, type: query.type! })
          : await iam.api.filters.planFor(auth, {
              tenantId,
              identityId: query.identity!,
              action: query.action!,
              type: query.type!,
              assumeMfa: query.mfa === '1',
            });
    } catch (error) {
      if (!isIamError(error)) throw error;
      plan = { error: `${error.code}: ${error.message}` };
    }
  const outputs =
    plan && !('error' in plan) && plan.kind === 'conditional'
      ? {
          postgres: compiled(() => {
            const where = filterToSql(plan.filter, { dialect: 'postgres', column: quoted });
            return `${where.sql}\n-- params: ${JSON.stringify(where.params)}`;
          }),
          sqlite: compiled(() => {
            const where = filterToSql(plan.filter, { dialect: 'sqlite', column: quoted });
            return `${where.sql}\n-- params: ${JSON.stringify(where.params)}`;
          }),
          prisma: compiled(() => JSON.stringify(filterToPrisma(plan.filter), null, 2)),
          mongo: compiled(() =>
            JSON.stringify(
              filterToMongo(plan.filter),
              (_, value: unknown) => (value instanceof RegExp ? String(value) : value),
              2,
            ),
          ),
        }
      : undefined;
  return (
    <>
      <PageHeader
        title="Data filters"
        description="Which resources of a type someone may act on, as a filter your application applies in its own database query. The plan is computed from the same roles, policies, relationships and session limits as every decision, and matches authorize for each row."
      />
      <div className="grid cols-2" style={{ gridTemplateColumns: '2fr 3fr' }}>
        <Card title="Preview a plan" description="Previewing someone else's plan requires iam:policies:simulate on them.">
          <form className="form" method="get">
            <div className="field">
              <label htmlFor="identity">Person or account</label>
              <select id="identity" className="select" name="identity" defaultValue={query.identity ?? 'me'} required>
                <option value="me">Me (this session)</option>
                {(members ?? []).map((identity) => (
                  <option key={identity.id} value={identity.id}>
                    {identity.name}
                    {identity.email ? ` (${identity.email})` : ''}
                  </option>
                ))}
              </select>
            </div>
            <div className="field">
              <label htmlFor="action">Action</label>
              <input
                id="action"
                className="input"
                name="action"
                defaultValue={query.action ?? ''}
                placeholder="documents:read"
                required
              />
            </div>
            <div className="field">
              <label htmlFor="type">Resource type</label>
              <input
                id="type"
                className="input"
                name="type"
                list="resource-types"
                defaultValue={query.type ?? ''}
                placeholder="document"
                required
              />
              <datalist id="resource-types">
                {(types ?? []).map((type) => (
                  <option key={type.name} value={type.name} />
                ))}
              </datalist>
            </div>
            <div className="field inline">
              <input id="mfa" type="checkbox" name="mfa" value="1" defaultChecked={query.mfa === '1'} />
              <label htmlFor="mfa">Plan as an MFA session</label>
            </div>
            <div className="form-actions">
              <button className="btn">Plan</button>
            </div>
          </form>
        </Card>
        <div className="stack">
          {!plan && (
            <Alert tone="info">
              Pick a person, an action such as <code>documents:read</code> and a resource type. In code:{' '}
              <code>iam.planResources(&#123; headers, tenantId, action, type &#125;)</code>, then{' '}
              <code>filterToSql</code>, <code>filterToPrisma</code> or <code>filterToMongo</code> from{' '}
              <code>better-iam/core</code>.
            </Alert>
          )}
          {plan && 'error' in plan && <Alert tone="danger">{plan.error}</Alert>}
          {plan && !('error' in plan) && (
            <Card
              title="Plan"
              actions={<Badge tone={kindTone[plan.kind] ?? 'neutral'}>{plan.kind}</Badge>}
              description={
                plan.kind === 'always'
                  ? 'Every resource of this type: no filter needed.'
                  : plan.kind === 'never'
                    ? 'No resource of this type: skip the query.'
                    : 'The resources that pass this filter, over id and the resource attributes.'
              }
            >
              <pre className="result">{describeFilter(plan.filter)}</pre>
            </Card>
          )}
          {outputs &&
            (
              [
                ['PostgreSQL', outputs.postgres],
                ['SQLite', outputs.sqlite],
                ['Prisma where', outputs.prisma],
                ['MongoDB query', outputs.mongo],
              ] as const
            ).map(([label, output]) => (
              <Card key={label} title={label}>
                {'error' in output && output.error !== undefined ? (
                  <div className="empty">{output.error}</div>
                ) : (
                  <pre className="result">{output.text}</pre>
                )}
              </Card>
            ))}
        </div>
      </div>
    </>
  );
}
