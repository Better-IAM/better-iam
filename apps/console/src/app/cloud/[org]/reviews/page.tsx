import Link from 'next/link';
import { Alert, Badge, Card, PageHeader, Table } from '@/components/ui';
import { isIamError } from '@/lib/errors';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

interface Query {
  mode?: string;
  action?: string;
  type?: string;
  id?: string;
  identity?: string;
  mfa?: string;
}

/** Review reads may be denied or hit an unregistered resource; both render inline instead of failing the page. */
async function review<T>(read: () => Promise<T>): Promise<T | { error: string }> {
  try {
    return await read();
  } catch (error) {
    if (isIamError(error)) return { error: `${error.code}: ${error.message}` };
    throw error;
  }
}

export default async function Reviews({
  params,
  searchParams,
}: {
  params: Promise<{ org: string }>;
  searchParams: Promise<Query>;
}) {
  const { org } = await params;
  const query = await searchParams;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const [actions, types, members] = await Promise.all([
    tryRead(() => iam.api.actions.list(auth, { tenantId })),
    tryRead(() => iam.api.resourceTypes.list(auth, { tenantId })),
    tryRead(() => iam.api.identities.list(auth, { tenantId })),
  ]);
  const resource = query.type && query.id ? { type: query.type, id: query.id } : undefined;
  const assumeMfa = query.mfa === '1';
  const who =
    query.mode === 'who' && query.action && resource
      ? await review(() =>
          iam.api.policies.whoCan(auth, { tenantId, action: query.action!, resource, assumeMfa }),
        )
      : undefined;
  const effective =
    query.mode === 'actions' && query.identity && resource
      ? await review(() =>
          iam.api.policies.effectiveActions(auth, {
            tenantId,
            identityId: query.identity!,
            resource,
            assumeMfa,
          }),
        )
      : undefined;
  const memberName = (identityId: string) =>
    members?.find((identity) => identity.id === identityId)?.name ?? identityId;
  const resourceFields = (
    <>
      <div className="field">
        <label htmlFor="type">Resource type</label>
        <select id="type" className="select" name="type" defaultValue={query.type ?? ''} required>
          <option value="">—</option>
          {(types ?? []).map((type) => (
            <option key={type.name} value={type.name}>
              {type.name}
            </option>
          ))}
        </select>
      </div>
      <div className="field">
        <label htmlFor="id">Resource ID</label>
        <input
          id="id"
          className="input"
          name="id"
          defaultValue={query.id ?? ''}
          placeholder="acme-prod"
          required
        />
      </div>
      <div className="field inline">
        <input id="mfa" type="checkbox" name="mfa" value="1" defaultChecked={assumeMfa} />
        <label htmlFor="mfa">Simulate an MFA session</label>
      </div>
    </>
  );
  return (
    <>
      <PageHeader
        title="Access reviews"
        description="Answer “who can do this?” and “what can this person do here?” from the same policy engine that enforces requests. Reviews need iam:policies:simulate, simulate synthetic sessions, and grant nothing."
      />
      <div className="grid cols-2">
        <Card
          title="Who can perform an action"
          description="Every active identity whose roles, groups, and relationships allow the action on one resource."
        >
          <form method="get" className="form">
            <input type="hidden" name="mode" value="who" />
            <div className="field">
              <label htmlFor="action">Action</label>
              <select
                id="action"
                className="select"
                name="action"
                defaultValue={query.action ?? ''}
                required
              >
                <option value="">—</option>
                {(actions ?? []).map((action) => (
                  <option key={action.name} value={action.name}>
                    {action.name}
                  </option>
                ))}
              </select>
            </div>
            {resourceFields}
            <div className="form-actions">
              <button className="btn">Review</button>
            </div>
          </form>
          {who && 'error' in who && <Alert tone="danger">{who.error}</Alert>}
        </Card>
        <Card
          title="What an identity can do"
          description="Every catalog action evaluated for one identity against one resource."
        >
          <form method="get" className="form">
            <input type="hidden" name="mode" value="actions" />
            <div className="field">
              <label htmlFor="identity">Identity</label>
              <select
                id="identity"
                className="select"
                name="identity"
                defaultValue={query.identity ?? ''}
                required
              >
                <option value="">—</option>
                {(members ?? []).map((identity) => (
                  <option key={identity.id} value={identity.id}>
                    {identity.name} {identity.kind === 'service' ? '(service account)' : ''}
                  </option>
                ))}
              </select>
            </div>
            {resourceFields}
            <div className="form-actions">
              <button className="btn">Review</button>
            </div>
          </form>
          {effective && 'error' in effective && <Alert tone="danger">{effective.error}</Alert>}
        </Card>
      </div>
      {who && !('error' in who) && (
        <Card
          title={`${who.total} identit${who.total === 1 ? 'y' : 'ies'} can ${query.action} on ${query.type}/${query.id}`}
          description={
            assumeMfa
              ? 'Evaluated as if each person had completed MFA.'
              : 'Evaluated without MFA; conditions on principal.mfa see false.'
          }
          flush
        >
          <Table
            head={['Identity', 'Email', 'Kind', 'Reason']}
            rows={who.identities.map((match) => [
              <Link key="n" href={`${base}/members/${match.identityId}`}>
                {match.name}
              </Link>,
              match.email ?? <span className="muted">—</span>,
              match.kind,
              <code key="r" className="small">
                {match.reason}
              </code>,
            ])}
            empty="Nobody. Root administrators are not listed because their override applies everywhere."
          />
        </Card>
      )}
      {effective && !('error' in effective) && (
        <Card
          title={`${memberName(query.identity!)} on ${query.type}/${query.id}: ${effective.allowed.length} of ${effective.results.length} actions allowed`}
          flush
        >
          <Table
            head={['Action', 'Decision', 'Reason']}
            rows={effective.results.map((result) => [
              <code key="a">{result.action}</code>,
              result.allowed ? (
                <Badge key="d" tone="success">
                  allowed
                </Badge>
              ) : (
                <Badge key="d" tone="danger">
                  denied
                </Badge>
              ),
              <code key="r" className="small">
                {result.reason}
              </code>,
            ])}
          />
        </Card>
      )}
      {!actions && (
        <Alert tone="warning">
          Actions are not listed because you lack <code>iam:actions:read</code>; reviews themselves
          need <code>iam:policies:simulate</code>.
        </Alert>
      )}
    </>
  );
}
