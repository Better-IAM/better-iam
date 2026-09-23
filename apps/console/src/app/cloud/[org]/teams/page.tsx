import Link from 'next/link';
import type { TeamSummary } from 'better-iam';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

/** Teams in tree order (each parent followed by its children), with their depth. */
function treeOrder(teams: TeamSummary[]): Array<{ team: TeamSummary; depth: number }> {
  const known = new Set(teams.map((team) => team.id));
  const children = new Map<string, TeamSummary[]>();
  const roots: TeamSummary[] = [];
  for (const team of teams)
    if (team.parentId && known.has(team.parentId))
      children.set(team.parentId, [...(children.get(team.parentId) ?? []), team]);
    else roots.push(team);
  const ordered: Array<{ team: TeamSummary; depth: number }> = [];
  const visit = (team: TeamSummary, depth: number) => {
    ordered.push({ team, depth });
    for (const child of children.get(team.id) ?? []) visit(child, depth + 1);
  };
  for (const root of roots) visit(root, 0);
  return ordered;
}

export default async function Teams({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const [teams, mine, identities, departments, groups] = await Promise.all([
    tryRead(() => iam.api.teams.list(auth, { tenantId })),
    tryRead(() => iam.api.teams.listMine(auth, { tenantId })),
    tryRead(() => iam.api.identities.list(auth, { tenantId, kind: 'user', status: 'active' })),
    tryRead(() => iam.api.departments.list(auth, { tenantId })),
    tryRead(() => iam.api.groups.list(auth, { tenantId })),
  ]);
  const departmentName = new Map((departments ?? []).map((item) => [item.id, item.name]));
  const pending = mine?.requests.filter((request) => request.status === 'pending') ?? [];
  return (
    <>
      <PageHeader
        title="Teams"
        description="Teams group people inside the organization. Maintainers manage their own team's membership; roles bound to a team reach everyone in it and in the teams below it."
      />
      <div className="stack">
        {mine && mine.reviews.length > 0 && (
          <Alert tone="warning">
            Membership reviews wait for you:{' '}
            {mine.reviews.map((review, index) => (
              <span key={review.id}>
                {index > 0 && ', '}
                <Link href={`${base}/teams/${review.team.id}`}>{review.team.name}</Link> (
                {review.undecided} to decide, due <Time value={review.dueAt} />)
              </span>
            ))}
          </Alert>
        )}
        {mine && (
          <div className="grid cols-2">
            <Card title="Your teams" flush>
              <Table
                head={['Team', 'Role', 'Until', '']}
                rows={mine.teams.map((team) => [
                  <span key="n">
                    <Link href={`${base}/teams/${team.id}`}>{team.name}</Link>
                    {team.parents.length > 0 && (
                      <span className="muted small">
                        {' '}
                        in {team.parents.map((parent) => parent.name).join(' › ')}
                      </span>
                    )}
                  </span>,
                  <Badge key="r" tone={team.role === 'maintainer' ? 'accent' : 'neutral'}>
                    {team.role}
                  </Badge>,
                  team.expiresAt ? (
                    <Time key="u" value={team.expiresAt} />
                  ) : (
                    <span key="u" className="muted">
                      permanent
                    </span>
                  ),
                  <ApiButton
                    key="l"
                    path="teams/leave"
                    body={{ tenantId, teamId: team.id }}
                    label="Leave"
                    tone="danger"
                    confirm={`Leave ${team.name}? You lose the access the team gives you.`}
                    tenantId={tenantId}
                  />,
                ])}
                empty="You are not in any team yet."
              />
            </Card>
            <Card
              title="Join a team"
              description="Teams that take join requests. A maintainer decides; you are emailed the answer."
              flush
            >
              <Table
                head={['Team', 'Members', '']}
                rows={mine.joinable.map((team) => {
                  const request = pending.find((item) => item.team.id === team.id);
                  return [
                    <span key="n">
                      <strong>{team.name}</strong>
                      {team.description && (
                        <>
                          <br />
                          <span className="muted small">{team.description}</span>
                        </>
                      )}
                    </span>,
                    team.memberCount,
                    request ? (
                      <span key="a" className="actions">
                        <Badge tone="warning">requested</Badge>
                        <ApiButton
                          path="teams/cancelRequest"
                          body={{ tenantId, requestId: request.id }}
                          label="Withdraw"
                          tenantId={tenantId}
                        />
                      </span>
                    ) : (
                      <ApiButton
                        key="a"
                        path="teams/requestToJoin"
                        body={{ tenantId, teamId: team.id }}
                        label="Ask to join"
                        tenantId={tenantId}
                      />
                    ),
                  ];
                })}
                empty="No team takes join requests right now."
              />
            </Card>
          </div>
        )}
        <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
          <Card title="All teams" flush>
            {teams ? (
              <Table
                head={['Team', 'Members', 'Maintainers', 'Department', 'Joining']}
                rows={treeOrder(teams).map(({ team, depth }) => [
                  <span key="n" style={{ paddingLeft: depth * 18 }}>
                    {depth > 0 && <span className="muted">└ </span>}
                    <Link href={`${base}/teams/${team.id}`}>{team.name}</Link>{' '}
                    <code className="small">{team.slug}</code>
                  </span>,
                  team.memberCount,
                  team.maintainerCount || <span className="muted">none</span>,
                  team.departmentId ? (
                    <Link key="d" href={`${base}/departments/${team.departmentId}`}>
                      {departmentName.get(team.departmentId) ?? 'department'}
                    </Link>
                  ) : (
                    <span key="d" className="muted">
                      —
                    </span>
                  ),
                  team.joinPolicy === 'request' ? (
                    <Badge key="j" tone="info">
                      on request
                    </Badge>
                  ) : (
                    <span key="j" className="muted">
                      invite only
                    </span>
                  ),
                ])}
                empty="No teams yet."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:teams:read</code>.
              </div>
            )}
          </Card>
          <Card title="Create a team">
            <ApiForm
              path="teams/create"
              tenantId={tenantId}
              submitLabel="Create team"
              redirectTo={`${base}/teams/{id}`}
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'name', label: 'Name', required: true, placeholder: 'Platform' },
                {
                  name: 'slug',
                  label: 'Slug',
                  placeholder: 'platform',
                  help: 'Lowercase letters, digits, and hyphens; derived from the name when left empty.',
                },
                { name: 'description', label: 'Description', type: 'textarea', rows: 2 },
                {
                  name: 'parentId',
                  label: 'Parent team',
                  type: 'select',
                  help: 'Members of the new team also receive what is bound to the parent.',
                  options: (teams ?? []).map((team) => ({ value: team.id, label: team.name })),
                },
                {
                  name: 'departmentId',
                  label: 'Department',
                  type: 'select',
                  options: (departments ?? []).map((item) => ({
                    value: item.id,
                    label: item.code ? `${item.name} (${item.code})` : item.name,
                  })),
                },
                {
                  name: 'joinPolicy',
                  label: 'Joining',
                  type: 'select',
                  required: true,
                  defaultValue: 'closed',
                  options: [
                    { value: 'closed', label: 'Invite only: maintainers add people' },
                    { value: 'request', label: 'On request: people ask, maintainers decide' },
                  ],
                },
                {
                  name: 'maintainerIds',
                  label: 'Maintainers',
                  type: 'multiselect',
                  help: 'Up to 20 people who manage the team’s membership.',
                  options: (identities ?? []).map((identity) => ({
                    value: identity.id,
                    label: `${identity.name} (${identity.email ?? identity.kind})`,
                  })),
                },
                {
                  name: 'syncGroupIds',
                  label: 'Sync members from groups',
                  type: 'multiselect',
                  help: 'Team sync: everyone in these groups (such as SCIM directory groups) becomes a member, and leaves with the group.',
                  options: (groups ?? [])
                    .filter((group) => !group.teamId)
                    .map((group) => ({ value: group.id, label: group.name })),
                },
              ]}
            />
          </Card>
        </div>
      </div>
    </>
  );
}
