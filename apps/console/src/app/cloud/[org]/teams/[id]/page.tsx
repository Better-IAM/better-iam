import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, KeyValues, PageHeader, Table, Time } from '@/components/ui';
import { money } from '@/lib/billing';
import { birthrightPackages } from '@/lib/birthright';
import { BirthrightSuggestions } from '@/components/birthright-suggestions';
import { can, key, orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Team({ params }: { params: Promise<{ org: string; id: string }> }) {
  const { org, id } = await params;
  const page = await orgPage(org);
  const { iam, auth, tenantId, base, session } = page;
  const team = await tryRead(() => iam.api.teams.get(auth, { tenantId, teamId: id }));
  if (!team) notFound();
  // Settings, deletion, and role grants are administrator actions; maintainers only manage membership.
  const teamResource = { type: 'iam', id };
  const allowed = await can(page, [
    { action: 'iam:teams:update', resource: teamResource },
    { action: 'iam:teams:delete', resource: teamResource },
    { action: 'iam:bindings:create' },
  ]);
  const mayUpdate = allowed[key('iam:teams:update', teamResource)];
  const mayDelete = allowed[key('iam:teams:delete', teamResource)];
  const mayBind = allowed[key('iam:bindings:create', undefined, tenantId)];
  const [members, requests, candidates, roles, teams, departments] = await Promise.all([
    tryRead(() =>
      iam.api.teams.listMembers(auth, { tenantId, teamId: id, includeChildTeams: true }),
    ),
    tryRead(() => iam.api.teams.listRequests(auth, { tenantId, teamId: id })),
    // People who could join; maintainers may list them without iam:identities:read.
    tryRead(() => iam.api.teams.candidates(auth, { tenantId, teamId: id, limit: 200 })),
    tryRead(() => iam.api.roles.list(auth, { tenantId })),
    tryRead(() => iam.api.teams.list(auth, { tenantId })),
    tryRead(() => iam.api.departments.list(auth, { tenantId })),
  ]);
  const groups = await tryRead(() => iam.api.groups.list(auth, { tenantId }));
  // Billing: this month's spend of the team and the teams below it (maintainers may read it without a permission).
  const spend = await tryRead(() => iam.api.billing.teamSpend(auth, { tenantId, teamId: id }));
  // Birthright access: packages whose rule names this team or a team above it (administrators with iam:packages:read).
  const packages = await tryRead(() => iam.api.packages.list(auth, { tenantId }));
  const birthright = birthrightPackages(packages, 'identity.teams', [
    team.id,
    ...team.path.map((step) => step.id).reverse(),
  ]);
  // Access most members hold by hand, as a ready-made birthright package (with iam:analysis:read).
  const suggestions = await tryRead(() =>
    iam.api.teams.suggestBirthright(auth, { tenantId, teamId: id }),
  );
  // Membership reviews: maintainers and administrators see them.
  const reviews = await tryRead(() => iam.api.teams.listReviews(auth, { tenantId, teamId: id }));
  const openSummary = reviews?.find((review) => review.status === 'open');
  const openReview = openSummary
    ? await tryRead(() => iam.api.teams.getReview(auth, { tenantId, reviewId: openSummary.id }))
    : undefined;
  const past = (reviews ?? []).filter((review) => review.status !== 'open').slice(0, 5);
  const teamNames = new Map([
    ...team.path.map((step) => [step.id, step.name] as const),
    [team.id, team.name],
  ]);
  // A team cannot move under itself or a team below it, so those are left out of the parent choices.
  const parentOf = new Map((teams ?? []).map((item) => [item.id, item.parentId]));
  const belowThis = (teamId: string) => {
    for (let cursor = parentOf.get(teamId), depth = 0; cursor && depth < 20; depth++) {
      if (cursor === team.id) return true;
      cursor = parentOf.get(cursor);
    }
    return false;
  };
  const direct = members?.filter((member) => member.team.id === team.id) ?? [];
  const below = members?.filter((member) => member.team.id !== team.id) ?? [];
  const me = session.identity.id;
  const maintainer = team.maintainers.some((person) => person.id === me);
  return (
    <>
      <PageHeader
        title={team.name}
        description={
          <>
            <Link href={`${base}/teams`}>Teams</Link>
            {team.path.map((step) => (
              <span key={step.id}>
                {' › '}
                <Link href={`${base}/teams/${step.id}`}>{step.name}</Link>
              </span>
            ))}
            {' › '}
            {team.name}
            {team.description ? ` · ${team.description}` : ''}
          </>
        }
        actions={
          mayDelete && (
            <ApiButton
              path="teams/delete"
              body={{ tenantId, teamId: id }}
              label="Delete team"
              tone="danger"
              confirm="Delete this team, its memberships and join requests, and the roles bound to it?"
              redirectTo={`${base}/teams`}
              tenantId={tenantId}
            />
          )
        }
      />
      <div className="stack">
        <div className="tiles">
          <div className="card stat">
            <span className="label">Members</span>
            <span className="value">{team.memberCount}</span>
            <span className="hint">{team.totalMemberCount} with the teams below</span>
          </div>
          <div className="card stat">
            <span className="label">Maintainers</span>
            <span className="value">{team.maintainerCount}</span>
            <span className="hint">
              {team.memberManagement === 'admins'
                ? 'administrators manage members'
                : 'manage the membership'}
            </span>
          </div>
          <div className="card stat">
            <span className="label">Roles</span>
            <span className="value">{team.roles.length}</span>
            <span className="hint">
              {team.roles.filter((grant) => grant.inherited).length} from teams above
            </span>
          </div>
          <div className="card stat">
            <span className="label">Joining</span>
            <span className="value">{team.joinPolicy === 'request' ? 'On request' : 'Invite'}</span>
            <span className="hint">
              {requests?.length ?? 0} pending {requests?.length === 1 ? 'request' : 'requests'}
            </span>
          </div>
        </div>
        {maintainer && team.memberManagement !== 'admins' && (
          <Alert tone="info">
            You maintain this team: you can add and remove members and decide join requests here.
          </Alert>
        )}
        <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
          <Card title="Members" flush>
            <Table
              head={['Name', 'Role', 'Until', '']}
              rows={direct.map((member) => [
                <span key="n">
                  <Link href={`${base}/members/${member.id}`}>{member.name}</Link>
                  <br />
                  <span className="muted small">{member.email}</span>
                </span>,
                <span key="r" className="row">
                  <Badge tone={member.role === 'maintainer' ? 'accent' : 'neutral'}>
                    {member.role}
                  </Badge>
                  {member.source === 'sync' && <Badge tone="info">synced</Badge>}
                </span>,
                member.expiresAt ? (
                  <Time key="u" value={member.expiresAt} />
                ) : (
                  <span key="u" className="muted">
                    permanent
                  </span>
                ),
                <span key="a" className="actions">
                  <ApiButton
                    path="teams/updateMember"
                    body={{
                      tenantId,
                      teamId: id,
                      identityId: member.id,
                      role: member.role === 'maintainer' ? 'member' : 'maintainer',
                    }}
                    label={member.role === 'maintainer' ? 'Make member' : 'Make maintainer'}
                    tenantId={tenantId}
                  />
                  {/* Synced members come and go with their source groups. */}
                  {member.expiresAt && member.source !== 'sync' && (
                    <ApiButton
                      path="teams/updateMember"
                      body={{ tenantId, teamId: id, identityId: member.id, expiresAt: null }}
                      label="Make permanent"
                      tenantId={tenantId}
                    />
                  )}
                  {member.source !== 'sync' && (
                    <ApiButton
                      path="teams/removeMember"
                      body={{ tenantId, teamId: id, identityId: member.id }}
                      label="Remove"
                      tone="danger"
                      tenantId={tenantId}
                    />
                  )}
                </span>,
              ])}
              empty={members ? 'No members yet.' : 'You cannot see this team’s members.'}
            />
            {candidates && candidates.length > 0 && (
              <div className="card-body">
                <ApiForm
                  path="teams/addMembers"
                  tenantId={tenantId}
                  submitLabel="Add to team"
                  compact
                  successMessage="Added."
                  fields={[
                    { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                    { name: 'teamId', label: 'Team', type: 'hidden', defaultValue: id },
                    {
                      name: 'identityIds',
                      label: 'People',
                      type: 'multiselect',
                      required: true,
                      help: 'Hold Ctrl/Cmd to select several; the whole batch is added or nothing is.',
                      options: candidates.map((person) => ({
                        value: person.id,
                        label: person.email ? `${person.name} (${person.email})` : person.name,
                      })),
                    },
                    {
                      name: 'role',
                      label: 'Role',
                      type: 'select',
                      required: true,
                      defaultValue: 'member',
                      options: [
                        { value: 'member', label: 'Member' },
                        { value: 'maintainer', label: 'Maintainer (manages membership)' },
                      ],
                    },
                    {
                      name: 'expiresAt',
                      label: 'Member until',
                      type: 'datetime',
                      help: 'Optional: a temporary membership ends by itself.',
                    },
                  ]}
                />
              </div>
            )}
          </Card>
          <div className="stack">
            <Card
              title="Join requests"
              description={
                team.joinPolicy === 'request'
                  ? 'People asking to join. Approving adds them as members.'
                  : 'This team is invite only; switch joining to “on request” in the settings to accept requests.'
              }
              flush
            >
              {requests ? (
                <Table
                  head={['Person', 'Asked', '']}
                  rows={requests.map((request) => [
                    <span key="p">
                      {request.requester.name}
                      {request.justification && (
                        <>
                          <br />
                          <span className="muted small">“{request.justification}”</span>
                        </>
                      )}
                    </span>,
                    <Time key="t" value={request.requestedAt} />,
                    <span key="a" className="actions">
                      <ApiButton
                        path="teams/approveRequest"
                        body={{ tenantId, requestId: request.id }}
                        label="Approve"
                        tenantId={tenantId}
                      />
                      <ApiButton
                        path="teams/denyRequest"
                        body={{ tenantId, requestId: request.id }}
                        label="Deny"
                        tone="danger"
                        tenantId={tenantId}
                      />
                    </span>,
                  ])}
                  empty="No pending requests."
                />
              ) : (
                <div className="empty">Maintainers and administrators see join requests.</div>
              )}
            </Card>
            <Card title="Teams below" flush>
              <Table
                head={['Team', 'Members']}
                rows={team.children.map((child) => [
                  <Link key="n" href={`${base}/teams/${child.id}`}>
                    {child.name}
                  </Link>,
                  child.memberCount,
                ])}
                empty="No teams below this one."
              />
              {below.length > 0 && (
                <div className="card-body muted small">
                  Also in this team through the teams below:{' '}
                  {below.map((member) => `${member.name} (${member.team.name})`).join(', ')}
                </div>
              )}
            </Card>
          </div>
        </div>
        {(reviews || mayUpdate) && (
          <Card
            title="Membership review"
            description={
              openReview
                ? `Maintainers confirm who still belongs by ${new Date(openReview.dueAt).toUTCString()}. Removals take effect when the review completes; people nobody decides on then ${openReview.onUndecided === 'remove' ? 'leave the team' : 'stay'}.`
                : 'Ask the maintainers to confirm who still belongs in the team. Members team sync manages are reviewed through their source groups.'
            }
            actions={
              openReview && (
                <span className="actions">
                  <ApiButton
                    path="teams/completeReview"
                    body={{ tenantId, reviewId: openReview.id }}
                    label="Complete review"
                    tone="primary"
                    confirm={`Remove the ${openReview.counts.remove} people decided “remove”${openReview.onUndecided === 'remove' && openReview.counts.undecided ? ` and the ${openReview.counts.undecided} nobody decided on` : ''} from the team?`}
                    showResult
                    tenantId={tenantId}
                  />
                  {mayUpdate && (
                    <ApiButton
                      path="teams/cancelReview"
                      body={{ tenantId, reviewId: openReview.id }}
                      label="Cancel review"
                      tone="danger"
                      confirm="Cancel this review without changing the team?"
                      tenantId={tenantId}
                    />
                  )}
                </span>
              )
            }
            flush
          >
            {openReview?.items ? (
              <Table
                head={['Person', 'Role', 'Decision', '']}
                rows={openReview.items.map((item) => [
                  <span key="p">
                    {item.person.name}
                    <br />
                    <span className="muted small">{item.person.email}</span>
                  </span>,
                  item.role,
                  item.decision ? (
                    <span key="d">
                      <Badge tone={item.decision === 'keep' ? 'success' : 'danger'}>
                        {item.decision}
                      </Badge>{' '}
                      <span className="muted small">
                        by {item.decidedBy?.name}
                        {item.note ? ` · “${item.note}”` : ''}
                      </span>
                    </span>
                  ) : (
                    <span key="d" className="muted">
                      undecided
                    </span>
                  ),
                  item.person.id === me ? (
                    <span key="a" className="muted small">
                      someone else decides
                    </span>
                  ) : (
                    <span key="a" className="actions">
                      <ApiButton
                        path="teams/decideReview"
                        body={{
                          tenantId,
                          reviewId: openReview.id,
                          decisions: [{ identityId: item.person.id, decision: 'keep' }],
                        }}
                        label="Keep"
                        tenantId={tenantId}
                      />
                      <ApiButton
                        path="teams/decideReview"
                        body={{
                          tenantId,
                          reviewId: openReview.id,
                          decisions: [{ identityId: item.person.id, decision: 'remove' }],
                        }}
                        label="Remove"
                        tone="danger"
                        tenantId={tenantId}
                      />
                    </span>
                  ),
                ])}
              />
            ) : (
              mayUpdate && (
                <div className="card-body">
                  <ApiForm
                    path="teams/startReview"
                    tenantId={tenantId}
                    submitLabel="Start review"
                    compact
                    successMessage="Review started; the maintainers were emailed."
                    fields={[
                      { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                      { name: 'teamId', label: 'Team', type: 'hidden', defaultValue: id },
                      {
                        name: 'dueAt',
                        label: 'Due',
                        type: 'datetime',
                        help: 'One to 90 days ahead; 14 days when left empty.',
                      },
                      {
                        name: 'onUndecided',
                        label: 'People nobody decides on',
                        type: 'select',
                        required: true,
                        defaultValue: 'keep',
                        options: [
                          { value: 'keep', label: 'Stay in the team' },
                          { value: 'remove', label: 'Leave the team' },
                        ],
                      },
                      {
                        name: 'note',
                        label: 'Note for the maintainers',
                        type: 'textarea',
                        rows: 2,
                      },
                    ]}
                  />
                </div>
              )
            )}
            {past.length > 0 && (
              <div className="card-body muted small">
                Earlier reviews:{' '}
                {past
                  .map((review) =>
                    review.status === 'cancelled'
                      ? `cancelled (started ${new Date(review.startedAt).toLocaleDateString('en')})`
                      : `${new Date(review.completedAt ?? review.startedAt).toLocaleDateString('en')}: ${review.outcome?.kept ?? 0} kept, ${review.outcome?.removed ?? 0} removed`,
                  )
                  .join(' · ')}
              </div>
            )}
          </Card>
        )}
        <Card
          title="Access through this team"
          description="Roles bound to this team or to a team above it; every member of this team holds them."
          flush
        >
          <Table
            head={['Role', 'Bound to', 'Kind', '']}
            rows={team.roles.map((grant) => [
              <Link key="r" href={`${base}/roles/${grant.roleId}`}>
                {grant.roleName}
              </Link>,
              grant.inherited ? (
                <Link key="t" href={`${base}/teams/${grant.team.id}`}>
                  {grant.team.name}
                </Link>
              ) : (
                <span key="t">this team</span>
              ),
              <span key="k" className="row">
                {grant.eligible && <Badge tone="info">eligible</Badge>}
                {grant.expiresAt ? (
                  <span className="muted small">
                    until <Time value={grant.expiresAt} />
                  </span>
                ) : (
                  !grant.eligible && <span className="muted small">standing</span>
                )}
              </span>,
              grant.inherited || !mayBind ? (
                <span key="d" className="muted small">
                  {grant.inherited ? 'inherited' : ''}
                </span>
              ) : (
                <ApiButton
                  key="d"
                  path="bindings/delete"
                  body={{ tenantId, bindingId: grant.bindingId }}
                  label="Remove"
                  tone="danger"
                  tenantId={tenantId}
                />
              ),
            ])}
            empty="The team holds no roles."
          />
          {roles && mayBind && (
            <div className="card-body">
              <ApiForm
                path="bindings/create"
                tenantId={tenantId}
                submitLabel="Give the team a role"
                compact
                successMessage="Role bound."
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  { name: 'subjectType', label: 'Subject', type: 'hidden', defaultValue: 'group' },
                  { name: 'subjectId', label: 'Group', type: 'hidden', defaultValue: team.groupId },
                  {
                    name: 'roleId',
                    label: 'Role',
                    type: 'select',
                    required: true,
                    help: 'Maintainers of this team (and of the teams below it) can then hand this role to anyone they add.',
                    options: roles
                      .filter((role) => !role.protected)
                      .map((role) => ({ value: role.id, label: role.name })),
                  },
                ]}
              />
            </div>
          )}
        </Card>
        {birthright.length > 0 && (
          <Card
            title="Birthright access"
            description="Access packages whose rule names this team or a team above it: members who meet the rest of the rule receive them automatically, and lose them when they leave."
            actions={
              <Link className="btn small secondary" href={`${base}/packages`}>
                Packages
              </Link>
            }
            flush
          >
            <Table
              head={['Package', 'Rule names', 'Holders', 'Status']}
              rows={birthright.map(({ pkg, via }) => [
                <strong key="n">{pkg.name}</strong>,
                via === team.id ? (
                  <span key="v">this team</span>
                ) : (
                  <Link key="v" href={`${base}/teams/${via}`}>
                    {teamNames.get(via) ?? via}
                  </Link>
                ),
                `${pkg.automaticAssignments ?? 0} automatic`,
                pkg.autoAssign?.status === 'active' ? (
                  <Badge key="s" tone="success">
                    active
                  </Badge>
                ) : (
                  <Badge key="s" tone="warning">
                    suspended
                  </Badge>
                ),
              ])}
            />
          </Card>
        )}
        <BirthrightSuggestions suggestions={suggestions ?? []} tenantId={tenantId} base={base} />
        {spend && (
          <Card
            title="Spend this month"
            description={`${money(spend.total.costMicros, spend.currency)} by the people of this team and the teams below it${spend.forecast ? `, on track for ${money(spend.forecast.costMicros, spend.currency)}` : ''}. People in several teams count toward each in equal parts.`}
            actions={
              <Link className="btn small secondary" href={`${base}/billing?view=team`}>
                Billing
              </Link>
            }
            flush
          >
            <Table
              head={['Person or account', 'Spend', 'Share']}
              rows={spend.rows.map((row) => [
                row.label ?? row.key,
                money(row.costMicros, spend.currency),
                `${row.share}%`,
              ])}
              empty="No spend this month."
            />
          </Card>
        )}
        <div className="grid cols-2">
          <Card title="Details">
            <KeyValues
              items={[
                ['Slug', <code key="s">{team.slug}</code>],
                [
                  'Department',
                  team.department ? (
                    <Link key="d" href={`${base}/departments/${team.department.id}`}>
                      {team.department.name}
                    </Link>
                  ) : (
                    <span key="d" className="muted">
                      none
                    </span>
                  ),
                ],
                [
                  'Maintainers',
                  team.maintainers.length ? (
                    team.maintainers.map((person) => person.name).join(', ')
                  ) : (
                    <span key="m" className="muted">
                      none: only administrators manage it
                    </span>
                  ),
                ],
                ['Backing group', <code key="g">team:{team.slug}</code>],
                [
                  'Team sync',
                  team.syncGroups.length ? (
                    <span key="s">
                      {team.syncGroups.map((group, index) => (
                        <span key={group.id}>
                          {index > 0 && ', '}
                          <Link href={`${base}/groups/${group.id}`}>{group.name}</Link>
                        </span>
                      ))}
                    </span>
                  ) : (
                    <span key="s" className="muted">
                      off
                    </span>
                  ),
                ],
                ['Created', <Time key="c" value={team.createdAt} />],
              ]}
            />
          </Card>
          {mayUpdate && (
            <Card title="Settings">
              <ApiForm
                path="teams/update"
                tenantId={tenantId}
                submitLabel="Save"
                compact
                successMessage="Saved."
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  { name: 'teamId', label: 'Team', type: 'hidden', defaultValue: id },
                  { name: 'name', label: 'Name', required: true, defaultValue: team.name },
                  { name: 'slug', label: 'Slug', required: true, defaultValue: team.slug },
                  {
                    name: 'description',
                    label: 'Description',
                    type: 'textarea',
                    rows: 2,
                    emptyAsNull: true,
                    defaultValue: team.description ?? '',
                  },
                  // Offered only when the choices could be read: an empty select would clear the value on save.
                  ...(teams
                    ? [
                        {
                          name: 'parentId',
                          label: 'Parent team',
                          type: 'select' as const,
                          emptyAsNull: true,
                          defaultValue: team.parentId ?? '',
                          options: teams
                            .filter((other) => other.id !== team.id && !belowThis(other.id))
                            .map((other) => ({ value: other.id, label: other.name })),
                        },
                      ]
                    : []),
                  ...(departments
                    ? [
                        {
                          name: 'departmentId',
                          label: 'Department',
                          type: 'select' as const,
                          emptyAsNull: true,
                          defaultValue: team.departmentId ?? '',
                          options: departments.map((item) => ({
                            value: item.id,
                            label: item.name,
                          })),
                        },
                      ]
                    : []),
                  {
                    name: 'joinPolicy',
                    label: 'Joining',
                    type: 'select',
                    required: true,
                    defaultValue: team.joinPolicy,
                    options: [
                      { value: 'closed', label: 'Invite only' },
                      { value: 'request', label: 'On request' },
                    ],
                  },
                  {
                    name: 'memberManagement',
                    label: 'Who manages members',
                    type: 'select',
                    required: true,
                    defaultValue: team.memberManagement,
                    options: [
                      { value: 'maintainers', label: 'Maintainers and administrators' },
                      { value: 'admins', label: 'Administrators only' },
                    ],
                  },
                  // Offered only when the groups could be read: an empty list would stop syncing.
                  ...(groups
                    ? [
                        {
                          name: 'syncGroupIds',
                          label: 'Sync members from groups',
                          type: 'multiselect' as const,
                          emptyAsNull: true,
                          defaultValue: team.syncGroupIds ?? [],
                          help: 'Team sync: everyone in these groups (for example directory groups provisioned by SCIM) is a member; leaving the group removes them. Clear to stop syncing.',
                          options: groups
                            .filter((group) => !group.teamId)
                            .map((group) => ({ value: group.id, label: group.name })),
                        },
                      ]
                    : []),
                ]}
              />
            </Card>
          )}
        </div>
      </div>
    </>
  );
}
