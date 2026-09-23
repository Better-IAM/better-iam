import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ApiButton, ApiForm } from '@/components/api-form';
import { ImpersonateForm } from '@/components/impersonation';
import {
  Alert,
  Badge,
  Card,
  KeyValues,
  PageHeader,
  StatusBadge,
  Table,
  Time,
} from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Member({ params }: { params: Promise<{ org: string; id: string }> }) {
  const { org, id } = await params;
  const { iam, auth, tenantId, tenant, base, session } = await orgPage(org);
  const identity = await tryRead(() => iam.api.identities.get(auth, { tenantId, identityId: id }));
  if (!identity) notFound();
  const [bindings, groups, roles, allGroups, shares, members, reports] = await Promise.all([
    tryRead(() => iam.api.identities.listBindings(auth, { tenantId, identityId: id })),
    tryRead(() => iam.api.identities.listGroups(auth, { tenantId, identityId: id })),
    tryRead(() => iam.api.roles.list(auth, { tenantId })),
    tryRead(() => iam.api.groups.list(auth, { tenantId })),
    tryRead(() =>
      iam.api.relationships.list(auth, { tenantId, subjectType: 'identity', subjectId: id }),
    ),
    tryRead(() => iam.api.identities.list(auth, { tenantId, limit: 1000 })),
    tryRead(() => iam.api.identities.listReports(auth, { tenantId, identityId: id })),
  ]);
  // The manager may sit beyond the loaded page of members.
  const manager = identity.managerId
    ? (members?.find((member) => member.id === identity.managerId) ??
      (await tryRead(() =>
        iam.api.identities.get(auth, { tenantId, identityId: identity.managerId! }),
      )))
    : undefined;
  const activations = await tryRead(() =>
    iam.api.bindings.listActivations(auth, { tenantId, identityId: id, includeExpired: true }),
  );
  // What this member actually used (accessUsage option; needs iam:analysis:read).
  const usage = await tryRead(() =>
    iam.api.roleMining.usage(auth, { tenantId, identityId: id, limit: 50 }),
  );
  // Teams and department (teams.ts / departments.ts; need iam:teams:read / iam:departments:read).
  const [memberTeams, memberDepartment, allTeams, allDepartments] = await Promise.all([
    tryRead(() => iam.api.teams.listForIdentity(auth, { tenantId, identityId: id })),
    tryRead(() => iam.api.departments.ofIdentity(auth, { tenantId, identityId: id })),
    tryRead(() => iam.api.teams.list(auth, { tenantId })),
    tryRead(() => iam.api.departments.list(auth, { tenantId })),
  ]);
  return (
    <>
      <PageHeader
        title={
          <>
            {identity.name} <StatusBadge status={identity.status} />
          </>
        }
        description={
          <>
            {identity.email ?? 'service account'} ·{' '}
            <Link href={`${base}/members`}>all members</Link>
          </>
        }
        actions={
          identity.id !== session.identity.id &&
          identity.kind === 'user' && (
            <>
              <ApiButton
                path="identities/unlock"
                body={{ tenantId, identityId: id }}
                label="Unlock"
                showResult
                tenantId={tenantId}
              />
              {identity.email && (
                <ApiButton
                  path="identities/requestPasswordReset"
                  body={{ tenantId, identityId: id }}
                  label="Send password reset"
                  confirm={`Email a password-reset link to ${identity.email}?`}
                  tenantId={tenantId}
                />
              )}
              <ApiButton
                path="identities/revokeSessions"
                body={{ tenantId, identityId: id }}
                label="Sign out everywhere"
                confirm="End every session of this member? They stay active and can sign in again."
                tenantId={tenantId}
              />
              <ApiButton
                path="identities/export"
                body={{ tenantId, identityId: id }}
                label="Export data"
                showResult
                tenantId={tenantId}
              />
              {identity.owner ? (
                <ApiButton
                  path="identities/setOwner"
                  body={{ tenantId, identityId: id, owner: false }}
                  label="Remove owner"
                  tone="danger"
                  confirm="Remove ownership from this member?"
                  tenantId={tenantId}
                />
              ) : (
                <ApiButton
                  path="identities/setOwner"
                  body={{ tenantId, identityId: id, owner: true }}
                  label="Make owner"
                  confirm="Grant full ownership of this organization?"
                  tenantId={tenantId}
                />
              )}
            </>
          )
        }
      />
      <div className="stack">
        <div className="grid cols-3">
          <Card title="Identity">
            <KeyValues
              items={[
                [
                  'ID',
                  <code key="i" className="small">
                    {identity.id}
                  </code>,
                ],
                ['Kind', identity.kind],
                ['Owner', identity.owner ? 'yes' : 'no'],
                ['Email verified', identity.emailVerified ? 'yes' : 'no'],
                ['Created', <Time key="c" value={identity.createdAt} />],
                [
                  'Deactivates',
                  identity.expiresAt ? (
                    <span key="x" className="row">
                      <Time value={identity.expiresAt} />
                      {identity.expiresAt <= Date.now() && <Badge tone="danger">expired</Badge>}
                      <ApiButton
                        path="identities/update"
                        body={{ tenantId, identityId: id, expiresAt: null }}
                        label="Clear"
                        tenantId={tenantId}
                      />
                    </span>
                  ) : (
                    'never'
                  ),
                ],
                [
                  'Manager',
                  identity.managerId ? (
                    <span key="m" className="row">
                      <Link href={`${base}/members/${identity.managerId}`}>
                        {manager?.name ?? identity.managerId}
                      </Link>
                      {manager && manager.status !== 'active' && (
                        <StatusBadge status={manager.status} />
                      )}
                      <ApiButton
                        path="identities/update"
                        body={{ tenantId, identityId: id, managerId: null }}
                        label="Clear"
                        tenantId={tenantId}
                      />
                    </span>
                  ) : (
                    '—'
                  ),
                ],
                [
                  'Attributes',
                  identity.attributes && Object.keys(identity.attributes).length ? (
                    <code key="at" className="small">
                      {Object.entries(identity.attributes)
                        .map(([name, value]) => `${name}: ${String(value)}`)
                        .join(', ')}
                    </code>
                  ) : (
                    '—'
                  ),
                ],
              ]}
            />
          </Card>
          <Card
            title="Profile"
            description="Attributes are declared by the product (department, title) and reach policies as principal.{name}."
          >
            <ApiForm
              path="identities/update"
              tenantId={tenantId}
              submitLabel="Save"
              compact
              successMessage="Saved."
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'identityId', label: 'Identity', type: 'hidden', defaultValue: id },
                { name: 'name', label: 'Name', required: true, defaultValue: identity.name },
                {
                  name: 'attributes',
                  label: 'Attributes',
                  type: 'json',
                  rows: 3,
                  defaultValue: JSON.stringify(identity.attributes ?? {}, null, 2),
                  help: 'Replaces every attribute; only declared names are accepted.',
                },
              ]}
            />
            {/* Separate forms, so saving the profile never re-sends (and shifts) the deactivation time or the manager. */}
            <ApiForm
              path="identities/update"
              tenantId={tenantId}
              submitLabel="Set manager"
              compact
              successMessage="Manager set."
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'identityId', label: 'Identity', type: 'hidden', defaultValue: id },
                {
                  name: 'managerId',
                  label: 'Manager',
                  type: 'select',
                  required: true,
                  defaultValue: identity.managerId ?? '',
                  options: (members ?? [])
                    .filter((candidate) => candidate.id !== id && candidate.status === 'active')
                    .map((candidate) => ({
                      value: candidate.id,
                      label: candidate.email ?? candidate.name,
                    })),
                  help: 'Requests marked for manager approval route to them.',
                },
              ]}
            />
            <ApiForm
              path="identities/update"
              tenantId={tenantId}
              submitLabel="Schedule deactivation"
              compact
              successMessage="Deactivation scheduled."
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'identityId', label: 'Identity', type: 'hidden', defaultValue: id },
                {
                  name: 'expiresAt',
                  label: 'Deactivate on',
                  type: 'datetime',
                  required: true,
                  help: `Contractors and temporary accounts: credentials stop working at this time and the retention worker disables the account.${identity.expiresAt ? ` Currently ${new Date(identity.expiresAt).toISOString().slice(0, 16).replace('T', ' ')} UTC.` : ''}`,
                },
              ]}
            />
          </Card>
          <Card
            title="Assign a role"
            description="Creates a binding under your grant authority. An eligible binding grants the role only while the member has activated it (Elevate page)."
          >
            {roles ? (
              <ApiForm
                path="bindings/create"
                tenantId={tenantId}
                submitLabel="Bind role"
                compact
                successMessage="Role assigned."
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'subjectType',
                    label: 'Subject',
                    type: 'hidden',
                    defaultValue: 'identity',
                  },
                  { name: 'subjectId', label: 'Identity', type: 'hidden', defaultValue: id },
                  {
                    name: 'roleId',
                    label: 'Role',
                    type: 'select',
                    required: true,
                    options: roles
                      .filter((role) => !role.protected)
                      .map((role) => ({ value: role.id, label: role.name })),
                  },
                  {
                    name: 'startsAt',
                    label: 'Starts on',
                    type: 'datetime',
                    help: 'Optional: the role applies from this time (onboarding that begins on a set day).',
                  },
                  {
                    name: 'expiresAt',
                    label: 'Ends on',
                    type: 'datetime',
                    help: 'Optional: a temporary grant that ends by itself.',
                  },
                  {
                    name: 'eligible',
                    label: 'Eligible only (just-in-time activation)',
                    type: 'checkbox',
                  },
                  {
                    name: 'maxActivationMs',
                    label: 'Max activation (minutes)',
                    type: 'number',
                    multiplier: 60_000,
                    placeholder: '60',
                    help: 'Eligible bindings only; up to seven days.',
                  },
                  {
                    name: 'requireJustification',
                    label: 'Require a justification',
                    type: 'checkbox',
                  },
                  { name: 'requireMfa', label: 'Require an MFA session', type: 'checkbox' },
                  {
                    name: 'requireApproval',
                    label: 'Require approval of each activation',
                    type: 'checkbox',
                  },
                  {
                    name: 'managerApproval',
                    label: "Let the member's manager approve",
                    type: 'checkbox',
                  },
                  {
                    name: 'approverGroupId',
                    label: 'Approver group',
                    type: 'select',
                    options: (allGroups ?? []).map((group) => ({
                      value: group.id,
                      label: group.name,
                    })),
                    help: 'Members of this group decide and are emailed each request; leave empty to let anyone holding iam:bindings:approve on the role decide.',
                  },
                  {
                    name: 'window',
                    label: 'Access window',
                    type: 'json',
                    rows: 2,
                    placeholder:
                      '{ "from": "09:00", "to": "17:00", "timeZone": "Europe/Berlin", "days": [1,2,3,4,5] }',
                    help: 'Optional business-hours window; the role applies only inside it.',
                  },
                ]}
              />
            ) : (
              <Alert tone="warning">
                Requires <code>iam:roles:read</code>.
              </Alert>
            )}
          </Card>
        </div>
        <div className="grid cols-2">
          <Card
            title="Effective roles"
            description="Direct bindings plus roles inherited through groups. Eligible roles apply only while activated."
            flush
          >
            {bindings ? (
              <Table
                head={['Role', 'Via', 'Mode', 'Authority', '']}
                rows={bindings.map((binding) => {
                  const via = binding.via;
                  return [
                    <Link key="r" href={`${base}/roles/${binding.roleId}`}>
                      {binding.role?.name ?? binding.roleId}
                    </Link>,
                    via === 'identity' ? (
                      'direct'
                    ) : (
                      <span key="v">
                        group{' '}
                        <Link href={`${base}/groups/${via.groupId}`}>
                          {allGroups?.find((group) => group.id === via.groupId)?.name ??
                            via.groupId}
                        </Link>
                      </span>
                    ),
                    binding.startsAt && binding.startsAt > Date.now() ? (
                      <span key="m" className="row">
                        <Badge tone="info">starts</Badge>
                        <span className="small">
                          <Time value={binding.startsAt} />
                        </span>
                      </span>
                    ) : binding.eligible ? (
                      binding.activation ? (
                        <span key="m" className="row">
                          <Badge tone="success">active</Badge>
                          <span className="small">
                            until <Time value={binding.activation.expiresAt} />
                          </span>
                        </span>
                      ) : (
                        <Badge key="m" tone="accent">
                          eligible
                        </Badge>
                      )
                    ) : binding.window ? (
                      <span key="m" className="row">
                        <Badge tone={binding.inWindow ? 'success' : 'neutral'}>
                          {binding.inWindow ? 'in window' : 'outside window'}
                        </Badge>
                        <span className="small muted">
                          {binding.window.from}–{binding.window.to} {binding.window.timeZone}
                          {binding.window.days ? ` · days ${binding.window.days.join(',')}` : ''}
                        </span>
                      </span>
                    ) : (
                      <span key="m" className="small muted">
                        standing
                      </span>
                    ),
                    <code key="a" className="small">
                      {binding.authorityId}
                    </code>,
                    <span key="d" className="actions">
                      {binding.activation && (
                        <ApiButton
                          path="bindings/revokeActivation"
                          body={{ tenantId, activationId: binding.activation.id }}
                          label="End activation"
                          tenantId={tenantId}
                        />
                      )}
                      {via === 'identity' && !binding.role?.protected && (
                        <ApiButton
                          path="bindings/delete"
                          body={{ tenantId, bindingId: binding.id }}
                          label="Remove"
                          tone="danger"
                          tenantId={tenantId}
                        />
                      )}
                    </span>,
                  ];
                })}
                empty="No roles."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:bindings:read</code>.
              </div>
            )}
          </Card>
          <Card title="Groups" flush>
            {groups ? (
              <Table
                head={['Group', 'Until', '']}
                rows={groups.map((group) => [
                  <Link key="g" href={`${base}/groups/${group.id}`}>
                    {group.name}
                  </Link>,
                  group.membershipExpiresAt ? (
                    <Time key="u" value={group.membershipExpiresAt} />
                  ) : (
                    <span key="u" className="muted">
                      permanent
                    </span>
                  ),
                  group.teamId ? (
                    <Badge key="r" tone="info">
                      through a team
                    </Badge>
                  ) : (
                    <ApiButton
                      key="r"
                      path="groups/removeMember"
                      body={{ tenantId, groupId: group.id, identityId: id }}
                      label="Remove"
                      tone="danger"
                      tenantId={tenantId}
                    />
                  ),
                ])}
                empty="Not in any group."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:groups:read</code>.
              </div>
            )}
            {allGroups && allGroups.some((group) => !group.teamId) && (
              <div className="card-body">
                <ApiForm
                  path="groups/addMember"
                  tenantId={tenantId}
                  submitLabel="Add to group"
                  compact
                  successMessage="Added."
                  fields={[
                    { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                    { name: 'identityId', label: 'Identity', type: 'hidden', defaultValue: id },
                    {
                      name: 'groupId',
                      label: 'Group',
                      type: 'select',
                      required: true,
                      options: allGroups
                        .filter(
                          (group) =>
                            !group.teamId && !groups?.some((member) => member.id === group.id),
                        )
                        .map((group) => ({ value: group.id, label: group.name })),
                    },
                  ]}
                />
              </div>
            )}
          </Card>
        </div>
        {(memberTeams || memberDepartment !== undefined) && identity.kind === 'user' && (
          <div className="grid cols-2">
            <Card title="Teams" flush>
              {memberTeams ? (
                <Table
                  head={['Team', 'Role', 'Until']}
                  rows={memberTeams.map((team) => [
                    <span key="t">
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
                  ])}
                  empty="Not in any team."
                />
              ) : (
                <div className="empty">
                  Requires <code>iam:teams:read</code>.
                </div>
              )}
              {allTeams && allTeams.length > 0 && identity.status === 'active' && (
                <div className="card-body">
                  <ApiForm
                    path="teams/addMember"
                    tenantId={tenantId}
                    submitLabel="Add to team"
                    compact
                    successMessage="Added."
                    fields={[
                      { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                      { name: 'identityId', label: 'Identity', type: 'hidden', defaultValue: id },
                      {
                        name: 'teamId',
                        label: 'Team',
                        type: 'select',
                        required: true,
                        options: allTeams
                          .filter((team) => !memberTeams?.some((item) => item.id === team.id))
                          .map((team) => ({ value: team.id, label: team.name })),
                      },
                    ]}
                  />
                </div>
              )}
            </Card>
            <Card title="Department">
              {memberDepartment === undefined ? (
                <div className="empty">
                  Requires <code>iam:departments:read</code>.
                </div>
              ) : memberDepartment ? (
                <KeyValues
                  items={[
                    [
                      'Department',
                      <span key="d">
                        {memberDepartment.path.map((step, index) => (
                          <span key={step.id}>
                            {index > 0 && ' › '}
                            <Link href={`${base}/departments/${step.id}`}>{step.name}</Link>
                          </span>
                        ))}
                      </span>,
                    ],
                    ['Title', memberDepartment.title ?? <span className="muted">—</span>],
                    ['Head', memberDepartment.head?.name ?? <span className="muted">none</span>],
                    ['Since', <Time key="s" value={memberDepartment.since} />],
                  ]}
                />
              ) : (
                <p className="muted">Not in a department.</p>
              )}
              {allDepartments && allDepartments.length > 0 && identity.status === 'active' && (
                <ApiForm
                  path="departments/assign"
                  tenantId={tenantId}
                  submitLabel={memberDepartment ? 'Move' : 'Place'}
                  compact
                  successMessage="Saved."
                  fields={[
                    { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                    { name: 'identityId', label: 'Identity', type: 'hidden', defaultValue: id },
                    {
                      name: 'departmentId',
                      label: 'Department',
                      type: 'select',
                      required: true,
                      defaultValue: memberDepartment?.department.id ?? '',
                      options: allDepartments.map((item) => ({
                        value: item.id,
                        label: item.name,
                      })),
                    },
                    {
                      name: 'title',
                      label: 'Title',
                      defaultValue: memberDepartment?.title ?? '',
                    },
                  ]}
                />
              )}
            </Card>
          </div>
        )}
        {reports && reports.length > 0 && (
          <Card
            title="Reports"
            description="Members whose manager this is; their requests marked for manager approval come here."
            flush
          >
            <Table
              head={['Name', 'Email', 'Status']}
              rows={reports.map((report) => [
                <Link key="n" href={`${base}/members/${report.id}`}>
                  {report.name}
                </Link>,
                report.email ?? '—',
                <StatusBadge key="s" status={report.status} />,
              ])}
            />
          </Card>
        )}
        {activations && activations.length > 0 && (
          <Card
            title="Activation history"
            description="Just-in-time activations and requests of this member; ended ones stay until the retention worker sweeps them."
            flush
          >
            <Table
              head={['Role', 'Status', 'Requested', 'Until', 'Justification', 'Decision']}
              rows={activations.map((activation) => [
                <Link key="r" href={`${base}/roles/${activation.roleId}`}>
                  {roles?.find((role) => role.id === activation.roleId)?.name ?? activation.roleId}
                </Link>,
                <Badge
                  key="s"
                  tone={
                    activation.active
                      ? 'success'
                      : activation.status === 'pending'
                        ? 'warning'
                        : activation.status === 'denied'
                          ? 'danger'
                          : 'neutral'
                  }
                >
                  {activation.active
                    ? 'active'
                    : activation.status === 'active'
                      ? 'ended'
                      : activation.status}
                </Badge>,
                <Time key="a" value={activation.activatedAt} />,
                <Time key="u" value={activation.expiresAt} />,
                activation.justification ?? <span className="muted">—</span>,
                activation.decidedBy ? (
                  <span key="d" className="small">
                    {members?.find((member) => member.id === activation.decidedBy)?.name ??
                      activation.decidedBy}
                    {activation.note ? `: ${activation.note}` : ''}
                  </span>
                ) : (
                  <span key="d" className="muted">
                    —
                  </span>
                ),
              ])}
            />
          </Card>
        )}
        {usage?.tracking && (
          <Card
            title="Access usage"
            description={
              usage.trackingSince === undefined ? (
                'No use recorded yet.'
              ) : (
                <>
                  Actions this member was allowed to use since <Time value={usage.trackingSince} />,
                  most recent first. See <Link href={`${base}/role-mining`}>Role mining</Link> for
                  unused grants.
                </>
              )
            }
            flush
          >
            <Table
              head={['Action', 'Last used', 'First used', 'Times']}
              rows={usage.records.map((record) => [
                <code key="a" className="small">
                  {record.action}
                </code>,
                <Time key="l" value={record.lastUsedAt} />,
                <Time key="f" value={record.firstUsedAt} />,
                record.count,
              ])}
              empty="Nothing used yet."
            />
          </Card>
        )}
        {shares && shares.length > 0 && (
          <Card
            title="Shared resources"
            description="Relationships this member holds directly; roles read them as resource.relations."
            flush
          >
            <Table
              head={['Resource', 'Relation', 'Expires', '']}
              rows={shares.map((tuple) => [
                tuple.type === 'workspace' ? (
                  <Link key="r" href={`${base}/workspaces/${tuple.resourceId}`}>
                    {tuple.type}/{tuple.resourceId}
                  </Link>
                ) : (
                  <code key="r">
                    {tuple.type}/{tuple.resourceId}
                  </code>
                ),
                <Badge key="l" tone="accent">
                  {tuple.relation}
                </Badge>,
                <Time key="e" value={tuple.expiresAt} />,
                <ApiButton
                  key="d"
                  path="relationships/delete"
                  body={{ tenantId, relationshipId: tuple.id }}
                  label="Remove"
                  tone="danger"
                  tenantId={tenantId}
                />,
              ])}
            />
          </Card>
        )}
        {tenant.authPolicy?.allowImpersonation &&
          identity.kind === 'user' &&
          identity.id !== session.identity.id &&
          !identity.owner &&
          !identity.rootAdmin &&
          !session.session.impersonatorId && (
            <Card
              title="View as this member"
              description="Opens the console as they see it for up to an hour. Needs iam:identities:impersonate and a recent sign-in; every action is recorded with your identity as the impersonator, and sensitive operations stay unavailable."
            >
              <ImpersonateForm
                tenantId={tenantId}
                identityId={id}
                name={identity.name}
                base={base}
              />
            </Card>
          )}
        {identity.id !== session.identity.id && identity.status === 'active' && (
          <Card
            title="Offboard"
            description="Disables the account and, in one transaction, ends its sessions and keys, removes its roles, group memberships, activations, shares, pending requests, and grant authorities, and hands the resources it owns to a successor. The record stays for retention; delete it later. Needs a recent sign-in."
          >
            <ApiForm
              path="identities/offboard"
              tenantId={tenantId}
              submitLabel="Offboard"
              showResult
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                { name: 'identityId', label: 'Identity', type: 'hidden', defaultValue: id },
                {
                  name: 'reason',
                  label: 'Reason',
                  required: true,
                  placeholder: 'Left the company (HR-1234)',
                },
                {
                  name: 'successorId',
                  label: 'Successor for owned resources',
                  type: 'select',
                  options: (members ?? [])
                    .filter((candidate) => candidate.id !== id && candidate.status === 'active')
                    .map((candidate) => ({
                      value: candidate.id,
                      label: candidate.email ?? candidate.name,
                    })),
                },
              ]}
            />
          </Card>
        )}
        {identity.owner && (
          <Alert tone="info">
            Owners hold the protected Owner role. Ownership is transferred with the owner controls
            above, never by editing that role.
          </Alert>
        )}
        {identity.id === session.identity.id && <Badge>This is you</Badge>}
      </div>
    </>
  );
}
