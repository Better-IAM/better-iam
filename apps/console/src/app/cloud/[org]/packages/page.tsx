import Link from 'next/link';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const day = 86400000;
const plural = (count: number, noun: string) => `${count} ${noun}${count === 1 ? '' : 's'}`;
/** The administrator-written part of a rule, for "Take over rule" (re-saving it under the caller). */
const ruleBody = (rule: {
  include: unknown[];
  exclude?: unknown[];
  graceMs?: number;
  maxGrants?: number;
  maxRemovals?: number;
}) => ({
  include: rule.include,
  ...(rule.exclude ? { exclude: rule.exclude } : {}),
  ...(rule.graceMs ? { graceMs: rule.graceMs } : {}),
  ...(rule.maxGrants ? { maxGrants: rule.maxGrants } : {}),
  ...(rule.maxRemovals ? { maxRemovals: rule.maxRemovals } : {}),
});

export default async function Packages({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, base } = await orgPage(org);
  const [packages, assignments, requests, roles, groups, identities, ruleKeys, teams, departments] =
    await Promise.all([
      tryRead(() => iam.api.packages.list(auth, { tenantId })),
      tryRead(() => iam.api.packages.listAssignments(auth, { tenantId })),
      tryRead(() => iam.api.packages.listRequests(auth, { tenantId })),
      tryRead(() => iam.api.roles.list(auth, { tenantId })),
      tryRead(() => iam.api.groups.list(auth, { tenantId })),
      tryRead(() => iam.api.identities.list(auth, { tenantId })),
      tryRead(() => iam.api.packages.previewAutoAssign(auth, { tenantId })),
      // Rules may name teams (identity.teams) and departments (identity.departments) by ID.
      tryRead(() => iam.api.teams.list(auth, { tenantId })),
      tryRead(() => iam.api.departments.list(auth, { tenantId })),
    ]);
  const roleName = (roleId: string) => roles?.find((role) => role.id === roleId)?.name ?? roleId;
  const groupName = (groupId: string) =>
    groups?.find((group) => group.id === groupId)?.name ?? groupId;
  const ruled = (packageId: string) =>
    packages?.find((pkg) => pkg.id === packageId)?.autoAssign !== undefined;
  const manual = assignments?.filter((assignment) => !assignment.automatic) ?? [];
  return (
    <>
      <PageHeader
        title="Access packages"
        description="Roles and group memberships granted to a person together, for a shared period: onboarding kits, project profiles, vendor access. Revoking removes exactly what the package added. A package with a rule is birthright access: everyone who matches receives it automatically."
      />
      <div className="stack">
        <Card title="Packages" flush>
          {packages ? (
            <Table
              head={['Name', 'Roles', 'Groups', 'Rules', 'Holders', '']}
              rows={packages.map((pkg) => {
                const rule = pkg.autoAssign;
                return [
                  <span key="n">
                    <strong>{pkg.name}</strong>
                    {pkg.description && <div className="muted">{pkg.description}</div>}
                  </span>,
                  pkg.roleIds.map(roleName).join(', ') || '—',
                  pkg.groupIds.map(groupName).join(', ') || '—',
                  <span key="r">
                    {[
                      pkg.maxDurationMs
                        ? `at most ${plural(Math.round(pkg.maxDurationMs / day), 'day')}`
                        : 'no time limit',
                      pkg.requireJustification ? 'justification required' : null,
                      pkg.requestable
                        ? pkg.approverGroupId
                          ? `requestable, approved by ${groupName(pkg.approverGroupId)}`
                          : 'requestable'
                        : null,
                      pkg.managerApproval ? 'manager approval' : null,
                    ]
                      .filter(Boolean)
                      .join(' · ')}
                    {rule && (
                      <span className="row">
                        {rule.status === 'active' ? (
                          <Badge tone="success">automatic</Badge>
                        ) : (
                          <span title={rule.suspendedDetail}>
                            <Badge tone="warning">rule suspended: {rule.suspendedReason}</Badge>
                          </span>
                        )}
                        <span className="small">
                          rule r{rule.revision} by {rule.ownerName}
                          {rule.graceMs
                            ? `, ${plural(Math.round(rule.graceMs / day), 'day')} grace`
                            : ''}
                        </span>
                        {rule.issueCount > 0 && (
                          <span
                            title={rule.issues
                              .map(
                                (issue) =>
                                  `${issue.identityName ?? issue.kind}: ${issue.code} ${issue.message}`,
                              )
                              .join('\n')}
                          >
                            <Badge tone="warning">{plural(rule.issueCount, 'issue')}</Badge>
                          </span>
                        )}
                      </span>
                    )}
                    {rule?.warnings.map((warning) => (
                      <div key={warning} className="small muted">
                        {warning}
                      </div>
                    ))}
                  </span>,
                  `${pkg.assignments}${pkg.automaticAssignments ? ` (${pkg.automaticAssignments} automatic)` : ''}`,
                  <span key="d" className="actions">
                    {rule && (
                      <>
                        <ApiButton
                          path="packages/previewAutoAssign"
                          body={{ tenantId, packageId: pkg.id }}
                          label="Preview"
                          showResult
                          tenantId={tenantId}
                        />
                        <ApiButton
                          path="packages/reconcile"
                          body={{ tenantId, packageId: pkg.id }}
                          label="Reconcile now"
                          showResult
                          tenantId={tenantId}
                        />
                        {rule.issues.some((issue) => issue.kind === 'braked') && (
                          <ApiButton
                            path="packages/reconcile"
                            body={{ tenantId, packageId: pkg.id, confirm: true }}
                            label="Confirm held changes"
                            tone="primary"
                            confirm="Apply the grants and removals the brake held back? You need the rights to assign this package by hand."
                            showResult
                            tenantId={tenantId}
                          />
                        )}
                        {rule.status === 'suspended' && (
                          <ApiButton
                            path="packages/update"
                            body={{ tenantId, packageId: pkg.id, autoAssign: ruleBody(rule) }}
                            label="Take over rule"
                            confirm="The rule will run under your grant authority from now on."
                            tenantId={tenantId}
                          />
                        )}
                        <ApiButton
                          path="packages/update"
                          body={{ tenantId, packageId: pkg.id, autoAssign: null }}
                          label="Stop automatic assignment"
                          tone="danger"
                          confirm="Automatic holders lose this package at the next reconcile. Continue?"
                          tenantId={tenantId}
                        />
                        <ApiButton
                          path="packages/update"
                          body={{
                            tenantId,
                            packageId: pkg.id,
                            autoAssign: null,
                            keepAutomaticAssignments: true,
                          }}
                          label="Stop, keep holders"
                          confirm="Automatic holders keep the package as ordinary assignments."
                          tenantId={tenantId}
                        />
                      </>
                    )}
                    <ApiButton
                      path="packages/delete"
                      body={{ tenantId, packageId: pkg.id }}
                      label="Delete"
                      tone="danger"
                      confirm="Delete this package? Nobody may hold it."
                      tenantId={tenantId}
                    />
                  </span>,
                ];
              })}
              empty="No packages yet."
            />
          ) : (
            <div className="empty">
              Requires <code>iam:packages:read</code>.
            </div>
          )}
        </Card>
        <Card
          title="Automatic assignment (birthright)"
          description="Identities that match a rule receive the package automatically and lose it when they stop matching (after the grace period). The rule runs under your grant authority, so you need the rights to assign the package by hand. Unusually large unattended changes are held back for confirmation."
        >
          <div className="grid cols-2">
            {packages && packages.length > 0 ? (
              <ApiForm
                path="packages/update"
                tenantId={tenantId}
                submitLabel="Save rule"
                successMessage="Rule saved. Matching identities were updated; any remainder follows on the next scheduled reconcile."
                showResult
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'packageId',
                    label: 'Package',
                    type: 'select',
                    required: true,
                    options: packages
                      .filter((pkg) => pkg.maxDurationMs === undefined)
                      .map((pkg) => ({ value: pkg.id, label: pkg.name })),
                  },
                  {
                    name: 'include',
                    label: 'Include (any clause)',
                    type: 'json',
                    group: 'autoAssign',
                    required: true,
                    rows: 6,
                    placeholder:
                      '[{ "StringEquals": { "principal.kind": "user", "principal.department": "engineering" } }]',
                    help: 'Clauses joined by OR; inside a clause every condition must hold. Missing attributes never match; test absence with Exists false.',
                  },
                  {
                    name: 'exclude',
                    label: 'Exclude (any clause)',
                    type: 'json',
                    group: 'autoAssign',
                    rows: 3,
                    placeholder: '[{ "StringEquals": { "principal.id": ["<identity id>"] } }]',
                  },
                  {
                    name: 'graceMs',
                    label: 'Grace period (days)',
                    type: 'number',
                    multiplier: day,
                    group: 'autoAssign',
                    help: '0 or empty removes access at the next reconcile; at most 90.',
                  },
                  {
                    name: 'maxGrants',
                    label: 'Hold back more new grants than',
                    type: 'number',
                    group: 'autoAssign',
                    help: 'Per scheduled run (default 100).',
                  },
                  {
                    name: 'maxRemovals',
                    label: 'Hold back more removals than',
                    type: 'number',
                    group: 'autoAssign',
                    help: 'Per scheduled run (default 25).',
                  },
                ]}
              />
            ) : (
              <div className="muted">Create a package first.</div>
            )}
            <ApiForm
              path="packages/previewAutoAssign"
              tenantId={tenantId}
              submitLabel="Preview"
              showResult
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                {
                  name: 'packageId',
                  label: 'Compare with package',
                  type: 'select',
                  options: (packages ?? []).map((pkg) => ({ value: pkg.id, label: pkg.name })),
                },
                {
                  name: 'include',
                  label: 'Include (any clause)',
                  type: 'json',
                  group: 'autoAssign',
                  required: true,
                  rows: 6,
                },
                {
                  name: 'exclude',
                  label: 'Exclude (any clause)',
                  type: 'json',
                  group: 'autoAssign',
                  rows: 3,
                },
              ]}
            />
          </div>
          {ruleKeys && (
            <div className="grid cols-2">
              <Table
                head={['Key', 'Type', 'Operators']}
                rows={ruleKeys.keys.map((key) => [
                  <code key="k" className="small">
                    {key.key}
                  </code>,
                  key.type,
                  <span key="o" className="small muted">
                    {key.operators.join(', ')}
                  </span>,
                ])}
              />
              {groups && groups.length > 0 && (
                <Table
                  head={['Group', 'ID for identity.groups']}
                  rows={groups.map((group) => [
                    group.name,
                    <code key="i" className="small">
                      {group.id}
                    </code>,
                  ])}
                />
              )}
              {teams && teams.length > 0 && (
                <Table
                  head={['Team', 'ID for identity.teams']}
                  rows={teams.map((team) => [
                    team.name,
                    <code key="i" className="small">
                      {team.id}
                    </code>,
                  ])}
                />
              )}
              {departments && departments.length > 0 && (
                <Table
                  head={['Department', 'ID for identity.departments']}
                  rows={departments.map((department) => [
                    department.name,
                    <code key="i" className="small">
                      {department.id}
                    </code>,
                  ])}
                />
              )}
            </div>
          )}
        </Card>
        <div className="grid cols-2">
          <Card title="New package">
            {roles && groups ? (
              <ApiForm
                path="packages/create"
                tenantId={tenantId}
                submitLabel="Create package"
                successMessage="Package created."
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  { name: 'name', label: 'Name', required: true, placeholder: 'Engineer kit' },
                  { name: 'description', label: 'Description' },
                  {
                    name: 'roleIds',
                    label: 'Roles',
                    type: 'multiselect',
                    help: 'Hold Ctrl/Cmd to select several.',
                    options: roles
                      .filter((role) => !role.protected)
                      .map((role) => ({ value: role.id, label: role.name })),
                  },
                  {
                    name: 'groupIds',
                    label: 'Groups',
                    type: 'multiselect',
                    options: groups.map((group) => ({ value: group.id, label: group.name })),
                  },
                  {
                    name: 'maxDurationMs',
                    label: 'Maximum duration (days)',
                    type: 'number',
                    multiplier: day,
                    help: 'Optional: assignments must then end within this many days. Not for rule packages.',
                  },
                  {
                    name: 'requireJustification',
                    label: 'Require a justification when assigning',
                    type: 'checkbox',
                  },
                  {
                    name: 'requestable',
                    label: 'Members may request it (self-service)',
                    type: 'checkbox',
                    help: 'Requesting needs iam:packages:request; a request waits for an approver.',
                  },
                  {
                    name: 'approverGroupId',
                    label: 'Approver group',
                    type: 'select',
                    options: groups.map((group) => ({ value: group.id, label: group.name })),
                    help: 'Optional: only its members decide on requests and are emailed each one.',
                  },
                  {
                    name: 'managerApproval',
                    label: "The requester's manager may approve",
                    type: 'checkbox',
                    help: 'Alongside the approver group, if any; the manager is emailed each request.',
                  },
                ]}
              />
            ) : (
              <Alert tone="warning">
                Requires <code>iam:roles:read</code> and <code>iam:groups:read</code>.
              </Alert>
            )}
          </Card>
          <Card title="Assign a package">
            {packages?.length && identities ? (
              <ApiForm
                path="packages/assign"
                tenantId={tenantId}
                submitLabel="Assign"
                successMessage="Package assigned."
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'packageId',
                    label: 'Package',
                    type: 'select',
                    required: true,
                    options: packages.map((pkg) => ({ value: pkg.id, label: pkg.name })),
                  },
                  {
                    name: 'identityId',
                    label: 'Person',
                    type: 'select',
                    required: true,
                    options: identities
                      .filter((identity) => identity.status === 'active')
                      .map((identity) => ({
                        value: identity.id,
                        label: `${identity.name} (${identity.email ?? identity.kind})`,
                      })),
                  },
                  {
                    name: 'expiresAt',
                    label: 'Until',
                    type: 'datetime',
                    help: 'Required when the package has a maximum duration. Assigning a package someone holds automatically takes it over as a manual assignment.',
                  },
                  {
                    name: 'justification',
                    label: 'Justification',
                    help: 'Required when the package asks for one; recorded in the audit trail.',
                  },
                ]}
              />
            ) : (
              <div className="muted">
                {packages ? 'Create a package first.' : 'Requires iam:packages:read.'}
              </div>
            )}
          </Card>
        </div>
        <Card title="Holders" flush>
          {assignments ? (
            <Table
              head={['Package', 'Person', 'Source', 'Assigned', 'Until', 'Added', '']}
              rows={assignments.map((assignment) => [
                assignment.broken ? (
                  <span key="n" className="row">
                    {assignment.packageName}
                    <Badge tone="danger">no longer granting</Badge>
                  </span>
                ) : (
                  assignment.packageName
                ),
                <Link key="p" href={`${base}/members/${assignment.identityId}`}>
                  {assignment.identityName}
                </Link>,
                assignment.automatic ? (
                  <span key="s" className="row">
                    <Badge tone="success">automatic</Badge>
                    {assignment.expiresAt && <Badge tone="warning">leaving</Badge>}
                  </span>
                ) : (
                  <span key="s" className="muted">
                    manual
                  </span>
                ),
                <Time key="a" value={assignment.assignedAt} />,
                assignment.expiresAt ? (
                  <Time key="u" value={assignment.expiresAt} />
                ) : (
                  <span key="u" className="muted">
                    permanent
                  </span>
                ),
                `${plural(assignment.bindingIds.length, 'role')}, ${plural(assignment.membershipIds.length, 'group')}`,
                assignment.automatic && ruled(assignment.packageId) ? (
                  <span key="r" className="muted small">
                    via rule
                  </span>
                ) : (
                  <ApiButton
                    key="r"
                    path="packages/revoke"
                    body={{
                      tenantId,
                      packageId: assignment.packageId,
                      identityId: assignment.identityId,
                    }}
                    label="Revoke"
                    tone="danger"
                    tenantId={tenantId}
                  />
                ),
              ])}
              empty="Nobody holds a package."
            />
          ) : (
            <div className="empty">
              Requires <code>iam:packages:read</code>.
            </div>
          )}
        </Card>
        {manual.length > 0 && (
          <Card
            title="Extend an assignment"
            description="Moves the end of everything a manual package assignment granted, in one step. Lengthening needs the rights to assign the package."
          >
            <ApiForm
              path="packages/extend"
              tenantId={tenantId}
              submitLabel="Extend"
              compact
              successMessage="Assignment extended."
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                {
                  name: 'packageId',
                  label: 'Package',
                  type: 'select',
                  required: true,
                  options: [...new Map(manual.map((a) => [a.packageId, a.packageName]))].map(
                    ([value, label]) => ({ value, label }),
                  ),
                },
                {
                  name: 'identityId',
                  label: 'Person',
                  type: 'select',
                  required: true,
                  options: [...new Map(manual.map((a) => [a.identityId, a.identityName]))].map(
                    ([value, label]) => ({ value, label }),
                  ),
                },
                { name: 'expiresAt', label: 'New end', type: 'datetime', required: true },
              ]}
            />
          </Card>
        )}
        <Card
          title="Requests"
          description="Self-service requests for requestable packages. Approving assigns the package under your authority, so it needs the same rights as assigning by hand."
          flush
        >
          {requests ? (
            <Table
              head={['Package', 'Person', 'Status', 'Requested', 'Until', 'Justification', '']}
              rows={requests.map((request) => [
                request.packageName,
                <Link key="p" href={`${base}/members/${request.identityId}`}>
                  {request.identityName}
                </Link>,
                <Badge
                  key="s"
                  tone={
                    request.status === 'pending'
                      ? 'warning'
                      : request.status === 'approved'
                        ? 'success'
                        : undefined
                  }
                >
                  {request.status}
                </Badge>,
                <Time key="r" value={request.requestedAt} />,
                request.desiredExpiresAt ? (
                  <Time key="u" value={request.desiredExpiresAt} />
                ) : (
                  <span key="u" className="muted">
                    open-ended
                  </span>
                ),
                request.justification ?? <span className="muted">—</span>,
                request.status === 'pending' ? (
                  <span key="a" className="actions">
                    <ApiButton
                      path="packages/approveRequest"
                      body={{ tenantId, requestId: request.id }}
                      label="Approve"
                      tone="primary"
                      tenantId={tenantId}
                    />
                    <ApiButton
                      path="packages/denyRequest"
                      body={{ tenantId, requestId: request.id }}
                      label="Deny"
                      tone="danger"
                      confirm="Deny this request?"
                      tenantId={tenantId}
                    />
                  </span>
                ) : (
                  <span key="a" className="small muted">
                    {request.note ?? ''}
                  </span>
                ),
              ])}
              empty="No requests."
            />
          ) : (
            <div className="empty">
              Requires <code>iam:packages:read</code>.
            </div>
          )}
        </Card>
      </div>
    </>
  );
}
