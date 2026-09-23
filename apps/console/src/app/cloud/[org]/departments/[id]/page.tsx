import Link from 'next/link';
import { notFound } from 'next/navigation';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Badge, Card, KeyValues, PageHeader, Table, Time } from '@/components/ui';
import { money } from '@/lib/billing';
import { birthrightPackages } from '@/lib/birthright';
import { BirthrightSuggestions } from '@/components/birthright-suggestions';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Department({
  params,
  searchParams,
}: {
  params: Promise<{ org: string; id: string }>;
  searchParams: Promise<{ below?: string }>;
}) {
  const { org, id } = await params;
  const { below } = await searchParams;
  const includeSubdepartments = below === '1';
  const { iam, auth, tenantId, base } = await orgPage(org);
  const department = await tryRead(() =>
    iam.api.departments.get(auth, { tenantId, departmentId: id }),
  );
  if (!department) notFound();
  const [members, departments, identities] = await Promise.all([
    tryRead(() =>
      iam.api.departments.listMembers(auth, {
        tenantId,
        departmentId: id,
        includeSubdepartments,
      }),
    ),
    tryRead(() => iam.api.departments.list(auth, { tenantId })),
    tryRead(() => iam.api.identities.list(auth, { tenantId, kind: 'user', status: 'active' })),
  ]);
  // Billing: this month's spend of the department and those below it (heads may read it without a permission).
  const spend = await tryRead(() =>
    iam.api.billing.departmentSpend(auth, { tenantId, departmentId: id }),
  );
  // Birthright access: packages whose rule names this department or one above it (with iam:packages:read).
  const packages = await tryRead(() => iam.api.packages.list(auth, { tenantId }));
  const birthright = birthrightPackages(packages, 'identity.departments', [
    id,
    ...department.path.map((step) => step.id).reverse(),
  ]);
  // Access most people here hold by hand, as a ready-made birthright package (with iam:analysis:read).
  const suggestions = await tryRead(() =>
    iam.api.departments.suggestBirthright(auth, { tenantId, departmentId: id }),
  );
  const departmentNames = new Map([
    ...department.path.map((step) => [step.id, step.name] as const),
    [id, department.name],
  ]);
  const people = (identities ?? []).map((identity) => ({
    value: identity.id,
    label: `${identity.name} (${identity.email ?? identity.kind})`,
  }));
  const names = new Map((identities ?? []).map((identity) => [identity.id, identity.name]));
  // A department cannot move under itself or a department below it.
  const parentOf = new Map((departments ?? []).map((item) => [item.id, item.parentId]));
  const belowThis = (departmentId: string) => {
    for (let cursor = parentOf.get(departmentId), depth = 0; cursor && depth < 25; depth++) {
      if (cursor === id) return true;
      cursor = parentOf.get(cursor);
    }
    return false;
  };
  return (
    <>
      <PageHeader
        title={
          <>
            {department.name} {department.code && <code className="small">{department.code}</code>}
          </>
        }
        description={
          <>
            <Link href={`${base}/departments`}>Departments</Link>
            {department.path.map((step) => (
              <span key={step.id}>
                {' › '}
                <Link href={`${base}/departments/${step.id}`}>{step.name}</Link>
              </span>
            ))}
            {' › '}
            {department.name}
            {department.description ? ` · ${department.description}` : ''}
          </>
        }
        actions={
          <ApiButton
            path="departments/delete"
            body={{ tenantId, departmentId: id }}
            label="Delete department"
            tone="danger"
            confirm="Delete this department? Its people become unassigned and its teams lose the link."
            redirectTo={`${base}/departments`}
            tenantId={tenantId}
          />
        }
      />
      <div className="stack">
        <div className="tiles">
          <div className="card stat">
            <span className="label">People</span>
            <span className="value">{department.memberCount}</span>
            <span className="hint">{department.totalMemberCount} with sub-departments</span>
          </div>
          <div className="card stat">
            <span className="label">Head</span>
            <span className="value" style={{ fontSize: 18 }}>
              {department.head ? department.head.name : '—'}
            </span>
            <span className="hint">{department.head?.email ?? 'nobody leads it yet'}</span>
          </div>
          <div className="card stat">
            <span className="label">Sub-departments</span>
            <span className="value">{department.childCount}</span>
          </div>
          <div className="card stat">
            <span className="label">Teams</span>
            <span className="value">{department.teamCount}</span>
          </div>
        </div>
        <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
          <Card
            title="People"
            actions={
              <Link
                className="btn small secondary"
                href={`${base}/departments/${id}${includeSubdepartments ? '' : '?below=1'}`}
              >
                {includeSubdepartments ? 'Only this department' : 'Include sub-departments'}
              </Link>
            }
            flush
          >
            {members ? (
              <Table
                head={['Name', 'Title', 'Manager', 'Since', '']}
                rows={members.map((member) => [
                  <span key="n">
                    <Link href={`${base}/members/${member.id}`}>{member.name}</Link>{' '}
                    {member.head && <Badge tone="accent">head</Badge>}
                    {member.department.id !== department.id && (
                      <span className="muted small"> · {member.department.name}</span>
                    )}
                  </span>,
                  member.title ?? <span className="muted">—</span>,
                  member.managerId ? (
                    <Link key="m" href={`${base}/members/${member.managerId}`}>
                      {names.get(member.managerId) ?? 'manager'}
                    </Link>
                  ) : (
                    <span key="m" className="muted">
                      —
                    </span>
                  ),
                  <Time key="s" value={member.since} />,
                  <ApiButton
                    key="r"
                    path="departments/unassign"
                    body={{ tenantId, identityId: member.id }}
                    label="Remove"
                    tone="danger"
                    tenantId={tenantId}
                  />,
                ])}
                empty="Nobody is in this department."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:departments:read</code>.
              </div>
            )}
            <div className="card-body">
              <ApiForm
                path="departments/assign"
                tenantId={tenantId}
                submitLabel="Place in department"
                compact
                successMessage="Placed."
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  { name: 'departmentId', label: 'Department', type: 'hidden', defaultValue: id },
                  {
                    name: 'identityIds',
                    label: 'People',
                    type: 'multiselect',
                    required: true,
                    help: 'People in another department move here.',
                    options: people.filter(
                      (option) =>
                        !members?.some(
                          (member) =>
                            member.id === option.value && member.department.id === department.id,
                        ),
                    ),
                  },
                  { name: 'title', label: 'Title', placeholder: 'Engineer' },
                ]}
              />
            </div>
          </Card>
          <div className="stack">
            <Card title="Sub-departments" flush>
              <Table
                head={['Department', 'People']}
                rows={department.children.map((child) => [
                  <Link key="n" href={`${base}/departments/${child.id}`}>
                    {child.name}
                  </Link>,
                  child.totalMemberCount,
                ])}
                empty="None."
              />
            </Card>
            <Card title="Teams in this department" flush>
              <Table
                head={['Team']}
                rows={department.teams.map((team) => [
                  <Link key="t" href={`${base}/teams/${team.id}`}>
                    {team.name}
                  </Link>,
                ])}
                empty="No team is filed under this department."
              />
            </Card>
            <Card title="Details">
              <KeyValues
                items={[
                  ['Cost center', department.costCenter ?? <span className="muted">—</span>],
                  ['Created', <Time key="c" value={department.createdAt} />],
                  ['Updated', <Time key="u" value={department.updatedAt} />],
                ]}
              />
            </Card>
          </div>
        </div>
        {birthright.length > 0 && (
          <Card
            title="Birthright access"
            description="Access packages whose rule names this department or one above it: people placed here who meet the rest of the rule receive them automatically, and lose them when they move out."
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
                via === id ? (
                  <span key="v">this department</span>
                ) : (
                  <Link key="v" href={`${base}/departments/${via}`}>
                    {departmentNames.get(via) ?? via}
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
            description={`${money(spend.total.costMicros, spend.currency)} by the people of this department and those below it${spend.forecast ? `, on track for ${money(spend.forecast.costMicros, spend.currency)}` : ''}${department.costCenter ? ` (cost center ${department.costCenter})` : ''}.`}
            actions={
              <Link className="btn small secondary" href={`${base}/billing?view=department`}>
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
        <Card title="Settings">
          <ApiForm
            path="departments/update"
            tenantId={tenantId}
            submitLabel="Save"
            compact
            successMessage="Saved."
            fields={[
              { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
              { name: 'departmentId', label: 'Department', type: 'hidden', defaultValue: id },
              { name: 'name', label: 'Name', required: true, defaultValue: department.name },
              {
                name: 'code',
                label: 'Code',
                emptyAsNull: true,
                defaultValue: department.code ?? '',
              },
              // Offered only when the choices could be read: an empty select would clear the value on save.
              ...(departments
                ? [
                    {
                      name: 'parentId',
                      label: 'Part of',
                      type: 'select' as const,
                      emptyAsNull: true,
                      defaultValue: department.parentId ?? '',
                      options: departments
                        .filter((item) => item.id !== id && !belowThis(item.id))
                        .map((item) => ({ value: item.id, label: item.name })),
                    },
                  ]
                : []),
              ...(identities
                ? [
                    {
                      name: 'headId',
                      label: 'Head',
                      type: 'select' as const,
                      emptyAsNull: true,
                      defaultValue: department.headId ?? '',
                      options: people,
                    },
                  ]
                : []),
              {
                name: 'costCenter',
                label: 'Cost center',
                emptyAsNull: true,
                defaultValue: department.costCenter ?? '',
              },
              {
                name: 'description',
                label: 'Description',
                type: 'textarea',
                rows: 2,
                emptyAsNull: true,
                defaultValue: department.description ?? '',
              },
            ]}
          />
        </Card>
      </div>
    </>
  );
}
