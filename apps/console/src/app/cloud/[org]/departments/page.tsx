import Link from 'next/link';
import type { DepartmentNode } from 'better-iam';
import { ApiForm } from '@/components/api-form';
import { BirthrightSuggestions } from '@/components/birthright-suggestions';
import { Alert, Badge, Card, KeyValues, PageHeader, Table, Time } from '@/components/ui';
import { can, key, orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

function OrgChart({ nodes, base }: { nodes: DepartmentNode[]; base: string }) {
  return (
    <ul className="org-chart">
      {nodes.map((node) => (
        <li key={node.id}>
          <div className="org-node">
            <Link href={`${base}/departments/${node.id}`}>
              <strong>{node.name}</strong>
            </Link>
            {node.code && <code className="small">{node.code}</code>}
            <span className="muted small">
              {node.head ? `led by ${node.head.name}` : 'no head'} · {node.memberCount}{' '}
              {node.memberCount === 1 ? 'person' : 'people'}
              {node.totalMemberCount !== node.memberCount &&
                ` (${node.totalMemberCount} with sub-departments)`}
              {node.teamCount > 0 &&
                ` · ${node.teamCount} ${node.teamCount === 1 ? 'team' : 'teams'}`}
            </span>
          </div>
          {node.children.length > 0 && <OrgChart nodes={node.children} base={base} />}
        </li>
      ))}
    </ul>
  );
}

export default async function Departments({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const page = await orgPage(org);
  const { iam, auth, tenantId, base } = page;
  // Changing the structure and syncing managers are administrator actions.
  const allowed = await can(page, [
    { action: 'iam:departments:manage' },
    { action: 'iam:identities:update' },
  ]);
  const mayManage = allowed[key('iam:departments:manage', undefined, tenantId)];
  const maySyncManagers = allowed[key('iam:identities:update', undefined, tenantId)];
  const [tree, departments, identities, mine] = await Promise.all([
    tryRead(() => iam.api.departments.tree(auth, { tenantId })),
    tryRead(() => iam.api.departments.list(auth, { tenantId })),
    tryRead(() => iam.api.identities.list(auth, { tenantId, kind: 'user', status: 'active' })),
    // Everyone's own place in the org chart, and the people a department head leads.
    tryRead(() => iam.api.departments.mine(auth, { tenantId })),
  ]);
  // Birthright suggestions across the org chart (with iam:analysis:read).
  const suggestions = await tryRead(() =>
    iam.api.departments.suggestBirthright(auth, { tenantId }),
  );
  const people = (identities ?? []).map((identity) => ({
    value: identity.id,
    label: `${identity.name} (${identity.email ?? identity.kind})`,
  }));
  const assigned = departments?.reduce((sum, item) => sum + item.memberCount, 0) ?? 0;
  return (
    <>
      <PageHeader
        title="Departments"
        description="The organization's reporting structure. Each person belongs to one department; policies can test principal.departments, and department heads can become everyone's managers for approvals."
      />
      <div className="stack">
        {mine && (mine.department || mine.leads.length > 0) && (
          <div className="grid cols-2">
            <Card title="Your department">
              {mine.department ? (
                <KeyValues
                  items={[
                    ['Department', mine.department.path.map((step) => step.name).join(' › ')],
                    ['Title', mine.department.title ?? <span className="muted">—</span>],
                    ['Head', mine.department.head?.name ?? <span className="muted">none</span>],
                    ['Since', <Time key="s" value={mine.department.since} />],
                  ]}
                />
              ) : (
                <p className="muted">You are not in a department.</p>
              )}
            </Card>
            {mine.leads.length > 0 && (
              <Card title="People you lead" flush>
                <Table
                  head={['Name', 'Department', 'Title']}
                  rows={mine.leads.flatMap((lead) =>
                    lead.people.map((member) => [
                      <span key="n">
                        {member.name} {member.head && <Badge tone="accent">head</Badge>}
                        <br />
                        <span className="muted small">{member.email}</span>
                      </span>,
                      member.department.name,
                      member.title ?? <span className="muted">—</span>,
                    ]),
                  )}
                  empty="Nobody is in the departments you lead yet."
                />
              </Card>
            )}
          </div>
        )}
        {departments && identities && (
          <div className="tiles">
            <div className="card stat">
              <span className="label">Departments</span>
              <span className="value">{departments.length}</span>
              <span className="hint">
                {departments.filter((item) => !item.headId).length} without a head
              </span>
            </div>
            <div className="card stat">
              <span className="label">People placed</span>
              <span className="value">{assigned}</span>
              <span className="hint">
                {Math.max(0, identities.length - assigned)} of {identities.length} not in a
                department
              </span>
            </div>
          </div>
        )}
        <div className="grid cols-2" style={{ gridTemplateColumns: '3fr 2fr' }}>
          <Card title="Org chart">
            {tree ? (
              tree.length ? (
                <OrgChart nodes={tree} base={base} />
              ) : (
                <div className="empty">No departments yet.</div>
              )
            ) : (
              <div className="empty">
                Requires <code>iam:departments:read</code>.
              </div>
            )}
          </Card>
          {mayManage && (
            <Card title="Create a department">
              <ApiForm
                path="departments/create"
                tenantId={tenantId}
                submitLabel="Create department"
                redirectTo={`${base}/departments/{id}`}
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  { name: 'name', label: 'Name', required: true, placeholder: 'Engineering' },
                  { name: 'code', label: 'Code', placeholder: 'ENG' },
                  {
                    name: 'parentId',
                    label: 'Part of',
                    type: 'select',
                    options: (departments ?? []).map((item) => ({
                      value: item.id,
                      label: item.name,
                    })),
                  },
                  { name: 'headId', label: 'Head', type: 'select', options: people },
                  { name: 'costCenter', label: 'Cost center', placeholder: 'CC-100' },
                  { name: 'description', label: 'Description', type: 'textarea', rows: 2 },
                ]}
              />
            </Card>
          )}
        </div>
        <BirthrightSuggestions
          suggestions={suggestions ?? []}
          tenantId={tenantId}
          base={base}
          showUnit
        />
        <div className="grid cols-2">
          {mayManage && (
            <Card
              title="Import from people's attributes"
              description="Places everyone in the department their string attribute names (by name or code, ignoring case), such as the department HR or SCIM provisioning fills."
            >
              <ApiForm
                path="departments/importFromAttribute"
                tenantId={tenantId}
                submitLabel="Import"
                compact
                showResult
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'attribute',
                    label: 'Identity attribute',
                    required: true,
                    defaultValue: 'department',
                  },
                  {
                    name: 'createMissing',
                    label: 'Create departments for values nothing matches',
                    type: 'checkbox',
                  },
                  {
                    name: 'dryRun',
                    label: 'Preview only',
                    type: 'checkbox',
                    defaultValue: true,
                  },
                ]}
              />
            </Card>
          )}
          {maySyncManagers && (
            <Card
              title="Managers from the org chart"
              description="Makes each person's department head their manager (a head reports to the nearest head above), so manager approvals follow the org chart. Needs iam:identities:update."
            >
              {departments && departments.every((item) => !item.headId) && (
                <Alert tone="warning">No department has a head yet.</Alert>
              )}
              <ApiForm
                path="departments/syncManagers"
                tenantId={tenantId}
                submitLabel="Sync managers"
                compact
                showResult
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'departmentId',
                    label: 'Only this department (and those below)',
                    type: 'select',
                    options: (departments ?? []).map((item) => ({
                      value: item.id,
                      label: item.name,
                    })),
                  },
                  {
                    name: 'overwrite',
                    label: 'Replace managers people already have',
                    type: 'checkbox',
                  },
                  { name: 'dryRun', label: 'Preview only', type: 'checkbox', defaultValue: true },
                ]}
              />
            </Card>
          )}
        </div>
      </div>
    </>
  );
}
