import Link from 'next/link';
import type { ResourceRecord } from 'better-iam/server';
import { Badge, Card, KeyValues, PageHeader, Stat, Table } from '@/components/ui';
import { can, key, orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const capabilities: [string, string][] = [
  ['iam:identities:read', 'View members'],
  ['iam:identities:create', 'Invite members'],
  ['iam:roles:create', 'Create roles'],
  ['iam:policies:create', 'Write policies'],
  ['iam:resource-types:create', 'Define resource types'],
  ['iam:resources:create', 'Register resources'],
  ['iam:credentials:create', 'Issue API keys'],
  ['iam:audit:read', 'Read the audit log'],
  ['iam:tenants:update', 'Change organization settings'],
];

export default async function Overview({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const page = await orgPage(org);
  const { iam, auth, tenantId, session, base } = page;
  const [access, bindings, members, roles, workspaces] = await Promise.all([
    can(
      page,
      capabilities.map(([action]) => ({ action })),
    ),
    tryRead(() =>
      iam.api.identities.listBindings(auth, { tenantId, identityId: session.identity.id }),
    ),
    tryRead(() => iam.api.identities.list(auth, { tenantId })),
    tryRead(() => iam.api.roles.list(auth, { tenantId })),
    iam.store.find<ResourceRecord>('resources', { tenantId, type: 'workspace' }),
  ]);
  // A glance at governance for people who can see it; the Governance page has the detail.
  const [findings, invariants, activationApprovals, packageApprovals, agreements] =
    await Promise.all([
      tryRead(() => iam.api.analysis.findings(auth, { tenantId })),
      tryRead(() => iam.api.invariants.run(auth, { tenantId })),
      tryRead(() => iam.api.bindings.listApprovals(auth, { tenantId })),
      tryRead(() => iam.api.packages.listApprovals(auth, { tenantId })),
      tryRead(() => iam.api.agreements.listMine(auth, { tenantId })),
    ]);
  const approvals =
    activationApprovals || packageApprovals
      ? (activationApprovals?.length ?? 0) + (packageApprovals?.length ?? 0)
      : undefined;
  // Setup checklists the levels above ask of this organization or project, while any is unfinished.
  const setup = await tryRead(() => iam.api.onboarding.setup(auth, { tenantId }));
  const setupSteps = setup?.flows.flatMap((flow) =>
    flow.steps.filter(
      (step) => !step.optional && step.state !== 'complete' && step.state !== 'unavailable',
    ),
  );
  const owedAgreements = agreements?.filter(
    (agreement) => agreement.required && !agreement.accepted,
  ).length;
  const readable = workspaces.length
    ? await can(
        page,
        workspaces.map((workspace) => ({
          action: 'workspaces:read',
          resource: { type: 'workspace', id: workspace.resourceId },
        })),
      )
    : {};
  return (
    <>
      <PageHeader
        title={`Welcome, ${session.identity.name}`}
        description="Your organization is an account: colleagues sign in with their own identities, and every action is authorized against the roles they hold here."
      />
      <div className="stack">
        <div className="grid cols-4">
          <Stat
            label="Workspaces you can open"
            value={`${Object.values(readable).filter(Boolean).length} / ${workspaces.length}`}
            hint={<Link href={`${base}/workspaces`}>Workspaces</Link>}
          />
          <Stat
            label="Members"
            value={members ? members.filter((identity) => identity.kind === 'user').length : '—'}
            hint={
              members ? (
                <Link href={`${base}/members`}>Manage members</Link>
              ) : (
                'Requires iam:identities:read'
              )
            }
          />
          <Stat
            label="Roles"
            value={roles ? roles.length : '—'}
            hint={
              roles ? <Link href={`${base}/roles`}>Manage roles</Link> : 'Requires iam:roles:read'
            }
          />
          <Stat
            label="Your roles"
            value={
              bindings
                ? bindings.filter((binding) => !binding.eligible || binding.activation).length
                : '—'
            }
            hint={
              bindings
                ? bindings
                    .map(
                      (binding) =>
                        `${binding.role?.name ?? binding.roleId}${
                          binding.eligible
                            ? binding.activation
                              ? ' (activated)'
                              : ' (eligible)'
                            : ''
                        }`,
                    )
                    .join(', ') || 'none'
                : 'Requires iam:bindings:read'
            }
          />
        </div>
        {setup && setup.flows.length > 0 && !setup.complete && (
          <Card
            title="Finish setting up"
            description={`${setup.flows.map((flow) => flow.name).join(', ')}: ${setupSteps?.length ?? 0} step${setupSteps?.length === 1 ? '' : 's'} left.`}
            actions={
              <Link className="btn small" href={`${base}/setup`}>
                Continue setup
              </Link>
            }
            flush
          >
            <div className="attention">
              {(setupSteps ?? []).slice(0, 5).map((step) => (
                <Link key={step.id} href={`${base}/setup`}>
                  <Badge tone={step.state === 'submitted' ? 'info' : 'warning'}>
                    {step.state === 'submitted' ? 'in review' : 'to do'}
                  </Badge>
                  <span>{step.title}</span>
                  <span className="small muted">{step.detail ?? ''}</span>
                </Link>
              ))}
            </div>
          </Card>
        )}
        {(findings || invariants || approvals !== undefined) && (
          <Card
            title="Governance at a glance"
            description="Risks, guardrails, and requests waiting on you."
            actions={
              <Link className="btn small secondary" href={`${base}/governance`}>
                Open governance
              </Link>
            }
          >
            <div className="grid cols-4">
              <div className="stack" style={{ gap: 4 }}>
                <span className="small muted">High-severity findings</span>
                <span>
                  {findings ? (
                    <Badge tone={findings.summary.high ? 'danger' : 'success'}>
                      {findings.summary.high}
                    </Badge>
                  ) : (
                    '—'
                  )}
                </span>
              </div>
              <div className="stack" style={{ gap: 4 }}>
                <span className="small muted">Invariants holding</span>
                <span>
                  {invariants ? (
                    <Badge
                      tone={
                        invariants.summary.failed + invariants.summary.errors
                          ? 'warning'
                          : 'success'
                      }
                    >
                      {invariants.summary.passed} / {invariants.results.length}
                    </Badge>
                  ) : (
                    '—'
                  )}
                </span>
              </div>
              <div className="stack" style={{ gap: 4 }}>
                <span className="small muted">Waiting for your approval</span>
                <span>
                  {approvals === undefined ? (
                    '—'
                  ) : (
                    <Link href={`${base}/elevate`}>
                      <Badge tone={approvals ? 'warning' : 'neutral'}>{approvals}</Badge>
                    </Link>
                  )}
                </span>
              </div>
              <div className="stack" style={{ gap: 4 }}>
                <span className="small muted">Agreements you owe</span>
                <span>
                  {owedAgreements === undefined ? (
                    '—'
                  ) : (
                    <Badge tone={owedAgreements ? 'warning' : 'success'}>{owedAgreements}</Badge>
                  )}
                </span>
              </div>
            </div>
          </Card>
        )}
        <div className="grid cols-2">
          <Card
            title="What you can do here"
            description="Advisory decisions from one batched authorization; the server re-checks every operation."
            flush
          >
            <Table
              head={['Capability', 'Action', 'Decision']}
              rows={capabilities.map(([action, label]) => [
                label,
                <code key="a" className="small">
                  {action}
                </code>,
                access[key(action, undefined, tenantId)] ? (
                  <Badge key="d" tone="success">
                    allowed
                  </Badge>
                ) : (
                  <Badge key="d" tone="danger">
                    denied
                  </Badge>
                ),
              ])}
            />
          </Card>
          <Card title="Your identity">
            <KeyValues
              items={[
                ['Name', session.identity.name],
                ['Email', session.identity.email ?? '—'],
                [
                  'Identity ID',
                  <code key="i" className="small">
                    {session.identity.id}
                  </code>,
                ],
                [
                  'Tenant ID',
                  <code key="t" className="small">
                    {tenantId}
                  </code>,
                ],
                ['Owner', session.identity.owner ? 'yes' : 'no'],
                ['Session MFA', session.session.mfa ? 'verified' : 'not used'],
                ['Session expires', new Date(session.session.expiresAt).toLocaleString()],
              ]}
            />
            <p className="small muted" style={{ marginTop: 12 }}>
              <Link href={`${base}/account`}>
                Manage sessions, password, MFA, and linked accounts →
              </Link>
            </p>
          </Card>
        </div>
      </div>
    </>
  );
}
