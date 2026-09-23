import type { FeatureEvaluation, FeatureFlagView, FeatureTargetView } from 'better-iam';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Table, Time } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

/** Why the flag has its value here, in the organization's words. */
function reason(evaluation: FeatureEvaluation, tenantId: string): string {
  switch (evaluation.reason) {
    case 'KILL_SWITCH':
      return 'switched off everywhere';
    case 'TARGET':
      return evaluation.decidedBy === tenantId
        ? evaluation.locked
          ? 'set for you (locked)'
          : 'set for you'
        : 'set for an enclosing tenant';
    case 'OVERRIDE':
      return evaluation.decidedBy === tenantId ? 'your choice' : 'inherited choice';
    case 'ROLLOUT':
      return 'gradual rollout';
    case 'DEFAULT':
      return 'default';
    default:
      return 'unknown flag';
  }
}

function Value({ on }: { on: boolean }) {
  return <Badge tone={on ? 'success' : 'neutral'}>{on ? 'on' : 'off'}</Badge>;
}

/**
 * Feature flags for one organization: the platform's flags as they apply here (with this organization's choice for
 * flags that allow one), and the organization's own flags, which reach its projects.
 */
export default async function Features({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId } = await orgPage(org);
  const [listing, children] = await Promise.all([
    tryRead(() => iam.api.features.list(auth, { tenantId })),
    tryRead(() => iam.api.tenants.listChildren(auth, { tenantId })),
  ]);
  if (!listing)
    return (
      <>
        <PageHeader title="Features" />
        <Alert tone="warning">
          Requires <code>iam:features:read</code>.
        </Alert>
      </>
    );
  const inherited = listing.flags.filter((flag) => flag.definedBy !== tenantId);
  const own = listing.flags.filter((flag) => flag.definedBy === tenantId);
  const projects = (children ?? []).filter((child) => child.status !== 'deleted');
  const targets = new Map<string, FeatureTargetView[]>(
    await Promise.all(
      own.map(
        async (flag) =>
          [
            flag.key,
            (await tryRead(() =>
              iam.api.features.listTargets(auth, { tenantId, key: flag.key }),
            )) ?? [],
          ] as const,
      ),
    ),
  );
  const choice = (flag: FeatureFlagView) => {
    if (!flag.tenantOverridable)
      return (
        <span key="c" className="small muted">
          decided by the platform
        </span>
      );
    if (!flag.evaluation.overridable)
      return (
        <Badge key="c" tone="warning">
          locked
        </Badge>
      );
    const set = (value: boolean | null, label: string) => (
      <ApiButton
        key={label}
        path="features/setOverride"
        body={{ tenantId, key: flag.key, value }}
        label={label}
        tone={value === null ? 'secondary' : 'primary'}
        tenantId={tenantId}
      />
    );
    return (
      <span key="c" className="row">
        {flag.override?.value !== true && set(true, 'Turn on')}
        {flag.override?.value !== false && set(false, 'Turn off')}
        {flag.override && set(null, 'Use default')}
      </span>
    );
  };

  return (
    <>
      <PageHeader
        title="Features"
        description="Feature flags decide which product features this organization and its projects get. Platform features come from the service; some let you choose. Your own flags reach your projects: set them per project, or roll them out gradually. Applications read them with useFeatureFlags, iam.features, or a tenant.features policy condition."
      />
      <div className="stack">
        <Card
          title="Platform features"
          description="Flags the platform defines. Where a flag allows it, your choice applies to this organization and its projects unless the platform locks it."
          flush
        >
          <Table
            head={['Flag', 'Value here', 'Why', 'Your choice']}
            rows={inherited.map((flag) => [
              <span key="k">
                <code>{flag.key}</code>
                {flag.description && <span className="small muted"> · {flag.description}</span>}
              </span>,
              <Value key="v" on={flag.evaluation.value} />,
              <span key="r" className="small">
                {reason(flag.evaluation, tenantId)}
                {flag.evaluation.expiresAt && (
                  <>
                    {' '}
                    until <Time value={flag.evaluation.expiresAt} />
                  </>
                )}
              </span>,
              choice(flag),
            ])}
            empty="The platform has not defined any features yet."
          />
        </Card>
        {listing.shadowed.length > 0 && (
          <Alert tone="warning">
            The platform now defines{' '}
            {listing.shadowed.map((flag) => (
              <code key={flag.key}>{flag.key} </code>
            ))}
            too, so its flag applies instead of yours. Rename or delete your flag.
          </Alert>
        )}
        {own.map((flag) => {
          const definition = flag.definition!;
          const entries = targets.get(flag.key) ?? [];
          return (
            <Card
              key={flag.key}
              title={
                <span className="row">
                  <code>{flag.key}</code>
                  {definition.killSwitch ? (
                    <Badge tone="danger">killed</Badge>
                  ) : definition.rolloutPercentage !== undefined ? (
                    <Badge tone="info">rollout {definition.rolloutPercentage}%</Badge>
                  ) : (
                    <Value on={definition.defaultValue} />
                  )}
                  {definition.tenantOverridable && (
                    <Badge tone="accent">projects may override</Badge>
                  )}
                  {definition.internal && <Badge tone="warning">internal</Badge>}
                </span>
              }
              description={definition.description}
              actions={
                <>
                  <ApiButton
                    path="features/update"
                    body={{ tenantId, key: flag.key, killSwitch: !definition.killSwitch }}
                    label={definition.killSwitch ? 'Restore' : 'Kill switch'}
                    tone={definition.killSwitch ? 'secondary' : 'danger'}
                    confirm={
                      definition.killSwitch
                        ? `Restore ${flag.key}?`
                        : `Turn ${flag.key} off for the organization and every project?`
                    }
                    tenantId={tenantId}
                  />
                  <ApiButton
                    path="features/delete"
                    body={{ tenantId, key: flag.key }}
                    label="Delete"
                    tone="danger"
                    confirm={`Delete ${flag.key}? Code that asks for it gets false.`}
                    tenantId={tenantId}
                  />
                </>
              }
            >
              <div className="stack">
                <Table
                  head={['Project', 'Set by', 'Value', 'Until', 'Status', '']}
                  rows={entries.map((entry) => [
                    entry.tenantName,
                    entry.source === 'target' ? (
                      <span key="s">
                        you {entry.locked && <Badge tone="warning">locked</Badge>}
                      </span>
                    ) : (
                      <span key="s" className="muted">
                        the project
                      </span>
                    ),
                    <Value key="v" on={entry.value} />,
                    entry.expiresAt ? <Time key="u" value={entry.expiresAt} /> : '—',
                    <Badge key="a" tone={entry.active ? 'success' : 'neutral'}>
                      {entry.active ? 'applies' : 'ignored'}
                    </Badge>,
                    entry.source === 'target' ? (
                      <ApiButton
                        key="x"
                        path="features/setTarget"
                        body={{
                          tenantId,
                          key: flag.key,
                          targetTenantId: entry.tenantId,
                          value: null,
                        }}
                        label="Remove"
                        tenantId={tenantId}
                      />
                    ) : (
                      ''
                    ),
                  ])}
                  empty="No project has its own value."
                />
                {projects.length > 0 && (
                  <details>
                    <summary className="small">Set for a project</summary>
                    <ApiForm
                      path="features/setTarget"
                      tenantId={tenantId}
                      submitLabel="Set"
                      resetOnSuccess
                      fields={[
                        {
                          name: 'tenantId',
                          label: 'Tenant',
                          type: 'hidden',
                          defaultValue: tenantId,
                        },
                        { name: 'key', label: 'Key', type: 'hidden', defaultValue: flag.key },
                        {
                          name: 'targetTenantId',
                          label: 'Project',
                          type: 'select',
                          required: true,
                          options: projects.map((project) => ({
                            value: project.id,
                            label: project.name,
                          })),
                        },
                        { name: 'value', label: 'On for this project', type: 'checkbox' },
                        {
                          name: 'locked',
                          label: 'Locked (the project cannot override)',
                          type: 'checkbox',
                        },
                        { name: 'expiresAt', label: 'Until', type: 'datetime' },
                      ]}
                    />
                  </details>
                )}
                <details>
                  <summary className="small">Settings</summary>
                  <ApiForm
                    path="features/update"
                    tenantId={tenantId}
                    fields={[
                      { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                      { name: 'key', label: 'Key', type: 'hidden', defaultValue: flag.key },
                      {
                        name: 'description',
                        label: 'Description',
                        defaultValue: definition.description ?? '',
                        emptyAsNull: true,
                      },
                      {
                        name: 'defaultValue',
                        label: 'On by default',
                        type: 'checkbox',
                        defaultValue: definition.defaultValue,
                      },
                      {
                        name: 'rolloutPercentage',
                        label: 'Rollout (% of projects)',
                        type: 'number',
                        defaultValue: definition.rolloutPercentage ?? '',
                        emptyAsNull: true,
                      },
                      {
                        name: 'tenantOverridable',
                        label: 'Projects may override',
                        type: 'checkbox',
                        defaultValue: definition.tenantOverridable,
                      },
                      {
                        name: 'internal',
                        label: 'Internal (server code and policies only)',
                        type: 'checkbox',
                        defaultValue: definition.internal,
                      },
                    ]}
                  />
                </details>
                <span className="small muted">
                  Updated <Time value={definition.updatedAt} />
                </span>
              </div>
            </Card>
          );
        })}
        <Card
          title="New organization flag"
          description="Your flags reach this organization and its projects only. Keys are lowercase letters and digits joined by -, _, or ., and cannot repeat a platform key."
        >
          <ApiForm
            path="features/create"
            tenantId={tenantId}
            submitLabel="Create flag"
            resetOnSuccess
            fields={[
              { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
              { name: 'key', label: 'Key', required: true, placeholder: 'beta-reports' },
              { name: 'description', label: 'Description' },
              { name: 'defaultValue', label: 'On by default', type: 'checkbox' },
              {
                name: 'rolloutPercentage',
                label: 'Rollout (% of projects)',
                type: 'number',
                help: 'Leave empty for none; requires the flag to be off by default.',
              },
              { name: 'tenantOverridable', label: 'Projects may override', type: 'checkbox' },
            ]}
          />
        </Card>
      </div>
    </>
  );
}
