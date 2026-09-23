import type { FeatureFlagView, FeatureTargetView, Tenant } from 'better-iam';
import { ApiButton, ApiForm } from '@/components/api-form';
import { Alert, Badge, Card, PageHeader, Stat, Table, Time } from '@/components/ui';
import { getIam } from '@/lib/iam';
import { credential, requireRootSession, rootTenant } from '@/lib/session';

/** How a flag's settings read at a glance. */
function SettingBadges({ flag }: { flag: NonNullable<FeatureFlagView['definition']> }) {
  return (
    <span className="row">
      {flag.killSwitch ? (
        <Badge tone="danger">killed</Badge>
      ) : flag.rolloutPercentage !== undefined ? (
        <Badge tone="info">rollout {flag.rolloutPercentage}%</Badge>
      ) : flag.defaultValue ? (
        <Badge tone="success">on by default</Badge>
      ) : (
        <Badge>off by default</Badge>
      )}
      {flag.tenantOverridable && <Badge tone="accent">organizations may override</Badge>}
      {flag.internal && <Badge tone="warning">internal</Badge>}
    </span>
  );
}

/**
 * Platform feature flags: the flags the root tenant defines, which reach every organization and project. Root
 * administrators set defaults and rollouts, pin values for single tenants (optionally locked, optionally lapsing),
 * and pull the kill switch; organizations may override flags that allow it, and those choices are listed here too.
 */
export default async function Features() {
  const admin = await requireRootSession();
  const iam = await getIam();
  const auth = await credential();
  const root = await rootTenant();
  if (!root) return <Alert tone="warning">No root tenant.</Alert>;
  const [listing, tenants] = await Promise.all([
    iam.api.features.list(auth, { tenantId: root.id }),
    iam.store.find<Tenant>('tenants'),
  ]);
  const flags = listing.flags.filter((flag) => flag.definedBy === root.id);
  const targets = new Map<string, FeatureTargetView[]>(
    await Promise.all(
      flags.map(
        async (flag) =>
          [
            flag.key,
            await iam.api.features.listTargets(auth, { tenantId: root.id, key: flag.key }),
          ] as const,
      ),
    ),
  );
  const tenantById = new Map(tenants.map((tenant) => [tenant.id, tenant]));
  const pathOf = (tenant: Tenant): string => {
    const parent = tenant.parentId ? tenantById.get(tenant.parentId) : undefined;
    return parent && parent.parentId ? `${pathOf(parent)} / ${tenant.name}` : tenant.name;
  };
  const choices = tenants
    .filter((tenant) => tenant.parentId !== null && tenant.status !== 'deleted')
    .map((tenant) => ({ value: tenant.id, label: `${pathOf(tenant)} (${tenant.type})` }))
    .sort((a, b) => a.label.localeCompare(b.label));
  const stepUp = admin.session.tenantId;
  const pinned = [...targets.values()].flat().filter((entry) => entry.active);

  return (
    <>
      <PageHeader
        title="Feature flags"
        description="Platform flags reach every organization and project. A flag's value for a tenant is decided, in order, by the kill switch, the closest target or organization override, the rollout, and the default. Applications read values with iam.features on the server, useFeatureFlags in React, or a tenant.features policy condition."
      />
      <div className="stack">
        <div className="grid cols-4">
          <Stat label="Platform flags" value={flags.length} />
          <Stat
            label="On by default"
            value={flags.filter((flag) => flag.definition?.defaultValue).length}
          />
          <Stat
            label="Rolling out"
            value={flags.filter((flag) => flag.definition?.rolloutPercentage !== undefined).length}
          />
          <Stat
            label="Tenant targets and overrides"
            value={pinned.length}
            hint={`${flags.filter((flag) => flag.definition?.killSwitch).length} killed`}
          />
        </div>
        {flags.map((flag) => {
          const definition = flag.definition!;
          const entries = targets.get(flag.key) ?? [];
          return (
            <Card
              key={flag.key}
              title={
                <span className="row">
                  <code>{flag.key}</code>
                  <SettingBadges flag={definition} />
                </span>
              }
              description={
                <>
                  {definition.description ?? 'No description.'} · updated{' '}
                  <Time value={definition.updatedAt} />
                </>
              }
              actions={
                <>
                  <ApiButton
                    path="features/update"
                    body={{ tenantId: root.id, key: flag.key, killSwitch: !definition.killSwitch }}
                    label={definition.killSwitch ? 'Restore' : 'Kill switch'}
                    tone={definition.killSwitch ? 'secondary' : 'danger'}
                    confirm={
                      definition.killSwitch
                        ? `Restore ${flag.key}? Targets, overrides, and the rollout apply again.`
                        : `Turn ${flag.key} off for every tenant, whatever targets and overrides say?`
                    }
                    tenantId={stepUp}
                  />
                  <ApiButton
                    path="features/delete"
                    body={{ tenantId: root.id, key: flag.key }}
                    label="Delete"
                    tone="danger"
                    confirm={`Delete ${flag.key} with its ${entries.length} target(s) and override(s)? Code that asks for it gets false.`}
                    tenantId={stepUp}
                  />
                </>
              }
            >
              <div className="stack">
                <Table
                  head={['Tenant', 'Set by', 'Value', 'Until', 'Note', 'Status', '']}
                  rows={entries.map((entry) => [
                    <span key="t">
                      {entry.tenantName}{' '}
                      {entry.tenantStatus !== 'active' && <Badge>{entry.tenantStatus}</Badge>}
                    </span>,
                    entry.source === 'target' ? (
                      <span key="s">
                        platform {entry.locked && <Badge tone="warning">locked</Badge>}
                      </span>
                    ) : (
                      <span key="s" className="muted">
                        organization&apos;s choice
                      </span>
                    ),
                    <Badge key="v" tone={entry.value ? 'success' : 'neutral'}>
                      {entry.value ? 'on' : 'off'}
                    </Badge>,
                    entry.expiresAt ? <Time key="u" value={entry.expiresAt} /> : '—',
                    entry.note ?? '',
                    <Badge key="a" tone={entry.active ? 'success' : 'neutral'}>
                      {entry.active ? 'applies' : 'ignored'}
                    </Badge>,
                    <ApiButton
                      key="x"
                      path={
                        entry.source === 'target' ? 'features/setTarget' : 'features/setOverride'
                      }
                      body={
                        entry.source === 'target'
                          ? {
                              tenantId: root.id,
                              key: flag.key,
                              targetTenantId: entry.tenantId,
                              value: null,
                            }
                          : { tenantId: entry.tenantId, key: flag.key, value: null }
                      }
                      label="Remove"
                      confirm={`Remove this ${entry.source} for ${entry.tenantName}?`}
                      tenantId={stepUp}
                    />,
                  ])}
                  empty="No tenant has a target or override: every tenant gets the rollout or the default."
                />
                <details>
                  <summary className="small">Target a tenant</summary>
                  <ApiForm
                    path="features/setTarget"
                    tenantId={stepUp}
                    submitLabel="Set target"
                    resetOnSuccess
                    fields={[
                      { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: root.id },
                      { name: 'key', label: 'Key', type: 'hidden', defaultValue: flag.key },
                      {
                        name: 'targetTenantId',
                        label: 'Organization or project',
                        type: 'select',
                        required: true,
                        options: choices,
                        help: 'Applies to the tenant and everything below it, unless something closer decides.',
                      },
                      { name: 'value', label: 'On for this tenant', type: 'checkbox' },
                      {
                        name: 'locked',
                        label: 'Locked (the tenant and its projects cannot override)',
                        type: 'checkbox',
                      },
                      {
                        name: 'expiresAt',
                        label: 'Until',
                        type: 'datetime',
                        help: 'A trial or a temporary block ends by itself.',
                      },
                      {
                        name: 'note',
                        label: 'Note',
                        placeholder: 'Only root administrators see it',
                      },
                    ]}
                  />
                </details>
                <details>
                  <summary className="small">Settings</summary>
                  <ApiForm
                    path="features/update"
                    tenantId={stepUp}
                    fields={[
                      { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: root.id },
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
                        label: 'Rollout (% of organizations)',
                        type: 'number',
                        defaultValue: definition.rolloutPercentage ?? '',
                        emptyAsNull: true,
                        help: 'Turns an off-by-default flag on for a stable share of organizations; raising it only adds organizations.',
                      },
                      {
                        name: 'tenantOverridable',
                        label: 'Organizations may override',
                        type: 'checkbox',
                        defaultValue: definition.tenantOverridable,
                      },
                      {
                        name: 'internal',
                        label: 'Internal (server code and policies only; hidden from tenants)',
                        type: 'checkbox',
                        defaultValue: definition.internal,
                      },
                    ]}
                  />
                </details>
              </div>
            </Card>
          );
        })}
        <Card
          title="New platform flag"
          description="Keys are lowercase letters and digits joined by -, _, or . (for example new-billing or reports.v2). Organizations cannot define a flag with a platform key, and a platform flag takes precedence over an organization flag created earlier with the same key."
        >
          <ApiForm
            path="features/create"
            tenantId={stepUp}
            submitLabel="Create flag"
            resetOnSuccess
            fields={[
              { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: root.id },
              { name: 'key', label: 'Key', required: true, placeholder: 'new-billing' },
              { name: 'description', label: 'Description' },
              { name: 'defaultValue', label: 'On by default', type: 'checkbox' },
              {
                name: 'rolloutPercentage',
                label: 'Rollout (% of organizations)',
                type: 'number',
                help: 'Leave empty for none; requires the flag to be off by default.',
              },
              { name: 'tenantOverridable', label: 'Organizations may override', type: 'checkbox' },
              {
                name: 'internal',
                label: 'Internal (server code and policies only; hidden from tenants)',
                type: 'checkbox',
              },
            ]}
          />
        </Card>
      </div>
    </>
  );
}
