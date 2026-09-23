import Link from 'next/link';
import { ApiButton, ApiForm } from '@/components/api-form';
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
import { authPolicyFields, uneditedPolicyKeys } from '@/lib/auth-policy-form';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Settings({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId, tenant, base, session } = await orgPage(org);
  // The page's own tenant record is a raw read that only proves membership; the details and the authentication
  // policy (allowed networks, impersonation, lockout limits) are shown only to viewers who may read the tenant.
  const [readable, children, usage, blocks] = await Promise.all([
    tryRead(() => iam.api.tenants.get(auth, { tenantId })),
    tryRead(() => iam.api.tenants.listChildren(auth, { tenantId })),
    tryRead(() => iam.api.tenants.usage(auth, { tenantId })),
    tryRead(() => iam.api.security.listBlocks(auth, { tenantId })),
  ]);
  const policy = readable?.authPolicy;
  const unedited = uneditedPolicyKeys(policy);
  // Sessions carry a client IP only when the deployment derives one (http.clientInfo, the console's
  // TRUSTED_PROXY_HOPS); without it the network controls below are saved but never enforced.
  const recordsAddresses = Boolean(session.session.client?.ip);
  const addressNotice = !recordsAddresses && (
    <Alert tone="warning">
      This deployment does not record client addresses (your own session has none), so allowed
      networks, session binding, and network blocks are saved but not enforced. The operator enables
      them by running the console behind a reverse proxy they control and setting{' '}
      <code>TRUSTED_PROXY_HOPS</code>.
    </Alert>
  );
  return (
    <>
      <PageHeader
        title="Organization settings"
        description="Changes here require recent authentication and iam:tenants:update; the console will ask you to confirm your password when needed."
      />
      <div className="stack">
        <div className="grid cols-3">
          <Card title="Details">
            {readable ? (
              <KeyValues
                items={[
                  [
                    'Tenant ID',
                    <code key="i" className="small">
                      {readable.id}
                    </code>,
                  ],
                  ['Type', readable.type],
                  ['Status', <StatusBadge key="s" status={readable.status} />],
                  ['Alias', readable.slug ?? '—'],
                  ['Created', <Time key="c" value={readable.createdAt} />],
                  [
                    'Boundary',
                    readable.boundary
                      ? `${readable.boundary.statements.length} statement(s) set by the platform`
                      : 'none',
                  ],
                ]}
              />
            ) : (
              <div className="empty">
                Requires <code>iam:tenants:read</code>.
              </div>
            )}
          </Card>
          <Card title="Name">
            <ApiForm
              path="tenants/update"
              tenantId={tenantId}
              submitLabel="Rename"
              compact
              successMessage="Renamed."
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                {
                  name: 'name',
                  label: 'Organization name',
                  required: true,
                  defaultValue: tenant.name,
                },
              ]}
            />
          </Card>
          <Card
            title="Sign-in alias"
            description="Changing it changes the console URL; share the new alias with members."
          >
            <ApiForm
              path="tenants/setSlug"
              tenantId={tenantId}
              submitLabel="Set alias"
              compact
              redirectTo="/cloud"
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                {
                  name: 'slug',
                  label: 'Alias',
                  defaultValue: tenant.slug ?? '',
                  placeholder: 'acme',
                  // tenants.setSlug removes the alias only for an explicit null; an omitted slug is invalid input.
                  emptyAsNull: true,
                  help: 'Leave empty to remove the alias; members then sign in with the tenant ID.',
                },
              ]}
            />
          </Card>
        </div>
        {usage && (
          <Card
            title="Usage and plan limits"
            description="Limits are set by the platform; ask your provider to raise them. Creation past a limit fails with LIMIT_EXCEEDED."
          >
            <div className="grid cols-4">
              {(
                [
                  ['Members', usage.identities, usage.limits.identities],
                  ['Members with MFA', usage.mfaEnrolled, usage.identities],
                  ['Service accounts', usage.serviceAccounts, usage.limits.serviceAccounts],
                  ['Groups', usage.groups, usage.limits.groups],
                  ['Roles', usage.roles, usage.limits.roles],
                  ['Policies', usage.policies, usage.limits.policies],
                  ['Resources', usage.resources, usage.limits.resources],
                  ['Webhooks', usage.webhooks, usage.limits.webhooks],
                  ['Active sessions', usage.activeSessions, undefined],
                ] as const
              ).map(([label, value, limit]) => (
                <KeyValues
                  key={label}
                  items={[[label, limit === undefined ? String(value) : `${value} / ${limit}`]]}
                />
              ))}
            </div>
          </Card>
        )}
        <div className="grid cols-2">
          <Card
            title="Projects and sub-organizations"
            description="Child tenants are separate accounts with their own members; parent membership grants nothing there."
            flush
          >
            {children ? (
              <Table
                head={['Name', 'Type', 'Status', 'Alias', 'Console']}
                rows={children.map((child) => [
                  child.name,
                  child.type,
                  <StatusBadge key="s" status={child.status} />,
                  child.slug ?? '—',
                  child.status === 'active' ? (
                    <Link
                      key="l"
                      href={`/cloud/login?org=${encodeURIComponent(child.slug ?? child.id)}`}
                    >
                      sign in
                    </Link>
                  ) : (
                    ''
                  ),
                ])}
                empty="No child tenants."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:tenants:read</code>.
              </div>
            )}
          </Card>
          <Card
            title="Create a child tenant"
            description="The owner receives an invitation; you keep your grant authority chain as the delegating parent."
          >
            <ApiForm
              path="tenants/create"
              tenantId={tenantId}
              submitLabel="Create and invite owner"
              successMessage="Child tenant created; the owner invitation is queued."
              resetOnSuccess
              fields={[
                { name: 'parentId', label: 'Parent', type: 'hidden', defaultValue: tenantId },
                {
                  name: 'type',
                  label: 'Type',
                  type: 'select',
                  required: true,
                  options: [{ value: 'project', label: 'Project' }],
                },
                { name: 'name', label: 'Name', required: true },
                { name: 'slug', label: 'Sign-in alias' },
                { name: 'ownerEmail', label: 'Owner email', type: 'email', required: true },
              ]}
            />
          </Card>
        </div>
        {readable && (
          <div className="grid cols-2">
            <Card
              title="Authentication policy"
              description="Tightens the deployment's rules for everyone in this organization: required MFA, accepted sign-in methods, and session lifetimes. Existing sessions are re-checked on their next request."
            >
              <KeyValues
                items={[
                  [
                    'MFA required',
                    policy?.requireMfa ? (
                      <Badge key="m" tone="success">
                        yes
                      </Badge>
                    ) : (
                      'no'
                    ),
                  ],
                  [
                    'MFA required for owners',
                    policy?.requireMfaForOwners ? (
                      <Badge key="mo" tone="success">
                        yes
                      </Badge>
                    ) : (
                      'no'
                    ),
                  ],
                  [
                    'Sessions bound to network',
                    policy?.bindSessionsToIp ? (
                      <Badge key="bs" tone="success">
                        yes
                      </Badge>
                    ) : (
                      'no'
                    ),
                  ],
                  ['Allowed methods', policy?.allowedMethods?.join(', ') ?? 'all configured'],
                  [
                    'Session lifetime',
                    policy?.sessionLifetimeMs
                      ? `${Math.round(policy.sessionLifetimeMs / 60000)} min`
                      : 'deployment default',
                  ],
                  [
                    'Idle timeout',
                    policy?.sessionIdleTimeoutMs
                      ? `${Math.round(policy.sessionIdleTimeoutMs / 60000)} min`
                      : 'deployment default',
                  ],
                  ['Attempts per window', policy?.maxAttempts?.toString() ?? 'deployment default'],
                  ['Minimum password length', policy?.minPasswordLength?.toString() ?? '12'],
                  [
                    'Password rules',
                    [
                      policy?.passwordMinClasses &&
                        `${policy.passwordMinClasses} character classes`,
                      policy?.passwordHistory && `last ${policy.passwordHistory} remembered`,
                      policy?.passwordMaxAgeDays &&
                        `expires after ${policy.passwordMaxAgeDays} days`,
                      policy?.passwordRejectPersonalInfo && 'no personal information',
                    ]
                      .filter(Boolean)
                      .join(', ') || 'length only',
                  ],
                  ['Concurrent sessions', policy?.maxSessions?.toString() ?? 'unlimited'],
                  [
                    'Remembered devices',
                    policy?.trustedDeviceDays === 0
                      ? 'off'
                      : policy?.trustedDeviceDays !== undefined
                        ? `${policy.trustedDeviceDays} days`
                        : 'deployment default',
                  ],
                  [
                    'Allowed networks',
                    policy?.allowedIpRanges?.length ? (
                      <code key="n" className="small">
                        {policy.allowedIpRanges.join(', ')}
                      </code>
                    ) : (
                      'any'
                    ),
                  ],
                  [
                    'View as member',
                    policy?.allowImpersonation ? (
                      <Badge key="i" tone="warning">
                        enabled
                      </Badge>
                    ) : (
                      'off'
                    ),
                  ],
                ]}
              />
              {policy && (
                <div style={{ marginTop: 12 }}>
                  <ApiButton
                    path="tenants/setAuthPolicy"
                    body={{ tenantId, authPolicy: null }}
                    label="Clear policy"
                    tone="danger"
                    confirm="Remove the organization's authentication policy?"
                    tenantId={tenantId}
                  />
                </div>
              )}
            </Card>
            <Card title="Set authentication policy" description="Replaces the whole policy.">
              <div className="stack">
                {addressNotice}
                {unedited.length > 0 && (
                  <Alert tone="warning">
                    The stored policy also sets {unedited.join(', ')}, which this form cannot edit;
                    saving it removes them. Change the policy through the API instead.
                  </Alert>
                )}
                <ApiForm
                  path="tenants/setAuthPolicy"
                  tenantId={tenantId}
                  submitLabel="Save policy"
                  compact
                  successMessage="Policy saved. Members without MFA must enroll on their next sign-in if you required it."
                  fields={[
                    { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                    ...authPolicyFields(policy, { recordsAddresses }),
                  ]}
                />
              </div>
            </Card>
          </div>
        )}
        {blocks && (
          <Card
            title="Blocked networks"
            description="Refuse every sign-in and live session from an address or CIDR block (IP_BLOCKED) for this organization, before passwords or rate limits are examined. Needs recorded client addresses and your recent authentication; your own address is refused."
          >
            {addressNotice && <div style={{ marginBottom: 12 }}>{addressNotice}</div>}
            <div className="grid cols-2">
              <ApiForm
                path="security/blockNetwork"
                tenantId={tenantId}
                submitLabel="Block network"
                compact
                resetOnSuccess
                successMessage="Blocked."
                fields={[
                  {
                    name: 'tenantId',
                    label: 'Tenant',
                    type: 'hidden',
                    defaultValue: tenantId,
                  },
                  {
                    name: 'network',
                    label: 'Address or CIDR block',
                    required: true,
                    placeholder: '198.51.100.0/24',
                  },
                  { name: 'reason', label: 'Reason', required: true, placeholder: 'Scanner' },
                  {
                    name: 'durationMs',
                    label: 'Duration in hours (empty: until lifted)',
                    type: 'number',
                    multiplier: 3_600_000,
                  },
                ]}
              />
              <Table
                head={['Network', 'Reason', 'Until', 'Status', '']}
                rows={blocks.map((block) => [
                  <code key="n" className="small">
                    {block.network}
                  </code>,
                  block.reason,
                  block.expiresAt ? (
                    <Time key="u" value={block.expiresAt} />
                  ) : (
                    <span key="u" className="muted">
                      until lifted
                    </span>
                  ),
                  <span key="s" className="row" style={{ display: 'inline-flex' }}>
                    <Badge tone={block.active ? 'danger' : 'neutral'}>
                      {block.active ? 'active' : 'lapsed'}
                    </Badge>
                    {block.platform && <Badge tone="warning">platform-wide</Badge>}
                  </span>,
                  // Platform-wide blocks (listed on the root organization) are lifted by root administrators only.
                  !block.platform || session.identity.rootAdmin ? (
                    <ApiButton
                      key="x"
                      path="security/unblockNetwork"
                      body={{ tenantId, blockId: block.id }}
                      label={block.active ? 'Lift' : 'Remove'}
                      tenantId={tenantId}
                    />
                  ) : (
                    <span key="x" className="small muted">
                      platform administrators
                    </span>
                  ),
                ])}
                empty="No networks are blocked."
              />
            </div>
          </Card>
        )}
        <Card title="Danger zone">
          <div className="row spread">
            <p className="muted">
              Incident response: end every member session in this organization. Your own session is
              kept so you can keep working; everyone else signs in again.
            </p>
            <ApiButton
              path="tenants/revokeSessions"
              body={{ tenantId }}
              label="Sign everyone out"
              tone="danger"
              confirm="End every other session in this organization?"
              tenantId={tenantId}
              showResult
            />
          </div>
          <div className="row spread" style={{ marginTop: 12 }}>
            <p className="muted">
              Deleting tombstones this organization and all child tenants, revokes every session,
              and purges data after the retention window. Audit records are kept.
            </p>
            <ApiButton
              path="tenants/setStatus"
              body={{ tenantId, status: 'deleted' }}
              label="Delete organization"
              tone="danger"
              confirm={`Delete ${tenant.name}? This cannot be undone from the console.`}
              redirectTo="/cloud"
              tenantId={tenantId}
            />
          </div>
        </Card>
        <Alert tone="info">
          Suspension, boundaries, and cross-organization trust are platform controls managed from
          the <Link href="/admin">administration panel</Link>, never by an organization on its own.
        </Alert>
        <p className="small muted">
          Console: <code>{base}</code>
        </p>
      </div>
    </>
  );
}
