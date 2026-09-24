import { ApiButton, ApiForm } from '@/components/api-form';
import { EvidenceExportButton } from '@/components/evidence-export';
import { Alert, Badge, Card, PageHeader, Stat, Table, Time, type Tone } from '@/components/ui';
import { orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const tone = (status?: string): Tone =>
  status === 'pass'
    ? 'success'
    : status === 'fail'
      ? 'danger'
      : status === 'warn'
        ? 'warning'
        : 'neutral';

export default async function Compliance({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const { iam, auth, tenantId } = await orgPage(org);
  const [catalog, controls, status, exceptions, runs] = await Promise.all([
    tryRead(() => iam.api.compliance.catalog(auth, { tenantId })),
    tryRead(() => iam.api.compliance.listControls(auth, { tenantId })),
    tryRead(() => iam.api.compliance.status(auth, { tenantId })),
    tryRead(() => iam.api.compliance.listExceptions(auth, { tenantId })),
    tryRead(() => iam.api.compliance.listRuns(auth, { tenantId, limit: 10 })),
  ]);
  const lastRun = runs?.[0];
  const adopted = new Set((status ?? []).map((item) => item.framework.id));
  return (
    <>
      <PageHeader
        title="Compliance"
        description="Automated checks over who can sign in and how, stale and privileged access, reviews, leavers and the audit log, mapped to SOC 2, ISO 27001, NIST 800-53 and GDPR requirements. Evaluations run daily; exceptions accept a finding for a while; evidence packs are signed for your auditors."
        actions={
          controls && controls.length > 0 ? (
            <ApiButton
              path="compliance/evaluate"
              body={{ tenantId }}
              label="Evaluate now"
              tenantId={tenantId}
            />
          ) : undefined
        }
      />
      {!catalog || !controls ? (
        <Alert tone="warning">
          Requires <code>iam:compliance:read</code>.
        </Alert>
      ) : (
        <div className="stack">
          {lastRun && (
            <div className="tiles">
              <Stat label="Passing" value={lastRun.counts.pass} />
              <Stat label="Failing" value={lastRun.counts.fail} />
              <Stat label="Warnings" value={lastRun.counts.warn} />
              <Stat label="Last evaluated" value={<Time value={lastRun.evaluatedAt} />} />
            </div>
          )}

          {(status ?? []).map((framework) => (
            <Card
              key={framework.framework.id}
              title={
                <span className="row">
                  {framework.framework.name}{' '}
                  <Badge tone={framework.passing === framework.total ? 'success' : 'warning'}>
                    {framework.passing}/{framework.total} requirements pass
                  </Badge>
                  {framework.covered < framework.total && (
                    <Badge>{framework.total - framework.covered} without a control</Badge>
                  )}
                </span>
              }
              actions={
                <EvidenceExportButton tenantId={tenantId} framework={framework.framework.id} />
              }
              flush
            >
              <Table
                head={['Requirement', 'Status', 'Controls']}
                rows={framework.requirements.map((requirement) => [
                  <span key="r">
                    <strong>{requirement.id}</strong> {requirement.title}
                  </span>,
                  <Badge key="s" tone={tone(requirement.status)}>
                    {requirement.status}
                  </Badge>,
                  <span key="c" className="small">
                    {requirement.controls
                      .map(
                        (control) =>
                          `${control.name} (${
                            !control.enabled
                              ? 'disabled'
                              : control.stale
                                ? 'stale'
                                : (control.status ?? 'not evaluated')
                          })`,
                      )
                      .join(' · ') || '—'}
                  </span>,
                ])}
              />
            </Card>
          ))}

          <Card
            title="Frameworks"
            description="Adopting a framework adds a control for each check its requirements use; controls are shared between frameworks."
          >
            <div className="row">
              {catalog.frameworks.map((framework) =>
                adopted.has(framework.id) ? (
                  <Badge key={framework.id} tone="success">
                    {framework.name}
                  </Badge>
                ) : (
                  <ApiButton
                    key={framework.id}
                    path="compliance/adoptFramework"
                    body={{ tenantId, framework: framework.id }}
                    label={`Adopt ${framework.name}`}
                    tenantId={tenantId}
                  />
                ),
              )}
            </div>
          </Card>

          <Card title="Controls" flush>
            <Table
              head={['Control', 'Status', 'Result', 'Mappings', '']}
              rows={controls.map((control) => [
                <span key="n">
                  <strong>{control.name}</strong> <code className="small">{control.key}</code>
                  {!control.enabled && (
                    <>
                      {' '}
                      <Badge>disabled</Badge>
                    </>
                  )}
                  {Object.keys(control.params).length > 0 && (
                    <>
                      <br />
                      <span className="small muted">
                        {Object.entries(control.params)
                          .map(([name, value]) => `${name} ${value}`)
                          .join(', ')}
                      </span>
                    </>
                  )}
                </span>,
                <span key="s" className="row">
                  <Badge tone={tone(control.latest?.status)}>
                    {control.latest?.status ?? 'not evaluated'}
                  </Badge>
                  {control.latest?.stale && <Badge tone="warning">stale</Badge>}
                </span>,
                <span key="r" className="small">
                  {control.latest ? (
                    <details>
                      <summary>
                        {control.latest.summary}
                        {control.latest.excepted ? ` · ${control.latest.excepted} excepted` : ''}
                      </summary>
                      <ul>
                        {control.latest.findings.map((finding, index) => (
                          <li key={`${index}:${finding.subject}`}>
                            {finding.name && <strong>{finding.name}: </strong>}
                            {finding.detail} <code className="small">{finding.subject}</code>
                            {finding.excepted && (
                              <>
                                {' '}
                                <Badge>excepted</Badge>
                              </>
                            )}
                          </li>
                        ))}
                      </ul>
                      {control.latest.findingsTotal > control.latest.findings.length && (
                        <span className="muted">
                          …and {control.latest.findingsTotal - control.latest.findings.length} more
                        </span>
                      )}
                    </details>
                  ) : (
                    '—'
                  )}
                </span>,
                <span key="m" className="small">
                  {control.mappings.join(', ')}
                </span>,
                <ApiButton
                  key="x"
                  path="compliance/updateControl"
                  body={{ tenantId, controlId: control.id, enabled: !control.enabled }}
                  label={control.enabled ? 'Disable' : 'Enable'}
                  tenantId={tenantId}
                />,
              ])}
              empty="No controls yet: adopt a framework above, or add one below."
            />
          </Card>

          <Card title="Add a control">
            <ApiForm
              path="compliance/createControl"
              tenantId={tenantId}
              submitLabel="Add control"
              resetOnSuccess
              fields={[
                { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                {
                  name: 'checkId',
                  label: 'Check',
                  type: 'select',
                  required: true,
                  options: catalog.checks.map((check) => ({ value: check.id, label: check.title })),
                },
                { name: 'key', label: 'Key', required: true, placeholder: 'inactive-30-days' },
                { name: 'name', label: 'Name', required: true },
                {
                  name: 'params',
                  label: 'Parameters (JSON; empty = defaults)',
                  type: 'json',
                  rows: 2,
                  placeholder: '{ "days": 30 }',
                },
                {
                  name: 'mappings',
                  label: 'Requirements it evidences',
                  type: 'list',
                  placeholder: 'soc2:CC6.2, internal:POL-7',
                },
              ]}
            />
          </Card>

          <Card
            title="Exceptions"
            description="An accepted finding no longer fails its control until the exception expires (at most a year). A second person approves each exception; nobody excepts a finding about themselves."
            flush
          >
            <Table
              head={['Control', 'Subject', 'Reason', 'Until', '']}
              rows={(exceptions ?? []).map((exception) => [
                <code key="c">{exception.controlKey}</code>,
                <code key="s" className="small">
                  {exception.subject}
                </code>,
                <span key="r" className="small">
                  {exception.reason}
                </span>,
                <span key="u">
                  <Time value={exception.expiresAt} />{' '}
                  {exception.status === 'approved' ? (
                    !exception.active && <Badge>expired</Badge>
                  ) : (
                    <Badge tone={exception.status === 'pending' ? 'warning' : 'neutral'}>
                      {exception.status}
                    </Badge>
                  )}
                </span>,
                exception.status === 'revoked' ? (
                  <span key="x" />
                ) : (
                  <span key="x" className="row">
                    {exception.status === 'pending' && (
                      <ApiButton
                        path="compliance/approveException"
                        body={{ tenantId, exceptionId: exception.id }}
                        label="Approve"
                        tenantId={tenantId}
                      />
                    )}
                    <ApiButton
                      path="compliance/revokeException"
                      body={{ tenantId, exceptionId: exception.id }}
                      label={exception.status === 'pending' ? 'Withdraw' : 'Revoke'}
                      tone="danger"
                      tenantId={tenantId}
                    />
                  </span>
                ),
              ])}
              empty="No exceptions."
            />
            <div className="card-body">
              <ApiForm
                path="compliance/createException"
                tenantId={tenantId}
                submitLabel="Add exception"
                resetOnSuccess
                fields={[
                  { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                  {
                    name: 'controlKey',
                    label: 'Control',
                    type: 'select',
                    required: true,
                    options: controls.map((control) => ({
                      value: control.key,
                      label: control.name,
                    })),
                  },
                  {
                    name: 'subject',
                    label: 'Finding subject',
                    required: true,
                    placeholder: 'identity:usr_…',
                  },
                  { name: 'reason', label: 'Reason', required: true },
                  { name: 'expiresAt', label: 'Until', type: 'datetime', required: true },
                ]}
              />
            </div>
          </Card>
          <div className="row">
            <EvidenceExportButton tenantId={tenantId} label="Download evidence for every control" />
          </div>
        </div>
      )}
    </>
  );
}
