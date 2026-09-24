import Link from 'next/link';
import { ApiButton } from '@/components/api-form';
import { DetectionSettingsForm, PlaybookForm, RulesTable } from '@/components/threat-forms';
import { Alert, Badge, Card, KeyValues, PageHeader, Table, Time } from '@/components/ui';
import { can, key, orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';
import {
  actionsSummary,
  durationLabel,
  severityTone,
  subjectTypeLabels,
  triggerSummary,
} from '@/lib/threats';

const settingsResource = { type: 'iam', id: 'threats/settings' };
const playbooksResource = { type: 'iam', id: 'threats/playbooks' };

export default async function ThreatSettings({ params }: { params: Promise<{ org: string }> }) {
  const { org } = await params;
  const page = await orgPage(org);
  const { iam, auth, tenantId, base, session } = page;
  const [rules, settings, playbooks, members, allowed] = await Promise.all([
    tryRead(() => iam.api.threats.rules(auth, { tenantId })),
    tryRead(() => iam.api.threats.getSettings(auth, { tenantId })),
    tryRead(() => iam.api.threats.listPlaybooks(auth, { tenantId })),
    tryRead(() => iam.api.identities.list(auth, { tenantId, limit: 1000 })),
    can(page, [
      { action: 'iam:threats:manage', resource: settingsResource },
      { action: 'iam:threats:manage', resource: playbooksResource },
    ]),
  ]);
  const mayConfigure = allowed[key('iam:threats:manage', settingsResource)] === true;
  const mayManagePlaybooks = allowed[key('iam:threats:manage', playbooksResource)] === true;
  const ruleTitle = (ruleId: string) => rules?.find((rule) => rule.id === ruleId)?.title ?? ruleId;
  const ruleOptions = (rules ?? []).map((rule) => ({ id: rule.id, title: rule.title }));
  const person = (identityId: string) => {
    const member = members?.find((candidate) => candidate.id === identityId);
    return member ? member.name || member.email || member.id : identityId;
  };
  return (
    <>
      <PageHeader
        title="Detection settings"
        description={
          <>
            Tune the detection rules, the networks they trust, and who is told; playbooks respond to
            new detections automatically. Changes require <code>iam:threats:manage</code> and a
            recent sign-in. Back to <Link href={`${base}/threats`}>threats</Link>.
          </>
        }
      />
      {!rules || !settings ? (
        <Alert tone="warning">
          Requires <code>iam:threats:read</code>.
        </Alert>
      ) : (
        <div className="stack">
          {!session.session.client?.ip && (
            <Alert tone="warning">
              This deployment does not record client addresses, so trusted networks, the network
              rules and network blocks have nothing to compare against. The operator enables them by
              setting <code>TRUSTED_PROXY_HOPS</code> behind a reverse proxy they control.
            </Alert>
          )}
          <Card
            title="Detection rules"
            description="A rule that counts trips when its threshold is reached within the window. Empty numbers use the rule's default. Turning a rule off is itself recorded as a detection, so other administrators see it."
            flush
          >
            {mayConfigure ? (
              <RulesTable tenantId={tenantId} rules={rules} />
            ) : (
              <Table
                head={['Rule', 'On', 'Severity', 'Threshold', 'Window']}
                rows={rules.map((rule) => [
                  <span key="r" className="stack" style={{ gap: 2 }}>
                    <strong>{rule.title}</strong>
                    <span className="small muted">{rule.description}</span>
                    <span className="small muted">
                      {rule.category} · about {subjectTypeLabels[rule.subject].toLowerCase()} ·{' '}
                      <code>{rule.technique}</code>
                      {rule.customized && ' · customized'}
                    </span>
                  </span>,
                  <Badge key="o" tone={rule.enabled ? 'success' : 'neutral'}>
                    {rule.enabled ? 'on' : 'off'}
                  </Badge>,
                  <Badge key="s" tone={severityTone(rule.severity)}>
                    {rule.severity}
                  </Badge>,
                  rule.threshold ?? <span className="muted">—</span>,
                  rule.windowMs !== undefined ? (
                    durationLabel(rule.windowMs)
                  ) : (
                    <span key="w" className="muted">
                      —
                    </span>
                  ),
                ])}
              />
            )}
          </Card>
          <Card
            title="Organization settings"
            description={
              settings.configured && settings.updatedAt ? (
                <>
                  Last changed <Time value={settings.updatedAt} />
                  {settings.updatedBy && <> by {person(settings.updatedBy)}</>}.
                </>
              ) : (
                'Everything is at its default.'
              )
            }
          >
            {mayConfigure ? (
              <DetectionSettingsForm tenantId={tenantId} settings={settings} />
            ) : (
              <KeyValues
                items={[
                  [
                    'Trusted networks',
                    settings.trustedNetworks.length ? (
                      <code key="n">{settings.trustedNetworks.join(', ')}</code>
                    ) : (
                      'none'
                    ),
                  ],
                  ['Dormant after', `${settings.dormantDays} days`],
                  ['Risk half-life', `${settings.riskHalfLifeHours} hours`],
                  [
                    'Notify',
                    [...(settings.notify.owners ? ['owners'] : []), ...settings.notify.emails].join(
                      ', ',
                    ) || 'nobody',
                  ],
                  ['Automatic containments per run', String(settings.maxAutomaticContainments)],
                ]}
              />
            )}
          </Card>
          <Card
            title="Playbooks"
            description="When a new detection matches a playbook's trigger, its actions run in order under the threat-detection actor. Automatic actions never contain owners or root administrators, and stop after the containment limit per run."
            flush
          >
            {playbooks ? (
              <Table
                head={['Playbook', 'When', 'Then', 'Runs', '']}
                rows={playbooks.map((playbook) => [
                  <span key="n" className="stack" style={{ gap: 2 }}>
                    <span className="row">
                      <strong>{playbook.name}</strong>
                      <Badge tone={playbook.enabled ? 'success' : 'neutral'}>
                        {playbook.enabled ? 'enabled' : 'disabled'}
                      </Badge>
                    </span>
                    {playbook.description && (
                      <span className="small muted">{playbook.description}</span>
                    )}
                  </span>,
                  <span key="w" className="small">
                    {triggerSummary(playbook.trigger, ruleTitle)}
                  </span>,
                  <span key="t" className="small">
                    {actionsSummary(playbook.actions)}
                  </span>,
                  <span key="r" className="stack small" style={{ gap: 2 }}>
                    <span>{playbook.runs}</span>
                    {playbook.lastRunAt && (
                      <span className="muted">
                        last <Time value={playbook.lastRunAt} />
                      </span>
                    )}
                  </span>,
                  mayManagePlaybooks ? (
                    <span key="a" className="row">
                      <ApiButton
                        path="threats/updatePlaybook"
                        body={{ tenantId, playbookId: playbook.id, enabled: !playbook.enabled }}
                        label={playbook.enabled ? 'Disable' : 'Enable'}
                        tenantId={tenantId}
                      />
                      <ApiButton
                        path="threats/deletePlaybook"
                        body={{ tenantId, playbookId: playbook.id }}
                        label="Delete"
                        tone="danger"
                        confirm={`Delete the playbook ${playbook.name}? Responses it already took stay on their incidents.`}
                        tenantId={tenantId}
                      />
                    </span>
                  ) : (
                    ''
                  ),
                ])}
                empty="No playbooks: detections wait for a person."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:threats:read</code> on <code>iam/threats/playbooks</code>.
              </div>
            )}
            {mayManagePlaybooks && (
              <div className="card-body stack">
                {(playbooks ?? []).map((playbook) => (
                  <details key={playbook.id}>
                    <summary>Edit {playbook.name}</summary>
                    <PlaybookForm tenantId={tenantId} rules={ruleOptions} playbook={playbook} />
                  </details>
                ))}
                <details>
                  <summary>New playbook</summary>
                  <PlaybookForm tenantId={tenantId} rules={ruleOptions} />
                </details>
              </div>
            )}
          </Card>
        </div>
      )}
    </>
  );
}
