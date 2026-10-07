import Link from 'next/link';
import { notFound } from 'next/navigation';
import type { ReactNode } from 'react';
import { ApiButton, ApiForm } from '@/components/api-form';
import { GrantClearanceForm, UpdateClearanceForm } from '@/components/clearance-forms';
import { Alert, Badge, Card, KeyValues, PageHeader, Table, Time } from '@/components/ui';
import {
  attempt,
  clearanceAttention,
  clearanceResource,
  compartmentName,
  dueState,
  effectiveStatusLabels,
  featureDisabled,
  historyEntry,
  isLive,
  levelName,
  levelOptions,
  relativeDays,
  statusLabels,
  statusTone,
  valueOf,
} from '@/lib/clearances';
import { can, key, orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

export default async function Clearance({
  params,
}: {
  params: Promise<{ org: string; identityId: string }>;
}) {
  const { org, identityId } = await params;
  const context = await orgPage(org);
  const { iam, auth, tenantId, base, session } = context;
  const resource = clearanceResource(identityId);
  const [clearanceRead, schemeRead, identity, allowed, history, members] = await Promise.all([
    attempt(() => iam.api.clearances.get(auth, { tenantId, identityId })),
    attempt(() => iam.api.clearances.getScheme(auth, { tenantId })),
    tryRead(() => iam.api.identities.get(auth, { tenantId, identityId })),
    can(context, [
      { action: 'iam:clearances:adjudicate', resource },
      { action: 'iam:clearances:suspend', resource },
    ]),
    // The clearance's own events (grant, read-ins, suspensions, ...); iam:audit:read.
    tryRead(() =>
      iam.api.audit.list(auth, {
        tenantId,
        resourceId: identityId,
        action: 'clearance:*',
        limit: 50,
      }),
    ),
    tryRead(() => iam.api.identities.list(auth, { tenantId, limit: 1000 })),
  ]);
  // Authorization comes first, so ACCESS_DENIED does not say whether the person exists; NOT_FOUND does.
  if (!clearanceRead.ok && clearanceRead.code === 'NOT_FOUND') notFound();
  const disabled = featureDisabled(clearanceRead, schemeRead);
  const view = valueOf(clearanceRead) ?? undefined;
  const scheme = valueOf(schemeRead) ?? undefined;
  // Names of levels and compartments come only from reads that need iam:clearances:read.
  const definition = scheme?.definition;
  const name = identity?.name ?? view?.identity.name ?? identityId;
  const self = identityId === session.identity.id;
  const impersonating = Boolean(session.session.impersonatorId);
  const mayAdjudicate =
    allowed[key('iam:clearances:adjudicate', resource)] === true && !impersonating;
  const maySuspend = allowed[key('iam:clearances:suspend', resource)] === true && !impersonating;
  const live = view !== undefined && isLive(view.status);
  const otherScheme =
    view !== undefined && scheme !== undefined && view.schemeTenantId !== scheme.tenantId;
  const guest = identity?.guest !== undefined || view?.identity.guest === true;
  // NDAs: to name the ones behind read-ins, and to offer them when reading someone in.
  const agreements =
    (mayAdjudicate && live && !self) || view?.readIns.some((readIn) => readIn.agreementId)
      ? await tryRead(() => iam.api.agreements.list(auth, { tenantId }))
      : undefined;
  const person = (id: string) =>
    members?.find((member) => member.id === id)?.name ??
    (id === 'identity-deleted' ? 'account deletion' : id);
  const agreementName = (id: string) => agreements?.find((item) => item.id === id)?.name ?? id;
  const now = Date.now();
  const unread = (definition?.compartments ?? []).filter(
    (compartment) => !view?.readIns.some((readIn) => readIn.compartmentId === compartment.id),
  );
  const hidden = (fields: Record<string, string>) =>
    Object.entries(fields).map(([field, value]) => ({
      name: field,
      label: field,
      type: 'hidden' as const,
      defaultValue: value,
    }));
  return (
    <>
      <PageHeader
        title={
          <>
            {name}{' '}
            {view && <Badge tone={statusTone(view.status)}>{statusLabels[view.status]}</Badge>}
            {view && live && view.effectiveStatus !== view.status && (
              <>
                {' '}
                <Badge tone={statusTone(view.effectiveStatus)}>
                  {effectiveStatusLabels[view.effectiveStatus]}
                </Badge>
              </>
            )}
          </>
        }
        description={
          <>
            Security clearance · <Link href={`${base}/clearances`}>all clearances</Link>
          </>
        }
        actions={
          <>
            {identity && identity.kind !== 'agent' && (
              <Link
                className="btn small secondary"
                href={`${base}/members/${encodeURIComponent(identityId)}`}
              >
                Member page
              </Link>
            )}
            {identity?.kind === 'agent' && (
              <Link
                className="btn small secondary"
                href={`${base}/agents/${encodeURIComponent(identityId)}`}
              >
                Agent page
              </Link>
            )}
            {mayAdjudicate && (
              <Link
                className="btn small secondary"
                href={`${base}/classification?explain=${encodeURIComponent(identityId)}#explain`}
              >
                Explain access
              </Link>
            )}
          </>
        }
      />
      {disabled ? (
        <Alert tone="info">
          This deployment does not enable security clearances (the <code>clearances</code> option).
        </Alert>
      ) : (
        <div className="stack">
          {self && (
            <Alert tone="info">
              This is your own clearance: another officer adjudicates it. You can still debrief
              yourself from a compartment.
            </Alert>
          )}
          {impersonating && (
            <Alert tone="warning">
              Clearances cannot be changed while viewing the console as someone else.
            </Alert>
          )}
          {otherScheme && (
            <Alert tone="warning">
              This clearance was issued under another scheme than the one in force, so decisions do
              not count it. Revoke it and grant a new one.
            </Alert>
          )}
          {!clearanceRead.ok ? (
            <Alert tone="warning">
              Reading this clearance requires <code>iam:clearances:read</code>.
            </Alert>
          ) : !view ? (
            <Card title="No clearance">
              <p className="muted">
                {name} holds no clearance: they read only unlabeled resources
                {scheme ? ` under the ${scheme.name} scheme` : ''}.
                {!scheme && ' No classification scheme applies to this organization yet.'}
              </p>
            </Card>
          ) : (
            <div className="grid cols-2">
              <Card title="Clearance">
                <KeyValues
                  items={[
                    [
                      'Level',
                      <span key="l" className="row">
                        <strong>{view.level.name ?? levelName(definition, view.level.id)}</strong>
                        {view.effectiveLevel && view.effectiveLevel !== view.level.id && (
                          <span className="small muted">
                            counts as {levelName(definition, view.effectiveLevel)} (guest ceiling)
                          </span>
                        )}
                      </span>,
                    ],
                    [
                      'Decisions see',
                      <span key="s" className="row" style={{ flexWrap: 'wrap' }}>
                        <Badge tone={statusTone(view.effectiveStatus)}>
                          {effectiveStatusLabels[view.effectiveStatus]}
                        </Badge>
                        {clearanceAttention(view, now)
                          .filter(
                            (item) => item.label !== 'expired' && item.label !== 'not counted',
                          )
                          .map((item) => (
                            <Badge key={item.label} tone={item.tone}>
                              {item.label}
                            </Badge>
                          ))}
                      </span>,
                    ],
                    [
                      'Citizenship',
                      view.citizenship.length ? (
                        view.citizenship.join(', ')
                      ) : (
                        <span key="c" className="muted">
                          none adjudicated
                        </span>
                      ),
                    ],
                    [
                      'Investigation',
                      view.investigation ? (
                        <span key="i">
                          {view.investigation.kind}, completed{' '}
                          <Time value={view.investigation.completedAt} />
                        </span>
                      ) : (
                        '—'
                      ),
                    ],
                    [
                      'Reinvestigation due',
                      view.reinvestigationDue ? (
                        <span key="d" className="row">
                          <Time value={view.reinvestigationDue} />
                          <span className="small muted">
                            {relativeDays(view.reinvestigationDue, now)}
                          </span>
                          {dueState(view.reinvestigationDue, now) === 'overdue' && (
                            <Badge tone="danger">overdue</Badge>
                          )}
                        </span>
                      ) : (
                        '—'
                      ),
                    ],
                    [
                      'Ends',
                      view.expiresAt ? (
                        <span key="e" className="row">
                          <Time value={view.expiresAt} />
                          <span className="small muted">{relativeDays(view.expiresAt, now)}</span>
                        </span>
                      ) : (
                        'never'
                      ),
                    ],
                    [
                      'Granted',
                      <span key="g">
                        <Time value={view.grantedAt} /> by {person(view.grantedBy)}
                      </span>,
                    ],
                    [
                      'Last changed',
                      <span key="u">
                        <Time value={view.updatedAt} /> by {person(view.updatedBy)}
                      </span>,
                    ],
                    ...(view.suspended
                      ? ([
                          [
                            'Suspended',
                            <span key="x" className="stack" style={{ gap: 2 }}>
                              <span>
                                <Time value={view.suspended.at} /> by {person(view.suspended.by)}
                              </span>
                              <span className="small">{view.suspended.reason}</span>
                              {view.suspended.incidentId && (
                                <Link
                                  className="small"
                                  href={`${base}/threats/incidents/${encodeURIComponent(view.suspended.incidentId)}`}
                                >
                                  Incident →
                                </Link>
                              )}
                            </span>,
                          ],
                        ] as [string, ReactNode][])
                      : []),
                    ...(view.revoked
                      ? ([
                          [
                            'Revoked',
                            <span key="v" className="stack" style={{ gap: 2 }}>
                              <span>
                                <Time value={view.revoked.at} /> by {person(view.revoked.by)}
                              </span>
                              <span className="small">{view.revoked.reason}</span>
                            </span>,
                          ],
                        ] as [string, ReactNode][])
                      : []),
                    ...(view.terminated
                      ? ([
                          [
                            'Ended',
                            <span key="t" className="stack" style={{ gap: 2 }}>
                              <span>
                                <Time value={view.terminated.at} /> by {person(view.terminated.by)}
                              </span>
                              <span className="small">{view.terminated.reason}</span>
                            </span>,
                          ],
                        ] as [string, ReactNode][])
                      : []),
                  ]}
                />
              </Card>
              <Card
                title="Read-ins"
                description="Compartments this person is read into. One backed by an NDA counts only while their acceptance of its current version is current."
                flush
              >
                <Table
                  head={['Compartment', 'Since', 'NDA', '']}
                  rows={view.readIns.map((readIn) => [
                    <span key="c" className="stack" style={{ gap: 2 }}>
                      <strong>
                        {readIn.compartmentName ??
                          compartmentName(definition, readIn.compartmentId)}
                      </strong>
                      <code className="small muted">{readIn.compartmentId}</code>
                    </span>,
                    <span key="s" className="small">
                      <Time value={readIn.readInAt} />
                      <br />
                      by {person(readIn.readInBy)}
                    </span>,
                    <span key="n" className="row">
                      {readIn.agreementId ? (
                        <span className="small">{agreementName(readIn.agreementId)}</span>
                      ) : (
                        <span className="small muted">none</span>
                      )}
                      <Badge tone={readIn.current ? 'success' : 'warning'}>
                        {readIn.current ? 'counts' : 'not current'}
                      </Badge>
                    </span>,
                    mayAdjudicate ? (
                      <ApiButton
                        key="d"
                        path="clearances/debrief"
                        body={{ tenantId, identityId, compartmentId: readIn.compartmentId }}
                        label="Debrief"
                        tone="danger"
                        confirm={`Debrief ${name} from ${readIn.compartmentName ?? readIn.compartmentId}? Their access to it ends at once.`}
                        tenantId={tenantId}
                      />
                    ) : (
                      ''
                    ),
                  ])}
                  empty="Not read into any compartment."
                />
                {mayAdjudicate &&
                  !self &&
                  !guest &&
                  !otherScheme &&
                  (view.status === 'active' || view.status === 'interim') &&
                  unread.length > 0 && (
                    <div className="card-body">
                      <ApiForm
                        path="clearances/readIn"
                        tenantId={tenantId}
                        submitLabel="Read in"
                        compact
                        successMessage="Read in."
                        fields={[
                          ...hidden({ tenantId, identityId }),
                          {
                            name: 'compartmentId',
                            label: 'Compartment',
                            type: 'select',
                            required: true,
                            options: unread.map((compartment) => ({
                              value: compartment.id,
                              label: compartment.name,
                            })),
                            help:
                              scheme?.adjudication === 'within-own'
                                ? 'You must be read into it yourself (an owner may bootstrap one nobody holds yet).'
                                : undefined,
                          },
                          ...(agreements && agreements.length
                            ? [
                                {
                                  name: 'agreementId',
                                  label: 'Backed by NDA',
                                  type: 'select' as const,
                                  options: agreements.map((agreement) => ({
                                    value: agreement.id,
                                    label: `${agreement.name} (v${agreement.version})`,
                                  })),
                                  help: 'The read-in counts only while they have accepted its current version.',
                                },
                              ]
                            : []),
                        ]}
                      />
                    </div>
                  )}
              </Card>
            </div>
          )}
          {view && live && !self && !otherScheme && mayAdjudicate && definition && scheme && (
            <Card
              title="Adjudicate"
              description="Change the level, citizenship, investigation and dates. Raising the level, like granting, stays within your own clearance under within-own adjudication. Needs a recent sign-in."
            >
              <UpdateClearanceForm
                tenantId={tenantId}
                view={view}
                levels={levelOptions(definition)}
                interimAllowed={scheme.interimAllowed}
              />
            </Card>
          )}
          {view && live && (maySuspend || mayAdjudicate) && (
            <div className="grid cols-2">
              {view.status === 'suspended'
                ? mayAdjudicate &&
                  !self &&
                  !otherScheme && (
                    <Card
                      title="Reinstate"
                      description="Lifts the suspension: the clearance and its read-ins count again. Any officer but the person themselves, within their own clearance; needs a recent sign-in. The person is emailed."
                    >
                      <ApiForm
                        path="clearances/reinstate"
                        tenantId={tenantId}
                        submitLabel="Reinstate"
                        compact
                        successMessage="Reinstated."
                        fields={[
                          ...hidden({ tenantId, identityId }),
                          {
                            name: 'reason',
                            label: 'Reason',
                            placeholder: 'Investigation closed: no finding',
                          },
                        ]}
                      />
                    </Card>
                  )
                : maySuspend && (
                    <Card
                      title="Suspend"
                      description="Stops the clearance counting at once, for an incident or an investigation; only an officer's reinstatement lifts it. No recent sign-in needed."
                    >
                      <ApiForm
                        path="clearances/suspend"
                        tenantId={tenantId}
                        submitLabel="Suspend"
                        compact
                        successMessage="Suspended."
                        fields={[
                          ...hidden({ tenantId, identityId }),
                          {
                            name: 'reason',
                            label: 'Reason',
                            required: true,
                            placeholder: 'Pending investigation of incident IR-31',
                          },
                          {
                            name: 'incidentId',
                            label: 'Threat incident id',
                            help: 'Links the suspension to an incident on the Threats page.',
                          },
                          {
                            name: 'notifyPerson',
                            label: 'Email the person',
                            type: 'checkbox',
                            defaultValue: true,
                            help: 'Untick for an investigation they must not learn of yet.',
                          },
                        ]}
                      />
                    </Card>
                  )}
              {mayAdjudicate && (
                <Card
                  title="Revoke"
                  description="Ends the clearance for cause and debriefs every compartment. The record stays as history; a new clearance needs a new grant. Needs a recent sign-in."
                >
                  <details>
                    <summary className="small">Revoke this clearance…</summary>
                    <ApiForm
                      path="clearances/revoke"
                      tenantId={tenantId}
                      submitLabel="Revoke clearance"
                      compact
                      successMessage="Revoked."
                      fields={[
                        ...hidden({ tenantId, identityId }),
                        {
                          name: 'reason',
                          label: 'Reason',
                          required: true,
                          placeholder: 'Adjudicated unfavorably (case 2026-114)',
                        },
                        {
                          name: 'notifyPerson',
                          label: 'Email the person',
                          type: 'checkbox',
                          defaultValue: true,
                        },
                      ]}
                    />
                  </details>
                </Card>
              )}
            </div>
          )}
          {clearanceRead.ok &&
            (!view || !live) &&
            !self &&
            mayAdjudicate &&
            definition &&
            scheme &&
            (identity?.status ?? view?.identity.status) === 'active' && (
              <Card
                title={view ? 'Grant a new clearance' : 'Grant a clearance'}
                description={`Under the ${scheme.name} scheme.${guest ? ` Guests hold at most ${scheme.guestCeiling ? levelName(definition, scheme.guestCeiling) : 'nothing: this scheme gives guests no clearance'}.` : ''} Needs a recent sign-in.`}
              >
                <GrantClearanceForm
                  tenantId={tenantId}
                  identityId={identityId}
                  levels={levelOptions(definition)}
                  interimAllowed={scheme.interimAllowed}
                />
              </Card>
            )}
          {!clearanceRead.ok && maySuspend && (
            <Card
              title="Suspend"
              description="Stops the clearance counting at once (for an incident); only an officer's reinstatement lifts it."
            >
              <ApiForm
                path="clearances/suspend"
                tenantId={tenantId}
                submitLabel="Suspend"
                compact
                successMessage="Suspended."
                fields={[
                  ...hidden({ tenantId, identityId }),
                  { name: 'reason', label: 'Reason', required: true },
                  { name: 'incidentId', label: 'Threat incident id' },
                  {
                    name: 'notifyPerson',
                    label: 'Email the person',
                    type: 'checkbox',
                    defaultValue: true,
                  },
                ]}
              />
            </Card>
          )}
          <Card
            title="History"
            description="Grants, changes, read-ins, debriefs, suspensions and reminders from the audit trail, newest first."
            flush
          >
            {history ? (
              <Table
                head={['When', 'What', 'By']}
                rows={history.map((event) => {
                  const entry = historyEntry(event, definition);
                  return [
                    <Time key="w" value={event.timestamp} />,
                    <span key="e" className="stack" style={{ gap: 2 }}>
                      <span>
                        <Badge tone={entry.tone}>{entry.title}</Badge>
                      </span>
                      {entry.details.length > 0 && (
                        <span className="small muted">{entry.details.join(' · ')}</span>
                      )}
                    </span>,
                    event.actorId === 'deployment-operator' ? (
                      <span key="b" className="muted">
                        scheduled job
                      </span>
                    ) : (
                      <span key="b">{person(event.actorId)}</span>
                    ),
                  ];
                })}
                empty="No clearance events yet."
              />
            ) : (
              <div className="empty">
                Requires <code>iam:audit:read</code>.
              </div>
            )}
          </Card>
        </div>
      )}
    </>
  );
}
