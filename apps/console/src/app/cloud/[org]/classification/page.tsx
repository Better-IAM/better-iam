import Link from 'next/link';
import { ApiForm } from '@/components/api-form';
import {
  DefaultLabelForm,
  ExplainTool,
  ResourceLabelForm,
  SchemeDefinitionForms,
  SchemeSettingsForm,
} from '@/components/clearance-forms';
import { Alert, Badge, Card, KeyValues, PageHeader, Table, Time } from '@/components/ui';
import {
  adjudicationLabels,
  anyClearanceResource,
  anyLabelResource,
  attempt,
  featureDisabled,
  labelFilterQuery,
  labelFilters,
  labelMarking,
  labelResource,
  levelName,
  levelOptions,
  levelsByRank,
  schemeResource,
  valueOf,
  type IamResource,
  type LabelFilterParams,
} from '@/lib/clearances';
import { batches } from '@/lib/guests';
import { can, key, orgPage } from '@/lib/org';
import { tryRead } from '@/lib/session';

const pageSize = 50;

export default async function Classification({
  params,
  searchParams,
}: {
  params: Promise<{ org: string }>;
  searchParams: Promise<
    LabelFilterParams & { lookupType?: string; lookupId?: string; explain?: string }
  >;
}) {
  const { org } = await params;
  const query = await searchParams;
  const context = await orgPage(org);
  const { iam, auth, tenantId, base, session } = context;
  const impersonating = Boolean(session.session.impersonatorId);
  const [schemeRead, templatesRead, allowed] = await Promise.all([
    attempt(() => iam.api.clearances.getScheme(auth, { tenantId })),
    attempt(() => iam.api.clearances.templates(auth)),
    can(context, [
      { action: 'iam:classifications:manage', resource: schemeResource },
      { action: 'iam:classifications:label', resource: anyLabelResource },
      { action: 'iam:clearances:adjudicate', resource: anyClearanceResource },
    ]),
  ]);
  const disabled = featureDisabled(schemeRead, templatesRead);
  const scheme = valueOf(schemeRead) ?? undefined;
  // The definition names compartments: it is read with iam:clearances:read and passed on only from here.
  const definition = scheme?.definition;
  const mayManage =
    allowed[key('iam:classifications:manage', schemeResource)] === true && !impersonating;
  const mayLabel =
    allowed[key('iam:classifications:label', anyLabelResource)] === true && !impersonating;
  const mayExplain = allowed[key('iam:clearances:adjudicate', anyClearanceResource)] === true;
  const { filters, page } = labelFilters(
    query,
    definition?.levels.map((level) => level.id),
  );
  const lookupType = query.lookupType?.trim();
  const lookupId = query.lookupId?.trim();
  const [labelsRead, lookup, people] = await Promise.all([
    scheme
      ? attempt(() =>
          iam.api.clearances.listLabels(auth, {
            tenantId,
            ...filters,
            limit: pageSize,
            offset: (page - 1) * pageSize,
          }),
        )
      : undefined,
    scheme && lookupType && lookupId
      ? attempt(() =>
          iam.api.clearances.getLabel(auth, { tenantId, type: lookupType, id: lookupId }),
        )
      : undefined,
    mayExplain
      ? tryRead(() => iam.api.identities.list(auth, { tenantId, limit: 1000 }))
      : undefined,
  ]);
  const labels = labelsRead ? valueOf(labelsRead) : undefined;
  // Raising and declassifying are authorized per resource; check each listed label (advisory).
  const rowResource = (type: string, id: string): IamResource =>
    labelResource(type, id) ?? anyLabelResource;
  const rowChecks = impersonating
    ? []
    : (labels?.labels ?? []).flatMap((item) => [
        { action: 'iam:classifications:label', resource: rowResource(item.type, item.id) },
        { action: 'iam:classifications:declassify', resource: rowResource(item.type, item.id) },
      ]);
  const rowAllowed = Object.assign(
    {},
    ...(await Promise.all(batches(rowChecks).map((batch) => can(context, batch)))),
  ) as Record<string, boolean>;
  const pages = labels ? Math.max(1, Math.ceil(labels.total / pageSize)) : 1;
  const href = (target: number) => `${base}/classification${labelFilterQuery(filters, target)}`;
  const filtering = Object.keys(filters).length > 0;
  const person = (id: string) => people?.find((member) => member.id === id)?.name ?? id;
  const peopleOptions = (people ?? [])
    .filter((member) => member.status === 'active')
    .map((member) => ({
      value: member.id,
      label: `${member.name}${member.email ? ` (${member.email})` : ''}${member.kind === 'user' ? '' : ` · ${member.kind}`}`,
    }));
  const templates = valueOf(templatesRead) ?? [];
  return (
    <>
      <PageHeader
        title="Classification"
        description="The classification scheme (ordered levels, compartments, and the NOFORN and REL TO dissemination controls) and the labels IAM holds for resources. A labeled resource is read only by sessions whose every party holds a clearance that dominates the label: no read up, whatever roles and policies allow. Labels only rise; lowering one is a declassification."
        actions={
          <Link className="btn small secondary" href={`${base}/clearances`}>
            Clearances
          </Link>
        }
      />
      {disabled ? (
        <Alert tone="info">
          This deployment does not enable security clearances. The operator turns them on with the{' '}
          <code>clearances</code> option.
        </Alert>
      ) : !schemeRead.ok ? (
        <Alert tone="warning">
          Reading the classification scheme requires <code>iam:clearances:read</code>.
        </Alert>
      ) : !scheme ? (
        <div className="stack">
          <Alert tone="info">
            No classification scheme applies to this organization yet, so nothing is labeled or
            enforced. A scheme applies to this organization and every project below it.
          </Alert>
          {mayManage ? (
            <div className="grid cols-2">
              <Card
                title="Start from a template"
                description="Levels, owner countries and caveats from a built-in scheme; add your own compartments afterwards. Needs iam:classifications:manage and a recent sign-in."
              >
                <ApiForm
                  path="clearances/defineScheme"
                  tenantId={tenantId}
                  submitLabel="Define scheme"
                  fields={[
                    { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                    {
                      name: 'name',
                      label: 'Name',
                      required: true,
                      placeholder: 'Program classification',
                    },
                    {
                      name: 'template',
                      label: 'Template',
                      type: 'select',
                      required: true,
                      options: templates.map((template) => ({
                        value: template.id,
                        label: `${template.name}: ${levelsByRank(template.definition)
                          .map((level) => level.name)
                          .join(' < ')}`,
                      })),
                    },
                    {
                      name: 'requireLabels',
                      label: 'Types that must carry a label',
                      type: 'list',
                      placeholder: 'document, dataset',
                      help: 'Comma-separated; * for every application type. Unlabeled resources of these types are refused to everyone.',
                    },
                    {
                      name: 'adjudication',
                      label: 'Adjudication',
                      type: 'select',
                      required: true,
                      defaultValue: 'within-own',
                      options: (['within-own', 'unrestricted'] as const).map((mode) => ({
                        value: mode,
                        label: adjudicationLabels[mode],
                      })),
                    },
                    {
                      name: 'interimAllowed',
                      label: 'Count interim clearances',
                      type: 'checkbox',
                    },
                  ]}
                />
              </Card>
              <Card
                title="Define your own"
                description="Two to twenty levels with ranks rising from 0 (the public level), compartments with opaque ids, owner countries (ISO alpha-3) and the caveats labels may carry."
              >
                <ApiForm
                  path="clearances/defineScheme"
                  tenantId={tenantId}
                  submitLabel="Define scheme"
                  fields={[
                    { name: 'tenantId', label: 'Tenant', type: 'hidden', defaultValue: tenantId },
                    { name: 'name', label: 'Name', required: true },
                    {
                      name: 'definition',
                      label: 'Definition',
                      type: 'json',
                      required: true,
                      rows: 12,
                      defaultValue: JSON.stringify(
                        {
                          levels: [
                            { id: 'public', name: 'Public', rank: 0 },
                            { id: 'internal', name: 'Internal', rank: 1 },
                            { id: 'restricted', name: 'Restricted', rank: 2 },
                          ],
                          compartments: [],
                          ownerCountries: [],
                          caveats: [],
                        },
                        null,
                        2,
                      ),
                    },
                  ]}
                />
              </Card>
            </div>
          ) : (
            <p className="small muted">
              Defining one needs <code>iam:classifications:manage</code>.
            </p>
          )}
        </div>
      ) : (
        <div className="stack">
          {scheme.inherited && (
            <Alert tone="info">
              The scheme in force here is defined by a parent organization (
              <code>{scheme.tenantId}</code>); it is changed there.
            </Alert>
          )}
          <div className="grid cols-2">
            <Card
              title={scheme.name}
              description={`Version ${scheme.version}, last changed ${new Date(scheme.updatedAt).toISOString().slice(0, 10)}.`}
            >
              <KeyValues
                items={[
                  [
                    'Levels',
                    <span key="l">
                      {levelsByRank(scheme.definition)
                        .map(
                          (level) =>
                            `${level.name}${level.abbreviation ? ` (${level.abbreviation})` : ''}`,
                        )
                        .join(' < ')}
                    </span>,
                  ],
                  [
                    'Owner countries',
                    scheme.definition.ownerCountries.length
                      ? scheme.definition.ownerCountries.join(', ')
                      : '—',
                  ],
                  [
                    'Caveats',
                    scheme.definition.caveats.length ? scheme.definition.caveats.join(', ') : '—',
                  ],
                  [
                    'Must carry a label',
                    scheme.requireLabels.length ? (
                      <code key="r">{scheme.requireLabels.join(', ')}</code>
                    ) : (
                      <span key="r" className="muted">
                        nothing: unlabeled resources are unclassified
                      </span>
                    ),
                  ],
                  [
                    'Default label',
                    scheme.defaultLabel ? (
                      <code key="d">{labelMarking(scheme.defaultLabel, scheme.definition)}</code>
                    ) : (
                      <span key="d" className="muted">
                        none: unlabeled required types are refused
                      </span>
                    ),
                  ],
                  [
                    'Guests',
                    scheme.guestCeiling
                      ? `count at most as ${levelName(scheme.definition, scheme.guestCeiling)}`
                      : 'hold no clearance',
                  ],
                  ['Interim clearances', scheme.interimAllowed ? 'count' : 'do not count'],
                  ['Adjudication', adjudicationLabels[scheme.adjudication]],
                  [
                    'Also reminded',
                    scheme.notify?.emails.length ? scheme.notify.emails.join(', ') : '—',
                  ],
                ]}
              />
            </Card>
            <Card
              title="Compartments"
              description="Need-to-know control systems. Readers of a label with compartments must be read into every one. Names are shown only to holders of iam:clearances:read; audit events and labels carry the ids."
              flush
            >
              <Table
                head={['Name', 'Id']}
                rows={scheme.definition.compartments.map((compartment) => [
                  <strong key="n">{compartment.name}</strong>,
                  <code key="i" className="small">
                    {compartment.id}
                  </code>,
                ])}
                empty="No compartments."
              />
            </Card>
          </div>
          {mayManage && !scheme.inherited && (
            <>
              <Card
                title="Settings"
                description="Changes take effect at the next decision. Needs iam:classifications:manage and a recent sign-in."
              >
                <SchemeSettingsForm tenantId={tenantId} scheme={scheme} />
              </Card>
              <div className="grid cols-2">
                <Card
                  title="Default label"
                  description="Given to unlabeled resources of the types that must carry a label, instead of refusing them."
                >
                  <DefaultLabelForm tenantId={tenantId} scheme={scheme} />
                </Card>
                <Card
                  title="Levels and compartments"
                  description="New levels go above the top one. Levels and compartments in use stay."
                >
                  <SchemeDefinitionForms tenantId={tenantId} scheme={scheme} />
                </Card>
              </div>
            </>
          )}
          <Card
            title="Labels"
            description="Labels IAM holds for resources of this organization. A label outlives its resource, so deleting and recreating a resource never declassifies it; one passed down to managed children applies to every descendant."
            flush
          >
            <form method="get" className="row" style={{ padding: '0 16px 12px' }}>
              <input
                className="input"
                name="type"
                defaultValue={filters.type ?? ''}
                placeholder="Resource type"
                aria-label="Resource type"
                style={{ width: 'auto' }}
              />
              <select
                className="select"
                name="level"
                defaultValue={filters.level ?? ''}
                aria-label="Level"
                style={{ width: 'auto' }}
              >
                <option value="">Any level</option>
                {levelOptions(scheme.definition).map((level) => (
                  <option key={level.value} value={level.value}>
                    {level.label}
                  </option>
                ))}
              </select>
              <button className="btn small secondary">Filter</button>
              {filtering && (
                <Link className="btn small ghost" href={`${base}/classification`}>
                  clear
                </Link>
              )}
            </form>
            {labels ? (
              <Table
                head={['Resource', 'Label', 'Labeled', '']}
                rows={labels.labels.map((item) => {
                  const resource = rowResource(item.type, item.id);
                  const mayRaise = rowAllowed[key('iam:classifications:label', resource)] === true;
                  const mayDeclassify =
                    rowAllowed[key('iam:classifications:declassify', resource)] === true;
                  const initial = {
                    type: item.type,
                    id: item.id,
                    label: item.label,
                    inheritToChildren: item.inheritToChildren,
                  };
                  return [
                    <span key="r" className="stack" style={{ gap: 2 }}>
                      <code>
                        {item.type}/{item.id}
                      </code>
                      {item.inheritToChildren && (
                        <span className="small muted">passed down to managed children</span>
                      )}
                    </span>,
                    <Badge key="l" tone="accent">
                      {labelMarking(item.label, scheme.definition)}
                    </Badge>,
                    <span key="b" className="small">
                      <Time value={item.labeledAt} />
                      <br />
                      by {person(item.labeledBy)} · v{item.version}
                    </span>,
                    <span key="a" className="stack" style={{ gap: 4 }}>
                      {mayRaise && (
                        <details>
                          <summary className="small">Raise</summary>
                          <ResourceLabelForm
                            tenantId={tenantId}
                            mode="label"
                            definition={scheme.definition}
                            initial={initial}
                          />
                        </details>
                      )}
                      {mayDeclassify && (
                        <details>
                          <summary className="small">Declassify</summary>
                          <ResourceLabelForm
                            tenantId={tenantId}
                            mode="declassify"
                            definition={scheme.definition}
                            initial={initial}
                          />
                        </details>
                      )}
                    </span>,
                  ];
                })}
                empty={
                  filtering ? 'No label matches these filters.' : 'No resource is labeled yet.'
                }
              />
            ) : (
              <div className="empty">
                Requires <code>iam:clearances:read</code>.
              </div>
            )}
            {labels && pages > 1 && (
              <div className="card-body row spread">
                <span className="small muted">
                  Page {page} of {pages} · {labels.total} labels
                </span>
                <span className="row">
                  {page > 1 && (
                    <Link className="btn small secondary" href={href(page - 1)}>
                      Previous
                    </Link>
                  )}
                  {page < pages && (
                    <Link className="btn small secondary" href={href(page + 1)}>
                      Next
                    </Link>
                  )}
                </span>
              </div>
            )}
          </Card>
          <div className="grid cols-2">
            {mayLabel && (
              <Card
                title="Label a resource"
                description="Raises a resource's label, or labels it for the first time; it need not exist yet. Lowering any part is a declassification. Needs iam:classifications:label."
              >
                <ResourceLabelForm
                  tenantId={tenantId}
                  mode="label"
                  definition={scheme.definition}
                />
              </Card>
            )}
            <Card
              title="Look up a resource"
              description="Its own label and what it inherits from managed parents. Labels an application's resolver adds are not shown here; Explain applies them."
            >
              <form method="get" className="form">
                <div className="grid cols-2">
                  <div className="field">
                    <label htmlFor="lookup-type">Resource type</label>
                    <input
                      id="lookup-type"
                      className="input"
                      name="lookupType"
                      defaultValue={lookupType ?? ''}
                      required
                    />
                  </div>
                  <div className="field">
                    <label htmlFor="lookup-id">Resource id</label>
                    <input
                      id="lookup-id"
                      className="input"
                      name="lookupId"
                      defaultValue={lookupId ?? ''}
                      required
                    />
                  </div>
                </div>
                <div className="form-actions">
                  <button className="btn small secondary">Look up</button>
                </div>
              </form>
              {lookup &&
                (lookup.ok ? (
                  <KeyValues
                    items={[
                      [
                        'Own label',
                        lookup.value.label ? (
                          <code key="o">
                            {labelMarking(lookup.value.label.label, scheme.definition)}
                          </code>
                        ) : (
                          <span key="o" className="muted">
                            none
                          </span>
                        ),
                      ],
                      [
                        'Inherited',
                        lookup.value.inherited ? (
                          <code key="i">
                            {labelMarking(lookup.value.inherited, scheme.definition)}
                          </code>
                        ) : (
                          <span key="i" className="muted">
                            nothing
                          </span>
                        ),
                      ],
                    ]}
                  />
                ) : (
                  <Alert tone="warning">
                    <strong>{lookup.code}</strong>
                  </Alert>
                ))}
            </Card>
          </div>
          {mayExplain && (
            <section id="explain">
              <Card
                title="Explain"
                description="For investigations: whether a person (with every agent that could act for them) may read a resource, which dimension fails, and each party's clearance. Decisions only ever say CLEARANCE_REQUIRED. Needs iam:clearances:adjudicate."
              >
                <ExplainTool
                  tenantId={tenantId}
                  people={peopleOptions}
                  definition={scheme.definition}
                  initialIdentityId={query.explain}
                />
              </Card>
            </section>
          )}
        </div>
      )}
    </>
  );
}
