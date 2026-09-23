/**
 * Playground scenarios. Context keys match what the server derives in `packages/server/src/decisions.ts`:
 * `principal.id`, `principal.mfa`, `principal.groups`, `principal.roles`, `principal.{attribute}`,
 * `request.time`, `request.sourceIp`, `resource.{attribute}`, `resource.relations`, and so on.
 */
export interface Scenario {
  id: string;
  title: string;
  summary: string;
  grants: unknown[];
  boundaries: unknown[];
  action: string;
  resource: string;
  context: Record<string, unknown>;
}

export const scenarios: Scenario[] = [
  {
    id: 'owner',
    title: 'Owners edit their own documents',
    summary:
      'Everyone reads; only the owner writes. `${principal.id}` is substituted literally before matching.',
    grants: [
      {
        version: 1,
        statements: [
          {
            sid: 'ReadAll',
            effect: 'allow',
            actions: ['documents:read'],
            resources: ['document/*'],
          },
          {
            sid: 'EditOwn',
            effect: 'allow',
            actions: ['documents:write'],
            resources: ['document/*'],
            conditions: { StringEquals: { 'resource.ownerId': '${principal.id}' } },
          },
        ],
      },
    ],
    boundaries: [],
    action: 'documents:write',
    resource: 'document/doc_42',
    context: { 'principal.id': 'usr_alice', 'resource.ownerId': 'usr_alice' },
  },
  {
    id: 'deny',
    title: 'Explicit deny wins',
    summary:
      'A broad allow plus a deny for destructive actions without MFA. Any matching deny overrides every allow.',
    grants: [
      {
        version: 1,
        statements: [
          {
            sid: 'ManageProjects',
            effect: 'allow',
            actions: ['projects:*'],
            resources: ['project/*'],
          },
          {
            sid: 'NoDeleteWithoutMfa',
            effect: 'deny',
            actions: ['projects:delete'],
            resources: ['project/*'],
            conditions: { Bool: { 'principal.mfa': false } },
          },
        ],
      },
    ],
    boundaries: [],
    action: 'projects:delete',
    resource: 'project/prj_7',
    context: { 'principal.id': 'usr_bob', 'principal.mfa': false },
  },
  {
    id: 'boundary',
    title: 'Permission boundary',
    summary:
      'Grants form a union; each boundary is an intersection that can only take access away.',
    grants: [
      {
        version: 1,
        statements: [{ sid: 'Everything', effect: 'allow', actions: ['*'], resources: ['*'] }],
      },
    ],
    boundaries: [
      {
        version: 1,
        statements: [
          {
            sid: 'ReadOnlyDocuments',
            effect: 'allow',
            actions: ['documents:read', 'documents:list'],
            resources: ['document/*'],
          },
        ],
      },
    ],
    action: 'documents:write',
    resource: 'document/doc_42',
    context: { 'principal.id': 'usr_contractor' },
  },
  {
    id: 'network',
    title: 'Office network during quarter close',
    summary:
      'IpAddress matches IPv4/IPv6 CIDR blocks; DateAfter/DateBefore compare ISO 8601 timestamps.',
    grants: [
      {
        version: 1,
        statements: [
          {
            sid: 'ApproveFromOffice',
            effect: 'allow',
            actions: ['invoices:approve'],
            resources: ['invoice/*'],
            conditions: {
              IpAddress: { 'request.sourceIp': ['10.0.0.0/8', '2001:db8::/32'] },
              DateAfter: { 'request.time': '2026-09-01T00:00:00Z' },
              DateBefore: { 'request.time': '2026-10-01T00:00:00Z' },
              NumericLessThanEquals: { 'resource.amount': 50000 },
            },
          },
        ],
      },
    ],
    boundaries: [],
    action: 'invoices:approve',
    resource: 'invoice/inv_1009',
    context: {
      'principal.id': 'usr_carol',
      'request.sourceIp': '10.4.2.7',
      'request.time': '2026-09-22T14:30:00Z',
      'resource.amount': 12500,
    },
  },
  {
    id: 'teams',
    title: 'Team workspaces with variables',
    summary:
      'Declared identity attributes become `principal.{name}`; variables inside patterns never widen them.',
    grants: [
      {
        version: 1,
        statements: [
          {
            sid: 'OwnTeamWorkspaces',
            effect: 'allow',
            actions: ['workspaces:read', 'workspaces:deploy'],
            resources: ['workspace/${principal.team}-*'],
          },
        ],
      },
    ],
    boundaries: [],
    action: 'workspaces:deploy',
    resource: 'workspace/payments-api',
    context: { 'principal.id': 'usr_dan', 'principal.team': 'payments' },
  },
  {
    id: 'relations',
    title: 'Sharing and groups',
    summary: 'Relationship tuples appear as `resource.relations`; group ids as `principal.groups`.',
    grants: [
      {
        version: 1,
        statements: [
          {
            sid: 'EditorsEdit',
            effect: 'allow',
            actions: ['files:read', 'files:write'],
            resources: ['file/*'],
            conditions: { ArrayContains: { 'resource.relations': ['editor', 'owner'] } },
          },
          {
            sid: 'OnCallReads',
            effect: 'allow',
            actions: ['files:read'],
            resources: ['file/*'],
            conditions: { ArrayContains: { 'principal.groups': 'grp_oncall' } },
          },
        ],
      },
    ],
    boundaries: [],
    action: 'files:write',
    resource: 'file/fil_3',
    context: {
      'principal.id': 'usr_erin',
      'principal.groups': ['grp_eng'],
      'resource.relations': ['viewer'],
    },
  },
];

/** Keys the server fills in for every decision, shown as insertable hints next to the context editor. */
export const contextKeys: { key: string; example: unknown; note: string }[] = [
  { key: 'principal.id', example: 'usr_alice', note: 'Identity id' },
  { key: 'principal.tenantId', example: 'ten_acme', note: 'Tenant of the session' },
  { key: 'principal.mfa', example: true, note: 'Session completed MFA' },
  { key: 'principal.kind', example: 'user', note: 'user or service' },
  { key: 'principal.owner', example: false, note: 'Tenant owner' },
  { key: 'principal.authMethod', example: 'passkey', note: 'How the session signed in' },
  { key: 'principal.impersonated', example: false, note: 'An administrator is viewing as' },
  { key: 'principal.groups', example: ['grp_eng'], note: 'Live group ids' },
  { key: 'principal.roles', example: ['rol_editor'], note: 'Bound role ids' },
  { key: 'principal.agreements', example: ['Acceptable use'], note: 'Accepted terms' },
  { key: 'request.time', example: '2026-09-22T14:30:00Z', note: 'Evaluation time (ISO 8601)' },
  { key: 'request.sourceIp', example: '203.0.113.9', note: 'Client address' },
  { key: 'resource.tenantId', example: 'ten_acme', note: 'Tenant of the resource' },
  { key: 'resource.relations', example: ['viewer'], note: 'Relations you hold on it' },
  { key: 'resource.parentRelations', example: [], note: 'Relations on its parent' },
];
