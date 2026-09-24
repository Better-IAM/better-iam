/** Shared, browser-safe contracts. No Node.js dependencies belong in this entrypoint. */
export * from './audit.js';
export * from './policy.js';
export * from './storage.js';
export * from './sql.js';
export * from './instrument.js';
export * from './snapshot.js';
export * from './jcs.js';
export * from './delegation-tokens.js';
export * from './shared-signals.js';
export * from './plan.js';
export * from './filter-compilers.js';

export class IamError extends Error {
  constructor(
    public readonly code: string,
    message: string,
    public readonly status = 400,
  ) {
    super(message);
    this.name = 'IamError';
  }
}

export type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
export interface StoredRecord {
  id: string;
  tenantId: string;
  /** Optional database-enforced natural key, unique within collection and tenant. */
  uniqueKey?: string;
  [key: string]: unknown;
}
export interface FindOptions {
  limit?: number;
  offset?: number;
  /**
   * Keyset pagination: only records whose id sorts after this id (code-point order). Unlike a
   * growing `offset`, each page costs the same however deep it is. `offset` applies after it.
   */
  after?: string;
}
/**
 * Orders `findOrdered` results by a numeric top-level field (ties by id, ascending), keeping only
 * records whose field is a number within `[from, to]`. Use it for time and sequence ordered data.
 */
export interface OrderOptions extends Omit<FindOptions, 'after'> {
  field: string;
  direction?: 'asc' | 'desc';
  from?: number;
  to?: number;
}
/** What `IamStore.describe()` reports about a database. */
export interface StoreDescription {
  adapter: string;
  schemaVersion: number | null;
  migrations: { name: string; appliedAt: number }[];
  collections: { name: string; records: number }[];
  /** Adapter settings worth checking in production (journal mode, durability, size, server version). */
  settings: Record<string, string | number | boolean | null>;
}
/** Filters are strict equality against JSON fields. All writes require transaction(). */
export interface IamStore {
  get<T extends StoredRecord = StoredRecord>(
    collection: string,
    id: string,
  ): Promise<T | undefined>;
  find<T extends StoredRecord = StoredRecord>(
    collection: string,
    filter?: Record<string, unknown>,
    options?: FindOptions,
  ): Promise<T[]>;
  /**
   * Optional: `find` ordered and bounded by a numeric field, paged by the database. Call it through
   * `findOrdered()` from this package, which falls back to `find` for stores without it.
   */
  findOrdered?<T extends StoredRecord = StoredRecord>(
    collection: string,
    filter: Record<string, unknown>,
    order: OrderOptions,
  ): Promise<T[]>;
  /** Optional: every collection holding at least one record, sorted (snapshots, diagnostics). */
  collections?(): Promise<string[]>;
  /** Optional: adapter, applied migrations, record counts, and storage settings (`better-iam doctor`). */
  describe?(): Promise<StoreDescription>;
  insert<T extends StoredRecord>(collection: string, record: T): Promise<T>;
  put<T extends StoredRecord>(collection: string, record: T): Promise<T>;
  delete(collection: string, id: string): Promise<void>;
  /** Serializable read/modify/write; nested transactions join the outer transaction. */
  transaction<T>(fn: (tx: IamStore) => Promise<T>): Promise<T>;
  migrate(): Promise<void>;
  close(): Promise<void>;
}

/** Walks a tenant and its ancestors: true only when every one exists and is active. Cycles read as inactive. */
export async function tenantTreeActive(
  store: Pick<IamStore, 'get'>,
  tenantId: string,
): Promise<boolean> {
  const visited = new Set<string>();
  let current: string | null = tenantId;
  while (current) {
    if (visited.has(current)) return false;
    visited.add(current);
    const tenant: Tenant | undefined = await store.get<Tenant>('tenants', current);
    if (!tenant || tenant.status !== 'active') return false;
    current = tenant.parentId;
  }
  return true;
}

export type TenantStatus = 'pending' | 'active' | 'suspended' | 'deleted';
/** How a user session was established. */
export type AuthMethod =
  | 'password'
  | 'passwordless-email'
  | 'passwordless-sms'
  | 'passkey'
  | 'federated'
  /** A session an administrator opened on a member's behalf (`identities.impersonate`); never a sign-in method. */
  | 'impersonation';
/** The sign-in methods a tenant policy can allow or restrict; impersonation is an administrative action, not a sign-in. */
export const authMethods: readonly AuthMethod[] = [
  'password',
  'passwordless-email',
  'passwordless-sms',
  'passkey',
  'federated',
];
/** Per-tenant authentication rules layered under the deployment's configuration; never looser than it. */
export interface TenantAuthPolicy {
  /** Every human sign-in must complete MFA; people without a factor enroll on their next sign-in. */
  requireMfa?: boolean;
  /** Sign-in methods the tenant accepts; unset accepts every method the deployment enables. */
  allowedMethods?: AuthMethod[];
  /** Absolute session lifetime, capped by the deployment's `sessionLifetimeMs`. */
  sessionLifetimeMs?: number;
  /** Idle timeout, capped by the deployment's `sessionIdleTimeoutMs` and by the lifetime. */
  sessionIdleTimeoutMs?: number;
  /** Attempts per rate-limit window for this tenant's authentication flows, never above the deployment's limits. */
  maxAttempts?: number;
  /** Minimum password length for people in this tenant (12 to 128; the deployment minimum is 12). */
  minPasswordLength?: number;
  /** Concurrent user sessions per person (1 to 100); issuing one more ends the oldest. */
  maxSessions?: number;
  /** Lets administrators holding `iam:identities:impersonate` open sessions as members ("view as"); off by default. */
  allowImpersonation?: boolean;
  /** How long a remembered device may skip MFA (0 to 365 days; 0 disables); never longer than the deployment allows. */
  trustedDeviceDays?: number;
  /** Reject reuse of this many most recent passwords, counting the current one (1 to 24). */
  passwordHistory?: number;
  /** Passwords older than this many days stop signing in (PASSWORD_EXPIRED) until reset (1 to 3650). */
  passwordMaxAgeDays?: number;
  /** Character classes (lowercase, uppercase, digits, symbols) a new password must mix (2 to 4). */
  passwordMinClasses?: number;
  /** Reject passwords that contain the person's email local part or a word of their name. */
  passwordRejectPersonalInfo?: boolean;
  /** Email people when a session starts from a client no live session or remembered device of theirs has used; overrides the deployment default. */
  notifyNewSignIn?: boolean;
  /**
   * Networks (IPv4/IPv6 addresses or CIDR blocks) sessions may be issued from and used from; sign-ins and sessions
   * whose recorded client IP falls outside them are refused with IP_NOT_ALLOWED. Needs `http.clientInfo` to record IPs.
   */
  allowedIpRanges?: string[];
  /**
   * Let people without an authenticator satisfy the MFA requirement with a one-time code emailed to their address
   * (`auth.requestMfaCode`); overrides the deployment default. Root administrators always need an authenticator.
   */
  mfaEmailCodes?: boolean;
  /** Owners must complete MFA even when the rest of the tenant need not (`requireMfa` covers everyone). */
  requireMfaForOwners?: boolean;
  /**
   * A user session is usable only from the client IP it was issued from; used elsewhere it is refused with
   * SESSION_NETWORK_MISMATCH (the person signs in again from the new network, the old session keeps working from the
   * old one). Needs recorded client IPs (`http.clientInfo`); sessions or requests without one are not judged.
   */
  bindSessionsToIp?: boolean;
}
/**
 * Floors for just-in-time activation across a tenant (`tenants.setAccessPolicy`): every eligible binding is at least
 * this strict, and a binding may only tighten further. Unset fields leave the binding's own settings in charge.
 */
export interface TenantAccessPolicy {
  /** Caps every binding's `maxActivationMs` (one minute to seven days). */
  maxActivationMs?: number;
  /** Every activation must state a justification. */
  requireJustification?: boolean;
  /** Every activation needs an MFA-verified session. */
  requireMfa?: boolean;
  /** Every activation starts as an approval request. */
  requireApproval?: boolean;
  /** How long a request waits for a decision before it lapses (five minutes to thirty days; one day by default). */
  approvalLifetimeMs?: number;
}
/** Plan limits a platform administrator sets on a tenant; creation past a limit fails with LIMIT_EXCEEDED. */
export interface TenantLimits {
  /** Active and disabled people (deleted tombstones do not count). */
  identities?: number;
  serviceAccounts?: number;
  /** AI agents (identities of kind `agent`, deleted ones excluded). */
  agents?: number;
  groups?: number;
  roles?: number;
  policies?: number;
  /** Registered managed resources. */
  resources?: number;
  webhooks?: number;
}
export interface Tenant extends StoredRecord {
  name: string;
  type: string;
  parentId: string | null;
  status: TenantStatus;
  /** Optional globally unique sign-in alias, like an AWS account alias. */
  slug?: string;
  /**
   * Home region, when the deployment runs in several regions (`regions` option). Unset means the parent's region;
   * sign-in for a tenant homed elsewhere is sent to that region's deployment.
   */
  region?: string;
  boundary?: import('./policy.js').PolicyDocument;
  authPolicy?: TenantAuthPolicy;
  accessPolicy?: TenantAccessPolicy;
  limits?: TenantLimits;
  createdAt: number;
  /** Set when a tenant is tombstoned; purge workers remove data after the retention window. */
  deletedAt?: number;
}
/**
 * The account profile of an AI agent (`Identity.kind === 'agent'`). An agent is a machine account with an accountable
 * person: its credentials work only while its sponsor is an active, unexpired person of the same tenant, so an agent can
 * never outlive the human answerable for it.
 */
export interface AgentProfile {
  /** The person accountable for the agent (an active user of the agent's tenant). */
  sponsorId: string;
  /** The model the agent runs on, such as `claude-opus-5-5`; exposed to policies as principal.agentModel. */
  model?: string;
  /** Who serves the model, such as `anthropic`; exposed to policies as principal.agentProvider. */
  provider?: string;
  /** What the agent is for, shown to people deciding whether to delegate to it. */
  purpose?: string;
  /** Where the agent can be reached or read about (an http(s) URL). */
  url?: string;
  /** Agent protocols it speaks, informational (for example `mcp`, `a2a`). */
  protocols?: string[];
  /** Whether people may delegate their access to the agent (`delegations`); true unless set to false. */
  delegable?: boolean;
  /** The longest delegated session the agent may hold, in seconds (60 to 43200; 3600 when unset). */
  maxDelegatedSessionSeconds?: number;
  /** A ceiling on everything the agent does, in its own right or on someone's behalf. */
  boundary?: import('./policy.js').PolicyDocument;
  /**
   * Services outside Better IAM the agent may present a person's delegation to (`delegations.issueToken`): audience
   * URLs or URNs, `*` matching any characters. Without it the agent cannot obtain delegation tokens.
   */
  tokenAudiences?: string[];
  /** Set while the agent is suspended: who suspended it, when, and why (`agents.suspend`). */
  suspended?: { by: string; at: number; reason?: string };
}
export interface Identity extends StoredRecord {
  /** `user` (a person), `service` (a service account) or `agent` (an AI agent with a sponsor, see `agent`). */
  kind: 'user' | 'service' | 'agent';
  /** Agents only: the agent's profile, sponsor and ceiling. */
  agent?: AgentProfile;
  email?: string;
  name: string;
  description?: string;
  /** Typed attributes declared by `permissions.identityAttributes`, exposed to policies as principal.{name}. */
  attributes?: Record<string, Json>;
  /** deleted identities are tombstones: no credentials, factors, bindings, or email, kept so audit records stay resolvable. */
  status: 'active' | 'disabled' | 'deleted';
  emailVerified: boolean;
  rootAdmin: boolean;
  owner: boolean;
  createdAt: number;
  passwordHash?: string;
  /** When the current password was set; drives `passwordMaxAgeDays` (identities without it use `createdAt`). */
  passwordChangedAt?: number;
  /**
   * Set by self sign-up: the password was chosen before anyone proved control of the email address. The first emailed
   * sign-in removes such a password (and ends the account's sessions); verifying the address or resetting the
   * password clears the flag.
   */
  unprovenPassword?: boolean;
  phone?: string;
  phoneVerified?: boolean;
  /**
   * Scheduled deactivation (epoch milliseconds) for contractors and temporary service accounts: past this time the
   * identity's credentials are refused and the retention worker disables it (`identity:expire`).
   */
  expiresAt?: number;
  /** The person's manager within the tenant: approvals may route to them, and offboarding hands reports to a successor. */
  managerId?: string;
  deletedAt?: number;
  deletedEmail?: string;
}
/** Client details recorded on a session for device lists; never used for authorization. */
export interface SessionClientInfo {
  ip?: string;
  userAgent?: string;
  /** A short free-form label the application derives, such as a device name. */
  label?: string;
}
/**
 * Sign-in bookkeeping kept per person by the authentication service (`authSignIns`, keyed by identity ID) for a
 * "last sign-in" notice; informational, never used for authorization.
 */
export interface SignInRecord {
  /** When the most recent session was issued by a sign-in flow, and from which client. */
  lastAt?: number;
  lastClient?: SessionClientInfo;
  /** Attempts since `lastAt` that named this account with a wrong password, factor, or recovery code. */
  failedAttempts: number;
  lastFailedAt?: number;
  lastFailedClient?: SessionClientInfo;
}
export interface Session extends StoredRecord {
  identityId: string;
  tokenHash: string;
  createdAt: number;
  expiresAt: number;
  lastSeenAt: number;
  authenticatedAt: number;
  mfa: boolean;
  /**
   * `user` (sign-in and impersonation sessions), `api-key` (service-account and agent keys), `role` (assumed roles,
   * including web-identity sessions), `session-token` (temporary credentials minted from a user session or API key) or
   * `delegated` (an agent acting on a person's behalf under a delegation; the identity is the person). Code that
   * branches on the kind must fail closed for kinds it does not know.
   */
  kind: 'user' | 'role' | 'api-key' | 'session-token' | 'delegated';
  /** Delegated sessions: the agent acting for the session's identity, and the delegation that allows it. */
  agentId?: string;
  delegationId?: string;
  /**
   * When a first-hand second factor (TOTP, passkey or an MFA step-up) was last verified for this session; exposed to
   * policies as principal.mfaTime. Absent on remembered-device, impersonation, API-key, web-identity and legacy rows.
   */
  mfaAuthenticatedAt?: number;
  /** The authority that issued an API key; session tokens minted from the key copy it and are bounded by its ceilings. */
  credentialAuthorityId?: string;
  /** Temporary credentials: a caller-chosen label (/^[\w+=,.@-]{2,64}$/), exposed as principal.sessionName. */
  sessionName?: string;
  /** Role sessions: the verified or trust-permitted source identity, exposed as principal.sourceIdentity. */
  sourceIdentity?: string;
  /** Role sessions: per-session tags admitted by the trust, exposed as principal.sessionTags.{key}. */
  sessionTags?: Record<string, string>;
  /** Session tokens: the source credential's own policy (such as API-key scopes), applied as an extra boundary. */
  sourcePolicy?: import('./policy.js').PolicyDocument;
  /** Temporary credentials issued as IAM-signed session JWTs; the row stores the hash of the JWT like any token. */
  format?: 'jwt';
  /** Session JWTs: the audiences the token was issued for. */
  audience?: string[];
  /** Web-identity role sessions: the OIDC provider and the verified external subject behind the session. */
  webIdentity?: { providerId: string; issuer: string; subject: string };
  /** The sign-in method that established a user session; exposed to policies as principal.authMethod. */
  method?: AuthMethod;
  /** Where the session was established, as captured by the HTTP layer (`http.clientInfo`); informational only. */
  client?: SessionClientInfo;
  /** API keys only: an administrator-facing label and purpose (`credentials.create`/`credentials.update`). */
  name?: string;
  description?: string;
  /** The administrator acting through this session (`identities.impersonate`); such sessions end with the administrator's own. */
  impersonatorId?: string;
  impersonatorSessionId?: string;
  /** Set when a remembered device satisfied the MFA requirement instead of a fresh second factor. */
  trustedDeviceId?: string;
  originalIdentityId?: string;
  sourceTenantId?: string;
  roleId?: string;
  trustId?: string;
  sourceSessionId?: string;
  sourceAuthorityIds?: string[];
  policy?: import('./policy.js').PolicyDocument;
  /**
   * User sessions from sign-in flows: the person's sign-in record as it stood when this session was issued (their
   * previous sign-in and the attempts that failed since), for a "last sign-in" notice. Absent on a first sign-in.
   */
  previousSignIn?: SignInRecord;
}
/** The kinds of stored session: long-lived `user` and `api-key` credentials and the temporary `role` and `session-token`. */
export type SessionKind = Session['kind'];
/**
 * The session an audited action ran under, recorded on audit events and webhook bodies. An allowlist projection of
 * the session: it never carries hashes, policies, tag values or authority ids.
 */
export interface AuditSessionContext {
  sessionId: string;
  kind: Session['kind'];
  roleId?: string;
  trustId?: string;
  sourceTenantId?: string;
  sessionName?: string;
  sourceIdentity?: string;
  webIdentityProviderId?: string;
  /** The verified external subject of a web-identity session, truncated to 256 characters. */
  webIdentitySubject?: string;
  /** Set only for session JWTs. */
  format?: 'jwt';
  /** Delegated sessions: the agent that acted on the person's behalf, and the delegation it acted under. */
  agentId?: string;
  delegationId?: string;
}
/** Produced by verified credential resolution. Server services never accept this from JSON. */
export interface AuthenticatedPrincipal {
  identity: Identity;
  session: Session;
  /**
   * The unverified device proof the request carried (`x-better-iam-device`, a compact JWS of at most 2048 characters).
   * Decisions verify it against the registered device keys and the session before it counts; never trust it as is.
   */
  deviceProof?: string;
}
export interface AuditEvent extends StoredRecord {
  actorId: string;
  action: string;
  resourceId: string;
  timestamp: number;
  outcome: 'allow' | 'deny';
  rootOverride?: boolean;
  originalActorId?: string;
  /** The administrator who performed the action through an impersonation session; `actorId` is the member. */
  impersonatorId?: string;
  metadata?: Record<string, Json>;
  /** The session the actor used, when the event was recorded for an authenticated principal; covered by the hash chain. */
  sessionContext?: AuditSessionContext;
  /** Position in the tenant's hash chain, from 1; see `verifyAuditChain`. */
  sequence?: number;
  previousHash?: string;
  hash?: string;
}
export interface OutboxMessage extends StoredRecord {
  /** Webhook messages address a webhook subscription (`to` is its ID) and carry the event in the sealed payload. */
  kind: 'email' | 'sms' | 'webhook';
  to: string;
  template: string;
  payload: Record<string, string>;
  createdAt: number;
  deliveredAt?: number;
  attempts: number;
  /** Set once delivery has been abandoned after the configured maximum attempts. */
  failedAt?: number;
  lastError?: string;
  /** What the message carries, such as the audit event ID behind a webhook delivery; enables redelivery. */
  reference?: string;
}
export interface CredentialInput {
  headers?: HeadersInit;
  token?: string;
}
export interface ResourceRef {
  tenantId: string;
  type: string;
  id: string;
}
export interface TenantType {
  allowedChildren: string[];
}
export interface HierarchyConfig {
  types: Record<string, TenantType>;
  maxDepth?: number;
}
export type AttributeType = 'string' | 'number' | 'boolean';
export interface ResourceTypeDefinition {
  description?: string;
  /** Fully qualified action names that apply to this resource type. They join the permission catalog. */
  actions?: string[];
  /** Attribute schema exposed to policy conditions as resource.{name}. */
  attributes?: Record<string, AttributeType>;
  /** Parent resource type for hierarchical resources. */
  parent?: string;
  /** Managed types are registered with IAM and resolved from its registry instead of resolveResource. */
  managed?: boolean;
  /**
   * Relation names (for example `viewer`, `editor`) that identities and groups may hold on resources of this type.
   * Held relations reach policies as `resource.relations` and, through the parent, `resource.parentRelations`.
   */
  relations?: string[];
}
export interface PermissionsConfig {
  /** catalog: only developer-defined actions and resource types. tenant-defined: tenants may also register their own. */
  mode?: 'catalog' | 'tenant-defined';
  /** Actions that are not tied to a declared resource type. */
  actions?: string[];
  resourceTypes?: Record<string, ResourceTypeDefinition>;
  /**
   * Typed attributes administrators may set on identities (`identities.update`), exposed to policy
   * conditions and variables as `principal.{name}`. Names cannot shadow the built-in principal keys.
   */
  identityAttributes?: Record<string, AttributeType>;
}
/** A delivery a plugin handler may queue in its transaction; it uses the host's configured email/SMS callbacks. */
export interface PluginDelivery {
  kind: 'email' | 'sms';
  to: string;
  template: string;
  payload: Record<string, string>;
}
export interface PluginEndpointContext {
  store: IamStore;
  principal: AuthenticatedPrincipal;
  tenantId: string;
  /** Queues an outbox delivery in the endpoint's transaction and returns the message ID. */
  deliver(delivery: PluginDelivery): Promise<string>;
}
export interface PluginEndpoint {
  method: 'POST';
  path: string;
  action: string;
  /** Validation must reject unknown/invalid fields before calling handler. */
  validate(input: unknown): Record<string, unknown>;
  /**
   * The record the endpoint acts on, from the validated input (for example `project/${input.projectId}`): the action
   * is then authorized on `iam/{resource}`, so policies about one record (a Deny on one project) apply. Without it the
   * endpoint is authorized on the tenant itself (`iam/{tenantId}`), which suits tenant-wide operations only.
   */
  resource?(input: Record<string, unknown>): string;
  handler(context: PluginEndpointContext, input: Record<string, unknown>): Promise<unknown>;
}
export interface OperationHookInput {
  store: IamStore;
  principal: AuthenticatedPrincipal;
  tenantId: string;
  action: string;
  resourceId: string;
}
export interface PluginHooks {
  /** Runs inside the operation's transaction after authorization and before the mutation; throwing aborts it. */
  beforeOperation?(input: OperationHookInput): Promise<void>;
  /** Runs inside the operation's transaction after the mutation, before its audit record; throwing aborts it. */
  afterOperation?(input: OperationHookInput & { result: unknown }): Promise<void>;
}
export interface IamPlugin {
  id: string;
  actions?: string[];
  /** Platform resource types contributed by the plugin, validated like `permissions.resourceTypes`. */
  resourceTypes?: Record<string, ResourceTypeDefinition>;
  endpoints?: PluginEndpoint[];
  hooks?: PluginHooks;
  validateConfig?(): void;
  migrate?(store: IamStore): Promise<void>;
  /** Adds trusted, server-derived keys to the policy evaluation context; never trust browser input here. */
  resolveContext?(principal: AuthenticatedPrincipal): Promise<Record<string, unknown>>;
  afterAudit?(event: AuditEvent): Promise<void>;
  /** Remove plugin-owned records before the server deletes purged tenants in the same transaction. */
  purge?(store: IamStore, tenantIds: string[]): Promise<void>;
}
