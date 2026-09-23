import type {
  AttributeType,
  Json,
  PolicyDocument,
  PolicyStatement,
  StoredRecord,
} from '@better-iam/core';
export interface Role extends StoredRecord {
  name: string;
  description?: string;
  policyIds: string[];
  document?: PolicyDocument;
  protected: boolean;
  /**
   * Roles whose grants this role includes (role hierarchy). Inherited grants stay bounded by this role's own
   * authority ceilings as well as the inherited role's, so inheriting a broader role cannot widen access.
   */
  inherits?: string[];
  /**
   * Role sessions (classic and web identity) created before this time (epoch milliseconds) are refused
   * (`roles.revokeSessions`). Monotonic and never in the future; role updates and config sync keep it.
   */
  sessionsRevokedBefore?: number;
}
/**
 * A recurring time window in a named time zone during which a binding applies: `from`/`to` are `HH:MM`
 * (24-hour); a window whose `to` is not after `from` wraps past midnight; `days` are 0 (Sunday) to 6 and
 * default to every day. Outside the window the binding grants nothing.
 */
export interface AccessWindow {
  days?: number[];
  from: string;
  to: string;
  timeZone: string;
}
export interface Policy extends StoredRecord {
  name: string;
  description?: string;
  document: PolicyDocument;
  version: number;
}
export interface GrantAuthority extends StoredRecord {
  identityId: string;
  ceiling: PolicyDocument;
  parentAuthorityId?: string;
  revoked: boolean;
}
/**
 * expiresAt makes the grant temporary: an expired binding grants nothing and is removed by the purge worker.
 * An eligible binding grants nothing until its subject activates it (`bindings.activate`) for a limited time.
 */
export interface Binding extends StoredRecord {
  subjectType: 'identity' | 'group';
  subjectId: string;
  roleId: string;
  authorityId: string;
  /** Future-dated grant: the binding grants nothing before this time (onboarding that starts on a set day). */
  startsAt?: number;
  expiresAt?: number;
  accessRequestId?: string;
  /** Just-in-time access: the role applies only while the subject holds a live activation. */
  eligible?: boolean;
  /** Longest activation the subject may request (default one hour, at most seven days). */
  maxActivationMs?: number;
  /** Activation must state a justification, recorded in the audit trail. */
  requireJustification?: boolean;
  /** Activation requires an MFA-verified session. */
  requireMfa?: boolean;
  /** Activation starts as a request that an approver must grant (`bindings.approveActivation`). */
  requireApproval?: boolean;
  /** When set, only members of this group may approve (besides root); they are emailed each request. */
  approverGroupId?: string;
  /** The requester's manager (`Identity.managerId`) may approve and is emailed each request. */
  managerApproval?: boolean;
  /** Business-hours access: the binding applies only inside this recurring window. */
  window?: AccessWindow;
  /** Set when an access-package assignment created this binding; revoking the assignment removes it. */
  packageAssignmentId?: string;
}
/**
 * An activation of an eligible binding by one identity; uniqueKey is `{bindingId}:{identityId}`. Without a
 * status it is live until `expiresAt`; `pending` waits for approval (then `expiresAt` bounds the request) and
 * `denied` is kept only until the purge worker sweeps it.
 */
export interface BindingActivation extends StoredRecord {
  bindingId: string;
  identityId: string;
  roleId: string;
  activatedAt: number;
  expiresAt: number;
  justification?: string;
  /** The session that activated; ending that session does not end the activation. */
  sessionId: string;
  status?: 'pending' | 'active' | 'denied';
  /** The activation length asked for while pending; applied on approval unless the approver shortens it. */
  requestedDurationMs?: number;
  decidedBy?: string;
  decidedAt?: number;
  note?: string;
}
export type AccessRequestStatus = 'pending' | 'approved' | 'denied' | 'cancelled' | 'expired';
/** A request for temporary or standing role bindings, approved under the reviewer's grant authority. */
export interface AccessRequest extends StoredRecord {
  requesterId: string;
  roleIds: string[];
  justification?: string;
  durationSeconds?: number;
  status: AccessRequestStatus;
  createdAt: number;
  expiresAt: number;
  reviewerId?: string;
  reviewedAt?: number;
  note?: string;
  bindingIds?: string[];
  grantExpiresAt?: number;
}
/** A webhook subscription. The signing secret is sealed at rest and returned only when created or rotated. */
export interface Webhook extends StoredRecord {
  url: string;
  events: string[];
  description?: string;
  active: boolean;
  /** subtree: also receive events recorded in descendant tenants. */
  scope: 'tenant' | 'subtree';
  /** Deliver only these outcomes (default both). */
  outcomes?: ('allow' | 'deny')[];
  /** Deliver only events whose resourceId matches one of these glob patterns (default all). */
  resources?: string[];
  secretSealed: string;
  createdAt: number;
  updatedAt: number;
  createdBy: string;
}
export interface Group extends StoredRecord {
  name: string;
  description?: string;
  /** Set on a team's backing group (teams.ts): its memberships come from the team and are refused elsewhere (TEAM_MANAGED). */
  teamId?: string;
}
export interface GroupMember extends StoredRecord {
  groupId: string;
  identityId: string;
  /** Temporary membership: past this time the person is no longer a member; the purge worker removes the record. */
  expiresAt?: number;
  /** Set when an access-package assignment created this membership; revoking the assignment removes it. */
  packageAssignmentId?: string;
  /** Set on memberships of a team's backing group: the team that owns the group (teams.ts writes these). */
  teamId?: string;
}
/**
 * An access package bundles roles and groups that are granted together (`packages.assign`) for a shared period:
 * an onboarding kit, a project profile, a vendor's access. Names are unique per tenant (uniqueKey `name:{lowercase}`).
 */
export interface AccessPackage extends StoredRecord {
  name: string;
  description?: string;
  roleIds: string[];
  groupIds: string[];
  /** Longest assignment the package allows; assignments must then state an end within it. */
  maxDurationMs?: number;
  /** Assignments must state a justification. */
  requireJustification?: boolean;
  /** Members holding `iam:packages:request` may ask for it (`packages.request`); an approver then decides. */
  requestable?: boolean;
  /** When set, only members of this group (besides root) decide on requests; they are emailed each one. */
  approverGroupId?: string;
  /** The requester's manager (`Identity.managerId`) may decide and is emailed each request. */
  managerApproval?: boolean;
  /** Birthright rule; see AutoAssignRule. Incompatible with maxDurationMs. */
  autoAssign?: AutoAssignRule;
  createdAt: number;
  updatedAt: number;
}
/** One clause of an access-package rule: exactly a policy statement's `conditions` block (operators and keys AND, listed values OR). */
export type PackageRuleConditions = NonNullable<PolicyStatement['conditions']>;
/**
 * Birthright rule of an access package: active identities matching any `include` clause and no `exclude` clause
 * receive the package automatically (`reconcilePackages` and after identity changes), and automatic holders lose it
 * `graceMs` after they stop matching. The rule runs under the grant authority and rights of its owner: whoever last
 * set it or changed the package's contents.
 */
export interface AutoAssignRule {
  /** 1-10 clauses; an identity matches when any clause holds. */
  include: PackageRuleConditions[];
  /** 0-10 clauses; an identity matching any of them never matches (deny wins). */
  exclude?: PackageRuleConditions[];
  /** Automatic holders keep the package this long after they stop matching (at most 90 days); absent: removed at the next reconcile. */
  graceMs?: number;
  /** Unattended runs hold back this package's new grants (assign and refresh) above this count (default 100). */
  maxGrants?: number;
  /** Unattended runs hold back this package's removals (revoke and grace starts) above this count (default 25). */
  maxRemovals?: number;
  /** The identity whose grant authority and rights the rule runs under. */
  ownerId: string;
  /** The owner's grant authority; every automatic binding is issued under it. */
  authorityId: string;
  /** Starts at 1; increments when the owner, the authority, or the package's roles or groups change. */
  revision: number;
  updatedAt: number;
  /** Planned change counts a person approved (an API save or a confirmed reconcile); unattended runs may apply up to these until `until`. */
  approved?: { grants: number; removals: number; until: number };
}
/**
 * A problem the package-rule reconciler met, kept so it is audited once per transition, shown to administrators,
 * and retried after fresh work. uniqueKey: `{packageId}:identity:{identityId}` (failed), `{packageId}:suspended`,
 * or `{packageId}:braked:{grants|removals}`.
 */
export interface PackageRuleIssue extends StoredRecord {
  packageId: string;
  kind: 'failed' | 'suspended' | 'braked';
  identityId?: string;
  /** IamError code (failed), the suspension reason (suspended), or 'grants' | 'removals' (braked). */
  code: string;
  message: string;
  /** The rule revision when recorded; a different revision counts as a new transition. */
  revision: number;
  since: number;
}
/**
 * Remembers that the expiry reminder for one item (uniqueKey `{kind}:{id}:{expiresAt}`) was sent, so each item and
 * end date is reminded once; swept by the purge worker once the item has ended.
 */
export interface ExpiryReminderMark extends StoredRecord {
  identityId: string;
  expiresAt: number;
}
export type PackageRequestStatus = 'pending' | 'approved' | 'denied' | 'cancelled' | 'expired';
/** A member's request for a requestable package; `expiresAt` is when a pending request lapses. */
export interface PackageRequest extends StoredRecord {
  packageId: string;
  identityId: string;
  status: PackageRequestStatus;
  requestedAt: number;
  expiresAt: number;
  /** The end the requester asked for; the approver may choose another. */
  desiredExpiresAt?: number;
  justification?: string;
  decidedBy?: string;
  decidedAt?: number;
  note?: string;
  /** The assignment an approval created. */
  assignmentId?: string;
}
/**
 * One person's assignment of a package (uniqueKey `{packageId}:{identityId}`). The bindings and memberships it
 * created are ordinary records tagged with `packageAssignmentId`; revoking removes exactly those.
 */
export interface PackageAssignment extends StoredRecord {
  packageId: string;
  identityId: string;
  assignedBy: string;
  assignedAt: number;
  expiresAt?: number;
  justification?: string;
  /** Set when the package rule assigned it: the rule revision it was last materialized for. Absent means a manual assignment. */
  ruleRevision?: number;
  bindingIds: string[];
  membershipIds: string[];
}
/** Claim conditions of a web-identity trust: exactly a policy statement's `conditions` block over `token.<claim>` keys. */
export type TrustConditions = NonNullable<PolicyStatement['conditions']>;
/** Whether a role session may, or must, carry a caller-supplied (or claim-mapped) source identity. */
export type SourceIdentityMode = 'forbidden' | 'optional' | 'required';
/**
 * Permission to assume a role of this tenant. An identity trust names one source identity (possibly in another
 * tenant) that may call `roles.assume`; a web-identity trust admits tokens of an OIDC provider that satisfy its
 * claim conditions (`sts.assumeRoleWithWebIdentity`), backed by a service account of this tenant. Records written
 * before these fields existed read as kind 'identity', no tags, source identity forbidden, a 3600 s cap, and
 * source attributes passed.
 */
export interface Trust extends StoredRecord {
  /** Absent on legacy records, which are identity trusts. */
  kind?: 'identity' | 'web-identity';
  /** The source identity's tenant; equal to `tenantId` for web-identity trusts. */
  sourceTenantId: string;
  /** The identity that may assume the role; for web-identity trusts, the anchoring service account. */
  sourceIdentityId: string;
  roleId: string;
  /** The source session must be MFA-verified (always false for web-identity trusts). */
  requireMfa: boolean;
  /** SHA-256 of the external ID the caller must present; never returned (see PublicTrust.requiresExternalId). */
  externalIdHash?: string;
  revoked: boolean;
  /** Upper bound on what role sessions under this trust may do, whatever the role grants (default: everything). */
  ceiling?: PolicyDocument;
  /** Longest role session this trust issues (60 up to the deployment's `sts.maxRoleSessionSeconds`); absent: 3600. */
  maxSessionSeconds?: number;
  /**
   * Whether the source identity's attributes appear as `principal.<attribute>` in role sessions. New cross-tenant
   * trusts default to false, same-tenant and web-identity trusts to true; absent (legacy) passes them.
   */
  passSourceAttributes?: boolean;
  /** Session tag keys callers may set on `roles.assume` (at most 50), or exactly ['*'] for any; absent: none. */
  allowedTagKeys?: string[];
  /** Whether callers may (optional) or must (required) state a source identity; absent: forbidden. */
  sourceIdentityMode?: SourceIdentityMode;
  /**
   * Sessions issued under this trust before this time (epoch milliseconds) are refused (`trust.revokeSessions`, and
   * automatically when `trust.update` tightens the trust). Monotonic and never in the future.
   */
  sessionsRevokedBefore?: number;
  /** Web identity: the OIDC provider whose tokens this trust admits. */
  providerId?: string;
  /** Web identity: conditions over the verified token's flattened claims; they must pin `token.sub`. */
  conditions?: TrustConditions;
  /** Web identity: session tag key to flattened claim name (at most 10); only valid string claims become tags. */
  tagClaims?: Record<string, string>;
  /** Web identity: the flattened claim that becomes the session's source identity. */
  sourceIdentityClaim?: string;
  /** Web identity: the creator's grant authority; revoking it ends the trust's sessions. */
  authorityId?: string;
  description?: string;
  createdAt?: number;
  createdBy?: string;
  updatedAt?: number;
}
/**
 * A trust as the API returns it: an allowlist projection that never carries the external ID hash and reports
 * whether one is required. Declared explicitly because `Omit` over StoredRecord's index signature loses the fields.
 */
export interface PublicTrust {
  id: string;
  tenantId: string;
  /** 'identity' for legacy records. */
  kind: 'identity' | 'web-identity';
  sourceTenantId: string;
  sourceIdentityId: string;
  roleId: string;
  requireMfa: boolean;
  /** The caller must present an external ID. */
  requiresExternalId: boolean;
  revoked: boolean;
  ceiling?: PolicyDocument;
  maxSessionSeconds?: number;
  passSourceAttributes?: boolean;
  allowedTagKeys?: string[];
  sourceIdentityMode?: SourceIdentityMode;
  sessionsRevokedBefore?: number;
  providerId?: string;
  conditions?: TrustConditions;
  tagClaims?: Record<string, string>;
  sourceIdentityClaim?: string;
  authorityId?: string;
  description?: string;
  createdAt?: number;
  createdBy?: string;
  updatedAt?: number;
}
/** JWS algorithms an OIDC provider's tokens may use; symmetric algorithms and `none` are never accepted. */
export type WebIdentityAlgorithm =
  | 'RS256'
  | 'RS384'
  | 'RS512'
  | 'PS256'
  | 'PS384'
  | 'PS512'
  | 'ES256'
  | 'ES384'
  | 'EdDSA';
/** A public JSON Web Key (RFC 7517). Private members are refused wherever keys are accepted. */
export interface PublicJwk {
  kty: string;
  kid?: string;
  alg?: string;
  use?: string;
  [member: string]: unknown;
}
/**
 * An external OpenID Connect issuer whose ID tokens web-identity trusts admit (collection 'oidcProviders',
 * uniqueKey `issuer:{issuer}`). Keys come from `jwks`, else `jwksUri`, else the issuer's discovery document; nothing
 * is fetched when the provider is created.
 */
export interface OidcProvider extends StoredRecord {
  name: string;
  /** Exact `iss` value; https without userinfo, query or fragment (http only for loopback in development). */
  issuer: string;
  /** Accepted `aud` values (1-10); a token must name one of them. */
  audiences: string[];
  /** https on port 443. */
  jwksUri?: string;
  /** Static public keys (at most 20), used instead of fetching. */
  jwks?: { keys: PublicJwk[] };
  /** Non-empty; default ['RS256', 'ES256']. */
  algorithms: WebIdentityAlgorithm[];
  /** Longest accepted token lifetime and age, `exp - iat` (60-86400; default 3600). */
  maxTokenLifetimeSeconds: number;
  /** Clock skew tolerated on `exp`, `nbf` and `iat` (0-120; default 30). */
  clockToleranceSeconds: number;
  /** 'single-use' (default) redeems each token once; 'off' suits tokens SDKs reuse until they rotate. */
  replayProtection: 'single-use' | 'off';
  /** A disabled provider admits no exchanges, and its live sessions stop working. */
  enabled: boolean;
  /** The creator's grant authority; it bounds every web-identity session through this provider. */
  authorityId: string;
  /** Sessions through this provider created before this time (epoch milliseconds) are refused. */
  sessionsRevokedBefore?: number;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
}
/** An OIDC provider as the API returns it (an explicit allowlist projection of OidcProvider). */
export interface PublicOidcProvider {
  id: string;
  tenantId: string;
  name: string;
  issuer: string;
  audiences: string[];
  jwksUri?: string;
  jwks?: { keys: PublicJwk[] };
  algorithms: WebIdentityAlgorithm[];
  maxTokenLifetimeSeconds: number;
  clockToleranceSeconds: number;
  replayProtection: 'single-use' | 'off';
  enabled: boolean;
  authorityId: string;
  sessionsRevokedBefore?: number;
  createdAt: number;
  createdBy: string;
  updatedAt: number;
}
/**
 * A redeemed web-identity token (collection 'webIdentityReplays'). The id is the replay key, a SHA-256 over the
 * provider and the token's `jti` (or the token's own hash); the raw token is never stored. Retention sweeps rows once
 * `expiresAt` (the token's `exp` plus the provider's clock tolerance) has passed.
 */
export interface WebIdentityReplay extends StoredRecord {
  providerId: string;
  expiresAt: number;
}
export interface OwnerInvitation extends StoredRecord {
  tokenHash: string;
  email: string;
  createdAt: number;
  expiresAt: number;
  authorityId: string;
  consumed: boolean;
  revoked?: boolean;
}
/** authorityId is the inviter's grant authority; it is present only when the invitation carries roles or groups. */
export interface MemberInvitation extends StoredRecord {
  tokenHash: string;
  email: string;
  name?: string;
  roleIds: string[];
  groupIds: string[];
  authorityId?: string;
  inviterId: string;
  createdAt: number;
  expiresAt: number;
  consumed: boolean;
  revoked?: boolean;
}
export interface IdentityLink extends StoredRecord {
  leftId: string;
  rightId: string;
  revoked: boolean;
}
export interface PrincipalBoundary extends StoredRecord {
  identityId: string;
  document: PolicyDocument;
}
export interface ActionDefinition extends StoredRecord {
  name: string;
  description?: string;
  resourceType?: string;
}
/** Tenant-defined resource type. Its actions are namespaced under the type name. */
export interface ResourceTypeRecord extends StoredRecord {
  name: string;
  description?: string;
  attributes: Record<string, AttributeType>;
  parent?: string;
  relations?: string[];
  createdAt: number;
}
/**
 * A relationship tuple: an identity or group holds a declared relation on one resource.
 * uniqueKey is `{type}/{resourceId}#{relation}@{subjectType}:{subjectId}` within the tenant.
 */
export interface Relationship extends StoredRecord {
  type: string;
  resourceId: string;
  relation: string;
  subjectType: 'identity' | 'group';
  subjectId: string;
  createdAt: number;
  createdBy: string;
  expiresAt?: number;
}
/** A managed resource registered with IAM; uniqueKey is `{type}/{resourceId}` within the tenant. */
export interface ResourceRecord extends StoredRecord {
  type: string;
  resourceId: string;
  attributes: Record<string, Json>;
  parentType?: string;
  parentId?: string;
  ownerId?: string;
  createdAt: number;
  updatedAt: number;
}
/** Global sign-in alias. The record id is the alias itself, so the primary key enforces uniqueness across tenants. */
export interface TenantAlias extends StoredRecord {
  createdAt: number;
}
