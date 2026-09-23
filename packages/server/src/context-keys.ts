/**
 * The registry of context keys the server derives for every decision. Decisions assign them, policy lint knows
 * their types, the catalog reserves their names as identity attributes, and package rules refuse the ones that
 * describe a session. Lower-precedence context (resolveContext, plugins, identity attributes) can never supply
 * them: `isServerOwnedKey` names every key that is removed before the server assigns its own values.
 *
 * This module has no runtime imports so every registry can share it.
 */

/** What a context key holds. `identifier` strings are never timestamps; `timestamp` values are ISO-8601 strings. */
export type ContextKeyType = 'identifier' | 'timestamp' | 'string' | 'number' | 'boolean' | 'list';

/**
 * Every `principal.*` and `request.*` key the server derives, with its type. Optional members
 * (`optionalPrincipalServerKeys`) are absent when their source is absent; the rest are always present.
 */
export const principalServerKeys: ReadonlyMap<string, ContextKeyType> = new Map<
  string,
  ContextKeyType
>([
  ['principal.id', 'identifier'],
  ['principal.tenantId', 'identifier'],
  ['principal.mfa', 'boolean'],
  ['principal.kind', 'identifier'],
  ['principal.owner', 'boolean'],
  ['principal.rootAdmin', 'boolean'],
  // 'user' | 'role' | 'api-key' | 'session-token' | 'delegated'.
  ['principal.sessionKind', 'identifier'],
  ['principal.authMethod', 'identifier'],
  ['principal.impersonated', 'boolean'],
  ['principal.impersonatorId', 'identifier'],
  ['principal.groups', 'list'],
  ['principal.roles', 'list'],
  ['principal.agreements', 'list'],
  ['principal.pendingAgreements', 'number'],
  // Onboarding flows the person completed (names) and required ones still open.
  ['principal.onboarding', 'list'],
  ['principal.pendingOnboarding', 'number'],
  // Teams the person belongs to (team IDs, with the teams above them) and their department with the ones above it.
  ['principal.teams', 'list'],
  ['principal.departments', 'list'],
  ['principal.departmentId', 'identifier'],
  // Spend (billing-service.ts): whether an enforced budget covering the principal is spent, and the spent budgets' names.
  ['principal.spendExceeded', 'boolean'],
  ['principal.budgetsExceeded', 'list'],
  // Session-aware keys: 'simulation' is the session id of simulated principals.
  ['principal.sessionId', 'identifier'],
  ['principal.tokenIssueTime', 'timestamp'],
  ['principal.authTime', 'timestamp'],
  ['principal.mfaTime', 'timestamp'],
  ['principal.sessionTagKeys', 'list'],
  ['principal.sourceTenantId', 'identifier'],
  ['principal.sessionName', 'identifier'],
  ['principal.sourceIdentity', 'identifier'],
  ['principal.webIdentityProvider', 'identifier'],
  ['principal.webIdentitySubject', 'string'],
  // AI agents (agents.ts): whether an agent acts on the person's behalf, and the agent behind the credential (its own
  // key or a delegated session) with its sponsor, model and provider.
  ['principal.delegated', 'boolean'],
  ['principal.delegationId', 'identifier'],
  ['principal.agentId', 'identifier'],
  ['principal.agentSponsorId', 'identifier'],
  ['principal.agentModel', 'string'],
  ['principal.agentProvider', 'string'],
  // Delegated sessions: the agents from the person's own delegate to the acting one (longer after hand-offs).
  ['principal.delegationChain', 'list'],
  ['request.time', 'timestamp'],
  // The client address the server saw; never set for simulated principals or without a client scope.
  ['request.sourceIp', 'identifier'],
]);

/**
 * `tenant.*` keys the server derives about the decision's tenant. `tenant.features` lists the keys of the feature
 * flags that are on for it (features.ts); decisions read it only when a condition names it.
 */
export const tenantServerKeys: ReadonlyMap<string, ContextKeyType> = new Map<
  string,
  ContextKeyType
>([['tenant.features', 'list']]);

/**
 * Server keys missing from some decisions (every operator except Exists is then false): API keys and role sessions
 * have no sign-in method, only impersonated sessions name an impersonator, mfaTime needs a first-hand MFA ceremony,
 * the role-session attribution keys exist only when set, and request.sourceIp needs a known client address.
 */
export const optionalPrincipalServerKeys: ReadonlySet<string> = new Set([
  'principal.authMethod',
  'principal.impersonatorId',
  'principal.mfaTime',
  'principal.sourceTenantId',
  'principal.sessionName',
  'principal.sourceIdentity',
  'principal.webIdentityProvider',
  'principal.webIdentitySubject',
  'principal.delegationId',
  'principal.agentId',
  'principal.agentSponsorId',
  'principal.agentModel',
  'principal.agentProvider',
  'principal.delegationChain',
  'principal.departmentId',
  'request.sourceIp',
]);

/** Session tags appear as `principal.sessionTags.<key>` (optional strings), one key per tag. */
export const sessionTagPrefix = 'principal.sessionTags.';
/** A session tag key: a letter, then letters, digits or underscores, at most 64 characters (matched case-sensitively). */
export const tagKeyPattern = /^[A-Za-z][A-Za-z0-9_]{0,63}$/;

/**
 * Bare principal names the session keys occupy. Identity attributes may not use them, so an attribute can never
 * shadow (or be mistaken for) a session-derived value.
 */
export const reservedSessionPrincipalNames: readonly string[] = [
  'sessionId',
  'tokenIssueTime',
  'authTime',
  'mfaTime',
  'sourceTenantId',
  'sessionName',
  'sourceIdentity',
  'sessionTags',
  'sessionTagKeys',
  'webIdentityProvider',
  'webIdentitySubject',
  'delegated',
  'delegationId',
  'agentId',
  'agentSponsorId',
  'agentModel',
  'agentProvider',
  'delegationChain',
];

/**
 * The session-derived principal keys as policies name them. They describe one credential rather than the identity,
 * so rules evaluated without a session (package rules) refuse them; the `sessionTagPrefix` family is refused as well.
 */
export const sessionScopedPrincipalKeys: readonly string[] = reservedSessionPrincipalNames
  .filter((name) => name !== 'sessionTags')
  .map((name) => `principal.${name}`);

/** Whether only the server may set this context key: a registry member or any `principal.sessionTags.` key. */
export function isServerOwnedKey(key: string): boolean {
  return (
    principalServerKeys.has(key) || tenantServerKeys.has(key) || key.startsWith(sessionTagPrefix)
  );
}

/** The context key (`principal.sessionTags.<key>`) for a session tag key, or undefined when the key is not valid. */
export function sessionTagName(key: string): string | undefined {
  return tagKeyPattern.test(key) ? `${sessionTagPrefix}${key}` : undefined;
}
