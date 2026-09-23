import { createAuth, type DeliveryMessage } from '@better-iam/auth';
import { createApi } from './api/index.js';
import { createHosts } from './hosts.js';
import { Catalog } from './catalog.js';
import { createCertificationWorker } from './certification-worker.js';
import { createFeatureEvaluator } from './api/features.js';
import { clientFromHeaders } from './client-info.js';
import { createContext } from './context.js';
import { createDecisions } from './decisions.js';
import { createEvents } from './events.js';
import { createFederation } from './federation.js';
import { createFlows } from './flows.js';
import { createAuthApi, createHttp } from './http.js';
import { createInferenceRuntime } from './api/inference.js';
import { inferencePlugins } from './inference.js';
import { createA2aRuntime } from './a2a.js';
import { createBillingRuntime } from './api/billing.js';
import { billingServiceOf } from './billing-service.js';
import { createLifecycle } from './lifecycle.js';
import { createMetrics } from './metrics.js';
import { createObserver } from './observe.js';
import { createUsageRecorder } from './usage.js';
import { checkInvariants } from './invariants.js';
import { closeOverdueTeamReviews } from './team-reviews.js';
import { createOperations } from './operations.js';
import { resolveConfig, type BetterIamOptions } from './options.js';
import { validatePlugins } from './plugins.js';
import { createPrincipals } from './principals.js';
import { assertionKey } from './assertions.js';
import { createRetention } from './retention.js';
import { createSelfCheck } from './self-check.js';
import { createSecretRotation } from './secrets.js';
import { createAuditArchive } from './audit-archive.js';
import { createSessionTokenSigner } from './token-signing.js';
import { createWebIdentityVerifier } from './web-identity.js';
import {
  SessionTokenError,
  type PublicSessionJwk,
  type SessionTokenClaims,
} from './session-tokens.js';
import type { IamStore, Identity, Session } from '@better-iam/core';
import { hash, sameHash } from './utils.js';

export * from './models.js';
export { IamError, verifyAuditChain, auditEventHash, canonicalJson } from '@better-iam/core';
export type { AuditChainVerification, AuditChainHead, AuditSessionContext } from '@better-iam/core';
export type {
  AssumeRoleInput,
  CallerIdentity,
  CredentialFormat,
  GetSessionTokenInput,
  RoleCredential,
  RoleSessionSummary,
  TemporaryCredential,
  TemporaryCredentialSession,
} from './temporary-credentials.js';
export { WrongRegionError } from './hosts.js';
export type { HostMatch, HostOptions, RegionOptions, TenantHostname } from './hosts.js';
export { publicTrust, webTrustTagClaims } from './api/trust.js';
export type {
  IdentityTrustCreateInput,
  TrustCreateInput,
  TrustRevokeSessionsInput,
  TrustUpdateInput,
  WebIdentityTrustCreateInput,
} from './api/trust.js';
export { publicOidcProvider } from './api/oidc-providers.js';
export type {
  OidcProviderCreateInput,
  OidcProviderRevokeSessionsInput,
  OidcProviderUpdateInput,
} from './api/oidc-providers.js';
export type {
  WebIdentityCredential,
  WebIdentityEvaluation,
  WebIdentityExchangeInput,
  WebIdentityRejectionReason,
} from './web-identity-exchange.js';
export type { WebIdentityFailureReason } from './web-identity.js';
export { verifyWebhookSignature } from './events.js';
export {
  authenticatedAuthMethods,
  publicApiMethods,
  publicAuthMethods,
  routeGroups,
} from './http.js';
export { verifyAssertion, assertionKey } from './assertions.js';
export type { AssertionClaims } from './assertions.js';
export type { DomainDiscovery, DomainOptions, TenantDomain } from './api/domains.js';
export type { AccessFinding, FindingKind, FindingSeverity } from './api/analysis.js';
export type {
  MiningRef,
  PeerOutlier,
  PeerOutlierResult,
  PeerRoleShare,
  RoleMiningResult,
  RoleSuggestion,
  RoleSuggestionKind,
  RightSizeEntry,
  RightSizeResult,
  RoleUsageSummary,
  ReviewRecommendation,
  ReviewRecommendationsResult,
} from './api/role-mining.js';
export type { AccessUsageOptions, AccessUsageRecord } from './usage.js';
export type {
  ImpactChange,
  ImpactIdentity,
  ImpactPreview,
  ImpactResourceDiff,
} from './api/impact.js';
export type {
  AccessInvariant,
  InvariantCheckResult,
  InvariantResult,
  InvariantSubject,
  InvariantViolation,
} from './invariants.js';
export type { InvariantInput, InvariantRunResult } from './api/invariants.js';
export type { Agreement, AgreementAcceptance } from './agreements.js';
export type { AgreementInput, AgreementStatus, MyAgreement } from './api/agreements.js';
export type {
  OnboardingAudience,
  OnboardingCheck,
  OnboardingField,
  OnboardingFieldType,
  OnboardingFlow,
  OnboardingFlowStatus,
  OnboardingProgress,
  OnboardingRule,
  OnboardingScope,
  OnboardingSettings,
  OnboardingSource,
  OnboardingStep,
  OnboardingStepKind,
  OnboardingStepState,
  OnboardingStepStatus,
  ResolvedOnboardingSettings,
} from './onboarding.js';
export type {
  EffectiveOnboarding,
  EffectiveOnboardingFlow,
  MyOnboarding,
  OnboardingFlowInput,
  OnboardingFlowUpdate,
  OnboardingProgressReport,
  OnboardingSettingsInput,
  OnboardingSubjectProgress,
} from './api/onboarding.js';
export type { AccessPath, AccessPathsResult } from './api/access-paths.js';
export type {
  CertificationCampaign,
  CertificationDecision,
  CertificationItem,
  CertificationOutcome,
  CertificationProgress,
} from './api/certifications.js';
export type { SodRule, SodViolation } from './sod.js';
export { lintPolicy } from './policy-lint.js';
export type { PolicyLintContext, PolicyLintResult, PolicyLintWarning } from './policy-lint.js';
export type { IamSpan, ObservabilityOptions, SpanKind } from './observe.js';
export { createMetrics } from './metrics.js';
export type { MetricsCollector, MetricsOptions, MetricsSnapshot } from './metrics.js';
export type {
  AccessRequestOptions,
  AccessibleResourcesRequest,
  AuthorizationCheck,
  AuthorizationRequest,
  BatchAuthorizationRequest,
  BetterIamOptions,
  EventOptions,
  HttpOptions,
  ProtocolMount,
  WebhookDelivery,
  WebhookEvent,
} from './options.js';
export type { CatalogResourceType } from './catalog.js';
export type { EffectiveBinding, GrantPath } from './decisions.js';
export type { MutationContext } from './operations.js';
export type { AccessDigestResult, ExpiryReminderResult, PurgeResult } from './lifecycle.js';
export type { SweepOptions, SweepResult } from './retention.js';
export type { SecretRotationOptions, SecretRotationResult } from './secrets.js';
export { createJsonlAuditArchive } from './audit-archive.js';
export type {
  AuditArchiveBatch,
  AuditArchiveCursor,
  AuditArchiveOptions,
  AuditArchiveResult,
} from './audit-archive.js';
export type {
  SelfCheckFinding,
  SelfCheckOptions,
  SelfCheckResult,
  SelfCheckSeverity,
} from './self-check.js';
export type { AutoAssignInput, RuleKey, RuleKeyType } from './package-rules.js';
export type {
  AutoAssignPreview,
  PackageReconcileResult,
  PublicAutoAssign,
  PublicPackage,
  ReconcileTrigger,
  RuleChange,
  RuleSuspension,
} from './api/packages.js';
export type { CertificationAutoCloseResult } from './certification-worker.js';
export { validateTenantConfig } from './sync.js';
export { configOptions, defineConfig, defineTenantConfig } from './define.js';
export type { IamConfigContext, IamConfigFactory, TenantConfigFactoryContext } from './define.js';
export type {
  ConfigChange,
  ConfigChangeAction,
  ConfigChangeKind,
  ConfigPlan,
  TenantConfig,
  TenantConfigAutoAssign,
  TenantConfigBinding,
  TenantConfigGroup,
  TenantConfigPackage,
  TenantConfigPolicy,
  TenantConfigResourceType,
  TenantConfigRole,
} from './sync.js';
export type { CredentialSummary } from './api/service-accounts.js';
export type {
  AccessReport,
  ExpiringBinding,
  ExpiringIdentity,
  ExpiringMembership,
  LiveActivation,
} from './api/reports.js';
export type { EligibilityInput } from './api/bindings.js';
export type { Api } from './api/index.js';
export { rolloutBucket } from './features.js';
export type { FeatureEvaluation, FeatureReason } from './features.js';
export type {
  FeatureFlagDefinition,
  FeatureFlagView,
  FeatureTargetView,
  IamFeatures,
} from './api/features.js';
export type { PublicIdentity } from './utils.js';
export {
  createSessionTokenVerifier,
  looksLikeJwt,
  SESSION_TOKEN_ALGORITHMS,
  SESSION_TOKEN_TYPE,
  SessionTokenError,
} from './session-tokens.js';
export type {
  PublicSessionJwk,
  SessionTokenAlgorithm,
  SessionTokenClaims,
  SessionTokenErrorReason,
  SessionTokenKind,
  SessionTokenVerifier,
  SessionTokenVerifierOptions,
} from './session-tokens.js';
export type { SessionTokenSigningOptions, StsOptions, StsWebIdentityOptions } from './options.js';
export {
  actsInOwnRight,
  nextWatermark,
  revokedByWatermark,
  temporarySessionKinds,
} from './session-kinds.js';
export type { AgentProfile } from '@better-iam/core';
export { machineIdentity } from './agents.js';
export type { AgentProfileInput, AgentStanding, AgentSummary } from './agents.js';
export type {
  AgentDetail,
  AgentListing,
  CreateAgentInput,
  UpdateAgentInput,
} from './api/agents.js';
export type {
  Delegation,
  DelegationConfirmation,
  DelegationHandoff,
  DelegationSpend,
} from './delegations.js';
export type {
  ConfirmationSummary,
  DelegatedCredential,
  DelegationScopeInput,
  DelegationSummary,
  DelegationToken,
} from './api/delegations.js';
export {
  budgetWindow,
  inferenceAction,
  inferenceResourceType,
  inferenceToolAction,
  inferenceToolResourceType,
  usageCost,
} from './inference.js';
export type {
  BudgetPeriod,
  BudgetStanding,
  InferenceBudget,
  InferenceModel,
  InferenceOptions,
  InferenceProvider,
  InferenceResponseRecord,
  InferenceTokenUsage,
  InferenceUsageRecord,
  InvocationCheck,
  ProviderKind,
  ProviderToolsMode,
  PublicModel,
} from './inference.js';
export type {
  InferenceBudgetInput,
  InferenceBudgetView,
  GatewayPermit,
  InferenceRuntime,
  ModelInput,
  PublicProvider,
  UsageReport,
  UsageRow,
} from './api/inference.js';
export { createInferenceGateway, providerToolsOf, usageFrom } from './inference-gateway.js';
export type { GatewayRuntime, InferenceGatewayOptions, UsageFormat } from './inference-gateway.js';
export { agentAttestationUri } from './a2a.js';
export type {
  A2aOptions,
  A2aRuntime,
  AgentAttestation,
  PublicCardJwk,
  SignedAgentCard,
  VerifyIssuedDelegationTokenOptions,
} from './a2a.js';
export {
  delegationTokenLimits,
  delegationTokenType,
  readDelegationTokenClaims,
} from '@better-iam/core';
export type {
  DelegationActor,
  DelegationTokenClaims,
  DelegationTokenRejection,
  DelegationTokenSummary,
} from '@better-iam/core';
export type {
  TenantConfigAgent,
  TenantConfigBudgetSubject,
  TenantConfigInferenceBudget,
  TenantConfigInferenceModel,
} from './ai-sync.js';
// Teams inside an organization and its departments (teams.ts, departments.ts).
export { isTeamMaintainer, primaryTeamOf, teamMaintainers, teamsOf } from './teams.js';
export type {
  Team,
  TeamJoinPolicy,
  TeamJoinRequest,
  TeamJoinRequestStatus,
  TeamMember,
  TeamMemberManagement,
  TeamRole,
  TeamSyncResult,
} from './teams.js';
export type {
  MyTeams,
  TeamDetail,
  TeamInput,
  TeamJoinRequestView,
  TeamMemberView,
  TeamPerson,
  TeamRef,
  TeamRoleGrant,
  TeamSummary,
  TeamUpdate,
} from './api/teams.js';
export { departmentHeads, departmentOf, departmentPath } from './departments.js';
export type { Department, DepartmentMember } from './departments.js';
export type { TenantConfigDepartment, TenantConfigTeam } from './org-sync.js';
export type {
  DepartmentDetail,
  DepartmentImportResult,
  DepartmentInput,
  DepartmentMemberView,
  DepartmentNode,
  DepartmentPerson,
  DepartmentRef,
  DepartmentSummary,
  DepartmentPlacement,
  DepartmentUpdate,
  ManagerSyncResult,
  MyDepartment,
} from './api/departments.js';
export type { BirthrightItem, BirthrightSuggestion, OrgUnitKind } from './org-insights.js';
export type {
  TeamReview,
  TeamReviewDecision,
  TeamReviewItem,
  TeamReviewOutcome,
  TeamReviewStatus,
} from './team-reviews.js';
export type { TeamReviewItemView, TeamReviewView } from './api/teams.js';
// Billing and spend tracking (billing.ts, billing-service.ts, api/billing.ts).
export {
  amountDue,
  amountPaid,
  billingPeriod,
  dayOf,
  periodBounds,
  periodOf,
  priceBreakdown,
  priceQuantity,
  priceSpec,
  shiftPeriod,
} from './billing.js';
export { renderInvoiceHtml } from './billing-invoices.js';
export type {
  BillingBudget,
  BillingCoupon,
  BillingCredit,
  BillingCreditNote,
  BillingDiscount,
  BillingInvoiceItem,
  BillingMeter,
  BillingOptions,
  BillingPlan,
  BillingPrice,
  BillingProfile,
  BillingProfileFields,
  BillingSettings,
  BillingStatement,
  BillingSubscription,
  BillingTerms,
  BudgetPeriodKind,
  BudgetSubjectType,
  CreditNoteReason,
  InvoiceIssuer,
  InvoicePayment,
  InvoiceStatus,
  PlanItem,
  PriceModel,
  PriceSpec,
  PriceTier,
  StatementAllocation,
  StatementBody,
  StatementLine,
  TierLine,
  UsageInput,
  UsageReceipt,
} from './billing.js';
export type {
  AnomalyAlertResult,
  AnomalyOptions,
  BillingHooks,
  BudgetAlertResult,
  BudgetStatus,
  ClosePeriodResult,
  PaymentReminderResult,
  PricedUsageInput,
  SeatRecordResult,
  SpendAnomaly,
  SpendCheck,
  SpendFilters,
  SpendGroupBy,
  SpendQuery,
  SpendReport,
  SpendRow,
  SpendTrend,
  StatementDraft,
} from './billing-service.js';
export type {
  AccountOverview,
  BillingBudgetInput,
  BillingBudgetView,
  CouponView,
  CreditNoteView,
  CreditView,
  CsvExport,
  DiscountView,
  IamBilling,
  InvoiceDocument,
  InvoiceItemView,
  MeterView,
  PlanItemView,
  PlanView,
  PriceView,
  ProfileView,
  PublicPriceSpec,
  StatementSummary,
  SubscriptionView,
  TermsView,
} from './api/billing.js';

/**
 * IAM-signed session JWTs (`sts.jwt`): the issuer, the public keys downstream services verify with, and an online,
 * revocation-aware check. Present only when `sts.jwt` is configured.
 */
export interface IamSessionTokens {
  /** The `iss` of every session JWT, also the audience IAM itself requires. */
  readonly issuer: string;
  /** The public signing and verification keys, as served at `{basePath}/.well-known/jwks.json`. */
  jwks(): { keys: PublicSessionJwk[] };
  /**
   * Verifies a session JWT for `audience` (default: the issuer) and then, unlike an offline verifier, requires its
   * stored session to be live: the row, its identity and every revocation condition are re-validated. A token that
   * verifies but has been revoked fails with `SessionTokenError` reason `revoked`.
   */
  verify(token: string, options?: { audience?: string }): Promise<SessionTokenClaims>;
}

/**
 * Composes the IAM server: configuration and catalog validation, the authentication service, the shared context,
 * the service modules, the provisioning API, deployment helpers, federation callbacks, and the HTTP transports.
 */
export function betterIam(options: BetterIamOptions) {
  const config = resolveConfig(options);
  // Built-in modules that extend the catalog (inference: the `model` type and `inference:invoke`) come last.
  const plugins = [...(options.plugins ?? []), ...inferencePlugins(options)];
  const catalog = new Catalog(options, plugins, config);
  validatePlugins(plugins, catalog);
  const now = () => options.authentication?.now?.() ?? Date.now();
  // Session JWT keys are validated here, so a bad `sts.jwt` fails construction with INVALID_CONFIG.
  const sessionTokens = createSessionTokenSigner(options.sts?.jwt, {
    issuer: `${config.baseURL.origin}${config.basePath}`,
    now,
  });
  // With organization addresses or regions, every email and SMS names its organization's sign-in URL, so the
  // application's link builders can send people to their own organization's address.
  const withSignInUrl =
    (send: (message: DeliveryMessage) => Promise<void>) => async (message: DeliveryMessage) => {
      if (!config.hosts.enabled && !config.regions) return send(message);
      const signInUrl = await ctx.hosts.signInUrl(message.tenantId).catch(() => undefined);
      return send(signInUrl ? { ...message, signInUrl } : message);
    };
  // Authentication events fan out through the event service, which is attached to the context below.
  const auth = createAuth({
    ...options.authentication,
    ...(options.authentication?.sendEmail
      ? { sendEmail: withSignInUrl(options.authentication.sendEmail) }
      : {}),
    ...(options.authentication?.sendSms
      ? { sendSms: withSignInUrl(options.authentication.sendSms) }
      : {}),
    store: options.database,
    secret: options.secret,
    ...(options.previousSecrets ? { previousSecrets: options.previousSecrets } : {}),
    baseURL: options.baseURL,
    trustedOrigins: options.trustedOrigins,
    onAudit: (tx, event) => ctx.events.fanOut(tx, event),
    deliverWebhook: (message) => ctx.events.deliverWebhookMessage(message),
  });
  const metricsOptions = options.observability?.metrics;
  const metrics = metricsOptions
    ? createMetrics(typeof metricsOptions === 'object' ? metricsOptions : {})
    : undefined;
  const onSpan = options.observability?.onSpan;
  const observe = createObserver({
    onSpan: metrics
      ? (span) => {
          metrics.onSpan(span);
          onSpan?.(span);
        }
      : onSpan,
  });
  const ctx = createContext({
    options,
    config,
    store: options.database,
    auth,
    plugins,
    catalog,
    now,
    observe,
  });
  ctx.sessionTokens = sessionTokens;
  ctx.hosts = createHosts(ctx);
  // The external-token verifier exists only while web-identity federation is enabled; its fetches use the
  // host transport (`sts.webIdentity.fetchJson`) when one is given, else the guarded fetch.
  if (config.sts.webIdentity.enabled)
    ctx.webIdentity = createWebIdentityVerifier({
      ...config.sts.webIdentity,
      fetchJson: options.sts?.webIdentity?.fetchJson,
      now,
      selfIssuer: sessionTokens?.issuer ?? `${config.baseURL.origin}${config.basePath}`,
    });
  ctx.events = createEvents(ctx);
  ctx.decisions = createDecisions(ctx);
  ctx.principals = createPrincipals(ctx);
  ctx.operations = createOperations(ctx);
  ctx.flows = createFlows(ctx);
  ctx.usage = createUsageRecorder(ctx);
  // The billing ledger; validates the `billing` option now, so a bad value fails construction with INVALID_CONFIG.
  ctx.billing = billingServiceOf(ctx).hooks;

  // In-process calls that carry request headers record and judge the same client the HTTP handler would.
  const authApi = createAuthApi(auth, observe, (headers) =>
    clientFromHeaders(options, headers, config.baseURL),
  );
  const api = createApi(ctx, authApi);
  const lifecycle = createLifecycle(ctx);
  const retention = createRetention(ctx);
  const rotateSecrets = createSecretRotation(ctx);
  const auditArchive = createAuditArchive(ctx);
  const certificationWorker = createCertificationWorker(ctx);
  const federation = createFederation(ctx, api.bindings);
  const http = createHttp(ctx, api, authApi, {
    metrics,
    metricsToken:
      typeof metricsOptions === 'object' && typeof metricsOptions.bearerToken === 'string'
        ? metricsOptions.bearerToken
        : undefined,
    metricsGauges: typeof metricsOptions === 'object' && metricsOptions.gauges === true,
  });
  const events = { subscribe: ctx.events.subscribe, dispatch: ctx.events.dispatch };
  const publicSessionTokens: IamSessionTokens | undefined = sessionTokens && {
    issuer: sessionTokens.issuer,
    jwks: () => sessionTokens.publicJwks(),
    async verify(token, verifyOptions) {
      const claims = await sessionTokens.verify(token, { audience: verifyOptions?.audience });
      try {
        await options.database.transaction(async (tx: IamStore) => {
          const session = await tx.get<Session>('sessions', claims.sid);
          if (
            !session ||
            session.format !== 'jwt' ||
            session.kind !== claims.kind ||
            session.identityId !== claims.sub ||
            session.tenantId !== claims.tid ||
            // The shared constant-time comparison: fail-closed on a non-string, by byte length.
            !sameHash(session.tokenHash, hash(token)) ||
            session.expiresAt <= now()
          )
            throw new SessionTokenError('revoked');
          const identity = await tx.get<Identity>('identities', session.identityId);
          if (!identity || identity.status !== 'active' || ctx.identityExpired(identity))
            throw new SessionTokenError('revoked');
          await ctx.principals.currentPrincipal(tx, { identity, session });
        });
      } catch {
        throw new SessionTokenError('revoked');
      }
      return claims;
    },
  };

  return {
    api,
    auth,
    handler: http.handler,
    nodeHandler: http.nodeHandler,
    authorize: ctx.operations.authorize,
    authorizeMany: ctx.operations.authorizeMany,
    listAccessible: ctx.operations.listAccessible,
    require: ctx.operations.requireAccess,
    authenticate: ctx.principals.authenticate,
    initialize: lifecycle.initialize,
    bootstrap: lifecycle.bootstrap,
    recoverRoot: lifecycle.recoverRoot,
    purgeDeleted: lifecycle.purgeDeleted,
    pruneAudit: lifecycle.pruneAudit,
    /** Copies new audit events, verified and in chain order, to `auditArchive` (a scheduler job). */
    archiveAudit: auditArchive.archiveAudit,
    /** Deletes expired sessions, protocol artifacts, and old delivery records in short batches (a scheduler job). */
    sweepExpired: retention.sweepExpired,
    /** Reports configuration and storage problems: schema, durability, secrets, transports, and scheduled jobs. */
    selfCheck: createSelfCheck(ctx, retention.countDue, (limit) =>
      rotateSecrets({ dryRun: true, limit }),
    ),
    /** Emails each organization's owners its access report when there is something to report (a scheduler job). */
    sendAccessDigest: lifecycle.sendAccessDigest,
    /** Emails each person whose access ends soon a reminder listing it, once per item (a scheduler job). */
    sendExpiryReminders: lifecycle.sendExpiryReminders,
    /** Assigns and removes rule-based (birthright) access packages under each rule owner's authority (a scheduler job). */
    reconcilePackages: lifecycle.reconcilePackages,
    /** Closes and applies every auto-closing access certification campaign past its due date (a scheduler job). */
    closeOverdueCertifications: certificationWorker.closeOverdueCertifications,
    /** Completes every open team membership review past its due date, applying its removals (a scheduler job). */
    closeOverdueTeamReviews: (input?: { tenantId?: string }) => closeOverdueTeamReviews(ctx, input),
    /** Evaluates every tenant's access invariants and audits breaks and restorations (a scheduler job). */
    checkInvariants: (input?: { tenantId?: string }) => checkInvariants(ctx, input),
    /** Writes buffered access usage now (`accessUsage` option); call it before shutting down. */
    flushAccessUsage: () => ctx.usage.flush(),
    /**
     * Feature flag values for a tenant, for the deployment's own server code: no credential, internal flags included.
     * Manage flags through `api.features`; members read their tenant's flags with `features.evaluate`.
     */
    features: createFeatureEvaluator(ctx),
    /**
     * Inference access control (`inference` option), server side: model checks that return the opened provider
     * credential, metering, and the HTTP gateway (`inference.gateway()`). Manage it through `api.inference`.
     */
    inference: createInferenceRuntime(ctx),
    /** IAM-attested A2A agent cards (`a2a` option): the public card keys to publish at `a2a.jwksUrl`. */
    a2a: createA2aRuntime(ctx),
    /**
     * Billing, server side: audit-free metering (`record`), enforced-budget checks, spend reports, payments from a
     * payment processor (`recordPayment`), and the scheduler jobs `recordSeats` (daily), `checkBudgets` (hourly),
     * `closePeriod` (daily; invoices ended months) and `sendPaymentReminders` (daily). Manage meters, prices, plans,
     * budgets and invoices through `api.billing`.
     */
    billing: createBillingRuntime(ctx),
    protocolHost: federation.protocolHost,
    useProtocol: http.useProtocol,
    dispatchAuditHooks: ctx.events.dispatch,
    events,
    callPlugin: ctx.operations.callPlugin,
    /** The derived key downstream services use with `verifyAssertion`; a deployment secret, never exposed over HTTP. */
    assertionKey: () => assertionKey(options.secret),
    /**
     * The current assertion key first, then those of `previousSecrets`: give downstream services
     * the list while a secret rotates (`verifyAssertion` accepts it), then only the first.
     */
    assertionKeys: () => [options.secret, ...(options.previousSecrets ?? [])].map(assertionKey),
    /** Re-seals values encrypted with `previousSecrets` using `secret` (a deployment operation). */
    rotateSecrets,
    /** Prometheus-style counters and histograms when `observability.metrics` is enabled. */
    metrics,
    /** Session JWT keys and online verification; present only when `sts.jwt` is configured. */
    sessionTokens: publicSessionTokens,
    store: options.database,
    /** Where the HTTP handler is mounted, for framework integrations that call it server-side. */
    endpoint: {
      origin: config.baseURL.origin,
      basePath: config.basePath,
      secure: config.baseURL.protocol === 'https:',
      /** The handler's cookie settings, so code that writes its own session cookies can match them. */
      cookieSameSite: options.http?.cookieSameSite ?? 'lax',
      persistentCookies: options.http?.persistentCookies ?? true,
    },
    /**
     * Organization sign-in addresses and regions (`hosts`, `regions` options), for framework integrations and
     * edge routing: which organization an address belongs to, each organization's sign-in URL, and whether a TLS
     * certificate may be issued for a hostname.
     */
    hosts: {
      /** This deployment's region, when `regions` is configured. */
      region: config.regions?.current,
      /** Whether organizations may verify custom hostnames (`hosts.customHostnames`). */
      customHostnames: config.hosts.customHostnames,
      /**
       * The organization an address (host with optional port) belongs to; undefined for the deployment's own and
       * unknown hosts. Throws `NOT_FOUND` for the address of an unknown or inactive organization and `WRONG_REGION`
       * when another region serves it.
       */
      resolve: (host: string) => ctx.hosts.resolve(host),
      /** An organization's canonical sign-in URL: its primary custom hostname, its subdomain, or its region's URL. */
      signInUrl: (tenantId: string) => ctx.hosts.signInUrl(tenantId),
      /** True when a TLS certificate may be issued for `hostname` (an on-demand TLS "ask" check). */
      allowed: (hostname: string) => ctx.hosts.allowed(hostname),
    },
  };
}
export type BetterIam = ReturnType<typeof betterIam>;
