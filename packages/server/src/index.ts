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
import { createKmsRuntime } from './api/keys.js';
import { createPkiRuntime } from './api/pki.js';
import { createProtectionRuntime } from './api/protection.js';
import { createVaultRuntime } from './api/vault.js';
import { createPlanRuntime } from './api/filters.js';
import { createQuotasRuntime } from './api/quotas.js';
import { createPrivacyRuntime } from './api/privacy.js';
import { createWorkflowsRuntime } from './api/workflows.js';
import { createComplianceRuntime } from './api/compliance.js';
import { createApplicationsRuntime } from './api/applications.js';
import { createSshRuntime } from './api/ssh.js';
import { sshPlugins } from './ssh.js';
import { createVcProtocol, createVcRuntime } from './api/verifiable-credentials.js';
import { vcOptions, vcPlugins } from './vc.js';
import { createLdapRuntime } from './ldap.js';
import { createSignalsProtocol, createSignalsRuntime } from './signal-receiver.js';
import { billingServiceOf } from './billing-service.js';
import { createLifecycle } from './lifecycle.js';
import { createMetrics } from './metrics.js';
import { createObserver } from './observe.js';
import { createUsageRecorder } from './usage.js';
import { checkInvariants } from './invariants.js';
import { closeOverdueTeamReviews } from './team-reviews.js';
import { detectThreats } from './threat-engine.js';
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
// SSH certificate authority (ssh-ca.ts wire format, api/ssh.ts service).
export {
  SSH_CERT_HOST,
  SSH_CERT_USER,
  buildSshKrl,
  generateSshAuthorityKey,
  parseSshCertificate,
  parseSshPublicKey,
  signSshCertificate,
  sshFingerprint,
  sshHostAddress,
  sshKeyLine,
  sshKeyTypes,
  sshLogin,
  sshSerial,
  sshSigningKey,
} from './ssh-ca.js';
export type {
  KrlAuthoritySection,
  ParsedSshCertificate,
  SshCertificateSpec,
  SshKeyType,
  SshPublicKey,
  SshSigningKey,
} from './ssh-ca.js';
export {
  sshForwardingActions,
  sshHostResourceType,
  sshLoginAction,
  sshLoginResourceType,
} from './ssh.js';
export type {
  SshAuthorityKind,
  SshAuthorityStatus,
  SshHostStatus,
  SshOptions,
  SshRevocationReason,
  SshSweepResult,
} from './ssh.js';
// Verifiable credentials: SD-JWT VCs, Token Status Lists and OpenID4VCI holder proofs (sd-jwt.ts).
export {
  HOLDER_PROOF_TYPE,
  KB_JWT_TYPE,
  SD_JWT_VC_TYPE,
  STATUS_INVALID,
  STATUS_LIST_JWT_TYPE,
  STATUS_SUSPENDED,
  STATUS_VALID,
  SdJwtError,
  createDisclosure,
  issueSdJwt,
  presentSdJwt,
  readDisclosure,
  readStatusList,
  setStatusAt,
  signStatusList,
  splitSdJwt,
  statusAt,
  verifyHolderProof,
  verifySdJwt,
} from './sd-jwt.js';
export type { SdJwtDisclosure, SdJwtFailure, VerifiedSdJwt } from './sd-jwt.js';
export { credentialTypeResource, vcRequestAction } from './vc.js';
export { normalizeBaseDn } from './ldap.js';
export type { LdapDirectory, LdapGroupView, LdapPerson, LdapService, LdapUidMode } from './ldap.js';
export type { LdapSettingsInput, LdapSettingsView } from './api/ldap.js';
export type {
  VcClaim,
  VcClaimSource,
  VcCredentialStatus,
  VcSweepResult,
  VerifiableCredentialOptions,
  VerifiedCredential,
} from './vc.js';
export type {
  VcCredentialTypeInput,
  VcCredentialTypeUpdate,
  VcCredentialTypeView,
  VcIssuedView,
  VcIssuerKeyView,
  VcOfferResult,
  VcVerification,
} from './api/verifiable-credentials.js';
export type {
  SshAccessEntry,
  SshAuthorityView,
  SshCertificateRequest,
  SshCertificateView,
  SshHostInput,
  SshHostSetup,
  SshHostUpdate,
  SshHostView,
  SshIssuedCertificate,
  SshSettingsView,
} from './api/ssh.js';
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
export type {
  EncryptionContext,
  GrantConstraints,
  GrantOperation,
  GrantSummary,
  KeySpec,
  KeyState,
  KeySummary,
  KeyUsage,
  MacAlgorithm,
  SignatureFormat,
  SigningAlgorithm,
} from './kms.js';
export type {
  AliasSummary,
  JwtVerification,
  KeyCreateInput,
  KeyMaintenanceResult,
  KeyVersionSummary,
  PublicKeyView,
} from './api/keys.js';
// Private certificate authority (pki.ts, api/pki.ts, x509.ts).
export { createCertificateRequest } from './x509.js';
export type {
  CertificateRequestInput,
  DistinguishedName,
  RevocationReason,
  SubjectAltNames,
} from './x509.js';
export type {
  AuthoritySummary,
  AuthorityState,
  CertificateSummary,
  CertificateUsage,
  CertificateVerification,
} from './pki.js';
export type { AuthorityCreateInput, CertificateIssueInput, IssuedCertificate } from './api/pki.js';
// Data protection by tokenization (tokenization.ts, api/protection.ts).
export type { DataType, MaskStyle, ProfileSummary, TokenFormat } from './tokenization.js';
export type { ProfileCreateInput } from './api/protection.js';
// Data filtering / query planning (core plan.ts, api/filters.ts).
export type { PlanResourcesRequest, ResourcePlanResult } from './api/filters.js';
// API usage plans and quotas (quotas.ts, api/quotas.ts).
export { QuotaExceededError, quotaWindow } from './quotas.js';
export type {
  QuotaDecision,
  QuotaLimit,
  QuotaLimitStatus,
  QuotaPeriod,
  QuotaSubjectType,
  QuotaThrottle,
} from './quotas.js';
export type {
  IamQuotas,
  QuotaAssignmentView,
  QuotaConsumeRequest,
  QuotaPlanView,
  QuotaUsageView,
} from './api/quotas.js';
export type { DecisionInputs } from './decisions.js';
// Secrets vault (vault.ts, api/vault.ts).
export { generateValue as generateSecretValue } from './vault.js';
export type {
  CheckoutPolicy,
  EngineHolder,
  EngineIssued,
  EngineIssueInput,
  EngineLeaseInput,
  GeneratorCharset,
  LeaseSettings,
  PasswordGenerator,
  RotatorInput,
  SecretFormat,
  SecretKind,
  SecretRotation,
  VaultEngine,
  VaultOptions,
  VaultRotator,
} from './vault.js';
export type {
  CheckoutResult,
  DynamicLeaseResult,
  IamVault,
  LeaseJobResult,
  RevealedSecret,
  RotationResult,
  SecretAccessView,
  SecretLeaseView,
  SecretVersionView,
  SecretView,
  VaultJobResult,
} from './api/vault.js';
// Privacy and consent (privacy.ts, api/privacy.ts).
export { regulationDeadlines, consentState } from './privacy.js';
export type {
  ConsentMode,
  ConsentReason,
  ConsentReceipt,
  ConsentSource,
  ConsentState,
  LegalBasis,
  PrivacyConsent,
  PrivacyConsentEvent,
  PrivacyHold,
  PrivacyPurpose,
  PrivacyRestriction,
  Regulation,
  RejectionReason,
  SubjectInput,
  SubjectRequest,
  SubjectRequestEvent,
  SubjectRequestStatus,
  SubjectRequestType,
} from './privacy.js';
export type {
  ConsentHistoryEntry,
  ConsentView,
  DeadlineReminderResult,
  MyPurpose,
  PrivacySettingsView,
  PrivacySummary,
  PurposeInput,
  SubjectRequestView,
} from './api/privacy.js';
// Lifecycle workflows (workflows.ts, api/workflows.ts).
export type {
  Workflow,
  WorkflowRun,
  WorkflowRunStatus,
  WorkflowStep,
  WorkflowStepKind,
  WorkflowStepResult,
  WorkflowTrigger,
} from './workflows.js';
export type {
  WorkflowInput,
  WorkflowJobResult,
  WorkflowPreview,
  WorkflowRunView,
  WorkflowView,
} from './api/workflows.js';
// Compliance center (compliance.ts, api/compliance.ts).
export { complianceChecks, complianceFrameworks } from './compliance.js';
export type {
  CheckFinding,
  CheckStatus,
  ComplianceCheck,
  ComplianceControl,
  ComplianceException,
  ComplianceFramework,
  ComplianceResult as ComplianceControlResult,
  ComplianceRun,
  FrameworkRequirement,
} from './compliance.js';
export { verifyEvidencePack } from './api/compliance.js';
export type {
  ComplianceJobResult,
  ControlInput,
  EvidenceKey,
  EvidencePack,
  FindingView,
  FrameworkStatus,
  RequirementStatus,
  ResultView,
} from './api/compliance.js';
// Application catalog and launcher (applications.ts, api/applications.ts).
export type { AppAssignment, AppLaunch, Application } from './applications.js';
export type { ApplicationInput, ApplicationUsage, MyApp } from './api/applications.js';
// Identity threat detection and response (threats.ts, threat-rules.ts, threat-engine.ts, api/threats.ts).
export { effectiveRisk, resolveThreatSettings, riskLevelFor, threatRules } from './threats.js';
export type {
  DetectionStatus,
  IdentityRisk,
  IncidentResolution,
  IncidentStatus,
  ResolvedThreatSettings,
  ResponseAction,
  ResponseActionKind,
  RiskContribution,
  RiskLevel,
  ThreatBaseline,
  ThreatCursor,
  ThreatDetection,
  ThreatDetectionRun,
  ThreatEvidence,
  ThreatIncident,
  ThreatNote,
  ThreatPlaybook,
  ThreatResponse,
  ThreatRuleCategory,
  ThreatRuleDefinition,
  ThreatRuleId,
  ThreatRuleSetting,
  ThreatSettings,
  ThreatSeverity,
  ThreatSubject,
  ThreatSubjectType,
} from './threats.js';
export type { DetectionCandidate } from './threat-rules.js';
export type {
  DetectionPage,
  IdentityRiskView,
  IncidentDetail,
  IncidentPage,
  RiskContributionView,
  RiskPage,
  SuspiciousActivityReport,
  ThreatPlaybookInput,
  ThreatRuleSettingInput,
  ThreatRuleView,
  ThreatSettingsInput,
  ThreatSettingsView,
  ThreatSummary,
} from './api/threats.js';
// Device posture (devices.ts, api/devices.ts).
export { assuranceOf, deviceProofHeader, evaluateCompliance, resolveDeviceSettings } from './devices.js';
export type {
  ComplianceReason,
  ComplianceResult,
  DeviceAssurance,
  DeviceEnrollment,
  DeviceIntegration,
  DeviceIntegrationVendor,
  DeviceKey,
  DevicePlatform,
  DevicePosture,
  DevicePublicJwk,
  DeviceSettings,
  DeviceStatus,
  RegisteredDevice,
  ResolvedDeviceSettings,
} from './devices.js';
export type {
  DeviceCheck,
  DeviceDetail,
  DeviceEnrollInput,
  DeviceEnrollmentCode,
  DeviceEnrollmentView,
  DeviceIntegrationView,
  DeviceKeyView,
  DevicePublicKeyInput,
  DeviceReport,
  DeviceReportResult,
  DeviceSettingsView,
  DeviceView,
  MyDevice,
} from './api/devices.js';
// Shared Signals receiver (signal-receiver.ts, api/signals.ts; event and subject parsing in @better-iam/core).
export {
  DEFAULT_SIGNAL_ALGORITHMS,
  maxSignalSourcesPerTenant,
  signalCollections,
  SignalRejectedError,
} from './signal-receiver.js';
export type {
  IamSignals,
  ReceivedSignal,
  SignalAction,
  SignalActionableEvent,
  SignalAlgorithm,
  SignalDelivery,
  SignalErrorCode,
  SignalPollResult,
  SignalPollState,
  SignalReceipt,
  SignalSource,
  SignalSourceStatus,
  SignalStatus,
  SignalSubjectMapping,
} from './signal-receiver.js';
export type {
  SignalEventPage,
  SignalEventView,
  SignalSourceCreated,
  SignalSourceCreateInput,
  SignalSourceUpdateInput,
  SignalSourceView,
} from './api/signals.js';
export type { ResolvedSignalsConfig, SignalsOptions } from './options.js';
export type { SecurityEventClaims, SignalEventType, SubjectIdentifier } from '@better-iam/core';

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
  const plugins = [
    ...(options.plugins ?? []),
    ...inferencePlugins(options),
    ...sshPlugins(options),
    ...vcPlugins(options),
  ];
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
  // Wallet-facing issuer endpoints (`{basePath}/vc/{tenantId}/...` and their /.well-known metadata).
  if (vcOptions(ctx)) ctx.mountedProtocols.push(createVcProtocol(ctx));
  // The Shared Signals push endpoint (`{signals.pushPath}/{sourceId}`, RFC 8935).
  ctx.mountedProtocols.push(createSignalsProtocol(ctx));

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
    /**
     * Identity threat detection (a scheduler job, every few minutes): reads each active tenant's new audit events
     * from its cursor (at most `maxEvents`, default 2000), verifies the hash chain, raises detections, groups them into
     * incidents, updates identity risk, and runs response playbooks. Manage it through `api.threats`.
     */
    detectThreats: (input?: { tenantId?: string; maxEvents?: number }) => detectThreats(ctx, input),
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
    /**
     * Key management, server side: the scheduler job `maintain` (hourly) that performs automatic key rotation,
     * destroys keys after their deletion waiting period and removes lapsed grants. Use keys through `api.keys`.
     */
    kms: createKmsRuntime(ctx),
    /**
     * The private certificate authority, server side: public CRLs (`crl`, `crlResponse` for a CRL distribution
     * point), trust bundles, and `verify` for servers that terminate mutual TLS. Manage it through `api.pki`.
     */
    pki: createPkiRuntime(ctx),
    /** Data protection, server side: the retention job `sweep` (daily). Tokenize through `api.protection`. */
    protection: createProtectionRuntime(ctx),
    /**
     * The secrets vault, server side: `get` and `resolve` (`vault://name#field` references) for the deployment's own
     * code, and the scheduler jobs `rotateDue` (hourly), `expireLeases` (every few minutes) and `purgeDeleted`
     * (daily). Manage secrets through `api.vault`.
     */
    vault: createVaultRuntime(ctx),
    /**
     * Data filtering: which resources of a type the caller may perform an action on, as a filter for your own queries
     * (`filterToSql`, `filterToPrisma`, `filterToMongo`, `filterMatches` from `@better-iam/core`). The credential goes in
     * the request, as with `authorize`.
     */
    planResources: createPlanRuntime(ctx),
    /**
     * API usage plans and quotas, in your request handlers: `consume` / `enforce` count use for the request's
     * credential (`enforce` throws QUOTA_EXCEEDED with `retryAfterMs`), `status` reads what is left, and `consumeFor`
     * counts for a subject your code identified. Define and assign plans through `api.quotas`.
     */
    quotas: createQuotasRuntime(ctx),
    /**
     * Privacy and consent, server side: credential-free `check` and `record` for the deployment's own code (such as a
     * cookie banner or a marketing send), and the scheduler job `sendDeadlineReminders` (daily) for data-subject
     * request deadlines. Manage purposes and requests through `api.privacy`.
     */
    privacy: createPrivacyRuntime(ctx),
    /**
     * Lifecycle workflows, server side: the scheduler job `runDue` (every few minutes) that starts runs for joiners,
     * movers, leavers and dates and resumes waiting runs, and `subscribe()` to react to changes within moments (needs
     * `dispatchAuditHooks` running). Manage workflows through `api.workflows`.
     */
    workflows: createWorkflowsRuntime(ctx),
    /** The compliance center, server side: the scheduler job `evaluateAll` (daily). Manage controls via `api.compliance`. */
    compliance: createComplianceRuntime(ctx),
    /**
     * The application catalog, server side: `allowed` tells an OAuth sign-in or consent page whether a person is
     * assigned the app registered for a client. Manage apps through `api.applications`.
     */
    applications: createApplicationsRuntime(ctx),
    /**
     * The SSH certificate authority (`ssh` option), server side: the scheduler job `sweep` (every few minutes) that
     * revokes certificates whose holder or access went away, and `revocationList(tenantId)` as bytes for a custom
     * route. Manage authorities, hosts and certificates through `api.ssh`.
     */
    ssh: createSshRuntime(ctx),
    /**
     * Verifiable credentials (`verifiableCredentials` option), server side: `verify` presentations of credentials the
     * deployment issued, and the scheduler job `sweep` (hourly) revoking credentials of people who left. Manage types
     * and credentials through `api.verifiableCredentials`; wallets use the `{basePath}/vc/{tenantId}` endpoints.
     */
    verifiableCredentials: createVcRuntime(ctx),
    /** The LDAP directory gateway's lookups before a bind (base DN → tenant, bind name → identity); see `@better-iam/ldap`. */
    ldap: createLdapRuntime(ctx),
    /**
     * The Shared Signals receiver, server side: the scheduler job `poll` (every minute or so) that fetches events from
     * poll sources (RFC 8936), and `receive(sourceId, set)` to hand in a security event token from a custom transport.
     * Pushes arrive at `{signals.pushPath}/{sourceId}`; manage sources and read events through `api.signals`.
     */
    signals: createSignalsRuntime(ctx),
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
