//! Better IAM for Rust in one dependency (the Rust port of the `better-iam` umbrella package).
//!
//! The crate root re-exports what the TypeScript umbrella's index exports: the server entry point, the core policy
//! and audit helpers, assertion and webhook verification, and the model types of the API. Every package is also a
//! module, the counterpart of the umbrella's subpath exports (`better-iam/core` is [`core`], `better-iam/client`
//! is [`client`], ...), each behind a feature:
//!
//! | feature | module | TypeScript subpath |
//! | --- | --- | --- |
//! | `server` (default) | [`server`], [`session_tokens`], the root re-exports | `better-iam`, `better-iam/server`, `better-iam/session-tokens` |
//! | always | [`core`] | `better-iam/core` |
//! | `auth` (default) | [`auth`] (with [`auth::templates`]) | `better-iam/auth`, `better-iam/auth/templates` |
//! | `sqlite` (default), `postgres`, `libsql` | [`adapter_sqlite`], [`adapter_postgres`], [`adapter_libsql`] | `better-iam/adapter-*` |
//! | `client` (default) | [`client`] (with [`client::session`], [`client::device`]) | `better-iam/client`, `/client/session`, `/client/device` |
//! | `projects` (default) | [`projects`] | `better-iam/projects` |
//! | `types` | [`types`] | the API types |
//!
//! ```ignore
//! use better_iam::{better_iam, define_policy};
//! use better_iam::adapter_sqlite::{sqlite_adapter, SqliteAdapterOptions};
//! use better_iam::client::{create_iam_client, ClientOptions};
//! ```
//!
//! The JavaScript-only entries of the umbrella (React, Vue, Svelte, Next.js, Nuxt, NestJS, React Router, the browser
//! passkey helpers) have no Rust counterpart.
#![forbid(unsafe_code)]

/// `better-iam/core`: records, the store contract, policies, the audit chain.
pub mod core {
    pub use better_iam_core::*;
}

/// `better-iam/server`: the server and every module of it.
#[cfg(feature = "server")]
pub mod server {
    pub use better_iam_server::*;
}

/// `better-iam/session-tokens`: verifying IAM-signed session JWTs.
#[cfg(feature = "server")]
pub mod session_tokens {
    pub use better_iam_server::session_tokens::*;
}

/// `better-iam/auth`: tenant-scoped authentication.
#[cfg(feature = "auth")]
pub mod auth {
    pub use better_iam_auth::*;
}

/// `better-iam/adapter-sqlite`.
#[cfg(feature = "sqlite")]
pub mod adapter_sqlite {
    pub use better_iam_adapter_sqlite::*;
}

/// `better-iam/adapter-postgres`.
#[cfg(feature = "postgres")]
pub mod adapter_postgres {
    pub use better_iam_adapter_postgres::*;
}

/// `better-iam/adapter-libsql`.
#[cfg(feature = "libsql")]
pub mod adapter_libsql {
    pub use better_iam_adapter_libsql::*;
}

/// `better-iam/client`: the typed HTTP client, its session store and device proofs.
#[cfg(feature = "client")]
pub mod client {
    pub use better_iam_client::*;
}

/// `better-iam/projects`: the projects reference plugin.
#[cfg(feature = "projects")]
pub mod projects {
    pub use better_iam_projects::*;
}

/// The request, result and model types of the HTTP API.
#[cfg(feature = "types")]
pub mod types {
    pub use better_iam_types::*;
}

// The server entry point.
pub use better_iam_core::{IamError, IamResult};
#[cfg(feature = "server")]
pub use better_iam_server::options::{AuthorizationRequest, BetterIamOptions, ProtocolMount};
#[cfg(feature = "server")]
pub use better_iam_server::{BetterIam, better_iam};

// Policies and the audit chain.
pub use better_iam_core::{
    append_audit_event, canonical_json, define_policy, evaluate_policy, validate_policy,
    verify_audit_chain,
};

// Assertions, webhooks, and certificate requests.
#[cfg(feature = "server")]
pub use better_iam_server::assertions::{assertion_key, verify_assertion};
#[cfg(feature = "server")]
pub use better_iam_server::events::verify_webhook_signature;
#[cfg(feature = "server")]
pub use better_iam_server::x509::{CertificateRequestInput, create_certificate_request};

// The runtimes of `BetterIam` (the TypeScript `iam.features`, `iam.billing`, ... interfaces).
#[cfg(feature = "server")]
pub use better_iam_server::api::billing::BillingRuntime as IamBilling;
#[cfg(feature = "server")]
pub use better_iam_server::api::clearances::ClearancesRuntime as IamClearances;
#[cfg(feature = "server")]
pub use better_iam_server::api::features::FeatureEvaluator as IamFeatures;
#[cfg(feature = "server")]
pub use better_iam_server::api::guests::GuestsRuntime as IamGuests;
#[cfg(feature = "server")]
pub use better_iam_server::api::licenses::LicensesRuntime as IamLicenses;
#[cfg(feature = "server")]
pub use better_iam_server::signal_receiver::SignalsRuntime as IamSignals;

// Options and records of the server modules.
#[cfg(feature = "server")]
pub use better_iam_server::billing::{BillingStatement, InvoiceIssuer};
#[cfg(feature = "server")]
pub use better_iam_server::departments::Department;
#[cfg(feature = "server")]
pub use better_iam_server::devices::RegisteredDevice;
#[cfg(feature = "server")]
pub use better_iam_server::guests::GuestSettings;
#[cfg(feature = "server")]
pub use better_iam_server::inference_gateway::InferenceGatewayOptions;
#[cfg(feature = "server")]
pub use better_iam_server::licenses::LicenseProduct;
#[cfg(feature = "server")]
pub use better_iam_server::options::{
    A2aOptions, BillingOptions, ClearanceOptions, InferenceOptions, SignalsOptions,
};
#[cfg(feature = "server")]
pub use better_iam_server::pki::{CertificateUsage, CertificateVerification};
#[cfg(feature = "server")]
pub use better_iam_server::signal_receiver::{SignalAction, SignalReceipt};
#[cfg(feature = "server")]
pub use better_iam_server::teams::Team;
#[cfg(feature = "server")]
pub use better_iam_server::threats::{IdentityRisk, ThreatDetection, ThreatIncident};

// Core records and contracts.
pub use better_iam_core::{
    AgentProfile, AuditEvent, ClassificationLabel, ClassificationLevel,
    ClassificationSchemeDefinition, Compartment, CredentialInput, Decision, DominanceFailure,
    GuestProfile, IamPlugin, IamStore, Identity, PolicyDocument, PolicyStatement, ResourceRef,
    SecurityEventClaims, Session, SessionClientInfo, SignInRecord, SubjectIdentifier, Tenant,
};

// The model types of the API (feature flags, agents, teams and departments, billing, threats, devices, signals,
// licenses, guests, clearances, keys and certificates, data protection).
#[cfg(feature = "server")]
pub use better_iam_types::{
    AccountOverview, AdjudicationMode, AgentDetail, AgentListing, AgentStanding, AgentSummary,
    AliasSummary, AuthorityCreateInput, AuthoritySummary, BillingBudgetView, BirthrightSuggestion,
    BudgetStanding, BudgetStatus, CertificateIssueInput, CertificateSummary,
    ClassificationSchemeInput, ClassificationSchemeView, ClassificationTemplateName,
    ClassificationTemplateView, ClearanceExplanation, ClearanceGrantInput, ClearancePage,
    ClearancePartyView, ClearanceReadInView, ClearanceStatus, ClearanceUpdateInput, ClearanceView,
    ComplianceResult, ConfirmationSummary, CreditNoteView, CreditView, CrossTenantPartner,
    CsvExport, DataType, DelegatedCredential, DelegationSummary, DepartmentDetail,
    DepartmentMemberView, DepartmentNode, DepartmentSummary, DetectionPage, DeviceAssurance,
    DeviceCheck, DeviceDetail, DeviceEnrollmentCode, DeviceIntegrationView, DevicePlatform,
    DeviceReport, DeviceReportResult, DeviceSettingsView, DeviceView, DiscountView,
    EffectiveClearanceStatus, EncryptionContext, FeatureEvaluation, FeatureFlagDefinition,
    FeatureFlagView, FeatureReason, FeatureTargetView, GrantSummary, GuestAccountStatus,
    GuestInvitationStatus, GuestInvitationView, GuestInviteInput, GuestPage, GuestRemoval,
    GuestSettingsInput, GuestSettingsView, GuestView, IdentityRiskView, InboundGuestSettings,
    IncidentDetail, IncidentPage, IncidentResolution, IncidentStatus, InferenceBudgetView,
    InvoiceDocument, InvoiceItemView, InvoicePayment, InvoiceStatus, IssuedCertificate,
    JwtVerification, KeyCreateInput, KeySpec, KeySummary, KeyUsage, LicenseAssignmentView,
    LicensePoolView, LicenseProductView, LicenseSeatChange, LicenseSeatStatus, LicenseSeatView,
    LicenseSettingsView, LicenseUsage, LicenseUsageReport, MaskStyle, MeterView, MyClearance,
    MyDepartment, MyDevice, MyLicense, MyLicenses, MyTeams, OutboundGuestSettings, PlanView,
    PriceView, ProfileCreateInput, ProfileSummary, ProfileView, PublicKeyView, PublicModel,
    PublicProvider, ResourceLabelPage, ResourceLabelState, ResourceLabelView, ResponseAction,
    RiskLevel, RiskPage, SignalEventPage, SignalEventType, SignalEventView, SignalPollResult,
    SignalSourceCreateInput, SignalSourceCreated, SignalSourceUpdateInput, SignalSourceView,
    SignalStatus, SignedAgentCard, SpendAnomaly, SpendCheck, SpendGroupBy, SpendReport, SpendRow,
    SpendTrend, StatementAllocation, StatementDraft, StatementLine, StatementSummary,
    SubscriptionView, SuspiciousActivityReport, TeamDetail, TeamJoinRequestView, TeamMemberView,
    TeamRole, TeamSummary, TermsView, ThreatDetectionRun, ThreatDetectionView, ThreatIncidentView,
    ThreatNote, ThreatPlaybook, ThreatPlaybookInput, ThreatResponse, ThreatRuleId, ThreatRuleView,
    ThreatSettingsInput, ThreatSettingsView, ThreatSeverity, ThreatSubject, ThreatSubjectView,
    ThreatSummary, TierLine, TokenFormat, UsageInput, UsageReceipt, UsageReport, UsageRow,
};
