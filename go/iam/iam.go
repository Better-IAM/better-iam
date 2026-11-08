// Package iam is the umbrella import of better-iam (port of packages/better-iam/src/index.ts): the server
// constructor, the policy and audit helpers, assertion and webhook verification, and the types an application
// usually names, re-exported from go/server, go/core and go/apitypes.
//
//	import "github.com/Better-IAM/better-iam/go/iam"
//
//	server, err := iam.New(&iam.BetterIamOptions{Database: store, Secret: secret, BaseURL: "https://app.example.com"})
//	policy, err := iam.DefinePolicy(iam.PolicyDocument{Version: 1, Statements: statements})
//
// The npm umbrella's subpath exports are the module's other packages:
//
//	better-iam/client, client-session, client-device  github.com/Better-IAM/better-iam/go/client
//	better-iam/projects                                 github.com/Better-IAM/better-iam/go/projects
//	better-iam/server                                   github.com/Better-IAM/better-iam/go/server
//	better-iam/core                                     github.com/Better-IAM/better-iam/go/core
//	better-iam/auth                                     github.com/Better-IAM/better-iam/go/auth
//	better-iam/adapter-sqlite, -postgres, -libsql       github.com/Better-IAM/better-iam/go/adapters/{sqlite,postgres,libsql}
//	better-iam/cli loadConfig (a configuration file)    github.com/Better-IAM/better-iam/go/configfile
//
// The browser-only and framework entry points (passkeys ceremony helpers, React, Vue, Svelte, Next.js, NestJS) have
// no Go form. TypeScript types that describe records the Go server keeps as *core.Object (Department, Team,
// BillingStatement, RegisteredDevice, ...) have no alias here; the request and answer types of every route are in
// go/apitypes.
package iam

import (
	"context"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

// New composes the IAM server (betterIam): it validates the configuration and the catalog and wires every module.
func New(options *BetterIamOptions) (*BetterIam, error) { return server.New(options) }

// IamError is the error every module raises: a stable code, a message and an HTTP status.
type IamError = core.IamError

// NewIamError builds an IamError; the status defaults to 400.
func NewIamError(code, message string, status ...int) *IamError {
	return core.NewIamError(code, message, status...)
}

// Inputs and results of the helpers below.
type (
	EvaluationInput         = core.EvaluationInput
	VerifyAuditChainOptions = core.VerifyAuditChainOptions
	AuditChainVerification  = core.AuditChainVerification
	VerifyAssertionOptions  = server.VerifyAssertionOptions
	VerifyWebhookInput      = server.VerifyWebhookInput
)

// DefinePolicy validates a policy document and returns it (definePolicy).
func DefinePolicy(document PolicyDocument) (*PolicyDocument, error) {
	return core.DefinePolicy(document)
}

// EvaluatePolicy evaluates policies for a request (evaluatePolicy).
func EvaluatePolicy(input EvaluationInput) (Decision, error) { return core.EvaluatePolicy(input) }

// ValidatePolicy checks a policy document of any shape (validatePolicy).
func ValidatePolicy(document any) error { return core.ValidatePolicy(document) }

// VerifyAuditChain verifies the hash chain of audit events (verifyAuditChain).
func VerifyAuditChain(events []*core.Object, options VerifyAuditChainOptions) AuditChainVerification {
	return core.VerifyAuditChain(events, options)
}

// AppendAuditEvent appends an event to its tenant's audit chain inside a transaction (appendAuditEvent).
func AppendAuditEvent(ctx context.Context, tx IamStore, event *core.Object) (*core.Object, error) {
	return core.AppendAuditEvent(ctx, tx, event)
}

// CanonicalJSON is the canonical JSON the audit chain hashes (canonicalJson).
func CanonicalJSON(value any) string { return core.CanonicalJSON(value) }

// VerifyAssertion verifies a signed authorization assertion (verifyAssertion).
func VerifyAssertion(token any, options VerifyAssertionOptions) (*core.Object, error) {
	return server.VerifyAssertion(token, options)
}

// AssertionKey derives the assertion verification key from the server secret (assertionKey).
func AssertionKey(secret string) string { return server.AssertionKey(secret) }

// VerifyWebhookSignature checks a webhook delivery's signature (verifyWebhookSignature).
func VerifyWebhookSignature(input VerifyWebhookInput) bool {
	return server.VerifyWebhookSignature(input)
}

// CreateCertificateRequest builds a PKCS #10 certificate signing request for the private CA
// (createCertificateRequest).
func CreateCertificateRequest(input *core.Object) (string, error) {
	return server.CreateCertificateRequest(input)
}

// The server and its options.
type (
	BetterIam            = server.BetterIam
	BetterIamOptions     = server.BetterIamOptions
	AuthorizationRequest = server.AuthorizationRequest
	ProtocolMount        = server.ProtocolMount
)

// Feature flags.
type (
	FeatureEvaluation     = apitypes.FeatureEvaluation
	FeatureFlagDefinition = apitypes.FeatureFlagDefinition
	FeatureFlagView       = apitypes.FeatureFlagView
	FeatureReason         = apitypes.FeatureReason
	FeatureTargetView     = apitypes.FeatureTargetView
	IamFeatures           = server.IamFeatures
)

// Agents, delegation and the inference gateway.
type (
	A2aOptions          = server.A2aOptions
	AgentDetail         = apitypes.AgentDetail
	AgentListing        = apitypes.AgentListing
	AgentProfile        = core.AgentProfile
	AgentStanding       = apitypes.AgentStanding
	AgentSummary        = apitypes.AgentSummary
	SignedAgentCard     = apitypes.SignedAgentCard
	BudgetStanding      = apitypes.BudgetStanding
	ConfirmationSummary = apitypes.ConfirmationSummary
	DelegatedCredential = apitypes.DelegatedCredential
	DelegationSummary   = apitypes.DelegationSummary
	InferenceBudgetView = apitypes.InferenceBudgetView
	InferenceOptions    = server.InferenceOptions
	PublicModel         = apitypes.PublicModel
	PublicProvider      = apitypes.PublicProvider
	UsageReport         = apitypes.UsageReport
	UsageRow            = apitypes.UsageRow
)

// Teams inside an organization and its departments.
type (
	BirthrightSuggestion = apitypes.BirthrightSuggestion
	DepartmentDetail     = apitypes.DepartmentDetail
	DepartmentMemberView = apitypes.DepartmentMemberView
	DepartmentNode       = apitypes.DepartmentNode
	DepartmentSummary    = apitypes.DepartmentSummary
	MyDepartment         = apitypes.MyDepartment
	MyTeams              = apitypes.MyTeams
	TeamDetail           = apitypes.TeamDetail
	TeamJoinRequestView  = apitypes.TeamJoinRequestView
	TeamMemberView       = apitypes.TeamMemberView
	TeamRole             = apitypes.TeamRole
	TeamSummary          = apitypes.TeamSummary
)

// Billing and spend tracking.
type (
	AccountOverview     = apitypes.AccountOverview
	BillingBudgetView   = apitypes.BillingBudgetView
	BillingOptions      = server.BillingOptions
	BudgetStatus        = apitypes.BudgetStatus
	CreditView          = apitypes.CreditView
	IamBilling          = server.IamBilling
	MeterView           = apitypes.MeterView
	PriceView           = apitypes.PriceView
	ProfileView         = apitypes.ProfileView
	CsvExport           = apitypes.CsvExport
	SpendAnomaly        = apitypes.SpendAnomaly
	SpendCheck          = apitypes.SpendCheck
	SpendGroupBy        = apitypes.SpendGroupBy
	SpendReport         = apitypes.SpendReport
	SpendRow            = apitypes.SpendRow
	SpendTrend          = apitypes.SpendTrend
	StatementAllocation = apitypes.StatementAllocation
	StatementDraft      = apitypes.StatementDraft
	StatementSummary    = apitypes.StatementSummary
	TermsView           = apitypes.TermsView
	UsageInput          = apitypes.UsageInput
	UsageReceipt        = apitypes.UsageReceipt
)

// Invoicing: invoice items, payments, credit notes, plans, subscriptions and coupons.
type (
	CouponView       = apitypes.CouponView
	CreditNoteView   = apitypes.CreditNoteView
	DiscountView     = apitypes.DiscountView
	InvoiceDocument  = apitypes.InvoiceDocument
	InvoiceIssuer    = server.InvoiceIssuer
	InvoiceItemView  = apitypes.InvoiceItemView
	InvoicePayment   = apitypes.InvoicePayment
	InvoiceStatus    = apitypes.InvoiceStatus
	PlanView         = apitypes.PlanView
	StatementLine    = apitypes.StatementLine
	SubscriptionView = apitypes.SubscriptionView
	TierLine         = apitypes.TierLine
)

// Identity threat detection and response.
type (
	DetectionPage            = apitypes.DetectionPage
	IdentityRiskView         = apitypes.IdentityRiskView
	IncidentDetail           = apitypes.IncidentDetail
	IncidentPage             = apitypes.IncidentPage
	IncidentResolution       = apitypes.IncidentResolution
	IncidentStatus           = apitypes.IncidentStatus
	ResponseAction           = apitypes.ResponseAction
	RiskLevel                = apitypes.RiskLevel
	RiskPage                 = apitypes.RiskPage
	SuspiciousActivityReport = apitypes.SuspiciousActivityReport
	ThreatDetectionRun       = apitypes.ThreatDetectionRun
	ThreatDetectionView      = apitypes.ThreatDetectionView
	ThreatIncidentView       = apitypes.ThreatIncidentView
	ThreatNote               = apitypes.ThreatNote
	ThreatPlaybook           = apitypes.ThreatPlaybook
	ThreatPlaybookInput      = apitypes.ThreatPlaybookInput
	ThreatResponse           = apitypes.ThreatResponse
	ThreatRuleId             = apitypes.ThreatRuleId
	ThreatRuleView           = apitypes.ThreatRuleView
	ThreatSettingsInput      = apitypes.ThreatSettingsInput
	ThreatSettingsView       = apitypes.ThreatSettingsView
	ThreatSeverity           = apitypes.ThreatSeverity
	ThreatSubject            = apitypes.ThreatSubject
	ThreatSubjectView        = apitypes.ThreatSubjectView
	ThreatSummary            = apitypes.ThreatSummary
)

// Device posture.
type (
	ComplianceResult      = apitypes.ComplianceResult
	DeviceAssurance       = apitypes.DeviceAssurance
	DeviceCheck           = apitypes.DeviceCheck
	DeviceDetail          = apitypes.DeviceDetail
	DeviceEnrollmentCode  = apitypes.DeviceEnrollmentCode
	DeviceIntegrationView = apitypes.DeviceIntegrationView
	DevicePlatform        = apitypes.DevicePlatform
	DeviceReport          = apitypes.DeviceReport
	DeviceReportResult    = apitypes.DeviceReportResult
	DeviceSettingsView    = apitypes.DeviceSettingsView
	DeviceView            = apitypes.DeviceView
	MyDevice              = apitypes.MyDevice
)

// Shared Signals receiver.
type (
	IamSignals              = server.IamSignals
	SecurityEventClaims     = core.SecurityEventClaims
	SignalEventPage         = apitypes.SignalEventPage
	SignalEventType         = core.SignalEventType
	SignalEventView         = apitypes.SignalEventView
	SignalPollResult        = apitypes.SignalPollResult
	SignalSourceCreated     = apitypes.SignalSourceCreated
	SignalSourceCreateInput = apitypes.SignalSourceCreateInput
	SignalSourceUpdateInput = apitypes.SignalSourceUpdateInput
	SignalSourceView        = apitypes.SignalSourceView
	SignalStatus            = apitypes.SignalStatus
	SignalsOptions          = server.SignalsOptions
	SubjectIdentifier       = core.SubjectIdentifier
)

// License management.
type (
	IamLicenses           = server.IamLicenses
	LicenseAssignmentView = apitypes.LicenseAssignmentView
	LicensePoolView       = apitypes.LicensePoolView
	LicenseProductView    = apitypes.LicenseProductView
	LicenseSeatChange     = apitypes.LicenseSeatChange
	LicenseSeatStatus     = apitypes.LicenseSeatStatus
	LicenseSeatView       = apitypes.LicenseSeatView
	LicenseSettingsView   = apitypes.LicenseSettingsView
	LicenseUsage          = apitypes.LicenseUsage
	LicenseUsageReport    = apitypes.LicenseUsageReport
	MyLicense             = apitypes.MyLicense
	MyLicenses            = apitypes.MyLicenses
)

// B2B guest collaboration.
type (
	CrossTenantPartner    = apitypes.CrossTenantPartner
	GuestAccountStatus    = apitypes.GuestAccountStatus
	GuestInvitationStatus = apitypes.GuestInvitationStatus
	GuestInvitationView   = apitypes.GuestInvitationView
	GuestInviteInput      = apitypes.GuestInviteInput
	GuestPage             = apitypes.GuestPage
	GuestProfile          = core.GuestProfile
	GuestRemoval          = apitypes.GuestRemoval
	GuestSettingsInput    = apitypes.GuestSettingsInput
	GuestSettingsView     = apitypes.GuestSettingsView
	GuestView             = apitypes.GuestView
	IamGuests             = server.IamGuests
	InboundGuestSettings  = apitypes.InboundGuestSettings
	OutboundGuestSettings = apitypes.OutboundGuestSettings
)

// Security clearances and mandatory access control.
type (
	AdjudicationMode               = apitypes.AdjudicationMode
	ClassificationLabel            = core.ClassificationLabel
	ClassificationLevel            = core.ClassificationLevel
	ClassificationSchemeDefinition = core.ClassificationSchemeDefinition
	ClassificationSchemeInput      = apitypes.ClassificationSchemeInput
	ClassificationSchemeView       = apitypes.ClassificationSchemeView
	ClassificationTemplateName     = apitypes.ClassificationTemplateName
	ClassificationTemplateView     = apitypes.ClassificationTemplateView
	ClearanceExplanation           = apitypes.ClearanceExplanation
	ClearanceGrantInput            = apitypes.ClearanceGrantInput
	ClearanceOptions               = server.ClearanceOptions
	ClearancePage                  = apitypes.ClearancePage
	ClearancePartyView             = apitypes.ClearancePartyView
	ClearanceReadInView            = apitypes.ClearanceReadInView
	ClearanceStatus                = apitypes.ClearanceStatus
	ClearanceUpdateInput           = apitypes.ClearanceUpdateInput
	ClearanceView                  = apitypes.ClearanceView
	Compartment                    = core.Compartment
	DominanceFailure               = core.DominanceFailure
	EffectiveClearanceStatus       = apitypes.EffectiveClearanceStatus
	IamClearances                  = server.IamClearances
	MyClearance                    = apitypes.MyClearance
	ResourceLabelPage              = apitypes.ResourceLabelPage
	ResourceLabelState             = apitypes.ResourceLabelState
	ResourceLabelView              = apitypes.ResourceLabelView
)

// Key management and the private certificate authority.
type (
	AliasSummary          = apitypes.AliasSummary
	AuthorityCreateInput  = apitypes.AuthorityCreateInput
	AuthoritySummary      = apitypes.AuthoritySummary
	CertificateIssueInput = apitypes.CertificateIssueInput
	CertificateSummary    = apitypes.CertificateSummary
	EncryptionContext     = apitypes.EncryptionContext
	GrantSummary          = apitypes.GrantSummary
	IssuedCertificate     = apitypes.IssuedCertificate
	JwtVerification       = apitypes.JwtVerification
	KeyCreateInput        = apitypes.KeyCreateInput
	KeySpec               = apitypes.KeySpec
	KeySummary            = apitypes.KeySummary
	KeyUsage              = apitypes.KeyUsage
	PublicKeyView         = apitypes.PublicKeyView
)

// Data protection (tokenization).
type (
	DataType           = apitypes.DataType
	MaskStyle          = apitypes.MaskStyle
	ProfileCreateInput = apitypes.ProfileCreateInput
	ProfileSummary     = apitypes.ProfileSummary
	TokenFormat        = apitypes.TokenFormat
)

// Records, policies and storage (go/core).
type (
	PolicyDocument    = core.PolicyDocument
	PolicyStatement   = core.PolicyStatement
	Decision          = core.Decision
	IamPlugin         = core.IamPlugin
	IamStore          = core.IamStore
	CredentialInput   = core.CredentialInput
	ResourceRef       = core.ResourceRef
	Identity          = core.Identity
	Tenant            = core.Tenant
	Session           = core.Session
	SessionClientInfo = core.SessionClientInfo
	SignInRecord      = core.SignInRecord
	AuditEvent        = core.AuditEvent
)
