package server

// Skeleton of packages/server/src/privacy.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// ActiveHold (privacy.ts activeHold): The live legal hold on a subject, if any.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ActiveHold(ctx context.Context, tx core.IamStore, tenantID string, subject string, now int64) (result *core.Object, err error) {
	err = notImplemented("privacy.ts activeHold")
	return
}

// AssertNoLegalHold (privacy.ts assertNoLegalHold): Refuses to delete a person under a legal hold (`LEGAL_HOLD`,
// 409). Called from identity deletion, so every path that deletes (an administrator, an erasure request, a workflow,
// agent removal) is refused; offboarding and SCIM deprovisioning only disable the account, so its data stays anyway.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AssertNoLegalHold(ctx context.Context, tx core.IamStore, identity *core.Object, now int64) (err error) {
	err = notImplemented("privacy.ts assertNoLegalHold")
	return
}

// AssertNoTenantLegalHold (privacy.ts assertNoTenantLegalHold): Refuses to delete an organization (or the one above
// it) while a legal hold on anyone in it, or in a tenant below it, is active (`LEGAL_HOLD`, 409): deleting the
// tenant would purge the held people with it.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func AssertNoTenantLegalHold(ctx context.Context, tx core.IamStore, tenantID string, now int64, maxDepth float64) (err error) {
	err = notImplemented("privacy.ts assertNoTenantLegalHold")
	return
}

// ConsentContext (privacy.ts consentContext): Policy context for a person in their own tenant: `principal.consents`
// lists the keys of the consent and legitimate-interest purposes that may be processed for them right now (granted,
// not opted out, not objected to, not restricted). Service accounts and agents are not data subjects, so theirs is
// empty.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ConsentContext(ctx context.Context, tx core.IamStore, tenantID string, identity *core.Object, now int64) (result *core.Object, err error) {
	err = notImplemented("privacy.ts consentContext")
	return
}

// ConsentState (privacy.ts consentState): The processing decision for one purpose and subject. Restriction holds
// back everything except legal obligations and vital interests; bases other than consent and legitimate interests
// are allowed without a record. Opt-out purposes and legitimate interests are allowed until the person withdraws or
// objects; opt-in consent needs a live grant for the current version (unless the purpose keeps older grants valid).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ConsentState(purpose *core.Object, consent *core.Object, restricted any, now int64) (result *core.Object, err error) {
	err = notImplemented("privacy.ts consentState")
	return
}

// ConsentsOf (privacy.ts consentsOf): The subject's current decision on every purpose, keyed by purpose ID.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ConsentsOf(ctx context.Context, tx core.IamStore, tenantID string, subject string) (result map[string]*core.Object, err error) {
	err = notImplemented("privacy.ts consentsOf")
	return
}

// Days (privacy.ts days): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func Days(value any, name string, maxValue float64) (result float64, err error) {
	err = notImplemented("privacy.ts days")
	return
}

// Decidable (privacy.ts decidable): Purposes a person decides on: consent (opt-in or opt-out) and legitimate
// interests (objection).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func Decidable(purpose *core.Object) (result bool, err error) {
	err = notImplemented("privacy.ts decidable")
	return
}

// EmailSubject (privacy.ts emailSubject): The subject of a request from someone without an account: a keyed hash of
// their address, so a redacted request cannot be matched back to an email by hashing guesses.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func EmailSubject(secret string, address string) (result string, err error) {
	err = notImplemented("privacy.ts emailSubject")
	return
}

// ExternalSubjectID (privacy.ts externalSubjectId): Application-side subject identifiers: 1-256 visible characters
// (a customer number, a visitor ID, an email hash).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ExternalSubjectID(value any) (result string, err error) {
	err = notImplemented("privacy.ts externalSubjectId")
	return
}

// IdentitySubject (privacy.ts identitySubject): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func IdentitySubject(identityID string) (result string, err error) {
	err = notImplemented("privacy.ts identitySubject")
	return
}

// MentionsConsents (privacy.ts mentionsConsents): whether any statement of the documents names `principal.consents`
// in a condition.
func MentionsConsents(documents []any) bool {
	return anyConditionNames(documents, "principal.consents")
}

// OneOf (privacy.ts oneOf): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func OneOf(value any, allowed []any, name string) (result any, err error) {
	err = notImplemented("privacy.ts oneOf")
	return
}

// PrivacySettings (privacy.ts privacySettings): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PrivacySettings(ctx context.Context, tx core.IamStore, tenantID string) (result *core.Object, err error) {
	err = notImplemented("privacy.ts privacySettings")
	return
}

// Prose (privacy.ts prose): Free text up to `max` characters over several lines (tabs and line breaks allowed, other
// controls not).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func Prose(value any, name string, maxValue float64) (result string, err error) {
	err = notImplemented("privacy.ts prose")
	return
}

// PurposeKey (privacy.ts purposeKey): A purpose key: 1-64 lowercase letters, digits, dots, underscores or hyphens,
// starting with a letter.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func PurposeKey(value any) (result string, err error) {
	err = notImplemented("privacy.ts purposeKey")
	return
}

// ReceiptFromEvent (privacy.ts receiptFromEvent): The receipt of a recorded decision; receipts are deterministic, so
// they are rebuilt rather than stored.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReceiptFromEvent(secret string, event *core.Object) (result *core.Object, err error) {
	err = notImplemented("privacy.ts receiptFromEvent")
	return
}

// ReceiptSignatureValid (privacy.ts receiptSignatureValid): Whether a receipt was signed with one of the
// deployment's secrets (the current one or a previous one).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReceiptSignatureValid(secrets []string, receipt *core.Object) (result bool, err error) {
	err = notImplemented("privacy.ts receiptSignatureValid")
	return
}

// ReleasePrivacyRecords (privacy.ts releasePrivacyRecords): Removes a deleted person's current consent decisions and
// restriction. The consent history stays as proof of what was recorded (erasure redacts it separately), and
// data-subject requests stay as the record of their handling.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ReleasePrivacyRecords(ctx context.Context, tx core.IamStore, identity *core.Object) (err error) {
	err = notImplemented("privacy.ts releasePrivacyRecords")
	return
}

// RequestNumber (privacy.ts requestNumber): A request reference: `DSR-` and eight characters of Crockford base32.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RequestNumber() (result string, err error) {
	err = notImplemented("privacy.ts requestNumber")
	return
}

// RequestOverdue (privacy.ts requestOverdue): A request is overdue once its deadline passed while it is still being
// handled.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RequestOverdue(request *core.Object, now int64) (result bool, err error) {
	err = notImplemented("privacy.ts requestOverdue")
	return
}

// ResolveSubject (privacy.ts resolveSubject): Resolves a subject reference inside a tenant. Identities must be
// people (service accounts and agents have no privacy rights of their own) and, unless `allowDeleted`, not
// tombstones.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ResolveSubject(ctx context.Context, tx core.IamStore, tenantID string, value any, allowDeleted bool) (result *core.Object, err error) {
	err = notImplemented("privacy.ts resolveSubject")
	return
}

// ResponseWindow (privacy.ts responseWindow): The response window for a regulation, shortened by the tenant's own
// `responseDays` when set.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ResponseWindow(regulation string, settings *core.Object) (result *core.Object, err error) {
	err = notImplemented("privacy.ts responseWindow")
	return
}

// RestrictionOf (privacy.ts restrictionOf): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RestrictionOf(ctx context.Context, tx core.IamStore, tenantID string, subject string) (result *core.Object, err error) {
	err = notImplemented("privacy.ts restrictionOf")
	return
}

// RestrictionState (privacy.ts restrictionState): How a restriction record feeds `consentState`: none, an ordinary
// restriction, or an erasure's suppression marker.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func RestrictionState(restriction *core.Object) (result any, err error) {
	err = notImplemented("privacy.ts restrictionState")
	return
}

// DayMs is privacy.ts dayMs.
const DayMs = 86400000

// LegalBases is privacy.ts legalBases.
var LegalBases = []string{"consent", "contract", "legal-obligation", "vital-interests", "public-task", "legitimate-interests"}

// RegulationDeadlines is privacy.ts regulationDeadlines.
var RegulationDeadlines = mustObject(`{"gdpr":{"responseDays":30,"extensionDays":60},"uk-gdpr":{"responseDays":30,"extensionDays":60},"ccpa":{"responseDays":45,"extensionDays":45},"lgpd":{"responseDays":15,"extensionDays":0},"pipeda":{"responseDays":30,"extensionDays":30},"other":{"responseDays":30,"extensionDays":30}}`)

// Regulations is privacy.ts regulations.
var Regulations = []string{"gdpr", "uk-gdpr", "ccpa", "lgpd", "pipeda", "other"}

// RejectionReasons is privacy.ts rejectionReasons.
var RejectionReasons = []string{"unverified", "unfounded", "excessive", "exempt", "duplicate", "no-data", "other"}

// SubjectRequestTypes is privacy.ts subjectRequestTypes.
var SubjectRequestTypes = []string{"access", "portability", "erasure", "rectification", "restriction", "objection", "opt-out"}
