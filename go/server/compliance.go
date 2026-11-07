package server

// Skeleton of packages/server/src/compliance.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// CheckParams (compliance.ts checkParams): Validates check parameters, filling defaults.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CheckParams(check *ComplianceCheck, value any) (result *core.Object, err error) {
	err = notImplemented("compliance.ts checkParams")
	return
}

// CheckpointID (compliance.ts checkpointId): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CheckpointID(tenantID string) (result string, err error) {
	err = notImplemented("compliance.ts checkpointId")
	return
}

// EffectiveParams (compliance.ts effectiveParams): Stored parameters brought within the check's current bounds
// (bounds tighten over releases).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func EffectiveParams(check *ComplianceCheck, stored *core.Object) (result *core.Object, err error) {
	err = notImplemented("compliance.ts effectiveParams")
	return
}

// ExceptionActive (compliance.ts exceptionActive): Whether an exception covers findings now.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ExceptionActive(exception *core.Object, now int64) (result bool, err error) {
	err = notImplemented("compliance.ts exceptionActive")
	return
}

// CheckByID is compliance.ts checkById.
var CheckByID any // STUB: compliance.ts checkById has no literal form; port it with the module

// ComplianceChecks is compliance.ts complianceChecks.
var ComplianceChecks any // STUB: compliance.ts complianceChecks has no literal form; port it with the module

// ComplianceFrameworks is compliance.ts complianceFrameworks.
var ComplianceFrameworks = mustModel(`[{"id":"soc2","name":"SOC 2 (Trust Services Criteria)","requirements":[{"id":"CC6.1","title":"Logical access security","checks":["mfa-enforced","mfa-coverage","password-length","session-lifetime","api-key-lifetime"]},{"id":"CC6.2","title":"Registration and deregistration of users","checks":["leaver-access","inactive-accounts"]},{"id":"CC6.3","title":"Role-based access, least privilege, and access review","checks":["access-reviews","privileged-access","separation-of-duties","stale-api-keys"]},{"id":"CC7.2","title":"Monitoring of system components","checks":["audit-integrity"]}]},{"id":"iso27001","name":"ISO/IEC 27001:2022 Annex A","requirements":[{"id":"5.3","title":"Segregation of duties","checks":["separation-of-duties"]},{"id":"5.16","title":"Identity management","checks":["leaver-access","inactive-accounts"]},{"id":"5.17","title":"Authentication information","checks":["password-length","api-key-lifetime"]},{"id":"5.18","title":"Access rights","checks":["access-reviews","stale-api-keys"]},{"id":"5.34","title":"Privacy and protection of PII","checks":["privacy-deadlines"]},{"id":"8.2","title":"Privileged access rights","checks":["privileged-access","owner-redundancy"]},{"id":"8.5","title":"Secure authentication","checks":["mfa-enforced","mfa-coverage","session-lifetime"]},{"id":"8.15","title":"Logging","checks":["audit-integrity"]}]},{"id":"nist-800-53","name":"NIST SP 800-53 Rev. 5","requirements":[{"id":"AC-2","title":"Account management","checks":["leaver-access","inactive-accounts"]},{"id":"AC-5","title":"Separation of duties","checks":["separation-of-duties"]},{"id":"AC-6","title":"Least privilege","checks":["privileged-access"]},{"id":"AC-6(7)","title":"Review of user privileges","checks":["access-reviews"]},{"id":"AC-12","title":"Session termination","checks":["session-lifetime"]},{"id":"IA-2(1)","title":"Multi-factor authentication","checks":["mfa-enforced","mfa-coverage"]},{"id":"IA-5","title":"Authenticator management","checks":["password-length","api-key-lifetime","stale-api-keys"]},{"id":"AU-9","title":"Protection of audit information","checks":["audit-integrity"]}]},{"id":"gdpr","name":"GDPR (selected articles)","requirements":[{"id":"Art. 12","title":"Responding to data subjects in time","checks":["privacy-deadlines"]},{"id":"Art. 32","title":"Security of processing","checks":["mfa-coverage","audit-integrity","leaver-access"]}]}]`)

// FrameworkByID is compliance.ts frameworkById.
var FrameworkByID = mustObject(`{"soc2":{"id":"soc2","name":"SOC 2 (Trust Services Criteria)","requirements":[{"id":"CC6.1","title":"Logical access security","checks":["mfa-enforced","mfa-coverage","password-length","session-lifetime","api-key-lifetime"]},{"id":"CC6.2","title":"Registration and deregistration of users","checks":["leaver-access","inactive-accounts"]},{"id":"CC6.3","title":"Role-based access, least privilege, and access review","checks":["access-reviews","privileged-access","separation-of-duties","stale-api-keys"]},{"id":"CC7.2","title":"Monitoring of system components","checks":["audit-integrity"]}]},"iso27001":{"id":"iso27001","name":"ISO/IEC 27001:2022 Annex A","requirements":[{"id":"5.3","title":"Segregation of duties","checks":["separation-of-duties"]},{"id":"5.16","title":"Identity management","checks":["leaver-access","inactive-accounts"]},{"id":"5.17","title":"Authentication information","checks":["password-length","api-key-lifetime"]},{"id":"5.18","title":"Access rights","checks":["access-reviews","stale-api-keys"]},{"id":"5.34","title":"Privacy and protection of PII","checks":["privacy-deadlines"]},{"id":"8.2","title":"Privileged access rights","checks":["privileged-access","owner-redundancy"]},{"id":"8.5","title":"Secure authentication","checks":["mfa-enforced","mfa-coverage","session-lifetime"]},{"id":"8.15","title":"Logging","checks":["audit-integrity"]}]},"nist-800-53":{"id":"nist-800-53","name":"NIST SP 800-53 Rev. 5","requirements":[{"id":"AC-2","title":"Account management","checks":["leaver-access","inactive-accounts"]},{"id":"AC-5","title":"Separation of duties","checks":["separation-of-duties"]},{"id":"AC-6","title":"Least privilege","checks":["privileged-access"]},{"id":"AC-6(7)","title":"Review of user privileges","checks":["access-reviews"]},{"id":"AC-12","title":"Session termination","checks":["session-lifetime"]},{"id":"IA-2(1)","title":"Multi-factor authentication","checks":["mfa-enforced","mfa-coverage"]},{"id":"IA-5","title":"Authenticator management","checks":["password-length","api-key-lifetime","stale-api-keys"]},{"id":"AU-9","title":"Protection of audit information","checks":["audit-integrity"]}]},"gdpr":{"id":"gdpr","name":"GDPR (selected articles)","requirements":[{"id":"Art. 12","title":"Responding to data subjects in time","checks":["privacy-deadlines"]},{"id":"Art. 32","title":"Security of processing","checks":["mfa-coverage","audit-integrity","leaver-access"]}]}}`)

// ComplianceCheck is compliance.ts ComplianceCheck.
type ComplianceCheck struct {
	server      *ServerContext
	ID          string
	Title       string
	Description string
	Params      []*core.Object
	// NoExceptions Exceptions may not cover this check's findings (a broken audit chain cannot be accepted).
	NoExceptions *bool
}

// Evaluate (compliance.ts ComplianceCheck.evaluate): `store` is read outside any transaction.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *ComplianceCheck) Evaluate(ctx context.Context, server *ServerContext, store core.IamStore, tenant *core.Object, params *core.Object, now int64) (result *CheckOutcome, err error) {
	err = notImplemented("compliance.ts ComplianceCheck.evaluate")
	return
}

// CheckOutcome is compliance.ts CheckOutcome.
type CheckOutcome struct {
	server   *ServerContext
	Findings []*core.Object
	Metrics  *core.Object
	// Checkpoint Audit verification progress to store (audit-integrity only).
	Checkpoint *core.Object
}

// Judge (compliance.ts CheckOutcome.judge): The status given the findings that no exception covers.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *CheckOutcome) Judge(remaining []*core.Object) (result *core.Object, err error) {
	err = notImplemented("compliance.ts CheckOutcome.judge")
	return
}
