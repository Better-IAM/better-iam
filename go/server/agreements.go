package server

// Skeleton of packages/server/src/agreements.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// AcceptanceCurrent (agreements.ts acceptanceCurrent): whether an acceptance covers the agreement's current version
// and has not lapsed.
func AcceptanceCurrent(agreement *core.Object, acceptance *core.Object, now int64) bool {
	if acceptance == nil || acceptance.Get("version") != agreement.Get("version") {
		return false
	}
	days := agreement.Get("reacceptAfterDays")
	return isUndefined(days) || float64(now)-jsNumber(acceptance.Get("acceptedAt")) < jsNumber(days)*86_400_000
}

// AgreementContext (agreements.ts agreementContext): policy context for a person in their own tenant:
// `principal.agreements` lists the names of agreements they have accepted in their current version, and
// `principal.pendingAgreements` counts required ones they still owe. Service accounts and agents cannot accept
// anything, so nothing is pending for them.
func AgreementContext(ctx context.Context, tx core.IamStore, tenantID string, identityID string, kind string, now int64) (*core.Object, error) {
	agreements, err := tx.Find(ctx, "agreements", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	if len(agreements) == 0 {
		return core.NewObject("principal.agreements", []any{}, "principal.pendingAgreements", 0.0), nil
	}
	found, err := tx.Find(ctx, "agreementAcceptances", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	acceptances := map[string]*core.Object{}
	for _, acceptance := range found {
		acceptances[jsString(acceptance.Get("agreementId"))] = acceptance
	}
	accepted := []string{}
	pending := 0.0
	for _, agreement := range agreements {
		if AcceptanceCurrent(agreement, acceptances[jsString(agreement.Get("id"))], now) {
			accepted = append(accepted, jsString(agreement.Get("name")))
		} else if truthy(agreement.Get("required")) && kind == "user" {
			pending++
		}
	}
	sortStable(accepted, compareUTF16)
	return core.NewObject("principal.agreements", stringsOf(accepted), "principal.pendingAgreements", pending), nil
}
