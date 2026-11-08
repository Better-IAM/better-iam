package server

import (
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

// The KMS service use names its caller as the audit actor: a protection call must keep its principal (kms.ts records
// `use.principal` as the actor, not the deployment operator).
func TestKmsUsePrincipalSurvivesProtectionUse(t *testing.T) {
	principal := &Principal{
		Identity:    core.NewObject("id", "usr_1", "kind", "user"),
		Session:     core.NewObject("id", "ses_1", "kind", "user"),
		DeviceProof: "proof",
	}
	if got := kmsUsePrincipal(protectionUse(principal)); got != principal {
		t.Fatalf("protectionUse lost its principal: %#v", got)
	}

	// A principal stored normalized (its JSON encoding) still reads back.
	normalized := core.NewObject("via", "protection", "principal", principal)
	got := kmsUsePrincipal(normalized)
	if got == nil {
		t.Fatal("normalized principal was not recognized")
	}
	if got.Identity.Get("id") != "usr_1" || got.Session.Get("id") != "ses_1" || got.DeviceProof != "proof" {
		t.Fatalf("normalized principal read back wrong: %#v", got)
	}
}
