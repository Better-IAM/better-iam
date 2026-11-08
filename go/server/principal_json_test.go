package server

// Principal value encoding, after principals.ts authenticate: a principal is {identity, session}, with deviceProof
// spread in only when the request carried one. ToModel (the API and conformance value encoding) goes through JSON,
// so the Go field names must never leak.

import (
	"reflect"
	"testing"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

func principalModelKeys(t *testing.T, value any) (*core.Object, []string) {
	t.Helper()
	model, err := ToModel(value)
	if err != nil {
		t.Fatalf("ToModel: %v", err)
	}
	object, ok := model.(*core.Object)
	if !ok {
		t.Fatalf("ToModel returned %T, want an object", model)
	}
	return object, object.Keys()
}

func TestPrincipalEncodesWithTypeScriptMemberNames(t *testing.T) {
	identity := core.NewObject("id", "identity-1", "tenantId", "tenant-1")
	session := core.NewObject("id", "session-1", "identityId", "identity-1")

	object, keys := principalModelKeys(t, &Principal{Identity: identity, Session: session})
	if want := []string{"identity", "session"}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("principal keys = %v, want %v", keys, want)
	}
	if got, _ := object.Get("identity").(*core.Object); got == nil || got.Get("id") != "identity-1" {
		t.Fatalf("identity = %v", object.Get("identity"))
	}
	if got, _ := object.Get("session").(*core.Object); got == nil || got.Get("id") != "session-1" {
		t.Fatalf("session = %v", object.Get("session"))
	}

	object, keys = principalModelKeys(t, &Principal{Identity: identity, Session: session, DeviceProof: "a.b.c"})
	if want := []string{"identity", "session", "deviceProof"}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("principal with a device proof keys = %v, want %v", keys, want)
	}
	if object.Get("deviceProof") != "a.b.c" {
		t.Fatalf("deviceProof = %v", object.Get("deviceProof"))
	}

	_, keys = principalModelKeys(t, &auth.Principal{Identity: identity, Session: session})
	if want := []string{"identity", "session"}; !reflect.DeepEqual(keys, want) {
		t.Fatalf("auth principal keys = %v, want %v", keys, want)
	}
}
