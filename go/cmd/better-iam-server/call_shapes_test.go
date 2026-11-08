package main

import (
	"context"
	"reflect"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

func callShaped(t *testing.T, fn any, path string, args ...any) any {
	t.Helper()
	result, err := invokeMember(context.Background(), reflect.ValueOf(fn), path, args, nil)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return core.MustStringify(encodeValue(result))
}

func TestCallShapesDispatchCount(t *testing.T) {
	dispatch := func(context.Context) (int, error) { return 0, nil }
	for _, path := range []string{"dispatchAuditHooks", "events.dispatch"} {
		if got := callShaped(t, dispatch, path); got != `{"dispatched":0}` {
			t.Fatalf("%s answered %s", path, got)
		}
	}
	// Other members keep their result.
	if got := callShaped(t, dispatch, "flushAccessUsage"); got != `0` {
		t.Fatalf("flushAccessUsage answered %s", got)
	}
}

func TestCallShapesNilIsUndefined(t *testing.T) {
	none := func(context.Context, string) (*core.Object, error) { return nil, nil }
	for _, path := range []string{"hosts.resolve", "ldap.tenantForBase", "ldap.resolveBindName"} {
		if got := callShaped(t, none, path, "x"); got != `{"$undefined":true}` {
			t.Fatalf("%s answered %s", path, got)
		}
	}
	found := func(context.Context, string) (*core.Object, error) { return core.NewObject("tenantId", "t1"), nil }
	if got := callShaped(t, found, "ldap.tenantForBase", "x"); got != `{"tenantId":"t1"}` {
		t.Fatalf("ldap.tenantForBase answered %s", got)
	}
}

func TestCallShapesAssertTrustChangeSpreadsInput(t *testing.T) {
	var gotToken, gotTenant, gotProvider string
	assert := func(_ context.Context, credential core.CredentialInput, tenantID, providerID string) error {
		gotToken, gotTenant, gotProvider = credential.Token, tenantID, providerID
		return nil
	}
	got := callShaped(t, assert, "protocolHost.assertTrustChange",
		core.NewObject("token", "biam_ses_x"), core.NewObject("tenantId", "t1", "providerId", "okta"))
	if got != `{"$undefined":true}` || gotToken != "biam_ses_x" || gotTenant != "t1" || gotProvider != "okta" {
		t.Fatalf("answered %s with (%q, %q, %q)", got, gotToken, gotTenant, gotProvider)
	}
}
