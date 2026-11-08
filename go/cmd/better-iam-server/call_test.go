package main

import (
	"reflect"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

// decodedArgument is a call argument as /__conformance/call decodes it from the tagged JSON encoding.
func decodedArgument(t *testing.T, text string) any {
	t.Helper()
	parsed, err := core.ParseJSONString(text)
	if err != nil {
		t.Fatal(err)
	}
	return decodeValue(parsed)
}

func TestConvertArgumentCredentialHeaders(t *testing.T) {
	cases := map[string]string{
		"tagged headers": `{"headers":{"$headers":{"authorization":"Bearer abc","cookie":"a=1; b=2"}}}`,
		"plain headers":  `{"headers":{"authorization":"Bearer abc","cookie":"a=1; b=2"}}`,
	}
	for name, text := range cases {
		t.Run(name, func(t *testing.T) {
			converted, err := convertArgument(decodedArgument(t, text), credentialType, nil)
			if err != nil {
				t.Fatal(err)
			}
			credential := converted.Interface().(core.CredentialInput)
			if got := credential.Headers.Get("Authorization"); got != "Bearer abc" {
				t.Fatalf("Authorization = %q, want %q", got, "Bearer abc")
			}
			if got := credential.Headers.Get("Cookie"); got != "a=1; b=2" {
				t.Fatalf("Cookie = %q, want %q", got, "a=1; b=2")
			}
		})
	}
}

// A request type that extends CredentialInput carries token and headers beside its own members; JSON does not fill
// the Credential field (`json:"-"`), so the bridge must.
func TestConvertArgumentRequestCredential(t *testing.T) {
	text := `{"token":"tok","headers":{"$headers":{"authorization":"Bearer abc"}},"tenantId":"t1","action":"documents:read","resource":{"type":"document","id":"d1"}}`
	converted, err := convertArgument(decodedArgument(t, text), reflect.TypeOf(server.AuthorizationRequest{}), nil)
	if err != nil {
		t.Fatal(err)
	}
	request := converted.Interface().(server.AuthorizationRequest)
	if request.Credential.Token != "tok" || request.Credential.Headers.Get("Authorization") != "Bearer abc" {
		t.Fatalf("credential = %+v", request.Credential)
	}
	if request.TenantID != "t1" || request.Action != "documents:read" || request.Resource.ID != "d1" {
		t.Fatalf("request = %+v", request)
	}

	plan, err := convertArgument(decodedArgument(t, `{"headers":{"cookie":"s=1"},"tenantId":"t1","action":"a:b","type":"document"}`),
		reflect.TypeOf(server.PlanResourcesRequest{}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.Interface().(server.PlanResourcesRequest).Credential.Headers.Get("Cookie"); got != "s=1" {
		t.Fatalf("plan Cookie = %q", got)
	}

	batch, err := convertArgument(decodedArgument(t, `{"token":"tok","tenantId":"t1","checks":[{"action":"a:b","resource":{"type":"x","id":"1"}}]}`),
		reflect.TypeOf(server.BatchAuthorizationRequest{}), nil)
	if err != nil {
		t.Fatal(err)
	}
	if value := batch.Interface().(server.BatchAuthorizationRequest); value.Credential.Token != "tok" || value.ChecksValue == nil {
		t.Fatalf("batch = %+v", value)
	}
}
