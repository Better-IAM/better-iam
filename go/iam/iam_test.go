package iam_test

import (
	"context"
	"errors"
	"testing"

	"github.com/Better-IAM/better-iam/go/adapters/sqlite"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/iam"
	"github.com/Better-IAM/better-iam/go/projects"
)

// The umbrella composes a working server and re-exports the helpers of the npm umbrella's root entry point.
func TestUmbrellaComposesTheServerAndReexportsTheHelpers(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.New(sqlite.Options{Filename: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = store.Close(ctx) }()
	server, err := iam.New(&iam.BetterIamOptions{
		Database: store, Secret: "umbrella-test-secret-with-at-least-32-chars", BaseURL: "http://localhost:3000",
		Plugins: []*iam.IamPlugin{projects.NewPlugin()},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	if err := server.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := server.Bootstrap(ctx, core.NewObject("email", "root@example.test", "name", "Root", "password", "a strong root test password")); err != nil {
		t.Fatal(err)
	}
	if _, err := iam.New(nil); err == nil {
		t.Fatal("iam.New(nil) must fail")
	}

	policy, err := iam.DefinePolicy(iam.PolicyDocument{Version: 1, Statements: []iam.PolicyStatement{{Effect: "allow", Actions: []string{"projects:read"}, Resources: []string{"*"}}}})
	if err != nil || policy.Version != 1 {
		t.Fatalf("DefinePolicy: %v %v", policy, err)
	}
	_, err = iam.DefinePolicy(iam.PolicyDocument{Version: 2})
	var refused *iam.IamError
	if !errors.As(err, &refused) || refused.Code != "INVALID_POLICY" {
		t.Fatalf("DefinePolicy of an invalid document: %v", err)
	}
	if err := iam.ValidatePolicy(core.NewObject("version", 1, "statements", []any{})); err == nil {
		// An empty statement list is accepted or refused exactly as core decides; both paths go through core.
		if core.ValidatePolicy(core.NewObject("version", 1, "statements", []any{})) != nil {
			t.Fatal("ValidatePolicy differs from core")
		}
	}
	if got, want := iam.CanonicalJSON(core.NewObject("b", 1, "a", "x")), core.CanonicalJSON(core.NewObject("b", 1, "a", "x")); got != want {
		t.Fatalf("CanonicalJSON %s, want %s", got, want)
	}
	if iam.AssertionKey("umbrella-test-secret-with-at-least-32-chars") != server.AssertionKey() {
		t.Fatal("AssertionKey differs from the server's")
	}
	if e := iam.NewIamError("CONFLICT", "taken", 409); e.Status != 409 || iam.NewIamError("X", "y").Status != 400 {
		t.Fatal("NewIamError statuses")
	}
}
