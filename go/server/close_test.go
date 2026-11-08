package server

import (
	"context"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

// Close stops the background work and leaves the store open, as in TypeScript, where the instance has no close and
// the database belongs to whoever opened it: the store keeps serving the instance and the application closes it.
func TestCloseLeavesTheStoreOpen(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	iam, err := New(&BetterIamOptions{
		Database: store, Secret: testSecret, BaseURL: "http://localhost:3000", AccessUsage: On[AccessUsageOptions](),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := iam.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	iam.Close()
	iam.Close() // idempotent
	if _, err := iam.Bootstrap(ctx, core.NewObject("email", "root@example.test", "name", "Root", "password", "a strong root test password")); err != nil {
		t.Fatalf("the store was closed: %v", err)
	}
	if _, err := iam.FlushAccessUsage(ctx); err != nil {
		t.Fatal(err)
	}
	if err := iam.Store.Close(ctx); err != nil {
		t.Fatal(err)
	}
}
