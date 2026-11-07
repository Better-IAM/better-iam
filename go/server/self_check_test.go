package server

// Port of tests/self-check.test.ts (the CLI `doctor` case is the CLI's). The retention sweep's dry run (countDue) is
// another module's; the scheduled-job checks are exercised with a stand-in that answers the backlog the sweep would
// report, through CreateSelfCheck's countDue parameter.

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/adapters/sqlite"
	"github.com/Better-IAM/better-iam/go/core"
)

const selfCheckSecret = "self-check-test-secret-with-at-least-32-characters"

// checksOf is the findings as { check: severity }, in order.
func checksOf(result *core.Object) string {
	var parts []string
	for _, finding := range result.Get("findings").([]any) {
		object := finding.(*core.Object)
		parts = append(parts, jsString(object.Get("check"))+":"+jsString(object.Get("severity")))
	}
	return strings.Join(parts, ",")
}

func findingOf(result *core.Object, check string) *core.Object {
	for _, finding := range result.Get("findings").([]any) {
		if object := finding.(*core.Object); object.Get("check") == check {
			return object
		}
	}
	return nil
}

// selfCheckWith is iam.selfCheck with countDue answering due (the sweep backlog) and the real secret sampler.
func selfCheckWith(iam *BetterIam, due *core.Object) func(ctx context.Context, options *core.Object) (*core.Object, error) {
	server := iam.Context
	return CreateSelfCheck(server, func(context.Context, *core.Object) (*core.Object, error) {
		if due == nil {
			return core.NewObject(), nil
		}
		return due, nil
	}, func(ctx context.Context, limit float64) (*SecretRotationResult, error) {
		return RotateSecrets(ctx, server, SecretRotationOptions{DryRun: true, Limit: &limit})
	})
}

func TestSelfCheckReportsADatabaseWithoutTheSchema(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.New(sqlite.Options{Filename: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(ctx) })
	iam, err := New(&BetterIamOptions{Database: store, Secret: selfCheckSecret, BaseURL: "http://localhost:3000"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(iam.Close)
	result := must(iam.SelfCheck(ctx, nil))
	if result.Get("ok") != false || checksOf(result) != "schema-behind:error,in-memory-database:warning,no-email-transport:warning" {
		t.Fatalf("unexpected findings %s", core.MustStringify(result))
	}
	storage := result.Get("storage").(*core.Object)
	if storage.Get("adapter") != "sqlite" || storage.Get("schemaVersion") != nil {
		t.Fatalf("unexpected storage %s", core.MustStringify(storage))
	}
	if message := findingOf(result, "schema-behind").Get("message"); message != "The database has no IAM schema" {
		t.Fatalf("unexpected message %v", message)
	}
	if err := iam.Initialize(ctx); err != nil {
		t.Fatal(err)
	}
	after := must(selfCheckWith(iam, nil)(ctx, nil))
	if checksOf(after) != "in-memory-database:warning,not-bootstrapped:error,no-email-transport:warning" {
		t.Fatalf("unexpected findings after initialize %s", checksOf(after))
	}
}

func TestSelfCheckPassesAHealthyDeploymentAndNoticesJobsThatAreNotRunning(t *testing.T) {
	f := newTenantsFixture(t, nil)
	check := selfCheckWith(f.iam, nil)
	healthy := must(check(f.ctx, nil))
	if healthy.Get("ok") != true || checksOf(healthy) != "in-memory-database:warning" {
		t.Fatalf("unexpected findings %s", checksOf(healthy))
	}
	now := f.now()
	minute := 60_000.0
	f.seed("authChallenges", core.NewObject("id", "c", "tenantId", "t", "expiresAt", now-2*lifecycleDay))
	f.seed("outbox",
		core.NewObject("id", "waiting", "tenantId", "t", "kind", "email", "createdAt", now-20*minute, "attempts", 0.0),
		core.NewObject("id", "dead", "tenantId", "t", "kind", "email", "createdAt", now-2*lifecycleDay, "attempts", 25.0, "failedAt", now-minute),
	)
	f.seed("auditHooks", core.NewObject("id", "hook", "tenantId", "t", "delivered", false, "event", core.NewObject("timestamp", now-20*minute)))
	behindCheck := selfCheckWith(f.iam, core.NewObject("oauthArtifacts", 6.0, "oauthLoginStates", 0.0))
	behind := must(behindCheck(f.ctx, core.NewObject("cap", 5.0)))
	if behind.Get("ok") != true || checksOf(behind) != "in-memory-database:warning,sweep-backlog:warning,purge-not-running:warning,"+
		"outbox-stalled:warning,outbox-abandoned:warning,audit-hooks-stalled:warning" {
		t.Fatalf("unexpected findings %s", checksOf(behind))
	}
	backlog := findingOf(behind, "sweep-backlog")
	message := jsString(backlog.Get("message"))
	if backlog.Get("count") != 5.0 || !strings.Contains(message, "5+") || !strings.Contains(message, "oauthArtifacts: 6") ||
		strings.Contains(message, "oauthLoginStates") {
		t.Fatalf("unexpected backlog %s", core.MustStringify(backlog))
	}
	if stalled := findingOf(behind, "outbox-stalled"); stalled.Get("count") != 1.0 ||
		stalled.Get("message") != "1 outgoing message(s) have waited more than 15 minutes" {
		t.Fatalf("unexpected stalled finding %s", core.MustStringify(stalled))
	}
	// Running the jobs clears their findings.
	must(f.iam.PurgeDeleted(f.ctx, nil))
	err := f.store.Transaction(f.ctx, func(ctx context.Context, tx core.IamStore) error {
		if err := tx.Delete(ctx, "outbox", "waiting"); err != nil {
			return err
		}
		return tx.Delete(ctx, "auditHooks", "hook")
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := checksOf(must(check(f.ctx, core.NewObject("cap", 5.0)))); got != "in-memory-database:warning,outbox-abandoned:warning" {
		t.Fatalf("after the jobs ran: %s", got)
	}
	for _, options := range []*core.Object{
		core.NewObject("cap", 0.0), core.NewObject("cap", "5"), core.NewObject("deliveryRetentionMs", -1.0),
		core.NewObject("graceMs", 2*lifecycleDay),
	} {
		_, err := check(f.ctx, options)
		if code := errorCodeOf(t, err); code != "INVALID_INPUT" {
			t.Fatalf("options %s: %s", core.MustStringify(options), code)
		}
	}
	_, err = check(f.ctx, core.NewObject("graceMs", 2*lifecycleDay))
	expectError(t, err, "INVALID_INPUT", "graceMs must be an integer between 0 and 86400000")
}

func TestSelfCheckFlagsSettingsThatCanLoseDataOrBeGuessed(t *testing.T) {
	ctx := context.Background()
	store, err := sqlite.New(sqlite.Options{Filename: filepath.Join(t.TempDir(), "risky.db"), JournalMode: "delete", Durability: "normal"})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(ctx) })
	token := "short-token"
	f := newTenantsFixture(t, func(options *BetterIamOptions) {
		options.Database = store
		options.Secret = "change-me-change-me-change-me-change-me"
		options.Observability = &ObservabilityOptions{Metrics: With(MetricsOptions{BearerToken: &token})}
	})
	result := must(selfCheckWith(f.iam, nil)(ctx, nil))
	if result.Get("ok") != false || checksOf(result) != "sqlite-durability:error,weak-secret:warning,weak-metrics-token:warning" {
		t.Fatalf("unexpected findings %s", checksOf(result))
	}
	if message := findingOf(result, "sqlite-durability").Get("message"); message != "SQLite runs a rollback journal with synchronous=normal, which a power failure can corrupt" {
		t.Fatalf("unexpected message %v", message)
	}
}

func TestSelfCheckAcceptsRandomSecretsAndReportsPendingRotations(t *testing.T) {
	f := newTenantsFixture(t, func(options *BetterIamOptions) {
		// 32 hex digits with only ten distinct characters: random, not a placeholder.
		options.Secret = "3d5f6a92a99f9dffd33aacb3d2563256"
		options.PreviousSecrets = []string{"an-older-secret-with-at-least-32-characters"}
	})
	result := must(selfCheckWith(f.iam, nil)(f.ctx, nil))
	if checksOf(result) != "in-memory-database:warning,previous-secrets-configured:info" {
		t.Fatalf("unexpected findings %s", checksOf(result))
	}
}

func TestPlaceholderSecretsFollowJavaScriptCaseFolding(t *testing.T) {
	for secret, weak := range map[string]bool{
		"CHANGE_ME-please-1234567890": true, "Example-secret-0123456789abcdef": true, "Password1234567890abcdefghij": true,
		"my-password-is-long-and-random-0123": false, "ſecret-0123456789abcdefghijklmn": false,
	} {
		if got := placeholderSecret.MatchString(asciiLower(secret)); got != weak {
			t.Errorf("%q: placeholder %v, want %v", secret, got, weak)
		}
	}
}
