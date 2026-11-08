package server

// The vault's records, validation and helpers (vault.ts), after tests/vault.test.ts, tests/vault-security.test.ts
// and tests/vault-review.test.ts. The API steps (api/vault.ts) are another unit; these tests drive the helpers the
// API is built on over an in-memory store. Steps that reach the KMS module (customer-managed keys) skip while it is
// a stub.

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

// vaultSecretRecord is a stored secret as api/vault.ts creates it.
func vaultSecretRecord(k *kernel, name string, members ...any) *core.Object {
	secret := core.NewObject(
		"id", ID(), "tenantId", "org", "uniqueKey", name, "name", name, "kind", "static", "format", "text",
		"tags", core.NewObject(), "status", "active", "stages", core.NewObject(), "latestVersion", 0.0, "maxVersions", 3.0,
		"createdAt", float64(k.server.Now()), "createdBy", "owner", "updatedAt", float64(k.server.Now()), "updatedBy", "owner",
	)
	for index := 0; index < len(members); index += 2 {
		secret.Set(members[index].(string), members[index+1])
	}
	k.insert(VaultCollections.Secrets, secret)
	return secret
}

func TestVaultValidatesNamesValuesAndSettings(t *testing.T) {
	for _, name := range []any{"../etc", "a//b", ".hidden", "a/-b", strings.Repeat("x", 65), strings.Repeat("a/", 16) + "a"} {
		_, err := SecretName(name)
		expectError(t, err, "INVALID_INPUT", "Secret names are 1-16 segments of letters, digits and _.- (not starting with . or -) separated by /")
	}
	_, err := SecretName(42.0)
	expectError(t, err, "INVALID_INPUT", "Invalid name")
	if must(SecretName("db/prod/app_1.key")) != "db/prod/app_1.key" {
		t.Fatal("name")
	}
	if must(SecretPrefix(core.Undefined)) != "" || must(SecretPrefix("")) != "" || must(SecretPrefix("db/")) != "db/" {
		t.Fatal("prefix")
	}
	_, err = SecretPrefix("../")
	expectCode(t, err, "INVALID_INPUT")

	tags := must(SecretTags(core.NewObject("team", "payments", "Env", "prod")))
	if stringify(tags) != `{"Env":"prod","team":"payments"}` {
		t.Fatalf("tags %s", stringify(tags))
	}
	_, err = SecretTags(core.NewObject("1bad", "x"))
	expectError(t, err, "INVALID_INPUT", "Invalid tag name 1bad")
	_, err = SecretTags(core.NewObject("env", ""))
	expectError(t, err, "INVALID_INPUT", "Invalid tag env")
	many := core.NewObject()
	for index := range 21 {
		many.Set("t"+core.NumberString(float64(index)), "v")
	}
	_, err = SecretTags(many)
	expectError(t, err, "INVALID_INPUT", "A secret has at most 20 tags")

	if must(StageName("blue-green")) != "blue-green" {
		t.Fatal("stage")
	}
	_, err = StageName("Blue")
	expectError(t, err, "INVALID_INPUT", "Stage labels are 1-32 lowercase letters, digits or hyphens, starting with a letter")
	if must(SecretFormat(core.Undefined)) != "text" || must(SecretFormat("json")) != "json" {
		t.Fatal("format")
	}
	_, err = SecretFormat("yaml")
	expectError(t, err, "INVALID_INPUT", "format must be text or json")

	k := newKernel(t, func(options *BetterIamOptions) { options.Vault = &VaultOptions{MaxValueBytes: float(16)} })
	settings := must(VaultSettings(k.server))
	_, err = SecretValue(settings, "json", core.NewObject("value", "[1,2]"))
	expectError(t, err, "INVALID_INPUT", "json secrets hold a JSON object")
	_, err = SecretValue(settings, "json", core.NewObject("value", "{not json"))
	expectError(t, err, "INVALID_INPUT", "json secrets hold a JSON object")
	_, err = SecretValue(settings, "text", core.NewObject("value", ""))
	expectError(t, err, "INVALID_INPUT", "value must be a nonempty string")
	_, err = SecretValue(settings, "text", core.NewObject("fields", core.NewObject("a", "b")))
	expectError(t, err, "INVALID_INPUT", "fields are for json secrets; pass value instead")
	_, err = SecretValue(settings, "text", core.NewObject("value", "é"+strings.Repeat("x", 15)))
	expectError(t, err, "INVALID_INPUT", "Secret values are at most 16 bytes")
	if must(SecretValue(settings, "json", core.NewObject("fields", core.NewObject("u", "a", "p", "")))) != `{"u":"a","p":""}` {
		t.Fatal("fields value")
	}

	_, err = RotationSettings(settings, "text", core.NewObject("rotator", "nope"), nil)
	expectError(t, err, "INVALID_INPUT", "Unknown rotator nope")

	for _, item := range []struct {
		options *VaultOptions
		message string
	}{
		{&VaultOptions{Rotators: map[string]VaultRotator{"Bad": {Rotate: func(context.Context, RotatorInput) error { return nil }}}}, "vault.rotators keys must be lowercase identifiers"},
		{&VaultOptions{Rotators: map[string]VaultRotator{"db": {}}}, "vault.rotators.db must have a rotate function"},
		{&VaultOptions{Engines: map[string]VaultEngine{"pg": {}}}, "vault.engines.pg must have a issue function"},
		{&VaultOptions{MaxValueBytes: float(8)}, "vault.maxValueBytes must be an integer from 16 to 1048576"},
		{&VaultOptions{MaxSecretsPerTenant: float(1.5)}, "vault.maxSecretsPerTenant must be an integer from 1 to 100000"},
		{&VaultOptions{AccessRetentionDays: float(0)}, "vault.accessRetentionDays must be an integer from 1 to 3650"},
		{&VaultOptions{CallTimeoutMs: float(999)}, "vault.callTimeoutMs must be an integer from 1000 to 300000"},
	} {
		_, err := VaultSettings(&ServerContext{Options: &BetterIamOptions{Vault: item.options}})
		expectError(t, err, "INVALID_CONFIG", item.message)
	}
	defaults := must(VaultSettings(&ServerContext{Options: &BetterIamOptions{}}))
	if stringify(defaults) != `{"rotators":{},"engines":{},"maxValueBytes":65536,"maxSecretsPerTenant":1000,"accessRetentionMs":7776000000,"callTimeoutMs":30000}` {
		t.Fatalf("defaults %s", stringify(defaults))
	}

	generated := must(GenerateValue(must(PasswordGenerator(core.NewObject("length", 12.0, "charset", "numeric", "eachClass", false)))))
	if !regexp.MustCompile(`^[0-9]{12}$`).MatchString(generated) {
		t.Fatalf("generated %q", generated)
	}
}

func TestVaultGeneratesValuesWithEveryKeptClass(t *testing.T) {
	generator := must(PasswordGenerator(core.Undefined))
	if stringify(generator) != `{"length":32,"charset":"alphanumeric","eachClass":true}` || stringify(must(PasswordGenerator(true))) != stringify(generator) {
		t.Fatalf("default generator %s", stringify(generator))
	}
	for range 50 {
		value := must(GenerateValue(generator))
		if len(value) != 32 || !regexp.MustCompile(`[a-z]`).MatchString(value) || !regexp.MustCompile(`[A-Z]`).MatchString(value) ||
			!regexp.MustCompile(`[0-9]`).MatchString(value) {
			t.Fatalf("value %q misses a class", value)
		}
	}
	ascii := must(PasswordGenerator(core.NewObject("length", 8.0, "charset", "ascii", "exclude", "!#$")))
	if stringify(ascii) != `{"length":8,"charset":"ascii","eachClass":true,"exclude":"!#$"}` {
		t.Fatalf("ascii generator %s", stringify(ascii))
	}
	for range 50 {
		value := must(GenerateValue(ascii))
		if len(value) != 8 || strings.ContainsAny(value, "!#$") || !regexp.MustCompile(`[^a-zA-Z0-9]`).MatchString(value) {
			t.Fatalf("ascii value %q", value)
		}
	}
	for _, item := range []struct {
		input   *core.Object
		message string
	}{
		{core.NewObject("length", 7.0), "Invalid generator.length"},
		{core.NewObject("charset", "emoji"), "generator.charset must be alphanumeric, ascii, hex, base64url or numeric"},
		{core.NewObject("eachClass", "yes"), "generator.eachClass must be a boolean"},
		{core.NewObject("charset", "numeric", "exclude", "0123"), "The generator must keep at least 10 characters"},
	} {
		_, err := PasswordGenerator(item.input)
		expectError(t, err, "INVALID_INPUT", item.message)
	}
}

func TestVaultValidatesRotationCheckoutAndLeaseSettings(t *testing.T) {
	k := newKernel(t, func(options *BetterIamOptions) {
		options.Vault = &VaultOptions{Rotators: map[string]VaultRotator{"db": {Rotate: func(context.Context, RotatorInput) error { return nil }}}}
	})
	settings := must(VaultSettings(k.server))
	if must(VaultSettings(k.server)) != settings {
		t.Fatal("settings are cached per options object")
	}
	previous := core.NewObject("intervalDays", 30.0, "lastRotatedAt", 5.0, "nextRotationAt", 10.0)
	if must(RotationSettings(settings, "text", core.Undefined, previous)) != previous {
		t.Fatal("undefined keeps the rotation")
	}
	if must(RotationSettings(settings, "text", nil, previous)) != nil {
		t.Fatal("null clears the rotation")
	}
	rotation := must(RotationSettings(settings, "json", core.NewObject("field", "password", "generator", true, "rotator", "db", "intervalDays", 7.0), previous))
	if stringify(rotation) != `{"intervalDays":7,"rotator":"db","generator":{"length":32,"charset":"alphanumeric","eachClass":true},"field":"password","lastRotatedAt":5}` {
		t.Fatalf("rotation %s", stringify(rotation))
	}
	for _, field := range []string{"__proto__", "constructor", "prototype"} {
		_, err := RotationSettings(settings, "json", core.NewObject("field", field, "generator", true), nil)
		expectError(t, err, "INVALID_INPUT", "rotation.field must be a field name of letters, digits and _.-")
	}
	_, err := RotationSettings(settings, "json", core.NewObject("generator", true), nil)
	expectError(t, err, "INVALID_INPUT", "json secrets name the field rotation replaces (rotation.field)")
	_, err = RotationSettings(settings, "text", core.NewObject("field", "password"), nil)
	expectError(t, err, "INVALID_INPUT", "rotation.field is for json secrets")
	_, err = RotationSettings(settings, "text", core.NewObject("intervalDays", 366.0), nil)
	expectError(t, err, "INVALID_INPUT", "Invalid rotation.intervalDays")
	if stringify(must(RotationSettings(settings, "text", core.NewObject("generator", false, "rotator", nil), nil))) != `{}` {
		t.Fatal("a false generator and a null rotator are none")
	}

	checkout := must(CheckoutPolicy(core.NewObject(), nil))
	if stringify(checkout) != `{"required":true,"exclusive":false,"maxDurationMs":3600000,"rotateOnCheckin":false,"requireReason":false}` {
		t.Fatalf("checkout %s", stringify(checkout))
	}
	_, err = CheckoutPolicy(core.NewObject("exclusive", "yes"), nil)
	expectError(t, err, "INVALID_INPUT", "checkout.exclusive must be a boolean")
	_, err = CheckoutPolicy(core.NewObject("maxDurationMs", 1000.0), nil)
	expectError(t, err, "INVALID_INPUT", "Invalid checkout.maxDurationMs")
	if must(CheckoutPolicy(nil, checkout)) != nil || must(CheckoutPolicy(core.Undefined, checkout)) != checkout {
		t.Fatal("checkout undefined and null")
	}

	lease := must(LeaseSettings(core.Undefined, nil))
	if stringify(lease) != `{"defaultTtlMs":3600000,"maxTtlMs":86400000}` {
		t.Fatalf("lease %s", stringify(lease))
	}
	if stringify(must(LeaseSettings(core.NewObject("defaultTtlMs", 2*vaultDay), nil))) != `{"defaultTtlMs":172800000,"maxTtlMs":172800000}` {
		t.Fatal("max follows a longer default")
	}
	_, err = LeaseSettings(core.NewObject("defaultTtlMs", 2*vaultHour, "maxTtlMs", vaultHour), nil)
	expectError(t, err, "INVALID_INPUT", "lease.defaultTtlMs must not exceed lease.maxTtlMs")
	if must(LeaseSettings(core.Undefined, lease)) != lease {
		t.Fatal("undefined keeps the lease settings")
	}

	if stringify(must(EngineConfig(core.Undefined))) != `{}` || stringify(must(EngineConfig(core.NewObject("role", "reader")))) != `{"role":"reader"}` {
		t.Fatal("engine config")
	}
	_, err = EngineConfig(strings.Repeat("x", 8191))
	expectError(t, err, "INVALID_INPUT", "engineConfig must be JSON of at most 8 KiB")
}

func TestVaultFieldsAreOwnProperties(t *testing.T) {
	fields := must(ParseFields(`{"username":"app","password":"p"}`))
	if must(OwnField(fields, "password")) != "p" || !isUndefined(must(OwnField(fields, "constructor"))) ||
		!isUndefined(must(OwnField(fields, "__proto__"))) || !isUndefined(must(OwnField(nil, "password"))) {
		t.Fatal("own fields")
	}
	_, err := ParseFields(`"text"`)
	expectError(t, err, "INVALID_INPUT", "json secrets hold a JSON object")
	_, err = ParseFields(`null`)
	expectError(t, err, "INVALID_INPUT", "json secrets hold a JSON object")
}

func TestVaultRedactsEveryFieldOfAJSONValueFromErrors(t *testing.T) {
	value := `{"username":"app","password":"initial-password","port":54321}`
	message := must(RedactedMessage(errors.New("ALTER ROLE app PASSWORD 'initial-password' failed on 54321"), []string{value, ""}))
	if message != "ALTER ROLE app PASSWORD '[redacted]' failed on [redacted]" {
		t.Fatalf("message %q", message)
	}
	// JSON-escaped, URL-encoded and base64 spellings are redacted too; short fields are left alone.
	secret := `p@ss "word"/1`
	for _, spelling := range []string{`p@ss \"word\"/1`, "p%40ss%20%22word%22%2F1", "cEBzcyAid29yZCIvMQ"} {
		if got := must(RedactedMessage("failed: "+spelling, []string{secret})); got != "failed: [redacted]" {
			t.Fatalf("spelling %q -> %q", spelling, got)
		}
	}
	if got := must(RedactedMessage(core.NewIamError("X", "line\nbreak"), nil)); got != "line break" {
		t.Fatalf("control characters %q", got)
	}
	if got := must(RedactedMessage(errors.New(""), nil)); got != "Unknown error" {
		t.Fatalf("empty %q", got)
	}
	if got := must(RedactedMessage(strings.Repeat("é", 600), nil)); got != strings.Repeat("é", 512) {
		t.Fatal("at most 512 characters")
	}
	if got := must(RedactedMessage(42.0, nil)); got != "42" {
		t.Fatalf("non-error %q", got)
	}
}

func TestVaultStoresVersionsAndMovesStages(t *testing.T) {
	k := newKernel(t, nil)
	k.tenantTree()
	secret := vaultSecretRecord(k, "db/app", "rotation", core.NewObject("intervalDays", 30.0, "failures", 2.0, "lastFailure", core.NewObject("at", 1.0, "message", "x")))
	var err error
	err = k.tx(func(ctx context.Context, tx core.IamStore) error {
		for index, value := range []string{"one", "two", "three", "four", "five"} {
			added := must(AddVersion(ctx, k.server, tx, secret, value, "put", "owner", nil))
			version := added.Get("version").(*core.Object)
			if version.Get("version") != float64(index+1) || version.Get("uniqueKey") != jsString(secret.Get("id"))+":"+core.NumberString(float64(index+1)) {
				t.Fatalf("version %s", stringify(version))
			}
			keys := strings.Join(version.Keys(), ",")
			if keys != "id,tenantId,uniqueKey,secretId,version,state,source,createdAt,createdBy,sealed" {
				t.Fatalf("version members %s", keys)
			}
			secret = added.Get("secret").(*core.Object)
			secret, err = PromoteVersion(ctx, k.server, tx, secret, float64(index+1), "owner", false)
			if err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if stringify(secret.Get("stages")) != `{"current":5,"previous":4}` {
		t.Fatalf("stages %s", stringify(secret.Get("stages")))
	}
	rotation := secret.Get("rotation").(*core.Object)
	now := float64(k.server.Now())
	if stringify(rotation) != `{"intervalDays":30,"lastRotatedAt":`+core.NumberString(now)+`,"nextRotationAt":`+core.NumberString(now+30*vaultDay)+`}` {
		t.Fatalf("rotation %s", stringify(rotation))
	}
	_ = k.tx(func(ctx context.Context, tx core.IamStore) error {
		versions := must(SecretVersions(ctx, tx, secret))
		if len(versions) != 3 || versions[0].Get("version") != 5.0 || versions[2].Get("version") != 3.0 {
			t.Fatalf("kept %d versions", len(versions))
		}
		current := must(SelectVersion(ctx, tx, secret, core.NewObject()))
		if must(OpenVersion(ctx, k.server, tx, current, nil)) != "five" {
			t.Fatal("current value")
		}
		previous := must(SelectVersion(ctx, tx, secret, core.NewObject("stage", "previous")))
		if must(OpenVersion(ctx, k.server, tx, previous, nil)) != "four" {
			t.Fatal("previous value")
		}
		third := must(SelectVersion(ctx, tx, secret, core.NewObject("version", 3.0)))
		if must(OpenStored(ctx, k.server, tx, third, nil)) != "three" {
			t.Fatal("version 3")
		}
		_, err := SelectVersion(ctx, tx, secret, core.NewObject("version", 3.0, "stage", "current"))
		expectError(t, err, "INVALID_INPUT", "Pass version or stage, not both")
		_, err = SelectVersion(ctx, tx, secret, core.NewObject("version", 1.0))
		expectError(t, err, "NOT_FOUND", "Version not found")
		_, err = SelectVersion(ctx, tx, secret, core.NewObject("stage", "pending"))
		expectError(t, err, "NOT_FOUND", "No version has this stage")
		_, err = SelectVersion(ctx, tx, secret, core.NewObject("stage", "constructor"))
		expectError(t, err, "NOT_FOUND", "Version not found")
		_, err = SelectVersion(ctx, tx, secret.Spread(core.NewObject("stages", core.NewObject())), core.NewObject())
		expectError(t, err, "NOT_FOUND", "This secret has no current version")
		_, err = OpenVersion(ctx, k.server, tx, third.Spread(core.NewObject("state", "disabled")), nil)
		expectError(t, err, "VERSION_DISABLED", "This version is disabled")
		if must(OpenStored(ctx, k.server, tx, third.Spread(core.NewObject("state", "disabled")), nil)) != "three" {
			t.Fatal("re-encryption opens disabled versions")
		}
		destroyed := third.Spread(core.NewObject("state", "destroyed"))
		destroyed.Delete("sealed")
		_, err = OpenVersion(ctx, k.server, tx, destroyed, nil)
		expectError(t, err, "VERSION_DESTROYED", "This version was destroyed")
		// A value opens only as the version it was sealed for.
		_, err = OpenStored(ctx, k.server, tx, third.Spread(core.NewObject("version", 4.0)), nil)
		expectError(t, err, "INVALID_SEALED_VALUE", "The secret value cannot be opened")
		return nil
	})

	// Rolling back to an older version keeps the rotation clock; a pending label on the new current is dropped.
	k.advance(1000)
	_ = k.tx(func(ctx context.Context, tx core.IamStore) error {
		staged := secret.Spread(core.NewObject("stages", core.NewObject("current", 5.0, "previous", 4.0, "pending", 3.0), "rotationPending", 3.0))
		rolled := must(PromoteVersion(ctx, k.server, tx, staged, 4, "owner", false))
		if stringify(rolled.Get("stages")) != `{"current":4,"previous":5,"pending":3}` || rolled.Get("rotationPending") != 3.0 {
			t.Fatalf("rolled back %s", stringify(rolled))
		}
		if stringify(rolled.Get("rotation")) != stringify(rotation) {
			t.Fatal("a rollback restarted the rotation clock")
		}
		promoted := must(PromoteVersion(ctx, k.server, tx, rolled, 3, "owner", true))
		if stringify(promoted.Get("stages")) != `{"current":3,"previous":4}` || promoted.Has("rotationPending") {
			t.Fatalf("promoted %s", stringify(promoted))
		}
		if promoted.Get("rotation").(*core.Object).Get("lastRotatedAt") != float64(k.server.Now()) {
			t.Fatal("a rotation records when it happened")
		}
		return nil
	})
}

func TestVaultSchedulesRotation(t *testing.T) {
	if must(ScheduleRotation(nil, 1, 2)) != nil {
		t.Fatal("no rotation")
	}
	if stringify(must(ScheduleRotation(core.NewObject("rotator", "db", "nextRotationAt", 9.0), 1, 2))) != `{"rotator":"db"}` {
		t.Fatal("no interval")
	}
	scheduled := must(ScheduleRotation(core.NewObject("intervalDays", 1.0, "lastRotatedAt", 1000.0), 0, 5))
	if scheduled.Get("nextRotationAt") != 1000+vaultDay {
		t.Fatalf("scheduled %s", stringify(scheduled))
	}
	overdue := must(ScheduleRotation(core.NewObject("intervalDays", 1.0), 0, int64(3*vaultDay)))
	if overdue.Get("nextRotationAt") != 3*vaultDay {
		t.Fatal("an overdue rotation is due now")
	}
}

func TestVaultLogsAccessAndListsLiveLeases(t *testing.T) {
	k := newKernel(t, func(options *BetterIamOptions) { options.Vault = &VaultOptions{AccessRetentionDays: float(2)} })
	k.tenantTree()
	secret := vaultSecretRecord(k, "shared/root")
	now := float64(k.server.Now())
	k.insert(VaultCollections.Leases,
		core.NewObject("id", "l2", "tenantId", "org", "secretId", secret.Get("id"), "state", "active", "issuedAt", 2.0, "expiresAt", now+1000),
		core.NewObject("id", "l1", "tenantId", "org", "secretId", secret.Get("id"), "state", "active", "issuedAt", 1.0, "expiresAt", now+1000),
		core.NewObject("id", "l3", "tenantId", "org", "secretId", secret.Get("id"), "state", "active", "issuedAt", 0.0, "expiresAt", now),
		core.NewObject("id", "l4", "tenantId", "org", "secretId", secret.Get("id"), "state", "ended", "issuedAt", 0.0, "expiresAt", now+1000),
	)
	_ = k.tx(func(ctx context.Context, tx core.IamStore) error {
		leases := must(LiveLeases(ctx, k.server, tx, secret))
		if len(leases) != 2 || leases[0].Get("id") != "l1" || leases[1].Get("id") != "l2" {
			t.Fatalf("live leases %d", len(leases))
		}
		if err := RecordAccess(ctx, k.server, tx, secret, core.NewObject("identityId", "u1", "action", "put", "version", 1.0)); err != nil {
			t.Fatal(err)
		}
		if stored := must(tx.Get(ctx, VaultCollections.Secrets, jsString(secret.Get("id")))); stored.Has("lastAccessedAt") {
			t.Fatal("a put is not an access")
		}
		if err := RecordAccess(ctx, k.server, tx, secret, core.NewObject("identityId", "u1", "action", "reveal", "sessionKind", "user", "agentId", "a1")); err != nil {
			t.Fatal(err)
		}
		if stored := must(tx.Get(ctx, VaultCollections.Secrets, jsString(secret.Get("id")))); stored.Get("lastAccessedAt") != now {
			t.Fatal("a reveal stamps lastAccessedAt")
		}
		records := must(tx.Find(ctx, VaultCollections.Access, core.NewObject("secretId", secret.Get("id")), nil))
		if len(records) != 2 {
			t.Fatalf("%d access records", len(records))
		}
		for _, record := range records {
			record.Delete("id")
		}
		want := `{"tenantId":"org","secretId":"` + jsString(secret.Get("id")) + `","name":"shared/root","identityId":"u1","action":"reveal","sessionKind":"user","agentId":"a1","at":` +
			core.NumberString(now) + `,"expiresAt":` + core.NumberString(now+2*vaultDay) + `}`
		found := false
		for _, record := range records {
			found = found || stringify(record) == want
		}
		if !found {
			t.Fatalf("access records %s", stringify(records))
		}
		return nil
	})
}

func TestVaultResolvesSecretsWithTheirAttributes(t *testing.T) {
	k := newKernel(t, nil)
	k.tenantTree()
	vaultSecretRecord(k, "payments/stripe", "tags", core.NewObject("env", "prod"), "checkout", core.NewObject("required", true),
		"rotation", core.NewObject("intervalDays", 30.0), "engine", "pg", "kmsKeyId", "k1")
	_ = k.tx(func(ctx context.Context, tx core.IamStore) error {
		resolved, err := ResolveSecretResource(ctx, tx, core.ResourceRef{TenantID: "org", Type: "iam", ID: "vault/secrets/payments/stripe"})
		if err != nil {
			t.Fatal(err)
		}
		want := `{"name":"payments/stripe","kind":"static","format":"text","status":"active","createdBy":"owner","checkoutRequired":true,` +
			`"rotationEnabled":true,"customerManagedKey":true,"engine":"pg","tag.env":"prod"}`
		if stringify(resolved.Attributes) != want {
			t.Fatalf("attributes %s", stringify(resolved.Attributes))
		}
		unknown, _ := ResolveSecretResource(ctx, tx, core.ResourceRef{TenantID: "org", Type: "iam", ID: "vault/secrets/nobody"})
		if unknown == nil || unknown.Attributes != nil {
			t.Fatal("an unused name resolves without attributes")
		}
		other, _ := ResolveSecretResource(ctx, tx, core.ResourceRef{TenantID: "org", Type: "iam", ID: "roles/x"})
		if other != nil {
			t.Fatal("other resources fall through")
		}
		return nil
	})
	if must(SecretResource("a/b")) != "vault/secrets/a/b" || must(LeaseHandleContext("l1")) != "vault-lease:l1" {
		t.Fatal("resource and context")
	}
	plain := must(SecretAttributes(core.NewObject("name", "n", "kind", "dynamic", "format", "json", "status", "active", "createdBy", "u", "tags", core.NewObject())))
	if stringify(plain) != `{"name":"n","kind":"dynamic","format":"json","status":"active","createdBy":"u","checkoutRequired":false,"rotationEnabled":false,"customerManagedKey":false}` {
		t.Fatalf("plain attributes %s", stringify(plain))
	}
}

func TestVaultSealsWithTheDeploymentSecretAndOpensWithPreviousOnes(t *testing.T) {
	k := newKernel(t, nil)
	sealed := must(VaultSealValue(k.server, "value", "vault:org:s1:1"))
	if must(VaultOpenValue(k.server, sealed, "vault:org:s1:1")) != "value" {
		t.Fatal("open")
	}
	_, err := VaultOpenValue(k.server, sealed, "vault:org:s1:2")
	expectError(t, err, "INVALID_SEALED_VALUE", "The secret value cannot be opened")
	rotated := &ServerContext{Options: &BetterIamOptions{Secret: "a-brand-new-deployment-secret-of-32-characters", PreviousSecrets: []string{testSecret}}}
	if must(VaultOpenValue(rotated, sealed, "vault:org:s1:1")) != "value" {
		t.Fatal("previous secrets open old values")
	}
}

func TestVaultCustomerManagedKeysEncryptThroughKms(t *testing.T) {
	k := newKernel(t, nil)
	k.tenantTree()
	secret := vaultSecretRecord(k, "cmk/app", "kmsKeyId", "key-1")
	err := k.tx(func(ctx context.Context, tx core.IamStore) error {
		_, err := AddVersion(ctx, k.server, tx, secret, "value", "put", "owner", nil)
		return err
	})
	if known, ok := asIamError(err); ok && known.Code == "NOT_IMPLEMENTED" {
		t.Skip("kms.ts kmsEncryptFor is not ported yet")
	}
	if err != nil {
		t.Fatal(err)
	}
}

func TestVaultTimesOutSlowCalls(t *testing.T) {
	k := newKernel(t, func(options *BetterIamOptions) { options.Vault = &VaultOptions{CallTimeoutMs: float(1000)} })
	value, err := WithTimeout(k.ctx, k.server, "Rotator db", func(context.Context) (any, error) { return "done", nil })
	if err != nil || value != "done" {
		t.Fatal("a fast call returns its value")
	}
	_, err = WithTimeout(k.ctx, k.server, "Rotator db", func(context.Context) (any, error) { return nil, errors.New("refused") })
	if err == nil || err.Error() != "refused" {
		t.Fatal("a failing call returns its error")
	}
	_, err = WithTimeout(k.ctx, k.server, "Rotator db", func(context.Context) (any, error) { panic("boom") })
	if err == nil || err.Error() != "boom" {
		t.Fatal("a panicking call fails")
	}
	_, err = WithTimeout(k.ctx, k.server, "Rotator db", func(ctx context.Context) (any, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	if err == nil || err.Error() != "Rotator db did not finish within 1000 ms" {
		t.Fatalf("timeout %v", err)
	}
}
