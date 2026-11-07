package server

// Temporary credential core tests, after tests/sts-session-token.test.ts, tests/role-session-boundaries.test.ts,
// tests/audit-session-context.test.ts and tests/web-identity.test.ts: the input validators (session names, source
// identities, session tags, allowed tag keys, formats, audiences, durations and their bounds), MintCredential's opaque
// issuance and refusals, the allowlist projections, and eager deletion of role sessions.

import (
	"context"
	"errors"
	"math"
	"slices"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

func stringify(t *testing.T, value any) string {
	t.Helper()
	text, _, err := core.Stringify(value)
	if err != nil {
		t.Fatal(err)
	}
	return text
}

func TestTemporaryCredentialsSessionNamesAndSourceIdentities(t *testing.T) {
	for _, valid := range []string{"ab", "deploy-bot", "user+tag=x,y.z@example_1", strings.Repeat("a", 64)} {
		if name, err := SessionNameValue(valid); err != nil || name != valid {
			t.Errorf("session name %q: %q %v", valid, name, err)
		}
		if name, err := SourceIdentityValue(valid); err != nil || name != valid {
			t.Errorf("source identity %q: %q %v", valid, name, err)
		}
	}
	if name, err := SessionNameValue(core.Undefined); err != nil || name != "" {
		t.Errorf("undefined session name: %q %v", name, err)
	}
	for _, invalid := range []any{"a", strings.Repeat("a", 65), "has space", "slash/no", 42.0, nil, true} {
		_, err := SessionNameValue(invalid)
		expectError(t, err, "INVALID_INPUT", "sessionName must be 2-64 letters, digits or +=,.@_- characters")
		_, err = SourceIdentityValue(invalid)
		expectError(t, err, "INVALID_INPUT", "sourceIdentity must be 2-64 letters, digits or +=,.@_- characters")
	}
}

func TestTemporaryCredentialsSessionTags(t *testing.T) {
	if tags, err := SessionTagsValue(core.Undefined); err != nil || tags != nil {
		t.Errorf("undefined tags: %v %v", tags, err)
	}
	if tags, err := SessionTagsValue(obj(t, `{}`)); err != nil || tags != nil {
		t.Errorf("no tags: %v %v", tags, err)
	}
	for _, invalid := range []any{nil, "team=a", parse(t, `["a"]`), 1.0} {
		_, err := SessionTagsValue(invalid)
		expectError(t, err, "INVALID_INPUT", "tags must be an object of tag keys to string values")
	}
	tags, err := SessionTagsValue(obj(t, `{"Team":"Payments","city":"Zürich","path":"a/b:c=d+e-f@g h_i.j"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := stringify(t, tags); got != `{"Team":"Payments","city":"Zürich","path":"a/b:c=d+e-f@g h_i.j"}` {
		t.Errorf("tags: %s", got)
	}
	_, err = SessionTagsValue(obj(t, `{"_team":"a"}`))
	expectError(t, err, "INVALID_INPUT", "Tag keys must start with a letter and use at most 64 letters, digits or underscores")
	_, err = SessionTagsValue(obj(t, `{"`+strings.Repeat("k", 65)+`":"a"}`))
	expectError(t, err, "INVALID_INPUT", "Tag keys must start with a letter and use at most 64 letters, digits or underscores")
	_, err = SessionTagsValue(obj(t, `{"Team":"a","team":"b"}`))
	expectError(t, err, "INVALID_INPUT", "Tag key team is repeated (tag keys are case-insensitive)")
	for _, value := range []string{`1`, `"semi;colon"`, `"` + strings.Repeat("v", 257) + `"`, `null`} {
		_, err = SessionTagsValue(obj(t, `{"team":`+value+`}`))
		expectError(t, err, "INVALID_INPUT", "Tag team must be a string of at most 256 letters, digits, spaces or _.:/=+-@")
	}
	// 256 characters is the limit (counted in UTF-16 code units, like JavaScript).
	if _, err := SessionTagsValue(obj(t, `{"team":"`+strings.Repeat("ü", 256)+`"}`)); err != nil {
		t.Errorf("256 characters: %v", err)
	}
	many := core.NewObject()
	for index := range 51 {
		many.Set("k"+core.NumberString(float64(index)), "v")
	}
	_, err = SessionTagsValue(many)
	expectError(t, err, "INVALID_INPUT", "tags may contain at most 50 entries")
	// Packed size: ten 250-character values exceed 2048 bytes.
	large := core.NewObject()
	for index := range 10 {
		large.Set("k"+core.NumberString(float64(index)), strings.Repeat("v", 250))
	}
	_, err = SessionTagsValue(large)
	expectError(t, err, "INVALID_INPUT", "tags must pack into at most 2048 bytes")
	// Multi-byte characters count as their UTF-8 bytes when packed.
	wide := core.NewObject()
	for index := range 5 {
		wide.Set("k"+core.NumberString(float64(index)), strings.Repeat("ü", 210))
	}
	_, err = SessionTagsValue(wide)
	expectError(t, err, "INVALID_INPUT", "tags must pack into at most 2048 bytes")
}

func TestTemporaryCredentialsAllowedTagKeysAndFormats(t *testing.T) {
	if keys, err := AllowedTagKeysValue(parse(t, `["*"]`)); err != nil || len(keys) != 1 || keys[0] != "*" {
		t.Errorf("wildcard: %v %v", keys, err)
	}
	if keys, err := AllowedTagKeysValue(parse(t, `["team","Region_1"]`)); err != nil || strings.Join(keys, ",") != "team,Region_1" {
		t.Errorf("keys: %v %v", keys, err)
	}
	if keys, err := AllowedTagKeysValue(parse(t, `[]`)); err != nil || len(keys) != 0 {
		t.Errorf("no keys: %v %v", keys, err)
	}
	listMessage := "allowedTagKeys must be a list of at most 50 tag keys, or ['*']"
	tooMany := make([]any, 51)
	for index := range tooMany {
		tooMany[index] = "k" + core.NumberString(float64(index))
	}
	for _, invalid := range []any{core.Undefined, "team", obj(t, `{}`), tooMany, parse(t, `["*","team"]`), parse(t, `["9team"]`), parse(t, `[1]`)} {
		_, err := AllowedTagKeysValue(invalid)
		expectError(t, err, "INVALID_INPUT", listMessage)
	}
	_, err := AllowedTagKeysValue(parse(t, `["Team","TEAM"]`))
	expectError(t, err, "INVALID_INPUT", "Tag key TEAM is repeated (tag keys are case-insensitive)")

	if format, err := CredentialFormat(core.Undefined); err != nil || format != "opaque" {
		t.Errorf("default format: %q %v", format, err)
	}
	if format, err := CredentialFormat("jwt"); err != nil || format != "jwt" {
		t.Errorf("jwt format: %q %v", format, err)
	}
	for _, invalid := range []any{"JWT", nil, 1.0, ""} {
		_, err := CredentialFormat(invalid)
		expectError(t, err, "INVALID_INPUT", "format must be 'opaque' or 'jwt'")
	}

	if audience, err := AudienceValue(core.Undefined, "opaque"); err != nil || audience != nil {
		t.Errorf("no audience: %v %v", audience, err)
	}
	_, err = AudienceValue(parse(t, `["api"]`), "opaque")
	expectError(t, err, "INVALID_INPUT", "audience requires format 'jwt'")
	for _, invalid := range []any{"api", parse(t, `[]`), parse(t, `["a","b","c","d","e","f"]`)} {
		_, err := AudienceValue(invalid, "jwt")
		expectError(t, err, "INVALID_INPUT", "audience must list 1 to 5 audiences")
	}
	for _, invalid := range []string{`["-api"]`, `["has space"]`, `[1]`, `["` + strings.Repeat("a", 257) + `"]`} {
		_, err := AudienceValue(parse(t, invalid), "jwt")
		expectError(t, err, "INVALID_INPUT", "audience entries must be URL-safe identifiers of at most 256 characters")
	}
	if audience, err := AudienceValue(parse(t, `["https://api.example.test","billing","billing"]`), "jwt"); err != nil || strings.Join(audience, " ") != "https://api.example.test billing" {
		t.Errorf("deduplicated audience: %v %v", audience, err)
	}
}

func TestTemporaryCredentialsDurations(t *testing.T) {
	k := newKernel(t, nil)
	bounds := must(RoleDurationBounds(k.server, core.NewObject(), "opaque"))
	if got := stringify(t, bounds); got != `{"min":60,"max":3600,"fallback":900}` {
		t.Errorf("default role bounds: %s", got)
	}
	// A malformed stored maximum fails closed to the default; a lower one reduces the bounds and the fallback.
	for _, malformed := range []any{"7200", -5.0, 0.0, 1.5, math.NaN(), nil, 1e300} {
		if got := stringify(t, must(RoleDurationBounds(k.server, core.NewObject("maxSessionSeconds", malformed), "opaque"))); got != `{"min":60,"max":3600,"fallback":900}` {
			t.Errorf("malformed %v: %s", malformed, got)
		}
	}
	if got := stringify(t, must(RoleDurationBounds(k.server, core.NewObject("maxSessionSeconds", 600.0), "opaque"))); got != `{"min":60,"max":600,"fallback":600}` {
		t.Errorf("short trust: %s", got)
	}
	// The deployment ceiling caps a longer trust; without sts.jwt a JWT has no extra cap.
	if got := stringify(t, must(RoleDurationBounds(k.server, core.NewObject("maxSessionSeconds", 43200.0), "jwt"))); got != `{"min":60,"max":3600,"fallback":900}` {
		t.Errorf("deployment ceiling: %s", got)
	}
	long := newKernel(t, func(options *BetterIamOptions) {
		options.Sts = &StsOptions{MaxRoleSessionSeconds: float(43200), MaxSessionTokenSeconds: float(1800)}
	})
	if got := stringify(t, must(RoleDurationBounds(long.server, core.NewObject("maxSessionSeconds", 7200.0), "opaque"))); got != `{"min":60,"max":7200,"fallback":900}` {
		t.Errorf("long trust: %s", got)
	}
	if got := stringify(t, must(SessionTokenDurationBounds(k.server, "opaque"))); got != `{"min":60,"max":43200,"fallback":3600}` {
		t.Errorf("default session token bounds: %s", got)
	}
	if got := stringify(t, must(SessionTokenDurationBounds(long.server, "jwt"))); got != `{"min":60,"max":1800,"fallback":1800}` {
		t.Errorf("short session tokens: %s", got)
	}
	if seconds, err := DurationWithin(core.Undefined, bounds); err != nil || seconds != 900 {
		t.Errorf("fallback: %v %v", seconds, err)
	}
	if seconds, err := DurationWithin(nil, bounds); err != nil || seconds != 900 {
		t.Errorf("null falls back: %v %v", seconds, err)
	}
	if seconds, err := DurationWithin(3600.0, bounds); err != nil || seconds != 3600 {
		t.Errorf("maximum: %v %v", seconds, err)
	}
	for _, invalid := range []any{59.0, 3601.0, 900.5, "900", true, math.Inf(1)} {
		_, err := DurationWithin(invalid, bounds)
		expectError(t, err, "INVALID_INPUT", "durationSeconds must be an integer from 60 to 3600")
	}
}

func TestTemporaryCredentialsMintOpaque(t *testing.T) {
	k := newKernel(t, nil)
	k.tenantTree()
	alice := identity("alice", "org")
	k.insert("identities", alice)
	draft := session("role-session", "alice", "project", "role", "roleId", "role-1", "trustId", "trust-1", "sourceTenantId", "org",
		"format", "jwt", "audience", []any{"stale"}, "uniqueKey", "draft", "createdAt", 1_000.0, "expiresAt", 901_000.0)
	var minted *core.Object
	err := k.tx(func(ctx context.Context, tx core.IamStore) (err error) {
		minted, err = MintCredential(ctx, k.server, tx, core.NewObject("identity", alice, "draft", draft, "format", "opaque"))
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	token := jsString(minted.Get("token"))
	if !strings.HasPrefix(token, "biam_rol_") {
		t.Errorf("role token prefix: %s", token)
	}
	stored, err := k.store.Get(k.ctx, "sessions", "role-session")
	if err != nil || stored == nil {
		t.Fatalf("stored row: %v", err)
	}
	if stored.Get("tokenHash") != Hash(token) || stored.Get("uniqueKey") != Hash(token) {
		t.Errorf("token material: %v", stored)
	}
	if stored.Has("format") || stored.Has("audience") {
		t.Errorf("draft format or audience kept: %v", stored)
	}
	if draft.Get("format") != "jwt" {
		t.Error("the draft was modified")
	}
	// Session tokens are typed `sts`.
	stsDraft := session("sts-session", "alice", "org", "session-token", "createdAt", 1_000.0, "expiresAt", 901_000.0)
	err = k.tx(func(ctx context.Context, tx core.IamStore) (err error) {
		minted, err = MintCredential(ctx, k.server, tx, core.NewObject("identity", alice, "draft", stsDraft, "format", "opaque"))
		return err
	})
	if err != nil || !strings.HasPrefix(jsString(minted.Get("token")), "biam_sts_") {
		t.Errorf("session token: %v %v", minted, err)
	}
	refuse := func(input *core.Object) error {
		return k.tx(func(ctx context.Context, tx core.IamStore) error {
			_, err := MintCredential(ctx, k.server, tx, input)
			return err
		})
	}
	other := session("other", "alice", "org", "role")
	expectError(t, refuse(core.NewObject("identity", alice, "draft", other, "format", "opaque", "audience", []any{"api"})), "INVALID_INPUT", "audience requires format 'jwt'")
	expectError(t, refuse(core.NewObject("identity", alice, "draft", other, "format", "pem")), "INVALID_INPUT", "format must be 'opaque' or 'jwt'")
	expectError(t, refuse(core.NewObject("identity", alice, "draft", other, "format", "jwt")), "FEATURE_DISABLED", "Session JWTs are not enabled on this deployment (sts.jwt)")
	err = refuse(core.NewObject("identity", alice, "draft", session("user", "alice", "org", "user"), "format", "opaque"))
	var known *core.IamError
	if err == nil || errors.As(err, &known) || err.Error() != "mintCredential issues role sessions and session tokens only" {
		t.Errorf("user drafts: %v", err)
	}
}

func TestTemporaryCredentialsProjections(t *testing.T) {
	row := session("s1", "alice", "project", "role", "roleId", "role-1", "trustId", "trust-1", "sourceTenantId", "org",
		"sessionName", "deploy", "sourceIdentity", "alice@corp", "sessionTags", obj(t, `{"team":"payments"}`),
		"policy", obj(t, `{"version":1}`), "sourceSessionId", "parent", "format", "jwt", "audience", []any{"api", "billing"},
		"webIdentity", obj(t, `{"providerId":"gh","issuer":"https://token.actions.example","subject":"repo:acme/web"}`),
		"client", obj(t, `{"ip":"203.0.113.9"}`), "method", "password", "createdAt", 1_000.0, "expiresAt", 3_601_500.0, "authenticatedAt", 500.0)
	credential := must(TemporaryCredential("biam_rol_x", row, 1_000))
	want := `{"token":"biam_rol_x","tokenType":"Bearer","format":"jwt","expiresAt":3601500,"expiresIn":3600,"session":{"id":"s1","tenantId":"project","kind":"role","identityId":"alice","expiresAt":3601500,"mfa":false,"roleId":"role-1","trustId":"trust-1","sessionName":"deploy","sourceIdentity":"alice@corp"},"audience":["api","billing"]}`
	if got := stringify(t, credential); got != want {
		t.Errorf("temporary credential:\n got %s\nwant %s", got, want)
	}
	if got := jsNumber(must(TemporaryCredential("t", row, 4_000_000)).Get("expiresIn")); got != 0 {
		t.Errorf("expiresIn never negative: %v", got)
	}
	caller := must(CallerIdentity(principalOf(identity("alice", "org"), row)))
	want = `{"identityId":"alice","identityTenantId":"org","identityKind":"user","tenantId":"project","sessionId":"s1","sessionKind":"role","format":"jwt","mfa":false,"authenticatedAt":500,"issuedAt":1000,"expiresAt":3601500,"method":"password","roleId":"role-1","trustId":"trust-1","sourceTenantId":"org","sessionName":"deploy","sourceIdentity":"alice@corp","sessionTags":{"team":"payments"},"audience":["api","billing"],"webIdentity":{"providerId":"gh","issuer":"https://token.actions.example","subject":"repo:acme/web"}}`
	if got := stringify(t, caller); got != want {
		t.Errorf("caller identity:\n got %s\nwant %s", got, want)
	}
	plain := must(CallerIdentity(principalOf(identity("bob", "org"), session("s2", "bob", "org", "user", "sessionTags", obj(t, `{}`), "impersonatorId", "root", "agentId", "agent-1", "delegationId", "d-1"))))
	want = `{"identityId":"bob","identityTenantId":"org","identityKind":"user","tenantId":"org","sessionId":"s2","sessionKind":"user","format":"opaque","mfa":false,"authenticatedAt":1,"issuedAt":1,"expiresAt":9000000000000000,"impersonatorId":"root","agentId":"agent-1","delegationId":"d-1"}`
	if got := stringify(t, plain); got != want {
		t.Errorf("plain caller identity:\n got %s\nwant %s", got, want)
	}
	// A cross-tenant role session hides the source person's address from the target tenant.
	summary := must(RoleSessionSummary(row))
	want = `{"id":"s1","roleId":"role-1","trustId":"trust-1","identityId":"alice","mfa":false,"format":"jwt","createdAt":1000,"expiresAt":3601500,"sourceTenantId":"org","sessionName":"deploy","sourceIdentity":"alice@corp","webIdentity":{"providerId":"gh","subject":"repo:acme/web"}}`
	if got := stringify(t, summary); got != want {
		t.Errorf("role session summary:\n got %s\nwant %s", got, want)
	}
	local := must(RoleSessionSummary(row.Spread(core.NewObject("sourceTenantId", "project"))))
	if local.Get("clientIp") != "203.0.113.9" {
		t.Errorf("same-tenant client ip: %v", local)
	}
	recorded := AuditSessionContext(row.Spread(core.NewObject("agentId", "agent-1",
		"webIdentity", core.NewObject("providerId", "gh", "subject", strings.Repeat("s", 300)))))
	want = `{"sessionId":"s1","kind":"role","roleId":"role-1","trustId":"trust-1","sourceTenantId":"org","sessionName":"deploy","sourceIdentity":"alice@corp","webIdentityProviderId":"gh","webIdentitySubject":"` + strings.Repeat("s", 256) + `","format":"jwt","agentId":"agent-1"}`
	if got := stringify(t, recorded); got != want {
		t.Errorf("audit session context:\n got %s\nwant %s", got, want)
	}
	if got := stringify(t, AuditSessionContext(session("s3", "bob", "org", "user"))); got != `{"sessionId":"s3","kind":"user"}` {
		t.Errorf("plain audit session context: %s", got)
	}
	if AuditSessionContext(nil) != nil || AuditSessionContext(session("simulation", "bob", "org", "user")) != nil ||
		AuditSessionContext(core.NewObject("id", 1.0, "kind", "user")) != nil {
		t.Error("simulated or malformed sessions carry a context")
	}
}

func TestTemporaryCredentialsDeleteRoleSessions(t *testing.T) {
	k := newKernel(t, nil)
	web := obj(t, `{"providerId":"gh","issuer":"https://issuer.example","subject":"s"}`)
	k.insert("sessions",
		session("old-1", "a", "project", "role", "roleId", "r", "trustId", "t1", "createdAt", 100.0),
		session("old-2", "a", "project", "role", "roleId", "r", "trustId", "t2", "createdAt", 100.0, "webIdentity", web),
		session("new", "a", "project", "role", "roleId", "r", "trustId", "t1", "createdAt", 500.0),
		session("other-tenant", "a", "org", "role", "roleId", "r", "trustId", "t1", "createdAt", 100.0),
		session("other-role", "a", "project", "role", "roleId", "q", "trustId", "t1", "createdAt", 100.0),
		session("not-role", "a", "project", "session-token", "roleId", "r", "createdAt", 100.0),
	)
	remove := func(filter *core.Object) float64 {
		var deleted float64
		if err := k.tx(func(ctx context.Context, tx core.IamStore) (err error) {
			deleted, err = DeleteTemporarySessions(ctx, tx, filter)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		return deleted
	}
	if got := remove(core.NewObject("tenantId", "project", "roleId", "r", "providerId", "gh", "createdBefore", 200.0)); got != 1 {
		t.Errorf("by provider: %v", got)
	}
	if got := remove(core.NewObject("tenantId", "project", "roleId", "r", "trustId", "t2", "createdBefore", 200.0)); got != 0 {
		t.Errorf("by trust (already deleted): %v", got)
	}
	if got := remove(core.NewObject("tenantId", "project", "roleId", "r", "createdBefore", 200.0)); got != 1 {
		t.Errorf("by watermark: %v", got)
	}
	left, err := k.store.Find(k.ctx, "sessions", core.NewObject(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, row := range left {
		names = append(names, jsString(row.Get("id")))
	}
	slices.Sort(names)
	if strings.Join(names, ",") != "new,not-role,other-role,other-tenant" {
		t.Errorf("remaining sessions: %v", names)
	}
}
