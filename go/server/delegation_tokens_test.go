package server

// Ports of tests/delegation-tokens.test.ts (packages/server/src/delegation-tokens.ts and delegations.issueToken).
// delegations.issueToken signs with the a2a card signer, which belongs to another unit, so the scope, audience and
// chain checks of those tests are also exercised here directly: the basis is gathered from the acting session exactly
// as issueToken gathers it, and audienceRefusal / scopeRefusal / tokenStillStands are asked what issueToken and the
// live verification ask them.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"reflect"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

const (
	tokenCalendar = "https://calendar.example.com"
	tokenFiles    = "https://files.docs.example.com"
)

func tokenSigningKey(t *testing.T, kid string) *core.Object {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return core.NewObject("kty", "OKP", "crv", "Ed25519", "d", base64url(private.Seed()), "x", base64url(public),
		"kid", kid, "alg", "EdDSA", "use", "sig")
}

// tokenFixture is tests/delegation-tokens.test.ts setup: Acme with alice (read and write on every document) and
// agents with keys: an assistant that may present delegations to the calendar and any docs service, and a researcher
// only to docs services.
type tokenFixture struct {
	*dlgFixture
	alice        *core.Object
	assistant    handoffAgent
	researcher   handoffAgent
	aliceSession core.CredentialInput
}

func newTokenFixture(t *testing.T, a2a bool) *tokenFixture {
	t.Helper()
	f := newDlgFixture(t, func(options *BetterIamOptions) {
		if a2a {
			jwks := "https://iam.acme.test/jwks"
			options.A2a = &A2aOptions{SigningKeys: []*core.Object{tokenSigningKey(t, "card-1")}, JwksURL: &jwks}
		}
	})
	tf := &tokenFixture{dlgFixture: f}
	tf.alice = f.person("alice")
	tf.assistant = tf.agentWith("Assistant", []any{tokenCalendar, "https://*.docs.example.com"})
	tf.researcher = tf.agentWith("Researcher", []any{"https://*.docs.example.com"})
	f.roleFor(tf.alice.Get("id"), "Editor", dlgDoc([]string{"documents:read", "documents:write"}))
	tf.aliceSession = f.login("alice")
	return tf
}

// agentWith creates an agent with token audiences (nil: none) and a key (with keyScopes, when given).
func (f *tokenFixture) agentWith(name string, audiences []any, keyScopes ...any) handoffAgent {
	f.t.Helper()
	var profile []any
	if audiences != nil {
		profile = []any{"tokenAudiences", audiences}
	}
	created := f.agent(name, profile...)
	var members []any
	if len(keyScopes) > 0 {
		members = []any{"scopes", keyScopes}
	}
	return handoffAgent{id: created.Get("id"), key: f.key(created.Get("id"), members...)}
}

// actFor grants a delegation to an agent (read and write by default) and opens a delegated session with it.
func (f *tokenFixture) actFor(who handoffAgent, grant ...any) (*core.Object, core.CredentialInput) {
	f.t.Helper()
	if len(grant) == 0 {
		grant = []any{"scopes", []any{"documents:read", "documents:write"}}
	}
	delegation := f.grant(f.aliceSession, append([]any{"agentId", who.id}, grant...)...)
	return delegation, f.token(f.assume(who.key, delegation.Get("id")))
}

// tokenCheck is what issueToken would check for a delegated session: the agents the audience refuses, and the scope
// refusal of the scopes (the delegation's own when scopes is nil). It builds the basis as issueToken does.
type tokenCheck struct {
	outsider *core.Object
	refusal  *core.Object
	scopes   []string
	record   *core.Object
}

func (f *tokenFixture) check(credential core.CredentialInput, audience string, scopes []string) tokenCheck {
	f.t.Helper()
	server := f.iam.Context
	authenticated, err := server.Principals.Authenticate(f.ctx, credential)
	requirePorted(f.t, err)
	var result tokenCheck
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return err
		}
		session := principal.Session
		now := server.Now()
		delegation, err := tx.Get(ctx, "delegations", jsString(session.Get("delegationId")))
		if err != nil {
			return err
		}
		ancestors, err := LiveAncestors(ctx, server, tx, delegation, now)
		if err != nil {
			return err
		}
		if ancestors == nil {
			f.t.Fatal("the chain must be live")
		}
		agent, err := tx.Get(ctx, "identities", jsString(session.Get("agentId")))
		if err != nil {
			return err
		}
		tenant, err := tx.Get(ctx, "tenants", f.tenantID)
		if err != nil {
			return err
		}
		agents := []*core.Object{}
		for index := len(ancestors) - 1; index >= 0; index-- {
			agents = append(agents, ancestors[index].Agent)
		}
		agents = append(agents, agent)
		if result.outsider, err = AudienceRefusal(agents, audience); err != nil {
			return err
		}
		if scopes == nil {
			scopes = stringItems(coalesce(delegation.Get("scopes"), []any{}))
		}
		sessionPolicies := []any{}
		for _, policy := range []any{session.Get("policy"), session.Get("sourcePolicy")} {
			if truthy(policy) {
				sessionPolicies = append(sessionPolicies, policy)
			}
		}
		authorityIDs := []string{}
		if authorityID, ok := session.Get("credentialAuthorityId").(string); ok && authorityID != "" {
			authorityIDs = append(authorityIDs, authorityID)
		}
		result.scopes = scopes
		result.refusal, err = ScopeRefusal(ctx, server, tx, &TokenBasis{
			Tenant: tenant, PersonID: jsString(principal.Identity.Get("id")), Delegation: delegation, Ancestors: ancestors,
			Agents: agents, SessionPolicies: sessionPolicies, AuthorityIDs: authorityIDs,
		}, scopes)
		if err != nil {
			return err
		}
		// The record issueToken keeps for live verification.
		result.record = core.NewObject(
			"id", Token(), "tenantId", f.tenantID, "delegationId", delegation.Get("id"), "personId", principal.Identity.Get("id"),
			"agentId", agent.Get("id"), "keyId", session.Get("sourceSessionId"), "audience", audience, "scopes", stringsOf(scopes),
			"sessionPolicies", sessionPolicies, "createdAt", float64(now), "expiresAt", float64(now)+300_000,
		)
		if len(authorityIDs) > 0 {
			result.record.Set("authorityId", authorityIDs[0])
		}
		return nil
	})
	return result
}

// stands is tokenStillStands for a record.
func (f *tokenFixture) stands(record *core.Object) bool {
	f.t.Helper()
	var stands bool
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		var err error
		stands, err = TokenStillStands(ctx, f.iam.Context, tx, record, f.iam.Context.Now())
		return err
	})
	return stands
}

func expectRefusal(t *testing.T, check tokenCheck, scope, why string) {
	t.Helper()
	if check.refusal == nil || check.refusal.Get("scope") != scope || check.refusal.Get("why") != why {
		t.Fatalf("expected %s refused (%s), got %s", scope, why, core.MustStringify(check.refusal))
	}
}

func expectCarried(t *testing.T, check tokenCheck) {
	t.Helper()
	if check.outsider != nil || check.refusal != nil {
		t.Fatalf("expected the token allowed, got outsider %v refusal %s", check.outsider, core.MustStringify(check.refusal))
	}
}

func TestDelegationTokensShowAnotherServiceThatTheAgentActsForAPerson(t *testing.T) {
	f := newTokenFixture(t, true)
	delegation, session := f.actFor(f.assistant)
	// What issueToken checks and what live verification re-checks.
	check := f.check(session, tokenCalendar, nil)
	expectCarried(t, check)
	if !reflect.DeepEqual(check.scopes, []string{"documents:read", "documents:write"}) {
		t.Fatalf("scopes %v", check.scopes)
	}
	if !f.stands(check.record) {
		t.Fatal("a fresh token stands")
	}

	issued := f.object(f.api().IssueToken(f.ctx, session, Input[apitypes.DelegationsIssueTokenInput](f.in("audience", tokenCalendar))))
	dlgMatches(t, issued, core.NewObject("tokenType", "biam-delegation+jwt", "audience", tokenCalendar,
		"scopes", []any{"documents:read", "documents:write"}, "chain", []any{f.assistant.id}, "expiresIn", 300.0))
	f.revoke(f.aliceSession, delegation.Get("id"))
	if f.stands(check.record) {
		t.Fatal("a revoked delegation's token no longer stands")
	}
}

func TestDelegationTokensRefuseAudiencesScopesAndCallersOutsideEveryLimit(t *testing.T) {
	f := newTokenFixture(t, true)
	_, session := f.actFor(f.assistant)
	if outsider := f.check(session, "https://evil.example.com", nil).outsider; outsider == nil || outsider.Get("id") != f.assistant.id {
		t.Fatal("an audience outside the agent's tokenAudiences is refused")
	}
	for _, audience := range []string{"https://*.docs.example.com", "not a uri"} {
		if _, err := TokenAudience(audience); iamError(t, err).Code != "INVALID_INPUT" {
			t.Fatalf("audience %q must be invalid", audience)
		}
	}
	expectRefusal(t, f.check(session, tokenCalendar, []string{"billing:read"}), "billing:read", "limit")
	// A pattern broader than the delegation's scopes is refused.
	expectRefusal(t, f.check(session, tokenCalendar, []string{"documents:*"}), "documents:*", "limit")
	expectCarried(t, f.check(session, tokenFiles, []string{"documents:read"}))

	// A key limited to reading cannot carry the delegation's write scope.
	scoped := f.agentWith("Scoped", []any{tokenCalendar}, "documents:read")
	_, limited := f.actFor(scoped)
	expectRefusal(t, f.check(limited, tokenCalendar, nil), "documents:write", "limit")
	expectCarried(t, f.check(limited, tokenCalendar, []string{"documents:read"}))

	// A delegation given as a resource-limited policy carries no scopes, and cannot claim any.
	helper := f.agentWith("Team helper", []any{tokenCalendar})
	_, team := f.actFor(helper, "policy", dlgDoc([]string{"documents:read"}, "document/team-*"))
	teamCheck := f.check(team, tokenCalendar, nil)
	expectCarried(t, teamCheck)
	if len(teamCheck.scopes) != 0 {
		t.Fatalf("a policy delegation carries no scopes: %v", teamCheck.scopes)
	}
	expectRefusal(t, f.check(team, tokenCalendar, []string{"documents:read"}), "documents:read", "limit")

	// Without token audiences an agent gets no tokens at all.
	quiet := f.agentWith("Quiet", nil)
	_, quietSession := f.actFor(quiet)
	if outsider := f.check(quietSession, tokenCalendar, nil).outsider; outsider == nil || outsider.Get("id") != quiet.id {
		t.Fatal("an agent without token audiences is refused")
	}

	// Through the API: the agent's own key is not a delegation, and nothing is issued without the signer.
	_, err := f.api().IssueToken(f.ctx, f.assistant.key, Input[apitypes.DelegationsIssueTokenInput](f.in("audience", tokenCalendar)))
	expectCodeOrSkip(t, err, "ACCESS_DENIED")
}

func TestDelegationTokensNameEveryAgentAHandoffPassedThrough(t *testing.T) {
	f := newTokenFixture(t, true)
	delegation, session := f.actFor(f.assistant, "scopes", []any{"documents:read", "documents:write"},
		"handoff", core.NewObject("agents", []any{f.researcher.id}))
	handoff, err := f.handoff(session, "agentId", f.researcher.id, "scopes", []any{"documents:read"})
	requirePorted(t, err)
	acting := f.token(f.assume(f.researcher.key, handoff.Get("id")))
	check := f.check(acting, tokenFiles, nil)
	expectCarried(t, check)
	if !reflect.DeepEqual(check.scopes, []string{"documents:read"}) || check.record.Get("delegationId") != handoff.Get("id") {
		t.Fatalf("check %v %s", check.scopes, core.MustStringify(check.record))
	}
	actor, err := core.NewDelegationActor([]string{jsString(f.assistant.id), jsString(f.researcher.id)})
	if err != nil {
		t.Fatal(err)
	}
	if actor.Sub != f.researcher.id || actor.Act == nil || actor.Act.Sub != f.assistant.id {
		t.Fatalf("act %+v", actor)
	}
	if !f.stands(check.record) {
		t.Fatal("the hand-off's token stands")
	}

	// The researcher may not claim more than it was handed, nor reach a service the assistant may not.
	expectRefusal(t, f.check(acting, tokenFiles, []string{"documents:write"}), "documents:write", "limit")
	f.patchAgent(f.researcher.id, nil, "tokenAudiences", []any{tokenCalendar, "https://*.docs.example.com"})
	f.patchAgent(f.assistant.id, nil, "tokenAudiences", []any{"https://*.docs.example.com"})
	if outsider := f.check(acting, tokenCalendar, nil).outsider; outsider == nil || outsider.Get("id") != f.assistant.id {
		t.Fatal("the assistant may no longer present delegations to the calendar")
	}
	calendarRecord := check.record.Spread(core.NewObject("audience", tokenCalendar))
	if f.stands(calendarRecord) {
		t.Fatal("a token for an audience the chain lost no longer stands")
	}

	// Revoking the person's own delegation ends the hand-off below it, and live checks see it.
	f.revoke(f.aliceSession, delegation.Get("id"))
	if f.stands(check.record) {
		t.Fatal("the hand-off's token no longer stands")
	}
}

func TestDelegationTokensNeedTheA2aSigningKeys(t *testing.T) {
	f := newTokenFixture(t, false)
	_, session := f.actFor(f.assistant)
	_, err := f.api().IssueToken(f.ctx, session, Input[apitypes.DelegationsIssueTokenInput](f.in("audience", tokenCalendar)))
	expectCodeOrSkip(t, err, "FEATURE_DISABLED")
}

func TestDelegationTokensNeverCarryConfirmedActionsOrWhatTheirDeniesMayTouch(t *testing.T) {
	f := newTokenFixture(t, true)
	_, confirmed := f.actFor(f.assistant, "scopes", []any{"documents:read", "documents:write"}, "confirm", []any{"documents:wri?e"})
	expectRefusal(t, f.check(confirmed, tokenFiles, nil), "documents:write", "confirm")
	expectCarried(t, f.check(confirmed, tokenFiles, []string{"documents:read"}))

	// A deny among alice's own grants refuses any scope it could touch, whatever its resources or conditions.
	f.roleFor(f.alice.Get("id"), "No agent writes", core.NewObject("version", 1.0, "statements", []any{core.NewObject(
		"effect", "deny", "actions", []any{"documents:write"}, "resources", []any{"document/*"},
		"conditions", core.NewObject("Bool", core.NewObject("principal.delegated", true)),
	)}))
	_, plain := f.actFor(f.researcher)
	expectRefusal(t, f.check(plain, tokenFiles, nil), "documents:write", "deny")
	expectCarried(t, f.check(plain, tokenFiles, []string{"documents:read"}))
}

func TestDelegationTokensKeepHonouringADenyWhoseAuthorsAuthorityWasRevoked(t *testing.T) {
	f := newTokenFixture(t, true)
	security := f.person("security")
	writer := f.createRole(f.owner, "name", "Security policy writer", "permissions", []any{"iam:policies:create", "iam:policies:read"})
	f.bind(f.owner, writer.Get("id"), "identity", security.Get("id"))
	authority := f.object(f.iam.API.Authorities.Create(f.ctx, f.ownerSignIn(), Input[apitypes.AuthoritiesCreateInput](f.in(
		"identityId", security.Get("id"), "ceiling", core.NewObject("version", 1.0, "statements", []any{core.NewObject(
			"effect", "allow", "actions", []any{"documents:*"}, "resources", []any{"*"},
		)}),
	))))
	guard := f.object(f.iam.API.Policies.Create(f.ctx, f.login("security"), Input[apitypes.PoliciesCreateInput](f.in(
		"name", "No agent writes", "document", core.NewObject("version", 1.0, "statements", []any{core.NewObject(
			"effect", "deny", "actions", []any{"documents:write"}, "resources", []any{"document/*"},
		)}),
	))))
	staff := f.createRole(f.owner, "name", "Staff", "permissions", []any{"documents:read"})
	f.object(f.iam.API.Roles.Update(f.ctx, f.owner, Input[apitypes.RolesUpdateInput](f.in("roleId", staff.Get("id"), "policyIds", []any{guard.Get("id")}))))
	f.bind(f.owner, staff.Get("id"), "identity", f.alice.Get("id"))
	// The security engineer leaves: their authority is revoked, but the deny they wrote still applies, so a token for
	// alice must not carry documents:write either.
	f.ported(f.iam.API.Authorities.Revoke(f.ctx, f.ownerSignIn(), Input[apitypes.AuthoritiesRevokeInput](f.in("authorityId", authority.Get("id")))))
	_, acting := f.actFor(f.researcher)
	expectRefusal(t, f.check(acting, tokenFiles, nil), "documents:write", "deny")
}

func TestDelegationTokensReCheckEverythingLive(t *testing.T) {
	f := newTokenFixture(t, true)
	_, session := f.actFor(f.assistant)
	check := f.check(session, tokenCalendar, nil)
	if !f.stands(check.record) {
		t.Fatal("a fresh token stands")
	}
	// The agent stops accepting delegation.
	f.patchAgent(f.assistant.id, nil, "delegable", false)
	if f.stands(check.record) {
		t.Fatal("a token of an agent that no longer accepts delegation no longer stands")
	}
	f.patchAgent(f.assistant.id, nil, "delegable", true)
	if !f.stands(check.record) {
		t.Fatal("accepting delegation again restores the token")
	}
	// The agent is suspended.
	f.patchAgent(f.assistant.id, []any{"status", "suspended"})
	if f.stands(check.record) {
		t.Fatal("a suspended agent's token no longer stands")
	}
	f.patchAgent(f.assistant.id, []any{"status", "active"})
	// The scopes are no longer allowed outright (the agent's own ceiling narrows them).
	f.patchAgent(f.assistant.id, nil, "boundary", dlgDoc([]string{"documents:read"}))
	if f.stands(check.record) {
		t.Fatal("a token whose scopes the agent's ceiling no longer allows does not stand")
	}
	f.patchAgent(f.assistant.id, nil, "boundary", nil)
	if !f.stands(check.record) {
		t.Fatal("lifting the ceiling restores the token")
	}
	// The acting key is revoked.
	keys := f.items(f.iam.API.Credentials.List(f.ctx, f.owner, Input[apitypes.CredentialsListInput](f.in("identityId", f.assistant.id))))
	f.ported(f.iam.API.Credentials.Revoke(f.ctx, f.ownerSignIn(), Input[apitypes.CredentialsRevokeInput](f.in("credentialId", keys[0].Get("id")))))
	if f.stands(check.record) {
		t.Fatal("a token of a revoked key no longer stands")
	}
}

func TestDelegationTokensAudienceRefusal(t *testing.T) {
	agent := func(id string, audiences ...any) *core.Object {
		return core.NewObject("id", id, "kind", "agent", "agent", core.NewObject("sponsorId", "s", "tokenAudiences", audiences))
	}
	wide := agent("wide", "https://*.example.com", "https://api.example.org/v1/*")
	none := core.NewObject("id", "none", "kind", "agent", "agent", core.NewObject("sponsorId", "s"))
	for audience, refused := range map[string]bool{
		"https://files.example.com":         false,
		"https://api.example.org/v1/events": false,
		"https://example.com":               true,
		"https://api.example.org/v2":        true,
		"http://files.example.com":          true,
	} {
		outsider := must(AudienceRefusal([]*core.Object{wide}, audience))
		if (outsider != nil) != refused {
			t.Fatalf("%s: refused %v", audience, outsider != nil)
		}
	}
	if outsider := must(AudienceRefusal([]*core.Object{wide, none}, "https://files.example.com")); outsider == nil || outsider.Get("id") != "none" {
		t.Fatal("the first agent without the audience is named")
	}
	if outsider := must(AudienceRefusal(nil, "https://files.example.com")); outsider != nil {
		t.Fatal("no agents, no refusal")
	}
}
