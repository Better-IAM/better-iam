package server

// Terms-of-use tests, after tests/agreements.test.ts and the agreement cases of tests/derived-session-guards.test.ts:
// required agreements hold back access until accepted (and again after a new version), accepted names reach
// policies, and members only list and accept their own. Roles and bindings are seeded directly in the store.

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

type agreementScenario struct {
	*govFixture
	alice      *core.Object
	aliceID    string
	aliceToken string
}

func newAgreementScenario(t *testing.T) *agreementScenario {
	t.Helper()
	f := newGovFixture(t, nil)
	alice := f.person("alice")
	aliceID := jsString(alice.Get("id"))
	// Readers may read documents, but nothing until every required agreement is accepted.
	reader := document(
		allowStatement("documents:read", "*"),
		core.NewObject("effect", "deny", "actions", []any{"documents:*"}, "resources", []any{"*"},
			"conditions", core.NewObject("NumericGreaterThan", core.NewObject("principal.pendingAgreements", 0.0))),
	)
	f.seed("policies", core.NewObject("id", "policy-reader", "tenantId", f.tenantID, "name", "Reader", "document", reader, "version", 1.0, "authorityId", adminAuthority))
	f.seed("roles", core.NewObject("id", "role-reader", "tenantId", f.tenantID, "name", "Reader", "policyIds", []any{"policy-reader"}, "authorityId", adminAuthority))
	f.bind("binding-reader", "role-reader", "identity", aliceID, adminAuthority)
	return &agreementScenario{govFixture: f, alice: alice, aliceID: aliceID, aliceToken: f.token(alice)}
}

func (s *agreementScenario) can(token, action string) bool {
	s.t.Helper()
	return s.authorize(token, action, "document", "d1").Allowed
}

func TestAgreementsHoldBackAccessUntilAccepted(t *testing.T) {
	s := newAgreementScenario(t)
	api := s.iam.API.Agreements
	tenant := s.tenantID
	if !s.can(s.aliceToken, "documents:read") {
		t.Fatal("alice reads before any agreement")
	}
	content := "Be nice.\n\n1. Report incidents.\r\n2.\tLock your screen."
	agreement := s.obj(call(api.Create, s.adminToken, core.NewObject("tenantId", tenant, "name", "  Acceptable use ", "content", content, "url", "https://acme.test/aup")))
	if agreement.Get("version") != 1.0 || agreement.Get("required") != true || agreement.Get("name") != "Acceptable use" || agreement.Get("uniqueKey") != "name:acceptable use" {
		t.Fatalf("agreement = %s", stringify(agreement))
	}
	expectJSON(t, "member order", agreement.Keys(), `["uniqueKey","name","content","url","required","id","tenantId","version","createdAt","updatedAt"]`)
	agreementID := jsString(agreement.Get("id"))
	if s.can(s.aliceToken, "documents:read") {
		t.Fatal("a pending required agreement holds back access")
	}

	mine := s.list(call(api.ListMine, s.aliceToken, core.NewObject("tenantId", tenant)))
	if len(mine) != 1 {
		t.Fatalf("mine = %s", stringify(certRecordList(mine)))
	}
	expectJSON(t, "mine", mine[0], `{"id":"`+agreementID+`","name":"Acceptable use","content":`+core.QuoteJSON(content)+`,"url":"https://acme.test/aup","version":1,"required":true,"accepted":false}`)
	// Accepting an outdated version is refused.
	_, err := call(api.Accept, s.aliceToken, core.NewObject("tenantId", tenant, "agreementId", agreementID, "version", 2.0))
	expectError(t, err, "VERSION_CONFLICT", "The agreement changed; review the current version before accepting")
	_, err = call(api.Accept, s.aliceToken, core.NewObject("tenantId", tenant, "agreementId", agreementID, "version", 0.0))
	expectError(t, err, "INVALID_INPUT", "Invalid version")
	accepted := s.obj(call(api.Accept, s.aliceToken, core.NewObject("tenantId", tenant, "agreementId", agreementID, "version", 1.0)))
	expectJSON(t, "accepted", accepted, `{"accepted":true,"version":1,"acceptedAt":`+core.NumberString(s.now())+`}`)
	if !s.can(s.aliceToken, "documents:read") {
		t.Fatal("accepting restores access")
	}
	// Accepting again replaces the acceptance.
	s.obj(call(api.Accept, s.aliceToken, core.NewObject("tenantId", tenant, "agreementId", agreementID, "version", 1.0)))
	if acceptances := s.find("agreementAcceptances", core.NewObject("tenantId", tenant)); len(acceptances) != 1 || acceptances[0].Get("id") != agreementID+":"+s.aliceID {
		t.Errorf("acceptances = %s", stringify(certRecordList(acceptances)))
	}

	// A typo fix keeps acceptances; a new version asks again.
	fixed := s.obj(call(api.Update, s.adminToken, core.NewObject("tenantId", tenant, "agreementId", agreementID, "content", "Be kind.")))
	if fixed.Get("version") != 1.0 || fixed.Get("url") != "https://acme.test/aup" || fixed.Get("content") != "Be kind." {
		t.Errorf("fixed = %s", stringify(fixed))
	}
	if !s.can(s.aliceToken, "documents:read") {
		t.Fatal("a typo fix keeps acceptances")
	}
	v2 := s.obj(call(api.Update, s.adminToken, core.NewObject("tenantId", tenant, "agreementId", agreementID, "content", "Be kind and careful.", "newVersion", true)))
	if v2.Get("version") != 2.0 {
		t.Fatalf("v2 = %s", stringify(v2))
	}
	if s.can(s.aliceToken, "documents:read") {
		t.Fatal("a new version asks again")
	}
	status := s.obj(call(api.Status, s.adminToken, core.NewObject("tenantId", tenant, "agreementId", agreementID)))
	expectJSON(t, "status.accepted", status.Get("accepted"), `[]`)
	expectJSON(t, "status.agreement", status.Get("agreement"), `{"id":"`+agreementID+`","name":"Acceptable use","version":2,"required":true}`)
	if pending := stringify(status.Get("pending")); !strings.Contains(pending, `{"identity":{"id":"`+s.aliceID+`","name":"alice@acme.test"},"acceptedVersion":1}`) ||
		!strings.Contains(pending, `{"identity":{"id":"`+s.adminID+`","name":"admin@example.test"}}`) {
		t.Errorf("pending = %s", pending)
	}
	s.obj(call(api.Accept, s.aliceToken, core.NewObject("tenantId", tenant, "agreementId", agreementID, "version", 2.0)))
	if !s.can(s.aliceToken, "documents:read") {
		t.Fatal("accepting the new version restores access")
	}
	after := s.obj(call(api.Status, s.adminToken, core.NewObject("tenantId", tenant, "agreementId", agreementID)))
	acceptedList := s.list(after.Get("accepted"), nil)
	if len(acceptedList) != 1 || member(acceptedList[0].Get("identity"), "id") != s.aliceID || acceptedList[0].Get("version") != 2.0 {
		t.Errorf("accepted = %s", stringify(after.Get("accepted")))
	}

	// Annual re-acceptance: acceptance lapses.
	yearly := s.obj(call(api.Update, s.adminToken, core.NewObject("tenantId", tenant, "agreementId", agreementID, "reacceptAfterDays", 365.0)))
	if yearly.Get("reacceptAfterDays") != 365.0 || yearly.Get("version") != 2.0 {
		t.Errorf("yearly = %s", stringify(yearly))
	}
	s.advance(366 * certDay)
	fresh := s.token(s.alice)
	if s.can(fresh, "documents:read") {
		t.Fatal("a lapsed acceptance holds back access")
	}
	events := s.find("audit", core.NewObject("tenantId", tenant, "action", "agreement:accept"))
	sort.SliceStable(events, func(i, j int) bool { return jsNumber(events[i].Get("sequence")) < jsNumber(events[j].Get("sequence")) })
	if len(events) != 3 ||
		events[0].Get("actorId") != s.aliceID || stringify(events[0].Get("metadata")) != `{"name":"Acceptable use","version":1}` {
		t.Errorf("accept audit = %s", stringify(certRecordList(events)))
	}
	// Clearing the re-acceptance period (null) removes it.
	adminToken := s.token(s.admin)
	cleared := s.obj(call(api.Update, adminToken, core.NewObject("tenantId", tenant, "agreementId", agreementID, "reacceptAfterDays", nil, "url", "")))
	if cleared.Has("reacceptAfterDays") || cleared.Has("url") {
		t.Errorf("cleared = %s", stringify(cleared))
	}
	if !s.can(fresh, "documents:read") {
		t.Fatal("without a re-acceptance period the acceptance is current again")
	}
}

func TestAgreementsPolicyNamesOptionalAndSelfService(t *testing.T) {
	s := newAgreementScenario(t)
	api := s.iam.API.Agreements
	tenant := s.tenantID
	optional := s.obj(call(api.Create, s.adminToken, core.NewObject("tenantId", tenant, "name", "Beta program", "content", "Features may change.", "required", false)))
	// Optional agreements never hold anything back.
	if !s.can(s.aliceToken, "documents:read") {
		t.Fatal("optional agreements hold nothing back")
	}
	beta := document(core.NewObject("effect", "allow", "actions", []any{"documents:write"}, "resources", []any{"*"},
		"conditions", core.NewObject("ArrayContains", core.NewObject("principal.agreements", []any{"Beta program"}))))
	s.seed("policies", core.NewObject("id", "policy-beta", "tenantId", tenant, "name", "Beta", "document", beta, "version", 1.0, "authorityId", adminAuthority))
	s.seed("roles", core.NewObject("id", "role-beta", "tenantId", tenant, "name", "Beta writer", "policyIds", []any{"policy-beta"}, "authorityId", adminAuthority))
	s.bind("binding-beta", "role-beta", "identity", s.aliceID, adminAuthority)
	if s.can(s.aliceToken, "documents:write") {
		t.Fatal("beta writing needs the accepted agreement")
	}
	s.obj(call(api.Accept, s.aliceToken, core.NewObject("tenantId", tenant, "agreementId", optional.Get("id"), "version", 1.0)))
	if !s.can(s.aliceToken, "documents:write") {
		t.Fatal("the accepted name reaches policies")
	}

	// Management needs permissions; names are unique; members only accept for themselves.
	_, err := call(api.Create, s.aliceToken, core.NewObject("tenantId", tenant, "name", "Mine", "content", "x"))
	expectCodeStatus(t, err, "ACCESS_DENIED", 403)
	_, err = call(api.Create, s.adminToken, core.NewObject("tenantId", tenant, "name", "beta PROGRAM", "content", "x"))
	expectError(t, err, "CONFLICT", "An agreement with this name exists")
	_, err = call(api.Create, s.adminToken, core.NewObject("tenantId", tenant, "name", "Linked", "content", "x", "url", "javascript:alert(1)"))
	expectError(t, err, "INVALID_INPUT", "url must be an http(s) URL")
	_, err = call(api.Create, s.adminToken, core.NewObject("tenantId", tenant, "name", "Controls", "content", "bell \u0007"))
	expectError(t, err, "INVALID_INPUT", "Invalid content")
	_, err = call(api.Create, s.adminToken, core.NewObject("tenantId", tenant, "name", "   ", "content", "x"))
	expectError(t, err, "INVALID_INPUT", "Invalid name")
	_, err = call(api.Create, s.adminToken, core.NewObject("tenantId", tenant, "name", "Flag", "content", "x", "required", "yes"))
	expectError(t, err, "INVALID_INPUT", "required must be a boolean")
	_, err = call(api.Create, s.adminToken, core.NewObject("tenantId", tenant, "name", "Days", "content", "x", "reacceptAfterDays", 0.0))
	expectError(t, err, "INVALID_INPUT", "Invalid reacceptAfterDays")
	_, err = call(api.Update, s.adminToken, core.NewObject("tenantId", tenant, "agreementId", 5.0))
	expectError(t, err, "INVALID_INPUT", "Invalid agreementId")
	_, err = call(api.Update, s.adminToken, core.NewObject("tenantId", tenant, "agreementId", "missing"))
	expectError(t, err, "NOT_FOUND", "Resource not found")
	// Another tenant's agreements are not this session's to list.
	s.seed("tenants", core.NewObject("id", "other", "tenantId", "other", "name", "Other", "type", "organization", "parentId", tenant, "status", "active", "createdAt", 1.0))
	_, err = call(api.ListMine, s.aliceToken, core.NewObject("tenantId", "other"))
	expectError(t, err, "ACCESS_DENIED", "Agreements are accepted from an ordinary session of their tenant")
	_, err = call(api.Accept, s.aliceToken, core.NewObject("tenantId", "other", "agreementId", optional.Get("id"), "version", 1.0))
	expectError(t, err, "ACCESS_DENIED", "Agreements are accepted from an ordinary session of their tenant")
	_, err = call(api.ListMine, s.aliceToken, core.NewObject())
	expectError(t, err, "INVALID_INPUT", "Invalid tenantId")

	// listMine: outstanding before accepted, required before optional, then by name.
	s.obj(call(api.Create, s.adminToken, core.NewObject("tenantId", tenant, "name", "Zeta policy", "content", "z")))
	s.obj(call(api.Create, s.adminToken, core.NewObject("tenantId", tenant, "name", "Alpha extras", "content", "a", "required", false)))
	var order []string
	for _, entry := range s.list(call(api.ListMine, s.aliceToken, core.NewObject("tenantId", tenant))) {
		order = append(order, jsString(entry.Get("name")))
	}
	if strings.Join(order, ",") != "Zeta policy,Alpha extras,Beta program" {
		t.Errorf("listMine order = %v", order)
	}
	var names []string
	for _, entry := range s.list(call(api.List, s.adminToken, core.NewObject("tenantId", tenant))) {
		names = append(names, jsString(entry.Get("name")))
	}
	if strings.Join(names, ",") != "Alpha extras,Beta program,Zeta policy" {
		t.Errorf("list order = %v", names)
	}

	expectJSON(t, "delete", s.obj(call(api.Delete, s.adminToken, core.NewObject("tenantId", tenant, "agreementId", optional.Get("id")))), `{"deleted":true}`)
	if s.can(s.aliceToken, "documents:write") {
		t.Fatal("deleting the agreement removes the accepted name")
	}
	if acceptances := s.find("agreementAcceptances", core.NewObject("agreementId", optional.Get("id"))); len(acceptances) != 0 {
		t.Errorf("acceptances left: %d", len(acceptances))
	}
	if left := s.list(call(api.List, s.adminToken, core.NewObject("tenantId", tenant))); len(left) != 2 {
		t.Errorf("left = %d", len(left))
	}
}

func TestAgreementsLimitAndConfigurationHelpers(t *testing.T) {
	s := newAgreementScenario(t)
	ctx := context.Background()
	tenant := s.tenantID
	err := s.iam.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		for index := 0; index < maxAgreements; index++ {
			if _, err := SaveAgreement(ctx, s.iam.Context, tx, tenant, core.NewObject("name", "Agreement "+core.NumberString(float64(index)), "content", "x"), nil, false); err != nil {
				return err
			}
		}
		_, err := SaveAgreement(ctx, s.iam.Context, tx, tenant, core.NewObject("name", "One more", "content", "x"), nil, false)
		return err
	})
	expectError(t, err, "LIMIT_EXCEEDED", "At most 50 agreements")
	created, err := core.Transact(ctx, s.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return SaveAgreement(ctx, s.iam.Context, tx, tenant, core.NewObject("name", "Config", "content", "x", "reacceptAfterDays", 30.0), nil, false)
	})
	if err != nil {
		t.Fatal(err)
	}
	// An edit over a stored record keeps unknown members and their order.
	created.Set("custom", "kept")
	s.seed("agreements", created)
	edited, err := core.Transact(ctx, s.iam.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return SaveAgreement(ctx, s.iam.Context, tx, tenant, core.NewObject("url", "http://acme.test/config"), created, true)
	})
	if err != nil {
		t.Fatal(err)
	}
	expectJSON(t, "edited keys", edited.Keys(), `["uniqueKey","name","content","required","id","tenantId","version","createdAt","updatedAt","custom","url","reacceptAfterDays"]`)
	if edited.Get("version") != 2.0 || edited.Get("reacceptAfterDays") != 30.0 {
		t.Errorf("edited = %s", stringify(edited))
	}
	if err := s.iam.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error { return DeleteAgreement(ctx, tx, edited) }); err != nil {
		t.Fatal(err)
	}
	if found, _ := s.iam.Store.Get(ctx, "agreements", jsString(edited.Get("id"))); found != nil {
		t.Error("the agreement was not deleted")
	}
}
