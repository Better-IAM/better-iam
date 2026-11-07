package server

// Access request tests, after the access-request case of tests/access.test.ts and the guards of
// tests/derived-session-guards.test.ts and tests/security-impersonation-grants.test.ts: members request roles that a
// reviewer approves under their own grant authority as temporary bindings; denial, cancellation and expiry. Roles,
// authorities and bindings are seeded directly in the store.

import (
	"context"
	"sort"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

func TestAccessRequestsApproveUnderTheReviewersAuthority(t *testing.T) {
	lifetime := 60 * 60_000.0
	f := newGovFixture(t, func(options *BetterIamOptions) {
		options.AccessRequests = &AccessRequestOptions{LifetimeMs: &lifetime}
	})
	api := f.iam.API.AccessRequests
	tenant := f.tenantID
	ctx := context.Background()
	alice := f.person("alice")
	reviewer := f.person("reviewer")
	aliceID, reviewerID := jsString(alice.Get("id")), jsString(reviewer.Get("id"))
	f.bind("b-alice", f.role("role-requester", "Requester", false, "iam:access-requests:create"), "identity", aliceID, adminAuthority)
	f.bind("b-reviewer", f.role("role-reviewer", "Reviewer", false, "iam:access-requests:read", "iam:access-requests:review", "iam:bindings:create", "iam:roles:read"), "identity", reviewerID, adminAuthority)
	admin := f.role("role-docadmin", "Document admin", false, "documents:read", "documents:write")
	aliceToken, reviewerToken := f.token(alice), f.token(reviewer)

	_, err := call(api.Create, aliceToken, core.NewObject("tenantId", tenant, "roleIds", []any{f.ownerRole}))
	expectError(t, err, "PROTECTED_RESOURCE", "Owner roles cannot be requested")
	_, err = call(api.Create, aliceToken, core.NewObject("tenantId", tenant, "roleIds", []any{}))
	expectError(t, err, "INVALID_INPUT", "Request 1-20 roles")
	_, err = call(api.Create, aliceToken, core.NewObject("tenantId", tenant, "roleIds", []any{admin}, "durationSeconds", 10.0))
	expectError(t, err, "INVALID_INPUT", "Invalid durationSeconds")
	_, err = call(api.Create, aliceToken, core.NewObject("tenantId", tenant, "roleIds", []any{"missing"}))
	expectError(t, err, "NOT_FOUND", "Resource not found")
	_, err = call(api.Create, reviewerToken, core.NewObject("tenantId", tenant, "roleIds", []any{admin}))
	expectCodeStatus(t, err, "ACCESS_DENIED", 403)
	request := f.obj(call(api.Create, aliceToken, core.NewObject("tenantId", tenant, "roleIds", []any{admin, admin}, "justification", "Incident 42", "durationSeconds", 2*3600.0)))
	requestID := jsString(request.Get("id"))
	expectJSON(t, "request", request, `{"id":"`+requestID+`","tenantId":"`+tenant+`","requesterId":"`+aliceID+`","roleIds":["role-docadmin"],"status":"pending","createdAt":`+
		core.NumberString(f.now())+`,"expiresAt":`+core.NumberString(f.now()+lifetime)+`,"justification":"Incident 42","durationSeconds":7200}`)
	_, err = call(api.Create, aliceToken, core.NewObject("tenantId", tenant, "roleIds", []any{admin}))
	expectError(t, err, "CONFLICT", "An identical request is already pending")
	if mine := f.list(call(api.ListMine, aliceToken, core.NewObject("tenantId", tenant))); len(mine) != 1 || mine[0].Get("id") != requestID {
		t.Errorf("listMine = %s", stringify(certRecordList(mine)))
	}
	_, err = call(api.List, aliceToken, core.NewObject("tenantId", tenant))
	expectCodeStatus(t, err, "ACCESS_DENIED", 403)
	if pending := f.list(call(api.List, reviewerToken, core.NewObject("tenantId", tenant, "status", "pending"))); len(pending) != 1 || pending[0].Get("id") != requestID {
		t.Errorf("pending = %s", stringify(certRecordList(pending)))
	}
	_, err = call(api.List, reviewerToken, core.NewObject("tenantId", tenant, "status", "open"))
	expectError(t, err, "INVALID_INPUT", "Invalid status")
	if byRequester := f.list(call(api.List, reviewerToken, core.NewObject("tenantId", tenant, "requesterId", reviewerID))); len(byRequester) != 0 {
		t.Errorf("by requester = %d", len(byRequester))
	}
	check := func() bool { return f.authorize(aliceToken, "documents:write", "document", "runbook").Allowed }
	if check() {
		t.Fatal("nothing is granted before approval")
	}
	// A requester cannot approve their own request, and a reviewer needs a grant authority.
	_, err = call(api.Approve, aliceToken, core.NewObject("tenantId", tenant, "requestId", requestID))
	expectCodeStatus(t, err, "ACCESS_DENIED", 403)
	_, err = call(api.Approve, reviewerToken, core.NewObject("tenantId", tenant, "requestId", requestID))
	expectError(t, err, "GRANT_AUTHORITY_REQUIRED", "An active delegated grant authority is required")
	f.seed("grantAuthorities", core.NewObject("id", "authority-reviewer", "tenantId", tenant, "identityId", reviewerID,
		"ceiling", document(allowStatement("documents:*", "*")), "revoked", false))
	approved := f.obj(call(api.Approve, reviewerToken, core.NewObject("tenantId", tenant, "requestId", requestID, "note", "Approved for the incident")))
	if approved.Get("status") != "approved" || approved.Get("reviewerId") != reviewerID || approved.Get("note") != "Approved for the incident" ||
		approved.Get("grantExpiresAt") != f.now()+7200_000 || approved.Get("reviewedAt") != f.now() {
		t.Fatalf("approved = %s", stringify(approved))
	}
	bindingIDs, _ := approved.Get("bindingIds").([]any)
	if len(bindingIDs) != 1 {
		t.Fatalf("bindingIds = %v", bindingIDs)
	}
	if !check() {
		t.Fatal("approval grants the role")
	}
	granted := f.find("bindings", core.NewObject("tenantId", tenant, "roleId", admin, "subjectId", aliceID))
	if len(granted) != 1 || granted[0].Get("expiresAt") != f.now()+7200_000 || granted[0].Get("accessRequestId") != requestID ||
		granted[0].Get("uniqueKey") != "identity:"+aliceID+":"+admin+":authority-reviewer" || granted[0].Get("authorityId") != "authority-reviewer" {
		t.Errorf("granted = %s", stringify(certRecordList(granted)))
	}
	f.advance(7201_000)
	if check() {
		t.Fatal("the grant expires")
	}
	_, err = call(api.Approve, reviewerToken, core.NewObject("tenantId", tenant, "requestId", requestID))
	expectError(t, err, "INVALID_TRANSITION", "Request is approved")

	// Denial, cancellation, expiry, and the audit trail.
	second := f.obj(call(api.Create, aliceToken, core.NewObject("tenantId", tenant, "roleIds", []any{admin})))
	denied := f.obj(call(api.Deny, reviewerToken, core.NewObject("tenantId", tenant, "requestId", second.Get("id"), "note", "Not now")))
	if denied.Get("status") != "denied" || denied.Get("note") != "Not now" || denied.Get("reviewerId") != reviewerID {
		t.Errorf("denied = %s", stringify(denied))
	}
	third := f.obj(call(api.Create, aliceToken, core.NewObject("tenantId", tenant, "roleIds", []any{admin})))
	_, err = call(api.Cancel, reviewerToken, core.NewObject("tenantId", tenant, "requestId", third.Get("id")))
	expectCodeStatus(t, err, "ACCESS_DENIED", 403)
	cancelled := f.obj(call(api.Cancel, aliceToken, core.NewObject("tenantId", tenant, "requestId", third.Get("id"))))
	if cancelled.Get("status") != "cancelled" || cancelled.Get("reviewedAt") != f.now() {
		t.Errorf("cancelled = %s", stringify(cancelled))
	}
	fourth := f.obj(call(api.Create, aliceToken, core.NewObject("tenantId", tenant, "roleIds", []any{admin})))
	f.advance(61 * 60_000)
	if status := f.obj(call(api.Get, reviewerToken, core.NewObject("tenantId", tenant, "requestId", fourth.Get("id")))).Get("status"); status != "expired" {
		t.Errorf("fourth status = %v", status)
	}
	if expired := f.list(call(api.ListMine, aliceToken, core.NewObject("tenantId", tenant, "status", "pending"))); len(expired) != 1 || expired[0].Get("status") != "expired" {
		t.Errorf("pending filter reads expired requests as expired: %s", stringify(certRecordList(expired)))
	}
	_, err = call(api.Deny, reviewerToken, core.NewObject("tenantId", tenant, "requestId", fourth.Get("id")))
	expectError(t, err, "INVALID_TRANSITION", "Request is expired")
	// The stored record stays pending until the purge worker marks it.
	if stored, _ := f.iam.Store.Get(ctx, "accessRequests", jsString(fourth.Get("id"))); stored.Get("status") != "pending" {
		t.Errorf("stored status = %v", stored.Get("status"))
	}
	var trail []string
	for _, action := range []string{"access-request:approve", "access-request:deny"} {
		for _, event := range f.find("audit", core.NewObject("tenantId", tenant, "action", action)) {
			trail = append(trail, action)
			if action == "access-request:approve" && stringify(event.Get("metadata")) !=
				`{"requesterId":"`+aliceID+`","roleIds":["role-docadmin"],"bindingIds":["`+jsString(bindingIDs[0])+`"],"grantExpiresAt":`+core.NumberString(jsNumber(approved.Get("grantExpiresAt")))+`}` {
				t.Errorf("approve audit = %s", stringify(event))
			}
		}
	}
	sort.Strings(trail)
	expectJSON(t, "trail", stringsOf(trail), `["access-request:approve","access-request:deny"]`)

	// Approval reuses an existing standing binding instead of duplicating it, and an approver override shortens the
	// grant. (The expired grant is what the purge worker removes.)
	if err := f.iam.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		return tx.Delete(ctx, "bindings", jsString(bindingIDs[0]))
	}); err != nil {
		t.Fatal(err)
	}
	f.seed("bindings", core.NewObject("id", "standing", "tenantId", tenant, "uniqueKey", "identity:"+aliceID+":"+admin+":authority-reviewer",
		"subjectType", "identity", "subjectId", aliceID, "roleId", admin, "authorityId", "authority-reviewer"))
	reviewerToken = f.token(reviewer)
	aliceToken = f.token(alice)
	fifth := f.obj(call(api.Create, aliceToken, core.NewObject("tenantId", tenant, "roleIds", []any{admin}, "durationSeconds", 86400.0)))
	_, err = call(api.Approve, reviewerToken, core.NewObject("tenantId", tenant, "requestId", fifth.Get("id"), "durationSeconds", 30.0))
	expectError(t, err, "INVALID_INPUT", "Invalid durationSeconds")
	shortened := f.obj(call(api.Approve, reviewerToken, core.NewObject("tenantId", tenant, "requestId", fifth.Get("id"), "durationSeconds", 600.0)))
	if shortened.Get("grantExpiresAt") != f.now()+600_000 {
		t.Errorf("shortened = %s", stringify(shortened))
	}
	reused := f.find("bindings", core.NewObject("tenantId", tenant, "roleId", admin, "subjectId", aliceID))
	if len(reused) != 1 || reused[0].Get("id") != "standing" || reused[0].Get("expiresAt") != f.now()+600_000 || reused[0].Get("accessRequestId") != fifth.Get("id") {
		t.Errorf("reused = %s", stringify(certRecordList(reused)))
	}
}

func TestAccessRequestsSessionGuards(t *testing.T) {
	f := newGovFixture(t, nil)
	api := f.iam.API.AccessRequests
	tenant := f.tenantID
	alice := f.person("alice")
	aliceID := jsString(alice.Get("id"))
	f.bind("b-alice", f.role("role-requester", "Requester", false, "iam:access-requests:create"), "identity", aliceID, adminAuthority)
	readers := f.role("role-readers", "Readers", false, "documents:read")
	// A request is made from an ordinary session of the target tenant.
	f.seed("tenants", core.NewObject("id", "other", "tenantId", "other", "name", "Other", "type", "organization", "parentId", tenant, "status", "active", "createdAt", 1.0))
	f.seed("roles", core.NewObject("id", "role-other", "tenantId", "other", "name", "Other readers", "authorityId", adminAuthority))
	// The root administrator is authorized everywhere, but their session belongs to the root tenant.
	owner, err := f.iam.Store.Get(context.Background(), "identities", jsString(member(f.root.Get("identity"), "id")))
	if err != nil {
		t.Fatal(err)
	}
	rootToken := f.signIn(owner, true)
	_, err = call(api.Create, rootToken, core.NewObject("tenantId", "other", "roleIds", []any{"role-other"}))
	expectError(t, err, "INVALID_INPUT", "Requests are made from an ordinary session of the target tenant")
	// Twenty pending requests are the most one person keeps open.
	aliceToken := f.token(alice)
	roles := make([]any, 0, 21)
	for index := 0; index < 21; index++ {
		roles = append(roles, f.role("role-r"+core.NumberString(float64(index)), "R"+core.NumberString(float64(index)), false, "documents:read"))
	}
	_, err = call(api.Create, aliceToken, core.NewObject("tenantId", tenant, "roleIds", roles))
	expectError(t, err, "INVALID_INPUT", "Request 1-20 roles")
	for index := 0; index < 20; index++ {
		f.obj(call(api.Create, aliceToken, core.NewObject("tenantId", tenant, "roleIds", []any{roles[index]})))
	}
	_, err = call(api.Create, aliceToken, core.NewObject("tenantId", tenant, "roleIds", []any{readers}))
	expectError(t, err, "TOO_MANY_REQUESTS", "Resolve pending requests before opening more")
	// An inactive tenant takes no requests.
	f.change("tenants", "other", "status", "suspended")
	_, err = call(api.Create, rootToken, core.NewObject("tenantId", "other", "roleIds", []any{"role-other"}))
	expectError(t, err, "TENANT_INACTIVE", "Tenant must be active")
}
