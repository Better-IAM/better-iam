package server

// Tests of team_reviews.go, ported from tests/team-reviews.test.ts (completing a review and the scheduler job that
// closes overdue reviews) at the module level: the review API (start, decide, cancel) belongs to another unit.

import (
	"context"
	"slices"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

const reviewDay = 86_400_000

// reviewFixture: Platform with bob (maintainer), alice, carol and dave (manual members) and erin (synced from
// Contractors), plus an open review of its members started by the owner.
func reviewFixture(t *testing.T, onUndecided string, dueIn int64) (*orgFixture, *core.Object) {
	t.Helper()
	f := newOrgFixture(t)
	f.insert("identities", identity("erin", "org"), identity("owner", "org", "owner", true))
	for _, person := range []string{"alice", "carol", "dave"} {
		f.member("platform", person, "member", 2)
	}
	f.member("platform", "erin", "member", 2, "source", "sync")
	f.sync("platform")
	now := float64(f.now())
	review := core.NewObject("id", "rev-1", "tenantId", "org", "uniqueKey", "open:platform", "teamId", "platform",
		"status", "open", "onUndecided", onUndecided, "startedAt", now, "startedBy", "owner", "dueAt", now+float64(dueIn),
		"note", "Quarterly check")
	f.insert(TeamReviewCollections.Reviews, review)
	for _, person := range []string{"alice", "bob", "carol", "dave"} {
		role := "member"
		if person == "bob" {
			role = "maintainer"
		}
		f.insert(TeamReviewCollections.Items, core.NewObject("id", "item-"+person, "tenantId", "org",
			"uniqueKey", "rev-1:"+person, "reviewId", "rev-1", "teamId", "platform", "identityId", person, "role", role))
	}
	return f, review
}

func (f *orgFixture) decide(identityID, decision string) {
	f.t.Helper()
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		item := must(tx.Get(ctx, TeamReviewCollections.Items, "item-"+identityID))
		item.Set("decision", decision)
		item.Set("decidedBy", "bob")
		item.Set("decidedAt", float64(f.server.Now()))
		_, err := tx.Put(ctx, TeamReviewCollections.Items, item)
		return err
	}); err != nil {
		f.t.Fatal(err)
	}
}

func (f *orgFixture) teamMembers(teamID string) []string {
	f.t.Helper()
	records := must(f.store.Find(f.ctx, TeamCollections.Members, core.NewObject("tenantId", f.tenantID, "teamId", teamID), nil))
	out := orgStringsOf(records, "identityId")
	slices.Sort(out)
	return out
}

func orgStringsOf(records []*core.Object, key string) []string {
	out := []string{}
	for _, record := range records {
		out = append(out, orgString(record, key))
	}
	return out
}

func TestCompleteTeamReview(t *testing.T) {
	f, review := reviewFixture(t, "keep", 14*reviewDay)
	f.decide("alice", "keep")
	f.decide("carol", "remove")
	owner := principalOf(must(f.store.Get(f.ctx, "identities", "owner")), session("s-owner", "owner", "org", "user"))
	f.advance(1_000)
	var completion *core.Object
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		completion, err = CompleteTeamReview(ctx, f.server, tx, review, owner)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	expectObject(t, "removed", completion.Get("removed"), `["carol"]`)
	completed := completion.Get("review").(*core.Object)
	now := core.NumberString(float64(f.now()))
	start := core.NumberString(float64(f.now() - 1_000))
	expectObject(t, "review", completed, `{"id":"rev-1","tenantId":"org","teamId":"platform","status":"completed","onUndecided":"keep",`+
		`"startedAt":`+start+`,"startedBy":"owner","dueAt":`+core.NumberString(float64(f.now()-1_000+14*reviewDay))+`,"note":"Quarterly check",`+
		`"completedAt":`+now+`,"completedBy":"owner","outcome":{"kept":3,"removed":1,"undecided":2,"gone":0}}`)
	stored := must(f.store.Get(f.ctx, TeamReviewCollections.Reviews, "rev-1"))
	if !isUndefined(stored.Get("uniqueKey")) || orgString(stored, "status") != "completed" {
		t.Fatalf("stored %s", core.MustStringify(stored))
	}
	expectStrings(t, "members", f.teamMembers("platform"), "alice", "bob", "dave", "erin")
	expectStrings(t, "backing group", f.groupMembers("g-platform"), "alice", "bob", "dave", "erin")

	removals := must(f.store.Find(f.ctx, "audit", core.NewObject("tenantId", "org", "action", "team:member:remove"), nil))
	if len(removals) != 1 || orgString(removals[0], "actorId") != "owner" || orgString(removals[0], "resourceId") != "platform" {
		t.Fatalf("removals %s", core.MustStringify(removals))
	}
	expectObject(t, "removal metadata", removals[0].Get("metadata"), `{"identityId":"carol","role":"member","source":"review","reviewId":"rev-1"}`)
	completions := must(f.store.Find(f.ctx, "audit", core.NewObject("tenantId", "org", "action", "team:review:complete"), nil))
	if len(completions) != 1 {
		t.Fatalf("completions %d", len(completions))
	}
	expectObject(t, "completion metadata", completions[0].Get("metadata"), `{"reviewId":"rev-1","kept":3,"removed":1,"undecided":2,"gone":0}`)
}

func TestCompleteTeamReviewCountsPeopleWhoLeft(t *testing.T) {
	f, review := reviewFixture(t, "remove", 14*reviewDay)
	// Dave left; team sync now manages carol; alice's membership ended.
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		if err := tx.Delete(ctx, TeamCollections.Members, "tm-platform-dave"); err != nil {
			return err
		}
		carol := must(tx.Get(ctx, TeamCollections.Members, "tm-platform-carol"))
		carol.Set("source", "sync")
		if _, err := tx.Put(ctx, TeamCollections.Members, carol); err != nil {
			return err
		}
		alice := must(tx.Get(ctx, TeamCollections.Members, "tm-platform-alice"))
		alice.Set("expiresAt", float64(f.server.Now()))
		_, err := tx.Put(ctx, TeamCollections.Members, alice)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var completion *core.Object
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		var err error
		completion, err = CompleteTeamReview(ctx, f.server, tx, review, nil)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	expectObject(t, "removed", completion.Get("removed"), `["bob"]`)
	completed := completion.Get("review").(*core.Object)
	expectObject(t, "outcome", completed.Get("outcome"), `{"kept":0,"removed":1,"undecided":4,"gone":3}`)
	expectObject(t, "completedBy", completed.Get("completedBy"), `"deployment-operator"`)
	removals := must(f.store.Find(f.ctx, "audit", core.NewObject("tenantId", "org", "action", "team:member:remove"), nil))
	if len(removals) != 1 || orgString(removals[0], "actorId") != "deployment-operator" {
		t.Fatalf("removals %s", core.MustStringify(removals))
	}
	expectObject(t, "metadata", removals[0].Get("metadata"), `{"identityId":"bob","role":"maintainer","source":"review","reviewId":"rev-1","undecided":true}`)
}

// orgAfterChangeStub reports whether the only failures are the afterIdentityChange stub of another unit (the review
// itself committed before it runs).
func orgAfterChangeStub(failed []any) bool {
	for _, entry := range failed {
		if !strings.Contains(orgString(entry.(*core.Object), "message"), "afterIdentityChange") {
			return false
		}
	}
	return true
}

func TestCloseOverdueTeamReviews(t *testing.T) {
	f, _ := reviewFixture(t, "remove", 2*reviewDay)
	f.decide("alice", "keep")
	// Not due yet: nothing happens.
	expectObject(t, "not due", must(CloseOverdueTeamReviews(f.ctx, f.server, nil)), `{"completed":0,"removed":0,"failed":[]}`)
	f.advance(3 * reviewDay)
	// Another tenant's filter leaves it alone.
	expectObject(t, "other tenant", must(CloseOverdueTeamReviews(f.ctx, f.server, core.NewObject("tenantId", "project"))), `{"completed":0,"removed":0,"failed":[]}`)
	result := must(CloseOverdueTeamReviews(f.ctx, f.server, core.NewObject("tenantId", "org")))
	if jsNumber(result.Get("completed")) != 1 || jsNumber(result.Get("removed")) != 3 {
		t.Fatalf("result %s", core.MustStringify(result))
	}
	failed, _ := result.Get("failed").([]any)
	if len(failed) > 0 && !orgAfterChangeStub(failed) {
		t.Fatalf("failed %s", core.MustStringify(failed))
	}
	// Undecided people (bob, carol, dave) left; the synced member stays.
	expectStrings(t, "members", f.teamMembers("platform"), "alice", "erin")
	closed := must(f.store.Get(f.ctx, TeamReviewCollections.Reviews, "rev-1"))
	expectObject(t, "completedBy", closed.Get("completedBy"), `"deployment-operator"`)
	expectObject(t, "outcome", closed.Get("outcome"), `{"kept":1,"removed":3,"undecided":3,"gone":0}`)
	// Nothing left to close.
	expectObject(t, "again", must(CloseOverdueTeamReviews(f.ctx, f.server, nil)), `{"completed":0,"removed":0,"failed":[]}`)
	if len(failed) > 0 {
		t.Skip("birthright re-evaluation blocked by another unit: " + orgString(failed[0].(*core.Object), "message"))
	}
}

func TestCloseOverdueTeamReviewsSkipsInactiveOrganizations(t *testing.T) {
	f, _ := reviewFixture(t, "remove", reviewDay)
	f.advance(2 * reviewDay)
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		tenant := must(tx.Get(ctx, "tenants", "org"))
		tenant.Set("status", "suspended")
		_, err := tx.Put(ctx, "tenants", tenant)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	expectObject(t, "suspended", must(CloseOverdueTeamReviews(f.ctx, f.server, nil)), `{"completed":0,"removed":0,"failed":[]}`)
	if err := f.tx(func(ctx context.Context, tx core.IamStore) error {
		tenant := must(tx.Get(ctx, "tenants", "org"))
		tenant.Set("status", "active")
		if _, err := tx.Put(ctx, "tenants", tenant); err != nil {
			return err
		}
		return tx.Delete(ctx, TeamCollections.Teams, "platform")
	}); err != nil {
		t.Fatal(err)
	}
	// A review of a deleted team is left alone.
	expectObject(t, "deleted team", must(CloseOverdueTeamReviews(f.ctx, f.server, nil)), `{"completed":0,"removed":0,"failed":[]}`)
	expectObject(t, "still open", must(f.store.Get(f.ctx, TeamReviewCollections.Reviews, "rev-1")).Get("status"), `"open"`)
}
