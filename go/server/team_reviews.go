package server

// Port of packages/server/src/team-reviews.ts: team membership reviews. An administrator opens a review of a team's
// manual members, the team's maintainers (or those of a team above it, or administrators) decide `keep` or `remove`
// for each person, and completing the review removes everyone decided `remove` and, by the review's `onUndecided`
// rule, those nobody decided on. Members team sync manages are not reviewed (their source group is). A review past its
// `dueAt` is completed by the scheduler job `closeOverdueTeamReviews`.

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// CompleteTeamReview (team-reviews.ts completeTeamReview): Completes an open review inside the caller's transaction:
// removes the people decided (or defaulted to) `remove` who are still manual members, updates the backing groups,
// and audits every removal and the completion. `principal` is the person completing it; without one the scheduler
// (`deployment-operator`) is the actor. The result is `{ review, removed }` (`removed`: the people removed from the
// team, for re-evaluating their birthright packages after commit).
func CompleteTeamReview(ctx context.Context, server *ServerContext, tx core.IamStore, review *core.Object, principal *Principal) (*core.Object, error) {
	now := server.Now()
	tenantID := orgString(review, "tenantId")
	teamID := orgString(review, "teamId")
	reviewID := orgString(review, "id")
	record := func(action string, metadata *core.Object) error {
		if principal != nil {
			return server.Events.Audit(ctx, tx, principal, action, tenantID, teamID, "allow", false, metadata)
		}
		return server.Events.RecordAudit(ctx, tx, core.NewObject(
			"id", ID(),
			"tenantId", review.Get("tenantId"),
			"actorId", "deployment-operator",
			"action", action,
			"resourceId", review.Get("teamId"),
			"timestamp", now,
			"outcome", "allow",
			"metadata", metadata,
		))
	}
	kept, removedCount, undecided, gone := 0, 0, 0, 0
	removed := []string{}
	items, err := tx.Find(ctx, TeamReviewCollections.Items, core.NewObject("tenantId", tenantID, "reviewId", reviewID), nil)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		decision := item.Get("decision")
		if isUndefined(decision) {
			undecided++
		}
		members, err := tx.Find(ctx, TeamCollections.Members, core.NewObject("tenantId", tenantID, "uniqueKey", teamID+":"+orgString(item, "identityId")), nil)
		if err != nil {
			return nil, err
		}
		var member *core.Object
		if len(members) > 0 {
			member = members[0]
		}
		// Someone who left, or whom team sync now manages, is outside the review.
		if member == nil || !liveTeamMember(member, now) || orgString(member, "source") == "sync" {
			gone++
			continue
		}
		effective := decision
		if isUndefined(effective) {
			effective = review.Get("onUndecided")
		}
		if text, _ := effective.(string); text == "keep" {
			kept++
			continue
		}
		if err := tx.Delete(ctx, TeamCollections.Members, orgString(member, "id")); err != nil {
			return nil, err
		}
		removed = append(removed, orgString(member, "identityId"))
		removedCount++
		metadata := core.NewObject(
			"identityId", member.Get("identityId"),
			"role", member.Get("role"),
			"source", "review",
			"reviewId", review.Get("id"),
		)
		if isUndefined(decision) {
			metadata.Set("undecided", true)
		}
		if err := record("team:member:remove", metadata); err != nil {
			return nil, err
		}
	}
	if len(removed) > 0 {
		if _, err := SyncTeamGroups(ctx, tx, tenantID, []string{teamID}, now); err != nil {
			return nil, err
		}
	}
	outcome := func() *core.Object {
		return core.NewObject("kept", kept, "removed", removedCount, "undecided", undecided, "gone", gone)
	}
	rest := review.Clone()
	rest.Delete("uniqueKey")
	rest.Set("status", "completed")
	rest.Set("completedAt", now)
	if principal != nil {
		rest.Set("completedBy", principal.Identity.Get("id"))
	} else {
		rest.Set("completedBy", "deployment-operator")
	}
	rest.Set("outcome", outcome())
	completed, err := tx.Put(ctx, TeamReviewCollections.Reviews, rest)
	if err != nil {
		return nil, err
	}
	if err := record("team:review:complete", core.NewObject("reviewId", review.Get("id")).Assign(outcome())); err != nil {
		return nil, err
	}
	return core.NewObject("review", completed, "removed", stringsOf(removed)), nil
}

// CloseOverdueTeamReviews (team-reviews.ts closeOverdueTeamReviews): The scheduler job: completes every open team
// review past its due date (in active organizations), each in its own transaction, then re-evaluates the birthright
// packages of the people it removed. Input: `{ tenantId? }`; the result is `{ completed, removed, failed }`.
func CloseOverdueTeamReviews(ctx context.Context, server *ServerContext, input *core.Object) (*core.Object, error) {
	now := server.Now()
	filter := core.NewObject("status", "open")
	if input != nil {
		if tenantID := input.Get("tenantId"); truthy(tenantID) {
			filter.Set("tenantId", tenantID)
		}
	}
	reviews, err := server.Store.Find(ctx, TeamReviewCollections.Reviews, filter, nil)
	if err != nil {
		return nil, err
	}
	var due []*core.Object
	for _, review := range reviews {
		if jsNumber(review.Get("dueAt")) <= float64(now) {
			due = append(due, review)
		}
	}
	completed, removed := 0, 0
	failed := []any{}
	for _, candidate := range due {
		var done *core.Object
		err := server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			done = nil
			review, err := tx.Get(ctx, TeamReviewCollections.Reviews, orgString(candidate, "id"))
			if err != nil {
				return err
			}
			if review == nil || orgString(review, "status") != "open" || jsNumber(review.Get("dueAt")) > float64(server.Now()) {
				return nil
			}
			tenant, err := tx.Get(ctx, "tenants", orgString(review, "tenantId"))
			if err != nil {
				return err
			}
			if tenant == nil || orgString(tenant, "status") != "active" {
				return nil
			}
			team, err := tx.Get(ctx, TeamCollections.Teams, orgString(review, "teamId"))
			if err != nil {
				return err
			}
			if team == nil {
				return nil
			}
			done, err = CompleteTeamReview(ctx, server, tx, review, nil)
			return err
		})
		if err == nil && done != nil {
			completed++
			people := orgStrings(done, "removed")
			removed += len(people)
			_, err = AfterIdentityChange(ctx, server, orgString(candidate, "tenantId"), people, core.Undefined)
		}
		if err != nil {
			failed = append(failed, core.NewObject("reviewId", candidate.Get("id"), "message", errorMessage(err)))
		}
	}
	return core.NewObject("completed", completed, "removed", removed, "failed", failed), nil
}

// DefaultReviewMs is team-reviews.ts defaultReviewMs.
const DefaultReviewMs = 1209600000

// MaxReviewMs is team-reviews.ts maxReviewMs.
const MaxReviewMs = 7776000000

// MinReviewMs is team-reviews.ts minReviewMs.
const MinReviewMs = 86400000

// TeamReviewCollections is team-reviews.ts teamReviewCollections.
var TeamReviewCollections = struct {
	Reviews string
	Items   string
}{"teamReviews", "teamReviewItems"}
