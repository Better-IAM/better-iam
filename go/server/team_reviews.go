package server

// Skeleton of packages/server/src/team-reviews.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// CloseOverdueTeamReviews (team-reviews.ts closeOverdueTeamReviews): The scheduler job: completes every open team
// review past its due date (in active organizations), each in its own transaction, then re-evaluates the birthright
// packages of the people it removed.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CloseOverdueTeamReviews(ctx context.Context, server *ServerContext, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("team-reviews.ts closeOverdueTeamReviews")
	return
}

// CompleteTeamReview (team-reviews.ts completeTeamReview): Completes an open review inside the caller's transaction:
// removes the people decided (or defaulted to) `remove` who are still manual members, updates the backing groups,
// and audits every removal and the completion. `principal` is the person completing it; without one the scheduler
// (`deployment-operator`) is the actor.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func CompleteTeamReview(ctx context.Context, server *ServerContext, tx core.IamStore, review *core.Object, principal *Principal) (result *core.Object, err error) {
	err = notImplemented("team-reviews.ts completeTeamReview")
	return
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
