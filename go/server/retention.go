package server

// Port of packages/server/src/retention.ts: the retention sweep. It deletes records the rest of the system already
// treats as dead (expired sessions of the swept kinds, trusted devices, relationship tuples, protocol artifacts,
// delivered or abandoned deliveries, dispatched audit hooks, lapsed guest invitations, ...), a batch per short
// transaction, so storage stops growing with traffic, and never anything a person or report can still use.

import (
	"context"
	"math"

	"github.com/Better-IAM/better-iam/go/core"
)

const retentionDay = 86_400_000

// retentionSweptSessionKinds are the session kinds whose expired records nothing reads; API keys stay.
var retentionSweptSessionKinds = newOrderedSet("user", "role", "session-token", "delegated")

// retentionGrantMs is how long expired OAuth Grant rows stay (back-channel logout finds the client through them).
const retentionGrantMs = 31 * retentionDay

// Retention is retention.ts createRetention().
type Retention struct {
	server *ServerContext
}

// CreateRetention builds the Retention (retention.ts createRetention).
func CreateRetention(server *ServerContext) *Retention {
	return &Retention{server: server}
}

// sweepTarget is one collection (and field) the sweep walks.
type sweepTarget struct {
	collection string
	// filter is the equality filter; used only for legacy records that lack the indexed field (nil: none).
	filter *core.Object
	// field is the numeric field the expiry indexes order by; "" for flag-only targets.
	field string
	// cutoff is the newest field value that is due (set with field).
	cutoff float64
	// keep marks due records that must stay anyway (nil: none).
	keep func(record *core.Object) bool
}

func (t *sweepTarget) kept(record *core.Object) bool {
	return t.keep != nil && t.keep(record)
}

// retentionBounded is `value ?? fallback` as a safe integer within [min, max].
func retentionBounded(value any, fallback, min, max float64, name string) (float64, error) {
	resolved := coalesce(value, fallback)
	number, ok := resolved.(float64)
	if !ok || !core.IsSafeInteger(number) || number < min || number > max {
		return 0, invalidInput(name + " must be an integer between " + core.NumberString(min) + " and " + core.NumberString(max))
	}
	return number, nil
}

// sweepTargets are the sweep's targets for one run; also what CountDue counts. now (nil: the clocks) overrides
// both clocks.
func (s *Retention) sweepTargets(now any, retention, grace float64) []*sweepTarget {
	appNow, wallNow := float64(s.server.Now()), float64(s.server.Wall())
	if value, ok := now.(float64); ok {
		appNow, wallNow = value, value
	}
	expired := func(collection string, now float64, keep func(*core.Object) bool) *sweepTarget {
		return &sweepTarget{collection: collection, field: "expiresAt", cutoff: now - grace, keep: keep}
	}
	return []*sweepTarget{
		expired("sessions", appNow, func(record *core.Object) bool {
			kind, ok := record.Get("kind").(string)
			return !ok || !retentionSweptSessionKinds.Has(kind)
		}),
		expired("authDevices", appNow, nil),
		expired("relationships", appNow, nil),
		// Written on the authentication clock (the exchange verifies tokens against ctx.now()).
		expired("webIdentityReplays", appNow, nil),
		expired("oauthArtifacts", wallNow, func(record *core.Object) bool {
			return record.Get("model") == "Grant" && jsNumber(record.Get("expiresAt")) > wallNow-retentionGrantMs
		}),
		expired("oauthLoginStates", wallNow, nil),
		expired("samlRequests", wallNow, nil),
		expired("samlRelays", wallNow, nil),
		expired("samlAssertions", wallNow, nil),
		// Inference metering: usage records past retention, budget counters after their window, unredeemed tickets.
		expired("inferenceUsage", appNow, nil),
		expired("inferenceCounters", appNow, nil),
		expired("inferenceTickets", appNow, nil),
		// Responses API ownership records, kept as long as usage records.
		expired("inferenceResponses", appNow, nil),
		// Agent confirmation requests past their decision window or approval validity.
		expired("delegationConfirmations", appNow, nil),
		// Issued delegation tokens past their expiry.
		expired("delegationTokens", appNow, nil),
		// Agent directory entries whose attestation has expired.
		expired("agentCards", appNow, nil),
		// Team memberships past their end; join requests are history.
		expired("teamMembers", appNow, nil),
		// Vault access records past `vault.accessRetentionDays`.
		expired("vaultAccess", appNow, nil),
		// Quota window counters a day after their window, and idle throttle buckets once full again.
		expired("quotaCounters", appNow, nil),
		// Data-subject request exports past their download window.
		expired("privacyExports", appNow, nil),
		// Finished workflow runs 180 days after they ended.
		expired("workflowRuns", appNow, nil),
		// Compliance results and runs 400 days after their evaluation.
		expired("complianceResults", appNow, nil),
		expired("complianceRuns", appNow, nil),
		// Compliance exceptions (revoked ones too) 400 days after they expired.
		expired("complianceExceptions", appNow, func(record *core.Object) bool {
			return jsNumber(record.Get("expiresAt")) > appNow-400*86_400_000
		}),
		// App assignments past their end.
		expired("appAssignments", appNow, nil),
		// SSH certificate records `ssh.recordRetentionDays` after the certificate expired.
		expired("sshCertificates", appNow, nil),
		// Verifiable credential records past their retention, used or lapsed wallet offers, and proof nonces.
		expired("vcIssued", appNow, nil),
		expired("vcOffers", appNow, nil),
		expired("vcNonces", appNow, nil),
		// Device enrollment codes past their expiry, used or not.
		expired("deviceEnrollments", appNow, nil),
		// Received Shared Signals events 90 days after receipt.
		expired("signalEvents", appNow, nil),
		// License pools 400 days after their term ended.
		expired("licensePools", appNow, nil),
		// Guest invitations 90 days after they lapsed, once redeemed, revoked or expired.
		{collection: "guestInvitations", field: "expiresAt", cutoff: appNow - 90*retentionDay, keep: func(record *core.Object) bool {
			return record.Get("status") == "pending"
		}},
		{collection: "outbox", field: "deliveredAt", cutoff: appNow - retention},
		{collection: "outbox", field: "failedAt", cutoff: appNow - retention},
		{collection: "ssfDeliveries", field: "failedAt", cutoff: wallNow - retention},
		{collection: "auditHooks", field: "deliveredAt", cutoff: appNow - grace},
		// Rows written before these timestamps existed: not indexed, but a shrinking set.
		{collection: "ssfDeliveries", filter: core.NewObject("status", "failed", "failedAt", core.Undefined), field: "createdAt", cutoff: wallNow - retention},
		{collection: "auditHooks", filter: core.NewObject("delivered", true, "deliveredAt", core.Undefined)},
	}
}

// retentionBatch is what an act over one batch answers: the records it left in place, and whether to stop.
type retentionBatch struct {
	read      []*core.Object
	survivors []*core.Object
	stop      bool
}

// retentionWalk walks one target's due records oldest first, a batch at a time. act receives each batch (inside a
// transaction when transactional) and returns the records it left in place; the walk steps over those by moving its
// lower bound (`from`) and skipping the ones at the bound, so nothing is read twice. It answers true when the target
// is exhausted, false when act stopped it or the batch size reached 0.
func retentionWalk(ctx context.Context, store core.IamStore, target *sweepTarget, batchSize func() int, act func(ctx context.Context, store core.IamStore, records []*core.Object) (survivors []*core.Object, stop bool, err error), transactional bool) (bool, error) {
	var from *float64
	skip := 0
	for {
		size := batchSize()
		if size == 0 {
			return false, nil
		}
		step := func(ctx context.Context, reader core.IamStore) (retentionBatch, error) {
			filter := target.filter
			if filter == nil {
				filter = core.NewObject()
			}
			var read []*core.Object
			var err error
			offset, limit := skip, size
			if target.field == "" {
				read, err = reader.Find(ctx, target.collection, filter, &core.FindOptions{Offset: &offset, Limit: &limit})
			} else {
				to := target.cutoff
				order := core.OrderOptions{Field: target.field, To: &to, Offset: &offset, Limit: &limit}
				if from != nil {
					value := *from
					order.From = &value
				}
				read, err = core.FindOrdered(ctx, reader, target.collection, filter, order, nil)
			}
			if err != nil {
				return retentionBatch{}, err
			}
			survivors, stop, err := act(ctx, reader, read)
			if err != nil {
				return retentionBatch{}, err
			}
			return retentionBatch{read: read, survivors: survivors, stop: stop}, nil
		}
		// Deleting: each batch reads and deletes in one short transaction, so a record renewed between batches is
		// judged again on its current state.
		var batch retentionBatch
		var err error
		if transactional {
			batch, err = core.Transact(ctx, store, step)
		} else {
			batch, err = step(ctx, store)
		}
		if err != nil {
			return false, err
		}
		if len(batch.read) < size {
			return true, nil
		}
		if batch.stop {
			return false, nil
		}
		if target.field == "" {
			skip += len(batch.survivors)
			continue
		}
		last, _ := batch.read[len(batch.read)-1].Get(target.field).(float64)
		atLast := 0
		for _, record := range batch.survivors {
			if value, ok := record.Get(target.field).(float64); ok && value == last {
				atLast++
			}
		}
		if from != nil && *from == last {
			skip += atLast
		} else {
			value := last
			from = &value
			skip = atLast
		}
	}
}

// SweepExpired (retention.ts createRetention().sweepExpired): deletes records the rest of the system already treats
// as dead. Options: `now` (epoch milliseconds to treat as now), `batchSize` (default 500, 1-5000), `limit` (default
// 10000, at most 1000000), `deliveryRetentionMs` (default 30 days, 0-3650 days), `graceMs` (default 5 minutes, at
// most 1 day). The answer is `{ deleted, total, truncated }`.
func (s *Retention) SweepExpired(ctx context.Context, options *core.Object) (*core.Object, error) {
	now := member(options, "now")
	if !isUndefined(now) {
		value, ok := now.(float64)
		if !ok || math.IsNaN(value) || math.IsInf(value, 0) {
			return nil, invalidInput("now must be a finite number of milliseconds")
		}
	}
	batchSize, err := retentionBounded(member(options, "batchSize"), 500, 1, 5000, "batchSize")
	if err != nil {
		return nil, err
	}
	remaining, err := retentionBounded(member(options, "limit"), 10_000, 1, 1_000_000, "limit")
	if err != nil {
		return nil, err
	}
	retention, err := retentionBounded(member(options, "deliveryRetentionMs"), 30*retentionDay, 0, 3650*retentionDay, "deliveryRetentionMs")
	if err != nil {
		return nil, err
	}
	grace, err := retentionBounded(member(options, "graceMs"), 5*60_000, 0, retentionDay, "graceMs")
	if err != nil {
		return nil, err
	}
	deleted := core.NewObject()
	total := 0.0
	truncated := false
	for _, target := range s.sweepTargets(now, retention, grace) {
		target := target
		finished, err := retentionWalk(ctx, s.server.Store, target, func() int { return int(math.Min(batchSize, remaining)) },
			func(ctx context.Context, tx core.IamStore, records []*core.Object) ([]*core.Object, bool, error) {
				survivors := []*core.Object{}
				for _, record := range records {
					if target.kept(record) {
						survivors = append(survivors, record)
					} else if err := tx.Delete(ctx, target.collection, jsString(record.Get("id"))); err != nil {
						return nil, false, err
					}
				}
				if count := float64(len(records) - len(survivors)); count != 0 {
					previous, _ := deleted.Get(target.collection).(float64)
					deleted.Set(target.collection, previous+count)
					total += count
					remaining -= count
				}
				return survivors, false, nil
			}, true)
		if err != nil {
			return nil, err
		}
		if !finished {
			truncated = true
			break
		}
	}
	return core.NewObject("deleted", deleted, "total", total, "truncated", truncated), nil
}

// CountDue (retention.ts createRetention().countDue): Records a sweep with these settings would delete that have
// been due for at least `overdueMs`, per collection, counting at most `cap` per collection. Reads only; `selfCheck`
// uses it to spot a sweep that is not running or not keeping up.
func (s *Retention) CountDue(ctx context.Context, options *core.Object) (*core.Object, error) {
	capacity := jsNumber(member(options, "cap"))
	retention, err := retentionBounded(member(options, "deliveryRetentionMs"), 30*retentionDay, 0, 3650*retentionDay, "deliveryRetentionMs")
	if err != nil {
		return nil, err
	}
	grace, err := retentionBounded(member(options, "graceMs"), 5*60_000, 0, retentionDay, "graceMs")
	if err != nil {
		return nil, err
	}
	overdue := jsNumber(member(options, "overdueMs"))
	counts := core.NewObject()
	for _, target := range s.sweepTargets(core.Undefined, retention, grace) {
		target := target
		if target.field != "" {
			target.cutoff -= overdue
		}
		seen := func() float64 {
			count, _ := counts.Get(target.collection).(float64)
			return count
		}
		_, err := retentionWalk(ctx, s.server.Store, target, func() int { return int(math.Min(500, capacity-seen()+1)) },
			func(ctx context.Context, _ core.IamStore, records []*core.Object) ([]*core.Object, bool, error) {
				due := 0.0
				for _, record := range records {
					if !target.kept(record) {
						due++
					}
				}
				counts.Set(target.collection, seen()+due)
				return records, seen() >= capacity, nil
			}, false)
		if err != nil {
			return nil, err
		}
		counts.Set(target.collection, math.Min(seen(), capacity))
	}
	return counts, nil
}
