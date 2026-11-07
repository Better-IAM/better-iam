package server

// Port of packages/server/src/threat-engine.ts: the detection engine of the threats module (threats.go), a scheduled
// job (`iam.DetectThreats()`) that reads each tenant's audit chain from a cursor, verifies the chain as it goes,
// evaluates the detection rules (threat_rules.go) over the unread events and their lookback window, records
// detections grouped into incidents, keeps identity risk, and runs the tenant's playbooks for new detections. It
// reads the trail rather than hooking the recorders, so it also sees what the protocol packages write without fan-out
// and never slows a sign-in.

import (
	"context"
	"fmt"
	"math"
	"slices"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

const (
	// Default and largest number of unread events one run reads per tenant.
	threatDefaultMaxEvents = 2000
	threatMaxEventsLimit   = 20_000
	// Most lookback events one run loads per tenant for the window rules (the newest are kept).
	threatMaxHistory = 20_000
	// Most people whose sign-in baselines one run writes. Those writes happen in the run's transaction, which holds
	// the store's write lock, so a run reaching this many stops at that event and the next run continues from there.
	threatMaxBaselinesPerRun = 500
	// Detections an incident lists by id (newest last); older ones stay findable through `incidentId`.
	threatMaxIncidentDetections = 200
	// Risk contributions kept per identity (newest last); older ones have decayed to almost nothing.
	threatMaxContributions = 50
	// Contributions older than this many half-lives (under 0.1% of their points) are pruned.
	threatContributionHalfLives = 10
	// Longest `uniqueKey` the store accepts, in UTF-8 bytes; a longer key is stored as its hash.
	threatMaxKeyBytes = 512
)

var threatChainBreakText = map[string]string{
	"sequence-gap":           "events before it are missing",
	"sequence-repeated":      "its position in the chain is taken twice",
	"previous-hash-mismatch": "it does not follow the event before it",
	"hash-mismatch":          "its content no longer matches its hash",
	"head-rolled-back":       "the chain head moved back behind events already read",
	"head-mismatch":          "the latest event was replaced",
}

// threatChainBreak is one place where verification failed.
type threatChainBreak struct {
	reason   string
	sequence float64
	// The event at which verification failed; nil when the chain head itself moved.
	event *core.Object
}

// threatTenantOutcome is what one tenant contributed to a run.
type threatTenantOutcome struct {
	eventsScanned   int
	detections      int
	incidentsOpened int
	responses       int
	braked          float64
	chainBroken     bool
	pending         bool
}

// DetectThreats (threat-engine.ts detectThreats): Runs detection for every active tenant (or only `tenantId`,
// NOT_FOUND when it does not exist): reads up to `maxEvents` (default 2000, at most 20000) unread audit events per
// tenant (fewer when they hold the sign-ins of more than 500 people, whose baselines the run writes; the rest stays
// pending), verifies their hash chain (a break raises `audit-tampering` and detection continues), evaluates the
// rules, records detections and incidents, updates risk and sign-in baselines, advances the tenant's cursor, and
// runs matching playbooks for new detections (automatic containments braked at `maxAutomaticContainments` per tenant
// and run). A tenant whose evaluation fails, or whose detection settings changed while it was evaluated, records
// nothing and keeps its cursor, so the next run reads the same events again; the other tenants are unaffected. A
// deployment operation for schedulers: no credential. The first run of a tenant starts one day back.
func DetectThreats(ctx context.Context, server *ServerContext, input *core.Object) (result *core.Object, err error) {
	if input == nil {
		input = core.NewObject()
	}
	maxEvents, err := Integer(coalesce(input.Get("maxEvents"), float64(threatDefaultMaxEvents)), "maxEvents", 1, threatMaxEventsLimit)
	if err != nil {
		return nil, err
	}
	var tenants []*core.Object
	if tenantID := input.Get("tenantId"); !isUndefined(tenantID) {
		id, err := Text(tenantID, "tenantId")
		if err != nil {
			return nil, err
		}
		tenant, err := server.Tenant(ctx, server.Store, id)
		if err != nil {
			return nil, err
		}
		tenants = []*core.Object{tenant}
	} else {
		tenants, err = server.Store.Find(ctx, "tenants", core.NewObject("status", "active"), nil)
		if err != nil {
			return nil, err
		}
		slices.SortStableFunc(tenants, ByID)
	}
	run := struct {
		tenants, eventsScanned, detections, incidentsOpened, responses int
		braked                                                         float64
		chainBreaks, pending                                           int
	}{}
	for _, tenant := range tenants {
		// A tombstoned tenant only waits for the purge worker.
		if tenant.Get("status") == "deleted" {
			continue
		}
		run.tenants++
		tenantID, _ := tenant.Get("id").(string)
		outcome, err := Span(server.Observe, "operation", "threats:detect", tenantID, func() (outcome *threatTenantOutcome, err error) {
			// Whatever goes wrong for one tenant (a thrown error in TypeScript) leaves it for the next run.
			defer func() {
				if recovered := recover(); recovered != nil {
					outcome, err = nil, fmt.Errorf("threat detection failed: %v", recovered)
				}
			}()
			return threatDetectTenant(ctx, server, tenant, int(maxEvents))
		}, nil, nil)
		if err != nil {
			// Nothing was recorded and the cursor stayed put, so the next run retries these events; the span reports it.
			continue
		}
		run.eventsScanned += outcome.eventsScanned
		run.detections += outcome.detections
		run.incidentsOpened += outcome.incidentsOpened
		run.responses += outcome.responses
		run.braked += outcome.braked
		if outcome.chainBroken {
			run.chainBreaks++
		}
		if outcome.pending {
			run.pending++
		}
	}
	return core.NewObject(
		"tenants", float64(run.tenants),
		"eventsScanned", float64(run.eventsScanned),
		"detections", float64(run.detections),
		"incidentsOpened", float64(run.incidentsOpened),
		"responses", float64(run.responses),
		"braked", run.braked,
		"chainBreaks", float64(run.chainBreaks),
		"pending", float64(run.pending),
	), nil
}

// threatGet is `record?.[key]` for a record that may be absent.
func threatGet(record *core.Object, key string) any {
	if record == nil {
		return core.Undefined
	}
	return record.Get(key)
}

// threatJSON is JSON.stringify(record ?? null).
func threatJSON(record *core.Object) string {
	if record == nil {
		return "null"
	}
	text, _, _ := core.Stringify(record)
	return text
}

func threatFloatPtr(value float64) *float64 { return &value }
func threatIntPtr(value int) *int           { return &value }

type threatWritten struct {
	detections      int
	incidentsOpened int
	responses       []*core.Object
}

func threatDetectTenant(ctx context.Context, server *ServerContext, tenant *core.Object, maxEvents int) (*threatTenantOutcome, error) {
	store := server.Store
	tenantID, _ := tenant.Get("id").(string)
	now := server.Now()
	// Everything up to the rule results is read outside a transaction: hashing and evaluating thousands of events
	// would otherwise hold the store's write lock. The write transaction re-checks the cursor, so overlapping runs
	// never record the same events twice.
	cursor, err := store.Get(ctx, ThreatCollections.Cursors, tenantID)
	if err != nil {
		return nil, err
	}
	// Kept as read, so the write transaction can tell when threats.configure changed them meanwhile.
	storedSettings, err := store.Get(ctx, ThreatCollections.Settings, tenantID)
	if err != nil {
		return nil, err
	}
	settings, err := ResolveThreatSettings(storedSettings)
	if err != nil {
		return nil, err
	}
	head, err := store.Get(ctx, "auditChains", tenantID)
	if err != nil {
		return nil, err
	}
	headSequence := 0.0
	var headHash any = core.Undefined
	if head != nil {
		headSequence = jsNumber(coalesce(head.Get("sequence"), 0.0))
		headHash = head.Get("hash")
	}
	var breaks []threatChainBreak
	// The last verified chain position; undefined until known (the first run starts mid-chain).
	known := false
	sequence := 0.0
	var hash any = core.Undefined
	if cursor != nil {
		cursorSequence := jsNumber(cursor.Get("sequence"))
		rolledBack := cursorSequence > headSequence
		replaced := !rolledBack && head != nil && threatSame(cursor.Get("sequence"), head.Get("sequence")) &&
			!isUndefined(cursor.Get("hash")) && !threatSame(cursor.Get("hash"), head.Get("hash"))
		if rolledBack || replaced {
			reason := "head-mismatch"
			if rolledBack {
				reason = "head-rolled-back"
			}
			breaks = append(breaks, threatChainBreak{reason: reason, sequence: cursorSequence})
			// Continue from the head as it is now, so events appended after the rollback are still read.
			known, sequence, hash = true, headSequence, headHash
		} else {
			known, sequence, hash = true, cursorSequence, cursor.Get("hash")
		}
	}
	var events []*core.Object
	if known {
		events, err = core.FindOrdered(ctx, store, "audit", core.NewObject("tenantId", tenantID),
			core.OrderOptions{Field: "sequence", From: threatFloatPtr(sequence + 1), Limit: threatIntPtr(maxEvents + 1)}, nil)
		if err != nil {
			return nil, err
		}
	} else {
		// First run: start one day back instead of replaying the whole trail (both clocks, since server and
		// authentication events are stamped by different ones); the chain is verified from that event on.
		first, err := threatFirstEventSince(ctx, store, tenantID, float64(min(now, server.Wall()))-threatDay, headSequence)
		if err != nil {
			return nil, err
		}
		if first != nil {
			events, err = core.FindOrdered(ctx, store, "audit", core.NewObject("tenantId", tenantID),
				core.OrderOptions{Field: "sequence", From: threatFloatPtr(jsNumber(first.Get("sequence"))), Limit: threatIntPtr(maxEvents + 1)}, nil)
			if err != nil {
				return nil, err
			}
		} else {
			known, sequence, hash = true, headSequence, headHash
		}
	}
	pending := len(events) > maxEvents
	if pending {
		events = events[:maxEvents]
	}
	if within := threatWithinBaselineBudget(events); within < len(events) {
		events = events[:within]
		pending = true
	}

	// Chain verification, every event including the module's own.
	var prunes []*core.Object
	prunesRead := false
	// A gap left by `pruneAudit` while the cursor was behind: a checkpoint names the event just before this one.
	prunedBefore := func(event *core.Object) (bool, error) {
		if !prunesRead {
			found, err := store.Find(ctx, "audit", core.NewObject("tenantId", tenantID, "action", "audit:prune"), nil)
			if err != nil {
				return false, err
			}
			prunes, prunesRead = found, true
		}
		before := jsNumber(event.Get("sequence")) - 1
		for _, prune := range prunes {
			metadata := prune.Get("metadata")
			if threatSame(member(metadata, "prunedThroughSequence"), before) &&
				threatSame(member(metadata, "prunedThroughHash"), event.Get("previousHash")) {
				return true, nil
			}
		}
		return false, nil
	}
	for _, event := range events {
		position := jsNumber(event.Get("sequence"))
		previous := hash
		if isUndefined(previous) || previous == nil {
			previous = core.Undefined
			if known && sequence == 0 {
				previous = core.AuditGenesis
			}
		}
		reason := ""
		if known && position != sequence+1 {
			if position <= sequence {
				reason = "sequence-repeated"
			} else {
				pruned, err := prunedBefore(event)
				if err != nil {
					return nil, err
				}
				if !pruned {
					reason = "sequence-gap"
				}
			}
		} else if !isUndefined(previous) && !threatSame(event.Get("previousHash"), previous) {
			reason = "previous-hash-mismatch"
		}
		if reason == "" && !threatSame(event.Get("hash"), core.AuditEventHash(event)) {
			reason = "hash-mismatch"
		}
		if reason != "" {
			breaks = append(breaks, threatChainBreak{reason: reason, sequence: position, event: event})
		}
		// Detection continues from the event as stored, so one break is reported once.
		known, sequence, hash = true, position, event.Get("hash")
	}
	positionSequence := 0.0
	if known {
		positionSequence = sequence
	}
	positionHash := hash

	var candidates []*core.Object
	tampering, _ := member(settings.Get("rules"), "audit-tampering").(*core.Object)
	if tampering != nil && truthy(tampering.Get("enabled")) {
		severity, _ := tampering.Get("severity").(string)
		for _, found := range breaks {
			candidates = append(candidates, threatTamperingCandidate(tenant, found, severity, now))
		}
	}

	// The module's own events never feed the rules, nor do malformed ones (the chain check above reports an edited
	// event; its fields are not trusted here).
	var ruleEvents []*core.Object
	for _, event := range events {
		if threatConsidered(event) {
			ruleEvents = append(ruleEvents, event)
		}
	}
	baselines := map[string]*core.Object{}
	// Baselines stored for this tenant when read (overwritten in place), and ids another tenant's baseline holds.
	storedBaselines := map[string]bool{}
	foreignBaselines := map[string]bool{}
	state := &ThreatRuleState{}
	if cursor != nil && truthy(cursor.Get("authPolicy")) {
		state.AuthPolicy, _ = cursor.Get("authPolicy").(*core.Object)
	}
	touched := newOrderedSet()
	if len(ruleEvents) > 0 {
		first := math.Inf(1)
		last := math.Inf(-1)
		for _, event := range ruleEvents {
			first = math.Min(first, threatTime(event))
			last = math.Max(last, threatTime(event))
		}
		reach, err := RuleWindowMs(settings)
		if err != nil {
			return nil, err
		}
		// Newest first, so a crowded window keeps the events closest to the ones being judged. One more than the cap
		// tells whether older events were left out.
		newest, err := core.FindOrdered(ctx, store, "audit", core.NewObject("tenantId", tenantID), core.OrderOptions{
			Field:     "timestamp",
			Direction: "desc",
			From:      threatFloatPtr(first - reach),
			To:        threatFloatPtr(last),
			Limit:     threatIntPtr(threatMaxHistory + 1),
		}, threatConsidered)
		if err != nil {
			return nil, err
		}
		kept := newest
		if len(kept) > threatMaxHistory {
			kept = kept[:threatMaxHistory]
		}
		history := make([]*core.Object, len(kept))
		for index, event := range kept {
			history[len(kept)-1-index] = event
		}
		var historyFrom *float64
		if len(newest) > threatMaxHistory && len(history) > 0 {
			historyFrom = threatFloatPtr(threatTime(history[0]))
		}
		// Sign-ins compare against and update baselines; own sign-in method changes read the risky sign-in on them.
		for _, identityID := range threatBaselineIdentityIDs(ruleEvents) {
			baseline, err := store.Get(ctx, ThreatCollections.Baselines, identityID)
			if err != nil {
				return nil, err
			}
			if baseline != nil && baseline.Get("tenantId") == tenantID {
				baselines[identityID] = baseline
				storedBaselines[identityID] = true
			} else if baseline != nil {
				foreignBaselines[identityID] = true
			}
		}
		evaluated, err := EvaluateThreatRules(ctx, &ThreatRuleInput{
			TenantID:    tenantID,
			Events:      ruleEvents,
			History:     history,
			HistoryFrom: historyFrom,
			Settings:    settings,
			Baselines:   baselines,
			State:       state,
			Facts:       threatRuleFacts(server, tenantID),
			Now:         float64(now),
		})
		if err != nil {
			return nil, err
		}
		candidates = append(candidates, evaluated.Candidates...)
		touched = newOrderedSet(evaluated.TouchedBaselines...)
	}
	// With no sign-in policy seen yet (a first run, or none changed so far), the policy in force before this run's
	// events is the tenant's as read before them, so guardrail-weakened judges the first change after this run too.
	// Not while more events wait than one run reads: a later one may already be reflected in that read.
	if state.AuthPolicy == nil && !pending {
		state.AuthPolicy = core.NewObject()
		if policy := tenant.Get("authPolicy"); truthy(policy) {
			text, _, _ := core.Stringify(policy)
			if copied, err := core.ParseJSONString(text); err == nil {
				if object, ok := copied.(*core.Object); ok {
					state.AuthPolicy = object
				}
			}
		}
	}

	brake := core.NewObject("contained", 0.0)
	written, err := core.Transact(ctx, store, func(ctx context.Context, tx core.IamStore) (*threatWritten, error) {
		current, err := tx.Get(ctx, ThreatCollections.Cursors, tenantID)
		if err != nil {
			return nil, err
		}
		// Another run advanced the cursor since it was read: it recorded these events.
		if !threatSame(threatGet(current, "sequence"), threatGet(cursor, "sequence")) ||
			!threatSame(threatGet(current, "hash"), threatGet(cursor, "hash")) ||
			!threatSame(threatGet(current, "updatedAt"), threatGet(cursor, "updatedAt")) {
			return nil, nil
		}
		// The settings changed since this run read them (threats.configure): the events were judged under the old ones,
		// and playbooks would run with the old brake, trusted networks and recipients. Nothing is recorded; the next run
		// reads the same events under the new settings.
		settingsNow, err := tx.Get(ctx, ThreatCollections.Settings, tenantID)
		if err != nil {
			return nil, err
		}
		if threatJSON(settingsNow) != threatJSON(storedSettings) {
			return nil, nil
		}
		written := &threatWritten{}
		type createdPair struct{ detection, incident *core.Object }
		var created []createdPair
		for _, candidate := range candidates {
			recorded, err := RecordDetection(ctx, server, tx, tenantID, candidate, settings, now)
			if err != nil {
				return nil, err
			}
			if recorded.Get("created") != true {
				continue
			}
			written.detections++
			if recorded.Get("incidentOpened") == true {
				written.incidentsOpened++
			}
			detection, _ := recorded.Get("detection").(*core.Object)
			incident, _ := recorded.Get("incident").(*core.Object)
			created = append(created, createdPair{detection, incident})
			identityID, hasIdentity := candidate.Get("identityId").(string)
			if truthy(candidate.Get("riskySignIn")) && hasIdentity {
				baseline, err := threatBaselineFor(ctx, tx, tenantID, identityID, baselines, storedBaselines, now)
				if err != nil {
					return nil, err
				}
				occurredAt := threatNumber(candidate, "occurredAt")
				if baseline != nil {
					risky := baseline.Get("riskySignIn")
					if !truthy(risky) || jsNumber(member(risky, "at")) <= occurredAt {
						baseline.Set("riskySignIn", core.NewObject(
							"at", occurredAt,
							"detectionId", detection.Get("id"),
							"ruleId", candidate.Get("ruleId"),
						))
						touched.Add(identityID)
					}
				}
			}
		}
		// Two round trips per person under the write lock, and at most `maxBaselinesPerRun` people per run.
		for _, identityID := range touched.Values() {
			baseline := baselines[identityID]
			if baseline == nil || foreignBaselines[identityID] {
				continue
			}
			record := baseline.Spread(core.NewObject(
				"id", identityID,
				"tenantId", tenantID,
				"identityId", identityID,
				"updatedAt", float64(now),
			))
			// A baseline read from this tenant is overwritten; if identity deletion removed it meanwhile, the write fails
			// and so does the run, and the next run skips the deleted person.
			if storedBaselines[identityID] {
				if _, err := tx.Put(ctx, ThreatCollections.Baselines, record); err != nil {
					return nil, err
				}
				continue
			}
			// A deleted identity's baseline went with it (identity deletion); a late sign-in event does not bring it back.
			identity, err := tx.Get(ctx, "identities", identityID)
			if err != nil {
				return nil, err
			}
			if identity == nil || identity.Get("tenantId") != tenantID || identity.Get("status") == "deleted" {
				continue
			}
			if _, err := tx.Insert(ctx, ThreatCollections.Baselines, record); err != nil {
				return nil, err
			}
		}
		next := core.NewObject("id", tenantID, "tenantId", tenantID, "sequence", positionSequence)
		if !isUndefined(positionHash) {
			next.Set("hash", positionHash)
		}
		if state.AuthPolicy != nil {
			next.Set("authPolicy", state.AuthPolicy)
		}
		next.Set("updatedAt", float64(now))
		if current != nil {
			_, err = tx.Put(ctx, ThreatCollections.Cursors, next)
		} else {
			_, err = tx.Insert(ctx, ThreatCollections.Cursors, next)
		}
		if err != nil {
			return nil, err
		}
		written.responses = []*core.Object{}
		for _, pair := range created {
			responses, err := RunPlaybooks(ctx, server, tx, tenantID, pair.detection, pair.incident, settings, brake)
			if err != nil {
				return nil, err
			}
			written.responses = append(written.responses, responses...)
		}
		return written, nil
	})
	if err != nil {
		return nil, err
	}
	if written == nil {
		return &threatTenantOutcome{}, nil
	}
	if err := AfterThreatResponses(ctx, server, tenantID, written.responses); err != nil {
		return nil, err
	}
	applied := 0
	for _, response := range written.responses {
		if response.Get("outcome") == "applied" {
			applied++
		}
	}
	braked := 0.0
	if value := brake.Get("braked"); !nullish(value) {
		braked = jsNumber(value)
	}
	return &threatTenantOutcome{
		eventsScanned:   len(events),
		detections:      written.detections,
		incidentsOpened: written.incidentsOpened,
		responses:       applied,
		braked:          braked,
		chainBroken:     len(breaks) > 0,
		pending:         pending,
	}, nil
}

// threatFirstEventSince is the earliest event of the tenant's chain stamped at or after `cutoff`, found by bisecting
// sequences (timestamps rise along the chain, so this takes a few indexed reads however long the trail is). Pruned
// sequences are skipped. Nil when every event is older.
func threatFirstEventSince(ctx context.Context, store core.IamStore, tenantID string, cutoff, headSequence float64) (*core.Object, error) {
	// The first event at or after a sequence.
	from := func(sequence float64) (*core.Object, error) {
		found, err := core.FindOrdered(ctx, store, "audit", core.NewObject("tenantId", tenantID),
			core.OrderOptions{Field: "sequence", From: threatFloatPtr(sequence), Limit: threatIntPtr(1)}, nil)
		if err != nil || len(found) == 0 {
			return nil, err
		}
		return found[0], nil
	}
	low := 1.0
	high := headSequence + 1
	var found *core.Object
	for low < high {
		middle := math.Floor((low + high) / 2)
		event, err := from(middle)
		if err != nil {
			return nil, err
		}
		if event != nil && threatTime(event) < cutoff {
			low = jsNumber(event.Get("sequence")) + 1
		} else {
			if event != nil {
				found = event
			}
			high = middle
		}
	}
	return found, nil
}

// threatBaselineFor is the baseline a risky sign-in is marked on: preloaded, stored (noted in `storedBaselines`), or
// new; nil when another tenant holds the id.
func threatBaselineFor(ctx context.Context, tx core.IamStore, tenantID, identityID string, baselines map[string]*core.Object, storedBaselines map[string]bool, now int64) (*core.Object, error) {
	if loaded := baselines[identityID]; loaded != nil {
		return loaded, nil
	}
	stored, err := tx.Get(ctx, ThreatCollections.Baselines, identityID)
	if err != nil {
		return nil, err
	}
	if stored != nil && stored.Get("tenantId") != tenantID {
		return nil, nil
	}
	baseline := stored
	if stored != nil {
		storedBaselines[identityID] = true
	} else {
		baseline = core.NewObject(
			"id", identityID,
			"tenantId", tenantID,
			"identityId", identityID,
			"networks", []any{},
			"userAgents", []any{},
			"firstSeenAt", float64(now),
			"updatedAt", float64(now),
		)
	}
	baselines[identityID] = baseline
	return baseline, nil
}

// threatWithinBaselineBudget is how many of a run's events it takes so that it learns sign-ins (or reads risky
// sign-ins) of at most `maxBaselinesPerRun` people; every event when fewer people are involved.
func threatWithinBaselineBudget(events []*core.Object) int {
	people := map[string]bool{}
	for index, event := range events {
		if !threatConsidered(event) {
			continue
		}
		for _, identityID := range threatBaselineIdentityIDs([]*core.Object{event}) {
			if people[identityID] {
				continue
			}
			if len(people) >= threatMaxBaselinesPerRun {
				return index
			}
			people[identityID] = true
		}
	}
	return len(events)
}

func threatTamperingCandidate(tenant *core.Object, found threatChainBreak, severity string, now int64) *core.Object {
	// The event failed verification: none of its fields is trusted to have the right type.
	at := float64(now)
	var action, eventID any = core.Undefined, core.Undefined
	if found.event != nil {
		if stamped, ok := found.event.Get("timestamp").(float64); ok && !math.IsNaN(stamped) && !math.IsInf(stamped, 0) {
			at = stamped
		}
		if text, ok := found.event.Get("action").(string); ok {
			action = text
		}
		if text, ok := found.event.Get("id").(string); ok {
			eventID = text
		}
	}
	tenantID := tenant.Get("id")
	name := tenant.Get("name")
	eventIDs := []any{}
	if !isUndefined(eventID) {
		eventIDs = append(eventIDs, eventID)
	}
	evidence := core.NewObject("eventIds", eventIDs, "count", 1.0, "firstAt", at, "lastAt", at)
	if !isUndefined(action) {
		evidence.Set("actions", []any{action})
	}
	sequence := core.NumberString(found.sequence)
	return core.NewObject(
		"ruleId", "audit-tampering",
		"severity", severity,
		"title", "Audit trail tampering",
		"summary", "The audit trail of "+jsString(name)+" no longer verifies at event "+sequence+": "+threatChainBreakText[found.reason]+".",
		"subject", core.NewObject("type", "tenant", "id", tenantID, "name", name),
		"dedupeKey", jsString(tenantID)+":"+sequence,
		"occurredAt", at,
		"evidence", evidence,
		"metadata", core.NewObject("reason", found.reason, "sequence", found.sequence),
	)
}

// threatRuleFacts is the facts rules may ask about a tenant, read from the store and cached for the run. Privileged
// means owner, root administrator, or holder of a live standing binding (direct or through a live group membership)
// of a role whose inline document, attached policies, or inherited roles grant `*` or `iam:*` on `*` without
// conditions.
func threatRuleFacts(server *ServerContext, tenantID string) ThreatRuleFacts {
	store := server.Store
	identities := map[string]*core.Object{}
	identitiesRead := map[string]bool{}
	adminRoles := map[string]bool{}
	adminRolesRead := map[string]bool{}
	heldRoles := map[string]*orderedSet{}
	privileged := map[string]bool{}
	privilegedRead := map[string]bool{}
	incidents := map[string]*core.Object{}
	identity := func(ctx context.Context, identityID string) (*core.Object, error) {
		if !identitiesRead[identityID] {
			found, err := store.Get(ctx, "identities", identityID)
			if err != nil {
				return nil, err
			}
			if found != nil && found.Get("tenantId") != tenantID {
				found = nil
			}
			identities[identityID] = found
			identitiesRead[identityID] = true
		}
		return identities[identityID], nil
	}
	var grantsAdmin func(ctx context.Context, roleID string, seen map[string]bool) (bool, error)
	grantsAdmin = func(ctx context.Context, roleID string, seen map[string]bool) (bool, error) {
		if seen[roleID] || len(seen) >= 64 {
			return false, nil
		}
		seen[roleID] = true
		role, err := store.Get(ctx, "roles", roleID)
		if err != nil {
			return false, err
		}
		if role == nil || role.Get("tenantId") != tenantID {
			return false, nil
		}
		if analysisUnrestrictedAdmin(role.Get("document")) {
			return true, nil
		}
		for _, policyID := range threatTexts(role.Get("policyIds")) {
			policy, err := store.Get(ctx, "policies", policyID)
			if err != nil {
				return false, err
			}
			if policy != nil && policy.Get("tenantId") == tenantID && analysisUnrestrictedAdmin(policy.Get("document")) {
				return true, nil
			}
		}
		for _, inherited := range threatTexts(role.Get("inherits")) {
			admin, err := grantsAdmin(ctx, inherited, seen)
			if err != nil || admin {
				return admin, err
			}
		}
		return false, nil
	}
	isAdminRole := func(ctx context.Context, roleID string) (bool, error) {
		if !adminRolesRead[roleID] {
			admin, err := grantsAdmin(ctx, roleID, map[string]bool{})
			if err != nil {
				return false, err
			}
			adminRoles[roleID] = admin
			adminRolesRead[roleID] = true
		}
		return adminRoles[roleID], nil
	}
	held := func(ctx context.Context, identityID string) (*orderedSet, error) {
		if cached, ok := heldRoles[identityID]; ok {
			return cached, nil
		}
		roles := newOrderedSet()
		standing := func(binding *core.Object) bool {
			return !truthy(binding.Get("eligible")) && server.LiveBinding(binding)
		}
		direct, err := store.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "identity", "subjectId", identityID), nil)
		if err != nil {
			return nil, err
		}
		for _, binding := range direct {
			if standing(binding) {
				roles.Add(jsString(binding.Get("roleId")))
			}
		}
		members, err := store.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
		if err != nil {
			return nil, err
		}
		for _, groupMember := range members {
			if !server.LiveMembership(groupMember) {
				continue
			}
			bindings, err := store.Find(ctx, "bindings", core.NewObject("tenantId", tenantID, "subjectType", "group", "subjectId", groupMember.Get("groupId")), nil)
			if err != nil {
				return nil, err
			}
			for _, binding := range bindings {
				if standing(binding) {
					roles.Add(jsString(binding.Get("roleId")))
				}
			}
		}
		heldRoles[identityID] = roles
		return roles, nil
	}
	return ThreatRuleFacts{
		Identity:    identity,
		IsAdminRole: isAdminRole,
		HoldsRole: func(ctx context.Context, identityID, roleID string) (bool, error) {
			roles, err := held(ctx, identityID)
			if err != nil {
				return false, err
			}
			return roles.Has(roleID), nil
		},
		DetectionStands: func(ctx context.Context, detectionID string) (bool, error) {
			return threatStillCounts(ctx, store, tenantID, detectionID, incidents)
		},
		IsPrivileged: func(ctx context.Context, identityID string) (bool, error) {
			if privilegedRead[identityID] {
				return privileged[identityID], nil
			}
			found, err := identity(ctx, identityID)
			if err != nil {
				return false, err
			}
			result := false
			if found != nil && found.Get("status") != "deleted" {
				if truthy(found.Get("owner")) || truthy(found.Get("rootAdmin")) {
					result = true
				} else {
					roles, err := held(ctx, identityID)
					if err != nil {
						return false, err
					}
					for _, roleID := range roles.Values() {
						admin, err := isAdminRole(ctx, roleID)
						if err != nil {
							return false, err
						}
						if admin {
							result = true
							break
						}
					}
				}
			}
			privileged[identityID] = result
			privilegedRead[identityID] = true
			return result, nil
		},
	}
}

// threatStorageKey is a `uniqueKey` the store accepts: the value itself, or its prefix and hash when too long or not
// printable.
func threatStorageKey(value string) string {
	printable := true
	for index := 0; index < len(value); index++ {
		if code := value[index]; code < 32 || code == 127 {
			printable = false
			break
		}
	}
	if printable && len(utf8Bytes(value)) <= threatMaxKeyBytes {
		return value
	}
	prefix := "key:"
	if colon := strings.Index(value, ":"); colon >= 0 {
		prefix = value[:colon+1]
	}
	return prefix + "sha256:" + Hash(value)
}

// threatSubjectLabel is a readable name for a subject in titles.
func threatSubjectLabel(subject any) string {
	return jsString(coalesce(member(subject, "name"), member(subject, "id")))
}

// threatJoinIncident adds a detection to the subject's open (or investigating) incident, or opens one (uniqueKey
// `open:{subject.type}:{subject.id}`). An incident spanning several rules is retitled "N detections for X".
func threatJoinIncident(ctx context.Context, tx core.IamStore, tenantID string, detection *core.Object, now int64) (*core.Object, bool, error) {
	subject := detection.Get("subject")
	uniqueKey := threatStorageKey("open:" + jsString(member(subject, "type")) + ":" + jsString(member(subject, "id")))
	found, err := tx.Find(ctx, ThreatCollections.Incidents, core.NewObject("tenantId", tenantID, "uniqueKey", uniqueKey), nil)
	if err != nil {
		return nil, false, err
	}
	ruleID := detection.Get("ruleId")
	detectionIdentity := detection.Get("identityId")
	if len(found) > 0 {
		open := found[0]
		ruleIDs := append([]any{}, threatList(open.Get("ruleIds"))...)
		included := false
		for _, existing := range ruleIDs {
			if threatSame(existing, ruleID) {
				included = true
				break
			}
		}
		if !included {
			ruleIDs = append(ruleIDs, ruleID)
		}
		detectionCount := jsNumber(open.Get("detectionCount")) + 1
		// An incident about the tenant (or a network, a connection) gathers detections of whoever acted: once two name
		// different identities it names none, so a response to it never acts on whoever happened to come first.
		openIdentity := open.Get("identityId")
		several := open.Get("severalIdentities") == true ||
			(member(open.Get("subject"), "type") != "identity" &&
				!isUndefined(openIdentity) &&
				!isUndefined(detectionIdentity) &&
				!threatSame(detectionIdentity, openIdentity))
		rest := open.Spread()
		rest.Delete("identityId")
		var identityID any = core.Undefined
		if !several {
			identityID = coalesce(openIdentity, detectionIdentity)
		}
		severity, err := MaxSeverity(jsString(open.Get("severity")), jsString(detection.Get("severity")))
		if err != nil {
			return nil, false, err
		}
		title := open.Get("title")
		if len(ruleIDs) > 1 {
			title = core.NumberString(detectionCount) + " detections for " + threatSubjectLabel(open.Get("subject"))
		}
		detectionIDs := append(append([]any{}, threatList(open.Get("detectionIds"))...), detection.Get("id"))
		if len(detectionIDs) > threatMaxIncidentDetections {
			detectionIDs = detectionIDs[len(detectionIDs)-threatMaxIncidentDetections:]
		}
		changes := core.NewObject(
			"detectionIds", detectionIDs,
			"detectionCount", detectionCount,
			"ruleIds", ruleIDs,
			"severity", severity,
			"title", title,
			"lastDetectedAt", float64(now),
			"updatedAt", float64(now),
		)
		if !isUndefined(identityID) {
			changes.Set("identityId", identityID)
		}
		if several {
			changes.Set("severalIdentities", true)
		}
		if isUndefined(open.Get("network")) && !isUndefined(detection.Get("network")) {
			changes.Set("network", detection.Get("network"))
		}
		incident := rest.Spread(changes)
		if _, err := tx.Put(ctx, ThreatCollections.Incidents, incident); err != nil {
			return nil, false, err
		}
		return incident, false, nil
	}
	incident := core.NewObject(
		"id", ID(),
		"tenantId", tenantID,
		"uniqueKey", uniqueKey,
		"subject", subject,
	)
	if !isUndefined(detectionIdentity) {
		incident.Set("identityId", detectionIdentity)
	}
	if network := detection.Get("network"); !isUndefined(network) {
		incident.Set("network", network)
	}
	incident.Set("severity", detection.Get("severity"))
	incident.Set("title", detection.Get("title"))
	incident.Set("status", "open")
	incident.Set("detectionIds", []any{detection.Get("id")})
	incident.Set("detectionCount", 1.0)
	incident.Set("ruleIds", []any{ruleID})
	incident.Set("firstDetectedAt", float64(now))
	incident.Set("lastDetectedAt", float64(now))
	incident.Set("createdAt", float64(now))
	incident.Set("updatedAt", float64(now))
	if _, err := tx.Insert(ctx, ThreatCollections.Incidents, incident); err != nil {
		return nil, false, err
	}
	return incident, true, nil
}

// threatRiskPoints is threats.ts riskPoints by severity.
func threatRiskPoints(severity any) any {
	switch severity {
	case "low":
		return RiskPoints.Low
	case "medium":
		return RiskPoints.Medium
	case "high":
		return RiskPoints.High
	case "critical":
		return RiskPoints.Critical
	}
	return core.Undefined
}

// RecordDetection (threat-engine.ts recordDetection): Records a candidate once: its `uniqueKey` is
// `{ruleId}:{dedupeKey}`, so a candidate raised again (the same burst or triggering event) returns the existing
// detection with `created: false`. A new detection is `open`, joins its subject's open incident or opens one, is
// audited as `threat:detection` (and `threat:incident-open`) under the `threat-detection` actor, and adds
// `riskPoints[severity]` to its identity's risk (`recomputeRisk`). The result is `{detection, incident,
// incidentOpened, created}`.
func RecordDetection(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, candidate *core.Object, settings *core.Object, now int64) (result *core.Object, err error) {
	uniqueKey := threatStorageKey(jsString(candidate.Get("ruleId")) + ":" + jsString(candidate.Get("dedupeKey")))
	found, err := tx.Find(ctx, ThreatCollections.Detections, core.NewObject("tenantId", tenantID, "uniqueKey", uniqueKey), nil)
	if err != nil {
		return nil, err
	}
	if len(found) > 0 {
		existing := found[0]
		var linked *core.Object
		if incidentID := existing.Get("incidentId"); !isUndefined(incidentID) {
			linked, err = tx.Get(ctx, ThreatCollections.Incidents, jsString(incidentID))
			if err != nil {
				return nil, err
			}
		}
		if linked != nil && linked.Get("tenantId") == tenantID {
			return core.NewObject("detection", existing, "incident", linked, "incidentOpened", false, "created", false), nil
		}
		// Its incident is gone: attach it to the subject's current one rather than leave it orphaned.
		incident, opened, err := threatJoinIncident(ctx, tx, tenantID, existing, now)
		if err != nil {
			return nil, err
		}
		detection := existing.Spread(core.NewObject("incidentId", incident.Get("id")))
		if _, err := tx.Put(ctx, ThreatCollections.Detections, detection); err != nil {
			return nil, err
		}
		return core.NewObject("detection", detection, "incident", incident, "incidentOpened", opened, "created", false), nil
	}
	detection := core.NewObject(
		"id", ID(),
		"tenantId", tenantID,
		"uniqueKey", uniqueKey,
		"ruleId", candidate.Get("ruleId"),
		"severity", candidate.Get("severity"),
		"title", candidate.Get("title"),
		"summary", candidate.Get("summary"),
		"subject", candidate.Get("subject"),
	)
	if identityID := candidate.Get("identityId"); !isUndefined(identityID) {
		detection.Set("identityId", identityID)
	}
	if network := candidate.Get("network"); !isUndefined(network) {
		detection.Set("network", network)
	}
	detection.Set("evidence", candidate.Get("evidence"))
	if metadata := candidate.Get("metadata"); !isUndefined(metadata) {
		detection.Set("metadata", metadata)
	}
	detection.Set("status", "open")
	detection.Set("occurredAt", candidate.Get("occurredAt"))
	detection.Set("detectedAt", float64(now))
	incident, opened, err := threatJoinIncident(ctx, tx, tenantID, detection, now)
	if err != nil {
		return nil, err
	}
	detection.Set("incidentId", incident.Get("id"))
	if _, err := tx.Insert(ctx, ThreatCollections.Detections, detection); err != nil {
		return nil, err
	}
	detectionID := jsString(detection.Get("id"))
	subject := detection.Get("subject")
	audited := core.NewObject(
		"ruleId", detection.Get("ruleId"),
		"severity", detection.Get("severity"),
		"subjectType", member(subject, "type"),
		"subjectId", member(subject, "id"),
	)
	if identityID := detection.Get("identityId"); !isUndefined(identityID) {
		audited.Set("identityId", identityID)
	}
	if network := detection.Get("network"); !isUndefined(network) {
		audited.Set("network", network)
	}
	audited.Set("incidentId", incident.Get("id"))
	if err := ThreatAudit(ctx, server, tx, tenantID, core.NewObject("automatic", true), "threat:detection", "threats/detections/"+detectionID, audited); err != nil {
		return nil, err
	}
	if opened {
		incidentSubject := incident.Get("subject")
		opening := core.NewObject(
			"ruleId", detection.Get("ruleId"),
			"severity", incident.Get("severity"),
			"subjectType", member(incidentSubject, "type"),
			"subjectId", member(incidentSubject, "id"),
		)
		if identityID := incident.Get("identityId"); !isUndefined(identityID) {
			opening.Set("identityId", identityID)
		}
		if err := ThreatAudit(ctx, server, tx, tenantID, core.NewObject("automatic", true), "threat:incident-open", "threats/incidents/"+jsString(incident.Get("id")), opening); err != nil {
			return nil, err
		}
	}
	if identityID, ok := detection.Get("identityId").(string); ok {
		if _, err := RecomputeRisk(ctx, server, tx, tenantID, identityID, settings, now, "", core.NewObject(
			"add", core.NewObject(
				"detectionId", detectionID,
				"ruleId", detection.Get("ruleId"),
				"severity", detection.Get("severity"),
				"points", threatRiskPoints(detection.Get("severity")),
				"at", float64(now),
			),
		)); err != nil {
			return nil, err
		}
	}
	return core.NewObject("detection", detection, "incident", incident, "incidentOpened", opened, "created", true), nil
}

// threatStillCounts is whether a contribution's detection still counts: not dismissed, and not resolved in an
// incident closed as a false positive or benign. A detection that no longer exists does not count.
func threatStillCounts(ctx context.Context, tx core.IamStore, tenantID, detectionID string, incidents map[string]*core.Object) (bool, error) {
	detection, err := tx.Get(ctx, ThreatCollections.Detections, detectionID)
	if err != nil {
		return false, err
	}
	if detection == nil || detection.Get("tenantId") != tenantID || detection.Get("status") == "dismissed" {
		return false, nil
	}
	incidentValue := detection.Get("incidentId")
	if detection.Get("status") != "resolved" || isUndefined(incidentValue) {
		return true, nil
	}
	incidentID := jsString(incidentValue)
	incident, cached := incidents[incidentID]
	if !cached {
		incident, err = tx.Get(ctx, ThreatCollections.Incidents, incidentID)
		if err != nil {
			return false, err
		}
		incidents[incidentID] = incident
	}
	resolution := threatGet(incident, "resolution")
	return resolution != "false-positive" && resolution != "benign", nil
}

// RecomputeRisk (threat-engine.ts recomputeRisk): Recomputes an identity's risk record (`identityRisk`, id =
// identity id) in this tenant: adds `options.add`, drops `options.drop` and, when nothing is added, every
// contribution whose detection was dismissed or resolved as a false positive or benign; prunes contributions older
// than ten half-lives (ten days at least), keeps the newest 50, drops a lapsed override, and stores the effective
// score and level. A level change is audited as `threat:risk-change` (`{from, to, score}`, by `actorId` or the
// `threat-detection` actor when it is empty). Nil for identities outside the tenant or deleted, and when there is no
// record and nothing to add. `options` is `{add?: RiskContribution, drop?: string[]}` (nil for none).
func RecomputeRisk(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, identityID string, settings *core.Object, now int64, actorID string, options *core.Object) (result *core.Object, err error) {
	if options == nil {
		options = core.NewObject()
	}
	identity, err := tx.Get(ctx, "identities", identityID)
	if err != nil {
		return nil, err
	}
	if identity == nil || identity.Get("tenantId") != tenantID || identity.Get("status") == "deleted" {
		return nil, nil
	}
	stored, err := tx.Get(ctx, ThreatCollections.Risk, identityID)
	if err != nil {
		return nil, err
	}
	if stored != nil && stored.Get("tenantId") != tenantID {
		return nil, nil
	}
	add, _ := options.Get("add").(*core.Object)
	if stored == nil && add == nil {
		return nil, nil
	}
	halfLifeHours := jsNumber(settings.Get("riskHalfLifeHours"))
	// Never sooner than ten default half-lives: a half-life shortened for a while (threats.configure) decays scores at
	// once, but restoring it brings them back rather than finding the contributions gone.
	cutoff := float64(now) - threatContributionHalfLives*math.Max(DefaultThreatSettings.RiskHalfLifeHours, halfLifeHours)*threatHour
	drop := map[string]bool{}
	switch list := options.Get("drop").(type) {
	case []any:
		for _, item := range list {
			if text, ok := item.(string); ok {
				drop[text] = true
			}
		}
	case []string:
		for _, text := range list {
			drop[text] = true
		}
	}
	incidents := map[string]*core.Object{}
	var kept []*core.Object
	seen := map[string]bool{}
	for _, item := range threatList(threatGet(stored, "contributions")) {
		contribution, ok := item.(*core.Object)
		if !ok {
			continue
		}
		detectionID := jsString(contribution.Get("detectionId"))
		if drop[detectionID] || seen[detectionID] {
			continue
		}
		if jsNumber(contribution.Get("at")) < cutoff {
			continue
		}
		// A new detection cannot have changed older ones; dismissals and resolutions recompute without adding.
		if add == nil {
			counts, err := threatStillCounts(ctx, tx, tenantID, detectionID, incidents)
			if err != nil {
				return nil, err
			}
			if !counts {
				continue
			}
		}
		seen[detectionID] = true
		kept = append(kept, contribution)
	}
	if add != nil {
		addedID := jsString(add.Get("detectionId"))
		if !seen[addedID] && !drop[addedID] {
			kept = append(kept, add)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool {
		return jsNumber(kept[i].Get("at")) < jsNumber(kept[j].Get("at"))
	})
	if len(kept) > threatMaxContributions {
		kept = kept[len(kept)-threatMaxContributions:]
	}
	contributions := make([]any, len(kept))
	for index, contribution := range kept {
		contributions[index] = contribution
	}
	var next *core.Object
	if stored != nil {
		next = stored.Spread(core.NewObject("contributions", contributions, "updatedAt", float64(now)))
	} else {
		next = core.NewObject(
			"id", identityID,
			"tenantId", tenantID,
			"identityId", identityID,
			"contributions", contributions,
			"score", 0.0,
			"level", "none",
			"updatedAt", float64(now),
		)
	}
	if expiresAt := member(next.Get("override"), "expiresAt"); !isUndefined(expiresAt) && jsNumber(expiresAt) <= float64(now) {
		next.Delete("override")
	}
	effective, err := EffectiveRisk(next, now, halfLifeHours)
	if err != nil {
		return nil, err
	}
	previous := coalesce(threatGet(stored, "level"), "none")
	next.Set("score", effective.Get("score"))
	next.Set("level", effective.Get("level"))
	if stored != nil {
		_, err = tx.Put(ctx, ThreatCollections.Risk, next)
	} else {
		_, err = tx.Insert(ctx, ThreatCollections.Risk, next)
	}
	if err != nil {
		return nil, err
	}
	if !threatSame(next.Get("level"), previous) {
		actor := actorID
		if actor == "" {
			actor = ThreatActor
		}
		if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"actorId", actor,
			"action", "threat:risk-change",
			"resourceId", identityID,
			"timestamp", float64(server.Now()),
			"outcome", "allow",
			"metadata", core.NewObject("from", previous, "to", next.Get("level"), "score", next.Get("score")),
		)); err != nil {
			return nil, err
		}
	}
	return next, nil
}

// threatPlaybookMatches: a playbook fires for a detection when every trigger clause it sets matches (unset or empty
// clauses match all).
func threatPlaybookMatches(playbook, detection *core.Object) (bool, error) {
	trigger := coalesce(playbook.Get("trigger"), core.NewObject())
	ruleIDs := threatList(member(trigger, "ruleIds"))
	minSeverity := member(trigger, "minSeverity")
	subjectTypes := threatList(member(trigger, "subjectTypes"))
	includes := func(list []any, value any) bool {
		for _, item := range list {
			if threatSame(item, value) {
				return true
			}
		}
		return false
	}
	if len(ruleIDs) > 0 && !includes(ruleIDs, detection.Get("ruleId")) {
		return false, nil
	}
	if truthy(minSeverity) {
		atLeast, err := SeverityAtLeast(jsString(detection.Get("severity")), jsString(minSeverity))
		if err != nil {
			return false, err
		}
		if !atLeast {
			return false, nil
		}
	}
	return len(subjectTypes) == 0 || includes(subjectTypes, member(detection.Get("subject"), "type")), nil
}

// RunPlaybooks (threat-engine.ts runPlaybooks): Runs the tenant's enabled playbooks whose trigger matches a new
// detection, oldest playbook first, each action in order through `applyResponse` under the automatic actor, and
// counts the run on the playbook (`runs`, `lastRunAt`). Containments share `brake` (one per tenant and run). Returns
// every response recorded, applied or skipped; after the transaction commits the caller runs `afterThreatResponses`.
func RunPlaybooks(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, detection *core.Object, incident *core.Object, settings *core.Object, brake *core.Object) (result []*core.Object, err error) {
	found, err := tx.Find(ctx, ThreatCollections.Playbooks, core.NewObject("tenantId", tenantID, "enabled", true), nil)
	if err != nil {
		return nil, err
	}
	var playbooks []*core.Object
	for _, playbook := range found {
		matches, err := threatPlaybookMatches(playbook, detection)
		if err != nil {
			return nil, err
		}
		if matches {
			playbooks = append(playbooks, playbook)
		}
	}
	slices.SortStableFunc(playbooks, func(a, b *core.Object) int {
		if difference := jsNumber(a.Get("createdAt")) - jsNumber(b.Get("createdAt")); difference != 0 && !math.IsNaN(difference) {
			if difference < 0 {
				return -1
			}
			return 1
		}
		return ByID(a, b)
	})
	responses := []*core.Object{}
	for _, playbook := range playbooks {
		for _, item := range threatList(playbook.Get("actions")) {
			kind, _ := member(item, "kind").(string)
			if !containsString(ResponseActionKinds, kind) {
				continue
			}
			request := core.NewObject("action", item, "subject", detection.Get("subject"))
			if identityID := detection.Get("identityId"); !isUndefined(identityID) {
				request.Set("identityId", identityID)
			}
			if network := detection.Get("network"); !isUndefined(network) {
				request.Set("network", network)
			}
			request.Set("incidentId", incident.Get("id"))
			request.Set("detectionId", detection.Get("id"))
			request.Set("playbookId", playbook.Get("id"))
			request.Set("reason", "Playbook "+jsString(playbook.Get("name"))+": "+jsString(detection.Get("title")))
			request.Set("actor", core.NewObject("automatic", true))
			response, err := ApplyResponse(ctx, server, tx, tenantID, request, settings, brake)
			if err != nil {
				return nil, err
			}
			responses = append(responses, response)
		}
		runs := 0.0
		if value := playbook.Get("runs"); !nullish(value) {
			runs = jsNumber(value)
		}
		if _, err := tx.Put(ctx, ThreatCollections.Playbooks, playbook.Spread(core.NewObject(
			"runs", runs+1,
			"lastRunAt", float64(server.Now()),
		))); err != nil {
			return nil, err
		}
	}
	return responses, nil
}
