package server

// Port of packages/server/src/self-check.ts: the deployment self-check (schema, durability, secrets, transports, and
// scheduled jobs). It only reads.

import (
	"context"
	"regexp"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

const (
	selfCheckMinute = 60_000.0
	selfCheckDay    = 86_400_000.0
	// sweepOverdueMs: a sweep scheduled at least daily leaves nothing due for this long.
	sweepOverdueMs = 2 * selfCheckDay
)

// placeholderSecret is /change[-_ ]?me|replace[-_ ]?me|example|placeholder|^(?:secret|password)/i, matched against
// the secret with its ASCII letters lowercased (JavaScript's non-Unicode case folding never maps other characters
// onto these ASCII patterns).
var placeholderSecret = regexp.MustCompile(`change[-_ ]?me|replace[-_ ]?me|example|placeholder|^(?:secret|password)`)

// asciiLower lowercases the ASCII letters of a string only.
func asciiLower(value string) string {
	return strings.Map(func(r rune) rune {
		if r >= 'A' && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, value)
}

// selfCheckFinding is one problem selfCheck found, with the operator's next step (count only when it is about stored
// data).
func selfCheckFinding(check, severity, message, fix string, count ...float64) *core.Object {
	finding := core.NewObject("check", check, "severity", severity, "message", message, "fix", fix)
	if len(count) > 0 {
		finding.Set("count", count[0])
	}
	return finding
}

// countsSummary is `Object.entries(counts).map(([collection, count]) => `${collection}: ${count}`).join(', ')`,
// keeping only entries keep accepts.
func countsSummary(counts *core.Object, keep func(count any) bool) string {
	var parts []string
	counts.Entries(func(key string, value any) bool {
		if keep == nil || keep(value) {
			parts = append(parts, key+": "+jsString(value))
		}
		return true
	})
	return strings.Join(parts, ", ")
}

// countsTotal is the sum of a record of counts.
func countsTotal(counts *core.Object) float64 {
	total := 0.0
	counts.Entries(func(_ string, value any) bool {
		total += jsNumber(value)
		return true
	})
	return total
}

// cappedCount is `${count >= cap ? `${cap}+` : count}`.
func cappedCount(count, cap float64) string {
	if count >= cap {
		return jsString(cap) + "+"
	}
	return jsString(count)
}

// CreateSelfCheck (self-check.ts createSelfCheck): the deployment self-check (schema, durability, secrets, transports,
// scheduled jobs). countDue and sampleSecrets are the retention and secret-rotation dry runs it reports on. It checks a
// running deployment for problems an operator should act on: a schema behind this release, a platform never
// bootstrapped, a guessable secret, settings that lose data, missing delivery transports, and scheduled jobs that are
// not running.
func CreateSelfCheck(server *ServerContext, countDue func(context.Context, *core.Object) (*core.Object, error), sampleSecrets func(context.Context, float64) (*SecretRotationResult, error)) func(ctx context.Context, options *core.Object) (*core.Object, error) {
	return func(ctx context.Context, options *core.Object) (*core.Object, error) {
		if options == nil {
			options = core.NewObject()
		}
		cap, isNumber := core.Normalize(coalesce(options.Get("cap"), 1000.0)).(float64)
		if !isNumber || !core.IsSafeInteger(cap) || cap < 1 || cap > 100_000 {
			return nil, invalidInput("cap must be an integer between 1 and 100000")
		}
		for _, bound := range []struct {
			name string
			max  float64
		}{{"deliveryRetentionMs", 3650 * selfCheckDay}, {"graceMs", selfCheckDay}} {
			value := options.Get(bound.name)
			if isUndefined(value) {
				continue
			}
			number, isNumber := core.Normalize(value).(float64)
			if !isNumber || !core.IsSafeInteger(number) || number < 0 || number > bound.max {
				return nil, invalidInput(bound.name + " must be an integer between 0 and " + jsString(bound.max))
			}
		}
		settings, store := server.Options, server.Store
		findings := []any{}
		add := func(finding *core.Object) { findings = append(findings, finding) }
		now := float64(server.Now())
		result := func(storage any) *core.Object {
			ok := true
			for _, finding := range findings {
				if finding.(*core.Object).Get("severity") == "error" {
					ok = false
				}
			}
			return core.NewObject("ok", ok, "findings", findings, "storage", storage)
		}

		// --- storage ---------------------------------------------------------------------------
		var storage *core.StoreDescription
		if describer, ok := store.(core.Describer); ok {
			description, err := describer.Describe(ctx)
			if err != nil {
				return nil, err
			}
			storage = description
		}
		var storageModel any
		if storage != nil {
			model, err := ToModel(storage)
			if err != nil {
				return nil, err
			}
			storageModel = model
			applied := map[string]bool{}
			for _, migration := range storage.Migrations {
				applied[migration.Name] = true
			}
			var missing []string
			for _, name := range core.MigrationNames {
				if !applied[name] {
					missing = append(missing, name)
				}
			}
			if storage.SchemaVersion == nil || len(missing) > 0 {
				message := "The database has no IAM schema"
				if storage.SchemaVersion != nil {
					message = "Schema migrations not applied: " + strings.Join(missing, ", ")
				}
				add(selfCheckFinding("schema-behind", "error", message,
					"Run `better-iam migrate` (or `iam.initialize()`) before serving traffic"))
			}
			setting := storage.Settings
			if member(setting, "inMemory") == true || member(setting, "location") == "memory" {
				add(selfCheckFinding("in-memory-database", "warning",
					"The database lives in memory; everything is lost when the process exits",
					"Configure a file or server database for anything but tests"))
			}
			synchronous := member(setting, "synchronous")
			if storage.Adapter == "sqlite" && member(setting, "inMemory") == false && member(setting, "journalMode") == "delete" &&
				(synchronous == "normal" || synchronous == "off") {
				add(selfCheckFinding("sqlite-durability", "error",
					"SQLite runs a rollback journal with synchronous="+jsString(synchronous)+", which a power failure can corrupt",
					"Use `durability: 'full'`, or WAL mode (the default journalMode)"))
			}
			if member(setting, "synchronousCommit") == "off" {
				add(selfCheckFinding("postgres-async-commit", "warning",
					"PostgreSQL synchronous_commit is off: a crash can lose recently committed changes",
					"Set synchronous_commit to on (or remote_apply with replicas) for the IAM database"))
			}
		} else {
			add(selfCheckFinding("storage-undescribed", "info",
				"The storage adapter cannot describe its schema, so migrations were not checked",
				"Implement `IamStore.describe()` in the adapter"))
		}

		// --- platform ----------------------------------------------------------------------------
		if storage == nil || storage.SchemaVersion != nil {
			limit := 2
			roots, err := store.Find(ctx, "tenants", core.NewObject("parentId", nil), &core.FindOptions{Limit: &limit})
			if err != nil {
				return nil, err
			}
			if len(roots) == 0 {
				add(selfCheckFinding("not-bootstrapped", "error", "No root tenant exists yet",
					"Run `better-iam bootstrap` with BETTER_IAM_ROOT_EMAIL and BETTER_IAM_ROOT_PASSWORD"))
			}
		}
		secret := settings.Secret
		// Random hex, base64, or UUID secrets of the required length use far more than 8 characters.
		distinct := map[rune]bool{}
		for _, character := range secret {
			distinct[character] = true
		}
		if len(distinct) < 8 || placeholderSecret.MatchString(asciiLower(secret)) {
			add(selfCheckFinding("weak-secret", "warning",
				"The deployment secret looks like a placeholder or has little variety",
				"Use a random value, for example `openssl rand -base64 48`, kept in a secret store"))
		}
		if observability := settings.Observability; observability != nil && observability.Metrics != nil &&
			observability.Metrics.Options != nil && observability.Metrics.Options.BearerToken != nil &&
			utf16Len(*observability.Metrics.Options.BearerToken) < 24 {
			add(selfCheckFinding("weak-metrics-token", "warning", "The metrics bearer token is shorter than 24 characters",
				"Use a random token of at least 24 characters"))
		}
		if settings.Authentication == nil || settings.Authentication.SendEmail == nil {
			add(selfCheckFinding("no-email-transport", "warning",
				"No email transport: invitations, password resets, and verification emails cannot be sent",
				"Configure `authentication.sendEmail`"))
		}

		if storage != nil && storage.SchemaVersion == nil {
			return result(storageModel), nil
		}

		// --- sealed values ----------------------------------------------------------------------
		// A secret changed without listing the old one in `previousSecrets` silently breaks every authenticator app
		// and webhook signature; a sample of the stored values shows it.
		sealed, err := sampleSecrets(ctx, cap)
		if err != nil {
			return nil, err
		}
		if unreadable := countsTotal(sealed.Unreadable); unreadable != 0 {
			add(selfCheckFinding("unreadable-secrets", "error",
				jsString(unreadable)+" stored secret value(s) open with no configured secret ("+countsSummary(sealed.Unreadable, nil)+
					"); the deployment secret was probably changed without previousSecrets",
				"Put the old secret in `previousSecrets`, run `better-iam rotate-secrets`, then remove it", unreadable))
		}
		if pending := countsTotal(sealed.Resealed); pending != 0 {
			add(selfCheckFinding("secret-rotation-pending", "warning",
				jsString(pending)+" stored secret value(s) are still sealed with a previous secret",
				"Run `better-iam rotate-secrets` (or `iam.rotateSecrets()`) until it reports `done: true`, then remove `previousSecrets` a day later",
				pending))
		} else if len(settings.PreviousSecrets) > 0 {
			if sealed.Complete {
				add(selfCheckFinding("previous-secrets-configured", "info",
					"previousSecrets is set, and no stored value needs it any more",
					"A day after the rotation (pending links and assertions), remove `previousSecrets` and give downstream verifiers only `iam.assertionKey()`"))
			} else {
				// The sample covers the first records only, which a rotation also re-seals first.
				add(selfCheckFinding("secret-rotation-unverified", "warning",
					"previousSecrets is set; no value in a sample of "+jsString(cap)+" per collection needs it, but not every record was examined",
					"Run `better-iam rotate-secrets --dry-run` and remove `previousSecrets` only when it reports `done: true`"))
			}
		}

		// --- scheduled jobs ----------------------------------------------------------------------
		// Judged by age, with the sweep's own settings: a sweep that runs at least daily leaves nothing that has been
		// due for two days, however busy the deployment is.
		due, err := countDue(ctx, core.NewObject(
			"cap", cap, "deliveryRetentionMs", options.Get("deliveryRetentionMs"), "graceMs", options.Get("graceMs"),
			"overdueMs", sweepOverdueMs,
		))
		if err != nil {
			return nil, err
		}
		if backlog := min(cap, countsTotal(due)); backlog != 0 {
			add(selfCheckFinding("sweep-backlog", "warning",
				cappedCount(backlog, cap)+" record(s) have been due for the retention sweep for more than two days ("+
					countsSummary(due, truthy)+")",
				"Schedule `better-iam sweep` (or `iam.sweepExpired()`) hourly or daily, with a `limit` that keeps up", backlog))
		}
		lapsed := 0
		for _, collection := range []string{"bindings", "groupMembers", "authChallenges"} {
			to, one := now-selfCheckDay, 1
			found, err := core.FindOrdered(ctx, store, collection, core.NewObject(), core.OrderOptions{Field: "expiresAt", To: &to, Limit: &one}, nil)
			if err != nil {
				return nil, err
			}
			lapsed += len(found)
		}
		if lapsed > 0 {
			add(selfCheckFinding("purge-not-running", "warning",
				"Expired bindings, memberships, or challenges are more than a day old",
				"Schedule `better-iam purge` (or `iam.purgeDeleted()`) at least daily"))
		}
		capLimit := int(cap)
		stalledBefore := now - 15*selfCheckMinute
		stalledRows, err := core.FindOrdered(ctx, store, "outbox", core.NewObject("deliveredAt", core.Undefined, "failedAt", core.Undefined),
			core.OrderOptions{Field: "createdAt", To: &stalledBefore, Limit: &capLimit}, nil)
		if err != nil {
			return nil, err
		}
		if stalled := float64(len(stalledRows)); stalled != 0 {
			add(selfCheckFinding("outbox-stalled", "warning",
				cappedCount(stalled, cap)+" outgoing message(s) have waited more than 15 minutes",
				"Schedule `better-iam outbox` (or `iam.auth.dispatchOutbox()`) every minute, and check the delivery callbacks", stalled))
		}
		abandonedSince := now - selfCheckDay
		abandonedRows, err := core.FindOrdered(ctx, store, "outbox", core.NewObject(),
			core.OrderOptions{Field: "failedAt", From: &abandonedSince, Limit: &capLimit}, nil)
		if err != nil {
			return nil, err
		}
		if abandoned := float64(len(abandonedRows)); abandoned != 0 {
			add(selfCheckFinding("outbox-abandoned", "warning",
				jsString(abandoned)+" outgoing message(s) were abandoned in the last day after repeated failures",
				"Check the email, SMS, and webhook delivery callbacks and their `lastError`", abandoned))
		}
		hooks, err := store.Find(ctx, "auditHooks", core.NewObject("delivered", false), &core.FindOptions{Limit: &capLimit})
		if err != nil {
			return nil, err
		}
		waiting := 0.0
		for _, row := range hooks {
			if timestamp, ok := member(row.Get("event"), "timestamp").(float64); ok && timestamp <= now-15*selfCheckMinute {
				waiting++
			}
		}
		if waiting != 0 {
			add(selfCheckFinding("audit-hooks-stalled", "warning",
				jsString(waiting)+" audit event(s) have waited more than 15 minutes for plugins, subscribers, or onEvent",
				"Call `iam.dispatchAuditHooks()` every minute in the application process that registers event subscribers (the CLI `outbox` command serves only plugins and `events.onEvent`)",
				waiting))
		}
		if settings.AuditArchive != nil {
			// A tenant whose oldest unarchived event is over a day old: the archive job is not keeping up. Every tenant
			// is examined (a page of chain heads at a time); counting stops at `cap`.
			behind := 0.0
			var after *string
			for behind < cap {
				page := 500
				heads, err := store.Find(ctx, "auditChains", core.NewObject(), &core.FindOptions{Limit: &page, After: after})
				if err != nil {
					return nil, err
				}
				for _, head := range heads {
					headID := jsString(head.Get("id"))
					cursor, err := store.Get(ctx, "auditArchiveCursors", headID)
					if err != nil {
						return nil, err
					}
					archived := 0.0
					if cursor != nil {
						archived = jsNumber(coalesce(cursor.Get("sequence"), 0.0))
					}
					if jsNumber(head.Get("sequence")) <= archived {
						continue
					}
					from, one := archived+1, 1
					oldest, err := core.FindOrdered(ctx, store, "audit", core.NewObject("tenantId", headID),
						core.OrderOptions{Field: "sequence", From: &from, Limit: &one}, nil)
					if err != nil {
						return nil, err
					}
					if len(oldest) > 0 && jsNumber(oldest[0].Get("timestamp")) <= now-selfCheckDay {
						behind++
					}
					if behind >= cap {
						break
					}
				}
				if len(heads) < 500 {
					break
				}
				last := jsString(heads[len(heads)-1].Get("id"))
				after = &last
			}
			if behind != 0 {
				add(selfCheckFinding("audit-archive-behind", "warning",
					cappedCount(behind, cap)+" tenant(s) have audit events older than a day that are not archived",
					"Schedule `better-iam audit-archive` (or `iam.archiveAudit()`) at least hourly, and check the sink for failures",
					behind))
			}
		}
		return result(storageModel), nil
	}
}
