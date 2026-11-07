package server

// Port of packages/server/src/audit-archive.ts: continuous audit archiving. It copies each tenant's hash-chained audit
// events, verified and in order, to the configured sink, and records how far each chain has been archived
// (`auditArchiveCursors`). One run at a time holds a tenant (a lease on its cursor), so overlapping runs never race
// each other's batches. `pruneAudit` never deletes past the cursor.

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

const auditArchiveCursors = "auditArchiveCursors"

// AuditArchive is audit-archive.ts createAuditArchive().
type AuditArchive struct {
	server    *ServerContext
	sink      *AuditArchiveOptions
	batchSize float64
	leaseMs   float64
	configErr error
}

// CreateAuditArchive builds the AuditArchive (audit-archive.ts createAuditArchive). An invalid `auditArchive`
// option (batchSize, leaseMs) is reported by ConfigError, which construction checks.
func CreateAuditArchive(server *ServerContext) *AuditArchive {
	archive := &AuditArchive{server: server, batchSize: 1000, leaseMs: 10 * 60_000}
	if server.Options != nil {
		archive.sink = server.Options.AuditArchive
	}
	sink := archive.sink
	if sink != nil && sink.BatchSize != nil {
		archive.batchSize = *sink.BatchSize
	}
	if sink != nil && sink.LeaseMs != nil {
		archive.leaseMs = *sink.LeaseMs
	}
	if sink != nil && (!core.IsSafeInteger(archive.batchSize) || archive.batchSize < 1 || archive.batchSize > 10_000) {
		archive.configErr = invalidConfig("auditArchive.batchSize must be between 1 and 10000")
	} else if sink != nil && (!core.IsSafeInteger(archive.leaseMs) || archive.leaseMs < 60_000 || archive.leaseMs > 3_600_000) {
		archive.configErr = invalidConfig("auditArchive.leaseMs must be between 60000 and 3600000")
	}
	return archive
}

// ConfigError is the INVALID_CONFIG error createAuditArchive throws for an invalid `auditArchive` option (nil when
// valid).
func (s *AuditArchive) ConfigError() error { return s.configErr }

// claim takes or renews this run's lease on a tenant; nil when another live run holds it.
func (s *AuditArchive) claim(ctx context.Context, tenantID, leaseID string) (*core.Object, error) {
	return core.Transact(ctx, s.server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		current, err := tx.Get(ctx, auditArchiveCursors, tenantID)
		if err != nil {
			return nil, err
		}
		now := float64(s.server.Wall())
		if current != nil {
			held := current.Get("leaseId")
			if truthy(held) && held != leaseID && jsNumber(coalesce(current.Get("leaseUntil"), 0.0)) > now {
				return nil, nil
			}
		}
		next := core.NewObject(
			"id", tenantID, "tenantId", tenantID,
			"sequence", coalesce(member(current, "sequence"), 0.0),
			"hash", coalesce(member(current, "hash"), core.AuditGenesis),
			"updatedAt", coalesce(member(current, "updatedAt"), float64(s.server.Now())),
			"leaseId", leaseID, "leaseUntil", now+s.leaseMs,
		)
		if current != nil {
			_, err = tx.Put(ctx, auditArchiveCursors, next)
		} else {
			_, err = tx.Insert(ctx, auditArchiveCursors, next)
		}
		if err != nil {
			return nil, err
		}
		return next, nil
	})
}

// release gives the lease up when this run still holds it.
func (s *AuditArchive) release(ctx context.Context, tenantID, leaseID string) error {
	return s.server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		current, err := tx.Get(ctx, auditArchiveCursors, tenantID)
		if err != nil {
			return err
		}
		if current != nil && current.Get("leaseId") == leaseID {
			rest := current.Spread()
			rest.Delete("leaseId")
			rest.Delete("leaseUntil")
			_, err = tx.Put(ctx, auditArchiveCursors, rest)
		}
		return err
	})
}

// auditArchiveRun is the result of one ArchiveAudit run while it is built.
type auditArchiveRun struct {
	archived *core.Object
	batches  int
	failed   []any
	gaps     []any
	busy     []string
}

func (r *auditArchiveRun) markBusy(tenantID string) {
	if !containsString(r.busy, tenantID) {
		r.busy = append(r.busy, tenantID)
	}
}

// auditArchiveMessage is `error instanceof Error ? error.message.slice(0, 256) : String(error)`.
func auditArchiveMessage(err error) string {
	units := core.ToUTF16(errorMessage(err))
	if len(units) > 256 {
		units = units[:256]
	}
	return core.FromUTF16(units)
}

// archiveTenant archives one tenant's chain from its cursor, a batch at a time; false when the budget ran out.
func (s *AuditArchive) archiveTenant(ctx context.Context, tenantID string, budget func() float64, result *auditArchiveRun) (finished bool, err error) {
	leaseID := ID()
	defer func() {
		if releaseErr := s.release(ctx, tenantID, leaseID); releaseErr != nil {
			finished, err = false, releaseErr
		}
	}()
	for {
		size := s.batchSize
		if remaining := budget(); remaining < size {
			size = remaining
		}
		if size == 0 {
			return false, nil
		}
		// Renewed before every batch, so a run that holds the lease never loses it mid-batch unless one write
		// outlasts the whole lease.
		cursor, err := s.claim(ctx, tenantID, leaseID)
		if err != nil {
			return false, err
		}
		if cursor == nil {
			result.markBusy(tenantID)
			return true, nil
		}
		after := jsNumber(cursor.Get("sequence"))
		from := after + 1
		limit := int(size)
		events, err := core.FindOrdered(ctx, s.server.Store, "audit", core.NewObject("tenantId", tenantID), core.OrderOptions{Field: "sequence", From: &from, Limit: &limit}, nil)
		if err != nil {
			return false, err
		}
		if len(events) == 0 {
			return true, nil
		}
		first := events[0]
		firstSequence, _ := first.Get("sequence").(float64)
		contiguous := firstSequence == after+1
		if !contiguous {
			result.gaps = append(result.gaps, core.NewObject("tenantId", tenantID, "fromSequence", after+1, "toSequence", firstSequence-1))
		}
		previousHash := jsString(cursor.Get("hash"))
		if !contiguous {
			previousHash = jsString(coalesce(first.Get("previousHash"), core.AuditGenesis))
		}
		verification := core.VerifyAuditChain(events, core.VerifyAuditChainOptions{PreviousHash: &previousHash})
		if !verification.Valid || verification.Checked != len(events) {
			at := first.Get("sequence")
			if verification.Failure != nil {
				at = verification.Failure.Sequence
			}
			result.failed = append(result.failed, core.NewObject(
				"tenantId", tenantID, "code", "AUDIT_CHAIN_BROKEN", "message", "The chain does not verify at sequence "+jsString(at),
			))
			return true, nil
		}
		batch := AuditArchiveBatch{
			TenantID: tenantID, FromSequence: firstSequence, ToSequence: *verification.Last, PreviousHash: previousHash,
			LastHash: *verification.LastHash, Events: events,
		}
		// Outside any transaction: the sink is an external side effect.
		if err := s.sink.Write(ctx, batch); err != nil {
			code := "ARCHIVE_WRITE_FAILED"
			if known, ok := asIamError(err); ok && known.Code == "ARCHIVE_CONFLICT" {
				code = "ARCHIVE_CONFLICT"
			}
			result.failed = append(result.failed, core.NewObject("tenantId", tenantID, "code", code, "message", auditArchiveMessage(err)))
			return true, nil
		}
		advanced, err := core.Transact(ctx, s.server.Store, func(ctx context.Context, tx core.IamStore) (bool, error) {
			current, err := tx.Get(ctx, auditArchiveCursors, tenantID)
			if err != nil {
				return false, err
			}
			// Only the lease holder moves the cursor, and only from where it read.
			if current == nil || current.Get("leaseId") != leaseID || current.Get("sequence") != after {
				return false, nil
			}
			_, err = tx.Put(ctx, auditArchiveCursors, current.Spread(core.NewObject(
				"sequence", batch.ToSequence, "hash", batch.LastHash, "updatedAt", float64(s.server.Now()),
			)))
			return err == nil, err
		})
		if err != nil {
			return false, err
		}
		if !advanced {
			result.markBusy(tenantID)
			return true, nil
		}
		previous, _ := result.archived.Get(tenantID).(float64)
		result.archived.Set(tenantID, previous+float64(len(events)))
		result.batches++
		if float64(len(events)) < size {
			return true, nil
		}
	}
}

// ArchiveAudit (audit-archive.ts createAuditArchive().archiveAudit): Archives every tenant's new audit events (or
// one `tenantId`'s), at most `limit` events per run (default 100000). A scheduler job; run it before `pruneAudit`.
func (s *AuditArchive) ArchiveAudit(ctx context.Context, input *core.Object) (*core.Object, error) {
	if s.configErr != nil {
		return nil, s.configErr
	}
	if s.sink == nil {
		return nil, core.NewIamError("NO_AUDIT_ARCHIVE", "Configure auditArchive (for example createJsonlAuditArchive) to archive audit events", 501)
	}
	rawLimit := coalesce(member(input, "limit"), 100_000.0)
	limit, ok := rawLimit.(float64)
	if !ok || !core.IsSafeInteger(limit) || limit < 1 || limit > 10_000_000 {
		return nil, invalidInput("limit must be between 1 and 10000000")
	}
	result := &auditArchiveRun{archived: core.NewObject(), failed: []any{}, gaps: []any{}, busy: []string{}}
	budget := func() float64 {
		sum := 0.0
		result.archived.Entries(func(_ string, value any) bool {
			sum += jsNumber(value)
			return true
		})
		return limit - sum
	}
	var tenants []string
	if tenantID := member(input, "tenantId"); !isUndefined(tenantID) {
		tenants = []string{jsString(tenantID)}
	} else {
		heads, err := s.server.Store.Find(ctx, "auditChains", core.NewObject(), nil)
		if err != nil {
			return nil, err
		}
		for _, head := range heads {
			tenants = append(tenants, jsString(head.Get("id")))
		}
	}
	truncated := false
	for _, tenantID := range tenants {
		finished, err := s.archiveTenant(ctx, tenantID, budget, result)
		if err != nil {
			return nil, err
		}
		if !finished {
			truncated = true
			break
		}
	}
	return core.NewObject(
		"archived", result.archived, "batches", result.batches, "failed", result.failed, "gaps", result.gaps,
		"busy", stringsOf(result.busy), "truncated", truncated,
	), nil
}

// ArchiveCursor (audit-archive.ts createAuditArchive().archiveCursor): The archive position of one tenant's chain,
// or nil when nothing was archived yet.
func (s *AuditArchive) ArchiveCursor(ctx context.Context, tenantID string) (*core.Object, error) {
	return s.server.Store.Get(ctx, auditArchiveCursors, tenantID)
}

// syncDirectory flushes a directory entry (a created or renamed file) to disk; Windows cannot open directories for
// that.
func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	handle, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := handle.Sync()
	closeErr := handle.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

// jsonlTenantName is a tenant ID that is a safe file name.
var jsonlTenantName = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,200}$`)

// jsonlPad is `String(value).padStart(12, '0')`.
func jsonlPad(value float64) string {
	text := core.NumberString(value)
	for utf16Len(text) < 12 {
		text = "0" + text
	}
	return text
}

// CreateJsonlAuditArchive (audit-archive.ts createJsonlAuditArchive): a file sink for `auditArchive`, one JSON Lines
// file per batch at `{directory}/{tenantId}/{fromSequence}-{toSequence}.jsonl` (sequences zero-padded, so files sort
// in chain order). Files are write-once: each is written under a unique temporary name, flushed, and published with
// a hard link that never replaces an existing file. Writing the same batch again is accepted; a different batch under
// an existing name is refused (`ARCHIVE_CONFLICT`).
func CreateJsonlAuditArchive(directory string) *AuditArchiveOptions {
	root, rootErr := filepath.Abs(directory)
	return &AuditArchiveOptions{Write: func(ctx context.Context, batch AuditArchiveBatch) error {
		if rootErr != nil {
			return rootErr
		}
		if !jsonlTenantName.MatchString(batch.TenantID) || strings.HasPrefix(batch.TenantID, ".") {
			return invalidInput("Tenant id is not a safe file name")
		}
		folder := filepath.Join(root, batch.TenantID)
		// A newly created tenant folder must itself be durable before its files are.
		_, statErr := os.Stat(folder)
		if err := os.MkdirAll(folder, 0o777); err != nil {
			return err
		}
		if errors.Is(statErr, fs.ErrNotExist) {
			if err := syncDirectory(root); err != nil {
				return err
			}
		}
		name := jsonlPad(batch.FromSequence) + "-" + jsonlPad(batch.ToSequence) + ".jsonl"
		target := filepath.Join(folder, name)
		lines := make([]string, len(batch.Events))
		for index, event := range batch.Events {
			text, _, err := core.Stringify(event)
			if err != nil {
				return err
			}
			lines[index] = text
		}
		content := strings.Join(lines, "\n") + "\n"
		temporary := filepath.Join(folder, "."+name+"."+ID()+".tmp")
		file, err := os.OpenFile(temporary, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		_, writeErr := file.Write(utf8Bytes(content))
		if writeErr == nil {
			writeErr = file.Sync()
		}
		closeErr := file.Close()
		defer os.Remove(temporary)
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
		if err := os.Link(temporary, target); err != nil {
			if !errors.Is(err, fs.ErrExist) {
				return err
			}
			// Already archived: fine when identical, a conflict otherwise; the stored file stays.
			stored, err := os.ReadFile(target)
			if err != nil {
				return err
			}
			if decodeUTF8(stored) != content {
				return core.NewIamError("ARCHIVE_CONFLICT", batch.TenantID+"/"+name+" already holds different events", 409)
			}
		}
		if err := os.Remove(temporary); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		return syncDirectory(folder)
	}}
}
