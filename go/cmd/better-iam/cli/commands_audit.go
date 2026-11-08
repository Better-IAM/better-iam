package cli

// Port of packages/cli/src/commands/audit.ts.

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

var auditTenant = FlagSpec{Name: "tenant", Type: "string", Value: "TENANT_ID", Required: true, Description: "The tenant whose audit chain to read"}

// auditChain is a tenant's chained events in sequence order, straight from storage (no credential, no audit event).
func auditChain(ctx context.Context, store core.IamStore, tenantID string) (*core.Object, []*core.Object, error) {
	head, err := store.Get(ctx, "auditChains", tenantID)
	if err != nil {
		return nil, nil, err
	}
	found, err := store.Find(ctx, "audit", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, nil, err
	}
	var events []*core.Object
	for _, event := range found {
		if _, ok := event.Get("sequence").(float64); ok {
			events = append(events, event)
		}
	}
	sort.SliceStable(events, func(i, j int) bool {
		a, _ := events[i].Get("sequence").(float64)
		b, _ := events[j].Get("sequence").(float64)
		return a < b
	})
	return head, events, nil
}

func headRef(head *core.Object) *core.AuditChainHeadRef {
	if head == nil {
		return nil
	}
	sequence, _ := head.Get("sequence").(float64)
	hash, _ := head.Get("hash").(string)
	return &core.AuditChainHeadRef{Sequence: sequence, Hash: hash}
}

// spread is { ...prefix, ...value } for an object value (a struct with JSON tags or an *core.Object).
func spread(prefix *core.Object, value any) *core.Object {
	if object, ok := jsonValue(value).(*core.Object); ok && object != nil {
		prefix.Assign(object)
	}
	return prefix
}

var (
	archiveTenant = regexp.MustCompile(`^[\w.-]{1,200}$`)
	archiveFile   = regexp.MustCompile(`^\d{12}-\d{12}\.jsonl$`)
)

var auditCommands = []*CommandSpec{
	DefineCommand(CommandSpec{
		Name:        "audit-verify",
		Group:       "Audit",
		Summary:     "Recompute and check a tenant's audit hash chain",
		Description: "audit-verify recomputes a tenant's audit hash chain from storage and exits non-zero (AUDIT_CHAIN_BROKEN) when it does not verify; it records nothing.",
		Target:      "config",
		Flags:       []FlagSpec{auditTenant},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			tenantID := c.Flags.String("tenant")
			store := iam.Store
			// A mistyped tenant has no chain to break; it must not pass a CI gate as "valid".
			tenant, err := store.Get(ctx, "tenants", tenantID)
			if err != nil {
				return nil, err
			}
			if tenant == nil {
				return nil, core.NewIamError("NOT_FOUND", "No tenant "+tenantID)
			}
			head, events, err := auditChain(ctx, store, tenantID)
			if err != nil {
				return nil, err
			}
			// Events stripped of their chain fields are handed to the verifier too, which refuses them once a chain
			// exists.
			all, err := store.Find(ctx, "audit", core.NewObject("tenantId", tenantID), nil)
			if err != nil {
				return nil, err
			}
			checked := append([]*core.Object{}, events...)
			for _, event := range all {
				if _, ok := event.Get("sequence").(float64); !ok {
					checked = append(checked, event)
				}
			}
			verification := core.VerifyAuditChain(checked, core.VerifyAuditChainOptions{Head: headRef(head)})
			report := spread(core.NewObject("tenantId", tenantID), verification)
			if head != nil {
				report.Set("head", head)
			} else {
				report.Set("head", nil)
			}
			if err := c.Print(report); err != nil {
				return nil, err
			}
			if !verification.Valid {
				return nil, core.NewIamError("AUDIT_CHAIN_BROKEN", "The audit chain does not verify")
			}
			return nil, nil
		}),
	}),
	DefineCommand(CommandSpec{
		Name: "audit-export",
		// One line, as scripts that read this output by line have always received it.
		DefaultFormat: "compact",
		Group:         "Audit",
		Summary:       "Write a tenant's audit chain as JSON Lines",
		Description:   "audit-export writes a tenant's audit chain as JSON Lines for archiving (never overwriting a file); it records nothing.",
		Target:        "config",
		Flags: []FlagSpec{
			auditTenant,
			{Name: "output", Type: "string", Value: "PATH", Required: true, Description: "The .jsonl file to create (it must not exist)"},
		},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			tenantID := c.Flags.String("tenant")
			head, events, err := auditChain(ctx, iam.Store, tenantID)
			if err != nil {
				return nil, err
			}
			output := c.Path(c.Flags.String("output"))
			lines := make([]string, len(events))
			for index, event := range events {
				lines[index] = core.MustStringify(event)
			}
			// Owner-only, like store-export: every event names its actor, action, outcome and session.
			if err := writeNewFile(output, []byte(strings.Join(lines, "\n")+"\n"), 0o600); err != nil {
				return nil, err
			}
			var first, last any = nil, nil
			if len(events) > 0 {
				first = coalesceNull(events[0].Get("sequence"))
				last = coalesceNull(events[len(events)-1].Get("sequence"))
			}
			var headValue any
			if head != nil {
				headValue = core.NewObject("sequence", head.Get("sequence"), "hash", head.Get("hash"))
			}
			return core.NewObject("tenantId", tenantID, "output", output, "count", float64(len(events)),
				"firstSequence", first, "lastSequence", last, "head", headValue), nil
		}),
	}),
	DefineCommand(CommandSpec{
		Name: "audit-prune",
		// One line, as scripts that read this output by line have always received it.
		DefaultFormat: "compact",
		Group:         "Audit",
		Summary:       "Delete a tenant's archived audit events past retention",
		Description:   "audit-prune deletes a tenant's events older than --retention-days (365) after you archived them and appends an audit:prune checkpoint so the remaining chain still verifies. With an auditArchive configured, it only deletes events the archive already holds.",
		Target:        "config",
		Flags: []FlagSpec{
			auditTenant,
			func() FlagSpec {
				flag := boundedInteger("retention-days", "Keep events newer than this many days", 0, 36500, 365.0)
				// Deletes audit history: only cli.defaults['audit-prune'] may change it, never a shared '*' default.
				flag.NoWildcardDefault = true
				return flag
			}(),
		},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			return result(iam.PruneAudit(ctx, core.NewObject("tenantId", c.Flags.String("tenant"), "retentionMs", days(c.Flags, "retention-days", 365))))
		}),
	}),
	DefineCommand(CommandSpec{
		Name:        "audit-archive",
		Group:       "Audit",
		Summary:     "Copy new audit events to the configured archive",
		Description: "audit-archive copies new audit events, verified and in chain order, to the configured auditArchive; with an archive configured, audit-prune only deletes events it already holds.",
		Target:      "config",
		Flags: []FlagSpec{
			{Name: "tenant", Type: "string", Value: "TENANT_ID", Description: "Only this tenant (default: all)"},
			func() FlagSpec {
				low := 1.0
				return FlagSpec{Name: "limit", Type: "integer", Min: &low, Description: "Most events archived per tenant and run"}
			}(),
		},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			input := tenantOnly(c.Flags)
			if limit, ok := c.Flags.Int("limit"); ok {
				input.Set("limit", float64(limit))
			}
			archived, err := iam.ArchiveAudit(ctx, input)
			if err != nil {
				return nil, err
			}
			if err := c.Print(archived); err != nil {
				return nil, err
			}
			failed, _ := pathOf(archived, "failed").([]any)
			if len(failed) > 0 {
				parts := make([]string, len(failed))
				for index, failure := range failed {
					parts[index] = jsString(pathOf(failure, "tenantId")) + " (" + jsString(pathOf(failure, "code")) + ")"
				}
				return nil, core.NewIamError("AUDIT_ARCHIVE_FAILED", strconv.Itoa(len(failed))+" tenant(s) could not be archived: "+strings.Join(parts, ", "))
			}
			return nil, nil
		}),
	}),
	DefineCommand(CommandSpec{
		Name:        "audit-verify-archive",
		Group:       "Audit",
		Summary:     "Verify an archived audit chain from its files alone",
		Description: "audit-verify-archive verifies one tenant's archived chain from createJsonlAuditArchive files alone, without the database: every sequence present once, hashes recomputed, links intact.",
		Usage:       "better-iam audit-verify-archive --directory /var/lib/better-iam/audit --tenant TENANT_ID",
		Flags: []FlagSpec{
			{Name: "directory", Type: "string", Value: "PATH", Required: true, Description: "The archive directory (createJsonlAuditArchive)"},
			func() FlagSpec {
				flag := auditTenant
				flag.Description = "The tenant whose archive to verify"
				return flag
			}(),
		},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			tenantID := c.Flags.String("tenant")
			if !archiveTenant.MatchString(tenantID) || strings.HasPrefix(tenantID, ".") {
				return nil, UsageError("Tenant id is not a safe file name")
			}
			folder := resolvePath(c.Path(c.Flags.String("directory")), tenantID)
			entries, err := os.ReadDir(folder)
			if err != nil {
				return nil, systemError(err)
			}
			var files []string
			for _, entry := range entries {
				if archiveFile.MatchString(entry.Name()) {
					files = append(files, entry.Name())
				}
			}
			sort.Strings(files)
			// Files can overlap after a crash; each sequence must then carry the identical event.
			type archived struct {
				event *core.Object
				line  string
			}
			bySequence := map[string]archived{}
			var order []string
			conflicts := 0
			for _, name := range files {
				text, err := os.ReadFile(filepath.Join(folder, name))
				if err != nil {
					return nil, systemError(err)
				}
				for _, line := range strings.Split(string(text), "\n") {
					if core.JSTrim(line) == "" {
						continue
					}
					parsed, err := core.ParseJSONString(line)
					if err != nil {
						return nil, err
					}
					event, _ := parsed.(*core.Object)
					if event == nil {
						event = core.NewObject()
					}
					key := jsString(event.Get("sequence"))
					if seen, ok := bySequence[key]; ok && seen.line != line {
						conflicts++
					} else {
						if !ok {
							order = append(order, key)
						}
						bySequence[key] = archived{event: event, line: line}
					}
				}
			}
			events := make([]*core.Object, len(order))
			for index, key := range order {
				events[index] = bySequence[key].event
			}
			verification := core.VerifyAuditChain(events, core.VerifyAuditChainOptions{})
			if err := c.Print(spread(core.NewObject("tenantId", tenantID, "files", float64(len(files)), "conflicts", float64(conflicts)), verification)); err != nil {
				return nil, err
			}
			// An archive with nothing in it proves nothing: a CI gate must not pass on an empty or misnamed directory.
			if len(events) == 0 {
				return nil, core.NewIamError("AUDIT_ARCHIVE_INVALID", "No archived events of "+tenantID+" were found")
			}
			if !verification.Valid || conflicts > 0 {
				if conflicts > 0 {
					return nil, core.NewIamError("AUDIT_ARCHIVE_INVALID", strconv.Itoa(conflicts)+" archived event(s) disagree with another copy of the same sequence")
				}
				reason, sequence := "undefined", "undefined"
				if verification.Failure != nil {
					reason, sequence = string(verification.Failure.Reason), core.NumberString(verification.Failure.Sequence)
				}
				return nil, core.NewIamError("AUDIT_ARCHIVE_INVALID", "The archived chain does not verify ("+reason+" at sequence "+sequence+")")
			}
			return nil, nil
		},
	}),
}

// coalesceNull is value ?? null.
func coalesceNull(value any) any {
	if core.IsUndefined(value) {
		return nil
	}
	return value
}

// writeNewFile creates a file that must not exist (flag wx) with mode and writes data.
func writeNewFile(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return systemError(err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return systemError(err)
	}
	return systemError(file.Close())
}
