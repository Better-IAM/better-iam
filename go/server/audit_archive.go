package server

// Skeleton of packages/server/src/audit-archive.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// AuditArchive is audit-archive.ts createAuditArchive().
type AuditArchive struct {
	server *ServerContext
}

// ArchiveAudit (audit-archive.ts createAuditArchive().archiveAudit): Archives every tenant's new audit events (or
// one `tenantId`'s), at most `limit` events per run (default 100000). A scheduler job; run it before `pruneAudit`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *AuditArchive) ArchiveAudit(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("audit-archive.ts createAuditArchive().archiveAudit")
	return
}

// ArchiveCursor (audit-archive.ts createAuditArchive().archiveCursor): The archive position of one tenant's chain,
// or undefined when nothing was archived yet.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *AuditArchive) ArchiveCursor(ctx context.Context, tenantID string) (result *core.Object, err error) {
	err = notImplemented("audit-archive.ts createAuditArchive().archiveCursor")
	return
}

// CreateAuditArchive builds the AuditArchive (audit-archive.ts createAuditArchive). Its methods are stubs until the module is ported.
func CreateAuditArchive(server *ServerContext) *AuditArchive {
	return &AuditArchive{server: server}
}
