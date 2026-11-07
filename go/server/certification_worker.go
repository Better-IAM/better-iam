package server

// Skeleton of packages/server/src/certification-worker.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"context"

	"github.com/Better-IAM/better-iam/go/core"
)

// CertificationWorker is certification-worker.ts createCertificationWorker().
type CertificationWorker struct {
	server *ServerContext
}

// CloseOverdueCertifications (certification-worker.ts createCertificationWorker().closeOverdueCertifications):
// Closes every open `autoClose` campaign whose `dueAt` has passed (or only those of `tenantId`), each in its own
// transaction. Revocations run under the campaign creator's grant authority; when the creator no longer exists, is
// disabled or expired, or no longer holds iam:certifications:manage on the campaign, the campaign still closes and
// every revocation is reported as `revocation-failed`. Audited as `certification:auto-close` (with the outcome
// counts) plus one `iam:bindings:delete` per removed binding, both by `deployment-operator`. A deployment operation
// for schedulers: no credential.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *CertificationWorker) CloseOverdueCertifications(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	err = notImplemented("certification-worker.ts createCertificationWorker().closeOverdueCertifications")
	return
}

// CreateCertificationWorker builds the CertificationWorker (certification-worker.ts createCertificationWorker). Its methods are stubs until the module is ported.
func CreateCertificationWorker(server *ServerContext) *CertificationWorker {
	return &CertificationWorker{server: server}
}
