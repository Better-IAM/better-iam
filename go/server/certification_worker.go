package server

// Port of packages/server/src/certification-worker.ts: the deployment worker for access certifications. Not an HTTP
// endpoint.

import (
	"context"
	"sort"

	"github.com/Better-IAM/better-iam/go/core"
)

// CertificationWorker is certification-worker.ts createCertificationWorker().
type CertificationWorker struct {
	server *ServerContext
}

// CreateCertificationWorker builds the CertificationWorker (certification-worker.ts createCertificationWorker).
func CreateCertificationWorker(server *ServerContext) *CertificationWorker {
	return &CertificationWorker{server: server}
}

// actingCreator is the creator as the principal revocations run under, only while they could still close the
// campaign themselves: active, not expired, and allowed iam:certifications:manage on it. Offboarding (disabling,
// expiry, losing the permission) ends their authority here too, as deletion does. nil when they cannot.
func (s *CertificationWorker) actingCreator(ctx context.Context, tx core.IamStore, campaign *core.Object, creator *core.Object) (*Principal, error) {
	server := s.server
	if creator.Get("status") != "active" || server.IdentityExpired(creator) {
		return nil, nil
	}
	principal := server.Decisions.SimulatedPrincipal(creator, false)
	decision, err := server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
		TenantID: jsString(campaign.Get("tenantId")), Action: "iam:certifications:manage",
		Resource: ResourceTarget{Type: "iam", ID: "certifications/" + jsString(campaign.Get("id"))},
	}, true)
	if err != nil {
		return nil, err
	}
	if decision.Allowed {
		return principal, nil
	}
	return nil, nil
}

// CloseOverdueCertifications (certification-worker.ts createCertificationWorker().closeOverdueCertifications):
// Closes every open `autoClose` campaign whose `dueAt` has passed (or only those of `tenantId`), each in its own
// transaction. Revocations run under the campaign creator's grant authority; when the creator no longer exists, is
// disabled or expired, or no longer holds iam:certifications:manage on the campaign, the campaign still closes and
// every revocation is reported as `revocation-failed`. Audited as `certification:auto-close` (with the outcome
// counts) plus one `iam:bindings:delete` per removed binding, both by `deployment-operator`. A deployment operation
// for schedulers: no credential. The answer is `{ closed: [{ tenantId, campaignId, outcomes }], skipped }`.
func (s *CertificationWorker) CloseOverdueCertifications(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	server := s.server
	store := server.Store
	tenantID := ""
	if raw := member(input, "tenantId"); !isUndefined(raw) {
		text, err := Text(raw, "tenantId")
		if err != nil {
			return nil, err
		}
		tenant, err := server.Tenant(ctx, store, text)
		if err != nil {
			return nil, err
		}
		tenantID = jsString(tenant.Get("id"))
	}
	filter := core.NewObject("status", "open", "autoClose", true)
	if tenantID != "" {
		filter.Set("tenantId", tenantID)
	}
	candidates, err := store.Find(ctx, "certificationCampaigns", filter, nil)
	if err != nil {
		return nil, err
	}
	dueOf := func(campaign *core.Object) float64 {
		due := campaign.Get("dueAt")
		if nullish(due) {
			return 0
		}
		return jsNumber(due)
	}
	sort.SliceStable(candidates, func(i, j int) bool {
		if difference := dueOf(candidates[i]) - dueOf(candidates[j]); difference != 0 && difference == difference {
			return difference < 0
		}
		return compareUTF16(jsString(candidates[i].Get("id")), jsString(candidates[j].Get("id"))) < 0
	})
	closed := []any{}
	skipped := 0
	for _, candidate := range candidates {
		due := candidate.Get("dueAt")
		if isUndefined(due) || jsNumber(due) > float64(server.Now()) {
			skipped++
			continue
		}
		entry, err := core.Transact(ctx, store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
			campaign, err := tx.Get(ctx, "certificationCampaigns", jsString(candidate.Get("id")))
			if err != nil {
				return nil, err
			}
			// An administrator may have closed or deleted it since the scan.
			if campaign == nil || campaign.Get("status") != "open" {
				return nil, nil
			}
			creator, err := tx.Get(ctx, "identities", jsString(campaign.Get("createdBy")))
			if err != nil {
				return nil, err
			}
			var principal *Principal
			if creator != nil {
				if principal, err = s.actingCreator(ctx, tx, campaign, creator); err != nil {
					return nil, err
				}
			}
			applied, err := ApplyCampaign(ctx, server, tx, campaign, principal, core.NewObject("operator", "deployment-operator"))
			if err != nil {
				return nil, err
			}
			outcomes := applied.Get("outcomes")
			if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
				"id", ID(),
				"tenantId", campaign.Get("tenantId"),
				"actorId", "deployment-operator",
				"action", "certification:auto-close",
				"resourceId", campaign.Get("id"),
				"timestamp", float64(server.Now()),
				"outcome", "allow",
				"metadata", outcomes,
			)); err != nil {
				return nil, err
			}
			return core.NewObject("tenantId", campaign.Get("tenantId"), "campaignId", campaign.Get("id"), "outcomes", outcomes), nil
		})
		if err != nil {
			return nil, err
		}
		if entry != nil {
			closed = append(closed, entry)
		}
	}
	return core.NewObject("closed", closed, "skipped", float64(skipped)), nil
}
