package server

// Port of packages/server/src/api/certifications.ts: access certification campaigns. An administrator snapshots the
// tenant's role bindings (optionally for some roles or subject types); designated reviewers — or, in manager mode,
// each person's manager — keep or revoke each one, never their own access, and closing the campaign removes the
// revoked bindings under the closer's grant authority. Bindings the closer may not remove are reported as
// `revocation-failed` for a higher administrator instead of being forced.

import (
	"context"
	"sort"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// CertificationsAPI is the `certifications` API group (packages/server/src/api/certifications.ts createCertificationsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/certifications/{method} onto it.
type CertificationsAPI struct {
	server *ServerContext
}

// CreateCertificationsAPI builds the `certifications` API group.
func CreateCertificationsAPI(server *ServerContext) *CertificationsAPI {
	return &CertificationsAPI{server: server}
}

const maxCertificationItems = 5000

// certificationDecisions are the decisions a reviewer records.
var certificationDecisions = newOrderedSet("keep", "revoke")

// certificationDecision reports whether a value is a valid decision (`decisions.has(value)`).
func certificationDecision(value any) bool {
	text, ok := value.(string)
	return ok && certificationDecisions.Has(text)
}

// certRecordList is a record list as a model array.
func certRecordList(records []*core.Object) []any {
	list := make([]any, len(records))
	for index, record := range records {
		list[index] = record
	}
	return list
}

// certificationProgress is the progress of a campaign's items.
func certificationProgress(items []*core.Object) *core.Object {
	decided, keep, revoke := 0, 0, 0
	for _, item := range items {
		decision := item.Get("decision")
		if truthy(decision) {
			decided++
		}
		if decision == "keep" {
			keep++
		}
		if decision == "revoke" {
			revoke++
		}
	}
	return core.NewObject("total", float64(len(items)), "decided", float64(decided), "keep", float64(keep), "revoke", float64(revoke))
}

// byRoleAndSubject orders items by role name, subject name, then id (localeCompare each).
func byRoleAndSubject(items []*core.Object) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		for _, key := range []string{"roleName", "subjectName", "id"} {
			if order := localeCompare(jsString(a.Get(key)), jsString(b.Get(key))); order != 0 {
				return order < 0
			}
		}
		return false
	})
}

// certificationGroupsOf is the groups an identity belongs to, for the rule that nobody certifies their own access.
func certificationGroupsOf(ctx context.Context, tx core.IamStore, tenantID string, identityID any) (map[string]bool, error) {
	members, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	groups := map[string]bool{}
	for _, member := range members {
		groups[jsString(member.Get("groupId"))] = true
	}
	return groups, nil
}

// ownCertificationItem reports whether an item certifies the identity's own access, directly or through one of its
// groups.
func ownCertificationItem(item *core.Object, identityID any, groups map[string]bool) bool {
	if item.Get("subjectType") == "identity" {
		return item.Get("subjectId") == identityID
	}
	subjectID, ok := item.Get("subjectId").(string)
	return ok && groups[subjectID]
}

func selfReview() *core.IamError {
	return core.NewIamError("SELF_REVIEW", "Reviewers cannot certify their own access; ask another reviewer", 403)
}

// decidedItem is the item with a reviewer's decision (and optional note) recorded.
func decidedItem(item *core.Object, entry any, reviewerID any, now float64) (*core.Object, error) {
	updated := item.Spread(core.NewObject("decision", member(entry, "decision"), "decidedBy", reviewerID, "decidedAt", now))
	if note := member(entry, "note"); !isUndefined(note) {
		text, err := Text(note, "note", 500)
		if err != nil {
			return nil, err
		}
		updated.Set("note", core.JSTrim(text))
	} else {
		updated.Delete("note")
	}
	return updated, nil
}

// reviewLoad is the items per reviewer, in first-seen order: manager-assigned items count for their manager, the
// others for every named reviewer. Named reviewers of a manager-mode campaign are left out when nothing falls back
// to them.
type reviewLoad struct {
	order []string
	count map[string]int
}

func (l *reviewLoad) add(reviewerID string, count int) {
	if _, ok := l.count[reviewerID]; !ok {
		l.order = append(l.order, reviewerID)
	}
	l.count[reviewerID] += count
}

func certificationReviewLoad(campaign *core.Object, items []*core.Object) *reviewLoad {
	load := &reviewLoad{count: map[string]int{}}
	unassigned := 0
	for _, item := range items {
		if reviewerID := item.Get("reviewerId"); truthy(reviewerID) {
			load.add(jsString(reviewerID), 1)
		} else {
			unassigned++
		}
	}
	if unassigned != 0 || campaign.Get("reviewerMode") != "manager" {
		reviewerIDs, _ := campaign.Get("reviewerIds").([]any)
		for _, reviewerID := range reviewerIDs {
			load.add(jsString(reviewerID), unassigned)
		}
	}
	return load
}

// requireTenantSession rejects credentials that are not an ordinary session of the tenant (self-service reviews act
// as oneself), including role sessions, session tokens and unknown kinds.
func requireTenantSession(principal *Principal, tenantID string) error {
	if !ActsInOwnRight(principal.Session) || principal.Session.Get("tenantId") != tenantID {
		return core.NewIamError("ACCESS_DENIED", "Reviews are made from an ordinary session of the campaign tenant", 403)
	}
	return nil
}

// ApplyCampaign (api/certifications.ts applyCampaign): Applies an open campaign and closes it inside the caller's
// transaction: revoked (and, with `undecided: 'revoke'`, undecided) bindings are removed under the principal's grant
// authority, and each item records its outcome. Bindings the principal may not remove are reported as
// `revocation-failed`; without a principal (the creator of an auto-closing campaign no longer exists) every
// revocation is. options.operator (a deployment actor such as `deployment-operator`) is recorded as `closedBy` and
// as the actor of each revocation's `iam:bindings:delete` event (with the campaign ID) instead of the principal.
func ApplyCampaign(ctx context.Context, server *ServerContext, tx core.IamStore, campaign *core.Object, principal *Principal, options *core.Object) (result *core.Object, err error) {
	operator := member(options, "operator")
	closedBy := operator
	if nullish(closedBy) {
		closedBy = core.Undefined
		if principal != nil {
			closedBy = principal.Identity.Get("id")
		}
	}
	if isUndefined(closedBy) {
		return nil, invalidInput("Closing a campaign needs a principal or an operator")
	}
	tenantID := jsString(campaign.Get("tenantId"))
	outcomes := core.NewObject("kept", 0.0, "revoked", 0.0, "already-removed", 0.0, "revocation-failed", 0.0)
	items, err := tx.Find(ctx, "certificationItems", core.NewObject("tenantId", tenantID, "campaignId", campaign.Get("id")), nil)
	if err != nil {
		return nil, err
	}
	for _, item := range items {
		decision := coalesce(item.Get("decision"), campaign.Get("undecided"))
		binding, err := tx.Get(ctx, "bindings", jsString(item.Get("bindingId")))
		if err != nil {
			return nil, err
		}
		var outcome, detail string
		switch {
		case binding == nil || binding.Get("tenantId") != tenantID || binding.Get("roleId") != item.Get("roleId") || binding.Get("subjectId") != item.Get("subjectId"):
			if decision == "revoke" {
				outcome = "already-removed"
			} else {
				outcome = "kept"
			}
		case decision == "keep":
			outcome = "kept"
		case principal == nil:
			outcome = "revocation-failed"
			detail = "The campaign creator no longer exists, so nothing is revoked under their authority"
		default:
			outcome, detail, err = revokeCertifiedBinding(ctx, server, tx, campaign, principal, binding, operator, tenantID)
			if err != nil {
				return nil, err
			}
		}
		outcomes.Set(outcome, jsNumber(outcomes.Get(outcome))+1)
		updated := item.Spread(core.NewObject("outcome", outcome))
		if detail != "" {
			updated.Set("outcomeDetail", detail)
		}
		if _, err := tx.Put(ctx, "certificationItems", updated); err != nil {
			return nil, err
		}
	}
	closed, err := tx.Put(ctx, "certificationCampaigns", campaign.Spread(core.NewObject(
		"status", "closed", "closedAt", float64(server.Now()), "closedBy", closedBy,
	)))
	if err != nil {
		return nil, err
	}
	return closed.Spread(core.NewObject("outcomes", outcomes)), nil
}

// revokeCertifiedBinding removes a revoked binding under the principal's grant authority. A refusal (an IamError) is
// the `revocation-failed` outcome with its message; deleteBinding validates before it writes, so a refusal leaves
// nothing half-done.
func revokeCertifiedBinding(ctx context.Context, server *ServerContext, tx core.IamStore, campaign *core.Object, principal *Principal, binding *core.Object, operator any, tenantID string) (outcome, detail string, err error) {
	bindingID := jsString(binding.Get("id"))
	err = DeleteBinding(ctx, server, tx, principal, binding)
	if err == nil {
		if !isUndefined(operator) {
			err = server.Events.RecordAudit(ctx, tx, core.NewObject(
				"id", ID(),
				"tenantId", tenantID,
				"actorId", operator,
				"action", "iam:bindings:delete",
				"resourceId", bindingID,
				"timestamp", float64(server.Now()),
				"outcome", "allow",
				"metadata", core.NewObject("campaignId", campaign.Get("id")),
			))
		} else {
			err = server.Events.Audit(ctx, tx, principal, "iam:bindings:delete", tenantID, bindingID, "allow", false, nil)
		}
	}
	if err == nil {
		return "revoked", "", nil
	}
	known, ok := asIamError(err)
	// A module still being ported answers NOT_IMPLEMENTED, which TypeScript never throws: it surfaces instead of
	// reading as a refusal.
	if !ok || known.Code == "NOT_IMPLEMENTED" {
		return "", "", err
	}
	return "revocation-failed", known.Message, nil
}

// campaignOf is the tenant's campaign (NOT_FOUND otherwise).
func (api *CertificationsAPI) campaignOf(ctx context.Context, tx core.IamStore, tenantID string, campaignID any) (*core.Object, error) {
	id, err := Text(campaignID, "campaignId")
	if err != nil {
		return nil, err
	}
	return api.server.Scoped(ctx, tx, "certificationCampaigns", id, tenantID)
}

func certificationItemsOf(ctx context.Context, tx core.IamStore, tenantID string, campaignID any) ([]*core.Object, error) {
	return tx.Find(ctx, "certificationItems", core.NewObject("tenantId", tenantID, "campaignId", campaignID), nil)
}

// certificationResource is `certifications/${text(campaignId, 'campaignId')}`, the resource of a campaign operation.
func certificationResource(campaignID any) (string, error) {
	id, err := Text(campaignID, "campaignId")
	if err != nil {
		return "", err
	}
	return "certifications/" + id, nil
}

// sendsEmail is `ctx.options.authentication?.sendEmail`.
func (api *CertificationsAPI) sendsEmail() bool {
	options := api.server.Options
	return options != nil && options.Authentication != nil && options.Authentication.SendEmail != nil
}

// Close is POST {basePath}/certifications/close. Closes the campaign and applies it: revoked (and, with
// `undecided: 'revoke'`, undecided) bindings are removed under the caller's grant authority; each item records its
// outcome. Requires iam:certifications:manage and recent authentication.
func (api *CertificationsAPI) Close(ctx context.Context, credential core.CredentialInput, input In[apitypes.CertificationsCloseInput]) (Out[apitypes.CertificationsCloseOutput], error) {
	server := api.server
	resource, err := certificationResource(input.Get("campaignId"))
	if err != nil {
		return Out[apitypes.CertificationsCloseOutput]{}, err
	}
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:certifications:manage", resource, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		if err := server.Auth.RequireRecent(call.Principal.Auth()); err != nil {
			return nil, err
		}
		campaign, err := api.campaignOf(ctx, call.Tx, jsString(rawTenantID), input.Get("campaignId"))
		if err != nil {
			return nil, err
		}
		if campaign.Get("status") != "open" {
			return nil, core.NewIamError("CONFLICT", "The campaign is already closed", 409)
		}
		return ApplyCampaign(ctx, server, call.Tx, campaign, call.Principal, nil)
	}, false)
	return Out[apitypes.CertificationsCloseOutput]{Value: result}, err
}

// Create is POST {basePath}/certifications/create. Opens a campaign over the current bindings.
// `reviewerMode: 'manager'` assigns each person's items to their active manager, the rest to the named reviewers;
// `autoClose` (which needs `dueAt`) lets the deployment worker close it when due. When email delivery is configured,
// each reviewer is emailed (`certification-review`) with their item count. Requires iam:certifications:manage.
func (api *CertificationsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.CertificationsCreateInput]) (Out[apitypes.CertificationsCreateOutput], error) {
	server := api.server
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:certifications:manage", "certifications/*", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(rawTenantID)
		name, err := Text(input.Get("name"), "name", 200)
		if err != nil {
			return nil, err
		}
		name = core.JSTrim(name)
		subjectType := input.Get("subjectType")
		if !isUndefined(subjectType) && subjectType != "identity" && subjectType != "group" {
			return nil, invalidInput("subjectType must be identity or group")
		}
		reviewerMode := coalesce(input.Get("reviewerMode"), "named")
		if reviewerMode != "named" && reviewerMode != "manager" {
			return nil, invalidInput("reviewerMode must be named or manager")
		}
		undecided := coalesce(input.Get("undecided"), "keep")
		if !certificationDecision(undecided) {
			return nil, invalidInput("undecided must be keep or revoke")
		}
		now := float64(server.Now())
		dueAt := input.Get("dueAt")
		if !isUndefined(dueAt) {
			if due, ok := dueAt.(float64); !ok || !core.IsSafeInteger(due) || due <= now {
				return nil, invalidInput("dueAt must be a future timestamp in milliseconds")
			}
		}
		autoClose := input.Get("autoClose")
		if _, ok := autoClose.(bool); !isUndefined(autoClose) && !ok {
			return nil, invalidInput("autoClose must be boolean")
		}
		if truthy(autoClose) && isUndefined(dueAt) {
			return nil, invalidInput("autoClose requires dueAt")
		}
		var roleIDs []string
		restricted := !isUndefined(input.Get("roleIds"))
		if restricted {
			requested, err := Strings(input.Get("roleIds"), "roleIds")
			if err != nil {
				return nil, err
			}
			roleIDs = unique(requested)
		}
		roleList, err := tx.Find(ctx, "roles", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		roles := map[string]*core.Object{}
		for _, role := range roleList {
			roles[jsString(role.Get("id"))] = role
		}
		for _, roleID := range roleIDs {
			if role, ok := roles[roleID]; !ok || truthy(role.Get("protected")) {
				return nil, invalidInput("Role " + roleID + " cannot be certified")
			}
		}
		requestedReviewers, err := Strings(coalesce(input.Get("reviewerIds"), []any{}), "reviewerIds")
		if err != nil {
			return nil, err
		}
		reviewerIDs := unique(requestedReviewers)
		for _, reviewerID := range reviewerIDs {
			if _, err := server.ActiveIdentity(ctx, tx, reviewerID, tenantID); err != nil {
				return nil, err
			}
		}

		allBindings, err := tx.Find(ctx, "bindings", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		var bindings []*core.Object
		for _, binding := range allBindings {
			roleID, _ := binding.Get("roleId").(string)
			role, known := roles[roleID]
			if server.LiveBinding(binding) && known && !truthy(role.Get("protected")) &&
				(!restricted || containsString(roleIDs, roleID)) &&
				(!truthy(subjectType) || binding.Get("subjectType") == subjectType) {
				bindings = append(bindings, binding)
			}
		}
		if len(bindings) > maxCertificationItems {
			return nil, core.NewIamError("LIMIT_EXCEEDED", "A campaign covers at most 5000 bindings; narrow it by role or subject type", 409)
		}
		campaign := core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"name", name,
			"status", "open",
			"createdBy", principal.Identity.Get("id"),
			"createdAt", now,
			"reviewerIds", stringsOf(reviewerIDs),
			"reviewerMode", reviewerMode,
			"undecided", undecided,
		)
		if !isUndefined(dueAt) {
			campaign.Set("dueAt", dueAt)
		}
		if truthy(autoClose) {
			campaign.Set("autoClose", true)
		}
		if restricted {
			campaign.Set("roleIds", stringsOf(roleIDs))
		}
		if truthy(subjectType) {
			campaign.Set("subjectType", subjectType)
		}
		if _, err := tx.Insert(ctx, "certificationCampaigns", campaign); err != nil {
			return nil, err
		}
		// Manager mode: a person's reviewer is their manager while that manager is an active member of the tenant.
		managers := map[string]bool{}
		reviewerFor := func(subject *core.Object) (string, error) {
			if reviewerMode != "manager" || subject == nil || !truthy(subject.Get("managerId")) || subject.Get("managerId") == subject.Get("id") {
				return "", nil
			}
			managerID := jsString(subject.Get("managerId"))
			if _, cached := managers[managerID]; !cached {
				manager, err := tx.Get(ctx, "identities", managerID)
				if err != nil {
					return "", err
				}
				managers[managerID] = manager != nil && manager.Get("tenantId") == tenantID && manager.Get("status") == "active" && !server.IdentityExpired(manager)
			}
			if managers[managerID] {
				return managerID, nil
			}
			return "", nil
		}
		items := make([]*core.Object, 0, len(bindings))
		for _, binding := range bindings {
			collection := "groups"
			if binding.Get("subjectType") == "identity" {
				collection = "identities"
			}
			subject, err := tx.Get(ctx, collection, jsString(binding.Get("subjectId")))
			if err != nil {
				return nil, err
			}
			subjectName := binding.Get("subjectId")
			if subject != nil {
				subjectName = coalesce(coalesce(subject.Get("email"), subject.Get("name")), subjectName)
			}
			item := core.NewObject(
				"id", ID(),
				"tenantId", tenantID,
				"campaignId", campaign.Get("id"),
				"bindingId", binding.Get("id"),
				"roleId", binding.Get("roleId"),
				"roleName", roles[jsString(binding.Get("roleId"))].Get("name"),
				"subjectType", binding.Get("subjectType"),
				"subjectId", binding.Get("subjectId"),
				"subjectName", subjectName,
			)
			if expiresAt := binding.Get("expiresAt"); !isUndefined(expiresAt) {
				item.Set("bindingExpiresAt", expiresAt)
			}
			if truthy(binding.Get("eligible")) {
				item.Set("eligible", true)
			}
			if binding.Get("subjectType") == "identity" {
				reviewerID, err := reviewerFor(subject)
				if err != nil {
					return nil, err
				}
				if reviewerID != "" {
					item.Set("reviewerId", reviewerID)
				}
			}
			if _, err := tx.Insert(ctx, "certificationItems", item); err != nil {
				return nil, err
			}
			items = append(items, item)
		}
		// Reviewers hear about the campaign through the outbox, in the same transaction.
		if api.sendsEmail() {
			load := certificationReviewLoad(campaign, items)
			for _, reviewerID := range load.order {
				reviewer, err := tx.Get(ctx, "identities", reviewerID)
				if err != nil {
					return nil, err
				}
				if reviewer == nil || !truthy(reviewer.Get("email")) {
					continue
				}
				payload := core.NewObject("campaignId", campaign.Get("id"), "campaignName", name, "items", core.NumberString(float64(load.count[reviewerID])))
				if due := campaign.Get("dueAt"); truthy(due) {
					payload.Set("dueAt", isoString(jsNumber(due)))
				}
				if _, err := server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
					TenantID: tenantID, Kind: "email", To: jsString(reviewer.Get("email")), Template: "certification-review", Payload: payload,
				}); err != nil {
					return nil, err
				}
			}
		}
		return campaign.Spread(core.NewObject("progress", certificationProgress(nil), "items", float64(len(bindings)))), nil
	}, false)
	return Out[apitypes.CertificationsCreateOutput]{Value: result}, err
}

// Decide is POST {basePath}/certifications/decide. Records keep/revoke decisions (at most 200 per call). Reviewers
// must be listed on the campaign when it names reviewers, and nobody decides on their own access, directly or
// through a group. In manager mode an item assigned to a manager is theirs to decide, though holders of
// iam:certifications:manage may decide it too. Requires iam:certifications:review on the campaign. A role session
// holding it may decide (the decision records its source identity); a session token (a derived copy of the
// reviewer's own credential) and an impersonation session never do.
func (api *CertificationsAPI) Decide(ctx context.Context, credential core.CredentialInput, input In[apitypes.CertificationsDecideInput]) (Out[apitypes.CertificationsDecideOutput], error) {
	server := api.server
	resource, err := certificationResource(input.Get("campaignId"))
	if err != nil {
		return Out[apitypes.CertificationsDecideOutput]{}, err
	}
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:certifications:review", resource, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(rawTenantID)
		// A decision is recorded in the reviewer's name. An administrator impersonating a member never records one
		// for them, and neither does a session token or any other derived kind but an assumed role, which is an
		// explicit, audited delegation that has always been able to review with the permission.
		if truthy(principal.Session.Get("impersonatorId")) {
			return nil, core.NewIamError("IMPERSONATION_RESTRICTED", "Access cannot be reviewed while impersonating", 403)
		}
		if !ActsInOwnRight(principal.Session) && principal.Session.Get("kind") != "role" {
			return nil, core.NewIamError("ACCESS_DENIED", "Reviews are made from an ordinary session of the campaign tenant", 403)
		}
		campaign, err := api.campaignOf(ctx, tx, tenantID, input.Get("campaignId"))
		if err != nil {
			return nil, err
		}
		if campaign.Get("status") != "open" {
			return nil, core.NewIamError("CONFLICT", "The campaign is closed", 409)
		}
		identityID := principal.Identity.Get("id")
		reviewerIDs, _ := campaign.Get("reviewerIds").([]any)
		named := len(reviewerIDs) == 0
		for _, reviewerID := range reviewerIDs {
			if reviewerID == identityID {
				named = true
				break
			}
		}
		if !named && campaign.Get("reviewerMode") != "manager" {
			return nil, core.NewIamError("ACCESS_DENIED", "You are not a reviewer of this campaign", 403)
		}
		entries, ok := input.Get("decisions").([]any)
		if !ok || len(entries) == 0 || len(entries) > 200 {
			return nil, invalidInput("decisions must contain 1 to 200 entries")
		}
		memberOf, err := certificationGroupsOf(ctx, tx, tenantID, identityID)
		if err != nil {
			return nil, err
		}
		var manages *bool
		mayManage := func() (bool, error) {
			if manages == nil {
				decision, err := server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
					TenantID: tenantID, Action: "iam:certifications:manage",
					Resource: ResourceTarget{Type: "iam", ID: "certifications/" + jsString(campaign.Get("id"))},
				}, true)
				if err != nil {
					return false, err
				}
				manages = &decision.Allowed
			}
			return *manages, nil
		}
		now := float64(server.Now())
		recorded := 0
		for _, entry := range entries {
			if nullish(entry) {
				return nil, &core.TypeError{Message: "Cannot read properties of " + jsString(entry) + " (reading 'itemId')"}
			}
			itemID, err := Text(member(entry, "itemId"), "itemId")
			if err != nil {
				return nil, err
			}
			item, err := server.Scoped(ctx, tx, "certificationItems", itemID, tenantID)
			if err != nil {
				return nil, err
			}
			if item.Get("campaignId") != campaign.Get("id") {
				return nil, core.NewIamError("NOT_FOUND", "Item not found", 404)
			}
			if !certificationDecision(member(entry, "decision")) {
				return nil, invalidInput("decision must be keep or revoke")
			}
			if ownCertificationItem(item, identityID, memberOf) {
				return nil, selfReview()
			}
			if reviewerID := item.Get("reviewerId"); !isUndefined(reviewerID) {
				if reviewerID != identityID {
					allowed, err := mayManage()
					if err != nil {
						return nil, err
					}
					if !allowed {
						return nil, core.NewIamError("ACCESS_DENIED", "This item is assigned to the person's manager", 403)
					}
				}
			} else if !named {
				return nil, core.NewIamError("ACCESS_DENIED", "You are not a reviewer of this campaign", 403)
			}
			updated, err := decidedItem(item, entry, identityID, now)
			if err != nil {
				return nil, err
			}
			if _, err := tx.Put(ctx, "certificationItems", updated); err != nil {
				return nil, err
			}
			recorded++
		}
		return core.NewObject("recorded", float64(recorded)), nil
	}, false)
	return Out[apitypes.CertificationsDecideOutput]{Value: result}, err
}

// Delete is POST {basePath}/certifications/delete. Deletes a closed campaign and its items. Requires
// iam:certifications:manage.
func (api *CertificationsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.CertificationsDeleteInput]) (Out[apitypes.CertificationsDeleteOutput], error) {
	resource, err := certificationResource(input.Get("campaignId"))
	if err != nil {
		return Out[apitypes.CertificationsDeleteOutput]{}, err
	}
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, rawTenantID, "iam:certifications:manage", resource, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tenantID := jsString(rawTenantID)
		campaign, err := api.campaignOf(ctx, call.Tx, tenantID, input.Get("campaignId"))
		if err != nil {
			return nil, err
		}
		if campaign.Get("status") != "closed" {
			return nil, core.NewIamError("CONFLICT", "Close the campaign before deleting it", 409)
		}
		items, err := certificationItemsOf(ctx, call.Tx, tenantID, campaign.Get("id"))
		if err != nil {
			return nil, err
		}
		for _, item := range items {
			if err := call.Tx.Delete(ctx, "certificationItems", jsString(item.Get("id"))); err != nil {
				return nil, err
			}
		}
		if err := call.Tx.Delete(ctx, "certificationCampaigns", jsString(campaign.Get("id"))); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	return Out[apitypes.CertificationsDeleteOutput]{Value: result}, err
}

// Get is POST {basePath}/certifications/get. One campaign and its items; `mine` limits items to those the caller may
// decide.
func (api *CertificationsAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.CertificationsGetInput]) (Out[apitypes.CertificationsGetOutput], error) {
	resource, err := certificationResource(input.Get("campaignId"))
	if err != nil {
		return Out[apitypes.CertificationsGetOutput]{}, err
	}
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, rawTenantID, "iam:certifications:read", resource, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tenantID := jsString(rawTenantID)
		campaign, err := api.campaignOf(ctx, call.Tx, tenantID, input.Get("campaignId"))
		if err != nil {
			return nil, err
		}
		items, err := certificationItemsOf(ctx, call.Tx, tenantID, campaign.Get("id"))
		if err != nil {
			return nil, err
		}
		identityID := call.Principal.Identity.Get("id")
		memberOf, err := certificationGroupsOf(ctx, call.Tx, tenantID, identityID)
		if err != nil {
			return nil, err
		}
		mine := truthy(input.Get("mine"))
		visible := make([]*core.Object, 0, len(items))
		for _, item := range items {
			if !mine || !ownCertificationItem(item, identityID, memberOf) {
				visible = append(visible, item)
			}
		}
		byRoleAndSubject(visible)
		return campaign.Spread(core.NewObject("progress", certificationProgress(items), "items", certRecordList(visible))), nil
	}, false)
	return Out[apitypes.CertificationsGetOutput]{Value: result}, err
}

// List is POST {basePath}/certifications/list. Campaigns with their progress, newest first. Requires
// iam:certifications:read.
func (api *CertificationsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.CertificationsListInput]) (Out[apitypes.CertificationsListOutput], error) {
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, rawTenantID, "iam:certifications:read", "certifications/*", func(ctx context.Context, call MutationContext) ([]any, error) {
		filter := core.NewObject("tenantId", rawTenantID)
		if status := input.Get("status"); truthy(status) {
			filter.Set("status", status)
		}
		campaigns, err := call.Tx.Find(ctx, "certificationCampaigns", filter, nil)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(campaigns, func(i, j int) bool { return ByNewest(campaigns[i], campaigns[j]) < 0 })
		result := []any{}
		for _, campaign := range campaigns {
			items, err := certificationItemsOf(ctx, call.Tx, jsString(rawTenantID), campaign.Get("id"))
			if err != nil {
				return nil, err
			}
			result = append(result, campaign.Spread(core.NewObject("progress", certificationProgress(items))))
		}
		return result, nil
	}, false)
	return Out[apitypes.CertificationsListOutput]{Value: result}, err
}

// ListMine is POST {basePath}/certifications/listMine. The caller's review work: open campaigns with items assigned
// to them (manager mode), newest first, each with only those items and their progress. Needs no permission beyond
// an ordinary session of the tenant.
func (api *CertificationsAPI) ListMine(ctx context.Context, credential core.CredentialInput, input In[apitypes.CertificationsListMineInput]) (Out[apitypes.CertificationsListMineOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.CertificationsListMineOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.CertificationsListMineOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]any, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if err := requireTenantSession(principal, tenantID); err != nil {
			return nil, err
		}
		result := []any{}
		campaigns, err := tx.Find(ctx, "certificationCampaigns", core.NewObject("tenantId", tenantID, "status", "open"), nil)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(campaigns, func(i, j int) bool { return ByNewest(campaigns[i], campaigns[j]) < 0 })
		for _, campaign := range campaigns {
			mine, err := tx.Find(ctx, "certificationItems", core.NewObject("tenantId", tenantID, "campaignId", campaign.Get("id"), "reviewerId", principal.Identity.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			if len(mine) == 0 {
				continue
			}
			entry := core.NewObject("id", campaign.Get("id"), "name", campaign.Get("name"))
			if dueAt := campaign.Get("dueAt"); !isUndefined(dueAt) {
				entry.Set("dueAt", dueAt)
			}
			entry.Set("reviewerMode", coalesce(campaign.Get("reviewerMode"), "named"))
			byRoleAndSubject(mine)
			entry.Set("items", certRecordList(mine))
			entry.Set("progress", certificationProgress(mine))
			result = append(result, entry)
		}
		return result, nil
	})
	return Out[apitypes.CertificationsListMineOutput]{Value: result}, err
}

// Remind is POST {basePath}/certifications/remind. Emails a `certification-reminder` to every reviewer with
// undecided items: managers their assigned count, and the named reviewers the undecided items that fall back to them
// (nobody, when the campaign names no reviewers). Returns how many people were reminded and how many items are
// undecided. Requires iam:certifications:manage and an email delivery callback. Audited as `certification:remind`.
func (api *CertificationsAPI) Remind(ctx context.Context, credential core.CredentialInput, input In[apitypes.CertificationsRemindInput]) (Out[apitypes.CertificationsRemindOutput], error) {
	server := api.server
	resource, err := certificationResource(input.Get("campaignId"))
	if err != nil {
		return Out[apitypes.CertificationsRemindOutput]{}, err
	}
	rawTenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, rawTenantID, "iam:certifications:manage", resource, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		tenantID := jsString(rawTenantID)
		if !api.sendsEmail() {
			return nil, core.NewIamError("DELIVERY_REQUIRED", "Reminders require an email delivery callback")
		}
		campaign, err := api.campaignOf(ctx, tx, tenantID, input.Get("campaignId"))
		if err != nil {
			return nil, err
		}
		if campaign.Get("status") != "open" {
			return nil, core.NewIamError("CONFLICT", "The campaign is closed", 409)
		}
		items, err := certificationItemsOf(ctx, tx, tenantID, campaign.Get("id"))
		if err != nil {
			return nil, err
		}
		var undecided []*core.Object
		for _, item := range items {
			if !truthy(item.Get("decision")) {
				undecided = append(undecided, item)
			}
		}
		reminded := 0
		load := certificationReviewLoad(campaign, undecided)
		for _, reviewerID := range load.order {
			pending := load.count[reviewerID]
			if pending == 0 {
				continue
			}
			reviewer, err := tx.Get(ctx, "identities", reviewerID)
			if err != nil {
				return nil, err
			}
			if reviewer == nil || reviewer.Get("status") != "active" || !truthy(reviewer.Get("email")) {
				continue
			}
			payload := core.NewObject("campaignId", campaign.Get("id"), "campaignName", campaign.Get("name"), "pending", core.NumberString(float64(pending)))
			if due := campaign.Get("dueAt"); truthy(due) {
				payload.Set("dueAt", isoString(jsNumber(due)))
			}
			if _, err := server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
				TenantID: tenantID, Kind: "email", To: jsString(reviewer.Get("email")), Template: "certification-reminder", Payload: payload,
			}); err != nil {
				return nil, err
			}
			reminded++
		}
		if err := server.Events.Audit(ctx, tx, call.Principal, "certification:remind", tenantID, jsString(campaign.Get("id")), "allow", false,
			core.NewObject("reminded", float64(reminded), "pending", float64(len(undecided)))); err != nil {
			return nil, err
		}
		return core.NewObject("reminded", float64(reminded), "pending", float64(len(undecided))), nil
	}, false)
	return Out[apitypes.CertificationsRemindOutput]{Value: result}, err
}

// Review is POST {basePath}/certifications/review. Self-service for manager-mode reviewers: records keep/revoke
// decisions (at most 200 per call) on items assigned to the caller, without needing iam:certifications:review.
// Requires an ordinary, non-impersonated session of the tenant; nobody decides on their own access. Audited as
// `certification:review`.
func (api *CertificationsAPI) Review(ctx context.Context, credential core.CredentialInput, input In[apitypes.CertificationsReviewInput]) (Out[apitypes.CertificationsReviewOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.CertificationsReviewOutput]{}, err
	}
	campaignID, err := Text(input.Get("campaignId"), "campaignId")
	if err != nil {
		return Out[apitypes.CertificationsReviewOutput]{}, err
	}
	rawEntries, ok := input.Get("decisions").([]any)
	if !ok || len(rawEntries) == 0 || len(rawEntries) > 200 {
		return Out[apitypes.CertificationsReviewOutput]{}, invalidInput("decisions must contain 1 to 200 entries")
	}
	entries := make([]*core.Object, len(rawEntries))
	for index, raw := range rawEntries {
		// `!entry || typeof entry !== 'object'`: arrays are objects too, and carry no decision.
		var entry *core.Object
		switch value := raw.(type) {
		case *core.Object:
			entry = value
		case []any:
			entry = core.NewObject()
		}
		if entry == nil || !certificationDecision(entry.Get("decision")) {
			return Out[apitypes.CertificationsReviewOutput]{}, invalidInput("decision must be keep or revoke")
		}
		itemID, err := Text(entry.Get("itemId"), "itemId")
		if err != nil {
			return Out[apitypes.CertificationsReviewOutput]{}, err
		}
		entries[index] = entry.Spread(core.NewObject("itemId", itemID))
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.CertificationsReviewOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if err := requireTenantSession(principal, tenantID); err != nil {
			return nil, err
		}
		if truthy(principal.Session.Get("impersonatorId")) {
			return nil, core.NewIamError("IMPERSONATION_RESTRICTED", "Access cannot be reviewed while impersonating", 403)
		}
		campaign, err := api.campaignOf(ctx, tx, tenantID, campaignID)
		if err != nil {
			return nil, err
		}
		if campaign.Get("status") != "open" {
			return nil, core.NewIamError("CONFLICT", "The campaign is closed", 409)
		}
		identityID := principal.Identity.Get("id")
		memberOf, err := certificationGroupsOf(ctx, tx, tenantID, identityID)
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		counts := core.NewObject("keep", 0.0, "revoke", 0.0)
		for _, entry := range entries {
			item, err := tx.Get(ctx, "certificationItems", jsString(entry.Get("itemId")))
			if err != nil {
				return nil, err
			}
			if item == nil || item.Get("tenantId") != tenantID || item.Get("campaignId") != campaign.Get("id") || item.Get("reviewerId") != identityID {
				return nil, core.NewIamError("ACCESS_DENIED", "This item is not assigned to you", 403)
			}
			if ownCertificationItem(item, identityID, memberOf) {
				return nil, selfReview()
			}
			updated, err := decidedItem(item, entry, identityID, now)
			if err != nil {
				return nil, err
			}
			if _, err := tx.Put(ctx, "certificationItems", updated); err != nil {
				return nil, err
			}
			decision := jsString(entry.Get("decision"))
			counts.Set(decision, jsNumber(counts.Get(decision))+1)
		}
		metadata := core.NewObject("recorded", float64(len(entries))).Assign(counts)
		if err := server.Events.Audit(ctx, tx, principal, "certification:review", tenantID, jsString(campaign.Get("id")), "allow", false, metadata); err != nil {
			return nil, err
		}
		return core.NewObject("recorded", float64(len(entries))), nil
	})
	return Out[apitypes.CertificationsReviewOutput]{Value: result}, err
}
