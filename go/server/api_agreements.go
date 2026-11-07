package server

// Port of packages/server/src/api/agreements.ts: terms of use, versioned agreements a tenant asks its members to
// accept. Policies see `principal.agreements` (names accepted in their current version) and
// `principal.pendingAgreements` (required ones still owed), so a deny statement can hold back access until people
// accept. Managing needs `iam:agreements:manage`, reporting `iam:agreements:read`; members list and accept their own
// without a permission.

import (
	"context"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// AgreementsAPI is the `agreements` API group (packages/server/src/api/agreements.ts createAgreementsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/agreements/{method} onto it.
type AgreementsAPI struct {
	server *ServerContext
}

// CreateAgreementsAPI builds the `agreements` API group.
func CreateAgreementsAPI(server *ServerContext) *AgreementsAPI {
	return &AgreementsAPI{server: server}
}

const maxAgreements = 50

// agreementBody is the agreement text: up to 50 000 characters over several lines (tabs and line breaks allowed,
// other controls not).
func agreementBody(value any) (string, error) {
	text, ok := value.(string)
	if !ok || core.JSTrim(text) == "" || utf16Len(text) > 50_000 || agreementControl(text) {
		return "", invalidInput("Invalid content")
	}
	return text, nil
}

// agreementControl is /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.
func agreementControl(text string) bool {
	for _, r := range text {
		if r <= 0x08 || r == 0x0b || r == 0x0c || (r >= 0x0e && r <= 0x1f) || r == 0x7f {
			return true
		}
	}
	return false
}

// agreementSelfSession refuses role sessions, session tokens and unknown kinds: agreements are the caller's own
// business.
func agreementSelfSession(principal *Principal, tenantID string) error {
	if !ActsInOwnRight(principal.Session) || principal.Session.Get("tenantId") != tenantID || principal.Identity.Get("tenantId") != tenantID {
		return core.NewIamError("ACCESS_DENIED", "Agreements are accepted from an ordinary session of their tenant", 403)
	}
	return nil
}

// previousMember is `previous?.[key]`.
func previousMember(previous *core.Object, key string) any {
	if previous == nil {
		return core.Undefined
	}
	return previous.Get(key)
}

// agreementFields validates an agreement input over the previous version (nil when publishing).
func agreementFields(input *core.Object, previous *core.Object) (*core.Object, error) {
	name, err := Text(coalesce(input.Get("name"), previousMember(previous, "name")), "name", 100)
	if err != nil {
		return nil, err
	}
	name = core.JSTrim(name)
	if name == "" {
		return nil, invalidInput("name is required")
	}
	content, err := agreementBody(coalesce(input.Get("content"), previousMember(previous, "content")))
	if err != nil {
		return nil, err
	}
	var url any = core.Undefined
	if rawURL := input.Get("url"); isUndefined(rawURL) {
		url = previousMember(previous, "url")
	} else if truthy(rawURL) {
		if url, err = Text(rawURL, "url", 2048); err != nil {
			return nil, err
		}
	}
	if !isUndefined(url) {
		text := jsString(url)
		if !(strings.HasPrefix(text, "http://") || strings.HasPrefix(text, "https://")) {
			return nil, invalidInput("url must be an http(s) URL")
		}
	}
	required := coalesce(coalesce(input.Get("required"), previousMember(previous, "required")), true)
	if _, ok := required.(bool); !ok {
		return nil, invalidInput("required must be a boolean")
	}
	var reaccept any
	switch raw := input.Get("reacceptAfterDays"); {
	case isUndefined(raw):
		reaccept = previousMember(previous, "reacceptAfterDays")
	case raw == nil:
		reaccept = core.Undefined
	default:
		if reaccept, err = Integer(raw, "reacceptAfterDays", 1, 3650); err != nil {
			return nil, err
		}
	}
	values := core.NewObject("uniqueKey", "name:"+core.JSLower(name), "name", name, "content", content)
	if truthy(url) {
		values.Set("url", url)
	}
	values.Set("required", required)
	if !isUndefined(reaccept) {
		values.Set("reacceptAfterDays", reaccept)
	}
	return values, nil
}

// SaveAgreement (api/agreements.ts saveAgreement): Publishes (without `previous`) or edits an agreement after
// validating it; `newVersion` asks everyone to accept again. Shared by the `agreements` API and configuration apply.
func SaveAgreement(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, input *core.Object, previous *core.Object, newVersion bool) (result *core.Object, err error) {
	if input == nil {
		input = core.NewObject()
	}
	values, err := agreementFields(input, previous)
	if err != nil {
		return nil, err
	}
	all, err := tx.Find(ctx, "agreements", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	previousID := previousMember(previous, "id")
	var others []*core.Object
	for _, agreement := range all {
		if agreement.Get("id") != previousID {
			others = append(others, agreement)
		}
	}
	for _, agreement := range others {
		if agreement.Get("uniqueKey") == values.Get("uniqueKey") {
			return nil, core.NewIamError("CONFLICT", "An agreement with this name exists", 409)
		}
	}
	now := float64(server.Now())
	if previous != nil {
		kept := previous.Spread()
		kept.Delete("url")
		kept.Delete("reacceptAfterDays")
		version := jsNumber(previous.Get("version"))
		if newVersion {
			version++
		}
		record := kept.Assign(values)
		record.Set("version", version)
		record.Set("updatedAt", now)
		return tx.Put(ctx, "agreements", record)
	}
	if len(others) >= maxAgreements {
		return nil, core.NewIamError("LIMIT_EXCEEDED", "At most 50 agreements", 409)
	}
	record := values.Spread()
	record.Set("id", ID())
	record.Set("tenantId", tenantID)
	record.Set("version", 1.0)
	record.Set("createdAt", now)
	record.Set("updatedAt", now)
	return tx.Insert(ctx, "agreements", record)
}

// DeleteAgreement (api/agreements.ts deleteAgreement): Deletes an agreement with every acceptance of it.
func DeleteAgreement(ctx context.Context, tx core.IamStore, agreement *core.Object) (err error) {
	acceptances, err := tx.Find(ctx, "agreementAcceptances", core.NewObject("tenantId", agreement.Get("tenantId"), "agreementId", agreement.Get("id")), nil)
	if err != nil {
		return err
	}
	for _, acceptance := range acceptances {
		if err := tx.Delete(ctx, "agreementAcceptances", jsString(acceptance.Get("id"))); err != nil {
			return err
		}
	}
	return tx.Delete(ctx, "agreements", jsString(agreement.Get("id")))
}

// Accept is POST {basePath}/agreements/accept. Records that the caller accepts `version` of an agreement (which must
// be the current one, so nobody accepts text they were not shown). Impersonating administrators cannot accept on
// someone's behalf. Audited as `agreement:accept`.
func (api *AgreementsAPI) Accept(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgreementsAcceptInput]) (Out[apitypes.AgreementsAcceptOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.AgreementsAcceptOutput]{}, err
	}
	agreementID, err := Text(input.Get("agreementId"), "agreementId")
	if err != nil {
		return Out[apitypes.AgreementsAcceptOutput]{}, err
	}
	version, err := Integer(input.Get("version"), "version", 1, 1_000_000)
	if err != nil {
		return Out[apitypes.AgreementsAcceptOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.AgreementsAcceptOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if err := agreementSelfSession(principal, tenantID); err != nil {
			return nil, err
		}
		if truthy(principal.Session.Get("impersonatorId")) {
			return nil, core.NewIamError("IMPERSONATION_RESTRICTED", "Agreements cannot be accepted while impersonating", 403)
		}
		if principal.Identity.Get("kind") != "user" {
			return nil, invalidInput("Only people accept agreements")
		}
		agreement, err := server.Scoped(ctx, tx, "agreements", agreementID, tenantID)
		if err != nil {
			return nil, err
		}
		if agreement.Get("version") != version {
			return nil, core.NewIamError("VERSION_CONFLICT", "The agreement changed; review the current version before accepting", 409)
		}
		identityID := principal.Identity.Get("id")
		acceptance := core.NewObject(
			"id", jsString(agreement.Get("id"))+":"+jsString(identityID),
			"tenantId", tenantID,
			"agreementId", agreement.Get("id"),
			"identityId", identityID,
			"version", version,
			"acceptedAt", float64(server.Now()),
		)
		existing, err := tx.Get(ctx, "agreementAcceptances", jsString(acceptance.Get("id")))
		if err != nil {
			return nil, err
		}
		if existing != nil {
			_, err = tx.Put(ctx, "agreementAcceptances", acceptance)
		} else {
			_, err = tx.Insert(ctx, "agreementAcceptances", acceptance)
		}
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "agreement:accept", tenantID, jsString(agreement.Get("id")), "allow", false,
			core.NewObject("name", agreement.Get("name"), "version", version)); err != nil {
			return nil, err
		}
		return core.NewObject("accepted", true, "version", version, "acceptedAt", acceptance.Get("acceptedAt")), nil
	})
	return Out[apitypes.AgreementsAcceptOutput]{Value: result}, err
}

// Create is POST {basePath}/agreements/create. Publishes a new agreement at version 1, required by default.
func (api *AgreementsAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgreementsCreateInput]) (Out[apitypes.AgreementsCreateOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:agreements:manage", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return SaveAgreement(ctx, api.server, call.Tx, jsString(call.Tenant.Get("id")), input.Body, nil, false)
	}, false)
	return Out[apitypes.AgreementsCreateOutput]{Value: result}, err
}

// Delete is POST {basePath}/agreements/delete. Deletes an agreement together with every acceptance of it.
func (api *AgreementsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgreementsDeleteInput]) (Out[apitypes.AgreementsDeleteOutput], error) {
	resourceID, err := Text(input.Get("agreementId"), "agreementId")
	if err != nil {
		return Out[apitypes.AgreementsDeleteOutput]{}, err
	}
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:agreements:manage", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		agreement, err := api.server.Scoped(ctx, call.Tx, "agreements", input.Get("agreementId"), jsString(call.Tenant.Get("id")))
		if err != nil {
			return nil, err
		}
		if err := DeleteAgreement(ctx, call.Tx, agreement); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	return Out[apitypes.AgreementsDeleteOutput]{Value: result}, err
}

// List is POST {basePath}/agreements/list. Lists the tenant's agreements by name, with their full text, version, and settings.
func (api *AgreementsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgreementsListInput]) (Out[apitypes.AgreementsListOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:agreements:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		agreements, err := call.Tx.Find(ctx, "agreements", core.NewObject("tenantId", call.Tenant.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(agreements, func(i, j int) bool {
			return localeCompare(jsString(agreements[i].Get("name")), jsString(agreements[j].Get("name"))) < 0
		})
		return certRecordList(agreements), nil
	}, false)
	return Out[apitypes.AgreementsListOutput]{Value: result}, err
}

// ListMine is POST {basePath}/agreements/listMine. Returns every agreement of the tenant with the text and whether
// the caller has accepted its current version; needs only an ordinary session of the tenant.
func (api *AgreementsAPI) ListMine(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgreementsListMineInput]) (Out[apitypes.AgreementsListMineOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.AgreementsListMineOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.AgreementsListMineOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]any, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if err := agreementSelfSession(principal, tenantID); err != nil {
			return nil, err
		}
		found, err := tx.Find(ctx, "agreementAcceptances", core.NewObject("tenantId", tenantID, "identityId", principal.Identity.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		acceptances := map[string]*core.Object{}
		for _, acceptance := range found {
			acceptances[jsString(acceptance.Get("agreementId"))] = acceptance
		}
		now := server.Now()
		agreements, err := tx.Find(ctx, "agreements", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		mine := make([]*core.Object, 0, len(agreements))
		for _, agreement := range agreements {
			acceptance := acceptances[jsString(agreement.Get("id"))]
			entry := core.NewObject("id", agreement.Get("id"), "name", agreement.Get("name"), "content", agreement.Get("content"))
			if url := agreement.Get("url"); truthy(url) {
				entry.Set("url", url)
			}
			entry.Set("version", agreement.Get("version"))
			entry.Set("required", agreement.Get("required"))
			entry.Set("accepted", AcceptanceCurrent(agreement, acceptance, now))
			if acceptance != nil {
				entry.Set("acceptedAt", acceptance.Get("acceptedAt"))
				entry.Set("acceptedVersion", acceptance.Get("version"))
			}
			mine = append(mine, entry)
		}
		sort.SliceStable(mine, func(i, j int) bool {
			a, b := mine[i], mine[j]
			if difference := jsNumber(a.Get("accepted")) - jsNumber(b.Get("accepted")); difference != 0 {
				return difference < 0
			}
			if difference := jsNumber(b.Get("required")) - jsNumber(a.Get("required")); difference != 0 {
				return difference < 0
			}
			return localeCompare(jsString(a.Get("name")), jsString(b.Get("name"))) < 0
		})
		return certRecordList(mine), nil
	})
	return Out[apitypes.AgreementsListMineOutput]{Value: result}, err
}

// Status is POST {basePath}/agreements/status. Reports who accepted an agreement's current version and which active people still owe it.
func (api *AgreementsAPI) Status(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgreementsStatusInput]) (Out[apitypes.AgreementsStatusOutput], error) {
	server := api.server
	resourceID, err := Text(input.Get("agreementId"), "agreementId")
	if err != nil {
		return Out[apitypes.AgreementsStatusOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:agreements:read", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenantID := call.Tx, jsString(call.Tenant.Get("id"))
		agreement, err := server.Scoped(ctx, tx, "agreements", input.Get("agreementId"), tenantID)
		if err != nil {
			return nil, err
		}
		found, err := tx.Find(ctx, "agreementAcceptances", core.NewObject("tenantId", tenantID, "agreementId", agreement.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		acceptances := map[string]*core.Object{}
		for _, acceptance := range found {
			acceptances[jsString(acceptance.Get("identityId"))] = acceptance
		}
		now := server.Now()
		accepted, pending := []any{}, []any{}
		identities, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		var people []*core.Object
		for _, identity := range identities {
			if identity.Get("kind") == "user" && identity.Get("status") == "active" {
				people = append(people, identity)
			}
		}
		label := func(identity *core.Object) any { return coalesce(identity.Get("email"), identity.Get("name")) }
		sort.SliceStable(people, func(i, j int) bool {
			return localeCompare(jsString(label(people[i])), jsString(label(people[j]))) < 0
		})
		for _, identity := range people {
			ref := core.NewObject("id", identity.Get("id"), "name", label(identity))
			acceptance := acceptances[jsString(identity.Get("id"))]
			if AcceptanceCurrent(agreement, acceptance, now) {
				accepted = append(accepted, core.NewObject("identity", ref, "version", acceptance.Get("version"), "acceptedAt", acceptance.Get("acceptedAt")))
			} else {
				entry := core.NewObject("identity", ref)
				if acceptance != nil {
					entry.Set("acceptedVersion", acceptance.Get("version"))
				}
				pending = append(pending, entry)
			}
		}
		return core.NewObject(
			"agreement", core.NewObject("id", agreement.Get("id"), "name", agreement.Get("name"), "version", agreement.Get("version"), "required", agreement.Get("required")),
			"accepted", accepted,
			"pending", pending,
		), nil
	}, false)
	return Out[apitypes.AgreementsStatusOutput]{Value: result}, err
}

// Update is POST {basePath}/agreements/update. Edits an agreement. `newVersion: true` publishes the change as the
// next version, so everyone must accept again; without it the edit (a typo fix, a new link) keeps existing
// acceptances valid.
func (api *AgreementsAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.AgreementsUpdateInput]) (Out[apitypes.AgreementsUpdateOutput], error) {
	resourceID, err := Text(input.Get("agreementId"), "agreementId")
	if err != nil {
		return Out[apitypes.AgreementsUpdateOutput]{}, err
	}
	result, err := Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:agreements:manage", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tenantID := jsString(call.Tenant.Get("id"))
		previous, err := api.server.Scoped(ctx, call.Tx, "agreements", input.Get("agreementId"), tenantID)
		if err != nil {
			return nil, err
		}
		return SaveAgreement(ctx, api.server, call.Tx, tenantID, input.Body, previous, input.Get("newVersion") == true)
	}, false)
	return Out[apitypes.AgreementsUpdateOutput]{Value: result}, err
}
