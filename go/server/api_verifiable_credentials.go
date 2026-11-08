package server

// Port of packages/server/src/api/verifiable-credentials.ts: the `verifiableCredentials` API group (credential types
// (`iam:vc:manage`), issued credentials and their status (`iam:vc:read`, `iam:vc:revoke`), wallet offers for others
// (`iam:vc:issue`), and, for members, credentials and offers for themselves where policies allow `vc:request` on
// `credential-type/{name}`; `nonce`, `verify` and `issuerMetadata` are public), the wallet-facing OpenID4VCI protocol
// mount, and `iam.verifiableCredentials`.

import (
	"context"
	"errors"
	"math"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

var (
	vcTypeNamePattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)
	vcColorPattern    = regexp.MustCompile(`^#[0-9a-fA-F]{6}$`)
	// vcWhitespace is the JavaScript \s class.
	vcWhitespace = regexp.MustCompile(`[` + jsWhitespace + `]`)
)

// vcPreAuthorized is the OpenID4VCI pre-authorized code grant type.
const vcPreAuthorized = "urn:ietf:params:oauth:grant-type:pre-authorized_code"

// vcTypeView is typeView: the type record without its uniqueKey.
func vcTypeView(typeValue *core.Object) *core.Object {
	view := typeValue.Spread()
	view.Delete("uniqueKey")
	return view
}

// vcIssuedView is issuedView: the record without uniqueKey and expiresAt, and its state (`expired` once past
// validUntil, whatever the status).
func vcIssuedView(record *core.Object, now float64) *core.Object {
	view := record.Spread()
	view.Delete("uniqueKey")
	view.Delete("expiresAt")
	state := record.Get("status")
	if jsNumber(record.Get("validUntil")) <= now {
		state = "expired"
	}
	view.Set("state", state)
	return view
}

// vcKeyView is keyView.
func vcKeyView(key *core.Object) *core.Object {
	view := core.NewObject(
		"id", key.Get("id"),
		"kid", key.Get("kid"),
		"status", key.Get("status"),
		"alg", key.Get("alg"),
		"publicJwk", key.Get("publicJwk"),
		"createdAt", key.Get("createdAt"),
	)
	if rotatedAt := key.Get("rotatedAt"); !isUndefined(rotatedAt) {
		view.Set("rotatedAt", rotatedAt)
	}
	if retiredAt := key.Get("retiredAt"); !isUndefined(retiredAt) {
		view.Set("retiredAt", retiredAt)
	}
	return view
}

func vcTypeName(value any) (string, error) {
	text, ok := value.(string)
	if !ok || !vcTypeNamePattern.MatchString(text) {
		return "", invalidInput(`Type names use 1-64 lowercase letters, digits, "_" or "-"`)
	}
	return text, nil
}

func vcColor(value any, name string) (string, error) {
	text, ok := value.(string)
	if !ok || !vcColorPattern.MatchString(text) {
		return "", invalidInput(name + " must be a #rrggbb color")
	}
	return text, nil
}

func vcTenantOf(value any) (string, error) { return Text(value, "tenantId") }

// vcByName orders records by name (a < b ? -1 : 1).
func vcByName(a, b *core.Object) int {
	if compareUTF16(jsString(a.Get("name")), jsString(b.Get("name"))) < 0 {
		return -1
	}
	return 1
}

// vcByIssued orders records newest first, then by id.
func vcByIssued(a, b *core.Object) int {
	if diff := jsNumber(b.Get("issuedAt")) - jsNumber(a.Get("issuedAt")); diff != 0 && !math.IsNaN(diff) {
		if diff < 0 {
			return -1
		}
		return 1
	}
	if compareUTF16(jsString(a.Get("id")), jsString(b.Get("id"))) < 0 {
		return -1
	}
	return 1
}

func vcObjects(items []*core.Object) []any {
	out := make([]any, len(items))
	for index, item := range items {
		out[index] = item
	}
	return out
}

// VerifiableCredentialsAPI is the `verifiableCredentials` API group (packages/server/src/api/verifiable-credentials.ts createVerifiableCredentialsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/verifiableCredentials/{method} onto it.
type VerifiableCredentialsAPI struct {
	server *ServerContext
}

// CreateVerifiableCredentialsAPI builds the `verifiableCredentials` API group.
func CreateVerifiableCredentialsAPI(server *ServerContext) *VerifiableCredentialsAPI {
	return &VerifiableCredentialsAPI{server: server}
}

func (api *VerifiableCredentialsAPI) scopedType(ctx context.Context, tx core.IamStore, tenantID string, name any) (*core.Object, error) {
	checked, err := vcTypeName(name)
	if err != nil {
		return nil, err
	}
	typeValue, err := TypeByName(ctx, tx, tenantID, checked)
	if err != nil {
		return nil, err
	}
	if typeValue == nil {
		return nil, core.NewIamError("NOT_FOUND", "Unknown credential type", 404)
	}
	return typeValue, nil
}

// selfServiceRefusal: checks for people getting a credential for themselves: not "view as", MFA when the type asks,
// then policy. nil when allowed.
func (api *VerifiableCredentialsAPI) selfServiceRefusal(ctx context.Context, tx core.IamStore, principal *Principal, tenant, typeValue *core.Object) (*core.IamError, error) {
	session, identity := principal.Session, principal.Identity
	if truthy(session.Get("impersonatorId")) {
		return core.NewIamError("IMPERSONATION_RESTRICTED", "Credentials cannot be issued while viewing as someone", 403), nil
	}
	// An agent acting for a person never binds that person's credential to a key of its own choosing.
	if session.Get("kind") == "delegated" {
		return core.NewIamError("ACCESS_DENIED", "Agents acting for people cannot obtain credentials for them", 403), nil
	}
	if identity.Get("tenantId") != tenant.Get("id") {
		return core.NewIamError("ACCESS_DENIED", "Credentials are issued to members of this organization", 403), nil
	}
	if truthy(typeValue.Get("requireMfa")) && identity.Get("kind") == "user" && !truthy(session.Get("mfa")) {
		return core.NewIamError("MFA_REQUIRED", "Sign in with multi-factor authentication to get this credential", 403), nil
	}
	if !truthy(typeValue.Get("enabled")) {
		return core.NewIamError("TYPE_DISABLED", "This credential type is disabled", 409), nil
	}
	allowed, err := MayRequest(ctx, api.server, tx, principal, tenant, typeValue)
	if err != nil {
		return nil, err
	}
	if !allowed {
		return core.NewIamError("ACCESS_DENIED", "Access denied", 403), nil
	}
	return nil, nil
}

// requestDeadline: the latest a self-service credential may stay valid: assumed roles and temporary credentials end
// with their session; standing sign-ins with the time-limited grants (just-in-time, expiring bindings or memberships,
// access windows) that allow `vc:request`.
func (api *VerifiableCredentialsAPI) requestDeadline(ctx context.Context, tx core.IamStore, principal *Principal, tenantID string) (*float64, error) {
	kind := principal.Session.Get("kind")
	if kind != "user" && kind != "api-key" {
		expiresAt, ok := principal.Session.Get("expiresAt").(float64)
		if !ok {
			if isUndefined(principal.Session.Get("expiresAt")) {
				return nil, nil
			}
			expiresAt = math.NaN()
		}
		return &expiresAt, nil
	}
	deadline, err := GrantDeadline(ctx, api.server, tx, principal, tenantID, math.Inf(1), VcRequestAction)
	if err != nil {
		return nil, err
	}
	return &deadline, nil
}

// vcSelfService is selfService: a self-service call in its own transaction; a refusal is audited (committed) before
// it is returned.
func vcSelfService[T any](ctx context.Context, api *VerifiableCredentialsAPI, credential core.CredentialInput, tenantID string, name any,
	run func(ctx context.Context, tx core.IamStore, principal *Principal, tenant, typeValue *core.Object) (T, error)) (T, error) {
	var zero T
	server := api.server
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return zero, err
	}
	type outcome struct {
		refusal *core.IamError
		value   T
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (outcome, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return outcome{}, err
		}
		tenant, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return outcome{}, err
		}
		typeValue, err := api.scopedType(ctx, tx, tenantID, name)
		if err != nil {
			return outcome{}, err
		}
		refusal, err := api.selfServiceRefusal(ctx, tx, principal, tenant, typeValue)
		if err != nil {
			return outcome{}, err
		}
		if refusal != nil {
			if err := server.Events.Audit(ctx, tx, principal, VcRequestAction, tenantID, "credential-type/"+jsString(typeValue.Get("name")), "deny", false,
				core.NewObject("reason", refusal.Code)); err != nil {
				return outcome{}, err
			}
			return outcome{refusal: refusal}, nil
		}
		value, err := run(ctx, tx, principal, tenant, typeValue)
		if err != nil {
			return outcome{}, err
		}
		return outcome{value: value}, nil
	})
	if err != nil {
		return zero, err
	}
	if result.refusal != nil {
		return zero, result.refusal
	}
	return result.value, nil
}

func (api *VerifiableCredentialsAPI) makeOffer(ctx context.Context, tx core.IamStore, tenant, typeValue, identity *core.Object, principal *Principal,
	options *ResolvedVcOptions, selfService bool, withTxCode bool) (*core.Object, error) {
	server := api.server
	tenantID := jsString(tenant.Get("id"))
	offerID := ID()
	code := OfferToken("biam_vco", offerID)
	txCode := ""
	if withTxCode {
		txCode = strconv.FormatInt(randomInt(1_000_000), 10)
		for len(txCode) < 6 {
			txCode = "0" + txCode
		}
	}
	now := float64(server.Now())
	record := core.NewObject(
		"id", offerID,
		"tenantId", tenantID,
		"typeId", typeValue.Get("id"),
		"identityId", identity.Get("id"),
		"codeHash", Hash(code),
	)
	if txCode != "" {
		record.Set("txCodeHash", Hash(offerID+":"+txCode))
	}
	record.Set("txCodeAttempts", 0)
	record.Set("selfService", selfService)
	record.Set("mfa", principal.Session.Get("mfa"))
	record.Set("createdAt", now)
	record.Set("createdBy", principal.Identity.Get("id"))
	record.Set("expiresAt", now+options.OfferLifetimeMs)
	offer, err := tx.Insert(ctx, "vcOffers", record)
	if err != nil {
		return nil, err
	}
	if err := server.Events.Audit(ctx, tx, principal, "vc:offer:create", tenantID, "vc/offers/"+jsString(offer.Get("id")), "allow", false,
		core.NewObject("type", typeValue.Get("name"), "identityId", identity.Get("id"), "txCode", txCode != "")); err != nil {
		return nil, err
	}
	grant := core.NewObject("pre-authorized_code", code)
	if txCode != "" {
		grant.Set("tx_code", core.NewObject("length", 6, "input_mode", "numeric", "description", "The PIN shown with the offer"))
	}
	credentialOffer := core.NewObject(
		"credential_issuer", IssuerURL(server, tenantID),
		"credential_configuration_ids", []any{typeValue.Get("name")},
		"grants", core.NewObject(vcPreAuthorized, grant),
	)
	result := core.NewObject(
		"offerId", offer.Get("id"),
		"credentialOffer", credentialOffer,
		"offerUri", "openid-credential-offer://?credential_offer="+encodeURIComponent(core.MustStringify(credentialOffer)),
	)
	if txCode != "" {
		result.Set("txCode", txCode)
	}
	result.Set("expiresAt", offer.Get("expiresAt"))
	return result, nil
}

func (api *VerifiableCredentialsAPI) changeStatus(ctx context.Context, tx core.IamStore, record *core.Object, next string, actorID any, reason any) (*core.Object, error) {
	current := record.Get("status")
	allowed := (next == "revoked" && current != "revoked") ||
		(next == "suspended" && current == "valid") ||
		(next == "valid" && current == "suspended")
	if !allowed {
		return nil, core.NewIamError("INVALID_TRANSITION", "A "+jsString(current)+" credential cannot become "+next, 409)
	}
	if err := WriteStatus(ctx, api.server, tx, record, next); err != nil {
		return nil, err
	}
	now := float64(api.server.Now())
	changed := record.Spread(core.NewObject("status", next))
	if next == "revoked" {
		changed.Set("revokedAt", now)
		changed.Set("revokedBy", actorID)
	}
	if !isUndefined(reason) {
		text, err := Text(reason, "reason", 512)
		if err != nil {
			return nil, err
		}
		changed.Set("reason", text)
	}
	return tx.Put(ctx, "vcIssued", changed)
}

// Status is POST {basePath}/verifiableCredentials/status. The issuer at a glance: its identifier and metadata URL, the published keys, the number of credential types, issued credentials by state (valid, suspended, revoked, expired), and status lists.
func (api *VerifiableCredentialsAPI) Status(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsStatusInput]) (Out[apitypes.VerifiableCredentialsStatusOutput], error) {
	server := api.server
	tenantID, err := vcTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsStatusOutput]{}, err
	}
	value, err := Operate(ctx, server.Operations, credential, tenantID, "iam:vc:read", "vc/issuer", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		if _, err := AssertVc(server); err != nil {
			return nil, err
		}
		tx, id := call.Tx, jsString(call.Tenant.Get("id"))
		now := float64(server.Now())
		issued, err := tx.Find(ctx, "vcIssued", core.NewObject("tenantId", id), nil)
		if err != nil {
			return nil, err
		}
		live := []*core.Object{}
		for _, record := range issued {
			if jsNumber(record.Get("validUntil")) > now {
				live = append(live, record)
			}
		}
		count := func(status string) int {
			total := 0
			for _, record := range live {
				if record.Get("status") == status {
					total++
				}
			}
			return total
		}
		keys, err := IssuerKeys(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		published := []any{}
		for _, key := range keys {
			if key.Get("status") != "retired" {
				published = append(published, vcKeyView(key))
			}
		}
		types, err := tx.Find(ctx, "vcCredentialTypes", core.NewObject("tenantId", id), nil)
		if err != nil {
			return nil, err
		}
		lists, err := tx.Find(ctx, "vcStatusLists", core.NewObject("tenantId", id), nil)
		if err != nil {
			return nil, err
		}
		return core.NewObject(
			"issuer", IssuerURL(server, id),
			"metadataUrl", urlOrigin(server.Config.BaseURL)+"/.well-known/openid-credential-issuer"+server.Config.BasePath+"/vc/"+id,
			"keys", published,
			"types", len(types),
			"credentials", core.NewObject(
				"valid", count("valid"),
				"suspended", count("suspended"),
				"revoked", count("revoked"),
				"expired", len(issued)-len(live),
			),
			"statusLists", len(lists),
		), nil
	}, false)
	if err != nil {
		return Out[apitypes.VerifiableCredentialsStatusOutput]{}, err
	}
	return Answer[apitypes.VerifiableCredentialsStatusOutput](value), nil
}

// CreateType is POST {basePath}/verifiableCredentials/createType. Defines a credential type: a name, a displayName and description for wallets, card colors, a lifetime (default 30 days, at most the deployment's maxLifetimeMs), requireMfa, and 1 to 32 claims.
func (api *VerifiableCredentialsAPI) CreateType(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsCreateTypeInput]) (Out[apitypes.VerifiableCredentialsCreateTypeOutput], error) {
	server := api.server
	name, err := vcTypeName(input.Get("name"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsCreateTypeOutput]{}, err
	}
	tenantID, err := vcTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsCreateTypeOutput]{}, err
	}
	value, err := Operate(ctx, server.Operations, credential, tenantID, "iam:vc:manage", "vc/types/"+name, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		options, err := AssertVc(server)
		if err != nil {
			return nil, err
		}
		tx, id := call.Tx, jsString(call.Tenant.Get("id"))
		existing, err := TypeByName(ctx, tx, id, name)
		if err != nil {
			return nil, err
		}
		if existing != nil {
			return nil, core.NewIamError("CONFLICT", "A credential type with this name exists", 409)
		}
		own := IssuerURL(server, id)
		vct := own + "/types/" + name
		if given := input.Get("vct"); !isUndefined(given) {
			if vct, err = Text(given, "vct", 256); err != nil {
				return nil, err
			}
		}
		if vcWhitespace.MatchString(vct) {
			return nil, invalidInput("vct cannot contain whitespace")
		}
		// Type identifiers under this deployment's issuers belong to the issuer they name.
		if strings.HasPrefix(vct, vcIssuerPrefix(server)) && !strings.HasPrefix(vct, own+"/") {
			return nil, invalidInput("vct names another organization's issuer")
		}
		now := float64(server.Now())
		displayName, err := Text(input.Get("displayName"), "displayName", 128)
		if err != nil {
			return nil, err
		}
		record := core.NewObject("id", ID(), "tenantId", id, "uniqueKey", name, "name", name, "displayName", displayName)
		if description := input.Get("description"); !isUndefined(description) {
			text, err := Text(description, "description", 512)
			if err != nil {
				return nil, err
			}
			record.Set("description", text)
		}
		record.Set("vct", vct)
		claims, err := VcClaims(input.Get("claims"), server.Catalog.IdentityAttributes)
		if err != nil {
			return nil, err
		}
		record.Set("claims", claims)
		lifetime := math.Min(30*vcDay, options.MaxLifetimeMs)
		if given := input.Get("lifetimeMs"); !isUndefined(given) {
			if lifetime, err = Integer(given, "lifetimeMs", 5*60_000, options.MaxLifetimeMs); err != nil {
				return nil, err
			}
		}
		record.Set("lifetimeMs", lifetime)
		record.Set("requireMfa", input.Get("requireMfa") == true)
		record.Set("enabled", input.Get("enabled") != false)
		if given := input.Get("backgroundColor"); !isUndefined(given) {
			color, err := vcColor(given, "backgroundColor")
			if err != nil {
				return nil, err
			}
			record.Set("backgroundColor", color)
		}
		if given := input.Get("textColor"); !isUndefined(given) {
			color, err := vcColor(given, "textColor")
			if err != nil {
				return nil, err
			}
			record.Set("textColor", color)
		}
		record.Set("createdAt", now)
		record.Set("createdBy", call.Principal.Identity.Get("id"))
		record.Set("updatedAt", now)
		typeValue, err := tx.Insert(ctx, "vcCredentialTypes", record)
		if err != nil {
			return nil, err
		}
		// The first type also creates the tenant's issuer key.
		if _, err := ActiveIssuerKey(ctx, server, tx, id, jsString(call.Principal.Identity.Get("id"))); err != nil {
			return nil, err
		}
		return vcTypeView(typeValue), nil
	}, false)
	if err != nil {
		return Out[apitypes.VerifiableCredentialsCreateTypeOutput]{}, err
	}
	return Answer[apitypes.VerifiableCredentialsCreateTypeOutput](value), nil
}

// UpdateType is POST {basePath}/verifiableCredentials/updateType. Changes a type's display, claims, lifetime, requireMfa or enabled. The name and vct never change.
func (api *VerifiableCredentialsAPI) UpdateType(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsUpdateTypeInput]) (Out[apitypes.VerifiableCredentialsUpdateTypeOutput], error) {
	server := api.server
	name, err := vcTypeName(input.Get("name"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsUpdateTypeOutput]{}, err
	}
	tenantID, err := vcTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsUpdateTypeOutput]{}, err
	}
	value, err := Operate(ctx, server.Operations, credential, tenantID, "iam:vc:manage", "vc/types/"+name, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		options, err := AssertVc(server)
		if err != nil {
			return nil, err
		}
		tx := call.Tx
		typeValue, err := api.scopedType(ctx, tx, jsString(call.Tenant.Get("id")), name)
		if err != nil {
			return nil, err
		}
		next := typeValue.Spread(core.NewObject("updatedAt", float64(server.Now())))
		if given := input.Get("displayName"); !isUndefined(given) {
			text, err := Text(given, "displayName", 128)
			if err != nil {
				return nil, err
			}
			next.Set("displayName", text)
		}
		if given := input.Get("description"); given == nil {
			next.Delete("description")
		} else if !isUndefined(given) {
			text, err := Text(given, "description", 512)
			if err != nil {
				return nil, err
			}
			next.Set("description", text)
		}
		if given := input.Get("claims"); !isUndefined(given) {
			claims, err := VcClaims(given, server.Catalog.IdentityAttributes)
			if err != nil {
				return nil, err
			}
			next.Set("claims", claims)
		}
		if given := input.Get("lifetimeMs"); !isUndefined(given) {
			lifetime, err := Integer(given, "lifetimeMs", 5*60_000, options.MaxLifetimeMs)
			if err != nil {
				return nil, err
			}
			next.Set("lifetimeMs", lifetime)
		}
		for _, key := range []string{"requireMfa", "enabled"} {
			if given := input.Get(key); !isUndefined(given) {
				if _, ok := given.(bool); !ok {
					return nil, invalidInput(key + " must be a boolean")
				}
				next.Set(key, given)
			}
		}
		for _, key := range []string{"backgroundColor", "textColor"} {
			if given := input.Get(key); given == nil {
				next.Delete(key)
			} else if !isUndefined(given) {
				color, err := vcColor(given, key)
				if err != nil {
					return nil, err
				}
				next.Set(key, color)
			}
		}
		saved, err := tx.Put(ctx, "vcCredentialTypes", next)
		if err != nil {
			return nil, err
		}
		return vcTypeView(saved), nil
	}, false)
	if err != nil {
		return Out[apitypes.VerifiableCredentialsUpdateTypeOutput]{}, err
	}
	return Answer[apitypes.VerifiableCredentialsUpdateTypeOutput](value), nil
}

// DeleteType is POST {basePath}/verifiableCredentials/deleteType. Deletes a type and its pending offers; refused while valid credentials of it exist (disable it, or revoke them first).
func (api *VerifiableCredentialsAPI) DeleteType(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsDeleteTypeInput]) (Out[apitypes.VerifiableCredentialsDeleteTypeOutput], error) {
	server := api.server
	name, err := vcTypeName(input.Get("name"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsDeleteTypeOutput]{}, err
	}
	tenantID, err := vcTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsDeleteTypeOutput]{}, err
	}
	value, err := Operate(ctx, server.Operations, credential, tenantID, "iam:vc:manage", "vc/types/"+name, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		if _, err := AssertVc(server); err != nil {
			return nil, err
		}
		tx, id := call.Tx, jsString(call.Tenant.Get("id"))
		typeValue, err := api.scopedType(ctx, tx, id, name)
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		issued, err := tx.Find(ctx, "vcIssued", core.NewObject("tenantId", id, "typeId", typeValue.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		live := 0
		for _, record := range issued {
			if record.Get("status") != "revoked" && jsNumber(record.Get("validUntil")) > now {
				live++
			}
		}
		if live > 0 {
			return nil, core.NewIamError("RESOURCE_IN_USE", strconv.Itoa(live)+" credentials of this type are still valid", 409)
		}
		offers, err := tx.Find(ctx, "vcOffers", core.NewObject("tenantId", id, "typeId", typeValue.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		for _, offer := range offers {
			if err := tx.Delete(ctx, "vcOffers", jsString(offer.Get("id"))); err != nil {
				return nil, err
			}
		}
		if err := tx.Delete(ctx, "vcCredentialTypes", jsString(typeValue.Get("id"))); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	if err != nil {
		return Out[apitypes.VerifiableCredentialsDeleteTypeOutput]{}, err
	}
	return Answer[apitypes.VerifiableCredentialsDeleteTypeOutput](value), nil
}

// GetType is POST {basePath}/verifiableCredentials/getType. One credential type.
func (api *VerifiableCredentialsAPI) GetType(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsGetTypeInput]) (Out[apitypes.VerifiableCredentialsGetTypeOutput], error) {
	server := api.server
	name, err := vcTypeName(input.Get("name"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsGetTypeOutput]{}, err
	}
	tenantID, err := vcTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsGetTypeOutput]{}, err
	}
	value, err := Operate(ctx, server.Operations, credential, tenantID, "iam:vc:read", "vc/types/"+name, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		if _, err := AssertVc(server); err != nil {
			return nil, err
		}
		typeValue, err := api.scopedType(ctx, call.Tx, jsString(call.Tenant.Get("id")), name)
		if err != nil {
			return nil, err
		}
		return vcTypeView(typeValue), nil
	}, false)
	if err != nil {
		return Out[apitypes.VerifiableCredentialsGetTypeOutput]{}, err
	}
	return Answer[apitypes.VerifiableCredentialsGetTypeOutput](value), nil
}

// ListTypes is POST {basePath}/verifiableCredentials/listTypes. Every credential type of the tenant, by name.
func (api *VerifiableCredentialsAPI) ListTypes(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsListTypesInput]) (Out[apitypes.VerifiableCredentialsListTypesOutput], error) {
	server := api.server
	tenantID, err := vcTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsListTypesOutput]{}, err
	}
	value, err := Operate(ctx, server.Operations, credential, tenantID, "iam:vc:read", "vc/types", func(ctx context.Context, call MutationContext) ([]any, error) {
		if _, err := AssertVc(server); err != nil {
			return nil, err
		}
		types, err := call.Tx.Find(ctx, "vcCredentialTypes", core.NewObject("tenantId", call.Tenant.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		slices.SortStableFunc(types, vcByName)
		views := make([]any, len(types))
		for index, item := range types {
			views[index] = vcTypeView(item)
		}
		return views, nil
	}, false)
	if err != nil {
		return Out[apitypes.VerifiableCredentialsListTypesOutput]{}, err
	}
	return Answer[apitypes.VerifiableCredentialsListTypesOutput](value), nil
}

// Available is POST {basePath}/verifiableCredentials/available. The enabled types the caller may request for themselves right now: vc:request allowed on credential-type/{name}, MFA when the type asks, and not in a "view as" session or a delegated agent session.
func (api *VerifiableCredentialsAPI) Available(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsAvailableInput]) (Out[apitypes.VerifiableCredentialsAvailableOutput], error) {
	server := api.server
	if _, err := AssertVc(server); err != nil {
		return Out[apitypes.VerifiableCredentialsAvailableOutput]{}, err
	}
	tenantID, err := vcTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsAvailableOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.VerifiableCredentialsAvailableOutput]{}, err
	}
	value, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]any, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		tenant, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		types, err := tx.Find(ctx, "vcCredentialTypes", core.NewObject("tenantId", tenantID, "enabled", true), nil)
		if err != nil {
			return nil, err
		}
		result := []*core.Object{}
		for _, typeValue := range types {
			refusal, err := api.selfServiceRefusal(ctx, tx, principal, tenant, typeValue)
			if err != nil {
				return nil, err
			}
			if refusal == nil {
				result = append(result, vcTypeView(typeValue))
			}
		}
		slices.SortStableFunc(result, vcByName)
		return vcObjects(result), nil
	})
	if err != nil {
		return Out[apitypes.VerifiableCredentialsAvailableOutput]{}, err
	}
	return Answer[apitypes.VerifiableCredentialsAvailableOutput](value), nil
}

// Nonce is POST {basePath}/verifiableCredentials/nonce (public: no request credential). A single-use proof nonce (cnonce) for the tenant's issuer, valid five minutes. Nonces are signed rather than stored, so handing one out writes nothing; a proof spends its nonce. Public.
func (api *VerifiableCredentialsAPI) Nonce(ctx context.Context, input In[apitypes.VerifiableCredentialsNonceInput]) (Out[apitypes.VerifiableCredentialsNonceOutput], error) {
	server := api.server
	if _, err := AssertVc(server); err != nil {
		return Out[apitypes.VerifiableCredentialsNonceOutput]{}, err
	}
	tenantID, err := vcTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsNonceOutput]{}, err
	}
	if _, err := server.Tenant(ctx, server.Store, tenantID); err != nil {
		return Out[apitypes.VerifiableCredentialsNonceOutput]{}, err
	}
	// Stateless (signed, checked and spent at use): handing nonces out writes nothing.
	return Answer[apitypes.VerifiableCredentialsNonceOutput](core.NewObject("nonce", CreateNonce(server, tenantID), "expiresIn", 300)), nil
}

// Request is POST {basePath}/verifiableCredentials/request. Issues a credential of type to the caller, bound to the key in proof (an OpenID4VCI proof JWT over a nonce from `nonce`). Needs `vc:request` on `credential-type/{type}` (and MFA when the type asks). Audited as `vc:credential:issue`; a refusal as a denied `vc:request`.
func (api *VerifiableCredentialsAPI) Request(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsRequestInput]) (Out[apitypes.VerifiableCredentialsRequestOutput], error) {
	server := api.server
	tenantID, err := vcTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsRequestOutput]{}, err
	}
	value, err := vcSelfService(ctx, api, credential, tenantID, input.Get("type"), func(ctx context.Context, tx core.IamStore, principal *Principal, tenant, typeValue *core.Object) (*core.Object, error) {
		id := jsString(tenant.Get("id"))
		holder, err := HolderFromProof(ctx, server, tx, id, input.Get("proof"))
		if err != nil {
			return nil, err
		}
		deadline, err := api.requestDeadline(ctx, tx, principal, id)
		if err != nil {
			return nil, err
		}
		issued, err := IssueCredential(ctx, server, tx, IssueCredentialInput{
			Tenant:           tenant,
			Type:             typeValue,
			Identity:         principal.Identity,
			HolderJwk:        holder.Jwk,
			HolderThumbprint: holder.Thumbprint,
			Via:              "request",
			Actor:            principal,
			IssuedBy:         jsString(principal.Identity.Get("id")),
			SelfService:      true,
			Mfa:              principal.Session.Get("mfa"),
			Deadline:         deadline,
		})
		if err != nil {
			return nil, err
		}
		return core.NewObject("credential", issued.Credential, "record", vcIssuedView(issued.Record, float64(server.Now()))), nil
	})
	if err != nil {
		return Out[apitypes.VerifiableCredentialsRequestOutput]{}, err
	}
	return Answer[apitypes.VerifiableCredentialsRequestOutput](value), nil
}

// CreateOffer is POST {basePath}/verifiableCredentials/createOffer. An OpenID4VCI credential offer with a pre-authorized code, and its openid-credential-offer:// link for a wallet to scan: for the caller (`vc:request`) or, with `identityId`, for someone else (`iam:vc:issue`). `txCode: true` adds a 6-digit PIN the wallet asks for.
func (api *VerifiableCredentialsAPI) CreateOffer(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsCreateOfferInput]) (Out[apitypes.VerifiableCredentialsCreateOfferOutput], error) {
	server := api.server
	options, err := AssertVc(server)
	if err != nil {
		return Out[apitypes.VerifiableCredentialsCreateOfferOutput]{}, err
	}
	tenantID, err := vcTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsCreateOfferOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.VerifiableCredentialsCreateOfferOutput]{}, err
	}
	withTxCode := input.Get("txCode") == true
	identityID := input.Get("identityId")
	if isUndefined(identityID) || core.StrictEquals(identityID, authenticated.Identity.Get("id")) {
		value, err := vcSelfService(ctx, api, credential, tenantID, input.Get("type"), func(ctx context.Context, tx core.IamStore, principal *Principal, tenant, typeValue *core.Object) (*core.Object, error) {
			return api.makeOffer(ctx, tx, tenant, typeValue, principal.Identity, principal, options, true, withTxCode)
		})
		if err != nil {
			return Out[apitypes.VerifiableCredentialsCreateOfferOutput]{}, err
		}
		return Answer[apitypes.VerifiableCredentialsCreateOfferOutput](value), nil
	}
	name, err := vcTypeName(input.Get("type"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsCreateOfferOutput]{}, err
	}
	value, err := Operate(ctx, server.Operations, credential, tenantID, "iam:vc:issue", "vc/types/"+name, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant := call.Tx, call.Tenant
		id := jsString(tenant.Get("id"))
		typeValue, err := api.scopedType(ctx, tx, id, name)
		if err != nil {
			return nil, err
		}
		if !truthy(typeValue.Get("enabled")) {
			return nil, core.NewIamError("TYPE_DISABLED", "This credential type is disabled", 409)
		}
		checked, err := Text(identityID, "identityId")
		if err != nil {
			return nil, err
		}
		identity, err := server.ActiveIdentity(ctx, tx, checked, id)
		if err != nil {
			return nil, err
		}
		if identity.Get("status") != "active" || server.IdentityExpired(identity) {
			return nil, core.NewIamError("IDENTITY_INACTIVE", "Credentials are issued to active members only", 409)
		}
		// Security clearances: whoever offers it, the holder must be cleared for the type's classification label.
		cleared, err := HolderCleared(ctx, server, tx, tenant, identity, jsString(typeValue.Get("name")), truthy(call.Principal.Session.Get("mfa")))
		if err != nil {
			return nil, err
		}
		if !cleared {
			return nil, NewOperationDenied("The holder is not cleared for this credential type")
		}
		return api.makeOffer(ctx, tx, tenant, typeValue, identity, call.Principal, options, false, withTxCode)
	}, false)
	if err != nil {
		return Out[apitypes.VerifiableCredentialsCreateOfferOutput]{}, err
	}
	return Answer[apitypes.VerifiableCredentialsCreateOfferOutput](value), nil
}

// Mine is POST {basePath}/verifiableCredentials/mine. The caller's own credentials in the tenant, newest first (the last 100), with their state. Refused for delegated agent sessions (ACCESS_DENIED).
func (api *VerifiableCredentialsAPI) Mine(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsMineInput]) (Out[apitypes.VerifiableCredentialsMineOutput], error) {
	server := api.server
	if _, err := AssertVc(server); err != nil {
		return Out[apitypes.VerifiableCredentialsMineOutput]{}, err
	}
	tenantID, err := vcTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsMineOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.VerifiableCredentialsMineOutput]{}, err
	}
	value, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]any, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if principal.Session.Get("kind") == "delegated" {
			return nil, accessDenied()
		}
		now := float64(server.Now())
		records, err := tx.Find(ctx, "vcIssued", core.NewObject("tenantId", tenantID, "identityId", principal.Identity.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		slices.SortStableFunc(records, vcByIssued)
		if len(records) > 100 {
			records = records[:100]
		}
		views := make([]any, len(records))
		for index, record := range records {
			views[index] = vcIssuedView(record, now)
		}
		return views, nil
	})
	if err != nil {
		return Out[apitypes.VerifiableCredentialsMineOutput]{}, err
	}
	return Answer[apitypes.VerifiableCredentialsMineOutput](value), nil
}

// ListIssued is POST {basePath}/verifiableCredentials/listIssued. Issued credentials, newest first, by type, identityId or state (valid, suspended, revoked, expired), with limit (at most 500) and offset. Records hold claim names, never values.
func (api *VerifiableCredentialsAPI) ListIssued(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsListIssuedInput]) (Out[apitypes.VerifiableCredentialsListIssuedOutput], error) {
	server := api.server
	tenantID, err := vcTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsListIssuedOutput]{}, err
	}
	value, err := Operate(ctx, server.Operations, credential, tenantID, "iam:vc:read", "vc/credentials", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		if _, err := AssertVc(server); err != nil {
			return nil, err
		}
		limit, err := Integer(coalesce(input.Get("limit"), 100.0), "limit", 1, 500)
		if err != nil {
			return nil, err
		}
		offset, err := Integer(coalesce(input.Get("offset"), 0.0), "offset", 0, 1_000_000)
		if err != nil {
			return nil, err
		}
		filter := core.NewObject("tenantId", call.Tenant.Get("id"))
		if given := input.Get("type"); !isUndefined(given) {
			name, err := vcTypeName(given)
			if err != nil {
				return nil, err
			}
			filter.Set("typeName", name)
		}
		if given := input.Get("identityId"); !isUndefined(given) {
			identityID, err := Text(given, "identityId")
			if err != nil {
				return nil, err
			}
			filter.Set("identityId", identityID)
		}
		now := float64(server.Now())
		records, err := call.Tx.Find(ctx, "vcIssued", filter, nil)
		if err != nil {
			return nil, err
		}
		state := input.Get("state")
		views := []*core.Object{}
		for _, record := range records {
			view := vcIssuedView(record, now)
			if isUndefined(state) || core.StrictEquals(view.Get("state"), state) {
				views = append(views, view)
			}
		}
		slices.SortStableFunc(views, vcByIssued)
		start := int(math.Min(offset, float64(len(views))))
		end := int(math.Min(offset+limit, float64(len(views))))
		return core.NewObject("credentials", vcObjects(views[start:end]), "total", len(views)), nil
	}, false)
	if err != nil {
		return Out[apitypes.VerifiableCredentialsListIssuedOutput]{}, err
	}
	return Answer[apitypes.VerifiableCredentialsListIssuedOutput](value), nil
}

// Revoke is POST {basePath}/verifiableCredentials/revoke. Revokes a credential for good (its status list entry becomes invalid): the holder's own without permission, anyone's with iam:vc:revoke.
func (api *VerifiableCredentialsAPI) Revoke(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsRevokeInput]) (Out[apitypes.VerifiableCredentialsRevokeOutput], error) {
	server := api.server
	if _, err := AssertVc(server); err != nil {
		return Out[apitypes.VerifiableCredentialsRevokeOutput]{}, err
	}
	tenantID, err := vcTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsRevokeOutput]{}, err
	}
	credentialID, err := Text(input.Get("credentialId"), "credentialId")
	if err != nil {
		return Out[apitypes.VerifiableCredentialsRevokeOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.VerifiableCredentialsRevokeOutput]{}, err
	}
	found, err := server.Scoped(ctx, server.Store, "vcIssued", credentialID, tenantID)
	if err != nil {
		return Out[apitypes.VerifiableCredentialsRevokeOutput]{}, err
	}
	session := authenticated.Session
	// The holder's own path skips the permission, so only a session acting in its own unrestricted right takes it:
	// not "view as", not an agent acting for them, not a key or token narrowed by a session policy.
	if found.Get("identityId") == authenticated.Identity.Get("id") &&
		!truthy(session.Get("impersonatorId")) &&
		session.Get("kind") != "delegated" &&
		!truthy(session.Get("policy")) &&
		!truthy(session.Get("sourcePolicy")) {
		value, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
			principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
			if err != nil {
				return nil, err
			}
			record, err := server.Scoped(ctx, tx, "vcIssued", credentialID, tenantID)
			if err != nil {
				return nil, err
			}
			changed, err := api.changeStatus(ctx, tx, record, "revoked", principal.Identity.Get("id"), input.Get("reason"))
			if err != nil {
				return nil, err
			}
			if err := server.Events.Audit(ctx, tx, principal, "vc:credential:revoke", tenantID, "vc/credentials/"+credentialID, "allow", false,
				core.NewObject("own", true)); err != nil {
				return nil, err
			}
			return vcIssuedView(changed, float64(server.Now())), nil
		})
		if err != nil {
			return Out[apitypes.VerifiableCredentialsRevokeOutput]{}, err
		}
		return Answer[apitypes.VerifiableCredentialsRevokeOutput](value), nil
	}
	value, err := Operate(ctx, server.Operations, credential, tenantID, "iam:vc:revoke", "vc/credentials/"+credentialID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		record, err := server.Scoped(ctx, call.Tx, "vcIssued", credentialID, tenantID)
		if err != nil {
			return nil, err
		}
		changed, err := api.changeStatus(ctx, call.Tx, record, "revoked", call.Principal.Identity.Get("id"), input.Get("reason"))
		if err != nil {
			return nil, err
		}
		return vcIssuedView(changed, float64(server.Now())), nil
	}, false)
	if err != nil {
		return Out[apitypes.VerifiableCredentialsRevokeOutput]{}, err
	}
	return Answer[apitypes.VerifiableCredentialsRevokeOutput](value), nil
}

// statusChange is suspend and reinstate: requires iam:vc:revoke.
func (api *VerifiableCredentialsAPI) statusChange(ctx context.Context, credential core.CredentialInput, body In[apitypes.VerifiableCredentialsSuspendInput], next string, reason any) (any, error) {
	server := api.server
	tenantID, err := vcTenantOf(body.Get("tenantId"))
	if err != nil {
		return nil, err
	}
	credentialID, err := Text(body.Get("credentialId"), "credentialId")
	if err != nil {
		return nil, err
	}
	return Operate(ctx, server.Operations, credential, tenantID, "iam:vc:revoke", "vc/credentials/"+credentialID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		if _, err := AssertVc(server); err != nil {
			return nil, err
		}
		record, err := server.Scoped(ctx, call.Tx, "vcIssued", body.Get("credentialId"), jsString(call.Tenant.Get("id")))
		if err != nil {
			return nil, err
		}
		changed, err := api.changeStatus(ctx, call.Tx, record, next, call.Principal.Identity.Get("id"), reason)
		if err != nil {
			return nil, err
		}
		return vcIssuedView(changed, float64(server.Now())), nil
	}, false)
}

// Suspend is POST {basePath}/verifiableCredentials/suspend. Suspends a valid credential (a lost phone). Verifiers see it as suspended until reinstate.
func (api *VerifiableCredentialsAPI) Suspend(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsSuspendInput]) (Out[apitypes.VerifiableCredentialsSuspendOutput], error) {
	value, err := api.statusChange(ctx, credential, input, "suspended", input.Get("reason"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsSuspendOutput]{}, err
	}
	return Answer[apitypes.VerifiableCredentialsSuspendOutput](value), nil
}

// Reinstate is POST {basePath}/verifiableCredentials/reinstate. Lifts a suspension.
func (api *VerifiableCredentialsAPI) Reinstate(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsReinstateInput]) (Out[apitypes.VerifiableCredentialsReinstateOutput], error) {
	value, err := api.statusChange(ctx, credential, In[apitypes.VerifiableCredentialsSuspendInput]{Body: input.Body}, "valid", core.Undefined)
	if err != nil {
		return Out[apitypes.VerifiableCredentialsReinstateOutput]{}, err
	}
	return Answer[apitypes.VerifiableCredentialsReinstateOutput](value), nil
}

// ListKeys is POST {basePath}/verifiableCredentials/listKeys. The issuer's signing keys, oldest first: active, previous (still published, so its credentials verify) and retired.
func (api *VerifiableCredentialsAPI) ListKeys(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsListKeysInput]) (Out[apitypes.VerifiableCredentialsListKeysOutput], error) {
	server := api.server
	tenantID, err := vcTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsListKeysOutput]{}, err
	}
	value, err := Operate(ctx, server.Operations, credential, tenantID, "iam:vc:read", "vc/keys", func(ctx context.Context, call MutationContext) ([]any, error) {
		if _, err := AssertVc(server); err != nil {
			return nil, err
		}
		keys, err := IssuerKeys(ctx, call.Tx, jsString(call.Tenant.Get("id")))
		if err != nil {
			return nil, err
		}
		views := make([]any, len(keys))
		for index, key := range keys {
			views[index] = vcKeyView(key)
		}
		return views, nil
	}, false)
	if err != nil {
		return Out[apitypes.VerifiableCredentialsListKeysOutput]{}, err
	}
	return Answer[apitypes.VerifiableCredentialsListKeysOutput](value), nil
}

// RotateKey is POST {basePath}/verifiableCredentials/rotateKey. Starts signing with a new ES256 key. The current one stays published as previous, so credentials it signed keep verifying.
func (api *VerifiableCredentialsAPI) RotateKey(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsRotateKeyInput]) (Out[apitypes.VerifiableCredentialsRotateKeyOutput], error) {
	server := api.server
	tenantID, err := vcTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsRotateKeyOutput]{}, err
	}
	value, err := Operate(ctx, server.Operations, credential, tenantID, "iam:vc:manage", "vc/keys", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		if _, err := AssertVc(server); err != nil {
			return nil, err
		}
		id := jsString(call.Tenant.Get("id"))
		now := float64(server.Now())
		keys, err := IssuerKeys(ctx, call.Tx, id)
		if err != nil {
			return nil, err
		}
		for _, key := range keys {
			if key.Get("status") == "active" {
				if _, err := call.Tx.Put(ctx, "vcIssuerKeys", key.Spread(core.NewObject("status", "previous", "rotatedAt", now))); err != nil {
					return nil, err
				}
			}
		}
		created, err := CreateIssuerKey(ctx, server, call.Tx, id, jsString(call.Principal.Identity.Get("id")))
		if err != nil {
			return nil, err
		}
		return vcKeyView(created), nil
	}, false)
	if err != nil {
		return Out[apitypes.VerifiableCredentialsRotateKeyOutput]{}, err
	}
	return Answer[apitypes.VerifiableCredentialsRotateKeyOutput](value), nil
}

// RetireKey is POST {basePath}/verifiableCredentials/retireKey. Stops publishing a previous key, after which credentials it signed no longer verify. Refused while valid ones exist, unless `force` (which revokes them).
func (api *VerifiableCredentialsAPI) RetireKey(ctx context.Context, credential core.CredentialInput, input In[apitypes.VerifiableCredentialsRetireKeyInput]) (Out[apitypes.VerifiableCredentialsRetireKeyOutput], error) {
	server := api.server
	tenantID, err := vcTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsRetireKeyOutput]{}, err
	}
	value, err := Operate(ctx, server.Operations, credential, tenantID, "iam:vc:manage", "vc/keys", func(ctx context.Context, call MutationContext) (*core.Object, error) {
		if _, err := AssertVc(server); err != nil {
			return nil, err
		}
		tx, id := call.Tx, jsString(call.Tenant.Get("id"))
		keys, err := IssuerKeys(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		var key *core.Object
		for _, item := range keys {
			if core.StrictEquals(item.Get("kid"), input.Get("kid")) {
				key = item
				break
			}
		}
		if key == nil {
			return nil, core.NewIamError("NOT_FOUND", "Unknown issuer key", 404)
		}
		if key.Get("status") != "previous" {
			return nil, core.NewIamError("INVALID_TRANSITION", "Only a previous key can be retired", 409)
		}
		now := float64(server.Now())
		issued, err := tx.Find(ctx, "vcIssued", core.NewObject("tenantId", id, "keyId", key.Get("kid")), nil)
		if err != nil {
			return nil, err
		}
		live := []*core.Object{}
		for _, record := range issued {
			if record.Get("status") != "revoked" && jsNumber(record.Get("validUntil")) > now {
				live = append(live, record)
			}
		}
		if len(live) > 0 && input.Get("force") != true {
			return nil, core.NewIamError("RESOURCE_IN_USE", strconv.Itoa(len(live))+" credentials signed by this key are still valid", 409)
		}
		for _, record := range live {
			if _, err := api.changeStatus(ctx, tx, record, "revoked", call.Principal.Identity.Get("id"), "key-retired"); err != nil {
				return nil, err
			}
		}
		saved, err := tx.Put(ctx, "vcIssuerKeys", key.Spread(core.NewObject("status", "retired", "retiredAt", now)))
		if err != nil {
			return nil, err
		}
		return vcKeyView(saved), nil
	}, false)
	if err != nil {
		return Out[apitypes.VerifiableCredentialsRetireKeyOutput]{}, err
	}
	return Answer[apitypes.VerifiableCredentialsRetireKeyOutput](value), nil
}

// Verify is POST {basePath}/verifiableCredentials/verify (public: no request credential). Verifies a presentation of a credential this deployment issued (signature, disclosures, key binding for `audience` and `nonce`, current status); answers `{ valid: false, reason }` instead of failing.
func (api *VerifiableCredentialsAPI) Verify(ctx context.Context, input In[apitypes.VerifiableCredentialsVerifyInput]) (Out[apitypes.VerifiableCredentialsVerifyOutput], error) {
	server := api.server
	if _, err := AssertVc(server); err != nil {
		return Out[apitypes.VerifiableCredentialsVerifyOutput]{}, err
	}
	value, err := func() (*core.Object, error) {
		presentation, err := Text(input.Get("presentation"), "presentation", 65536)
		if err != nil {
			return nil, err
		}
		options := core.NewObject()
		if given := input.Get("audience"); !isUndefined(given) {
			audience, err := Text(given, "audience", 512)
			if err != nil {
				return nil, err
			}
			options.Set("audience", audience)
		}
		if given := input.Get("nonce"); !isUndefined(given) {
			nonce, err := Text(given, "nonce", 256)
			if err != nil {
				return nil, err
			}
			options.Set("nonce", nonce)
		}
		if given := input.Get("tenantId"); !isUndefined(given) {
			tenantID, err := vcTenantOf(given)
			if err != nil {
				return nil, err
			}
			options.Set("tenantId", tenantID)
		}
		verified, err := VerifyLocalPresentation(ctx, server, presentation, options)
		if err != nil {
			return nil, err
		}
		return core.NewObject("valid", true).Assign(verified), nil
	}()
	if err != nil {
		var failed *SdJwtError
		if errors.As(err, &failed) {
			return Answer[apitypes.VerifiableCredentialsVerifyOutput](core.NewObject("valid", false, "reason", failed.Reason, "message", failed.Message)), nil
		}
		return Out[apitypes.VerifiableCredentialsVerifyOutput]{}, err
	}
	return Answer[apitypes.VerifiableCredentialsVerifyOutput](value), nil
}

// IssuerMetadata is POST {basePath}/verifiableCredentials/issuerMetadata (public: no request credential). The tenant's OpenID4VCI credential issuer metadata: endpoints, and every enabled type with its format (dc+sd-jwt), vct, binding methods, proof algorithms and wallet display.
func (api *VerifiableCredentialsAPI) IssuerMetadata(ctx context.Context, input In[apitypes.VerifiableCredentialsIssuerMetadataInput]) (Out[apitypes.VerifiableCredentialsIssuerMetadataOutput], error) {
	server := api.server
	if _, err := AssertVc(server); err != nil {
		return Out[apitypes.VerifiableCredentialsIssuerMetadataOutput]{}, err
	}
	tenantID, err := vcTenantOf(input.Get("tenantId"))
	if err != nil {
		return Out[apitypes.VerifiableCredentialsIssuerMetadataOutput]{}, err
	}
	tenant, err := vcActiveTenantOf(ctx, server, server.Store, tenantID)
	if err != nil {
		return Out[apitypes.VerifiableCredentialsIssuerMetadataOutput]{}, err
	}
	metadata, err := vcIssuerMetadata(ctx, server, server.Store, tenant)
	if err != nil {
		return Out[apitypes.VerifiableCredentialsIssuerMetadataOutput]{}, err
	}
	return Answer[apitypes.VerifiableCredentialsIssuerMetadataOutput](metadata), nil
}

// vcActiveTenantOf is activeTenantOf: the tenant, TENANT_INACTIVE (403) unless it and every ancestor are active.
func vcActiveTenantOf(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string) (*core.Object, error) {
	tenant, err := server.Tenant(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	inactive, err := vcAnyInactive(ctx, server, tx, tenant)
	if err != nil {
		return nil, err
	}
	if inactive {
		return nil, core.NewIamError("TENANT_INACTIVE", "This organization is not active", 403)
	}
	return tenant, nil
}

// vcIssuerMetadata is issuerMetadata: OpenID4VCI 1.0 credential issuer metadata for a tenant's enabled types.
func vcIssuerMetadata(ctx context.Context, server *ServerContext, tx core.IamStore, tenant *core.Object) (*core.Object, error) {
	tenantID := jsString(tenant.Get("id"))
	issuer := IssuerURL(server, tenantID)
	types, err := tx.Find(ctx, "vcCredentialTypes", core.NewObject("tenantId", tenantID, "enabled", true), nil)
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(types, vcByName)
	supported := core.NewObject()
	for _, typeValue := range types {
		display := core.NewObject("name", typeValue.Get("displayName"), "locale", "en")
		if description := typeValue.Get("description"); truthy(description) {
			display.Set("description", description)
		}
		if color := typeValue.Get("backgroundColor"); truthy(color) {
			display.Set("background_color", color)
		}
		if color := typeValue.Get("textColor"); truthy(color) {
			display.Set("text_color", color)
		}
		claims := []any{}
		list, _ := typeValue.Get("claims").([]any)
		for _, raw := range list {
			claim := core.NewObject("path", []any{member(raw, "name")})
			if label := member(raw, "label"); truthy(label) {
				claim.Set("display", []any{core.NewObject("name", label, "locale", "en")})
			}
			claims = append(claims, claim)
		}
		supported.Set(jsString(typeValue.Get("name")), core.NewObject(
			"format", "dc+sd-jwt",
			"vct", typeValue.Get("vct"),
			"scope", typeValue.Get("name"),
			"cryptographic_binding_methods_supported", []any{"jwk"},
			"credential_signing_alg_values_supported", []any{"ES256"},
			"proof_types_supported", core.NewObject("jwt", core.NewObject("proof_signing_alg_values_supported", []any{"ES256", "ES384", "EdDSA"})),
			"credential_metadata", core.NewObject("display", []any{display}, "claims", claims),
		))
	}
	return core.NewObject(
		"credential_issuer", issuer,
		"credential_endpoint", issuer+"/credential",
		"nonce_endpoint", issuer+"/nonce",
		"display", []any{core.NewObject("name", tenant.Get("name"), "locale", "en")},
		"credential_configurations_supported", supported,
	), nil
}

// vcTypeMetadata is typeMetadata: SD-JWT VC type metadata for `{issuer}/types/{name}`.
func vcTypeMetadata(typeValue *core.Object) *core.Object {
	description := typeValue.Get("description")
	result := core.NewObject("vct", typeValue.Get("vct"), "name", typeValue.Get("displayName"))
	if truthy(description) {
		result.Set("description", description)
	}
	display := core.NewObject("locale", "en", "name", typeValue.Get("displayName"))
	if truthy(description) {
		display.Set("description", description)
	}
	background, text := typeValue.Get("backgroundColor"), typeValue.Get("textColor")
	if truthy(background) || truthy(text) {
		simple := core.NewObject()
		if truthy(background) {
			simple.Set("background_color", background)
		}
		if truthy(text) {
			simple.Set("text_color", text)
		}
		display.Set("rendering", core.NewObject("simple", simple))
	}
	result.Set("display", []any{display})
	claims := []any{}
	list, _ := typeValue.Get("claims").([]any)
	for _, raw := range list {
		sd := "always"
		if member(raw, "selective") == false {
			sd = "never"
		}
		claim := core.NewObject("path", []any{member(raw, "name")}, "sd", sd)
		if label := member(raw, "label"); truthy(label) {
			claim.Set("display", []any{core.NewObject("locale", "en", "label", label)})
		}
		claims = append(claims, claim)
	}
	result.Set("claims", claims)
	return result
}

// vcCors are the headers of every protocol answer.
var vcCors = [][2]string{
	{"access-control-allow-origin", "*"},
	{"access-control-allow-methods", "GET, POST, OPTIONS"},
	{"access-control-allow-headers", "authorization, content-type, dpop"},
	{"cache-control", "no-store"},
}

// vcResponse is a protocol answer, written once its transaction committed.
type vcResponse struct {
	status  int
	body    any
	text    string
	hasText bool
	headers [][2]string
}

func vcJSON(status int, body any, headers ...[2]string) *vcResponse {
	return &vcResponse{status: status, body: body, headers: headers}
}

func vcOAuthError(status int, code, description string, headers ...[2]string) *vcResponse {
	return vcJSON(status, core.NewObject("error", code, "error_description", description), headers...)
}

func vcNotFound() *vcResponse { return vcJSON(404, core.NewObject("error", "not_found")) }

// write answers the response with the CORS headers (its own headers override them).
func (r *vcResponse) write(w http.ResponseWriter) {
	header := w.Header()
	for _, item := range vcCors {
		header.Set(item[0], item[1])
	}
	if r.body != nil {
		header.Set("content-type", "application/json")
	}
	for _, item := range r.headers {
		header.Set(item[0], item[1])
	}
	w.WriteHeader(r.status)
	if r.hasText {
		_, _ = w.Write(utf8Bytes(r.text))
	} else if r.body != nil {
		_, _ = w.Write(utf8Bytes(core.MustStringify(r.body)))
	}
}

// vcBodyText is bodyText: reads at most `limit` bytes of a body, refusing (PAYLOAD_TOO_LARGE, 413) as soon as more
// arrive.
func vcBodyText(request *http.Request, limit int64) (string, error) {
	declared := 0.0
	if values := request.Header.Values("Content-Length"); len(values) > 0 {
		declared = jsNumber(strings.Join(values, ", "))
	} else if request.ContentLength > 0 {
		declared = float64(request.ContentLength)
	}
	tooLarge := core.NewIamError("PAYLOAD_TOO_LARGE", "Request body too large", 413)
	if declared > float64(limit) {
		return "", tooLarge
	}
	text, ok, err := signalBoundedBody(request, limit)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", tooLarge
	}
	return text, nil
}

// vcFormValue is new URLSearchParams(body).get(name): the application/x-www-form-urlencoded parser (`+` is a space,
// valid percent escapes are bytes, the result is UTF-8 with replacement), first match; ok false when absent.
func vcFormValue(body string, name string) (string, bool) {
	decode := func(part string) string {
		raw := []byte(part)
		out := make([]byte, 0, len(raw))
		for i := 0; i < len(raw); i++ {
			c := raw[i]
			switch {
			case c == '+':
				out = append(out, ' ')
			case c == '%' && i+2 < len(raw) && isHexDigit(raw[i+1]) && isHexDigit(raw[i+2]):
				value, _ := strconv.ParseUint(string(raw[i+1:i+3]), 16, 8)
				out = append(out, byte(value))
				i += 2
			default:
				out = append(out, c)
			}
		}
		return decodeUTF8(out)
	}
	for _, sequence := range strings.Split(body, "&") {
		if sequence == "" {
			continue
		}
		key, value, _ := strings.Cut(sequence, "=")
		if decode(key) == name {
			return decode(value), true
		}
	}
	return "", false
}

func isHexDigit(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// vcProtocol is the wallet-facing issuer mount.
type vcProtocol struct {
	server        *ServerContext
	prefix        string
	tenantPattern *regexp.Regexp
}

var vcWellKnown = []string{"openid-credential-issuer", "jwt-vc-issuer", "oauth-authorization-server"}

// CreateVcProtocol (api/verifiable-credentials.ts createVcProtocol): The wallet-facing endpoints of every tenant's
// issuer, mounted beside the HTTP API (`{issuer}` is `{origin}{basePath}/vc/{tenantId}`):
// `/.well-known/openid-credential-issuer{path}`, `/.well-known/jwt-vc-issuer{path}` and
// `/.well-known/oauth-authorization-server{path}` metadata, `{issuer}/token` (pre-authorized code),
// `{issuer}/nonce`, `{issuer}/credential`, `{issuer}/jwks.json`, `{issuer}/types/{name}` and
// `{issuer}/status/{listId}` (Token Status List).
func CreateVcProtocol(server *ServerContext) (ProtocolMount, error) {
	if _, err := VcOptions(server); err != nil {
		return ProtocolMount{}, err
	}
	protocol := &vcProtocol{server: server, prefix: server.Config.BasePath + "/vc/", tenantPattern: regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)}
	return ProtocolMount{Handle: protocol.handle}, nil
}

func (p *vcProtocol) handle(w http.ResponseWriter, request *http.Request) bool {
	if options, err := VcOptions(p.server); err != nil || options == nil {
		return false
	}
	pathname := request.URL.EscapedPath()
	tenantID, rest, metadata := "", "", ""
	for _, name := range vcWellKnown {
		start := "/.well-known/" + name + p.prefix
		if strings.HasPrefix(pathname, start) {
			metadata = name
			tenantID = pathname[len(start):]
		}
	}
	if metadata == "" {
		if !strings.HasPrefix(pathname, p.prefix) {
			return false
		}
		path := pathname[len(p.prefix):]
		if slash := strings.Index(path, "/"); slash < 0 {
			tenantID = path
		} else {
			tenantID, rest = path[:slash], path[slash+1:]
		}
	}
	if tenantID == "" || !p.tenantPattern.MatchString(tenantID) {
		vcNotFound().write(w)
		return true
	}
	if request.Method == http.MethodOptions {
		(&vcResponse{status: 204}).write(w)
		return true
	}
	response, err := p.dispatch(request, tenantID, metadata, rest)
	if err != nil {
		if known, ok := asIamError(err); ok {
			code := "invalid_request"
			if known.Status == 404 {
				code = "not_found"
			}
			response = vcJSON(known.Status, core.NewObject("error", code, "error_description", known.Message))
		} else {
			response = vcJSON(500, core.NewObject("error", "server_error"))
		}
	}
	response.write(w)
	return true
}

func (p *vcProtocol) dispatch(request *http.Request, tenantID, metadata, rest string) (*vcResponse, error) {
	ctx := request.Context()
	switch request.Method {
	case http.MethodGet:
		return p.read(ctx, tenantID, metadata, rest)
	case http.MethodPost:
		switch rest {
		case "token":
			return p.tokenEndpoint(request, tenantID)
		case "nonce":
			if _, err := vcActiveTenantOf(ctx, p.server, p.server.Store, tenantID); err != nil {
				return nil, err
			}
			return vcJSON(200, core.NewObject("c_nonce", CreateNonce(p.server, tenantID))), nil
		case "credential":
			return p.credentialEndpoint(request, tenantID)
		}
	}
	return vcNotFound(), nil
}

func (p *vcProtocol) read(ctx context.Context, tenantID, metadata, rest string) (*vcResponse, error) {
	server := p.server
	// Public reads stay off the write lock: nothing here creates or changes a row.
	reader := server.Store
	tenant, err := vcActiveTenantOf(ctx, server, reader, tenantID)
	if err != nil {
		return nil, err
	}
	issuer := IssuerURL(server, tenantID)
	switch metadata {
	case "openid-credential-issuer":
		body, err := vcIssuerMetadata(ctx, server, reader, tenant)
		if err != nil {
			return nil, err
		}
		return vcJSON(200, body), nil
	case "jwt-vc-issuer":
		jwks, err := IssuerJwks(ctx, reader, tenantID)
		if err != nil {
			return nil, err
		}
		return vcJSON(200, core.NewObject("issuer", issuer, "jwks", jwks)), nil
	case "oauth-authorization-server":
		return vcJSON(200, core.NewObject(
			"issuer", issuer,
			"token_endpoint", issuer+"/token",
			"grant_types_supported", []any{vcPreAuthorized},
			"pre-authorized_grant_anonymous_access_supported", true,
		)), nil
	}
	if rest == "jwks.json" {
		jwks, err := IssuerJwks(ctx, reader, tenantID)
		if err != nil {
			return nil, err
		}
		return vcJSON(200, jwks), nil
	}
	if strings.HasPrefix(rest, "types/") {
		typeValue, err := TypeByName(ctx, reader, tenantID, rest[len("types/"):])
		if err != nil {
			return nil, err
		}
		if typeValue == nil {
			return vcNotFound(), nil
		}
		return vcJSON(200, vcTypeMetadata(typeValue)), nil
	}
	if strings.HasPrefix(rest, "status/") {
		list, err := reader.Get(ctx, "vcStatusLists", rest[len("status/"):])
		if err != nil {
			return nil, err
		}
		if list == nil || list.Get("tenantId") != tenantID {
			return vcNotFound(), nil
		}
		token, err := StatusListToken(ctx, server, reader, list)
		if err != nil {
			return nil, err
		}
		options, err := AssertVc(server)
		if err != nil {
			return nil, err
		}
		return &vcResponse{status: 200, text: token, hasText: true, headers: [][2]string{
			{"content-type", "application/statuslist+jwt"},
			{"cache-control", "public, max-age=" + core.NumberString(options.StatusListTtlSeconds)},
		}}, nil
	}
	return vcNotFound(), nil
}

// tokenEndpoint is the pre-authorized code grant: one offer, one access token, the PIN checked at most five times.
func (p *vcProtocol) tokenEndpoint(request *http.Request, tenantID string) (*vcResponse, error) {
	server := p.server
	ctx := request.Context()
	contentType := core.JSLower(strings.Join(request.Header.Values("Content-Type"), ", "))
	if !strings.HasPrefix(contentType, "application/x-www-form-urlencoded") {
		return vcOAuthError(400, "invalid_request", "Send a form-encoded token request"), nil
	}
	body, err := vcBodyText(request, 8192)
	if err != nil {
		return nil, err
	}
	if grantType, ok := vcFormValue(body, "grant_type"); !ok || grantType != vcPreAuthorized {
		return vcOAuthError(400, "unsupported_grant_type", "Only the pre-authorized code grant is supported"), nil
	}
	code, _ := vcFormValue(body, "pre-authorized_code")
	offerID := OfferIDOf(code, "biam_vco")
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*vcResponse, error) {
		if _, err := vcActiveTenantOf(ctx, server, tx, tenantID); err != nil {
			return nil, err
		}
		var offer *core.Object
		if offerID != "" {
			if offer, err = tx.Get(ctx, "vcOffers", offerID); err != nil {
				return nil, err
			}
		}
		now := float64(server.Now())
		if offer == nil || offer.Get("tenantId") != tenantID || !MatchesHash(offer.Get("codeHash"), code) ||
			!isUndefined(offer.Get("redeemedAt")) || jsNumber(offer.Get("expiresAt")) <= now {
			return vcOAuthError(400, "invalid_grant", "The offer is unknown, used or expired"), nil
		}
		if truthy(offer.Get("txCodeHash")) {
			txCode, _ := vcFormValue(body, "tx_code")
			// A wallet that did not ask for the PIN yet has not guessed wrong.
			if txCode == "" {
				return vcOAuthError(400, "invalid_request", "This offer needs its PIN (tx_code)"), nil
			}
			if !MatchesHash(offer.Get("txCodeHash"), jsString(offer.Get("id"))+":"+txCode) {
				attempts := jsNumber(offer.Get("txCodeAttempts")) + 1
				// Five wrong PINs end the offer.
				changed := offer.Spread(core.NewObject("txCodeAttempts", attempts))
				if attempts >= 5 {
					changed.Set("expiresAt", now)
				}
				if _, err := tx.Put(ctx, "vcOffers", changed); err != nil {
					return nil, err
				}
				reason, message := "wrong-pin", "The PIN is wrong"
				if attempts >= 5 {
					reason, message = "pin-locked", "Too many wrong PINs; the offer ended"
				}
				if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
					"id", ID(),
					"tenantId", tenantID,
					"actorId", offer.Get("identityId"),
					"action", "vc:offer:redeem",
					"resourceId", "vc/offers/"+jsString(offer.Get("id")),
					"outcome", "deny",
					"timestamp", now,
					"metadata", core.NewObject("reason", reason, "attempts", attempts),
				)); err != nil {
					return nil, err
				}
				return vcOAuthError(400, "invalid_grant", message), nil
			}
		}
		accessToken := OfferToken("biam_vcat", jsString(offer.Get("id")))
		accessExpiresAt := now + 5*60_000
		if _, err := tx.Put(ctx, "vcOffers", offer.Spread(core.NewObject(
			"redeemedAt", now,
			"accessTokenHash", Hash(accessToken),
			"accessExpiresAt", accessExpiresAt,
			"expiresAt", accessExpiresAt,
		))); err != nil {
			return nil, err
		}
		return vcJSON(200, core.NewObject("access_token", accessToken, "token_type", "Bearer", "expires_in", 300)), nil
	})
}

// credentialEndpoint issues the offered credential to the wallet that holds the access token, bound to the key its
// proof names.
func (p *vcProtocol) credentialEndpoint(request *http.Request, tenantID string) (*vcResponse, error) {
	server := p.server
	ctx := request.Context()
	authorization := strings.Join(request.Header.Values("Authorization"), ", ")
	accessToken := ""
	if strings.HasPrefix(authorization, "Bearer ") {
		accessToken = core.JSTrim(authorization[len("Bearer "):])
	}
	offerID := OfferIDOf(accessToken, "biam_vcat")
	challenge := [2]string{"www-authenticate", `Bearer error="invalid_token"`}
	if offerID == "" {
		return vcOAuthError(401, "invalid_token", "A bearer access token is required", challenge), nil
	}
	var body *core.Object
	text, err := vcBodyText(request, 16384)
	if err == nil {
		parsed, parseErr := core.ParseJSONString(text)
		body, _ = parsed.(*core.Object)
		if parseErr != nil {
			body = nil
		}
	}
	if body == nil {
		return vcOAuthError(400, "invalid_credential_request", "Send a JSON credential request"), nil
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*vcResponse, error) {
		tenant, err := vcActiveTenantOf(ctx, server, tx, tenantID)
		if err != nil {
			return nil, err
		}
		offer, err := tx.Get(ctx, "vcOffers", offerID)
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		if offer == nil || offer.Get("tenantId") != tenantID || !MatchesHash(offer.Get("accessTokenHash"), accessToken) ||
			jsNumber(coalesce(offer.Get("accessExpiresAt"), 0.0)) <= now || !isUndefined(offer.Get("credentialId")) {
			return vcOAuthError(401, "invalid_token", "The access token is unknown, used or expired", challenge), nil
		}
		typeValue, err := tx.Get(ctx, "vcCredentialTypes", jsString(offer.Get("typeId")))
		if err != nil {
			return nil, err
		}
		if typeValue == nil || typeValue.Get("tenantId") != tenantID {
			return vcOAuthError(400, "unknown_credential_configuration", "The offered credential type no longer exists"), nil
		}
		// A refused redemption is answered, and audited: the transaction commits either way.
		refuse := func(status int, code, description, reason string) (*vcResponse, error) {
			if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
				"id", ID(),
				"tenantId", tenantID,
				"actorId", offer.Get("identityId"),
				"action", "vc:offer:redeem",
				"resourceId", "vc/offers/"+jsString(offer.Get("id")),
				"outcome", "deny",
				"timestamp", now,
				"metadata", core.NewObject("reason", reason, "type", typeValue.Get("name")),
			)); err != nil {
				return nil, err
			}
			return vcOAuthError(status, code, description), nil
		}
		requested := body.Get("credential_configuration_id")
		if nullish(requested) {
			requested = core.Undefined
			if core.StrictEquals(body.Get("vct"), typeValue.Get("vct")) {
				requested = typeValue.Get("name")
			}
		}
		if !core.StrictEquals(requested, typeValue.Get("name")) {
			return vcOAuthError(400, "unknown_credential_configuration", "This token is for another credential"), nil
		}
		var proof any = core.Undefined
		if jwts, ok := member(body.Get("proofs"), "jwt").([]any); ok && len(jwts) == 1 {
			proof = jwts[0]
		} else if member(body.Get("proof"), "proof_type") == "jwt" {
			proof = member(body.Get("proof"), "jwt")
		}
		if isUndefined(proof) {
			return vcOAuthError(400, "invalid_proof", "Send one jwt proof"), nil
		}
		identity, err := tx.Get(ctx, "identities", jsString(offer.Get("identityId")))
		if err != nil {
			return nil, err
		}
		if identity == nil || identity.Get("tenantId") != tenantID || identity.Get("status") != "active" || server.IdentityExpired(identity) {
			return refuse(400, "invalid_credential_request", "The holder is no longer a member", "identity-inactive")
		}
		// Self-service offers are re-decided now: access or MFA may have changed since the offer was made, and the
		// credential ends with the time-limited grants that allow it.
		var deadline *float64
		mfa := truthy(offer.Get("mfa"))
		if truthy(offer.Get("selfService")) {
			principal := server.Decisions.SimulatedPrincipal(identity, mfa)
			refused := truthy(typeValue.Get("requireMfa")) && identity.Get("kind") == "user" && !mfa
			if !refused {
				allowed, err := MayRequest(ctx, server, tx, principal, tenant, typeValue)
				if err != nil {
					return nil, err
				}
				refused = !allowed
			}
			if refused {
				return refuse(403, "access_denied", "The holder may no longer receive this credential", "access-changed")
			}
			until, err := GrantDeadline(ctx, server, tx, principal, tenantID, math.Inf(1), VcRequestAction)
			if err != nil {
				return nil, err
			}
			deadline = &until
		} else {
			cleared, err := HolderCleared(ctx, server, tx, tenant, identity, jsString(typeValue.Get("name")), mfa)
			if err != nil {
				return nil, err
			}
			if !cleared {
				// An administrator's offer needs no `vc:request`, but the holder must still be cleared for the type's
				// classification label now (security clearances).
				return refuse(403, "access_denied", "The holder may no longer receive this credential", "access-changed")
			}
		}
		holder, err := HolderFromProof(ctx, server, tx, tenantID, proof)
		if err != nil {
			code := "invalid_proof"
			if known, ok := asIamError(err); ok && known.Code == "INVALID_NONCE" {
				code = "invalid_nonce"
			}
			return vcOAuthError(400, code, errorMessage(err)), nil
		}
		issuedBy := jsString(offer.Get("createdBy"))
		if truthy(offer.Get("selfService")) {
			// An administrator's offer is theirs to answer for; a self-service one is the person's.
			issuedBy = jsString(identity.Get("id"))
		}
		issued, err := IssueCredential(ctx, server, tx, IssueCredentialInput{
			Tenant:           tenant,
			Type:             typeValue,
			Identity:         identity,
			HolderJwk:        holder.Jwk,
			HolderThumbprint: holder.Thumbprint,
			Via:              "offer",
			ActorID:          jsString(identity.Get("id")),
			IssuedBy:         issuedBy,
			SelfService:      truthy(offer.Get("selfService")),
			Mfa:              offer.Get("mfa"),
			OfferID:          jsString(offer.Get("id")),
			Deadline:         deadline,
		})
		if err != nil {
			if known, ok := asIamError(err); ok {
				return refuse(400, "invalid_credential_request", known.Message, core.JSLower(known.Code))
			}
			return nil, err
		}
		rest := offer.Spread()
		rest.Delete("accessTokenHash")
		if _, err := tx.Put(ctx, "vcOffers", rest.Spread(core.NewObject("credentialId", issued.Record.Get("id")))); err != nil {
			return nil, err
		}
		// OpenID4VCI 1.0 answers `credentials`; `credential` keeps wallets on the earlier drafts working.
		return vcJSON(200, core.NewObject("credentials", []any{core.NewObject("credential", issued.Credential)}, "credential", issued.Credential)), nil
	})
}

// VcRuntime is api/verifiable-credentials.ts createVcRuntime(): `iam.verifiableCredentials`, server-side
// verification and the scheduler job, no credential.
type VcRuntime struct {
	server *ServerContext
	// Enabled Whether the `verifiableCredentials` option is on.
	Enabled bool
}

// Verify (api/verifiable-credentials.ts createVcRuntime().verify): Verifies a presentation of a credential this
// deployment issued; fails with *SdJwtError with the reason. options is `{ audience?, nonce?, tenantId?,
// requireKeyBinding? }` (nil for none).
func (s *VcRuntime) Verify(ctx context.Context, presentation string, options *core.Object) (*core.Object, error) {
	return VerifyLocalPresentation(ctx, s.server, presentation, options)
}

// Sweep (api/verifiable-credentials.ts createVcRuntime().sweep): Revokes credentials of people who are no longer
// active members (run hourly).
func (s *VcRuntime) Sweep(ctx context.Context, input *core.Object) (*core.Object, error) {
	return SweepCredentials(ctx, s.server, input)
}

// Nonce (api/verifiable-credentials.ts createVcRuntime().nonce): A holder-proof nonce for a tenant, for applications
// embedding their own wallet flow.
func (s *VcRuntime) Nonce(tenantID string) string {
	return CreateNonce(s.server, tenantID)
}

// Issuer (api/verifiable-credentials.ts createVcRuntime().issuer): The tenant's issuer identifier.
func (s *VcRuntime) Issuer(tenantID string) string {
	return IssuerURL(s.server, tenantID)
}

// CreateVcRuntime builds the VcRuntime (api/verifiable-credentials.ts createVcRuntime).
func CreateVcRuntime(server *ServerContext) *VcRuntime {
	options, err := VcOptions(server)
	return &VcRuntime{server: server, Enabled: err == nil && options != nil}
}
