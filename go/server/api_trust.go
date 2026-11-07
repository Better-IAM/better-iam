package server

// Port of packages/server/src/api/trust.ts: trust relationships for temporary role assumption (identity trusts,
// platform-controlled, and web-identity trusts, tenant-managed), linked accounts for account switchers, and root
// administrators.

import (
	"context"
	"math"
	"reflect"
	"regexp"
	"sort"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

var sourceIdentityModes = []string{"forbidden", "optional", "required"}
var identityOnlyFields = []string{"requireMfa", "allowedTagKeys", "sourceIdentityMode"}
var webOnlyFields = []string{"conditions", "tagClaims", "sourceIdentityClaim"}

// identityCreateFields and webCreateFields are the fields `trust.create` accepts only for identity trusts, and only
// for web-identity trusts.
var identityCreateFields = []string{"sourceTenantId", "sourceIdentityId", "requireMfa", "externalId", "allowedTagKeys", "sourceIdentityMode"}
var webCreateFields = []string{"providerId", "serviceAccountId", "conditions", "tagClaims", "sourceIdentityClaim"}

const maxTagClaims = 10

// defaultMaxSessionSeconds is the duration cap of a trust without `maxSessionSeconds`.
const defaultMaxSessionSeconds = 3600.0

// webIdentityTokenShape is /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$/.
var webIdentityTokenShape = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$`)

func webIdentityDisabled() *core.IamError {
	return core.NewIamError("FEATURE_DISABLED", "Web identity federation is not enabled", 403)
}

// spreadMembers is `{ ...value }` for a stored value: an object's own members, an array's or a string's indexed
// elements, nothing for anything else.
func spreadMembers(value any) *core.Object {
	switch typed := value.(type) {
	case *core.Object:
		if typed != nil {
			return typed.Spread()
		}
	case []any:
		out := core.NewObject()
		for index, item := range typed {
			out.Set(core.NumberString(float64(index)), item)
		}
		return out
	case string:
		out := core.NewObject()
		for index, unit := range utf16Units(typed) {
			out.Set(core.NumberString(float64(index)), unit)
		}
		return out
	}
	return core.NewObject()
}

// utf16Units splits a string into its UTF-16 code units as strings (what spreading a string yields per index: lone
// surrogates stay one unit each, encoded as the replacement character).
func utf16Units(s string) []string {
	var units []string
	for _, r := range s {
		if r > 0xFFFF {
			units = append(units, "�", "�")
			continue
		}
		units = append(units, string(r))
	}
	return units
}

// PublicTrustOf (api/trust.ts publicTrust) is a trust as the API returns it: an allowlist projection that never carries
// the external ID hash, reports whether an external ID is required, and reads legacy records (no kind) as identity
// trusts.
func PublicTrustOf(trust *core.Object) *core.Object {
	kind := "identity"
	if trust.Get("kind") == "web-identity" {
		kind = "web-identity"
	}
	_, hasExternalID := trust.Get("externalIdHash").(string)
	result := core.NewObject(
		"id", trust.Get("id"),
		"tenantId", trust.Get("tenantId"),
		"kind", kind,
		"sourceTenantId", trust.Get("sourceTenantId"),
		"sourceIdentityId", trust.Get("sourceIdentityId"),
		"roleId", trust.Get("roleId"),
		"requireMfa", trust.Get("requireMfa"),
		"requiresExternalId", hasExternalID,
		"revoked", trust.Get("revoked"),
	)
	if value := trust.Get("ceiling"); !isUndefined(value) {
		result.Set("ceiling", core.CloneValue(value))
	}
	if value := trust.Get("maxSessionSeconds"); !isUndefined(value) {
		result.Set("maxSessionSeconds", value)
	}
	if value := trust.Get("passSourceAttributes"); !isUndefined(value) {
		result.Set("passSourceAttributes", value)
	}
	// A malformed stored value (not a list) is left out rather than failing the whole projection.
	if keys, ok := trust.Get("allowedTagKeys").([]any); ok {
		result.Set("allowedTagKeys", append([]any{}, keys...))
	}
	if value := trust.Get("sourceIdentityMode"); !isUndefined(value) {
		result.Set("sourceIdentityMode", value)
	}
	if value := trust.Get("sessionsRevokedBefore"); !isUndefined(value) {
		result.Set("sessionsRevokedBefore", value)
	}
	if value := trust.Get("providerId"); !isUndefined(value) {
		result.Set("providerId", value)
	}
	if value := trust.Get("conditions"); !isUndefined(value) {
		result.Set("conditions", core.CloneValue(value))
	}
	if value := trust.Get("tagClaims"); !isUndefined(value) {
		result.Set("tagClaims", spreadMembers(value))
	}
	for _, key := range []string{"sourceIdentityClaim", "authorityId", "description", "createdAt", "createdBy", "updatedAt"} {
		if value := trust.Get(key); !isUndefined(value) {
			result.Set(key, value)
		}
	}
	return result
}

// maxSessionSecondsValue is the longest role session a trust issues: 60 up to the deployment's
// `sts.maxRoleSessionSeconds`.
func maxSessionSecondsValue(server *ServerContext, value any) (float64, error) {
	ceiling := float64(server.Config.Sts.MaxRoleSessionSeconds)
	number, ok := core.Normalize(value).(float64)
	if !ok || !core.IsSafeInteger(number) || number < 60 || number > ceiling {
		return 0, invalidInput("maxSessionSeconds must be an integer from 60 to " + core.NumberString(ceiling))
	}
	return number, nil
}

func booleanValue(value any, name string) (bool, error) {
	flag, ok := value.(bool)
	if !ok {
		return false, invalidInput(name + " must be a boolean")
	}
	return flag, nil
}

func sourceIdentityModeValue(value any) (string, error) {
	mode, ok := value.(string)
	if !ok || !containsString(sourceIdentityModes, mode) {
		return "", invalidInput("sourceIdentityMode must be 'forbidden', 'optional' or 'required'")
	}
	return mode, nil
}

// WebTrustTagClaims (api/trust.ts webTrustTagClaims) is a web-identity trust's claim-to-tag mapping: at most 10
// entries, each a session tag key (unique case-insensitively) mapped to a flattened claim name (`token.<claim>`).
func WebTrustTagClaims(value any) (*core.Object, error) {
	object, ok := value.(*core.Object)
	if !ok || object == nil {
		return nil, invalidInput("tagClaims must map session tag keys to token.<claim> names")
	}
	if object.Len() > maxTagClaims {
		return nil, invalidInput("tagClaims may contain at most " + core.NumberString(maxTagClaims) + " entries")
	}
	seen := map[string]bool{}
	mapping := core.NewObject()
	for _, key := range object.Keys() {
		if !TagKeyPattern.MatchString(key) {
			return nil, invalidInput("Tag keys must start with a letter and use at most 64 letters, digits or underscores")
		}
		folded := core.JSLower(key)
		if seen[folded] {
			return nil, invalidInput("Tag key " + key + " is repeated (tag keys are case-insensitive)")
		}
		seen[folded] = true
		claim, err := WebIdentityClaimName(object.Get(key))
		if err != nil {
			return nil, err
		}
		mapping.Set(key, claim)
	}
	return mapping, nil
}

// trustCanonical is JSON with object keys sorted, so equal values compare equal whatever their key order.
func trustCanonical(value any) string {
	return core.CanonicalJSON(value)
}

// sameTagKeys compares tag key lists as sets. A stored value that is not a list (malformed) reads as no keys.
func sameTagKeys(a, b any) bool {
	keys := func(value any) []any {
		list, ok := value.([]any)
		if !ok {
			return []any{}
		}
		sorted := append([]any{}, list...)
		sort.SliceStable(sorted, func(i, j int) bool { return jsDefaultSortLess(sorted[i], sorted[j]) })
		return sorted
	}
	return trustCanonical(keys(a)) == trustCanonical(keys(b))
}

// jsDefaultSortLess is Array.prototype.sort's default order: undefined last, everything else by String(value) in
// UTF-16 code unit order.
func jsDefaultSortLess(a, b any) bool {
	if isUndefined(a) {
		return false
	}
	if isUndefined(b) {
		return true
	}
	return compareUTF16(jsString(a), jsString(b)) < 0
}

// jsStrictEqual is JavaScript `a === b` for model values: primitives by value, objects and arrays by identity.
func jsStrictEqual(a, b any) bool {
	switch left := a.(type) {
	case []any:
		right, ok := b.([]any)
		if !ok {
			return false
		}
		if left == nil || right == nil {
			return left == nil && right == nil
		}
		return reflect.ValueOf(left).Pointer() == reflect.ValueOf(right).Pointer() && len(left) == len(right)
	case *core.Object:
		right, ok := b.(*core.Object)
		return ok && left == right
	case float64:
		right, ok := b.(float64)
		return ok && left == right
	case string, bool, nil, core.UndefinedType:
		if _, ok := b.([]any); ok {
			return false
		}
		if _, ok := b.(*core.Object); ok {
			return false
		}
		return a == b
	}
	return false
}

// assertTrustManager says who may manage a trust: identity trusts (a named source identity, possibly in another
// tenant) stay platform-controlled and need a root principal; web-identity trusts are tenant-managed and editable by
// their creator's authority (`canEditGrantResource`). Refusals are audited denials.
func assertTrustManager(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, trust *core.Object) error {
	if trust.Get("kind") == "web-identity" {
		return server.CanEditGrantResource(ctx, tx, principal, trust)
	}
	root, err := server.RootPrincipal(ctx, tx, principal)
	if err != nil {
		return err
	}
	if !root {
		return NewOperationDenied("Only a root administrator can manage identity trusts")
	}
	return nil
}

// assertServiceAccountControl: a web-identity trust hands its workloads the service account it names, so creating or
// changing one needs authority over that account: iam:identities:update on it, the permission
// `serviceAccounts.update` and `setStatus` manage service accounts with. Otherwise a trust administrator could act as
// any service account of the tenant. The refusal is an audited denial (ACCESS_DENIED).
func assertServiceAccountControl(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID, accountID string) error {
	decision, err := server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
		TenantID: tenantID, Action: "iam:identities:update", Resource: ResourceTarget{Type: "iam", ID: accountID},
	}, true)
	if err != nil {
		return err
	}
	if !decision.Allowed {
		return NewOperationDenied("Binding a service account to a web-identity trust requires iam:identities:update on it")
	}
	return nil
}

// TrustAPI is the `trust` API group (packages/server/src/api/trust.ts createTrustApi): every method runs through the
// operation envelope; the router maps POST {basePath}/trust/{method} onto it.
type TrustAPI struct {
	server *ServerContext
}

// CreateTrustAPI builds the `trust` API group.
func CreateTrustAPI(server *ServerContext) *TrustAPI {
	return &TrustAPI{server: server}
}

// createWebTrust is `trust.create` for web-identity trusts: tenant-managed (iam:trust:create on the role, not
// root-only), recent authentication, the feature gate first. The role must not be protected, the provider must belong
// to the tenant, and the service account must be active and unexpired, with the caller holding iam:identities:update
// on it (ACCESS_DENIED otherwise). The trust records the creator's grant authority, which bounds its sessions
// (`credentialAuthorityId`) and is the only authority that may edit it besides root.
func (api *TrustAPI) createWebTrust(ctx context.Context, credential core.CredentialInput, input In[apitypes.TrustCreateInput]) (*core.Object, error) {
	server := api.server
	if !server.Config.Sts.WebIdentity.Enabled {
		return nil, webIdentityDisabled()
	}
	for _, field := range identityCreateFields {
		if !isUndefined(input.Get(field)) {
			return nil, invalidInput(field + " applies only to identity trusts")
		}
	}
	providerID, err := Text(input.Get("providerId"), "providerId")
	if err != nil {
		return nil, err
	}
	serviceAccountID, err := Text(input.Get("serviceAccountId"), "serviceAccountId")
	if err != nil {
		return nil, err
	}
	conditions, err := WebIdentityConditions(input.Get("conditions"))
	if err != nil {
		return nil, err
	}
	var tagClaims *core.Object
	if !isUndefined(input.Get("tagClaims")) {
		if tagClaims, err = WebTrustTagClaims(input.Get("tagClaims")); err != nil {
			return nil, err
		}
	}
	var sourceIdentityClaim *string
	if !isUndefined(input.Get("sourceIdentityClaim")) {
		claim, err := WebIdentityClaimName(input.Get("sourceIdentityClaim"))
		if err != nil {
			return nil, err
		}
		sourceIdentityClaim = &claim
	}
	var maxSessionSeconds *float64
	if !isUndefined(input.Get("maxSessionSeconds")) {
		seconds, err := maxSessionSecondsValue(server, input.Get("maxSessionSeconds"))
		if err != nil {
			return nil, err
		}
		maxSessionSeconds = &seconds
	}
	passSourceAttributes := true
	if !isUndefined(input.Get("passSourceAttributes")) {
		if passSourceAttributes, err = booleanValue(input.Get("passSourceAttributes"), "passSourceAttributes"); err != nil {
			return nil, err
		}
	}
	var description *string
	if !isUndefined(input.Get("description")) {
		text, err := Text(input.Get("description"), "description", 512)
		if err != nil {
			return nil, err
		}
		description = &text
	}
	tenantID, roleID := input.Get("tenantId"), input.Get("roleId")
	return Operate(ctx, server.Operations, credential, tenantID, "iam:trust:create", jsString(roleID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		tenant := jsString(tenantID)
		role, err := server.Scoped(ctx, tx, "roles", roleID, tenant)
		if err != nil {
			return nil, err
		}
		if truthy(role.Get("protected")) {
			return nil, core.NewIamError("PROTECTED_RESOURCE", "Cannot assume protected owner roles")
		}
		if _, err := server.Scoped(ctx, tx, "oidcProviders", providerID, tenant); err != nil {
			return nil, err
		}
		account, err := server.Scoped(ctx, tx, "identities", serviceAccountID, tenant)
		if err != nil {
			return nil, err
		}
		if account.Get("kind") != "service" || account.Get("status") != "active" || server.IdentityExpired(account) {
			return nil, core.NewIamError("INVALID_IDENTITY", "Web-identity trusts require an active service account")
		}
		if err := assertServiceAccountControl(ctx, server, tx, principal, tenant, jsString(account.Get("id"))); err != nil {
			return nil, err
		}
		ceiling := input.Get("ceiling")
		if truthy(ceiling) {
			if err := server.Catalog.Validate(ctx, tx, tenant, ceiling); err != nil {
				return nil, err
			}
		}
		authority, err := server.GrantingAuthority(ctx, tx, principal, tenant, "")
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		trust := core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"kind", "web-identity",
			"sourceTenantId", tenantID,
			"sourceIdentityId", account.Get("id"),
			"roleId", role.Get("id"),
			"requireMfa", false,
			"ceiling", coalesce(ceiling, All()),
			"revoked", false,
			"passSourceAttributes", passSourceAttributes,
			"providerId", providerID,
			"conditions", conditions,
			"authorityId", authority.Get("id"),
			"createdAt", now,
			"createdBy", principal.Identity.Get("id"),
			"updatedAt", now,
		)
		if tagClaims != nil {
			trust.Set("tagClaims", tagClaims)
		}
		if sourceIdentityClaim != nil {
			trust.Set("sourceIdentityClaim", *sourceIdentityClaim)
		}
		if maxSessionSeconds != nil {
			trust.Set("maxSessionSeconds", *maxSessionSeconds)
		}
		if description != nil {
			trust.Set("description", *description)
		}
		stored, err := tx.Insert(ctx, "trusts", trust)
		if err != nil {
			return nil, err
		}
		return PublicTrustOf(stored), nil
	}, false)
}

// Create is POST {basePath}/trust/create. Creates a trust. Identity trusts are platform-controlled: they establish
// exact source-identity to target-role trust for temporary role assumption (root only, recent authentication).
// Defaults: MFA required, no ceiling beyond the role, a 3600 s session cap, no session tags, source identity
// forbidden, and source attributes passed only for same-tenant trusts. Web-identity trusts (`kind: 'web-identity'`)
// admit the tokens of an OIDC provider that satisfy their claim conditions.
func (api *TrustAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.TrustCreateInput]) (Out[apitypes.TrustCreateOutput], error) {
	server := api.server
	if input.Get("kind") == "web-identity" {
		result, err := api.createWebTrust(ctx, credential, input)
		return Out[apitypes.TrustCreateOutput]{Value: result}, err
	}
	fail := func(err error) (Out[apitypes.TrustCreateOutput], error) {
		return Out[apitypes.TrustCreateOutput]{}, err
	}
	kind := input.Get("kind")
	if !isUndefined(kind) && kind != "identity" {
		return fail(invalidInput("kind must be 'identity' or 'web-identity'"))
	}
	for _, field := range webCreateFields {
		if !isUndefined(input.Get(field)) {
			return fail(invalidInput(field + " applies only to web-identity trusts"))
		}
	}
	if !isUndefined(input.Get("requireMfa")) {
		if _, err := booleanValue(input.Get("requireMfa"), "requireMfa"); err != nil {
			return fail(err)
		}
	}
	externalID := input.Get("externalId")
	if !isUndefined(externalID) {
		if _, ok := externalID.(string); !ok {
			return fail(invalidInput("externalId must be a string"))
		}
	}
	var maxSessionSeconds *float64
	if !isUndefined(input.Get("maxSessionSeconds")) {
		seconds, err := maxSessionSecondsValue(server, input.Get("maxSessionSeconds"))
		if err != nil {
			return fail(err)
		}
		maxSessionSeconds = &seconds
	}
	tenantID, roleID := input.Get("tenantId"), input.Get("roleId")
	sourceTenantID, sourceIdentityID := input.Get("sourceTenantId"), input.Get("sourceIdentityId")
	var passSourceAttributes bool
	if isUndefined(input.Get("passSourceAttributes")) {
		passSourceAttributes = jsStrictEqual(sourceTenantID, tenantID)
	} else {
		var err error
		if passSourceAttributes, err = booleanValue(input.Get("passSourceAttributes"), "passSourceAttributes"); err != nil {
			return fail(err)
		}
	}
	allowedTagKeys := []any{}
	if !isUndefined(input.Get("allowedTagKeys")) {
		keys, err := AllowedTagKeysValue(input.Get("allowedTagKeys"))
		if err != nil {
			return fail(err)
		}
		allowedTagKeys = stringsOf(keys)
	}
	sourceIdentityMode := "forbidden"
	if !isUndefined(input.Get("sourceIdentityMode")) {
		mode, err := sourceIdentityModeValue(input.Get("sourceIdentityMode"))
		if err != nil {
			return fail(err)
		}
		sourceIdentityMode = mode
	}
	var description *string
	if !isUndefined(input.Get("description")) {
		text, err := Text(input.Get("description"), "description", 512)
		if err != nil {
			return fail(err)
		}
		description = &text
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:trust:create", jsString(roleID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		role, err := server.Scoped(ctx, tx, "roles", roleID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		if truthy(role.Get("protected")) {
			return nil, core.NewIamError("PROTECTED_RESOURCE", "Cannot assume protected owner roles")
		}
		sourceTenant, _ := sourceTenantID.(string)
		if _, err := server.Scoped(ctx, tx, "identities", sourceIdentityID, sourceTenant); err != nil {
			return nil, err
		}
		ceiling := input.Get("ceiling")
		if truthy(ceiling) {
			if err := server.Catalog.Validate(ctx, tx, jsString(tenantID), ceiling); err != nil {
				return nil, err
			}
		}
		now := float64(server.Now())
		trust := core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"kind", "identity",
			"sourceTenantId", sourceTenantID,
			"sourceIdentityId", sourceIdentityID,
			"roleId", roleID,
			"requireMfa", coalesce(input.Get("requireMfa"), true),
			"ceiling", coalesce(ceiling, All()),
			"revoked", false,
			"passSourceAttributes", passSourceAttributes,
			"allowedTagKeys", allowedTagKeys,
			"sourceIdentityMode", sourceIdentityMode,
			"createdAt", now,
			"createdBy", principal.Identity.Get("id"),
			"updatedAt", now,
		)
		if truthy(externalID) {
			trust.Set("externalIdHash", Hash(externalID.(string)))
		}
		if maxSessionSeconds != nil {
			trust.Set("maxSessionSeconds", *maxSessionSeconds)
		}
		if description != nil {
			trust.Set("description", *description)
		}
		stored, err := tx.Insert(ctx, "trusts", trust)
		if err != nil {
			return nil, err
		}
		return PublicTrustOf(stored), nil
	}, true)
	return Out[apitypes.TrustCreateOutput]{Value: result}, err
}

// EvaluateWebIdentity is POST {basePath}/trust/evaluateWebIdentity. Dry run of AssumeRoleWithWebIdentity for
// administrators (iam:trust:read on the trust, web identity enabled): verifies a token against the trust's provider,
// evaluates the claim conditions (listing each unmet entry) and the claim mappings, and reports why the exchange would
// refuse it, stored-state causes included. Nothing is issued and no replay record is written, so the token stays
// redeemable. Web-identity trusts only (INVALID_INPUT otherwise).
func (api *TrustAPI) EvaluateWebIdentity(ctx context.Context, credential core.CredentialInput, input In[apitypes.TrustEvaluateWebIdentityInput]) (Out[apitypes.TrustEvaluateWebIdentityOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.TrustEvaluateWebIdentityOutput], error) {
		return Out[apitypes.TrustEvaluateWebIdentityOutput]{}, err
	}
	if !server.Config.Sts.WebIdentity.Enabled {
		return fail(webIdentityDisabled())
	}
	trustID, err := Text(input.Get("trustId"), "trustId")
	if err != nil {
		return fail(err)
	}
	// The same size bound as the public exchange, before anything is parsed or verified.
	token, ok := input.Get("webIdentityToken").(string)
	if !ok || utf16Len(token) > 8192 {
		return fail(invalidInput("webIdentityToken must be a compact JWT of at most 8192 characters"))
	}
	wellFormed := webIdentityTokenShape.MatchString(token)
	tenantID := input.Get("tenantId")
	type located struct {
		trust    *core.Object
		provider *core.Object
	}
	// Authorized on the trust before it is read, so the answer reveals nothing to callers without the permission.
	found, err := Operate(ctx, server.Operations, credential, tenantID, "iam:trust:read", trustID, func(ctx context.Context, call MutationContext) (*located, error) {
		trust, err := server.Scoped(ctx, call.Tx, "trusts", trustID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		providerID, isText := trust.Get("providerId").(string)
		if trust.Get("kind") != "web-identity" || !isText {
			return nil, invalidInput("Only web-identity trusts evaluate web identity tokens")
		}
		provider, err := server.Scoped(ctx, call.Tx, "oidcProviders", providerID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		return &located{trust: trust, provider: provider}, nil
	}, false)
	if err != nil {
		return fail(err)
	}
	// A value that is not a compact JWS never reaches the verifier.
	if !wellFormed {
		return Out[apitypes.TrustEvaluateWebIdentityOutput]{Value: core.NewObject("verified", false, "reason", "malformed")}, nil
	}
	// Outside the transaction: verification may fetch the provider's keys.
	result, err := EvaluateWebIdentity(ctx, server, core.NewObject("trust", found.trust, "provider", found.provider, "token", token))
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.TrustEvaluateWebIdentityOutput]{Value: result}, nil
}

// List is POST {basePath}/trust/list. Trust relationships targeting this tenant's roles, as PublicTrust (external ID
// hashes are never returned).
func (api *TrustAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.TrustListInput]) (Out[apitypes.TrustListOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:trust:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		trusts, err := call.Tx.Find(ctx, "trusts", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		includeRevoked := input.Get("includeRevoked") == true
		list := []any{}
		for _, trust := range trusts {
			if includeRevoked || !truthy(trust.Get("revoked")) {
				list = append(list, PublicTrustOf(trust))
			}
		}
		return list, nil
	}, false)
	return Out[apitypes.TrustListOutput]{Value: result}, err
}

// Revoke is POST {basePath}/trust/revoke. Permanently revokes a trust and deletes its live role sessions (recent
// authentication; identity trusts need a root principal, web-identity trusts their creator's authority). Revoking
// only removes access, so it works for web-identity trusts while `sts.webIdentity.enabled` is off (their provider can
// then be deleted).
func (api *TrustAPI) Revoke(ctx context.Context, credential core.CredentialInput, input In[apitypes.TrustRevokeInput]) (Out[apitypes.TrustRevokeOutput], error) {
	server := api.server
	tenantID, trustID := input.Get("tenantId"), input.Get("trustId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:trust:revoke", jsString(trustID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		trust, err := server.Scoped(ctx, tx, "trusts", trustID, jsString(tenantID))
		if err != nil {
			return nil, err
		}
		if err := assertTrustManager(ctx, server, tx, principal, trust); err != nil {
			return nil, err
		}
		if _, err := DeleteTemporarySessions(ctx, tx, core.NewObject(
			"tenantId", trust.Get("tenantId"),
			"roleId", trust.Get("roleId"),
			"trustId", trust.Get("id"),
			"createdBefore", math.Inf(1),
		)); err != nil {
			return nil, err
		}
		stored, err := tx.Put(ctx, "trusts", trust.Spread(core.NewObject("revoked", true, "updatedAt", float64(server.Now()))))
		if err != nil {
			return nil, err
		}
		return PublicTrustOf(stored), nil
	}, false)
	return Out[apitypes.TrustRevokeOutput]{Value: result}, err
}

// RevokeSessions is POST {basePath}/trust/revokeSessions. Revokes the trust's role sessions issued before `before`
// (default: every session so far): moves the trust's `sessionsRevokedBefore` watermark forward and deletes the
// matching rows. Delegated like `roles.revokeSessions` (iam:roles:revoke-sessions on the trust's role, recent
// authentication), so a target tenant's administrators can end sessions under platform-controlled trusts. Audited as
// `role:sessions-revoked`.
func (api *TrustAPI) RevokeSessions(ctx context.Context, credential core.CredentialInput, input In[apitypes.TrustRevokeSessionsInput]) (Out[apitypes.TrustRevokeSessionsOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.TrustRevokeSessionsOutput], error) {
		return Out[apitypes.TrustRevokeSessionsOutput]{}, err
	}
	// The action targets the trust's role, so the trust is pre-read with ctx.scoped, as roles.assume does (after the
	// credential is verified, so anonymous callers cannot probe trust ids): a missing or foreign trust is NOT_FOUND
	// (spec F2).
	if _, err := server.Principals.Authenticate(ctx, credential); err != nil {
		return fail(err)
	}
	trustID, err := Text(input.Get("trustId"), "trustId")
	if err != nil {
		return fail(err)
	}
	tenantID := input.Get("tenantId")
	tenantKey, _ := tenantID.(string)
	requested, err := server.Scoped(ctx, server.Store, "trusts", trustID, tenantKey)
	if err != nil {
		return fail(err)
	}
	resourceID := requested.Get("roleId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:roles:revoke-sessions", jsString(resourceID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		trust, err := server.Scoped(ctx, tx, "trusts", trustID, tenantKey)
		if err != nil {
			return nil, err
		}
		// Authorized for another resource than this trust's role (it changed since the pre-read).
		if !jsStrictEqual(trust.Get("roleId"), resourceID) {
			return nil, core.NewIamError("NOT_FOUND", "Resource not found", 404)
		}
		sessionsRevokedBefore, err := NextWatermark(trust.Get("sessionsRevokedBefore"), input.Get("before"), float64(server.Now()))
		if err != nil {
			return nil, err
		}
		if _, err := tx.Put(ctx, "trusts", trust.Spread(core.NewObject("sessionsRevokedBefore", sessionsRevokedBefore))); err != nil {
			return nil, err
		}
		revoked, err := DeleteTemporarySessions(ctx, tx, core.NewObject(
			"tenantId", trust.Get("tenantId"),
			"roleId", trust.Get("roleId"),
			"trustId", trust.Get("id"),
			"createdBefore", sessionsRevokedBefore,
		))
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "role:sessions-revoked", tenantKey, jsString(trust.Get("id")), "allow", false,
			core.NewObject("sessionsRevokedBefore", sessionsRevokedBefore, "revoked", revoked)); err != nil {
			return nil, err
		}
		return core.NewObject("trustId", trust.Get("id"), "sessionsRevokedBefore", sessionsRevokedBefore, "revoked", revoked), nil
	}, false)
	return Out[apitypes.TrustRevokeSessionsOutput]{Value: result}, err
}

// Update is POST {basePath}/trust/update. Changes a trust's knobs (recent authentication; identity trusts need a root
// principal, web-identity trusts their creator's authority and iam:identities:update on their service account).
// Tightening what a trust admits (tag keys, source identity mode, claim conditions or mappings, or a lower session
// cap) also revokes the sessions issued under the old rules, through the trust's `sessionsRevokedBefore` watermark. A
// revoked trust is CONFLICT; an update that changes nothing is INVALID_INPUT.
func (api *TrustAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.TrustUpdateInput]) (Out[apitypes.TrustUpdateOutput], error) {
	server := api.server
	tenantID, trustID := input.Get("tenantId"), input.Get("trustId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:trust:update", jsString(trustID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		tenant := jsString(tenantID)
		trust, err := server.Scoped(ctx, tx, "trusts", trustID, tenant)
		if err != nil {
			return nil, err
		}
		web := trust.Get("kind") == "web-identity"
		if web && !server.Config.Sts.WebIdentity.Enabled {
			return nil, core.NewIamError("FEATURE_DISABLED", "Web identity federation is not enabled", 403)
		}
		if err := assertTrustManager(ctx, server, tx, principal, trust); err != nil {
			return nil, err
		}
		if truthy(trust.Get("revoked")) {
			return nil, core.NewIamError("CONFLICT", "The trust is revoked", 409)
		}
		// Changing what a web-identity trust admits changes who acts as its service account.
		if web {
			if err := assertServiceAccountControl(ctx, server, tx, principal, tenant, jsString(trust.Get("sourceIdentityId"))); err != nil {
				return nil, err
			}
		}
		foreign, other := webOnlyFields, "web-identity"
		if web {
			foreign, other = identityOnlyFields, "identity"
		}
		for _, field := range foreign {
			if !isUndefined(input.Get(field)) {
				return nil, invalidInput(field + " applies only to " + other + " trusts")
			}
		}
		next := trust.Spread()
		if value := input.Get("requireMfa"); !isUndefined(value) {
			flag, err := booleanValue(value, "requireMfa")
			if err != nil {
				return nil, err
			}
			next.Set("requireMfa", flag)
		}
		if value := input.Get("ceiling"); value == nil {
			next.Set("ceiling", All())
		} else if !isUndefined(value) {
			if err := server.Catalog.Validate(ctx, tx, tenant, value); err != nil {
				return nil, err
			}
			next.Set("ceiling", value)
		}
		if value := input.Get("maxSessionSeconds"); value == nil {
			next.Delete("maxSessionSeconds")
		} else if !isUndefined(value) {
			seconds, err := maxSessionSecondsValue(server, value)
			if err != nil {
				return nil, err
			}
			next.Set("maxSessionSeconds", seconds)
		}
		if value := input.Get("passSourceAttributes"); !isUndefined(value) {
			flag, err := booleanValue(value, "passSourceAttributes")
			if err != nil {
				return nil, err
			}
			next.Set("passSourceAttributes", flag)
		}
		if value := input.Get("allowedTagKeys"); value == nil {
			next.Set("allowedTagKeys", []any{})
		} else if !isUndefined(value) {
			keys, err := AllowedTagKeysValue(value)
			if err != nil {
				return nil, err
			}
			next.Set("allowedTagKeys", stringsOf(keys))
		}
		if value := input.Get("sourceIdentityMode"); !isUndefined(value) {
			mode, err := sourceIdentityModeValue(value)
			if err != nil {
				return nil, err
			}
			next.Set("sourceIdentityMode", mode)
		}
		if value := input.Get("description"); value == nil {
			next.Delete("description")
		} else if !isUndefined(value) {
			text, err := Text(value, "description", 512)
			if err != nil {
				return nil, err
			}
			next.Set("description", text)
		}
		if value := input.Get("conditions"); !isUndefined(value) {
			conditions, err := WebIdentityConditions(value)
			if err != nil {
				return nil, err
			}
			next.Set("conditions", conditions)
		}
		if value := input.Get("tagClaims"); value == nil {
			next.Delete("tagClaims")
		} else if !isUndefined(value) {
			mapping, err := WebTrustTagClaims(value)
			if err != nil {
				return nil, err
			}
			next.Set("tagClaims", mapping)
		}
		if value := input.Get("sourceIdentityClaim"); value == nil {
			next.Delete("sourceIdentityClaim")
		} else if !isUndefined(value) {
			claim, err := WebIdentityClaimName(value)
			if err != nil {
				return nil, err
			}
			next.Set("sourceIdentityClaim", claim)
		}
		if trustCanonical(next) == trustCanonical(trust) {
			return nil, invalidInput("The update changes nothing")
		}
		// Sessions issued under looser rules would keep what the trust no longer admits, so they end.
		tightened := !sameTagKeys(trust.Get("allowedTagKeys"), next.Get("allowedTagKeys")) ||
			!jsStrictEqual(coalesce(trust.Get("sourceIdentityMode"), "forbidden"), coalesce(next.Get("sourceIdentityMode"), "forbidden")) ||
			trustCanonical(coalesce(trust.Get("conditions"), nil)) != trustCanonical(coalesce(next.Get("conditions"), nil)) ||
			trustCanonical(coalesce(trust.Get("tagClaims"), nil)) != trustCanonical(coalesce(next.Get("tagClaims"), nil)) ||
			!jsStrictEqual(coalesce(trust.Get("sourceIdentityClaim"), nil), coalesce(next.Get("sourceIdentityClaim"), nil)) ||
			jsLess(coalesce(next.Get("maxSessionSeconds"), defaultMaxSessionSeconds), coalesce(trust.Get("maxSessionSeconds"), defaultMaxSessionSeconds))
		now := float64(server.Now())
		if tightened {
			watermark, err := NextWatermark(trust.Get("sessionsRevokedBefore"), core.Undefined, now)
			if err != nil {
				return nil, err
			}
			next.Set("sessionsRevokedBefore", watermark)
		}
		next.Set("updatedAt", now)
		stored, err := tx.Put(ctx, "trusts", next)
		if err != nil {
			return nil, err
		}
		return PublicTrustOf(stored), nil
	}, false)
	return Out[apitypes.TrustUpdateOutput]{Value: result}, err
}

// LinksAPI is the `links` API group (packages/server/src/api/trust.ts createLinksApi): every method runs through the
// operation envelope; the router maps POST {basePath}/links/{method} onto it.
type LinksAPI struct {
	server *ServerContext
}

// CreateLinksAPI builds the `links` API group.
func CreateLinksAPI(server *ServerContext) *LinksAPI {
	return &LinksAPI{server: server}
}

// bodyCredential is a credential given in a request body (`{ token }` or `{ headers }`).
func bodyCredential(value any) core.CredentialInput {
	object, _ := value.(*core.Object)
	return quotaRequestCredential(object)
}

// Create is POST {basePath}/links/create. Links the caller's account to another account of theirs in a different
// tenant, proving control of both.
func (api *LinksAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.LinksCreateInput]) (Out[apitypes.LinksCreateOutput], error) {
	result, err := api.server.Flows.LinkIdentities(ctx, credential, bodyCredential(input.Get("targetCredential")))
	if err != nil {
		return Out[apitypes.LinksCreateOutput]{}, err
	}
	return Out[apitypes.LinksCreateOutput]{Value: result}, nil
}

// List is POST {basePath}/links/list. Linked accounts of the current identity, for account-switcher UIs. Switching
// still requires a target credential.
func (api *LinksAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.LinksListInput]) (Out[apitypes.LinksListOutput], error) {
	server := api.server
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.LinksListOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]any, error) {
		current, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		currentID := current.Identity.Get("id")
		left, err := tx.Find(ctx, "identityLinks", core.NewObject("leftId", currentID, "revoked", false), nil)
		if err != nil {
			return nil, err
		}
		right, err := tx.Find(ctx, "identityLinks", core.NewObject("rightId", currentID, "revoked", false), nil)
		if err != nil {
			return nil, err
		}
		links := append(append([]*core.Object{}, left...), right...)
		result := []any{}
		for _, link := range links {
			otherID := link.Get("leftId")
			if jsStrictEqual(link.Get("leftId"), currentID) {
				otherID = link.Get("rightId")
			}
			other, err := tx.Get(ctx, "identities", jsString(otherID))
			if err != nil {
				return nil, err
			}
			var realm *core.Object
			if other != nil {
				if realm, err = tx.Get(ctx, "tenants", jsString(other.Get("tenantId"))); err != nil {
					return nil, err
				}
			}
			if other == nil || realm == nil {
				continue
			}
			result = append(result, core.NewObject(
				"id", link.Get("id"),
				"identityId", other.Get("id"),
				"email", other.Get("email"),
				"name", other.Get("name"),
				"status", other.Get("status"),
				"tenantId", realm.Get("id"),
				"tenantName", realm.Get("name"),
				"tenantSlug", realm.Get("slug"),
				"tenantStatus", realm.Get("status"),
			))
		}
		return result, nil
	})
	if err != nil {
		return Out[apitypes.LinksListOutput]{}, err
	}
	return Out[apitypes.LinksListOutput]{Value: result}, nil
}

// Revoke is POST {basePath}/links/revoke. Removes a link the person no longer wants.
func (api *LinksAPI) Revoke(ctx context.Context, credential core.CredentialInput, input In[apitypes.LinksRevokeInput]) (Out[apitypes.LinksRevokeOutput], error) {
	server := api.server
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.LinksRevokeOutput]{}, err
	}
	if err := server.Auth.RequireRecent(authenticated.Auth()); err != nil {
		return Out[apitypes.LinksRevokeOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		if _, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated); err != nil {
			return nil, err
		}
		var link *core.Object
		if linkID, ok := input.Get("linkId").(string); ok {
			if link, err = tx.Get(ctx, "identityLinks", linkID); err != nil {
				return nil, err
			}
		}
		identityID := authenticated.Identity.Get("id")
		if link == nil || (!jsStrictEqual(link.Get("leftId"), identityID) && !jsStrictEqual(link.Get("rightId"), identityID)) {
			return nil, core.NewIamError("NOT_FOUND", "Link not found", 404)
		}
		if _, err := tx.Put(ctx, "identityLinks", link.Spread(core.NewObject("revoked", true))); err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, authenticated, "identity:unlink", jsString(authenticated.Identity.Get("tenantId")), jsString(link.Get("id")), "allow", false, nil); err != nil {
			return nil, err
		}
		return core.NewObject("revoked", true), nil
	})
	if err != nil {
		return Out[apitypes.LinksRevokeOutput]{}, err
	}
	return Out[apitypes.LinksRevokeOutput]{Value: result}, nil
}

// Switch is POST {basePath}/links/switch. Opens a fresh session for a linked account, using a recently authenticated
// credential for that account.
func (api *LinksAPI) Switch(ctx context.Context, credential core.CredentialInput, input In[apitypes.LinksSwitchInput]) (Out[apitypes.LinksSwitchOutput], error) {
	body := input.Body
	if body == nil {
		body = core.NewObject()
	}
	result, err := api.server.Flows.SwitchIdentity(ctx, credential, body)
	if err != nil {
		return Out[apitypes.LinksSwitchOutput]{}, err
	}
	return Out[apitypes.LinksSwitchOutput]{Value: result}, nil
}

// RootAPI is the `root` API group (packages/server/src/api/trust.ts createRootApi): every method runs through the
// operation envelope; the router maps POST {basePath}/root/{method} onto it.
type RootAPI struct {
	server *ServerContext
}

// CreateRootAPI builds the `root` API group.
func CreateRootAPI(server *ServerContext) *RootAPI {
	return &RootAPI{server: server}
}

// ListAdministrators is POST {basePath}/root/listAdministrators. Lists the identities that hold the root capability.
func (api *RootAPI) ListAdministrators(ctx context.Context, credential core.CredentialInput, input In[apitypes.RootListAdministratorsInput]) (Out[apitypes.RootListAdministratorsOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:identities:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		realm := call.Tenant
		if realm.Get("parentId") != nil {
			return nil, invalidInput("Root administrators belong to the root tenant")
		}
		identities, err := call.Tx.Find(ctx, "identities", core.NewObject("tenantId", realm.Get("id"), "rootAdmin", true), nil)
		if err != nil {
			return nil, err
		}
		list := make([]any, len(identities))
		for index, identity := range identities {
			list[index] = PublicIdentity(identity)
		}
		return list, nil
	}, true)
	return Out[apitypes.RootListAdministratorsOutput]{Value: result}, err
}

// SetAdministrator is POST {basePath}/root/setAdministrator. Grants or removes the protected root capability; only
// root administrators may call it.
func (api *RootAPI) SetAdministrator(ctx context.Context, credential core.CredentialInput, input In[apitypes.RootSetAdministratorInput]) (Out[apitypes.RootSetAdministratorOutput], error) {
	server := api.server
	tenantID, identityID := input.Get("tenantId"), input.Get("identityId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:root:grant", jsString(identityID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, principal, realm := call.Tx, call.Principal, call.Tenant
		if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
			return nil, err
		}
		enabled, isBool := input.Get("enabled").(bool)
		if realm.Get("parentId") != nil || !isBool {
			return nil, invalidInput("Root administrator must belong to root")
		}
		identity, err := server.Scoped(ctx, tx, "identities", identityID, jsString(realm.Get("id")))
		if err != nil {
			return nil, err
		}
		if identity.Get("kind") != "user" {
			return nil, invalidInput("Root administrators must be users")
		}
		if !enabled {
			if err := server.ProtectLastOwner(ctx, tx, identity); err != nil {
				return nil, err
			}
		}
		if err := server.RevokeAll(ctx, tx, jsString(identity.Get("id"))); err != nil {
			return nil, err
		}
		stored, err := tx.Put(ctx, "identities", identity.Spread(core.NewObject("rootAdmin", enabled)))
		if err != nil {
			return nil, err
		}
		return PublicIdentity(stored), nil
	}, true)
	return Out[apitypes.RootSetAdministratorOutput]{Value: result}, err
}
