package server

// Port of packages/server/src/vc.ts. Verifiable credentials: each tenant is an issuer of SD-JWT VCs (IETF
// SD-JWT-based Verifiable Credentials) that wallets hold and present, with selective disclosure, holder key binding,
// and revocation through a Token Status List. Credential types map identity data (email, name, attributes, teams,
// department, static values) to claims. People get credentials for themselves when policies allow `vc:request` on
// `credential-type/{name}`, through the API or a wallet (OpenID4VCI pre-authorized code flow, served by the protocol
// mount in api_verifiable_credentials.go); administrators issue them for others (`iam:vc:issue`). Verifiers check
// presentations offline with the issuer's keys and status list, or through `iam.verifiableCredentials.verify`.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// ResolvedVcOptions are the validated `verifiableCredentials` options (vc.ts ResolvedVcOptions), in milliseconds
// unless named otherwise.
type ResolvedVcOptions struct {
	MaxLifetimeMs        float64
	StatusListSize       float64
	OfferLifetimeMs      float64
	StatusListLifetimeMs float64
	StatusListTtlSeconds float64
	RecordRetentionMs    float64
}

const (
	vcMinute = 60_000.0
	vcDay    = 86_400_000.0
)

func vcBounded(value *float64, fallback, min, max float64, name string) (float64, error) {
	resolved := fallback
	if value != nil {
		resolved = *value
	}
	if !core.IsSafeInteger(resolved) || resolved < min || resolved > max {
		return 0, invalidConfig("verifiableCredentials." + name + " must be an integer between " +
			core.NumberString(min) + " and " + core.NumberString(max))
	}
	return resolved, nil
}

// ResolveVcOptions is vc.ts resolveVcOptions: nil when the option is off.
func ResolveVcOptions(value *Toggle[VerifiableCredentialOptions]) (*ResolvedVcOptions, error) {
	if !value.IsOn() {
		return nil, nil
	}
	options := VerifiableCredentialOptions{}
	if value.Options != nil {
		options = *value.Options
	}
	size, err := vcBounded(options.StatusListSize, 65536, 1024, 1_048_576, "statusListSize")
	if err != nil {
		return nil, err
	}
	if math.Mod(size, 1024) != 0 {
		return nil, invalidConfig("verifiableCredentials.statusListSize must be a multiple of 1024")
	}
	resolved := &ResolvedVcOptions{StatusListSize: size}
	if resolved.MaxLifetimeMs, err = vcBounded(options.MaxLifetimeMs, 365*vcDay, 5*vcMinute, 5*365*vcDay, "maxLifetimeMs"); err != nil {
		return nil, err
	}
	if resolved.OfferLifetimeMs, err = vcBounded(options.OfferLifetimeMs, 10*vcMinute, vcMinute, vcDay, "offerLifetimeMs"); err != nil {
		return nil, err
	}
	if resolved.StatusListLifetimeMs, err = vcBounded(options.StatusListLifetimeMs, vcDay, 10*vcMinute, 30*vcDay, "statusListLifetimeMs"); err != nil {
		return nil, err
	}
	if resolved.StatusListTtlSeconds, err = vcBounded(options.StatusListTtlSeconds, 300, 10, 86_400, "statusListTtlSeconds"); err != nil {
		return nil, err
	}
	days, err := vcBounded(options.RecordRetentionDays, 30, 1, 3650, "recordRetentionDays")
	if err != nil {
		return nil, err
	}
	resolved.RecordRetentionMs = days * vcDay
	return resolved, nil
}

// VcOptions (vc.ts vcOptions): the resolved options of the deployment, nil when verifiable credentials are off.
func VcOptions(server *ServerContext) (*ResolvedVcOptions, error) {
	return ResolveVcOptions(server.Options.VerifiableCredentials)
}

// AssertVc (vc.ts assertVc): the resolved options, FEATURE_DISABLED (403) when the option is off.
func AssertVc(server *ServerContext) (*ResolvedVcOptions, error) {
	options, err := VcOptions(server)
	if err != nil {
		return nil, err
	}
	if options == nil {
		return nil, core.NewIamError("FEATURE_DISABLED", "Verifiable credentials are not enabled on this deployment", 403)
	}
	return options, nil
}

// CredentialTypeResource is the resource type of credential types (`credential-type/{name}`).
const CredentialTypeResource = "credential-type"

// VcRequestAction is vc.ts vcRequestAction.
const VcRequestAction = "vc:request"

// VcPlugins (vc.ts vcPlugins): the catalog entries the module contributes when enabled (the `credential-type` type and
// `vc:request`); none when it is off.
func VcPlugins(options *BetterIamOptions) ([]*core.IamPlugin, error) {
	resolved, err := ResolveVcOptions(options.VerifiableCredentials)
	if err != nil || resolved == nil {
		return nil, err
	}
	return []*core.IamPlugin{{
		ID: "better-iam:verifiable-credentials",
		ResourceTypes: []core.NamedResourceType{{
			Name: CredentialTypeResource,
			Definition: core.ResourceTypeDefinition{
				Description: "A kind of verifiable credential the organization issues: credential-type/{name}",
				Actions:     []string{VcRequestAction},
				Attributes: []core.NamedAttribute{
					{Name: "name", Type: "string"}, {Name: "vct", Type: "string"}, {Name: "requireMfa", Type: "boolean"},
				},
			},
		}},
	}}, nil
}

// VcCollections is vc.ts vcCollections.
var VcCollections = []string{"vcIssuerKeys", "vcCredentialTypes", "vcIssued", "vcStatusLists", "vcOffers", "vcNonces"}

// IssuerURL (vc.ts issuerUrl): The issuer identifier (and base URL of its endpoints) of a tenant.
func IssuerURL(server *ServerContext, tenantID string) string {
	return vcIssuerPrefix(server) + tenantID
}

// vcIssuerPrefix is `{origin}{basePath}/vc/`.
func vcIssuerPrefix(server *ServerContext) string {
	return urlOrigin(server.Config.BaseURL) + server.Config.BasePath + "/vc/"
}

func vcKeyContext(record *core.Object) string { return "vc-issuer-key:" + jsString(record.Get("id")) }

// vcByCreated orders records by createdAt, then id.
func vcByCreated(a, b *core.Object) int {
	if diff := jsNumber(a.Get("createdAt")) - jsNumber(b.Get("createdAt")); diff != 0 && !math.IsNaN(diff) {
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

// IssuerKeys (vc.ts issuerKeys): the tenant's issuer keys, oldest first.
func IssuerKeys(ctx context.Context, tx core.IamStore, tenantID string) ([]*core.Object, error) {
	keys, err := tx.Find(ctx, "vcIssuerKeys", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	slices.SortStableFunc(keys, vcByCreated)
	return keys, nil
}

// CreateIssuerKey (vc.ts createIssuerKey): a new active ES256 issuer key, its private key sealed with the deployment
// secret.
func CreateIssuerKey(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, actorID string) (*core.Object, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	jwk := core.NewObject("kty", "EC", "crv", "P-256",
		"x", base64url(private.PublicKey.X.FillBytes(make([]byte, 32))),
		"y", base64url(private.PublicKey.Y.FillBytes(make([]byte, 32))))
	kid, err := jwkThumbprint(jwk)
	if err != nil {
		return nil, err
	}
	record := core.NewObject(
		"id", ID(),
		"tenantId", tenantID,
		"uniqueKey", kid,
		"kid", kid,
		"status", "active",
		"alg", "ES256",
		"publicJwk", jwk.Spread(core.NewObject("kid", kid, "alg", "ES256", "use", "sig")),
		"keySealed", "",
		"createdAt", float64(server.Now()),
		"createdBy", actorID,
	)
	der, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		return nil, err
	}
	record.Set("keySealed", auth.EncryptSecret(base64.StdEncoding.EncodeToString(der), server.Options.Secret, vcKeyContext(record)))
	return tx.Insert(ctx, "vcIssuerKeys", record)
}

// ActiveIssuerKey (vc.ts activeIssuerKey): The active signing key, created on first use.
func ActiveIssuerKey(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, actorID string) (*core.Object, error) {
	keys, err := IssuerKeys(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, key := range keys {
		if key.Get("status") == "active" {
			return key, nil
		}
	}
	return CreateIssuerKey(ctx, server, tx, tenantID, actorID)
}

// OpenIssuerKey (vc.ts openIssuerKey): the private signing key of an issuer key record.
func OpenIssuerKey(server *ServerContext, key *core.Object) (*ecdsa.PrivateKey, error) {
	secrets := append([]string{server.Options.Secret}, server.Options.PreviousSecrets...)
	opened, err := auth.DecryptSecret(jsString(key.Get("keySealed")), secrets, vcKeyContext(key))
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParsePKCS8PrivateKey(nodeBase64Decode(opened))
	if err != nil {
		return nil, err
	}
	private, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("The issuer key is not an EC key")
	}
	return private, nil
}

// IssuerJwks (vc.ts issuerJwks): The public keys verifiers accept: active and previous (retired keys verify
// nothing).
func IssuerJwks(ctx context.Context, tx core.IamStore, tenantID string) (*core.Object, error) {
	keys, err := IssuerKeys(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	published := []any{}
	for _, key := range keys {
		if key.Get("status") != "retired" {
			published = append(published, key.Get("publicJwk"))
		}
	}
	return core.NewObject("keys", published), nil
}

// TypeByName (vc.ts typeByName): the tenant's credential type of that name, nil when there is none.
func TypeByName(ctx context.Context, tx core.IamStore, tenantID string, name string) (*core.Object, error) {
	found, err := tx.Find(ctx, "vcCredentialTypes", core.NewObject("tenantId", tenantID, "uniqueKey", name), nil)
	if err != nil || len(found) == 0 {
		return nil, err
	}
	return found[0], nil
}

// TypeResource is vc.ts typeResource: the resource a credential type is decided as.
func TypeResource(typeValue *core.Object) ResolvedResource {
	return ResolvedResource{
		TenantID: jsString(typeValue.Get("tenantId")),
		Type:     CredentialTypeResource,
		ID:       jsString(typeValue.Get("name")),
		Attributes: core.NewObject("name", typeValue.Get("name"), "vct", typeValue.Get("vct"),
			"requireMfa", typeValue.Get("requireMfa")),
	}
}

// ResolveCredentialTypeResource (vc.ts resolveCredentialTypeResource): resolves `credential-type/{name}` for the
// decision engine; nil for other types or when verifiable credentials are off.
func ResolveCredentialTypeResource(ctx context.Context, server *ServerContext, tx core.IamStore, reference core.ResourceRef) (*ResolvedResource, error) {
	if reference.Type != CredentialTypeResource {
		return nil, nil
	}
	options, err := VcOptions(server)
	if err != nil || options == nil {
		return nil, err
	}
	typeValue, err := TypeByName(ctx, tx, reference.TenantID, reference.ID)
	if err != nil {
		return nil, err
	}
	if typeValue == nil {
		return nil, core.NewIamError("NOT_FOUND", "Unknown credential type", 404)
	}
	resource := TypeResource(typeValue)
	return &resource, nil
}

// MayRequest (vc.ts mayRequest): Whether a principal may request a type for themselves (`vc:request`), outside a
// root override from elsewhere.
func MayRequest(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenant *core.Object, typeValue *core.Object) (bool, error) {
	prepared, err := server.Decisions.PrepareDecision(ctx, tx, principal, tenant, VcRequestAction)
	if err != nil {
		return false, err
	}
	if IsRootOverride(prepared) && principal.Identity.Get("tenantId") != tenant.Get("id") {
		return false, nil
	}
	if prepared.Fixed != nil {
		return prepared.Fixed.Allowed, nil
	}
	// With security clearances, the type carries its classification label, as `resolve` attaches it.
	resource := TypeResource(typeValue)
	labeled, err := ModuleResourceLabels(ctx, server, tx, jsString(tenant.Get("id")), []ResolvedResource{resource})
	if err != nil {
		return false, err
	}
	decision, err := DecideOn(prepared, labeled(resource), VcRequestAction)
	if err != nil {
		return false, err
	}
	return decision.Allowed, nil
}

// HolderCleared (vc.ts holderCleared): Whether a person (an agent with its sponsor) is cleared for the
// classification label of credential type `typeName` (security clearances), whatever roles and policies say: what an
// administrator offers or issues still needs the holder to dominate the type's label, at the offer, at redemption,
// and in the sweep. Self-service credentials are decided through `mayRequest`, which applies the label itself. True
// without clearances.
func HolderCleared(ctx context.Context, server *ServerContext, tx core.IamStore, tenant *core.Object, identity *core.Object, typeName string, mfa bool) (bool, error) {
	tenantID := jsString(tenant.Get("id"))
	return ClearedFor(ctx, server, tx, server.Decisions.SimulatedPrincipal(identity, mfa), tenant,
		ResolvedResource{TenantID: tenantID, Type: CredentialTypeResource, ID: typeName}, VcRequestAction)
}

var (
	vcClaimName = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_]{0,63}$`)
	vcSources   = newOrderedSet("email", "emailVerified", "name", "identityId", "kind", "tenantId", "tenantName", "teams", "department", "static")
	// vcStructuralKey finds `"_sd":`, `"_sd_alg":` or `"...":` (JavaScript \s between the key and the colon).
	vcStructuralKey = regexp.MustCompile(`"(?:_sd|_sd_alg|\.\.\.)"[` + jsWhitespace + `]*:`)
)

// VcClaims (vc.ts vcClaims): Validates a type's claim list (1 to 32 claims, unique names, known sources).
func VcClaims(value any, attributes *core.Object) ([]any, error) {
	list, ok := value.([]any)
	if !ok || len(list) == 0 || len(list) > 32 {
		return nil, invalidInput("claims must list 1 to 32 claims")
	}
	seen := map[string]bool{}
	claims := make([]any, 0, len(list))
	for _, raw := range list {
		item, ok := raw.(*core.Object)
		if !ok || item == nil {
			return nil, invalidInput("Each claim is an object")
		}
		name, isText := item.Get("name").(string)
		if !isText || !vcClaimName.MatchString(name) || ReservedVcClaims.Has(name) || seen[name] {
			return nil, invalidInput("Invalid, reserved or repeated claim name " + jsSlice(jsString(item.Get("name")), 64))
		}
		seen[name] = true
		source, sourceText := item.Get("source").(string)
		attribute := ""
		if sourceText && strings.HasPrefix(source, "attribute:") {
			attribute = source[len("attribute:"):]
		}
		if !sourceText || (!vcSources.Has(source) && !(attribute != "" && attributes != nil && attributes.Has(attribute))) {
			return nil, invalidInput("Claim " + name + " has an unknown source")
		}
		claim := core.NewObject("name", name, "source", source)
		if source == "static" {
			staticValue := item.Get("value")
			if isUndefined(staticValue) {
				return nil, invalidInput("Static claim " + name + " needs a value of at most 2 KiB")
			}
			text, _, err := core.Stringify(staticValue)
			if err != nil {
				return nil, err
			}
			if utf16Len(text) > 2048 {
				return nil, invalidInput("Static claim " + name + " needs a value of at most 2 KiB")
			}
			if vcStructuralKey.MatchString(text) {
				return nil, invalidInput("Static claim " + name + " may not contain _sd, _sd_alg or ... keys")
			}
			claim.Set("value", staticValue)
		}
		if selective := item.Get("selective"); !isUndefined(selective) {
			if _, ok := selective.(bool); !ok {
				return nil, invalidInput("selective must be a boolean")
			}
			claim.Set("selective", selective)
		}
		if required := item.Get("required"); !isUndefined(required) {
			if _, ok := required.(bool); !ok {
				return nil, invalidInput("required must be a boolean")
			}
			claim.Set("required", required)
		}
		if label := item.Get("label"); !isUndefined(label) {
			text, ok := label.(string)
			if !ok || core.JSTrim(text) == "" || utf16Len(text) > 64 {
				return nil, invalidInput("label must be 1-64 characters")
			}
			claim.Set("label", text)
		}
		claims = append(claims, claim)
	}
	return claims, nil
}

// vcClaimValues is claimValues: the value of each claim for an identity; missing values are left out (required ones
// refuse).
func vcClaimValues(ctx context.Context, tx core.IamStore, tenant, identity, typeValue *core.Object, at float64) (*core.Object, *core.Object, error) {
	plain, disclosable := core.NewObject(), core.NewObject()
	tenantID := jsString(tenant.Get("id"))
	claims, _ := typeValue.Get("claims").([]any)
	for _, raw := range claims {
		claim, _ := raw.(*core.Object)
		if claim == nil {
			claim = core.NewObject()
		}
		var value any = core.Undefined
		source := jsString(claim.Get("source"))
		switch source {
		case "email":
			value = identity.Get("email")
		case "emailVerified":
			if truthy(identity.Get("email")) {
				value = identity.Get("emailVerified") == true
			}
		case "name":
			value = identity.Get("name")
		case "identityId":
			value = identity.Get("id")
		case "kind":
			value = identity.Get("kind")
		case "tenantId":
			value = tenant.Get("id")
		case "tenantName":
			value = tenant.Get("name")
		case "teams":
			teamIDs, err := TeamsOf(ctx, tx, tenantID, jsString(identity.Get("id")), core.NewObject("at", at))
			if err != nil {
				return nil, nil, err
			}
			names := []string{}
			for _, teamID := range teamIDs {
				team, err := tx.Get(ctx, "teams", teamID)
				if err != nil {
					return nil, nil, err
				}
				if team != nil && team.Get("tenantId") == tenantID {
					if name, ok := team.Get("name").(string); ok {
						names = append(names, name)
					}
				}
			}
			if len(names) > 0 {
				slices.SortFunc(names, compareUTF16)
				value = stringsOf(names)
			}
		case "department":
			departmentID, err := DepartmentOf(ctx, tx, tenantID, jsString(identity.Get("id")))
			if err != nil {
				return nil, nil, err
			}
			if departmentID != "" {
				department, err := tx.Get(ctx, "departments", departmentID)
				if err != nil {
					return nil, nil, err
				}
				if department != nil && department.Get("tenantId") == tenantID {
					value = department.Get("name")
				}
			}
		case "static":
			value = claim.Get("value")
		default:
			value = member(identity.Get("attributes"), jsSliceFrom(source, len("attribute:")))
		}
		if nullish(value) || value == "" {
			if truthy(claim.Get("required")) {
				return nil, nil, core.NewIamError("CLAIM_UNAVAILABLE", "This person has no value for the claim "+jsString(claim.Get("name")), 409)
			}
			continue
		}
		if claim.Get("selective") == false {
			plain.Set(jsString(claim.Get("name")), value)
		} else {
			disclosable.Set(jsString(claim.Get("name")), value)
		}
	}
	return plain, disclosable, nil
}

// jsSliceFrom is `text.slice(start)` in UTF-16 code units.
func jsSliceFrom(text string, start int) string {
	units := core.ToUTF16(text)
	if start >= len(units) {
		return ""
	}
	return core.FromUTF16(units[start:])
}

// vcAllocateStatus is allocateStatus: hands out a fresh status index (random, never reused), opening a new list when
// the current one is half full.
func vcAllocateStatus(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, options *ResolvedVcOptions) (*core.Object, int64, error) {
	lists, err := tx.Find(ctx, "vcStatusLists", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, 0, err
	}
	slices.SortStableFunc(lists, vcByCreated)
	var list *core.Object
	for _, item := range lists {
		if jsNumber(item.Get("allocated")) < jsNumber(item.Get("size"))/2 {
			list = item
			break
		}
	}
	if list == nil {
		now := float64(server.Now())
		list, err = tx.Insert(ctx, "vcStatusLists", core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"size", options.StatusListSize,
			"bits", 2,
			"bytes", base64.StdEncoding.EncodeToString(make([]byte, int(options.StatusListSize/4))),
			"allocatedBits", base64.StdEncoding.EncodeToString(make([]byte, int(options.StatusListSize/8))),
			"allocated", 0,
			"version", 0,
			"createdAt", now,
			"updatedAt", now,
		))
		if err != nil {
			return nil, 0, err
		}
	}
	taken := nodeBase64Decode(jsString(list.Get("allocatedBits")))
	size := int64(jsNumber(list.Get("size")))
	for {
		// Random indexes keep a credential's position from revealing when it was issued.
		index := randomInt(size)
		position := index >> 3
		bit := byte(1 << (index & 7))
		if position < int64(len(taken)) {
			if taken[position]&bit != 0 {
				continue
			}
			taken[position] |= bit
		}
		saved, err := tx.Put(ctx, "vcStatusLists", list.Spread(core.NewObject(
			"allocatedBits", base64.StdEncoding.EncodeToString(taken),
			"allocated", jsNumber(list.Get("allocated"))+1,
			"updatedAt", float64(server.Now()),
		)))
		if err != nil {
			return nil, 0, err
		}
		return saved, index, nil
	}
}

// WriteStatus (vc.ts writeStatus): Writes a credential's status into its list.
func WriteStatus(ctx context.Context, server *ServerContext, tx core.IamStore, record *core.Object, status string) error {
	list, err := tx.Get(ctx, "vcStatusLists", jsString(record.Get("statusListId")))
	if err != nil {
		return err
	}
	if list == nil || list.Get("tenantId") != record.Get("tenantId") {
		return core.NewIamError("NOT_FOUND", "Status list not found", 404)
	}
	bytes := nodeBase64Decode(jsString(list.Get("bytes")))
	value := float64(StatusValid)
	switch status {
	case "revoked":
		value = StatusInvalid
	case "suspended":
		value = StatusSuspended
	}
	if err := SetStatusAt(bytes, jsNumber(record.Get("statusIndex")), 2, value); err != nil {
		return err
	}
	_, err = tx.Put(ctx, "vcStatusLists", list.Spread(core.NewObject(
		"bytes", base64.StdEncoding.EncodeToString(bytes),
		"version", jsNumber(list.Get("version"))+1,
		"updatedAt", float64(server.Now()),
	)))
	return err
}

// IssueCredentialInput is what issueCredential takes. The actor is Actor (a principal) or, when Actor is nil,
// ActorID (`{ actorId }`). OfferID "" is none; Deadline nil is none.
type IssueCredentialInput struct {
	Tenant           *core.Object
	Type             *core.Object
	Identity         *core.Object
	HolderJwk        *core.Object
	HolderThumbprint string
	Via              string
	Actor            *Principal
	ActorID          string
	// IssuedBy is who is answerable for it: the person for self-service, the administrator who made an offer for
	// someone.
	IssuedBy    string
	SelfService bool
	Mfa         any
	OfferID     string
	Deadline    *float64
}

// IssuedCredential is the issued SD-JWT VC and its record.
type IssuedCredential struct {
	Credential string
	Record     *core.Object
}

// IssueCredential (vc.ts issueCredential): Issues one SD-JWT VC of `type` for `identity`, bound to `holderJwk`, and
// records it (status index allocated, audit event `vc:credential:issue`). The lifetime never outlives the account's
// scheduled expiry nor `deadline` (the end of the grant or session that allowed a self-service request).
func IssueCredential(ctx context.Context, server *ServerContext, tx core.IamStore, input IssueCredentialInput) (*IssuedCredential, error) {
	options, err := AssertVc(server)
	if err != nil {
		return nil, err
	}
	tenant, typeValue, identity := input.Tenant, input.Type, input.Identity
	tenantID := jsString(tenant.Get("id"))
	if !truthy(typeValue.Get("enabled")) {
		return nil, core.NewIamError("TYPE_DISABLED", "This credential type is disabled", 409)
	}
	if identity.Get("status") != "active" || server.IdentityExpired(identity) || identity.Get("tenantId") != tenant.Get("id") {
		return nil, core.NewIamError("IDENTITY_INACTIVE", "Credentials are issued to active members only", 409)
	}
	actorID := input.ActorID
	if input.Actor != nil {
		actorID = jsString(input.Actor.Identity.Get("id"))
	}
	key, err := ActiveIssuerKey(ctx, server, tx, tenantID, actorID)
	if err != nil {
		return nil, err
	}
	now := float64(server.Now())
	plain, disclosable, err := vcClaimValues(ctx, tx, tenant, identity, typeValue, now)
	if err != nil {
		return nil, err
	}
	validUntil := now + jsMin(jsNumber(typeValue.Get("lifetimeMs")), options.MaxLifetimeMs)
	if expiresAt, ok := identity.Get("expiresAt").(float64); ok {
		validUntil = jsMin(validUntil, expiresAt)
	}
	if input.Deadline != nil {
		validUntil = jsMin(validUntil, *input.Deadline)
	}
	if validUntil < now+vcMinute {
		return nil, core.NewIamError("ACCESS_EXPIRING", "The access that allows this credential ends within a minute", 409)
	}
	list, index, err := vcAllocateStatus(ctx, server, tx, tenantID, options)
	if err != nil {
		return nil, err
	}
	issuer := IssuerURL(server, tenantID)
	signing, err := OpenIssuerKey(server, key)
	if err != nil {
		return nil, err
	}
	listID := jsString(list.Get("id"))
	issued, err := IssueSdJwt(ctx, SdJwtIssueInput{
		Alg: "ES256",
		Kid: jsString(key.Get("kid")),
		Key: signing,
		Typ: SdJwtVcType,
		Plain: plain.Spread(core.NewObject(
			"iss", issuer,
			"iat", math.Floor(now/1000),
			"exp", math.Floor(validUntil/1000),
			"vct", typeValue.Get("vct"),
			"cnf", core.NewObject("jwk", input.HolderJwk),
			"status", core.NewObject("status_list", core.NewObject("idx", float64(index), "uri", issuer+"/status/"+listID)),
		)),
		Disclosable: disclosable,
		Decoys:      int(randomInt(4)),
	})
	if err != nil {
		return nil, err
	}
	claimNames := append(plain.Keys(), disclosable.Keys()...)
	slices.SortFunc(claimNames, compareUTF16)
	record := core.NewObject(
		"id", ID(),
		"tenantId", tenantID,
		"uniqueKey", listID+":"+strconv.FormatInt(index, 10),
		"typeId", typeValue.Get("id"),
		"typeName", typeValue.Get("name"),
		"vct", typeValue.Get("vct"),
		"identityId", identity.Get("id"),
		"holderThumbprint", input.HolderThumbprint,
		"keyId", key.Get("kid"),
		"statusListId", listID,
		"statusIndex", float64(index),
		"status", "valid",
		"claimNames", stringsOf(claimNames),
		"via", input.Via,
		"issuedBy", input.IssuedBy,
		"selfService", input.SelfService,
		"mfa", input.Mfa,
	)
	if input.OfferID != "" {
		record.Set("offerId", input.OfferID)
	}
	record.Set("issuedAt", now)
	record.Set("validUntil", validUntil)
	record.Set("expiresAt", validUntil+options.RecordRetentionMs)
	record, err = tx.Insert(ctx, "vcIssued", record)
	if err != nil {
		return nil, err
	}
	recordID := jsString(record.Get("id"))
	metadata := core.NewObject(
		"type", typeValue.Get("name"),
		"credentialId", recordID,
		"identityId", identity.Get("id"),
		"issuedBy", input.IssuedBy,
		"holder", input.HolderThumbprint,
		"via", input.Via,
		"claims", record.Get("claimNames"),
		"validUntil", validUntil,
	)
	if input.OfferID != "" {
		metadata.Set("offerId", input.OfferID)
	}
	if input.Actor == nil {
		err = server.Events.RecordAudit(ctx, tx, core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"actorId", actorID,
			"action", "vc:credential:issue",
			"resourceId", "vc/credentials/"+recordID,
			"outcome", "allow",
			"timestamp", now,
			"metadata", metadata,
		))
	} else {
		err = server.Events.Audit(ctx, tx, input.Actor, "vc:credential:issue", tenantID, "vc/credentials/"+recordID, "allow", false, metadata)
	}
	if err != nil {
		return nil, err
	}
	return &IssuedCredential{Credential: issued.SdJwt, Record: record}, nil
}

// jsMin is Math.min of two numbers (NaN when either is NaN).
func jsMin(a, b float64) float64 {
	if math.IsNaN(a) || math.IsNaN(b) {
		return math.NaN()
	}
	return math.Min(a, b)
}

const vcNonceMs = 5 * vcMinute

// vcNonceKey is the nonce MAC key: SHA-256 of `better-iam:vc-nonce:{secret}`.
func vcNonceKey(server *ServerContext) []byte {
	digest := sha256.Sum256(utf8Bytes("better-iam:vc-nonce:" + server.Options.Secret))
	return digest[:]
}

func vcNonceMac(server *ServerContext, tenantID, issued, random string) string {
	mac := hmac.New(sha256.New, vcNonceKey(server))
	mac.Write(utf8Bytes(tenantID + "." + issued + "." + random))
	return base64url(mac.Sum(nil))
}

// CreateNonce (vc.ts createNonce): A proof nonce (`c_nonce`) for one tenant, valid five minutes: stateless
// (`{time}.{random}.{mac}`), so handing them out writes nothing; only using one records it, once.
func CreateNonce(server *ServerContext, tenantID string) string {
	issued := strconv.FormatInt(server.Now(), 36)
	random := base64url(randomBytes(16))
	return issued + "." + random + "." + vcNonceMac(server, tenantID, issued, random)
}

// ConsumeNonce (vc.ts consumeNonce): Consumes a nonce; false when forged, expired, another tenant's, or used before.
// value nil is undefined.
func ConsumeNonce(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, value *string) (bool, error) {
	var parts []string
	if value != nil && utf16Len(*value) <= 128 {
		parts = strings.Split(*value, ".")
	}
	if len(parts) != 3 {
		return false, nil
	}
	issued, random, mac := parts[0], parts[1], parts[2]
	expected := utf8Bytes(vcNonceMac(server, tenantID, issued, random))
	given := utf8Bytes(mac)
	if len(expected) != len(given) || subtle.ConstantTimeCompare(expected, given) != 1 {
		return false, nil
	}
	at, ok := vcParseInt36(issued)
	now := float64(server.Now())
	if !ok || !core.IsSafeInteger(at) || at > now+vcMinute || now-at > vcNonceMs {
		return false, nil
	}
	recordID := Hash("vc-nonce:" + *value)
	used, err := tx.Get(ctx, "vcNonces", recordID)
	if err != nil {
		return false, err
	}
	if used != nil {
		return false, nil
	}
	if _, err := tx.Insert(ctx, "vcNonces", core.NewObject("id", recordID, "tenantId", tenantID, "expiresAt", at+vcNonceMs, "usedAt", now)); err != nil {
		return false, err
	}
	return true, nil
}

// vcParseInt36 is Number.parseInt(text, 36): leading whitespace and a sign, then the longest run of base-36 digits
// (NaN, ok false, when there is none).
func vcParseInt36(text string) (float64, bool) {
	text = strings.TrimLeftFunc(text, jsSpace)
	negative := false
	if strings.HasPrefix(text, "-") || strings.HasPrefix(text, "+") {
		negative = text[0] == '-'
		text = text[1:]
	}
	end := 0
	for end < len(text) {
		c := text[end]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			break
		}
		end++
	}
	value, ok := parseRadix(text[:end], 36)
	if !ok {
		return math.NaN(), false
	}
	if negative {
		value = -value
	}
	return value, true
}

// HolderFromProof (vc.ts holderFromProof): Checks an OpenID4VCI proof for the tenant's issuer and consumes its
// nonce; returns the holder key.
func HolderFromProof(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, proof any) (*HolderProof, error) {
	now := float64(server.Now())
	checked, err := VerifyHolderProof(ctx, proof, HolderProofOptions{Audience: IssuerURL(server, tenantID), Now: &now})
	if err != nil {
		return nil, core.NewIamError("INVALID_PROOF", errorMessage(err), 400)
	}
	consumed, err := ConsumeNonce(ctx, server, tx, tenantID, checked.Nonce)
	if err != nil {
		return nil, err
	}
	if !consumed {
		return nil, core.NewIamError("INVALID_NONCE", "The proof needs a fresh nonce from verifiableCredentials.nonce", 400)
	}
	return &HolderProof{Jwk: checked.Jwk, Thumbprint: checked.Thumbprint}, nil
}

// vcStatusTokenCache holds the signed Status List Tokens of one deployment, by list version and signing key.
type vcStatusTokenCache struct {
	mu      sync.Mutex
	entries map[string]vcStatusTokenEntry
}

type vcStatusTokenEntry struct {
	token string
	at    float64
}

// vcStatusTokens is statusTokens (a WeakMap keyed by the options object).
var vcStatusTokens sync.Map

// StatusListToken (vc.ts statusListToken): the signed Status List Token of a list, cached per list version and
// signing key until half its cache time passed.
func StatusListToken(ctx context.Context, server *ServerContext, reader core.IamStore, list *core.Object) (string, error) {
	options, err := AssertVc(server)
	if err != nil {
		return "", err
	}
	tenantID := jsString(list.Get("tenantId"))
	// A list exists only after a credential was issued, and with it the key: reads never create one.
	keys, err := IssuerKeys(ctx, reader, tenantID)
	if err != nil {
		return "", err
	}
	var key *core.Object
	for _, item := range keys {
		if item.Get("status") == "active" {
			key = item
			break
		}
	}
	if key == nil {
		return "", core.NewIamError("NOT_FOUND", "No issuer key", 404)
	}
	cached, _ := vcStatusTokens.LoadOrStore(server.Options, &vcStatusTokenCache{entries: map[string]vcStatusTokenEntry{}})
	cache := cached.(*vcStatusTokenCache)
	cacheKey := jsString(list.Get("id")) + ":" + jsString(list.Get("version")) + ":" + jsString(key.Get("kid"))
	now := float64(server.Now())
	cache.mu.Lock()
	hit, found := cache.entries[cacheKey]
	cache.mu.Unlock()
	if found && now-hit.at < (options.StatusListTtlSeconds*1000)/2 && now >= hit.at {
		return hit.token, nil
	}
	signing, err := OpenIssuerKey(server, key)
	if err != nil {
		return "", err
	}
	signed, err := SignStatusList(ctx, StatusListInput{
		URI:        IssuerURL(server, tenantID) + "/status/" + jsString(list.Get("id")),
		Bytes:      nodeBase64Decode(jsString(list.Get("bytes"))),
		Bits:       2,
		Alg:        "ES256",
		Kid:        jsString(key.Get("kid")),
		Key:        signing,
		IssuedAt:   now,
		ExpiresAt:  now + options.StatusListLifetimeMs,
		TTLSeconds: options.StatusListTtlSeconds,
	})
	if err != nil {
		return "", err
	}
	cache.mu.Lock()
	if len(cache.entries) > 1000 {
		cache.entries = map[string]vcStatusTokenEntry{}
	}
	cache.entries[cacheKey] = vcStatusTokenEntry{token: signed, at: now}
	cache.mu.Unlock()
	return signed, nil
}

// VerifyLocalPresentation (vc.ts verifyLocalPresentation): Verifies a presentation of a credential this deployment
// issued: the tenant's keys, disclosures, key binding (for `audience` and `nonce`, both required unless
// `requireKeyBinding: false`) and the credential's current standing: revoked and suspended credentials fail, and so
// do those of holders who are no longer active members or of an organization that is suspended (even before the
// sweep revokes them). Reads only, outside any transaction. options is `{ audience?, nonce?, requireKeyBinding?,
// tenantId? }` (nil for none); the result is the VerifiedCredential record.
func VerifyLocalPresentation(ctx context.Context, server *ServerContext, presentation string, options *core.Object) (*core.Object, error) {
	if _, err := AssertVc(server); err != nil {
		return nil, err
	}
	if options == nil {
		options = core.NewObject()
	}
	audience, nonce := options.Get("audience"), options.Get("nonce")
	requireKeyBinding := options.Get("requireKeyBinding")
	if requireKeyBinding != false && (isUndefined(audience) || isUndefined(nonce)) {
		return nil, invalidInput("Verify a presentation for your audience and the nonce you issued; without them it could be a replay")
	}
	reader := server.Store
	prefix := vcIssuerPrefix(server)
	tenantID := ""
	wanted := options.Get("tenantId")
	now := float64(server.Now())
	verified, err := VerifySdJwt(ctx, presentation, &SdJwtVerifyOptions{
		IssuerKey: func(ctx context.Context, kid, issuer string) (any, error) {
			if !strings.HasPrefix(issuer, prefix) {
				return nil, nil
			}
			tenantID = issuer[len(prefix):]
			if tenantID == "" || strings.Contains(tenantID, "/") || (truthy(wanted) && !core.StrictEquals(wanted, tenantID)) {
				return nil, nil
			}
			keys, err := IssuerKeys(ctx, reader, tenantID)
			if err != nil {
				return nil, err
			}
			for _, key := range keys {
				if key.Get("kid") == kid && key.Get("status") != "retired" {
					if jwk, ok := key.Get("publicJwk").(*core.Object); ok {
						return jwk, nil
					}
					return key.Get("publicJwk"), nil
				}
			}
			return nil, nil
		},
		Now:               &now,
		RequireKeyBinding: requireKeyBinding,
		Audience:          audience,
		HasAudience:       !isUndefined(audience),
		Nonce:             nonce,
		HasNonce:          !isUndefined(nonce),
	})
	if err != nil {
		return nil, err
	}
	reference, _ := verified.Get("status").(*core.Object)
	statusPrefix := IssuerURL(server, tenantID) + "/status/"
	listID := ""
	if reference != nil {
		if uri, ok := reference.Get("uri").(string); ok && strings.HasPrefix(uri, statusPrefix) {
			listID = uri[len(statusPrefix):]
		}
	}
	var list *core.Object
	if listID != "" {
		if list, err = reader.Get(ctx, "vcStatusLists", listID); err != nil {
			return nil, err
		}
	}
	if reference == nil || list == nil || list.Get("tenantId") != tenantID {
		return nil, sdJwtFail("status-unavailable", "The credential has no status this issuer knows")
	}
	index := jsNumber(reference.Get("index"))
	status, err := StatusAt(nodeBase64Decode(jsString(list.Get("bytes"))), index, 2)
	if err != nil {
		return nil, err
	}
	switch status {
	case StatusInvalid:
		return nil, sdJwtFail("revoked", "The credential was revoked")
	case StatusSuspended:
		return nil, sdJwtFail("suspended", "The credential is suspended")
	}
	if status != StatusValid {
		return nil, sdJwtFail("status-unavailable", "The credential status is unknown")
	}
	records, err := reader.Find(ctx, "vcIssued", core.NewObject("tenantId", tenantID, "uniqueKey", jsString(list.Get("id"))+":"+jsString(index)), nil)
	if err != nil {
		return nil, err
	}
	if len(records) == 0 {
		return nil, sdJwtFail("status-unavailable", "The credential is unknown to this issuer")
	}
	record := records[0]
	identity, err := reader.Get(ctx, "identities", jsString(record.Get("identityId")))
	if err != nil {
		return nil, err
	}
	if identity == nil || identity.Get("status") != "active" || server.IdentityExpired(identity) {
		return nil, sdJwtFail("revoked", "The holder is no longer a member")
	}
	tenant, err := reader.Get(ctx, "tenants", tenantID)
	if err != nil {
		return nil, err
	}
	suspended := tenant == nil
	if !suspended {
		if suspended, err = vcAnyInactive(ctx, server, reader, tenant); err != nil {
			return nil, err
		}
	}
	if suspended {
		return nil, sdJwtFail("suspended", "The issuing organization is suspended")
	}
	return verified.Spread(core.NewObject("tenantId", tenantID, "status", reference, "type", record.Get("typeName"))), nil
}

// vcAnyInactive is `(await ctx.ancestry(tx, tenant)).some((item) => item.status !== 'active')`.
func vcAnyInactive(ctx context.Context, server *ServerContext, tx core.IamStore, tenant *core.Object) (bool, error) {
	ancestry, err := server.Ancestry(ctx, tx, tenant)
	if err != nil {
		return false, err
	}
	for _, item := range ancestry {
		if item.Get("status") != "active" {
			return true, nil
		}
	}
	return false, nil
}

// SweepCredentials (vc.ts sweepCredentials): Revokes valid credentials whose holder is no longer an active member,
// self-service ones whose holder may no longer request them (`vc:request` decided again, with the MFA state of the
// issuing session), and, with security clearances, any other whose holder no longer dominates the type's
// classification label (`holderCleared`). A scheduler job; each tenant in its own transaction. input is
// `{ tenantId? }` (nil for every tenant); the result is `{ examined, revoked }`.
func SweepCredentials(ctx context.Context, server *ServerContext, input *core.Object) (*core.Object, error) {
	if _, err := AssertVc(server); err != nil {
		return nil, err
	}
	if input == nil {
		input = core.NewObject()
	}
	examined, revoked := 0, 0
	now := float64(server.Now())
	var tenantIDs []string
	if wanted := input.Get("tenantId"); truthy(wanted) {
		tenantIDs = []string{jsString(wanted)}
	} else {
		valid, err := server.Store.Find(ctx, "vcIssued", core.NewObject("status", "valid"), nil)
		if err != nil {
			return nil, err
		}
		for _, record := range valid {
			if jsNumber(record.Get("validUntil")) > now {
				tenantIDs = append(tenantIDs, jsString(record.Get("tenantId")))
			}
		}
		tenantIDs = unique(tenantIDs)
	}
	for _, tenantID := range tenantIDs {
		err := server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			tenant, err := tx.Get(ctx, "tenants", tenantID)
			if err != nil || tenant == nil {
				return err
			}
			found, err := tx.Find(ctx, "vcIssued", core.NewObject("tenantId", tenantID, "status", "valid"), nil)
			if err != nil {
				return err
			}
			types := map[string]*core.Object{}
			for _, record := range found {
				if !(jsNumber(record.Get("validUntil")) > now) {
					continue
				}
				examined++
				identity, err := tx.Get(ctx, "identities", jsString(record.Get("identityId")))
				if err != nil {
					return err
				}
				reason := ""
				mfa := record.Get("mfa") == true
				if identity == nil || identity.Get("status") != "active" || server.IdentityExpired(identity) {
					reason = "identity-inactive"
				} else if truthy(record.Get("selfService")) {
					typeID := jsString(record.Get("typeId"))
					typeValue, known := types[typeID]
					if !known {
						if typeValue, err = tx.Get(ctx, "vcCredentialTypes", typeID); err != nil {
							return err
						}
						types[typeID] = typeValue
					}
					principal := server.Decisions.SimulatedPrincipal(identity, mfa)
					// Only a clear refusal revokes: a suspended organization's credentials already fail verification.
					allowed := typeValue != nil && (!truthy(typeValue.Get("requireMfa")) || mfa)
					if allowed {
						if allowed, err = MayRequest(ctx, server, tx, principal, tenant, typeValue); err != nil {
							return err
						}
					}
					suspended, err := vcAnyInactive(ctx, server, tx, tenant)
					if err != nil {
						return err
					}
					if !allowed && !suspended {
						reason = "access-changed"
					}
				} else {
					cleared, err := HolderCleared(ctx, server, tx, tenant, identity, jsString(record.Get("typeName")), mfa)
					if err != nil {
						return err
					}
					if !cleared {
						// An administrator's credential needs no `vc:request`, but its holder must still be cleared
						// for the type's classification label (security clearances).
						suspended, err := vcAnyInactive(ctx, server, tx, tenant)
						if err != nil {
							return err
						}
						if !suspended {
							reason = "access-changed"
						}
					}
				}
				if reason == "" {
					continue
				}
				if err := WriteStatus(ctx, server, tx, record, "revoked"); err != nil {
					return err
				}
				if _, err := tx.Put(ctx, "vcIssued", record.Spread(core.NewObject(
					"status", "revoked", "revokedAt", now, "revokedBy", "deployment-operator", "reason", reason,
				))); err != nil {
					return err
				}
				if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
					"id", ID(),
					"tenantId", tenantID,
					"actorId", "deployment-operator",
					"action", "vc:credential:revoke",
					"resourceId", "vc/credentials/"+jsString(record.Get("id")),
					"outcome", "allow",
					"timestamp", now,
					"metadata", core.NewObject("reason", reason, "identityId", record.Get("identityId")),
				)); err != nil {
					return err
				}
				revoked++
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return core.NewObject("examined", examined, "revoked", revoked), nil
}

// OfferToken (vc.ts offerToken): Pre-authorized codes and access tokens name their offer:
// `biam_vco.{offerId}.{secret}` / `biam_vcat.…`.
func OfferToken(prefix string, offerID string) string {
	return prefix + "." + offerID + "." + base64url(randomBytes(32))
}

// OfferIDOf (vc.ts offerIdOf): the offer a code or access token names ("" for anything else).
func OfferIDOf(value any, prefix string) string {
	text, ok := value.(string)
	if !ok || utf16Len(text) > 256 {
		return ""
	}
	parts := strings.Split(text, ".")
	if len(parts) == 3 && parts[0] == prefix && parts[1] != "" && parts[2] != "" {
		return parts[1]
	}
	return ""
}

// MatchesHash (vc.ts matchesHash): whether a stored token hash is the hash of value.
func MatchesHash(stored any, value string) bool {
	text, ok := stored.(string)
	return ok && SameHash(text, Hash(value))
}
