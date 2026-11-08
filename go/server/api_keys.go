package server

// Port of packages/server/src/api/keys.ts: key management (KMS). Keys belong to a tenant and are addressed by id or
// `alias/{name}`; policies name them as `iam/kms/{keyId}` and may condition on `resource.keySpec`,
// `resource.keyUsage`, `resource.keyState`, `resource.aliases`, `resource.tags.{key}`,
// `resource.encryptionContext.{key}` / `resource.encryptionContextKeys` and, for signatures, `resource.algorithm`.
// Every call is authorized and audited (actions `iam:kms:*`, resource `kms/{keyId}`, never the plaintext); a key grant
// allows named operations to one identity when no policy does, within the caller's boundaries. Sessions viewing as
// someone else ("impersonation") are refused.

import (
	"context"
	"encoding/base64"
	"errors"
	"math"
	"regexp"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

const kmsDay = 86_400_000.0

// kmsKeyTarget is a guarded KMS target: the audited resource (`kms` or `kms/{keyId}`), with the key, its aliases and
// the call's encryption context (for context-constrained grants) once located.
type kmsKeyTarget struct {
	GuardTarget
	key     *core.Object
	aliases []string
	context *core.Object
}

var kmsAlgorithmName = regexp.MustCompile(`^[A-Za-z0-9]{1,16}$`)

var kmsTokenPart = regexp.MustCompile(`^[A-Za-z0-9_-]*$`)

// kmsOptionalText is `value === undefined ? undefined : text(value, name, max).trim()` ("" with false when absent).
func kmsOptionalText(value any, name string, max int) (string, bool, error) {
	if isUndefined(value) {
		return "", false, nil
	}
	text, err := Text(value, name, max)
	if err != nil {
		return "", false, err
	}
	return core.JSTrim(text), true, nil
}

func kmsAliasName(value any) (string, error) {
	name, err := Text(value, "alias", 256)
	if err != nil {
		return "", err
	}
	if !AliasPattern.MatchString(name) {
		return "", invalidInput("alias must be alias/{name} with letters, digits, slashes, underscores or hyphens")
	}
	return name, nil
}

// kmsRotationPeriod is the rotation period of an input (nil when absent or null).
func kmsRotationPeriod(value any) (*float64, error) {
	if nullish(value) {
		return nil, nil
	}
	period, err := Integer(value, "rotationPeriodDays", 1, 3650)
	if err != nil {
		return nil, err
	}
	return &period, nil
}

func kmsSignatureFormat(value any) (string, error) {
	if isUndefined(value) {
		return "der", nil
	}
	if value != "der" && value != "jose" {
		return "", invalidInput("format must be der or jose")
	}
	return value.(string), nil
}

// kmsRequestedAlgorithm is the algorithm a signing call asks for, as `resource.algorithm`: the key's default when
// none is named, otherwise the name itself (bounded). It is validated against the key only once the call is
// authorized, so callers without access learn nothing about the key.
func kmsRequestedAlgorithm(key *core.Object, value any) (string, error) {
	if isUndefined(value) {
		algorithms, err := KeyAlgorithms(key)
		if err != nil {
			return "", err
		}
		if len(algorithms) == 0 {
			return "none", nil
		}
		return algorithms[0], nil
	}
	if text, ok := value.(string); ok && kmsAlgorithmName.MatchString(text) {
		return text, nil
	}
	return "invalid", nil
}

// kmsJwtAttributes is what a token names, as `resource.jwt.*`, so policies can limit the tokens a caller mints.
func kmsJwtAttributes(claims *core.Object, tokenType string) *core.Object {
	attributes := core.NewObject("jwt", true, "jwt.typ", tokenType)
	for _, name := range []string{"sub", "iss"} {
		if value, ok := claims.Get(name).(string); ok {
			attributes.Set("jwt."+name, value)
		}
	}
	switch audience := claims.Get("aud").(type) {
	case string:
		attributes.Set("jwt.aud", audience)
	case []any:
		audiences := []string{}
		for _, item := range audience {
			if text, ok := item.(string); ok {
				audiences = append(audiences, text)
			}
		}
		attributes.Set("jwt.audiences", stringsOf(kmsSortedStrings(audiences)))
	}
	return attributes
}

func kmsJSONSegment(value, name string) (*core.Object, error) {
	parsed, err := core.ParseJSONString(decodeUTF8(nodeBase64Decode(value)))
	if err == nil {
		if object, err := Object(parsed); err == nil {
			return object, nil
		}
	}
	return nil, invalidInput("The token " + name + " is not valid JSON")
}

// kmsStateChange refuses a state change from a state not listed.
func kmsStateChange(key *core.Object, allowedFrom []string, verb string) error {
	state := jsString(key.Get("state"))
	if !containsString(allowedFrom, state) {
		return core.NewIamError("KEY_STATE_INVALID", "A key that is "+strings.Replace(state, "-", " ", 1)+" cannot be "+verb, 409)
	}
	return nil
}

func kmsByNewest(a, b *core.Object) int {
	if difference := jsNumber(b.Get("createdAt")) - jsNumber(a.Get("createdAt")); difference != 0 && !math.IsNaN(difference) {
		if difference < 0 {
			return -1
		}
		return 1
	}
	if jsString(a.Get("id")) < jsString(b.Get("id")) {
		return -1
	}
	return 1
}

func kmsByVersionDescending(a, b *core.Object) int {
	difference := jsNumber(b.Get("version")) - jsNumber(a.Get("version"))
	switch {
	case difference < 0:
		return -1
	case difference > 0:
		return 1
	}
	return 0
}

func kmsByName(a, b *core.Object) int {
	if compareUTF16(jsString(a.Get("name")), jsString(b.Get("name"))) < 0 {
		return -1
	}
	return 1
}

// KeysAPI is the `keys` API group (packages/server/src/api/keys.ts createKeysApi): every method runs through the
// guard envelope; the router maps POST {basePath}/keys/{method} onto it.
type KeysAPI struct {
	server *ServerContext
	guard  *Guard[kmsKeyTarget]
}

// CreateKeysAPI builds the `keys` API group.
func CreateKeysAPI(server *ServerContext) *KeysAPI {
	api := &KeysAPI{server: server}
	// The envelope of every KMS call (guarded.go): authenticate, locate the key, decide, run, audit. A key grant
	// stands in for a policy grant only when nothing denied the call and every boundary allowed it; a ciphertext that
	// fails to decrypt after the call was authorized is audited as a denied call.
	api.guard = CreateGuard(server, "kms", GuardOptions[kmsKeyTarget]{
		Fallback: func(ctx context.Context, tx core.IamStore, principal *Principal, action string, target kmsKeyTarget) (*core.Object, error) {
			operation, ok := GrantOperationOf.Get(action).(string)
			if !ok || target.key == nil {
				return nil, nil
			}
			grants, err := CandidateGrants(ctx, server, tx, target.key, principal, operation, target.context)
			if err != nil {
				return nil, err
			}
			for _, grant := range grants {
				allowed, err := api.creatorStillAllowed(ctx, tx, grant, action, target)
				if err != nil {
					return nil, err
				}
				if allowed {
					return core.NewObject("grantId", grant.Get("id")), nil
				}
			}
			return nil, nil
		},
		Describe: func(target kmsKeyTarget) *core.Object {
			described := core.NewObject()
			if target.key != nil {
				described.Set("keyId", target.key.Get("id"))
			}
			if target.context != nil && target.context.Len() > 0 {
				described.Set("encryptionContext", target.context.Clone())
			}
			return described
		},
		RecordedFailures: map[string]string{
			"INVALID_CIPHERTEXT": "invalid-ciphertext",
			"KEY_STATE_INVALID":  "key-state",
			"KEY_MANAGED":        "key-managed",
		},
		// Plugins see which key and version served a call, never plaintexts, data keys or signed tokens.
		HookResult: func(value any) any {
			object, ok := value.(*core.Object)
			if !ok || object == nil {
				return value
			}
			rest := object.Spread()
			rest.Delete("plaintext")
			rest.Delete("plaintextBase64")
			rest.Delete("token")
			return rest
		},
	})
	return api
}

// creatorStillAllowed: a grant works only while its creator could make the same call now, with the same key
// attributes and encryption context: an expired binding, a revoked role, a lapsed activation or a deny added later
// takes the grant down with it. The creator is evaluated as a plain session of their own (no MFA, no session tags),
// which fails closed for policies that need more.
func (api *KeysAPI) creatorStillAllowed(ctx context.Context, tx core.IamStore, grant *core.Object, action string, target kmsKeyTarget) (bool, error) {
	creator, err := tx.Get(ctx, "identities", jsString(grant.Get("createdBy")))
	if err != nil {
		return false, err
	}
	if creator == nil || !core.StrictEquals(creator.Get("tenantId"), grant.Get("tenantId")) || creator.Get("status") != "active" ||
		api.server.IdentityExpired(creator) {
		return false, nil
	}
	tenant, err := api.server.Tenant(ctx, tx, grant.Get("tenantId"))
	if err != nil {
		return false, err
	}
	decision, err := api.guard.Decide(ctx, tx, api.server.Decisions.SimulatedPrincipal(creator, false), tenant, action, target.GuardTarget, nil, nil)
	if err != nil {
		return false, err
	}
	return decision.Allowed, nil
}

// assertAliasAllowed: alias names are a namespace of their own: creating, moving or removing `alias/{name}` also
// needs iam:kms:update on `iam/kms/alias/{name}` (`resource.alias`), so whoever manages one key cannot claim a name
// others rely on.
func (api *KeysAPI) assertAliasAllowed(ctx context.Context, call GuardCall, name string) error {
	allowed, err := call.Allowed(ctx, kmsAction("update"), GuardTarget{ResourceID: "kms/" + name, Attributes: core.NewObject("alias", name)})
	if err != nil {
		return err
	}
	if !allowed {
		return NewOperationDenied("You may not manage the alias " + name)
	}
	return nil
}

// assertNoNewRights: changing what a key looks like to policies (its tags, its aliases) must not hand the caller
// rights on it: every KMS action they may not take on the key as it is stays refused on the key as it would be.
func (api *KeysAPI) assertNoNewRights(ctx context.Context, call GuardCall, key *core.Object, beforeTags *core.Object, beforeAliases []string, afterTags *core.Object, afterAliases []string) error {
	target := func(tags *core.Object, aliases []string) (GuardTarget, error) {
		view := key.Spread()
		view.Set("tags", tags)
		attributes, err := KeyAttributes(view, aliases, nil)
		if err != nil {
			return GuardTarget{}, err
		}
		return GuardTarget{ResourceID: "kms/" + jsString(key.Get("id")), Attributes: attributes}, nil
	}
	before, err := target(beforeTags, beforeAliases)
	if err != nil {
		return err
	}
	after, err := target(afterTags, afterAliases)
	if err != nil {
		return err
	}
	for _, name := range KmsActions.Keys() {
		action := kmsAction(name)
		if action == kmsAction("create") {
			continue
		}
		allowedBefore, err := call.Allowed(ctx, action, before)
		if err != nil {
			return err
		}
		if allowedBefore {
			continue
		}
		allowedAfter, err := call.Allowed(ctx, action, after)
		if err != nil {
			return err
		}
		if allowedAfter {
			return NewOperationDenied("That change would give you " + action + " on this key")
		}
	}
	return nil
}

// keyTarget locates a key (id or alias) with its aliases and policy attributes; extra may name `context` and
// `algorithm`.
func (api *KeysAPI) keyTarget(tenantID any, reference any, extra *core.Object) func(ctx context.Context, tx core.IamStore, principal *Principal) (kmsKeyTarget, error) {
	return func(ctx context.Context, tx core.IamStore, principal *Principal) (kmsKeyTarget, error) {
		return api.locateKey(ctx, tx, tenantID, reference, extra)
	}
}

func (api *KeysAPI) locateKey(ctx context.Context, tx core.IamStore, tenantID any, reference any, extra *core.Object) (kmsKeyTarget, error) {
	tenant, err := Text(tenantID, "tenantId")
	if err != nil {
		return kmsKeyTarget{}, err
	}
	key, err := FindKey(ctx, tx, tenant, reference)
	if err != nil {
		return kmsKeyTarget{}, err
	}
	aliases, err := AliasNames(ctx, tx, key)
	if err != nil {
		return kmsKeyTarget{}, err
	}
	attributes, err := KeyAttributes(key, aliases, extra)
	if err != nil {
		return kmsKeyTarget{}, err
	}
	target := kmsKeyTarget{GuardTarget: GuardTarget{ResourceID: "kms/" + jsString(key.Get("id")), Attributes: attributes}, key: key, aliases: aliases}
	if extra != nil {
		if context, ok := extra.Get("context").(*core.Object); ok && context != nil {
			target.context = context
		}
	}
	return target, nil
}

func kmsTenantTarget(ctx context.Context, tx core.IamStore, principal *Principal) (kmsKeyTarget, error) {
	return kmsKeyTarget{GuardTarget: GuardTarget{ResourceID: "kms", Attributes: core.NewObject()}}, nil
}

// run is the guard envelope with a fixed action.
func (api *KeysAPI) run(ctx context.Context, credential core.CredentialInput, tenantID any, action string,
	locate func(ctx context.Context, tx core.IamStore, principal *Principal) (kmsKeyTarget, error),
	fn func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error)) (any, error) {
	return api.guard.Run(ctx, credential, guardTenantID(tenantID), GuardAction[kmsKeyTarget]{Name: action}, locate, fn)
}

// saveKey stores a key with changes (an Undefined change removes the member).
func (api *KeysAPI) saveKey(ctx context.Context, tx core.IamStore, key *core.Object, changes *core.Object) (*core.Object, error) {
	next := key.Spread()
	for _, name := range changes.Keys() {
		next.Set(name, changes.Get(name))
	}
	next.Set("updatedAt", float64(api.server.Now()))
	for _, name := range changes.Keys() {
		if isUndefined(changes.Get(name)) {
			next.Delete(name)
		}
	}
	if _, err := tx.Put(ctx, "kmsKeys", next); err != nil {
		return nil, err
	}
	return next, nil
}

func (api *KeysAPI) rotateKey(ctx context.Context, tx core.IamStore, key *core.Object, origin string) (*core.Object, error) {
	current := jsNumber(key.Get("currentVersion"))
	if current >= MaxVersions {
		return nil, core.NewIamError("LIMIT_EXCEEDED", "A key keeps at most "+core.NumberString(MaxVersions)+" versions", 409)
	}
	version := current + 1
	if _, err := AddKeyVersion(ctx, api.server, tx, key, version, origin); err != nil {
		return nil, err
	}
	now := float64(api.server.Now())
	changes := core.NewObject("currentVersion", version, "lastRotatedAt", now)
	if period := key.Get("rotationPeriodDays"); !isUndefined(period) {
		changes.Set("nextRotationAt", now+jsNumber(period)*kmsDay)
	}
	return api.saveKey(ctx, tx, key, changes)
}

// keyVersionOf is the version a call names (keyVersion, 1 to MAX_VERSIONS), or the key's current one.
func kmsRequestedVersion(key *core.Object, value any) (float64, error) {
	if isUndefined(value) {
		return jsNumber(key.Get("currentVersion")), nil
	}
	return Integer(value, "keyVersion", 1, MaxVersions)
}

// ---- Crypto internals shared by the public calls (reEncrypt uses two of them) ------------------------------

func (api *KeysAPI) encryptCall(ctx context.Context, credential core.CredentialInput, tenantID any, keyRef any, plaintext []byte, isText bool, encryptionContext *core.Object, note *core.Object) (*core.Object, error) {
	value, err := api.run(ctx, credential, tenantID, kmsAction("encrypt"),
		api.keyTarget(tenantID, keyRef, core.NewObject("context", encryptionContext)),
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			key := target.key
			if err := AssertUsable(key, "encrypt"); err != nil {
				return nil, err
			}
			if err := AssertUnmanaged(key); err != nil {
				return nil, err
			}
			version, err := KeyVersion(ctx, call.Tx, key, jsNumber(key.Get("currentVersion")))
			if err != nil {
				return nil, err
			}
			if note != nil {
				call.Metadata.Assign(note)
			}
			call.Metadata.Set("keyVersion", version.Get("version"))
			ciphertext, err := EncryptWith(api.server, key, version, plaintext, isText, encryptionContext)
			if err != nil {
				return nil, err
			}
			return core.NewObject("ciphertext", ciphertext, "keyId", key.Get("id"), "keyVersion", version.Get("version")), nil
		})
	if err != nil {
		return nil, err
	}
	return value.(*core.Object), nil
}

// decryptCall decrypts a ciphertext; the result holds the plaintext bytes (`plaintext`), whether it was text, and
// the key and version.
func (api *KeysAPI) decryptCall(ctx context.Context, credential core.CredentialInput, tenantID any, ciphertext any, encryptionContext *core.Object, expectedKey any, note *core.Object) (*core.Object, error) {
	parsed, err := ParseCiphertext(ciphertext)
	if err != nil {
		return nil, err
	}
	value, err := api.run(ctx, credential, tenantID, kmsAction("decrypt"),
		func(ctx context.Context, tx core.IamStore, principal *Principal) (kmsKeyTarget, error) {
			target, err := api.locateKey(ctx, tx, tenantID, parsed.Get("keyId"), core.NewObject("context", encryptionContext))
			if err != nil {
				return kmsKeyTarget{}, err
			}
			if !isUndefined(expectedKey) {
				expected, err := FindKey(ctx, tx, guardTenantID(tenantID), expectedKey)
				if err != nil {
					return kmsKeyTarget{}, err
				}
				if !core.StrictEquals(expected.Get("id"), target.key.Get("id")) {
					return kmsKeyTarget{}, core.NewIamError("INVALID_CIPHERTEXT", "The ciphertext was not produced by that key", 400)
				}
			}
			return target, nil
		},
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			key := target.key
			if err := AssertUsable(key, "encrypt"); err != nil {
				return nil, err
			}
			if err := AssertUnmanaged(key); err != nil {
				return nil, err
			}
			version, err := KeyVersion(ctx, call.Tx, key, jsNumber(parsed.Get("version")))
			if err != nil {
				return nil, kmsInvalidCiphertext()
			}
			if note != nil {
				call.Metadata.Assign(note)
			}
			call.Metadata.Set("keyVersion", version.Get("version"))
			plaintext, err := DecryptWith(api.server, key, version, parsed, encryptionContext)
			if err != nil {
				return nil, err
			}
			return core.NewObject().SetRaw("plaintext", plaintext).Set("text", parsed.Get("text")).
				Set("keyId", key.Get("id")).Set("keyVersion", version.Get("version")), nil
		})
	if err != nil {
		return nil, err
	}
	return value.(*core.Object), nil
}

// Create is POST {basePath}/keys/create. Creates a key: `aes-256-gcm` (default; encrypt/decrypt and data keys),
// `hmac-sha256|384|512` (MACs), `ecc-p256|p384` and `ed25519` (signatures), or `rsa-2048|3072|4096` with `keyUsage`
// `encrypt` (RSA-OAEP) or `sign` (PS256-PS512, RS256-RS512). Policies can require request tags or specs through
// `resource.tags.{key}`, `resource.keySpec` and `resource.keyUsage`. Requires iam:kms:create on `iam/kms`; audited as
// `iam:kms:create`.
func (api *KeysAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysCreateInput]) (Out[apitypes.KeysCreateOutput], error) {
	fail := func(err error) (Out[apitypes.KeysCreateOutput], error) { return Out[apitypes.KeysCreateOutput]{}, err }
	requested := input.Get("keySpec")
	if nullish(requested) {
		requested = "aes-256-gcm"
	}
	spec, err := KeySpec(requested)
	if err != nil {
		return fail(err)
	}
	usage, err := KeyUsageFor(spec, input.Get("keyUsage"))
	if err != nil {
		return fail(err)
	}
	tags, err := KeyTags(input.Get("tags"))
	if err != nil {
		return fail(err)
	}
	description, _, err := kmsOptionalText(input.Get("description"), "description", 512)
	if err != nil {
		return fail(err)
	}
	period, err := kmsRotationPeriod(input.Get("rotationPeriodDays"))
	if err != nil {
		return fail(err)
	}
	alias := ""
	if value := input.Get("alias"); !isUndefined(value) {
		if alias, err = kmsAliasName(value); err != nil {
			return fail(err)
		}
	}
	server := api.server
	result, err := api.run(ctx, credential, input.Get("tenantId"), kmsAction("create"),
		func(ctx context.Context, tx core.IamStore, principal *Principal) (kmsKeyTarget, error) {
			attributes, err := RequestAttributes(spec, usage, tags)
			if err != nil {
				return kmsKeyTarget{}, err
			}
			return kmsKeyTarget{GuardTarget: GuardTarget{ResourceID: "kms", Attributes: attributes}}, nil
		},
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			tx, principal, tenant, metadata := call.Tx, call.Principal, call.Tenant, call.Metadata
			if alias != "" {
				if err := api.assertAliasAllowed(ctx, call, alias); err != nil {
					return nil, err
				}
			}
			existing, err := tx.Find(ctx, "kmsKeys", core.NewObject("tenantId", tenant.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			if len(existing) >= MaxKeysPerTenant {
				return nil, core.NewIamError("LIMIT_EXCEEDED", "A tenant keeps at most "+core.NumberString(MaxKeysPerTenant)+" keys", 409)
			}
			if alias != "" {
				taken, err := tx.Find(ctx, "kmsAliases", core.NewObject("tenantId", tenant.Get("id"), "uniqueKey", alias), nil)
				if err != nil {
					return nil, err
				}
				if len(taken) > 0 {
					return nil, core.NewIamError("CONFLICT", "That alias is already in use", 409)
				}
			}
			now := float64(server.Now())
			key := core.NewObject(
				"id", ID(),
				"tenantId", tenant.Get("id"),
				"keySpec", spec,
				"keyUsage", usage,
				"state", "enabled",
				"currentVersion", 1.0,
				"tags", tags,
				"createdAt", now,
				"createdBy", principal.Identity.Get("id"),
				"updatedAt", now,
			)
			if description != "" {
				key.Set("description", description)
			}
			if period != nil {
				key.Set("rotationPeriodDays", *period)
				key.Set("nextRotationAt", now+*period*kmsDay)
			}
			if _, err := tx.Insert(ctx, "kmsKeys", key); err != nil {
				return nil, err
			}
			if _, err := AddKeyVersion(ctx, server, tx, key, 1, "create"); err != nil {
				return nil, err
			}
			aliases := []string{}
			if alias != "" {
				if _, err := tx.Insert(ctx, "kmsAliases", core.NewObject(
					"id", ID(),
					"tenantId", tenant.Get("id"),
					"uniqueKey", alias,
					"name", alias,
					"keyId", key.Get("id"),
					"createdAt", now,
					"createdBy", principal.Identity.Get("id"),
					"updatedAt", now,
				)); err != nil {
					return nil, err
				}
				aliases = []string{alias}
			}
			metadata.Assign(core.NewObject("keyId", key.Get("id"), "keySpec", spec, "keyUsage", usage))
			if alias != "" {
				metadata.Set("alias", alias)
			}
			return SummarizeKey(key, aliases)
		})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.KeysCreateOutput]{Value: result}, nil
}

// List is POST {basePath}/keys/list. The tenant's keys the caller may read (`iam:kms:read`, evaluated per key so
// tag-scoped readers see theirs), newest first, optionally only one `state` or `keyUsage`. Never material.
func (api *KeysAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysListInput]) (Out[apitypes.KeysListOutput], error) {
	fail := func(err error) (Out[apitypes.KeysListOutput], error) { return Out[apitypes.KeysListOutput]{}, err }
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return fail(err)
	}
	limit, err := Integer(coalesce(input.Get("limit"), 100.0), "limit", 1, 1000)
	if err != nil {
		return fail(err)
	}
	offset, err := Integer(coalesce(input.Get("offset"), 0.0), "offset", 0, 1_000_000)
	if err != nil {
		return fail(err)
	}
	state := input.Get("state")
	if !isUndefined(state) && state != "enabled" && state != "disabled" && state != "pending-deletion" {
		return fail(invalidInput("Invalid state"))
	}
	usage := input.Get("keyUsage")
	if !isUndefined(usage) && usage != "encrypt" && usage != "sign" && usage != "mac" {
		return fail(invalidInput("Invalid keyUsage"))
	}
	keys, err := GuardVisible(ctx, api.guard, credential, tenantID, kmsAction("read"), "kms",
		func(ctx context.Context, tx core.IamStore, tenant *core.Object) ([]VisibleItem[any], error) {
			aliases := map[string][]string{}
			stored, err := tx.Find(ctx, "kmsAliases", core.NewObject("tenantId", tenant.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			for _, alias := range stored {
				keyID := jsString(alias.Get("keyId"))
				aliases[keyID] = append(aliases[keyID], jsString(alias.Get("name")))
			}
			all, err := tx.Find(ctx, "kmsKeys", core.NewObject("tenantId", tenant.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			matching := []*core.Object{}
			for _, key := range all {
				if (isUndefined(state) || core.StrictEquals(key.Get("state"), state)) && (isUndefined(usage) || core.StrictEquals(key.Get("keyUsage"), usage)) {
					matching = append(matching, key)
				}
			}
			sortStable(matching, kmsByNewest)
			items := make([]VisibleItem[any], 0, len(matching))
			for _, key := range matching {
				names := aliases[jsString(key.Get("id"))]
				if names == nil {
					names = []string{}
				}
				summary, err := SummarizeKey(key, names)
				if err != nil {
					return nil, err
				}
				attributes, err := KeyAttributes(key, names, nil)
				if err != nil {
					return nil, err
				}
				items = append(items, VisibleItem[any]{Item: summary, Target: GuardTarget{ResourceID: "kms/" + jsString(key.Get("id")), Attributes: attributes}})
			}
			return items, nil
		})
	if err != nil {
		return fail(err)
	}
	start := int(math.Min(offset, float64(len(keys))))
	end := int(math.Min(offset+limit, float64(len(keys))))
	return Out[apitypes.KeysListOutput]{Value: core.NewObject("keys", append([]any{}, keys[start:end]...), "total", float64(len(keys)))}, nil
}

// Get is POST {basePath}/keys/get. One key by id or alias. Requires iam:kms:read (or a grant allowing `read`).
func (api *KeysAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysGetInput]) (Out[apitypes.KeysGetOutput], error) {
	result, err := api.run(ctx, credential, input.Get("tenantId"), kmsAction("read"),
		api.keyTarget(input.Get("tenantId"), input.Get("keyId"), nil),
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			return SummarizeKey(target.key, target.aliases)
		})
	if err != nil {
		return Out[apitypes.KeysGetOutput]{}, err
	}
	return Out[apitypes.KeysGetOutput]{Value: result}, nil
}

// ListVersions is POST {basePath}/keys/listVersions. The key's versions, newest first, with the public key
// fingerprint of asymmetric ones. Requires iam:kms:read.
func (api *KeysAPI) ListVersions(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysListVersionsInput]) (Out[apitypes.KeysListVersionsOutput], error) {
	result, err := api.run(ctx, credential, input.Get("tenantId"), kmsAction("read"),
		api.keyTarget(input.Get("tenantId"), input.Get("keyId"), nil),
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			key := target.key
			versions, err := call.Tx.Find(ctx, "kmsKeyVersions", core.NewObject("tenantId", key.Get("tenantId"), "keyId", key.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			sortStable(versions, kmsByVersionDescending)
			list := make([]any, 0, len(versions))
			for _, version := range versions {
				summary := core.NewObject(
					"version", version.Get("version"),
					"current", core.StrictEquals(version.Get("version"), key.Get("currentVersion")),
					"origin", version.Get("origin"),
					"createdAt", version.Get("createdAt"),
				)
				if pemText := version.Get("publicKeyPem"); truthy(pemText) {
					fingerprint, err := Fingerprint(jsString(pemText))
					if err != nil {
						return nil, err
					}
					summary.Set("publicKeyFingerprint", fingerprint)
				}
				list = append(list, summary)
			}
			return list, nil
		})
	if err != nil {
		return Out[apitypes.KeysListVersionsOutput]{}, err
	}
	return Out[apitypes.KeysListVersionsOutput]{Value: result}, nil
}

// Update is POST {basePath}/keys/update. Changes the description, replaces the tags, or sets (`null` clears) the
// automatic rotation period. New tags must leave the caller able to manage the key: iam:kms:update is evaluated
// again with them, so a tag-scoped administrator cannot move a key out of their reach or into another team's.
// Requires iam:kms:update.
func (api *KeysAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysUpdateInput]) (Out[apitypes.KeysUpdateOutput], error) {
	fail := func(err error) (Out[apitypes.KeysUpdateOutput], error) { return Out[apitypes.KeysUpdateOutput]{}, err }
	clearDescription := input.Get("description") == nil
	description, hasDescription := "", false
	if !clearDescription {
		var err error
		if description, hasDescription, err = kmsOptionalText(input.Get("description"), "description", 512); err != nil {
			return fail(err)
		}
	}
	var tags *core.Object
	if value := input.Get("tags"); !isUndefined(value) {
		var err error
		if tags, err = KeyTags(value); err != nil {
			return fail(err)
		}
	}
	clearPeriod := input.Get("rotationPeriodDays") == nil
	var period *float64
	if !clearPeriod {
		var err error
		if period, err = kmsRotationPeriod(input.Get("rotationPeriodDays")); err != nil {
			return fail(err)
		}
	}
	server := api.server
	result, err := api.run(ctx, credential, input.Get("tenantId"), kmsAction("update"),
		api.keyTarget(input.Get("tenantId"), input.Get("keyId"), nil),
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			key, aliases := target.key, target.aliases
			if key.Get("state") == "pending-deletion" {
				if err := kmsStateChange(key, []string{"enabled", "disabled"}, "updated"); err != nil {
					return nil, err
				}
			}
			changes := core.NewObject()
			if clearDescription {
				changes.Set("description", core.Undefined)
			} else if hasDescription {
				changes.Set("description", description)
			}
			if tags != nil {
				moved := key.Spread()
				moved.Set("tags", tags)
				attributes, err := KeyAttributes(moved, aliases, nil)
				if err != nil {
					return nil, err
				}
				allowed, err := call.Allowed(ctx, kmsAction("update"), GuardTarget{ResourceID: "kms/" + jsString(key.Get("id")), Attributes: attributes})
				if err != nil {
					return nil, err
				}
				if !allowed {
					return nil, NewOperationDenied("Those tags would take the key out of your reach")
				}
				currentTags, _ := key.Get("tags").(*core.Object)
				if err := api.assertNoNewRights(ctx, call, key, currentTags, aliases, tags, aliases); err != nil {
					return nil, err
				}
				changes.Set("tags", tags)
				call.Metadata.Set("tags", stringsOf(kmsSortedStrings(tags.Keys())))
			}
			if clearPeriod {
				changes.Set("rotationPeriodDays", core.Undefined)
				changes.Set("nextRotationAt", core.Undefined)
			} else if period != nil {
				changes.Set("rotationPeriodDays", *period)
				changes.Set("nextRotationAt", float64(server.Now())+*period*kmsDay)
				call.Metadata.Set("rotationPeriodDays", *period)
			}
			saved, err := api.saveKey(ctx, call.Tx, key, changes)
			if err != nil {
				return nil, err
			}
			return SummarizeKey(saved, aliases)
		})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.KeysUpdateOutput]{Value: result}, nil
}

// setState is the body of enable and disable.
func (api *KeysAPI) setState(ctx context.Context, credential core.CredentialInput, tenantID, keyID any, state, verb string) (any, error) {
	return api.run(ctx, credential, tenantID, kmsAction("update"), api.keyTarget(tenantID, keyID, nil),
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			if err := kmsStateChange(target.key, []string{"enabled", "disabled"}, verb); err != nil {
				return nil, err
			}
			call.Metadata.Set("state", state)
			saved, err := api.saveKey(ctx, call.Tx, target.key, core.NewObject("state", state))
			if err != nil {
				return nil, err
			}
			return SummarizeKey(saved, target.aliases)
		})
}

// Enable is POST {basePath}/keys/enable. Enables a disabled key. Requires iam:kms:update.
func (api *KeysAPI) Enable(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysEnableInput]) (Out[apitypes.KeysEnableOutput], error) {
	result, err := api.setState(ctx, credential, input.Get("tenantId"), input.Get("keyId"), "enabled", "enabled")
	if err != nil {
		return Out[apitypes.KeysEnableOutput]{}, err
	}
	return Out[apitypes.KeysEnableOutput]{Value: result}, nil
}

// Disable is POST {basePath}/keys/disable. Every cryptographic call with the key is refused (`KEY_STATE_INVALID`)
// until it is enabled again, which makes everything encrypted under it unreadable meanwhile. Requires
// iam:kms:update.
func (api *KeysAPI) Disable(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysDisableInput]) (Out[apitypes.KeysDisableOutput], error) {
	result, err := api.setState(ctx, credential, input.Get("tenantId"), input.Get("keyId"), "disabled", "disabled")
	if err != nil {
		return Out[apitypes.KeysDisableOutput]{}, err
	}
	return Out[apitypes.KeysDisableOutput]{Value: result}, nil
}

// Rotate is POST {basePath}/keys/rotate. New material becomes the current version for encrypting, signing and MACs;
// older versions keep decrypting and verifying. Requires iam:kms:update; enabled keys only.
func (api *KeysAPI) Rotate(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysRotateInput]) (Out[apitypes.KeysRotateOutput], error) {
	server := api.server
	result, err := api.run(ctx, credential, input.Get("tenantId"), kmsAction("update"),
		api.keyTarget(input.Get("tenantId"), input.Get("keyId"), nil),
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			key := target.key
			if err := kmsStateChange(key, []string{"enabled"}, "rotated"); err != nil {
				return nil, err
			}
			// Each version is new key material (RSA generation is slow): ten on-demand rotations a day per key.
			versions, err := call.Tx.Find(ctx, "kmsKeyVersions", core.NewObject("tenantId", key.Get("tenantId"), "keyId", key.Get("id"), "origin", "rotate"), nil)
			if err != nil {
				return nil, err
			}
			recent := 0
			for _, version := range versions {
				if jsNumber(version.Get("createdAt")) > float64(server.Now())-kmsDay {
					recent++
				}
			}
			if recent >= 10 {
				return nil, core.NewIamError("RATE_LIMITED", "A key rotates on demand at most ten times a day", 429)
			}
			rotated, err := api.rotateKey(ctx, call.Tx, key, "rotate")
			if err != nil {
				return nil, err
			}
			call.Metadata.Set("rotated", true)
			call.Metadata.Set("keyVersion", rotated.Get("currentVersion"))
			return SummarizeKey(rotated, target.aliases)
		})
	if err != nil {
		return Out[apitypes.KeysRotateOutput]{}, err
	}
	return Out[apitypes.KeysRotateOutput]{Value: result}, nil
}

// ScheduleDeletion is POST {basePath}/keys/scheduleDeletion. Schedules destruction after a waiting period (7-30
// days, default 30). Meanwhile the key is unusable and the deletion can be cancelled; afterwards kms.maintain()
// destroys its material, aliases and grants. Requires iam:kms:delete and recent authentication.
func (api *KeysAPI) ScheduleDeletion(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysScheduleDeletionInput]) (Out[apitypes.KeysScheduleDeletionOutput], error) {
	waitingDays, err := Integer(coalesce(input.Get("waitingDays"), 30.0), "waitingDays", 7, 30)
	if err != nil {
		return Out[apitypes.KeysScheduleDeletionOutput]{}, err
	}
	server := api.server
	result, err := api.run(ctx, credential, input.Get("tenantId"), kmsAction("delete"),
		api.keyTarget(input.Get("tenantId"), input.Get("keyId"), nil),
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			if err := server.Auth.RequireRecent(call.Principal.Auth()); err != nil {
				return nil, err
			}
			if err := kmsStateChange(target.key, []string{"enabled", "disabled"}, "scheduled for deletion"); err != nil {
				return nil, err
			}
			deletionDate := float64(server.Now()) + waitingDays*kmsDay
			call.Metadata.Set("deletionDate", deletionDate)
			saved, err := api.saveKey(ctx, call.Tx, target.key, core.NewObject("state", "pending-deletion", "deletionDate", deletionDate))
			if err != nil {
				return nil, err
			}
			return SummarizeKey(saved, target.aliases)
		})
	if err != nil {
		return Out[apitypes.KeysScheduleDeletionOutput]{}, err
	}
	return Out[apitypes.KeysScheduleDeletionOutput]{Value: result}, nil
}

// CancelDeletion is POST {basePath}/keys/cancelDeletion. Cancels a scheduled deletion; the key comes back disabled.
// Requires iam:kms:delete.
func (api *KeysAPI) CancelDeletion(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysCancelDeletionInput]) (Out[apitypes.KeysCancelDeletionOutput], error) {
	result, err := api.run(ctx, credential, input.Get("tenantId"), kmsAction("delete"),
		api.keyTarget(input.Get("tenantId"), input.Get("keyId"), nil),
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			if err := kmsStateChange(target.key, []string{"pending-deletion"}, "restored"); err != nil {
				return nil, err
			}
			call.Metadata.Set("cancelled", true)
			saved, err := api.saveKey(ctx, call.Tx, target.key, core.NewObject("state", "disabled", "deletionDate", core.Undefined))
			if err != nil {
				return nil, err
			}
			return SummarizeKey(saved, target.aliases)
		})
	if err != nil {
		return Out[apitypes.KeysCancelDeletionOutput]{}, err
	}
	return Out[apitypes.KeysCancelDeletionOutput]{Value: result}, nil
}

func kmsAliasView(alias *core.Object) *core.Object {
	return core.NewObject("name", alias.Get("name"), "keyId", alias.Get("keyId"), "createdAt", alias.Get("createdAt"), "updatedAt", alias.Get("updatedAt"))
}

// kmsRefuseAliasKeyID refuses an alias where a key id is required.
func kmsRefuseAliasKeyID(value any) error {
	if text, ok := value.(string); ok && strings.HasPrefix(text, "alias/") {
		return invalidInput("keyId must be a key id, not an alias")
	}
	return nil
}

func kmsWith(items []string, item string) []string {
	return append(append([]string{}, items...), item)
}

func kmsWithout(items []string, item string) []string {
	out := []string{}
	for _, value := range items {
		if value != item {
			out = append(out, value)
		}
	}
	return out
}

// CreateAlias is POST {basePath}/keys/createAlias. Names a key `alias/{name}` (unique in the tenant, at most 50 per
// key). Requires iam:kms:update on the key and on `iam/kms/alias/{name}`.
func (api *KeysAPI) CreateAlias(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysCreateAliasInput]) (Out[apitypes.KeysCreateAliasOutput], error) {
	fail := func(err error) (Out[apitypes.KeysCreateAliasOutput], error) {
		return Out[apitypes.KeysCreateAliasOutput]{}, err
	}
	name, err := kmsAliasName(input.Get("alias"))
	if err != nil {
		return fail(err)
	}
	if err := kmsRefuseAliasKeyID(input.Get("keyId")); err != nil {
		return fail(err)
	}
	server := api.server
	result, err := api.run(ctx, credential, input.Get("tenantId"), kmsAction("update"),
		api.keyTarget(input.Get("tenantId"), input.Get("keyId"), nil),
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			tx, principal, tenant, metadata := call.Tx, call.Principal, call.Tenant, call.Metadata
			key, aliases := target.key, target.aliases
			if err := api.assertAliasAllowed(ctx, call, name); err != nil {
				return nil, err
			}
			if key.Get("state") == "pending-deletion" {
				if err := kmsStateChange(key, []string{"enabled", "disabled"}, "given an alias"); err != nil {
					return nil, err
				}
			}
			taken, err := tx.Find(ctx, "kmsAliases", core.NewObject("tenantId", tenant.Get("id"), "uniqueKey", name), nil)
			if err != nil {
				return nil, err
			}
			if len(taken) > 0 {
				return nil, core.NewIamError("CONFLICT", "That alias is already in use", 409)
			}
			if len(aliases) >= MaxAliasesPerKey {
				return nil, core.NewIamError("LIMIT_EXCEEDED", "A key has at most "+core.NumberString(MaxAliasesPerKey)+" aliases", 409)
			}
			tags, _ := key.Get("tags").(*core.Object)
			if err := api.assertNoNewRights(ctx, call, key, tags, aliases, tags, kmsWith(aliases, name)); err != nil {
				return nil, err
			}
			now := float64(server.Now())
			alias, err := tx.Insert(ctx, "kmsAliases", core.NewObject(
				"id", ID(),
				"tenantId", tenant.Get("id"),
				"uniqueKey", name,
				"name", name,
				"keyId", key.Get("id"),
				"createdAt", now,
				"createdBy", principal.Identity.Get("id"),
				"updatedAt", now,
			))
			if err != nil {
				return nil, err
			}
			metadata.Set("alias", name)
			return core.NewObject("name", name, "keyId", alias.Get("keyId"), "createdAt", now, "updatedAt", now), nil
		})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.KeysCreateAliasOutput]{Value: result}, nil
}

// UpdateAlias is POST {basePath}/keys/updateAlias. Points an alias at another key of the same usage and kind, so
// applications that name the alias switch keys without a deploy. Requires iam:kms:update on both keys and on
// `iam/kms/alias/{name}`.
func (api *KeysAPI) UpdateAlias(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysUpdateAliasInput]) (Out[apitypes.KeysUpdateAliasOutput], error) {
	fail := func(err error) (Out[apitypes.KeysUpdateAliasOutput], error) {
		return Out[apitypes.KeysUpdateAliasOutput]{}, err
	}
	name, err := kmsAliasName(input.Get("alias"))
	if err != nil {
		return fail(err)
	}
	if err := kmsRefuseAliasKeyID(input.Get("keyId")); err != nil {
		return fail(err)
	}
	server := api.server
	result, err := api.run(ctx, credential, input.Get("tenantId"), kmsAction("update"),
		api.keyTarget(input.Get("tenantId"), input.Get("keyId"), nil),
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			key, aliases := target.key, target.aliases
			if err := api.assertAliasAllowed(ctx, call, name); err != nil {
				return nil, err
			}
			found, err := call.Tx.Find(ctx, "kmsAliases", core.NewObject("tenantId", call.Tenant.Get("id"), "uniqueKey", name), nil)
			if err != nil {
				return nil, err
			}
			if len(found) == 0 {
				return nil, core.NewIamError("NOT_FOUND", "Alias not found", 404)
			}
			alias := found[0]
			if key.Get("state") == "pending-deletion" {
				if err := kmsStateChange(key, []string{"enabled", "disabled"}, "given an alias"); err != nil {
					return nil, err
				}
			}
			if !core.StrictEquals(alias.Get("keyId"), key.Get("id")) && len(aliases) >= MaxAliasesPerKey {
				return nil, core.NewIamError("LIMIT_EXCEEDED", "A key has at most "+core.NumberString(MaxAliasesPerKey)+" aliases", 409)
			}
			previous, err := FindKey(ctx, call.Tx, jsString(call.Tenant.Get("id")), alias.Get("keyId"))
			if err != nil {
				return nil, err
			}
			if !core.StrictEquals(previous.Get("keyUsage"), key.Get("keyUsage")) ||
				kmsSpecFamily(jsString(previous.Get("keySpec"))) != kmsSpecFamily(jsString(key.Get("keySpec"))) {
				return nil, invalidInput("An alias can only move to a key of the same kind and usage")
			}
			previousAliases, err := AliasNames(ctx, call.Tx, previous)
			if err != nil {
				return nil, err
			}
			attributes, err := KeyAttributes(previous, previousAliases, nil)
			if err != nil {
				return nil, err
			}
			allowed, err := call.Allowed(ctx, kmsAction("update"), GuardTarget{ResourceID: "kms/" + jsString(previous.Get("id")), Attributes: attributes})
			if err != nil {
				return nil, err
			}
			if !allowed {
				return nil, NewOperationDenied("You may not manage the key the alias names now")
			}
			if !core.StrictEquals(previous.Get("id"), key.Get("id")) {
				// The new key gains the name and the old one loses it: neither may open anything for the caller.
				tags, _ := key.Get("tags").(*core.Object)
				if err := api.assertNoNewRights(ctx, call, key, tags, aliases, tags, kmsWith(aliases, name)); err != nil {
					return nil, err
				}
				previousTags, _ := previous.Get("tags").(*core.Object)
				if err := api.assertNoNewRights(ctx, call, previous, previousTags, previousAliases, previousTags, kmsWithout(previousAliases, name)); err != nil {
					return nil, err
				}
			}
			updated := alias.Spread()
			updated.Set("keyId", key.Get("id"))
			updated.Set("updatedAt", float64(server.Now()))
			if _, err := call.Tx.Put(ctx, "kmsAliases", updated); err != nil {
				return nil, err
			}
			call.Metadata.Assign(core.NewObject("alias", name, "previousKeyId", previous.Get("id")))
			return core.NewObject("name", name, "keyId", updated.Get("keyId"), "createdAt", updated.Get("createdAt"), "updatedAt", updated.Get("updatedAt")), nil
		})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.KeysUpdateAliasOutput]{Value: result}, nil
}

// DeleteAlias is POST {basePath}/keys/deleteAlias. Removes an alias; the key stays. Requires iam:kms:update on the
// key it names and on `iam/kms/alias/{name}`.
func (api *KeysAPI) DeleteAlias(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysDeleteAliasInput]) (Out[apitypes.KeysDeleteAliasOutput], error) {
	name, err := kmsAliasName(input.Get("alias"))
	if err != nil {
		return Out[apitypes.KeysDeleteAliasOutput]{}, err
	}
	result, err := api.run(ctx, credential, input.Get("tenantId"), kmsAction("update"),
		api.keyTarget(input.Get("tenantId"), name, nil),
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			key, aliases := target.key, target.aliases
			if err := api.assertAliasAllowed(ctx, call, name); err != nil {
				return nil, err
			}
			tags, _ := key.Get("tags").(*core.Object)
			if err := api.assertNoNewRights(ctx, call, key, tags, aliases, tags, kmsWithout(aliases, name)); err != nil {
				return nil, err
			}
			found, err := call.Tx.Find(ctx, "kmsAliases", core.NewObject("tenantId", call.Tenant.Get("id"), "uniqueKey", name), nil)
			if err != nil {
				return nil, err
			}
			if len(found) == 0 {
				return nil, errors.New("Cannot read properties of undefined (reading 'id')")
			}
			if err := call.Tx.Delete(ctx, "kmsAliases", jsString(found[0].Get("id"))); err != nil {
				return nil, err
			}
			call.Metadata.Set("alias", name)
			return core.NewObject("success", true), nil
		})
	if err != nil {
		return Out[apitypes.KeysDeleteAliasOutput]{}, err
	}
	return Out[apitypes.KeysDeleteAliasOutput]{Value: result}, nil
}

// ListAliases is POST {basePath}/keys/listAliases. Every alias of the tenant, or of one key. Requires iam:kms:read
// on `iam/kms` (or on that key).
func (api *KeysAPI) ListAliases(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysListAliasesInput]) (Out[apitypes.KeysListAliasesOutput], error) {
	views := func(aliases []*core.Object) []any {
		sortStable(aliases, kmsByName)
		list := make([]any, len(aliases))
		for index, alias := range aliases {
			list[index] = kmsAliasView(alias)
		}
		return list
	}
	var result any
	var err error
	if keyID := input.Get("keyId"); !isUndefined(keyID) {
		result, err = api.run(ctx, credential, input.Get("tenantId"), kmsAction("read"),
			api.keyTarget(input.Get("tenantId"), keyID, nil),
			func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
				aliases, err := call.Tx.Find(ctx, "kmsAliases", core.NewObject("tenantId", target.key.Get("tenantId"), "keyId", target.key.Get("id")), nil)
				if err != nil {
					return nil, err
				}
				return views(aliases), nil
			})
	} else {
		result, err = api.run(ctx, credential, input.Get("tenantId"), kmsAction("read"), kmsTenantTarget,
			func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
				aliases, err := call.Tx.Find(ctx, "kmsAliases", core.NewObject("tenantId", call.Tenant.Get("id")), nil)
				if err != nil {
					return nil, err
				}
				return views(aliases), nil
			})
	}
	if err != nil {
		return Out[apitypes.KeysListAliasesOutput]{}, err
	}
	return Out[apitypes.KeysListAliasesOutput]{Value: result}, nil
}

// CreateGrant is POST {basePath}/keys/createGrant. Grants an identity (a person, service account or agent) named
// operations on one key, optionally until `expiresAt` and, for encryption operations, only with a given encryption
// context. A grant only passes on what its creator holds: every operation must be allowed to the caller by policy
// now, and each use checks again that the creator could still make that very call. Requires iam:kms:grant from a
// user session or API key acting in its own right; at most 50 per key.
func (api *KeysAPI) CreateGrant(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysCreateGrantInput]) (Out[apitypes.KeysCreateGrantOutput], error) {
	fail := func(err error) (Out[apitypes.KeysCreateGrantOutput], error) {
		return Out[apitypes.KeysCreateGrantOutput]{}, err
	}
	if granteeType := input.Get("granteeType"); !isUndefined(granteeType) && granteeType != "identity" {
		return fail(invalidInput("Grants name one identity; grant a group access with a role instead"))
	}
	granteeID, err := Text(input.Get("granteeId"), "granteeId")
	if err != nil {
		return fail(err)
	}
	name, _, err := kmsOptionalText(input.Get("name"), "name", 128)
	if err != nil {
		return fail(err)
	}
	server := api.server
	result, err := api.run(ctx, credential, input.Get("tenantId"), kmsAction("grant"),
		api.keyTarget(input.Get("tenantId"), input.Get("keyId"), nil),
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			tx, tenant, principal, metadata := call.Tx, call.Tenant, call.Principal, call.Metadata
			key, aliases := target.key, target.aliases
			// A grant is checked against its creator's own access for as long as it lives, so it must be made by an
			// identity of this tenant acting in its own right, not a role, token or delegated session.
			if !kmsActsInOwnRight(principal) || !core.StrictEquals(principal.Identity.Get("tenantId"), tenant.Get("id")) {
				return nil, NewOperationDenied("Create grants from your own session or API key")
			}
			if key.Get("state") == "pending-deletion" {
				if err := kmsStateChange(key, []string{"enabled", "disabled"}, "granted"); err != nil {
					return nil, err
				}
			}
			if err := AssertUnmanaged(key); err != nil {
				return nil, err
			}
			operations, err := GrantOperations(input.Get("operations"), jsString(key.Get("keyUsage")))
			if err != nil {
				return nil, err
			}
			constraints, err := GrantConstraints(input.Get("constraints"), operations)
			if err != nil {
				return nil, err
			}
			var expiresAt *float64
			if value := input.Get("expiresAt"); !isUndefined(value) {
				expiry, err := server.BindingExpiry(value)
				if err != nil {
					return nil, err
				}
				expiresAt = &expiry
			}
			if _, err := server.ActiveIdentity(ctx, tx, granteeID, jsString(tenant.Get("id"))); err != nil {
				return nil, err
			}
			// Checked with the context the grant is limited to, where it names one exactly.
			var exact *core.Object
			if constraints != nil {
				exact, _ = constraints.Get("encryptionContextEquals").(*core.Object)
			}
			for _, operation := range operations {
				action := kmsAction(operation)
				var extra *core.Object
				if exact != nil && operation != "read" {
					extra = core.NewObject("context", exact)
				}
				attributes, err := KeyAttributes(key, aliases, extra)
				if err != nil {
					return nil, err
				}
				allowed, err := call.Allowed(ctx, action, GuardTarget{ResourceID: "kms/" + jsString(key.Get("id")), Attributes: attributes})
				if err != nil {
					return nil, err
				}
				if !allowed {
					return nil, NewOperationDenied("You may not grant " + operation + ": you do not hold it")
				}
			}
			existing, err := tx.Find(ctx, "kmsGrants", core.NewObject("tenantId", tenant.Get("id"), "keyId", key.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			if len(existing) >= MaxGrantsPerKey {
				return nil, core.NewIamError("LIMIT_EXCEEDED", "A key has at most "+core.NumberString(MaxGrantsPerKey)+" grants", 409)
			}
			grant := core.NewObject(
				"id", ID(),
				"tenantId", tenant.Get("id"),
				"keyId", key.Get("id"),
				"granteeType", "identity",
				"granteeId", granteeID,
				"operations", stringsOf(operations),
				"createdAt", float64(server.Now()),
				"createdBy", principal.Identity.Get("id"),
			)
			if name != "" {
				grant.Set("name", name)
			}
			if constraints != nil {
				grant.Set("constraints", constraints)
			}
			if expiresAt != nil {
				grant.Set("expiresAt", *expiresAt)
			}
			if _, err := tx.Insert(ctx, "kmsGrants", grant); err != nil {
				return nil, err
			}
			metadata.Assign(core.NewObject(
				"grantId", grant.Get("id"),
				"granteeType", grant.Get("granteeType"),
				"granteeId", granteeID,
				"operations", stringsOf(operations),
			))
			if constraints != nil {
				metadata.Set("constraints", core.CloneValue(constraints))
			}
			if expiresAt != nil {
				metadata.Set("expiresAt", *expiresAt)
			}
			return SummarizeGrant(grant, server.Now())
		})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.KeysCreateGrantOutput]{Value: result}, nil
}

// ListGrants is POST {basePath}/keys/listGrants. The key's grants, newest first, with `active` (not lapsed).
// Requires iam:kms:read; a caller reading through a `read` grant of its own sees only its own grants.
func (api *KeysAPI) ListGrants(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysListGrantsInput]) (Out[apitypes.KeysListGrantsOutput], error) {
	server := api.server
	result, err := api.run(ctx, credential, input.Get("tenantId"), kmsAction("read"),
		api.keyTarget(input.Get("tenantId"), input.Get("keyId"), nil),
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			grants, err := call.Tx.Find(ctx, "kmsGrants", core.NewObject("tenantId", target.key.Get("tenantId"), "keyId", target.key.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			viaGrant := !isUndefined(call.Metadata.Get("grantId"))
			visible := []*core.Object{}
			for _, grant := range grants {
				if !viaGrant || core.StrictEquals(grant.Get("granteeId"), call.Principal.Identity.Get("id")) {
					visible = append(visible, grant)
				}
			}
			sortStable(visible, kmsByNewest)
			list := make([]any, 0, len(visible))
			for _, grant := range visible {
				summary, err := SummarizeGrant(grant, server.Now())
				if err != nil {
					return nil, err
				}
				list = append(list, summary)
			}
			return list, nil
		})
	if err != nil {
		return Out[apitypes.KeysListGrantsOutput]{}, err
	}
	return Out[apitypes.KeysListGrantsOutput]{Value: result}, nil
}

// RevokeGrant is POST {basePath}/keys/revokeGrant. Revokes a grant. Requires iam:kms:grant on its key.
func (api *KeysAPI) RevokeGrant(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysRevokeGrantInput]) (Out[apitypes.KeysRevokeGrantOutput], error) {
	server := api.server
	result, err := api.run(ctx, credential, input.Get("tenantId"), kmsAction("grant"),
		func(ctx context.Context, tx core.IamStore, principal *Principal) (kmsKeyTarget, error) {
			grantID, err := Text(input.Get("grantId"), "grantId")
			if err != nil {
				return kmsKeyTarget{}, err
			}
			tenantID, err := Text(input.Get("tenantId"), "tenantId")
			if err != nil {
				return kmsKeyTarget{}, err
			}
			grant, err := server.Scoped(ctx, tx, "kmsGrants", grantID, tenantID)
			if err != nil {
				return kmsKeyTarget{}, err
			}
			return api.locateKey(ctx, tx, input.Get("tenantId"), grant.Get("keyId"), nil)
		},
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			grantID := jsString(input.Get("grantId"))
			if err := call.Tx.Delete(ctx, "kmsGrants", grantID); err != nil {
				return nil, err
			}
			call.Metadata.Assign(core.NewObject("grantId", input.Get("grantId"), "revoked", true))
			return core.NewObject("success", true), nil
		})
	if err != nil {
		return Out[apitypes.KeysRevokeGrantOutput]{}, err
	}
	return Out[apitypes.KeysRevokeGrantOutput]{Value: result}, nil
}

// RetireGrant is POST {basePath}/keys/retireGrant. Gives up a grant made to the caller's own identity: no permission
// needed, so a workload can drop access it no longer uses. Audited as `kms:grant-retire`.
func (api *KeysAPI) RetireGrant(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysRetireGrantInput]) (Out[apitypes.KeysRetireGrantOutput], error) {
	fail := func(err error) (Out[apitypes.KeysRetireGrantOutput], error) {
		return Out[apitypes.KeysRetireGrantOutput]{}, err
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return fail(err)
	}
	grantID, err := Text(input.Get("grantId"), "grantId")
	if err != nil {
		return fail(err)
	}
	server := api.server
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return fail(err)
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (any, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		tenant, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		if tenant.Get("status") != "active" {
			return nil, core.NewIamError("TENANT_INACTIVE", "The tenant is not active", 403)
		}
		grant, err := server.Scoped(ctx, tx, "kmsGrants", grantID, tenantID)
		if err != nil {
			return nil, err
		}
		if !kmsActsInOwnRight(principal) || principal.Session.Get("tenantId") != tenantID ||
			!core.StrictEquals(grant.Get("granteeId"), principal.Identity.Get("id")) {
			return nil, core.NewIamError("ACCESS_DENIED", "Only the grantee can retire this grant", 403)
		}
		if err := tx.Delete(ctx, "kmsGrants", jsString(grant.Get("id"))); err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "kms:grant-retire", tenantID, "kms/"+jsString(grant.Get("keyId")), "allow", false,
			core.NewObject("grantId", grant.Get("id"))); err != nil {
			return nil, err
		}
		return core.NewObject("success", true), nil
	})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.KeysRetireGrantOutput]{Value: result}, nil
}

// kmsRefuseSymmetric refuses keys without a public key.
func kmsRefuseSymmetric(key *core.Object) error {
	if kmsSpecFamily(jsString(key.Get("keySpec"))) == "aes" || key.Get("keyUsage") == "mac" {
		return invalidInput("Symmetric keys have no public key")
	}
	return nil
}

// PublicKey is POST {basePath}/keys/publicKey. The public key of an asymmetric key version (default: current) as
// SPKI PEM and JWK (`kid` = `{keyId}.{version}`), for verifying signatures or encrypting offline. Requires
// iam:kms:read.
func (api *KeysAPI) PublicKey(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysPublicKeyInput]) (Out[apitypes.KeysPublicKeyOutput], error) {
	result, err := api.run(ctx, credential, input.Get("tenantId"), kmsAction("read"),
		api.keyTarget(input.Get("tenantId"), input.Get("keyId"), nil),
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			key := target.key
			if err := kmsRefuseSymmetric(key); err != nil {
				return nil, err
			}
			number, err := kmsRequestedVersion(key, input.Get("keyVersion"))
			if err != nil {
				return nil, err
			}
			version, err := KeyVersion(ctx, call.Tx, key, number)
			if err != nil {
				return nil, err
			}
			algorithms, err := KeyAlgorithms(key)
			if err != nil {
				return nil, err
			}
			jwk, err := kmsPublicJwk(key, version)
			if err != nil {
				return nil, err
			}
			return core.NewObject(
				"keyId", key.Get("id"),
				"keyVersion", version.Get("version"),
				"keySpec", key.Get("keySpec"),
				"keyUsage", key.Get("keyUsage"),
				"algorithms", stringsOf(algorithms),
				"publicKeyPem", version.Get("publicKeyPem"),
				"jwk", jwk,
			), nil
		})
	if err != nil {
		return Out[apitypes.KeysPublicKeyOutput]{}, err
	}
	return Out[apitypes.KeysPublicKeyOutput]{Value: result}, nil
}

// Jwks is POST {basePath}/keys/jwks. Every version's public key of an asymmetric key as a JWK Set, for JWT
// verifiers. Requires iam:kms:read.
func (api *KeysAPI) Jwks(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysJwksInput]) (Out[apitypes.KeysJwksOutput], error) {
	result, err := api.run(ctx, credential, input.Get("tenantId"), kmsAction("read"),
		api.keyTarget(input.Get("tenantId"), input.Get("keyId"), nil),
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			key := target.key
			if err := kmsRefuseSymmetric(key); err != nil {
				return nil, err
			}
			versions, err := call.Tx.Find(ctx, "kmsKeyVersions", core.NewObject("tenantId", key.Get("tenantId"), "keyId", key.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			sortStable(versions, kmsByVersionDescending)
			keys := make([]any, 0, len(versions))
			for _, version := range versions {
				jwk, err := kmsPublicJwk(key, version)
				if err != nil {
					return nil, err
				}
				keys = append(keys, jwk)
			}
			return core.NewObject("keys", keys), nil
		})
	if err != nil {
		return Out[apitypes.KeysJwksOutput]{}, err
	}
	return Out[apitypes.KeysJwksOutput]{Value: result}, nil
}

// Encrypt is POST {basePath}/keys/encrypt. Encrypts up to 4 KiB (`plaintext` as UTF-8 text, or `plaintextBase64`)
// under an encryption key's current version, bound to the optional `encryptionContext`. Returns a self-describing
// `ciphertext` (key and version inside). Requires iam:kms:encrypt.
func (api *KeysAPI) Encrypt(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysEncryptInput]) (Out[apitypes.KeysEncryptOutput], error) {
	fail := func(err error) (Out[apitypes.KeysEncryptOutput], error) {
		return Out[apitypes.KeysEncryptOutput]{}, err
	}
	body, err := Object(input.Body)
	if err != nil {
		return fail(err)
	}
	payload, err := Payload(body, "plaintext", MaxPlaintextBytes)
	if err != nil {
		return fail(err)
	}
	bound, err := EncryptionContext(input.Get("encryptionContext"), "")
	if err != nil {
		return fail(err)
	}
	isText, _ := payload.Get("text").(bool)
	result, err := api.encryptCall(ctx, credential, input.Get("tenantId"), input.Get("keyId"), payloadBytes(payload), isText, bound, nil)
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.KeysEncryptOutput]{Value: result}, nil
}

// Decrypt is POST {basePath}/keys/decrypt. Decrypts a ciphertext from `encrypt`, `generateDataKey` or `reEncrypt`
// with the same `encryptionContext`. Text comes back as `plaintext`, bytes as `plaintextBase64`. The key is read from
// the ciphertext; `keyId` (id or alias) additionally insists on it. A wrong context or a tampered ciphertext fails
// with `INVALID_CIPHERTEXT` and is audited as a denied decrypt. Requires iam:kms:decrypt.
func (api *KeysAPI) Decrypt(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysDecryptInput]) (Out[apitypes.KeysDecryptOutput], error) {
	fail := func(err error) (Out[apitypes.KeysDecryptOutput], error) {
		return Out[apitypes.KeysDecryptOutput]{}, err
	}
	bound, err := EncryptionContext(input.Get("encryptionContext"), "")
	if err != nil {
		return fail(err)
	}
	opened, err := api.decryptCall(ctx, credential, input.Get("tenantId"), input.Get("ciphertext"), bound, input.Get("keyId"), nil)
	if err != nil {
		return fail(err)
	}
	plaintext, _ := opened.Get("plaintext").([]byte)
	defer wipe(plaintext)
	result := core.NewObject()
	if opened.Get("text") == true {
		result.Set("plaintext", decodeUTF8(plaintext))
	} else {
		result.Set("plaintextBase64", base64.StdEncoding.EncodeToString(plaintext))
	}
	result.Set("keyId", opened.Get("keyId"))
	result.Set("keyVersion", opened.Get("keyVersion"))
	return Out[apitypes.KeysDecryptOutput]{Value: result}, nil
}

// ReEncrypt is POST {basePath}/keys/reEncrypt. Decrypts and encrypts again under `destinationKeyId` (and context)
// without the plaintext leaving the server. Needs iam:kms:decrypt on the source key and iam:kms:encrypt on the
// destination; audited as both.
func (api *KeysAPI) ReEncrypt(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysReEncryptInput]) (Out[apitypes.KeysReEncryptOutput], error) {
	fail := func(err error) (Out[apitypes.KeysReEncryptOutput], error) {
		return Out[apitypes.KeysReEncryptOutput]{}, err
	}
	source, err := EncryptionContext(input.Get("sourceEncryptionContext"), "sourceEncryptionContext")
	if err != nil {
		return fail(err)
	}
	destination, err := EncryptionContext(input.Get("destinationEncryptionContext"), "destinationEncryptionContext")
	if err != nil {
		return fail(err)
	}
	// One id links the decrypt and encrypt events of the same re-encryption.
	note := core.NewObject("reEncryptId", ID())
	opened, err := api.decryptCall(ctx, credential, input.Get("tenantId"), input.Get("ciphertext"), source, core.Undefined, note)
	if err != nil {
		return fail(err)
	}
	plaintext, _ := opened.Get("plaintext").([]byte)
	defer wipe(plaintext)
	isText, _ := opened.Get("text").(bool)
	sealed, err := api.encryptCall(ctx, credential, input.Get("tenantId"), input.Get("destinationKeyId"), plaintext, isText, destination, note)
	if err != nil {
		return fail(err)
	}
	result := sealed.Spread()
	result.Set("sourceKeyId", opened.Get("keyId"))
	result.Set("sourceKeyVersion", opened.Get("keyVersion"))
	return Out[apitypes.KeysReEncryptOutput]{Value: result}, nil
}

// GenerateDataKey is POST {basePath}/keys/generateDataKey. A fresh data key (`bytes`: 16, 24, 32 (default) or 64)
// for encrypting large data locally: the plaintext (`plaintextBase64`, omitted with `includePlaintext: false`) to use
// and discard, and its `ciphertext` under the KMS key to store beside the data. Requires iam:kms:generate-data-key
// (and iam:kms:decrypt later).
func (api *KeysAPI) GenerateDataKey(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysGenerateDataKeyInput]) (Out[apitypes.KeysGenerateDataKeyOutput], error) {
	fail := func(err error) (Out[apitypes.KeysGenerateDataKeyOutput], error) {
		return Out[apitypes.KeysGenerateDataKeyOutput]{}, err
	}
	size, ok := core.Normalize(coalesce(input.Get("bytes"), 32.0)).(float64)
	if !ok || (size != 16 && size != 24 && size != 32 && size != 64) {
		return fail(invalidInput("bytes must be 16, 24, 32 or 64"))
	}
	bound, err := EncryptionContext(input.Get("encryptionContext"), "")
	if err != nil {
		return fail(err)
	}
	server := api.server
	result, err := api.run(ctx, credential, input.Get("tenantId"), kmsAction("generate-data-key"),
		api.keyTarget(input.Get("tenantId"), input.Get("keyId"), core.NewObject("context", bound)),
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			key := target.key
			if err := AssertUsable(key, "encrypt"); err != nil {
				return nil, err
			}
			if err := AssertUnmanaged(key); err != nil {
				return nil, err
			}
			version, err := KeyVersion(ctx, call.Tx, key, jsNumber(key.Get("currentVersion")))
			if err != nil {
				return nil, err
			}
			material := kmsRandomBytes(int(size))
			defer wipe(material)
			call.Metadata.Set("keyVersion", version.Get("version"))
			call.Metadata.Set("bytes", size)
			ciphertext, err := EncryptWith(server, key, version, material, false, bound)
			if err != nil {
				return nil, err
			}
			answer := core.NewObject("ciphertext", ciphertext)
			if input.Get("includePlaintext") != false {
				answer.Set("plaintextBase64", base64.StdEncoding.EncodeToString(material))
			}
			answer.Set("keyId", key.Get("id"))
			answer.Set("keyVersion", version.Get("version"))
			answer.Set("bytes", size)
			return answer, nil
		})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.KeysGenerateDataKeyOutput]{Value: result}, nil
}

// signingTarget locates a signing call's key with the requested algorithm as `resource.algorithm`.
func (api *KeysAPI) signingTarget(tenantID, keyID, algorithm any) func(ctx context.Context, tx core.IamStore, principal *Principal) (kmsKeyTarget, error) {
	return func(ctx context.Context, tx core.IamStore, principal *Principal) (kmsKeyTarget, error) {
		tenant, err := Text(tenantID, "tenantId")
		if err != nil {
			return kmsKeyTarget{}, err
		}
		key, err := FindKey(ctx, tx, tenant, keyID)
		if err != nil {
			return kmsKeyTarget{}, err
		}
		requested, err := kmsRequestedAlgorithm(key, algorithm)
		if err != nil {
			return kmsKeyTarget{}, err
		}
		return api.locateKey(ctx, tx, tenantID, key.Get("id"), core.NewObject("algorithm", requested))
	}
}

// Sign is POST {basePath}/keys/sign. Signs a message (`message` UTF-8 or `messageBase64`, up to 64 KiB) with a
// signing key's current version. `algorithm` defaults to the key's first (ES256, ES384, EdDSA, or PS256 for RSA);
// ECDSA signatures are DER unless `format: 'jose'` (raw r||s, as in JWS). Requires iam:kms:sign
// (`resource.algorithm` names the algorithm).
func (api *KeysAPI) Sign(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysSignInput]) (Out[apitypes.KeysSignOutput], error) {
	fail := func(err error) (Out[apitypes.KeysSignOutput], error) { return Out[apitypes.KeysSignOutput]{}, err }
	body, err := Object(input.Body)
	if err != nil {
		return fail(err)
	}
	payload, err := Payload(body, "message", MaxMessageBytes)
	if err != nil {
		return fail(err)
	}
	format, err := kmsSignatureFormat(input.Get("format"))
	if err != nil {
		return fail(err)
	}
	server := api.server
	result, err := api.run(ctx, credential, input.Get("tenantId"), kmsAction("sign"),
		api.signingTarget(input.Get("tenantId"), input.Get("keyId"), input.Get("algorithm")),
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			key := target.key
			if err := AssertUsable(key, "sign"); err != nil {
				return nil, err
			}
			// A certificate authority's key signs only through the pki API: a raw signature over a certificate body
			// would be a certificate nobody decided on.
			if err := AssertUnmanaged(key); err != nil {
				return nil, err
			}
			algorithm, err := SigningAlgorithm(key, target.Attributes.Get("algorithm"))
			if err != nil {
				return nil, err
			}
			version, err := KeyVersion(ctx, call.Tx, key, jsNumber(key.Get("currentVersion")))
			if err != nil {
				return nil, err
			}
			call.Metadata.Assign(core.NewObject("keyVersion", version.Get("version"), "algorithm", algorithm))
			signature, err := SignWith(server, version, algorithm, payloadBytes(payload), format)
			if err != nil {
				return nil, err
			}
			return core.NewObject(
				"signature", base64url(signature),
				"algorithm", algorithm,
				"format", format,
				"keyId", key.Get("id"),
				"keyVersion", version.Get("version"),
			), nil
		})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.KeysSignOutput]{Value: result}, nil
}

// Verify is POST {basePath}/keys/verify. Checks a signature from `sign` against the message, with `keyVersion`
// (default: current) and `algorithm` (default: the key's first). Returns `{ valid }`; a mismatch is not an error.
// Requires iam:kms:verify.
func (api *KeysAPI) Verify(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysVerifyInput]) (Out[apitypes.KeysVerifyOutput], error) {
	fail := func(err error) (Out[apitypes.KeysVerifyOutput], error) { return Out[apitypes.KeysVerifyOutput]{}, err }
	body, err := Object(input.Body)
	if err != nil {
		return fail(err)
	}
	payload, err := Payload(body, "message", MaxMessageBytes)
	if err != nil {
		return fail(err)
	}
	signature, err := Base64Bytes(input.Get("signature"), "signature", 1024)
	if err != nil {
		return fail(err)
	}
	format, err := kmsSignatureFormat(input.Get("format"))
	if err != nil {
		return fail(err)
	}
	result, err := api.run(ctx, credential, input.Get("tenantId"), kmsAction("verify"),
		api.signingTarget(input.Get("tenantId"), input.Get("keyId"), input.Get("algorithm")),
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			key := target.key
			if err := AssertUsable(key, "sign"); err != nil {
				return nil, err
			}
			algorithm, err := SigningAlgorithm(key, target.Attributes.Get("algorithm"))
			if err != nil {
				return nil, err
			}
			number, err := kmsRequestedVersion(key, input.Get("keyVersion"))
			if err != nil {
				return nil, err
			}
			version, err := KeyVersion(ctx, call.Tx, key, number)
			if err != nil {
				return nil, err
			}
			valid, err := VerifyWith(version, algorithm, payloadBytes(payload), signature, format)
			if err != nil {
				return nil, err
			}
			call.Metadata.Assign(core.NewObject("keyVersion", version.Get("version"), "algorithm", algorithm, "valid", valid))
			return core.NewObject("valid", valid, "algorithm", algorithm, "keyId", key.Get("id"), "keyVersion", version.Get("version")), nil
		})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.KeysVerifyOutput]{Value: result}, nil
}

// GenerateMac is POST {basePath}/keys/generateMac. An HMAC (`mac`, base64url) of a message with a MAC key's current
// version. Requires iam:kms:generate-mac.
func (api *KeysAPI) GenerateMac(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysGenerateMacInput]) (Out[apitypes.KeysGenerateMacOutput], error) {
	fail := func(err error) (Out[apitypes.KeysGenerateMacOutput], error) {
		return Out[apitypes.KeysGenerateMacOutput]{}, err
	}
	body, err := Object(input.Body)
	if err != nil {
		return fail(err)
	}
	payload, err := Payload(body, "message", MaxMessageBytes)
	if err != nil {
		return fail(err)
	}
	server := api.server
	result, err := api.run(ctx, credential, input.Get("tenantId"), kmsAction("generate-mac"),
		api.keyTarget(input.Get("tenantId"), input.Get("keyId"), nil),
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			key := target.key
			if err := AssertUsable(key, "mac"); err != nil {
				return nil, err
			}
			if err := AssertUnmanaged(key); err != nil {
				return nil, err
			}
			version, err := KeyVersion(ctx, call.Tx, key, jsNumber(key.Get("currentVersion")))
			if err != nil {
				return nil, err
			}
			call.Metadata.Set("keyVersion", version.Get("version"))
			mac, err := MacWith(server, key, version, payloadBytes(payload))
			if err != nil {
				return nil, err
			}
			algorithms, err := KeyAlgorithms(key)
			if err != nil {
				return nil, err
			}
			return core.NewObject("mac", base64url(mac), "algorithm", algorithms[0], "keyId", key.Get("id"), "keyVersion", version.Get("version")), nil
		})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.KeysGenerateMacOutput]{Value: result}, nil
}

// VerifyMac is POST {basePath}/keys/verifyMac. Checks a MAC in constant time with `keyVersion` (default: current).
// Returns `{ valid }`. Requires iam:kms:verify-mac.
func (api *KeysAPI) VerifyMac(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysVerifyMacInput]) (Out[apitypes.KeysVerifyMacOutput], error) {
	fail := func(err error) (Out[apitypes.KeysVerifyMacOutput], error) {
		return Out[apitypes.KeysVerifyMacOutput]{}, err
	}
	body, err := Object(input.Body)
	if err != nil {
		return fail(err)
	}
	payload, err := Payload(body, "message", MaxMessageBytes)
	if err != nil {
		return fail(err)
	}
	expected, err := Base64Bytes(input.Get("mac"), "mac", 128)
	if err != nil {
		return fail(err)
	}
	server := api.server
	result, err := api.run(ctx, credential, input.Get("tenantId"), kmsAction("verify-mac"),
		api.keyTarget(input.Get("tenantId"), input.Get("keyId"), nil),
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			key := target.key
			if err := AssertUsable(key, "mac"); err != nil {
				return nil, err
			}
			if err := AssertUnmanaged(key); err != nil {
				return nil, err
			}
			number, err := kmsRequestedVersion(key, input.Get("keyVersion"))
			if err != nil {
				return nil, err
			}
			version, err := KeyVersion(ctx, call.Tx, key, number)
			if err != nil {
				return nil, err
			}
			mac, err := MacWith(server, key, version, payloadBytes(payload))
			if err != nil {
				return nil, err
			}
			valid, _ := SameBytes(mac, expected)
			call.Metadata.Assign(core.NewObject("keyVersion", version.Get("version"), "valid", valid))
			return core.NewObject("valid", valid, "keyId", key.Get("id"), "keyVersion", version.Get("version")), nil
		})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.KeysVerifyMacOutput]{Value: result}, nil
}

// SignJwt is POST {basePath}/keys/signJwt. Signs a JWT with a signing key (ES256, ES384, EdDSA, PS256-PS512,
// RS256-RS512) or a MAC key (HS256-HS512): header `{ alg, kid, typ }` with `kid` = `{keyId}.{version}` (matching
// `jwks`), the given `claims`, `iat` when absent, and `exp` from `expiresInSeconds` (1 s to 1 year). Requires
// iam:kms:sign or iam:kms:generate-mac, with `resource.algorithm`, `resource.jwt` (true), `resource.jwt.typ` and the
// `sub`, `iss` and `aud` claims as `resource.jwt.*`, so policies can limit which tokens a caller may mint.
func (api *KeysAPI) SignJwt(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysSignJwtInput]) (Out[apitypes.KeysSignJwtOutput], error) {
	fail := func(err error) (Out[apitypes.KeysSignJwtOutput], error) {
		return Out[apitypes.KeysSignJwtOutput]{}, err
	}
	given, err := Object(input.Get("claims"))
	if err != nil {
		return fail(err)
	}
	claims := given.Spread()
	var expiresIn *float64
	if value := input.Get("expiresInSeconds"); !isUndefined(value) {
		seconds, err := Integer(value, "expiresInSeconds", 1, 366*86400)
		if err != nil {
			return fail(err)
		}
		expiresIn = &seconds
	}
	tokenType := "JWT"
	if value := input.Get("type"); !isUndefined(value) {
		if tokenType, err = Text(value, "type", 64); err != nil {
			return fail(err)
		}
	}
	server := api.server
	tenantID := input.Get("tenantId")
	action := GuardAction[kmsKeyTarget]{Of: func(target kmsKeyTarget) string {
		if target.key.Get("keyUsage") == "mac" {
			return kmsAction("generate-mac")
		}
		return kmsAction("sign")
	}}
	result, err := api.guard.Run(ctx, credential, guardTenantID(tenantID), action,
		func(ctx context.Context, tx core.IamStore, principal *Principal) (kmsKeyTarget, error) {
			tenant, err := Text(tenantID, "tenantId")
			if err != nil {
				return kmsKeyTarget{}, err
			}
			key, err := FindKey(ctx, tx, tenant, input.Get("keyId"))
			if err != nil {
				return kmsKeyTarget{}, err
			}
			if key.Get("keyUsage") == "encrypt" {
				return kmsKeyTarget{}, invalidInput("Encryption keys cannot sign tokens")
			}
			requested, err := kmsRequestedAlgorithm(key, input.Get("algorithm"))
			if err != nil {
				return kmsKeyTarget{}, err
			}
			target, err := api.locateKey(ctx, tx, tenantID, key.Get("id"), core.NewObject("algorithm", requested))
			if err != nil {
				return kmsKeyTarget{}, err
			}
			target.Attributes.Assign(kmsJwtAttributes(claims, tokenType))
			return target, nil
		},
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			key := target.key
			if err := AssertUsable(key, jsString(key.Get("keyUsage"))); err != nil {
				return nil, err
			}
			if err := AssertUnmanaged(key); err != nil {
				return nil, err
			}
			algorithm, err := SigningAlgorithm(key, target.Attributes.Get("algorithm"))
			if err != nil {
				return nil, err
			}
			version, err := KeyVersion(ctx, call.Tx, key, jsNumber(key.Get("currentVersion")))
			if err != nil {
				return nil, err
			}
			now := math.Floor(float64(server.Now()) / 1000)
			if isUndefined(claims.Get("iat")) {
				claims.Set("iat", now)
			}
			if expiresIn != nil {
				claims.Set("exp", now+*expiresIn)
			}
			claimsJSON, _, err := core.Stringify(claims)
			if err != nil {
				return nil, err
			}
			encodedClaims := base64url(utf8Bytes(claimsJSON))
			if len(encodedClaims) > 65536 {
				return nil, invalidInput("claims are larger than 48 KiB")
			}
			header := core.NewObject("alg", algorithm, "kid", jsString(key.Get("id"))+"."+core.NumberString(jsNumber(version.Get("version"))), "typ", tokenType)
			headerJSON, _, err := core.Stringify(header)
			if err != nil {
				return nil, err
			}
			signingInput := base64url(utf8Bytes(headerJSON)) + "." + encodedClaims
			var signature []byte
			if key.Get("keyUsage") == "mac" {
				signature, err = MacWith(server, key, version, utf8Bytes(signingInput))
			} else {
				signature, err = SignWith(server, version, algorithm, utf8Bytes(signingInput), "jose")
			}
			if err != nil {
				return nil, err
			}
			call.Metadata.Assign(core.NewObject("keyVersion", version.Get("version"), "algorithm", algorithm, "jwt", true))
			return core.NewObject(
				"token", signingInput+"."+base64url(signature),
				"algorithm", algorithm,
				"keyId", key.Get("id"),
				"keyVersion", version.Get("version"),
			), nil
		})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.KeysSignJwtOutput]{Value: result}, nil
}

// VerifyJwt is POST {basePath}/keys/verifyJwt. Verifies a JWT signed by `signJwt` (or any JWS made with the key):
// the `kid` names the key version, `alg` must be one the key supports, and `exp` / `nbf` are checked with
// `clockToleranceSeconds` (default 60), plus `audience` and `issuer` when given. Returns `{ valid: true, claims,
// header }` or `{ valid: false, reason }`. Requires iam:kms:verify or iam:kms:verify-mac.
func (api *KeysAPI) VerifyJwt(ctx context.Context, credential core.CredentialInput, input In[apitypes.KeysVerifyJwtInput]) (Out[apitypes.KeysVerifyJwtOutput], error) {
	fail := func(err error) (Out[apitypes.KeysVerifyJwtOutput], error) {
		return Out[apitypes.KeysVerifyJwtOutput]{}, err
	}
	token, err := Text(input.Get("token"), "token", 131072)
	if err != nil {
		return fail(err)
	}
	parts := strings.Split(token, ".")
	malformed := len(parts) != 3
	for _, part := range parts {
		if !kmsTokenPart.MatchString(part) {
			malformed = true
		}
	}
	if malformed {
		return fail(invalidInput("token must be a compact JWS"))
	}
	header, err := kmsJSONSegment(parts[0], "header")
	if err != nil {
		return fail(err)
	}
	claims, err := kmsJSONSegment(parts[1], "claims")
	if err != nil {
		return fail(err)
	}
	kid, _ := ParseKid(header.Get("kid"))
	if kid == nil && isUndefined(input.Get("keyId")) {
		return fail(invalidInput("The token has no KMS kid; pass keyId"))
	}
	tolerance, err := Integer(coalesce(input.Get("clockToleranceSeconds"), 60.0), "clockToleranceSeconds", 0, 600)
	if err != nil {
		return fail(err)
	}
	server := api.server
	tenantInput := input.Get("tenantId")
	action := GuardAction[kmsKeyTarget]{Of: func(target kmsKeyTarget) string {
		if target.key.Get("keyUsage") == "mac" {
			return kmsAction("verify-mac")
		}
		return kmsAction("verify")
	}}
	result, err := api.guard.Run(ctx, credential, guardTenantID(tenantInput), action,
		func(ctx context.Context, tx core.IamStore, principal *Principal) (kmsKeyTarget, error) {
			tenantID, err := Text(tenantInput, "tenantId")
			if err != nil {
				return kmsKeyTarget{}, err
			}
			reference := input.Get("keyId")
			if nullish(reference) {
				if kid == nil {
					return kmsKeyTarget{}, errors.New("Cannot read properties of undefined (reading 'keyId')")
				}
				reference = kid.Get("keyId")
			}
			key, err := FindKey(ctx, tx, tenantID, reference)
			if err != nil {
				return kmsKeyTarget{}, err
			}
			if kid != nil && !core.StrictEquals(kid.Get("keyId"), key.Get("id")) {
				return kmsKeyTarget{}, invalidInput("The token was not signed with that key")
			}
			if key.Get("keyUsage") == "encrypt" {
				return kmsKeyTarget{}, invalidInput("Encryption keys do not sign tokens")
			}
			// The token's own claim, bounded before it reaches policies as `resource.algorithm`.
			algorithm := "none"
			if alg, ok := header.Get("alg").(string); ok && kmsAlgorithmName.MatchString(alg) {
				algorithm = alg
			}
			return api.locateKey(ctx, tx, tenantID, key.Get("id"), core.NewObject("algorithm", algorithm))
		},
		func(ctx context.Context, call GuardCall, target kmsKeyTarget) (any, error) {
			key := target.key
			if err := AssertUsable(key, jsString(key.Get("keyUsage"))); err != nil {
				return nil, err
			}
			algorithm := jsString(target.Attributes.Get("algorithm"))
			number := jsNumber(key.Get("currentVersion"))
			if kid != nil {
				number = jsNumber(kid.Get("version"))
			}
			version, err := KeyVersion(ctx, call.Tx, key, number)
			if err != nil {
				return nil, err
			}
			invalid := func(reason string) *core.Object {
				return core.NewObject("valid", false, "reason", reason, "keyId", key.Get("id"), "keyVersion", version.Get("version"))
			}
			outcome := func() (*core.Object, error) {
				algorithms, err := KeyAlgorithms(key)
				if err != nil {
					return nil, err
				}
				if !containsString(algorithms, algorithm) {
					return invalid("algorithm"), nil
				}
				// Critical extensions are not understood here, so a token that needs them is refused (RFC 7515 4.1.11).
				if !isUndefined(header.Get("crit")) {
					return invalid("header"), nil
				}
				timeClaim := func(value any) bool {
					if isUndefined(value) {
						return true
					}
					number, ok := value.(float64)
					return ok && !math.IsNaN(number) && !math.IsInf(number, 0)
				}
				if !timeClaim(claims.Get("exp")) || !timeClaim(claims.Get("nbf")) {
					return invalid("claims"), nil
				}
				signingInput := utf8Bytes(parts[0] + "." + parts[1])
				signature := nodeBase64Decode(parts[2])
				// One spelling per signature, so string-keyed replay caches cannot be sidestepped.
				if base64url(signature) != parts[2] {
					return invalid("signature"), nil
				}
				var valid bool
				if key.Get("keyUsage") == "mac" {
					mac, err := MacWith(server, key, version, signingInput)
					if err != nil {
						return nil, err
					}
					valid, _ = SameBytes(mac, signature)
				} else if valid, err = VerifyWith(version, algorithm, signingInput, signature, "jose"); err != nil {
					return nil, err
				}
				if !valid {
					return invalid("signature"), nil
				}
				now := math.Floor(float64(server.Now()) / 1000)
				if exp, ok := claims.Get("exp").(float64); ok && exp+tolerance <= now {
					return invalid("expired"), nil
				}
				if nbf, ok := claims.Get("nbf").(float64); ok && nbf-tolerance > now {
					return invalid("not-yet-valid"), nil
				}
				if audience := input.Get("audience"); !isUndefined(audience) {
					audiences, ok := claims.Get("aud").([]any)
					if !ok {
						audiences = []any{claims.Get("aud")}
					}
					found := false
					for _, item := range audiences {
						if core.StrictEquals(item, audience) {
							found = true
							break
						}
					}
					if !found {
						return invalid("audience"), nil
					}
				}
				if issuer := input.Get("issuer"); !isUndefined(issuer) && !core.StrictEquals(claims.Get("iss"), issuer) {
					return invalid("issuer"), nil
				}
				return core.NewObject("valid", true, "algorithm", algorithm, "header", header, "claims", claims,
					"keyId", key.Get("id"), "keyVersion", version.Get("version")), nil
			}
			answer, err := outcome()
			if err != nil {
				return nil, err
			}
			call.Metadata.Assign(core.NewObject("keyVersion", version.Get("version"), "algorithm", algorithm, "jwt", true, "valid", answer.Get("valid")))
			if answer.Get("valid") != true {
				call.Metadata.Set("reason", answer.Get("reason"))
			}
			return answer, nil
		})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.KeysVerifyJwtOutput]{Value: result}, nil
}

// MaintainKeys (api/keys.ts maintainKeys) is the KMS scheduler job: rotates keys whose automatic rotation is due,
// destroys keys whose deletion waiting period has passed (material, aliases and grants; audited as
// `kms:key-destroy`), and removes lapsed grants and grants whose grantee is gone. Run it hourly.
func MaintainKeys(ctx context.Context, server *ServerContext, input *core.Object) (*core.Object, error) {
	rotated, destroyed := []any{}, []any{}
	grantsRemoved := 0.0
	filter := core.NewObject()
	if input != nil && truthy(input.Get("tenantId")) {
		tenantID, err := Text(input.Get("tenantId"), "tenantId")
		if err != nil {
			return nil, err
		}
		filter.Set("tenantId", tenantID)
	}
	keys, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]*core.Object, error) {
		return tx.Find(ctx, "kmsKeys", filter, nil)
	})
	if err != nil {
		return nil, err
	}
	system := func(tenantID any, action string, keyID any, metadata *core.Object) *core.Object {
		return core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"actorId", "deployment-operator",
			"action", action,
			"resourceId", "kms/"+jsString(keyID),
			"timestamp", float64(server.Now()),
			"outcome", "allow",
			"metadata", metadata,
		)
	}
	deletionDate := func(key *core.Object) float64 {
		if value := key.Get("deletionDate"); !nullish(value) {
			return jsNumber(value)
		}
		return math.Inf(1)
	}
	for _, candidate := range keys {
		now := float64(server.Now())
		if candidate.Get("state") == "pending-deletion" && deletionDate(candidate) <= now {
			err := server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
				key, err := tx.Get(ctx, "kmsKeys", jsString(candidate.Get("id")))
				if err != nil {
					return err
				}
				if key == nil || key.Get("state") != "pending-deletion" || deletionDate(key) > now {
					return nil
				}
				for _, collection := range []string{"kmsKeyVersions", "kmsAliases", "kmsGrants"} {
					records, err := tx.Find(ctx, collection, core.NewObject("tenantId", key.Get("tenantId"), "keyId", key.Get("id")), nil)
					if err != nil {
						return err
					}
					for _, record := range records {
						if err := tx.Delete(ctx, collection, jsString(record.Get("id"))); err != nil {
							return err
						}
					}
				}
				if err := tx.Delete(ctx, "kmsKeys", jsString(key.Get("id"))); err != nil {
					return err
				}
				if err := server.Events.RecordAudit(ctx, tx, system(key.Get("tenantId"), "kms:key-destroy", key.Get("id"),
					core.NewObject("keySpec", key.Get("keySpec"), "versions", key.Get("currentVersion")))); err != nil {
					return err
				}
				destroyed = append(destroyed, core.NewObject("tenantId", key.Get("tenantId"), "keyId", key.Get("id")))
				return nil
			})
			if err != nil {
				return nil, err
			}
			continue
		}
		next, scheduled := candidate.Get("nextRotationAt").(float64)
		if candidate.Get("state") == "enabled" && !isUndefined(candidate.Get("nextRotationAt")) && scheduled && next <= now {
			err := server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
				key, err := tx.Get(ctx, "kmsKeys", jsString(candidate.Get("id")))
				if err != nil {
					return err
				}
				if key == nil || key.Get("state") != "enabled" || isUndefined(key.Get("nextRotationAt")) || jsNumber(key.Get("nextRotationAt")) > now ||
					isUndefined(key.Get("rotationPeriodDays")) || jsNumber(key.Get("currentVersion")) >= MaxVersions {
					return nil
				}
				version := jsNumber(key.Get("currentVersion")) + 1
				if _, err := AddKeyVersion(ctx, server, tx, key, version, "automatic"); err != nil {
					return err
				}
				updated := key.Spread()
				updated.Set("currentVersion", version)
				updated.Set("lastRotatedAt", now)
				updated.Set("nextRotationAt", now+jsNumber(key.Get("rotationPeriodDays"))*kmsDay)
				updated.Set("updatedAt", now)
				if _, err := tx.Put(ctx, "kmsKeys", updated); err != nil {
					return err
				}
				if err := server.Events.RecordAudit(ctx, tx, system(key.Get("tenantId"), "kms:key-rotate", key.Get("id"),
					core.NewObject("keyVersion", version, "automatic", true))); err != nil {
					return err
				}
				rotated = append(rotated, core.NewObject("tenantId", key.Get("tenantId"), "keyId", key.Get("id"), "keyVersion", version))
				return nil
			})
			if err != nil {
				return nil, err
			}
		}
	}
	// Lapsed grants, and grants whose grantee or creator is gone, one tenant per transaction.
	tenants, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]string, error) {
		grants, err := tx.Find(ctx, "kmsGrants", filter, nil)
		if err != nil {
			return nil, err
		}
		set := newOrderedSet()
		for _, grant := range grants {
			set.Add(jsString(grant.Get("tenantId")))
		}
		return set.Values(), nil
	})
	if err != nil {
		return nil, err
	}
	for _, tenantID := range tenants {
		err := server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			now := float64(server.Now())
			deleted := func(identityID any) (bool, error) {
				identity, err := tx.Get(ctx, "identities", jsString(identityID))
				if err != nil {
					return false, err
				}
				return identity == nil || identity.Get("tenantId") != tenantID || identity.Get("status") == "deleted", nil
			}
			grants, err := tx.Find(ctx, "kmsGrants", core.NewObject("tenantId", tenantID), nil)
			if err != nil {
				return err
			}
			for _, grant := range grants {
				gone := false
				if expiresAt, ok := grant.Get("expiresAt").(float64); ok && expiresAt <= now {
					gone = true
				}
				if !gone {
					if gone, err = deleted(grant.Get("granteeId")); err != nil {
						return err
					}
				}
				if !gone {
					if gone, err = deleted(grant.Get("createdBy")); err != nil {
						return err
					}
				}
				if !gone {
					continue
				}
				if err := tx.Delete(ctx, "kmsGrants", jsString(grant.Get("id"))); err != nil {
					return err
				}
				grantsRemoved++
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return core.NewObject("rotated", rotated, "destroyed", destroyed, "grantsRemoved", grantsRemoved), nil
}

// KmsRuntime is api/keys.ts createKmsRuntime(): `iam.kms`, the scheduler job and nothing else; applications use
// `api.keys`.
type KmsRuntime struct {
	server *ServerContext
}

// Maintain (api/keys.ts createKmsRuntime().maintain): Automatic rotation, destruction after the deletion waiting
// period, and grant cleanup (run hourly).
func (s *KmsRuntime) Maintain(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	return MaintainKeys(ctx, s.server, input)
}

// CreateKmsRuntime builds the KmsRuntime (api/keys.ts createKmsRuntime).
func CreateKmsRuntime(server *ServerContext) *KmsRuntime {
	return &KmsRuntime{server: server}
}
