package server

// Port of packages/server/src/api/protection.ts: data protection by tokenization. A profile says how one kind of
// sensitive value is tokenized, masked and protected; policies name it as `iam/protection/{name}` with
// `resource.profile`, `resource.dataType`, `resource.format` and `resource.deterministic`; detokenizing adds
// `resource.purpose` and masking `resource.style`. Values are encrypted under the profile's KMS key (one wrapped data
// key per call) and never written to the audit trail; tokens are not either, only counts. Sessions that view as
// someone else are refused.

import (
	"context"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

const protectionDay = 86_400_000

// protectionSweepBatch is the number of tokens a retention sweep reads per transaction.
const protectionSweepBatch = 500

// protectionTarget is a guarded protection resource, with the profile it names once located.
type protectionTarget struct {
	GuardTarget
	profile *core.Object
}

// purposePattern is /^[a-z][a-z0-9-]{0,63}$/.
var purposePattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,63}$`)

// protectionList requires 1 to MAX_BATCH entries.
func protectionList(value any, name string) ([]any, error) {
	list, ok := value.([]any)
	if !ok || len(list) == 0 || len(list) > MaxBatch {
		return nil, invalidInput(name + " must list 1 to " + core.NumberString(MaxBatch) + " entries")
	}
	return list, nil
}

func purposeOf(value any) (string, error) {
	purpose, err := Text(value, "purpose", 64)
	if err != nil {
		return "", err
	}
	if !purposePattern.MatchString(purpose) {
		return "", invalidInput("purpose is a short lowercase name, such as payment-processing or fraud-review")
	}
	return purpose, nil
}

// hasC0Control is /[\u0000-\u001f]/.
func hasC0Control(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r <= 0x1f }) >= 0
}

func tokenList(value any) ([]string, error) {
	list, err := protectionList(value, "tokens")
	if err != nil {
		return nil, err
	}
	tokens := make([]string, len(list))
	for index, item := range list {
		token, ok := item.(string)
		if !ok || token == "" || utf16Len(token) > 4096 || hasC0Control(token) {
			return nil, invalidInput("Every token must be a string")
		}
		tokens[index] = token
	}
	return tokens, nil
}

// guardTenantID is a tenant ID as the guard validates it (a value that is not a string fails its text() check).
func guardTenantID(value any) string {
	text, _ := value.(string)
	return text
}

// defaultMaskOf is `defaultMask[dataType]`.
func defaultMaskOf(dataType string) string {
	switch dataType {
	case "card":
		return DefaultMask.Card
	case "ssn":
		return DefaultMask.Ssn
	case "email":
		return DefaultMask.Email
	case "phone":
		return DefaultMask.Phone
	}
	return DefaultMask.Generic
}

// wipe zeroes a key buffer.
func wipe(key []byte) {
	for index := range key {
		key[index] = 0
	}
}

// dataKeyOf reads the data key and its wrapped form from a kmsDataKeyFor result.
func dataKeyOf(result *core.Object) ([]byte, string) {
	if result == nil {
		return nil, ""
	}
	key, _ := result.Get("dataKey").([]byte)
	wrapped, _ := result.Get("wrapped").(string)
	return key, wrapped
}

// ProtectionAPI is the `protection` API group (packages/server/src/api/protection.ts createProtectionApi): every
// method runs through the guard envelope; the router maps POST {basePath}/protection/{method} onto it.
type ProtectionAPI struct {
	server *ServerContext
	guard  *Guard[protectionTarget]
}

// CreateProtectionAPI builds the `protection` API group.
func CreateProtectionAPI(server *ServerContext) *ProtectionAPI {
	guard := CreateGuard(server, "protection", GuardOptions[protectionTarget]{
		// Refusals are audited with the profile and purpose too.
		Describe: func(target protectionTarget) *core.Object {
			described := core.NewObject()
			if target.profile != nil {
				described.Set("profile", target.profile.Get("name"))
			}
			if target.Attributes != nil {
				if purpose, ok := target.Attributes.Get("purpose").(string); ok {
					described.Set("purpose", purpose)
				}
			}
			return described
		},
		RecordedFailures: map[string]string{"KEY_STATE_INVALID": "key-unavailable"},
		// Plugins see which profile served a call, never values or tokens (format-preserving ones keep digits).
		HookResult: func(value any) any {
			object, ok := value.(*core.Object)
			if !ok || object == nil {
				return value
			}
			rest := object.Spread()
			rest.Delete("values")
			rest.Delete("tokens")
			return rest
		},
	})
	return &ProtectionAPI{server: server, guard: guard}
}

func profileAttributes(profile *core.Object, extra *core.Object) *core.Object {
	attributes := core.NewObject(
		"profile", profile.Get("name"),
		"dataType", profile.Get("dataType"),
		"format", profile.Get("format"),
		"deterministic", profile.Get("deterministic"),
	)
	if extra != nil {
		attributes.Assign(extra)
	}
	return attributes
}

func (api *ProtectionAPI) findProfile(ctx context.Context, tx core.IamStore, tenantID any, name any) (*core.Object, error) {
	tenant, err := Text(tenantID, "tenantId")
	if err != nil {
		return nil, err
	}
	profileName, err := ProfileName(name)
	if err != nil {
		return nil, err
	}
	profiles, err := tx.Find(ctx, "protectionProfiles", core.NewObject("tenantId", tenant, "uniqueKey", "name:"+profileName), nil)
	if err != nil {
		return nil, err
	}
	if len(profiles) == 0 {
		return nil, core.NewIamError("NOT_FOUND", "Protection profile not found", 404)
	}
	return profiles[0], nil
}

// profileTarget locates the named profile of a call; extra adds attributes computed from the profile.
func (api *ProtectionAPI) profileTarget(tenantID any, name any, extra func(profile *core.Object) (*core.Object, error)) func(ctx context.Context, tx core.IamStore, principal *Principal) (protectionTarget, error) {
	return func(ctx context.Context, tx core.IamStore, principal *Principal) (protectionTarget, error) {
		profile, err := api.findProfile(ctx, tx, tenantID, name)
		if err != nil {
			return protectionTarget{}, err
		}
		var added *core.Object
		if extra != nil {
			if added, err = extra(profile); err != nil {
				return protectionTarget{}, err
			}
		}
		return protectionTarget{
			GuardTarget: GuardTarget{ResourceID: "protection/" + jsString(profile.Get("name")), Attributes: profileAttributes(profile, added)},
			profile:     profile,
		}, nil
	}
}

// protectionKeyTarget is a KMS key as a guarded target.
func protectionKeyTarget(ctx context.Context, tx core.IamStore, key *core.Object) (GuardTarget, error) {
	aliases, err := AliasNames(ctx, tx, key)
	if err != nil {
		return GuardTarget{}, err
	}
	attributes, err := KeyAttributes(key, aliases, nil)
	if err != nil {
		return GuardTarget{}, err
	}
	return GuardTarget{ResourceID: "kms/" + jsString(key.Get("id")), Attributes: attributes}, nil
}

// requireKeyUse: a profile bound to a customer key (one it did not create) leaves the key's owner in charge, as the
// vault does: every call needs the caller's own KMS permission on the key, so revoking it stops the profile's use too.
func (api *ProtectionAPI) requireKeyUse(ctx context.Context, call GuardCall, profile *core.Object, action string) error {
	key, err := FindKey(ctx, call.Tx, jsString(profile.Get("tenantId")), profile.Get("keyId"))
	if err != nil {
		return err
	}
	if key.Get("managedBy") == "protection" && jsStrictEqual(key.Get("managedId"), profile.Get("id")) {
		return nil
	}
	target, err := protectionKeyTarget(ctx, call.Tx, key)
	if err != nil {
		return err
	}
	allowed, err := call.Allowed(ctx, action, target)
	if err != nil {
		return err
	}
	if !allowed {
		return NewOperationDenied("This needs " + action + " on the profile's customer-managed key")
	}
	return nil
}

// protectionUse is the KMS service use of a protection call (`{ via: 'protection', principal }`).
func protectionUse(principal *Principal) *core.Object {
	return core.NewObject("via", "protection", "principal", principal)
}

// lookupKey is the profile's fingerprint key, unwrapped by its KMS key (so it stops with the key). Wipe it after use.
func (api *ProtectionAPI) lookupKey(ctx context.Context, tx core.IamStore, profile *core.Object, principal *Principal) ([]byte, error) {
	lookup, err := LookupContext(jsString(profile.Get("id")))
	if err != nil {
		return nil, err
	}
	wrapped, _ := profile.Get("lookupKeyWrapped").(string)
	return KmsOpenDataKeyFor(ctx, api.server, tx, jsString(profile.Get("tenantId")), wrapped, lookup, protectionUse(principal))
}

// protectedRecords are the stored records of tokens in a profile, keyed by token, in first-asked order.
type protectedRecords struct {
	order   []string
	byToken map[string]*core.Object
}

func (r *protectedRecords) values() []*core.Object {
	records := make([]*core.Object, len(r.order))
	for index, token := range r.order {
		records[index] = r.byToken[token]
	}
	return records
}

// recordsOf is the stored records of `tokens` in a profile (absent tokens are missing).
func (api *ProtectionAPI) recordsOf(ctx context.Context, tx core.IamStore, profile *core.Object, tokens []string) (*protectedRecords, error) {
	records := &protectedRecords{byToken: map[string]*core.Object{}}
	profileID := jsString(profile.Get("id"))
	for _, token := range unique(tokens) {
		key, err := TokenKey(profileID, token)
		if err != nil {
			return nil, err
		}
		found, err := tx.Find(ctx, "protectionTokens", core.NewObject("tenantId", profile.Get("tenantId"), "uniqueKey", key), nil)
		if err != nil {
			return nil, err
		}
		if len(found) == 0 {
			continue
		}
		record := found[0]
		if jsStrictEqual(record.Get("profileId"), profile.Get("id")) && record.Get("token") == token {
			if _, seen := records.byToken[token]; !seen {
				records.order = append(records.order, token)
			}
			records.byToken[token] = record
		}
	}
	return records, nil
}

// openAll opens the values of stored tokens, unwrapping each distinct batch data key once.
func (api *ProtectionAPI) openAll(ctx context.Context, tx core.IamStore, profile *core.Object, records []*core.Object, principal *Principal) (map[string]string, error) {
	keys := map[string][]byte{}
	defer func() {
		for _, key := range keys {
			wipe(key)
		}
	}()
	values := map[string]string{}
	for _, record := range records {
		wrapped, _ := record.Get("wrapped").(string)
		dataKey, ok := keys[wrapped]
		if !ok {
			opened, err := KmsOpenDataKeyFor(ctx, api.server, tx, jsString(profile.Get("tenantId")), wrapped,
				core.NewObject("protection", profile.Get("id")), protectionUse(principal))
			if err != nil {
				return nil, err
			}
			dataKey = opened
			keys[wrapped] = dataKey
		}
		value, err := OpenValue(dataKey, record)
		if err != nil {
			return nil, err
		}
		values[jsString(record.Get("token"))] = value
	}
	return values, nil
}

// holdsTokens says whether any token remains in a profile (read by query, not by the counter).
func holdsTokens(ctx context.Context, tx core.IamStore, profile *core.Object) (bool, error) {
	limit := 1
	found, err := tx.Find(ctx, "protectionTokens", core.NewObject("tenantId", profile.Get("tenantId"), "profileId", profile.Get("id")), &core.FindOptions{Limit: &limit})
	if err != nil {
		return false, err
	}
	return len(found) > 0, nil
}

// tokenCount is `profile.tokens ?? 0`.
func tokenCount(profile *core.Object) float64 {
	return jsNumber(coalesce(profile.Get("tokens"), 0.0))
}

// CreateProfile is POST {basePath}/protection/createProfile. Creates a tokenization profile for one kind of value
// (`card`, `ssn`, `email`, `phone` or `generic`): its token format, whether tokens are deterministic, its display mask,
// its retention, and the tenant AES key that protects its values (an existing one the caller may use, or a new one
// managed by the profile). Requires iam:protection:manage on `iam/protection/{name}`.
func (api *ProtectionAPI) CreateProfile(ctx context.Context, credential core.CredentialInput, input In[apitypes.ProtectionCreateProfileInput]) (Out[apitypes.ProtectionCreateProfileOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.ProtectionCreateProfileOutput], error) {
		return Out[apitypes.ProtectionCreateProfileOutput]{}, err
	}
	name, err := ProfileName(input.Get("name"))
	if err != nil {
		return fail(err)
	}
	dataType, isText := input.Get("dataType").(string)
	if !isText || !containsString(DataTypes, dataType) {
		return fail(invalidInput("dataType must be one of " + strings.Join(DataTypes, ", ")))
	}
	format := input.Get("format")
	if nullish(format) {
		if dataType == "generic" {
			format = "random"
		} else {
			format = "format-preserving"
		}
	}
	if format != "random" && format != "format-preserving" {
		return fail(invalidInput("format must be random or format-preserving"))
	}
	formatName := format.(string)
	given := input.Get("deterministic")
	if !isUndefined(given) {
		if _, ok := given.(bool); !ok {
			return fail(invalidInput("deterministic must be true or false"))
		}
	}
	needed, err := NeedsDeterministic(dataType, formatName)
	if err != nil {
		return fail(err)
	}
	deterministic := needed
	if flag, ok := given.(bool); ok {
		deterministic = flag
	}
	if !deterministic && needed {
		return fail(invalidInput("Format-preserving " + dataType + " tokens keep the last four digits and have few random ones left, so these profiles must be deterministic (or use random tokens)"))
	}
	var mask string
	if isUndefined(input.Get("mask")) {
		mask = defaultMaskOf(dataType)
	} else if mask, err = MaskStyle(dataType, input.Get("mask"), "mask"); err != nil {
		return fail(err)
	}
	var description string
	if !isUndefined(input.Get("description")) {
		if description, err = Text(input.Get("description"), "description", 512); err != nil {
			return fail(err)
		}
	}
	var retentionDays *float64
	if !isUndefined(input.Get("retentionDays")) {
		days, err := Integer(input.Get("retentionDays"), "retentionDays", 1, 3650)
		if err != nil {
			return fail(err)
		}
		retentionDays = &days
	}
	keyRef := input.Get("keyId")
	result, err := api.guard.Run(ctx, credential, guardTenantID(input.Get("tenantId")), GuardAction[protectionTarget]{Name: ProtectionActions.Manage},
		func(ctx context.Context, tx core.IamStore, principal *Principal) (protectionTarget, error) {
			return protectionTarget{GuardTarget: GuardTarget{
				ResourceID: "protection/" + name,
				Attributes: core.NewObject("profile", name, "dataType", dataType, "format", formatName, "deterministic", deterministic),
			}}, nil
		},
		func(ctx context.Context, call GuardCall, target protectionTarget) (any, error) {
			tx, tenant, principal, metadata := call.Tx, call.Tenant, call.Principal, call.Metadata
			tenantKey := jsString(tenant.Get("id"))
			existing, err := tx.Find(ctx, "protectionProfiles", core.NewObject("tenantId", tenant.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			if len(existing) >= MaxProfilesPerTenant {
				return nil, core.NewIamError("LIMIT_EXCEEDED", "A tenant keeps at most "+core.NumberString(MaxProfilesPerTenant)+" protection profiles", 409)
			}
			for _, profile := range existing {
				if profile.Get("name") == name {
					return nil, core.NewIamError("CONFLICT", "A profile with that name exists", 409)
				}
			}
			profileID := ID()
			var key *core.Object
			if !isUndefined(keyRef) {
				if key, err = FindKey(ctx, tx, tenantKey, keyRef); err != nil {
					return nil, err
				}
				if err := AssertUsable(key, "encrypt"); err != nil {
					return nil, err
				}
				// Another profile's or module's key stays theirs.
				if err := AssertUnmanaged(key); err != nil {
					return nil, err
				}
				if key.Get("keySpec") != "aes-256-gcm" {
					return nil, invalidInput("Profiles need an aes-256-gcm key")
				}
				// Whoever binds a key to a profile must be able to use it for exactly this (and every caller will).
				keyGuard, err := protectionKeyTarget(ctx, tx, key)
				if err != nil {
					return nil, err
				}
				for _, action := range []string{jsString(KmsActions.Get("generate-data-key")), jsString(KmsActions.Get("decrypt"))} {
					allowed, err := call.Allowed(ctx, action, keyGuard)
					if err != nil {
						return nil, err
					}
					if !allowed {
						return nil, NewOperationDenied("You may not protect values with that key")
					}
				}
			} else if key, err = CreateServiceKey(ctx, server, tx, core.NewObject(
				"tenantId", tenantKey,
				"keySpec", "aes-256-gcm",
				"keyUsage", "encrypt",
				"description", "Data protection profile: "+name,
				"tags", core.NewObject("protection-profile", name),
				"createdBy", principal.Identity.Get("id"),
				"managedBy", "protection",
				"managedId", profileID,
			)); err != nil {
				return nil, err
			}
			bound, err := LookupContext(profileID)
			if err != nil {
				return nil, err
			}
			lookup, err := KmsDataKeyFor(ctx, server, tx, tenantKey, jsString(key.Get("id")), bound, protectionUse(principal))
			if err != nil {
				return nil, err
			}
			dataKey, wrapped := dataKeyOf(lookup)
			wipe(dataKey)
			now := float64(server.Now())
			profile := core.NewObject(
				"id", profileID,
				"tenantId", tenant.Get("id"),
				"uniqueKey", "name:"+name,
				"name", name,
				"dataType", dataType,
				"format", formatName,
				"deterministic", deterministic,
				"keyId", key.Get("id"),
				"mask", mask,
				"lookupKeyWrapped", wrapped,
				"tokens", 0.0,
				"createdAt", now,
				"createdBy", principal.Identity.Get("id"),
				"updatedAt", now,
			)
			if description != "" {
				profile.Set("description", description)
			}
			if retentionDays != nil {
				profile.Set("retentionDays", *retentionDays)
			}
			if _, err := tx.Insert(ctx, "protectionProfiles", profile); err != nil {
				return nil, err
			}
			metadata.Assign(core.NewObject(
				"profile", name,
				"dataType", dataType,
				"format", formatName,
				"deterministic", deterministic,
				"keyId", key.Get("id"),
			))
			return SummarizeProfile(profile)
		})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.ProtectionCreateProfileOutput]{Value: result}, nil
}

// DeleteProfile is POST {basePath}/protection/deleteProfile. Deletes a profile that holds no tokens (delete its
// tokens first). Requires iam:protection:manage and recent authentication. A key the profile created is scheduled for
// deletion (7 days); a customer key stays.
func (api *ProtectionAPI) DeleteProfile(ctx context.Context, credential core.CredentialInput, input In[apitypes.ProtectionDeleteProfileInput]) (Out[apitypes.ProtectionDeleteProfileOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := api.guard.Run(ctx, credential, guardTenantID(tenantID), GuardAction[protectionTarget]{Name: ProtectionActions.Manage},
		api.profileTarget(tenantID, input.Get("profile"), nil),
		func(ctx context.Context, call GuardCall, target protectionTarget) (any, error) {
			tx, principal, metadata := call.Tx, call.Principal, call.Metadata
			profile := target.profile
			if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
				return nil, err
			}
			holds, err := holdsTokens(ctx, tx, profile)
			if err != nil {
				return nil, err
			}
			if holds {
				return nil, core.NewIamError("RESOURCE_IN_USE", "The profile still holds tokens", 409)
			}
			if err := tx.Delete(ctx, "protectionProfiles", jsString(profile.Get("id"))); err != nil {
				return nil, err
			}
			deletionDate, err := RetireServiceKey(ctx, server, tx, jsString(profile.Get("tenantId")), jsString(profile.Get("keyId")), "protection", jsString(profile.Get("id")))
			if err != nil {
				return nil, err
			}
			if deletionDate != nil {
				metadata.Set("keyDeletionDate", *deletionDate)
			}
			return core.NewObject("success", true), nil
		})
	if err != nil {
		return Out[apitypes.ProtectionDeleteProfileOutput]{}, err
	}
	return Out[apitypes.ProtectionDeleteProfileOutput]{Value: result}, nil
}

// DeleteTokens is POST {basePath}/protection/deleteTokens. Deletes tokens and their values for good (right to
// erasure), named by `tokens` or by `values` (every token issued for each value, found by its keyed fingerprint, which
// needs the profile's key enabled). Up to 100 either way. Requires iam:protection:delete on the profile.
func (api *ProtectionAPI) DeleteTokens(ctx context.Context, credential core.CredentialInput, input In[apitypes.ProtectionDeleteTokensInput]) (Out[apitypes.ProtectionDeleteTokensOutput], error) {
	fail := func(err error) (Out[apitypes.ProtectionDeleteTokensOutput], error) {
		return Out[apitypes.ProtectionDeleteTokensOutput]{}, err
	}
	if isUndefined(input.Get("tokens")) == isUndefined(input.Get("values")) {
		return fail(invalidInput("Name either tokens or values"))
	}
	var tokens []string
	var raw []any
	var err error
	if !isUndefined(input.Get("tokens")) {
		if tokens, err = tokenList(input.Get("tokens")); err != nil {
			return fail(err)
		}
	}
	if !isUndefined(input.Get("values")) {
		if raw, err = protectionList(input.Get("values"), "values"); err != nil {
			return fail(err)
		}
	}
	tenantID := input.Get("tenantId")
	result, err := api.guard.Run(ctx, credential, guardTenantID(tenantID), GuardAction[protectionTarget]{Name: ProtectionActions.Delete},
		api.profileTarget(tenantID, input.Get("profile"), nil),
		func(ctx context.Context, call GuardCall, target protectionTarget) (any, error) {
			tx, principal, metadata := call.Tx, call.Principal, call.Metadata
			current := target.profile
			dataType := jsString(current.Get("dataType"))
			var doomed []*core.Object
			if tokens != nil {
				records, err := api.recordsOf(ctx, tx, current, tokens)
				if err != nil {
					return nil, err
				}
				doomed = append(doomed, records.values()...)
			} else {
				normalized := make([]string, 0, len(raw))
				for _, item := range raw {
					value, err := NormalizeValue(dataType, item)
					if err != nil {
						return nil, err
					}
					normalized = append(normalized, value)
				}
				values := unique(normalized)
				key, err := api.lookupKey(ctx, tx, current, principal)
				if err != nil {
					return nil, err
				}
				err = func() error {
					defer wipe(key)
					for _, value := range values {
						fingerprint, err := TokenizationFingerprint(key, value)
						if err != nil {
							return err
						}
						found, err := tx.Find(ctx, "protectionTokens", core.NewObject(
							"tenantId", current.Get("tenantId"), "profileId", current.Get("id"), "fingerprint", fingerprint,
						), nil)
						if err != nil {
							return err
						}
						doomed = append(doomed, found...)
					}
					return nil
				}()
				if err != nil {
					return nil, err
				}
			}
			for _, record := range doomed {
				if err := tx.Delete(ctx, "protectionTokens", jsString(record.Get("id"))); err != nil {
					return nil, err
				}
			}
			if len(doomed) > 0 {
				if _, err := tx.Put(ctx, "protectionProfiles", current.Spread(core.NewObject(
					"tokens", math.Max(0, tokenCount(current)-float64(len(doomed))),
				))); err != nil {
					return nil, err
				}
			}
			by := "value"
			if tokens != nil {
				by = "token"
			}
			metadata.Assign(core.NewObject("deleted", float64(len(doomed)), "by", by))
			return core.NewObject("deleted", float64(len(doomed))), nil
		})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.ProtectionDeleteTokensOutput]{Value: result}, nil
}

// Detokenize is POST {basePath}/protection/detokenize. Turns up to 100 tokens of one profile back into their values,
// in order (`null` for tokens the profile does not hold). `purpose` (a short lowercase name, such as
// `payment-processing`) is required: policies read it as `resource.purpose` and the audit records it, refusals
// included. Requires iam:protection:detokenize on the profile (and iam:kms:decrypt on a customer key).
func (api *ProtectionAPI) Detokenize(ctx context.Context, credential core.CredentialInput, input In[apitypes.ProtectionDetokenizeInput]) (Out[apitypes.ProtectionDetokenizeOutput], error) {
	fail := func(err error) (Out[apitypes.ProtectionDetokenizeOutput], error) {
		return Out[apitypes.ProtectionDetokenizeOutput]{}, err
	}
	tokens, err := tokenList(input.Get("tokens"))
	if err != nil {
		return fail(err)
	}
	purpose, err := purposeOf(input.Get("purpose"))
	if err != nil {
		return fail(err)
	}
	tenantID := input.Get("tenantId")
	result, err := api.guard.Run(ctx, credential, guardTenantID(tenantID), GuardAction[protectionTarget]{Name: ProtectionActions.Detokenize},
		api.profileTarget(tenantID, input.Get("profile"), func(profile *core.Object) (*core.Object, error) {
			return core.NewObject("purpose", purpose), nil
		}),
		func(ctx context.Context, call GuardCall, target protectionTarget) (any, error) {
			tx, principal, metadata := call.Tx, call.Principal, call.Metadata
			if err := api.requireKeyUse(ctx, call, target.profile, jsString(KmsActions.Get("decrypt"))); err != nil {
				return nil, err
			}
			records, err := api.recordsOf(ctx, tx, target.profile, tokens)
			if err != nil {
				return nil, err
			}
			opened, err := api.openAll(ctx, tx, target.profile, records.values(), principal)
			if err != nil {
				return nil, err
			}
			metadata.Assign(core.NewObject("purpose", purpose, "count", float64(len(tokens)), "found", float64(len(records.order))))
			values := make([]any, len(tokens))
			for index, token := range tokens {
				if value, ok := opened[token]; ok {
					values[index] = value
				} else {
					values[index] = nil
				}
			}
			return core.NewObject("values", values), nil
		})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.ProtectionDetokenizeOutput]{Value: result}, nil
}

// GetProfile is POST {basePath}/protection/getProfile. One profile, with the number of tokens it holds. Requires
// iam:protection:read.
func (api *ProtectionAPI) GetProfile(ctx context.Context, credential core.CredentialInput, input In[apitypes.ProtectionGetProfileInput]) (Out[apitypes.ProtectionGetProfileOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := api.guard.Run(ctx, credential, guardTenantID(tenantID), GuardAction[protectionTarget]{Name: ProtectionActions.Read},
		api.profileTarget(tenantID, input.Get("profile"), nil),
		func(ctx context.Context, call GuardCall, target protectionTarget) (any, error) {
			return SummarizeProfile(target.profile)
		})
	if err != nil {
		return Out[apitypes.ProtectionGetProfileOutput]{}, err
	}
	return Out[apitypes.ProtectionGetProfileOutput]{Value: result}, nil
}

// ListProfiles is POST {basePath}/protection/listProfiles. The tenant's profiles the caller may read
// (`iam:protection:read`, per profile).
func (api *ProtectionAPI) ListProfiles(ctx context.Context, credential core.CredentialInput, input In[apitypes.ProtectionListProfilesInput]) (Out[apitypes.ProtectionListProfilesOutput], error) {
	listed, err := GuardVisible(ctx, api.guard, credential, guardTenantID(input.Get("tenantId")), ProtectionActions.Read, "protection",
		func(ctx context.Context, tx core.IamStore, tenant *core.Object) ([]VisibleItem[any], error) {
			profiles, err := tx.Find(ctx, "protectionProfiles", core.NewObject("tenantId", tenant.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			sort.SliceStable(profiles, func(i, j int) bool {
				return jsLess(profiles[i].Get("name"), profiles[j].Get("name"))
			})
			items := make([]VisibleItem[any], 0, len(profiles))
			for _, profile := range profiles {
				summary, err := SummarizeProfile(profile)
				if err != nil {
					return nil, err
				}
				items = append(items, VisibleItem[any]{
					Item:   summary,
					Target: GuardTarget{ResourceID: "protection/" + jsString(profile.Get("name")), Attributes: profileAttributes(profile, nil)},
				})
			}
			return items, nil
		})
	if err != nil {
		return Out[apitypes.ProtectionListProfilesOutput]{}, err
	}
	return Out[apitypes.ProtectionListProfilesOutput]{Value: listed}, nil
}

// Mask is POST {basePath}/protection/mask. The masked form of up to 100 tokens' values, for display
// (`**** **** **** 4242`, `j***@example.com`), with the profile's mask or `style` (one its data type allows). Policies
// see the style used as `resource.style`. A mask never shows more than half of a value, except the first six and last
// four digits of a long card number. Requires iam:protection:mask (and iam:kms:decrypt on a customer key).
func (api *ProtectionAPI) Mask(ctx context.Context, credential core.CredentialInput, input In[apitypes.ProtectionMaskInput]) (Out[apitypes.ProtectionMaskOutput], error) {
	tokens, err := tokenList(input.Get("tokens"))
	if err != nil {
		return Out[apitypes.ProtectionMaskOutput]{}, err
	}
	var style string
	tenantID := input.Get("tenantId")
	result, err := api.guard.Run(ctx, credential, guardTenantID(tenantID), GuardAction[protectionTarget]{Name: ProtectionActions.Mask},
		api.profileTarget(tenantID, input.Get("profile"), func(profile *core.Object) (*core.Object, error) {
			if requested := input.Get("style"); isUndefined(requested) {
				style = jsString(profile.Get("mask"))
			} else {
				chosen, err := MaskStyle(jsString(profile.Get("dataType")), requested, "style")
				if err != nil {
					return nil, err
				}
				style = chosen
			}
			return core.NewObject("style", style), nil
		}),
		func(ctx context.Context, call GuardCall, target protectionTarget) (any, error) {
			tx, principal, metadata := call.Tx, call.Principal, call.Metadata
			profile := target.profile
			if err := api.requireKeyUse(ctx, call, profile, jsString(KmsActions.Get("decrypt"))); err != nil {
				return nil, err
			}
			records, err := api.recordsOf(ctx, tx, profile, tokens)
			if err != nil {
				return nil, err
			}
			opened, err := api.openAll(ctx, tx, profile, records.values(), principal)
			if err != nil {
				return nil, err
			}
			metadata.Assign(core.NewObject("style", style, "count", float64(len(tokens)), "found", float64(len(records.order))))
			values := make([]any, len(tokens))
			for index, token := range tokens {
				value, ok := opened[token]
				if !ok {
					values[index] = nil
					continue
				}
				masked, err := MaskValue(jsString(profile.Get("dataType")), style, value)
				if err != nil {
					return nil, err
				}
				values[index] = masked
			}
			return core.NewObject("values", values), nil
		})
	if err != nil {
		return Out[apitypes.ProtectionMaskOutput]{}, err
	}
	return Out[apitypes.ProtectionMaskOutput]{Value: result}, nil
}

// Tokenize is POST {basePath}/protection/tokenize. Replaces up to 100 values by tokens, in order. Values are
// validated and normalized for the profile's data type (a card number must pass the Luhn check). A deterministic
// profile returns the token it already issued for a value; otherwise every call issues new tokens. On a deterministic
// profile this permission can test guesses against known tokens, so grant it as narrowly as detokenize
// (`resource.deterministic`). Requires iam:protection:tokenize on the profile (and iam:kms:generate-data-key on a
// customer key); audited with counts only.
func (api *ProtectionAPI) Tokenize(ctx context.Context, credential core.CredentialInput, input In[apitypes.ProtectionTokenizeInput]) (Out[apitypes.ProtectionTokenizeOutput], error) {
	server := api.server
	raw, err := protectionList(input.Get("values"), "values")
	if err != nil {
		return Out[apitypes.ProtectionTokenizeOutput]{}, err
	}
	tenantID := input.Get("tenantId")
	result, err := api.guard.Run(ctx, credential, guardTenantID(tenantID), GuardAction[protectionTarget]{Name: ProtectionActions.Tokenize},
		api.profileTarget(tenantID, input.Get("profile"), nil),
		func(ctx context.Context, call GuardCall, target protectionTarget) (any, error) {
			tx, principal, metadata := call.Tx, call.Principal, call.Metadata
			current := target.profile
			dataType, format := jsString(current.Get("dataType")), jsString(current.Get("format"))
			tenantKey, profileID := jsString(current.Get("tenantId")), jsString(current.Get("id"))
			values := make([]string, len(raw))
			for index, item := range raw {
				value, err := NormalizeValue(dataType, item)
				if err != nil {
					return nil, err
				}
				values[index] = value
			}
			if current.Get("format") == "format-preserving" {
				for _, value := range values {
					spacious, err := FormatPreservingSpace(dataType, value)
					if err != nil {
						return nil, err
					}
					if !spacious {
						return nil, invalidInput("Format-preserving generic values need at least 12 letters or digits; use a random profile")
					}
				}
			}
			if err := api.requireKeyUse(ctx, call, current, jsString(KmsActions.Get("generate-data-key"))); err != nil {
				return nil, err
			}
			key, err := api.lookupKey(ctx, tx, current, principal)
			if err != nil {
				return nil, err
			}
			tokens := []any{}
			issued := map[string]string{}
			issuedTokens := map[string]bool{}
			var batchKey []byte
			var batchWrapped string
			batched := false
			created := 0
			err = func() error {
				defer func() {
					wipe(key)
					wipe(batchKey)
				}()
				for _, value := range values {
					fingerprint, err := TokenizationFingerprint(key, value)
					if err != nil {
						return err
					}
					if truthy(current.Get("deterministic")) {
						known, ok := issued[fingerprint]
						if !ok {
							found, err := tx.Find(ctx, "protectionTokens", core.NewObject(
								"tenantId", current.Get("tenantId"), "profileId", current.Get("id"), "fingerprint", fingerprint,
							), nil)
							if err != nil {
								return err
							}
							if len(found) > 0 {
								known, _ = found[0].Get("token").(string)
							}
						}
						if known != "" {
							tokens = append(tokens, known)
							issued[fingerprint] = known
							issuedTokens[known] = true
							continue
						}
					}
					if !batched {
						batch, err := KmsDataKeyFor(ctx, server, tx, tenantKey, jsString(current.Get("keyId")),
							core.NewObject("protection", current.Get("id")), protectionUse(principal))
						if err != nil {
							return err
						}
						batchKey, batchWrapped = dataKeyOf(batch)
						batched = true
					}
					token := ""
					for attempt := 0; attempt < 10 && token == ""; attempt++ {
						candidate, err := NewToken(dataType, format, value)
						if err != nil {
							return err
						}
						candidateKey, err := TokenKey(profileID, candidate)
						if err != nil {
							return err
						}
						taken, err := tx.Find(ctx, "protectionTokens", core.NewObject("tenantId", current.Get("tenantId"), "uniqueKey", candidateKey), nil)
						if err != nil {
							return err
						}
						if len(taken) == 0 && !issuedTokens[candidate] {
							token = candidate
						}
					}
					if token == "" {
						return core.NewIamError("CONFLICT", "No free token could be found for a value", 409)
					}
					uniqueKey, err := TokenKey(profileID, token)
					if err != nil {
						return err
					}
					sealed, err := SealValue(batchKey, tenantKey, profileID, token, value)
					if err != nil {
						return err
					}
					if _, err := tx.Insert(ctx, "protectionTokens", core.NewObject(
						"id", ID(),
						"tenantId", current.Get("tenantId"),
						"uniqueKey", uniqueKey,
						"profileId", current.Get("id"),
						"token", token,
						"fingerprint", fingerprint,
						"wrapped", batchWrapped,
						"sealed", sealed,
						"createdAt", float64(server.Now()),
						"createdBy", principal.Identity.Get("id"),
					)); err != nil {
						return err
					}
					issued[fingerprint] = token
					issuedTokens[token] = true
					tokens = append(tokens, token)
					created++
				}
				return nil
			}()
			if err != nil {
				return nil, err
			}
			if created > 0 {
				if _, err := tx.Put(ctx, "protectionProfiles", current.Spread(core.NewObject(
					"tokens", tokenCount(current)+float64(created),
				))); err != nil {
					return nil, err
				}
			}
			// Whether a value was known already stays in the audit trail: callers would learn who else is stored.
			metadata.Assign(core.NewObject("count", float64(len(values)), "created", float64(created)))
			return core.NewObject("tokens", tokens), nil
		})
	if err != nil {
		return Out[apitypes.ProtectionTokenizeOutput]{}, err
	}
	return Out[apitypes.ProtectionTokenizeOutput]{Value: result}, nil
}

// UpdateProfile is POST {basePath}/protection/updateProfile. Changes a profile's description, mask or retention
// (`retentionDays: null` keeps tokens until deleted). The data type, format and key never change: tokens already
// issued depend on them. Requires iam:protection:manage; setting or shortening retention deletes tokens, so it also
// needs iam:protection:delete and recent authentication.
func (api *ProtectionAPI) UpdateProfile(ctx context.Context, credential core.CredentialInput, input In[apitypes.ProtectionUpdateProfileInput]) (Out[apitypes.ProtectionUpdateProfileOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := api.guard.Run(ctx, credential, guardTenantID(tenantID), GuardAction[protectionTarget]{Name: ProtectionActions.Manage},
		api.profileTarget(tenantID, input.Get("profile"), nil),
		func(ctx context.Context, call GuardCall, target protectionTarget) (any, error) {
			tx, principal, metadata := call.Tx, call.Principal, call.Metadata
			profile := target.profile
			next := profile.Spread(core.NewObject("updatedAt", float64(server.Now())))
			if value := input.Get("description"); value == nil {
				next.Delete("description")
			} else if !isUndefined(value) {
				text, err := Text(value, "description", 512)
				if err != nil {
					return nil, err
				}
				next.Set("description", text)
			}
			if value := input.Get("mask"); !isUndefined(value) {
				mask, err := MaskStyle(jsString(profile.Get("dataType")), value, "mask")
				if err != nil {
					return nil, err
				}
				next.Set("mask", mask)
			}
			if value := input.Get("retentionDays"); value == nil {
				next.Delete("retentionDays")
			} else if !isUndefined(value) {
				days, err := Integer(value, "retentionDays", 1, 3650)
				if err != nil {
					return nil, err
				}
				current := profile.Get("retentionDays")
				if isUndefined(current) || jsLess(days, current) {
					allowed, err := call.Allowed(ctx, ProtectionActions.Delete, target.GuardTarget)
					if err != nil {
						return nil, err
					}
					if !allowed {
						return nil, NewOperationDenied("Setting or shortening retention deletes tokens: it needs iam:protection:delete")
					}
					if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
						return nil, err
					}
				}
				next.Set("retentionDays", days)
			}
			if _, err := tx.Put(ctx, "protectionProfiles", next); err != nil {
				return nil, err
			}
			metadata.Set("mask", next.Get("mask"))
			if retention := next.Get("retentionDays"); !isUndefined(retention) {
				metadata.Set("retentionDays", retention)
			}
			return SummarizeProfile(next)
		})
	if err != nil {
		return Out[apitypes.ProtectionUpdateProfileOutput]{}, err
	}
	return Out[apitypes.ProtectionUpdateProfileOutput]{Value: result}, nil
}

// sweepPage is one transaction of a retention sweep.
type sweepPage struct {
	count int
	last  *string
	full  bool
}

// SweepTokens (api/protection.ts sweepTokens) deletes tokens past their profile's retention, a batch per transaction
// (so the write lock is never held for a whole profile), and audits each profile swept as
// `protection:retention-sweep`.
func SweepTokens(ctx context.Context, server *ServerContext, input *core.Object) (*core.Object, error) {
	if input == nil {
		input = core.NewObject()
	}
	profiles, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]*core.Object, error) {
		filter := core.NewObject()
		if tenantID := input.Get("tenantId"); truthy(tenantID) {
			text, err := Text(tenantID, "tenantId")
			if err != nil {
				return nil, err
			}
			filter.Set("tenantId", text)
		}
		return tx.Find(ctx, "protectionProfiles", filter, nil)
	})
	if err != nil {
		return nil, err
	}
	deleted := 0
	swept := 0
	for _, listed := range profiles {
		if isUndefined(listed.Get("retentionDays")) {
			continue
		}
		swept++
		removed := 0
		var after *string
		for {
			page, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*sweepPage, error) {
				profile, err := tx.Get(ctx, "protectionProfiles", jsString(listed.Get("id")))
				if err != nil {
					return nil, err
				}
				if profile == nil || isUndefined(profile.Get("retentionDays")) {
					return nil, nil
				}
				cutoff := float64(server.Now()) - jsNumber(profile.Get("retentionDays"))*protectionDay
				limit := protectionSweepBatch
				options := &core.FindOptions{Limit: &limit}
				if after != nil {
					options.After = after
				}
				records, err := tx.Find(ctx, "protectionTokens", core.NewObject("tenantId", profile.Get("tenantId"), "profileId", profile.Get("id")), options)
				if err != nil {
					return nil, err
				}
				count := 0
				for _, record := range records {
					if jsNumber(record.Get("createdAt")) <= cutoff {
						if err := tx.Delete(ctx, "protectionTokens", jsString(record.Get("id"))); err != nil {
							return nil, err
						}
						count++
					}
				}
				if count > 0 {
					if _, err := tx.Put(ctx, "protectionProfiles", profile.Spread(core.NewObject(
						"tokens", math.Max(0, tokenCount(profile)-float64(count)),
					))); err != nil {
						return nil, err
					}
				}
				result := &sweepPage{count: count, full: len(records) == protectionSweepBatch}
				if len(records) > 0 {
					if last, ok := records[len(records)-1].Get("id").(string); ok {
						result.last = &last
					}
				}
				return result, nil
			})
			if err != nil {
				return nil, err
			}
			if page == nil {
				break
			}
			removed += page.count
			if !page.full || page.last == nil {
				break
			}
			after = page.last
		}
		if removed > 0 {
			err := server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
				return server.Events.RecordAudit(ctx, tx, core.NewObject(
					"id", ID(),
					"tenantId", listed.Get("tenantId"),
					"actorId", "deployment-operator",
					"action", "protection:retention-sweep",
					"resourceId", "protection/"+jsString(listed.Get("name")),
					"timestamp", float64(server.Now()),
					"outcome", "allow",
					"metadata", core.NewObject("deleted", float64(removed), "retentionDays", coalesce(listed.Get("retentionDays"), nil)),
				))
			})
			if err != nil {
				return nil, err
			}
		}
		deleted += removed
	}
	return core.NewObject("deleted", float64(deleted), "profiles", float64(swept)), nil
}

// ProtectionRuntime is api/protection.ts createProtectionRuntime(): `iam.protection`, the retention job.
// Applications use `api.protection`.
type ProtectionRuntime struct {
	server *ServerContext
}

// Sweep (api/protection.ts createProtectionRuntime().sweep): Deletes tokens older than their profile's
// `retentionDays` (run daily).
func (s *ProtectionRuntime) Sweep(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	return SweepTokens(ctx, s.server, input)
}

// CreateProtectionRuntime builds the ProtectionRuntime (api/protection.ts createProtectionRuntime).
func CreateProtectionRuntime(server *ServerContext) *ProtectionRuntime {
	return &ProtectionRuntime{server: server}
}
