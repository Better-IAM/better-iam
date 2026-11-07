package server

// Port of packages/server/src/secrets.ts: re-sealing values sealed with a previous deployment secret. The sealing
// format is go/auth's EncryptSecret/OpenSecret (byte-compatible with the TypeScript one, see spec/vectors/secrets).

import (
	"context"
	"math"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// SecretRotationOptions configure RotateSecrets.
type SecretRotationOptions struct {
	// DryRun reports what would change without writing anything.
	DryRun bool
	// BatchSize is the number of records read per transaction (default 200, 1-2000).
	BatchSize *float64
	// Limit is the most records examined per collection (a sample, for selfCheck); nil: all of them.
	Limit *float64
}

// SecretRotationResult is what RotateSecrets reports. Resealed and Unreadable map collections to counts, in the
// order collections were first counted.
type SecretRotationResult struct {
	// Resealed counts values re-sealed with the current secret (or, in a dry run, that would be), per collection.
	Resealed *core.Object `json:"resealed"`
	// Unreadable counts values no configured secret opens, per collection.
	Unreadable *core.Object `json:"unreadable"`
	// Current counts values already sealed with the current secret.
	Current int `json:"current"`
	// Complete: every record was examined; false when Limit cut a collection short.
	Complete bool `json:"complete"`
	// Done: nothing sealed with a previous secret remains. Only then can previousSecrets go.
	Done bool `json:"done"`
}

// SealedField is a sealed value inside a record: where it lives and the context it was sealed for.
type SealedField struct {
	Collection string
	// Filter selects only records that still hold a sealed value (a fresh object per call).
	Filter  func() *core.Object
	Read    func(record *core.Object) (string, bool)
	Write   func(record *core.Object, sealed string) *core.Object
	Context func(record *core.Object) string
}

// stringMember reads a string member.
func stringMember(key string) func(record *core.Object) (string, bool) {
	return func(record *core.Object) (string, bool) {
		value, ok := record.Get(key).(string)
		return value, ok
	}
}

// setMember returns `{ ...record, [key]: sealed }`.
func setMember(key string) func(record *core.Object, sealed string) *core.Object {
	return func(record *core.Object, sealed string) *core.Object {
		return record.Spread(core.NewObject(key, sealed))
	}
}

// nestedString reads a string member of an object member.
func nestedString(outer, key string) func(record *core.Object) (string, bool) {
	return func(record *core.Object) (string, bool) {
		value, ok := member(record.Get(outer), key).(string)
		return value, ok
	}
}

// setNested returns `{ ...record, [outer]: { ...record[outer], [key]: sealed } }`.
func setNested(outer, key string) func(record *core.Object, sealed string) *core.Object {
	return func(record *core.Object, sealed string) *core.Object {
		inner := core.NewObject()
		if existing, ok := record.Get(outer).(*core.Object); ok {
			inner = existing.Spread()
		}
		inner.Set(key, sealed)
		return record.Spread(core.NewObject(outer, inner))
	}
}

func noFilter() *core.Object { return core.NewObject() }

// SealedFields are every sealed value the server keeps under the deployment secret, in rotation order.
var SealedFields = []SealedField{
	{
		// TOTP authenticator secrets.
		Collection: "authMfa", Filter: noFilter, Read: stringMember("encryptedSecret"), Write: setMember("encryptedSecret"),
		Context: func(record *core.Object) string { return "mfa:" + jsString(record.Get("identityId")) },
	},
	{
		// Webhook signing secrets.
		Collection: "webhooks", Filter: noFilter, Read: stringMember("secretSealed"), Write: setMember("secretSealed"),
		Context: func(record *core.Object) string { return "webhook:" + jsString(record.Get("id")) },
	},
	{
		// Undelivered email, SMS, and webhook payloads (delivered ones are cleared).
		Collection: "outbox",
		Filter: func() *core.Object {
			return core.NewObject("deliveredAt", core.Undefined, "failedAt", core.Undefined)
		},
		Read:    nestedString("payload", "sealed"),
		Write:   setNested("payload", "sealed"),
		Context: func(record *core.Object) string { return "outbox:" + jsString(record.Get("id")) },
	},
	{
		// Inference provider API keys (inference.ts providerKeyContext).
		Collection: "inferenceProviders", Filter: noFilter, Read: stringMember("keySealed"), Write: setMember("keySealed"),
		Context: func(record *core.Object) string { return "inference-provider:" + jsString(record.Get("id")) },
	},
	// KMS key material sealed under the deployment secret (kms.ts); data protection keys are wrapped under KMS keys.
	KmsSealedField,
	{
		// Vault secret values (vault.ts versionContext); values under a customer-managed key are KMS ciphertexts.
		Collection: "vaultVersions", Filter: noFilter,
		Read: func(record *core.Object) (string, bool) {
			value, ok := record.Get("sealed").(string)
			return value, ok && isUndefined(record.Get("kmsKeyId"))
		},
		Write: setMember("sealed"),
		Context: func(record *core.Object) string {
			return "vault:" + jsString(record.Get("tenantId")) + ":" + jsString(record.Get("secretId")) + ":" + jsString(record.Get("version"))
		},
	},
	{
		// Dynamic secret engines' revocation handles (vault.ts leaseHandleContext).
		Collection: "vaultLeases", Filter: noFilter, Read: stringMember("handleSealed"), Write: setMember("handleSealed"),
		Context: func(record *core.Object) string { return "vault-lease:" + jsString(record.Get("id")) },
	},
	{
		// SSH certificate authority keys (ssh.ts authorityContext).
		Collection: "sshAuthorities", Filter: noFilter, Read: stringMember("keySealed"), Write: setMember("keySealed"),
		Context: func(record *core.Object) string { return "ssh-authority:" + jsString(record.Get("id")) },
	},
	{
		// Verifiable credential issuer keys (vc.ts keyContext).
		Collection: "vcIssuerKeys", Filter: noFilter, Read: stringMember("keySealed"), Write: setMember("keySealed"),
		Context: func(record *core.Object) string { return "vc-issuer-key:" + jsString(record.Get("id")) },
	},
	{
		// Shared Signals poll sources' bearer tokens (signal-receiver.ts pollTokenContext).
		Collection: "signalSources", Filter: noFilter, Read: nestedString("poll", "tokenSealed"), Write: setNested("poll", "tokenSealed"),
		Context: func(record *core.Object) string { return "signal-poll:" + jsString(record.Get("id")) },
	},
}

// RotateSecrets re-seals every value encrypted with a previous deployment secret using the current one, so the
// previous secret can be retired (createSecretRotation). Configure the new secret with the old one in
// previousSecrets, run this until Done, wait a day for pending challenges and assertions to expire, then remove
// previousSecrets. Sessions and API keys are hashed without the secret, so nobody is signed out.
func RotateSecrets(ctx context.Context, server *ServerContext, options SecretRotationOptions) (*SecretRotationResult, error) {
	batchSize := 200.0
	if options.BatchSize != nil {
		batchSize = *options.BatchSize
	}
	if !core.IsSafeInteger(batchSize) || batchSize < 1 || batchSize > 2000 {
		return nil, invalidInput("batchSize must be an integer between 1 and 2000")
	}
	limit := math.Inf(1)
	if options.Limit != nil {
		limit = *options.Limit
	}
	if !math.IsInf(limit, 1) && (!core.IsSafeInteger(limit) || limit < 1) {
		return nil, invalidInput("limit must be a positive integer")
	}
	secrets := append([]string{server.Options.Secret}, server.Options.PreviousSecrets...)
	result := &SecretRotationResult{Resealed: core.NewObject(), Unreadable: core.NewObject(), Complete: true, Done: true}
	count := func(bucket *core.Object, collection string) {
		previous, _ := bucket.Get(collection).(float64)
		bucket.Set(collection, previous+1)
	}
	for _, field := range SealedFields {
		after := ""
		examined := 0.0
		for {
			size := math.Min(batchSize, limit-examined)
			if size <= 0 {
				// The limit stopped this collection after a full page: records may remain unexamined.
				result.Complete = false
				break
			}
			page := func(ctx context.Context, tx core.IamStore) ([]*core.Object, error) {
				pageSize := int(size)
				find := &core.FindOptions{Limit: &pageSize}
				if after != "" {
					cursor := after
					find.After = &cursor
				}
				records, err := tx.Find(ctx, field.Collection, field.Filter(), find)
				if err != nil {
					return nil, err
				}
				for _, record := range records {
					sealed, ok := field.Read(record)
					if !ok {
						continue
					}
					opened, ok := auth.OpenSecret(sealed, secrets, field.Context(record))
					if !ok {
						count(result.Unreadable, field.Collection)
						continue
					}
					if opened.Index == 0 {
						result.Current++
						continue
					}
					count(result.Resealed, field.Collection)
					if !options.DryRun {
						resealed := auth.EncryptSecret(opened.Value, server.Options.Secret, field.Context(record))
						if _, err := tx.Put(ctx, field.Collection, field.Write(record, resealed)); err != nil {
							return nil, err
						}
					}
				}
				return records, nil
			}
			// Each page reads and rewrites in one short transaction, so a value changed meanwhile is re-read rather
			// than overwritten with a stale copy.
			var records []*core.Object
			var err error
			if options.DryRun {
				records, err = page(ctx, server.Store)
			} else {
				records, err = core.Transact(ctx, server.Store, page)
			}
			if err != nil {
				return nil, err
			}
			examined += float64(len(records))
			if float64(len(records)) < size {
				break
			}
			after = jsString(records[len(records)-1].Get("id"))
		}
	}
	result.Done = result.Complete && !(options.DryRun && result.Resealed.Len() > 0)
	return result, nil
}
