package server

// Port of packages/server/src/api/vault.ts: the secrets vault's API group, the trusted `iam.vault` runtime and the
// vault's scheduler jobs. Secrets live in one tenant under a path-like name and are authorized as
// `iam/vault/secrets/{name}`: `iam:vault:read` (metadata), `iam:vault:reveal` (values), `iam:vault:write` (new
// versions and stages), `iam:vault:rotate`, `iam:vault:lease` (check-outs and dynamic leases) and `iam:vault:manage`
// (create, settings, delete, versions' state). Policy conditions see `resource.name`, `resource.tag.{key}`,
// `resource.kind`, `resource.createdBy`, `resource.checkoutRequired` and `resource.rotationEnabled`.

import (
	"context"
	"errors"
	"math"
	"regexp"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// secretActions is every action decided on `iam/vault/secrets/{name}`.
var secretActions = []string{
	"iam:vault:read",
	"iam:vault:reveal",
	"iam:vault:write",
	"iam:vault:rotate",
	"iam:vault:lease",
	"iam:vault:manage",
}

// revokePatienceMs is how long revocations that keep failing are retried before the lease is given up.
var revokePatienceMs = 7 * VaultTime.DAY

// vaultScanPage is SCAN_PAGE: the page size of the jobs' keyset scans.
const vaultScanPage = 500

// vaultReference is /^vault:\/\/([^#]+)(?:#(.+))?$/ (JavaScript's `.` stops at line terminators).
var vaultReference = regexp.MustCompile(`^vault://([^#]+)(?:#([^\n\r\x{2028}\x{2029}]+))?$`)

// --- helpers -------------------------------------------------------------------------------------

// vaultRecorder is Recorder: the vault's audit recorder for one secret.
type vaultRecorder func(ctx context.Context, tx core.IamStore, action, outcome string, metadata *core.Object) error

// stagedRotation is StagedRotation: what the rotation machinery carries from the staging transaction to the
// promotion one.
type stagedRotation struct {
	TenantID string
	SecretID string
	Name     string
	Version  float64
	Value    string
	Previous *string
	Format   string
	Tags     any
	Rotator  *string
}

// answer is the staged rotation without its values, as plugin hooks see it.
func (s *stagedRotation) answer() *core.Object {
	object := core.NewObject(
		"tenantId", s.TenantID,
		"secretId", s.SecretID,
		"name", s.Name,
		"version", s.Version,
		"format", s.Format,
		"tags", s.Tags,
	)
	if s.Rotator != nil {
		object.Set("rotator", *s.Rotator)
	}
	return object
}

// values is the staged rotation's values: `{ value, previous? }`.
func (s *stagedRotation) values() *core.Object {
	object := core.NewObject("value", s.Value)
	if s.Previous != nil {
		object.Set("previous", *s.Previous)
	}
	return object
}

// rotationOutcome is completeRotation's answer: the result, or the failure message.
type rotationOutcome struct {
	ok      bool
	result  *core.Object
	message string
}

// vaultSettingsOf is vaultSettings(ctx). It accepts the settings function with either the skeleton's or the vault
// module's parameter, so this file builds against both while vault.ts is ported concurrently.
func vaultSettingsOf(server *ServerContext) (*core.Object, error) {
	switch settings := any(VaultSettings).(type) {
	case func(*ServerContext) (*core.Object, error):
		return settings(server)
	case func(*core.Object) (*core.Object, error):
		return settings(nil)
	}
	return nil, notImplemented("vault.ts vaultSettings")
}

// vaultRotatorsOf is `settings.rotators`.
func vaultRotatorsOf(settings *core.Object) map[string]VaultRotator {
	if rotators, ok := settings.Get("rotators").(map[string]VaultRotator); ok {
		return rotators
	}
	return map[string]VaultRotator{}
}

// vaultEnginesOf is `settings.engines`.
func vaultEnginesOf(settings *core.Object) map[string]VaultEngine {
	if engines, ok := settings.Get("engines").(map[string]VaultEngine); ok {
		return engines
	}
	return map[string]VaultEngine{}
}

// vaultSecretResource is secretResource(name): `vault/secrets/{name}`.
func vaultSecretResource(name string) string {
	resource, err := SecretResource(name)
	if err != nil {
		return SecretResourcePrefix + name
	}
	return resource
}

// vaultObject is a member as an object, nil when it is not one.
func vaultObject(value any) *core.Object {
	object, _ := value.(*core.Object)
	return object
}

// vaultStages is a secret's stage labels (never nil).
func vaultStages(secret *core.Object) *core.Object {
	if stages := vaultObject(secret.Get("stages")); stages != nil {
		return stages
	}
	return core.NewObject()
}

// vaultSorted sorts records by a numeric member, ascending (or descending), stably.
func vaultSorted(records []*core.Object, key string, descending bool) {
	sortStable(records, func(a, b *core.Object) int {
		difference := jsNumber(a.Get(key)) - jsNumber(b.Get(key))
		if descending {
			difference = -difference
		}
		switch {
		case difference < 0:
			return -1
		case difference > 0:
			return 1
		}
		return 0
	})
}

func secretView(secret *core.Object, leases []*core.Object, now float64) *core.Object {
	view := core.NewObject("name", secret.Get("name"))
	if description := secret.Get("description"); !isUndefined(description) {
		view.Set("description", description)
	}
	view.Set("kind", secret.Get("kind"))
	view.Set("format", secret.Get("format"))
	view.Set("tags", secret.Get("tags"))
	view.Set("status", secret.Get("status"))
	if deletionAt := secret.Get("deletionAt"); !isUndefined(deletionAt) {
		view.Set("deletionAt", deletionAt)
	}
	view.Set("stages", secret.Get("stages"))
	view.Set("latestVersion", secret.Get("latestVersion"))
	view.Set("maxVersions", secret.Get("maxVersions"))
	if rotation := secret.Get("rotation"); truthy(rotation) {
		shown := core.NewObject()
		for _, key := range []string{"intervalDays"} {
			if value := member(rotation, key); !isUndefined(value) {
				shown.Set(key, value)
			}
		}
		if generator := member(rotation, "generator"); truthy(generator) {
			shown.Set("generator", generator)
		}
		for _, key := range []string{"field", "rotator", "lastRotatedAt", "nextRotationAt"} {
			if value := member(rotation, key); !isUndefined(value) {
				shown.Set(key, value)
			}
		}
		next := member(rotation, "nextRotationAt")
		shown.Set("due", !isUndefined(next) && jsNumber(next) <= now)
		if lastFailure := member(rotation, "lastFailure"); truthy(lastFailure) {
			shown.Set("lastFailure", lastFailure)
		}
		if failures := member(rotation, "failures"); truthy(failures) {
			shown.Set("failures", failures)
		}
		view.Set("rotation", shown)
	}
	if checkout := secret.Get("checkout"); truthy(checkout) {
		view.Set("checkout", checkout)
	}
	for _, key := range []string{"engine", "engineConfig"} {
		if value := secret.Get(key); !isUndefined(value) {
			view.Set(key, value)
		}
	}
	if lease := secret.Get("lease"); truthy(lease) {
		view.Set("lease", lease)
	}
	if keyID := secret.Get("kmsKeyId"); !isUndefined(keyID) {
		view.Set("kmsKeyId", keyID)
	}
	checkedOut := []any{}
	active := 0.0
	for _, lease := range leases {
		switch lease.Get("kind") {
		case "checkout":
			checkedOut = append(checkedOut, core.NewObject(
				"leaseId", lease.Get("id"), "holderId", lease.Get("holderId"), "expiresAt", lease.Get("expiresAt"),
			))
		case "dynamic":
			active++
		}
	}
	view.Set("checkedOut", checkedOut)
	view.Set("activeLeases", active)
	view.Set("createdAt", secret.Get("createdAt"))
	view.Set("createdBy", secret.Get("createdBy"))
	view.Set("updatedAt", secret.Get("updatedAt"))
	view.Set("updatedBy", secret.Get("updatedBy"))
	if accessed := secret.Get("lastAccessedAt"); !isUndefined(accessed) {
		view.Set("lastAccessedAt", accessed)
	}
	return view
}

// secretStagesOf is the stage labels pointing at a version, sorted.
func secretStagesOf(secret *core.Object, version any) []any {
	labels := []string{}
	vaultStages(secret).Entries(func(label string, value any) bool {
		if core.StrictEquals(value, version) {
			labels = append(labels, label)
		}
		return true
	})
	sortStable(labels, compareUTF16)
	return stringsOf(labels)
}

func secretVersionView(secret *core.Object, version *core.Object) *core.Object {
	view := core.NewObject(
		"version", version.Get("version"),
		"state", version.Get("state"),
		"stages", secretStagesOf(secret, version.Get("version")),
		"source", version.Get("source"),
		"createdAt", version.Get("createdAt"),
		"createdBy", version.Get("createdBy"),
	)
	for _, key := range []string{"disabledAt", "destroyedAt"} {
		if value := version.Get(key); !isUndefined(value) {
			view.Set(key, value)
		}
	}
	return view
}

// splitSecretValues splits a revealed secret into what plugin hooks may see and the values they may not.
func splitSecretValues(shown *core.Object) (answer *core.Object, values *core.Object) {
	answer = shown.Spread()
	answer.Delete("value")
	answer.Delete("fields")
	values = core.NewObject("value", shown.Get("value"))
	if fields := shown.Get("fields"); !isUndefined(fields) {
		values.Set("fields", fields)
	}
	return answer, values
}

// vaultLeaseActor is the agent and delegation behind a delegated session, recorded on the leases it takes.
func vaultLeaseActor(lease *core.Object, principal *Principal) {
	if agentID, ok := principal.Session.Get("agentId").(string); ok {
		lease.Set("agentId", agentID)
	}
	if delegationID, ok := principal.Session.Get("delegationId").(string); ok {
		lease.Set("delegationId", delegationID)
	}
}

func revealedSecret(secret *core.Object, version *core.Object, value string) (*core.Object, error) {
	shown := core.NewObject(
		"name", secret.Get("name"),
		"version", version.Get("version"),
		"stages", secretStagesOf(secret, version.Get("version")),
		"format", secret.Get("format"),
		"value", value,
	)
	if secret.Get("format") == "json" {
		fields, err := ParseFields(value)
		if err != nil {
			return nil, err
		}
		shown.Set("fields", fields)
	}
	shown.Set("createdAt", version.Get("createdAt"))
	return shown, nil
}

func secretLeaseView(lease *core.Object, holderName *string) *core.Object {
	view := core.NewObject(
		"id", lease.Get("id"),
		"name", lease.Get("name"),
		"kind", lease.Get("kind"),
		"holderId", lease.Get("holderId"),
	)
	if holderName != nil {
		view.Set("holderName", *holderName)
	}
	for _, key := range []string{"version", "reason"} {
		if value := lease.Get(key); !isUndefined(value) {
			view.Set(key, value)
		}
	}
	view.Set("state", lease.Get("state"))
	view.Set("issuedAt", lease.Get("issuedAt"))
	view.Set("expiresAt", lease.Get("expiresAt"))
	view.Set("maxExpiresAt", lease.Get("maxExpiresAt"))
	for _, key := range []string{"endedAt", "endedBy", "lastError"} {
		if value := lease.Get(key); !isUndefined(value) {
			view.Set(key, value)
		}
	}
	return view
}

func vaultWritable(realm *core.Object) error {
	if realm.Get("status") == "deleted" {
		return core.NewIamError("INVALID_TRANSITION", "Deleted tenants cannot be updated")
	}
	return nil
}

func existingSecret(ctx context.Context, tx core.IamStore, tenantID, name string) (*core.Object, error) {
	secret, err := FindSecret(ctx, tx, tenantID, name)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return nil, core.NewIamError("NOT_FOUND", "Secret not found", 404)
	}
	return secret, nil
}

func activeSecret(secret *core.Object) (*core.Object, error) {
	if secret.Get("status") != "active" {
		return nil, core.NewIamError("SECRET_PENDING_DELETION", "This secret is scheduled for deletion; restore it first", 409)
	}
	return secret, nil
}

func staticSecret(secret *core.Object) (*core.Object, error) {
	if secret.Get("kind") != "static" {
		return nil, invalidInput("Dynamic secrets have no stored value; request a lease with vault.lease")
	}
	return secret, nil
}

// existingStatic is staticSecret(activeSecret(await existingSecret(...))).
func existingStatic(ctx context.Context, tx core.IamStore, tenantID, name string, active bool) (*core.Object, error) {
	secret, err := existingSecret(ctx, tx, tenantID, name)
	if err != nil {
		return nil, err
	}
	if active {
		if secret, err = activeSecret(secret); err != nil {
			return nil, err
		}
	}
	return staticSecret(secret)
}

// refuseVaultImpersonation: values leave the vault only for the person themselves, never through "view as".
func refuseVaultImpersonation(principal *Principal) error {
	if truthy(principal.Session.Get("impersonatorId")) {
		return NewOperationDenied("Secret values are not available while viewing as another member")
	}
	return nil
}

func vaultAccessEntry(principal *Principal, pairs ...any) *core.Object {
	entry := core.NewObject("identityId", principal.Identity.Get("id"))
	if kind := principal.Session.Get("kind"); !isUndefined(kind) {
		entry.Set("sessionKind", kind)
	}
	if agentID := principal.Session.Get("agentId"); truthy(agentID) {
		entry.Set("agentId", agentID)
	}
	for index := 0; index+1 < len(pairs); index += 2 {
		if value := pairs[index+1]; !isUndefined(value) {
			entry.Set(pairs[index].(string), value)
		}
	}
	return entry
}

// checkoutFits: a json secret that rotates when checked in must say which field rotation replaces, or returns would
// not rotate.
func checkoutFits(secret *core.Object) error {
	if member(secret.Get("checkout"), "rotateOnCheckin") == true && secret.Get("format") == "json" &&
		!truthy(member(secret.Get("rotation"), "field")) {
		return invalidInput("A json secret that rotates on check-in needs rotation.field, the field rotation replaces")
	}
	return nil
}

func vaultMaxVersions(value any) (float64, error) {
	if isUndefined(value) {
		return 10, nil
	}
	return Integer(value, "maxVersions", 1, 100)
}

// vaultDefaultGenerator is defaultGenerator as a generator object.
func vaultDefaultGenerator() *core.Object {
	return core.NewObject("length", DefaultGenerator.Length, "charset", DefaultGenerator.Charset, "eachClass", DefaultGenerator.EachClass)
}

// hasExplicitValue says the caller passed `value` or `fields`.
func hasExplicitValue(explicit *core.Object) bool {
	return explicit != nil && (!isUndefined(explicit.Get("value")) || !isUndefined(explicit.Get("fields")))
}

// nextRotationValue is nextValue: the next value a rotation writes, the explicit one or the generator's (into
// `rotation.field` for json secrets).
func nextRotationValue(server *ServerContext, secret *core.Object, previous *string, explicit *core.Object) (string, string, error) {
	format := jsString(secret.Get("format"))
	if hasExplicitValue(explicit) {
		settings, err := vaultSettingsOf(server)
		if err != nil {
			return "", "", err
		}
		value, err := SecretValue(settings, format, explicit)
		return value, "put", err
	}
	rotation := secret.Get("rotation")
	generator := vaultObject(member(rotation, "generator"))
	if generator == nil {
		generator = vaultDefaultGenerator()
	}
	generated, err := GenerateValue(generator)
	if err != nil {
		return "", "", err
	}
	if format == "text" {
		return generated, "rotation", nil
	}
	field := member(rotation, "field")
	if !truthy(field) {
		return "", "", invalidInput("Pass the new fields, or set rotation.field so rotation can generate one")
	}
	fields := core.NewObject()
	if previous != nil && *previous != "" {
		if fields, err = ParseFields(*previous); err != nil {
			return "", "", err
		}
	}
	fields.Set(jsString(field), generated)
	settings, err := vaultSettingsOf(server)
	if err != nil {
		return "", "", err
	}
	value, err := SecretValue(settings, "json", core.NewObject("fields", fields))
	return value, "rotation", err
}

// stageRotation stages the next version as `pending` (or reuses a pending version left by a failed attempt, so a
// rotator sees the same value on every retry) and returns what the rotator needs. Runs inside the caller's
// transaction.
func stageRotation(ctx context.Context, server *ServerContext, tx core.IamStore, original *core.Object, actorID string, explicit *core.Object, use *Principal) (*stagedRotation, error) {
	secret, err := activeSecret(original)
	if err != nil {
		return nil, err
	}
	if secret, err = staticSecret(secret); err != nil {
		return nil, err
	}
	stages := vaultStages(secret)
	var current, pending *core.Object
	if label := stages.Get("current"); !isUndefined(label) {
		if current, err = VersionOf(ctx, tx, secret, jsNumber(label)); err != nil {
			return nil, err
		}
	}
	var previous *string
	if current != nil && current.Get("state") == "enabled" {
		opened, err := OpenVersion(ctx, server, tx, current, use)
		if err != nil {
			return nil, err
		}
		previous = &opened
	}
	if label := stages.Get("pending"); !isUndefined(label) {
		if pending, err = VersionOf(ctx, tx, secret, jsNumber(label)); err != nil {
			return nil, err
		}
	}
	fresh := hasExplicitValue(explicit)
	var version *core.Object
	var value string
	// Only a version this machinery staged (and whose attempt failed) is retried: a `pending` label someone set with
	// `put` or `setStage` is never handed to the rotator, or `iam:vault:write` could choose the live credential.
	if !fresh && pending != nil && pending.Get("state") == "enabled" && core.StrictEquals(secret.Get("rotationPending"), pending.Get("version")) {
		version = pending
		if value, err = OpenVersion(ctx, server, tx, pending, use); err != nil {
			return nil, err
		}
	} else {
		nextValue, source, err := nextRotationValue(server, secret, previous, explicit)
		if err != nil {
			return nil, err
		}
		added, err := AddVersion(ctx, server, tx, secret, nextValue, source, actorID, use)
		if err != nil {
			return nil, err
		}
		addedSecret, addedVersion := vaultObject(added.Get("secret")), vaultObject(added.Get("version"))
		nextStages := stages.Spread()
		nextStages.Set("pending", addedVersion.Get("version"))
		if secret, err = tx.Put(ctx, VaultCollections.Secrets, addedSecret.Spread(core.NewObject(
			"stages", nextStages,
			"rotationPending", addedVersion.Get("version"),
			"updatedAt", float64(server.Now()),
			"updatedBy", actorID,
		))); err != nil {
			return nil, err
		}
		version = addedVersion
		value = nextValue
	}
	staged := &stagedRotation{
		TenantID: jsString(secret.Get("tenantId")),
		SecretID: jsString(secret.Get("id")),
		Name:     jsString(secret.Get("name")),
		Version:  jsNumber(version.Get("version")),
		Value:    value,
		Previous: previous,
		Format:   jsString(secret.Get("format")),
		Tags:     secret.Get("tags"),
	}
	if rotator := member(secret.Get("rotation"), "rotator"); !isUndefined(rotator) {
		name := jsString(rotator)
		staged.Rotator = &name
	}
	return staged, nil
}

// recordRotationFailure records a failed rotation on the secret (the message must already be redacted) and schedules
// the retry: one hour, doubling up to a day, for secrets that rotate on a schedule or when a check-out comes back. An
// on-demand rotation is retried by calling it again.
func recordRotationFailure(ctx context.Context, server *ServerContext, tx core.IamStore, secret *core.Object, message string) error {
	now := float64(server.Now())
	rotation := vaultObject(secret.Get("rotation"))
	failures := 1.0
	if count := member(rotation, "failures"); !nullish(count) {
		failures = jsNumber(count) + 1
	}
	retryIn := math.Min(VaultTime.DAY, 60*VaultTime.MINUTE*math.Pow(2, math.Min(failures-1, 5)))
	scheduled := !isUndefined(member(rotation, "intervalDays")) || member(secret.Get("checkout"), "rotateOnCheckin") == true
	next := core.NewObject()
	if rotation != nil {
		next = rotation.Spread()
	}
	next.Set("lastFailure", core.NewObject("at", now, "message", message))
	next.Set("failures", failures)
	if scheduled {
		next.Set("nextRotationAt", now+retryIn)
	}
	_, err := tx.Put(ctx, VaultCollections.Secrets, secret.Spread(core.NewObject("rotation", next)))
	return err
}

// completeRotation calls the rotator (outside any transaction), then promotes the pending version, or records the
// failure with a growing retry delay. Returns the outcome; the caller decides whether a failure throws.
func completeRotation(ctx context.Context, server *ServerContext, staged *stagedRotation, actorID string, record vaultRecorder) (rotationOutcome, error) {
	var failure *string
	if staged.Rotator != nil {
		settings, err := vaultSettingsOf(server)
		if err != nil {
			return rotationOutcome{}, err
		}
		rotator, configured := vaultRotatorsOf(settings)[*staged.Rotator]
		if !configured {
			message := "The rotator " + *staged.Rotator + " is not configured"
			failure = &message
		} else {
			_, err := WithTimeout(ctx, server, "The rotator "+*staged.Rotator, func(callCtx context.Context) (any, error) {
				input := RotatorInput{
					TenantID: staged.TenantID,
					Name:     staged.Name,
					Version:  staged.Version,
					Value:    staged.Value,
					Tags:     map[string]string{},
				}
				if staged.Format == "json" {
					fields, err := ParseFields(staged.Value)
					if err != nil {
						return nil, err
					}
					input.Fields = fields
				}
				if staged.Previous != nil {
					previous := *staged.Previous
					input.Previous = &previous
					if staged.Format == "json" {
						fields, err := ParseFields(previous)
						if err != nil {
							return nil, err
						}
						input.PreviousFields = fields
					}
				}
				if tags := vaultObject(staged.Tags); tags != nil {
					tags.Entries(func(key string, value any) bool {
						input.Tags[key] = jsString(value)
						return true
					})
				}
				return nil, rotator.Rotate(callCtx, input)
			})
			if err != nil {
				previous := ""
				if staged.Previous != nil {
					previous = *staged.Previous
				}
				message, redactErr := RedactedMessage(err, []string{staged.Value, previous})
				if redactErr != nil {
					return rotationOutcome{}, redactErr
				}
				failure = &message
			}
		}
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (rotationOutcome, error) {
		secret, err := tx.Get(ctx, VaultCollections.Secrets, staged.SecretID)
		if err != nil {
			return rotationOutcome{}, err
		}
		if secret == nil || secret.Get("status") != "active" {
			return rotationOutcome{message: "The secret was deleted during rotation"}, nil
		}
		if failure != nil {
			if err := recordRotationFailure(ctx, server, tx, secret, *failure); err != nil {
				return rotationOutcome{}, err
			}
			metadata := core.NewObject("name", secret.Get("name"), "version", staged.Version)
			if staged.Rotator != nil {
				metadata.Set("rotator", *staged.Rotator)
			}
			metadata.Set("error", *failure)
			if err := record(ctx, tx, "vault:rotate", "deny", metadata); err != nil {
				return rotationOutcome{}, err
			}
			return rotationOutcome{message: *failure}, nil
		}
		stages := vaultStages(secret)
		if !core.StrictEquals(stages.Get("pending"), staged.Version) && !core.StrictEquals(stages.Get("current"), staged.Version) {
			return rotationOutcome{message: "Another change replaced the pending version during rotation"}, nil
		}
		// The version may have been disabled or destroyed while the rotator ran: never make that current.
		version, err := VersionOf(ctx, tx, secret, staged.Version)
		if err != nil {
			return rotationOutcome{}, err
		}
		if version == nil || version.Get("state") != "enabled" {
			return rotationOutcome{message: "The pending version was disabled or destroyed during rotation"}, nil
		}
		promoted, err := PromoteVersion(ctx, server, tx, secret, staged.Version, actorID, true)
		if err != nil {
			return rotationOutcome{}, err
		}
		if err := RecordAccess(ctx, server, tx, promoted, core.NewObject(
			"identityId", actorID, "action", "rotate", "version", staged.Version,
		)); err != nil {
			return rotationOutcome{}, err
		}
		metadata := core.NewObject("name", secret.Get("name"), "version", staged.Version)
		if staged.Rotator != nil {
			metadata.Set("rotator", *staged.Rotator)
		}
		if err := record(ctx, tx, "vault:rotate", "allow", metadata); err != nil {
			return rotationOutcome{}, err
		}
		rotatedAt := member(promoted.Get("rotation"), "lastRotatedAt")
		if nullish(rotatedAt) {
			rotatedAt = float64(server.Now())
		}
		result := core.NewObject("name", promoted.Get("name"), "version", staged.Version, "rotatedAt", rotatedAt)
		if staged.Rotator != nil {
			result.Set("rotator", *staged.Rotator)
		}
		result.Set("stages", promoted.Get("stages"))
		return rotationOutcome{ok: true, result: result}, nil
	})
}

// rotateReturned rotates a `rotateOnCheckin` secret once its last check-out has ended (returned, revoked or
// expired). Failures, including one that stops the rotation before the rotator runs, are recorded on the secret and
// audited, and `iam.vault.rotateDue` retries them; they are never returned, because the check-out has ended either
// way.
func rotateReturned(ctx context.Context, server *ServerContext, tenantID, secretID, actorID string, record func(name string) vaultRecorder) (*float64, error) {
	staged, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*stagedRotation, error) {
		secret, err := tx.Get(ctx, VaultCollections.Secrets, secretID)
		if err != nil {
			return nil, err
		}
		if secret == nil || secret.Get("tenantId") != tenantID || secret.Get("status") != "active" ||
			!truthy(member(secret.Get("checkout"), "rotateOnCheckin")) {
			return nil, nil
		}
		// Another holder still has the value: rotate once the last one returns it.
		live, err := LiveLeases(ctx, server, tx, secret)
		if err != nil {
			return nil, err
		}
		for _, lease := range live {
			if lease.Get("kind") == "checkout" {
				return nil, nil
			}
		}
		return stageRotation(ctx, server, tx, secret, actorID, core.NewObject(), nil)
	})
	if err != nil {
		cause := err
		_ = server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			secret, err := tx.Get(ctx, VaultCollections.Secrets, secretID)
			if err != nil {
				return err
			}
			if secret == nil || secret.Get("status") != "active" {
				return nil
			}
			message, err := RedactedMessage(cause, nil)
			if err != nil {
				return err
			}
			if err := recordRotationFailure(ctx, server, tx, secret, message); err != nil {
				return err
			}
			return record(jsString(secret.Get("name")))(ctx, tx, "vault:rotate", "deny", core.NewObject(
				"name", secret.Get("name"), "error", message,
			))
		})
		return nil, nil
	}
	if staged == nil {
		return nil, nil
	}
	outcome, err := completeRotation(ctx, server, staged, actorID, record(staged.Name))
	if err != nil {
		return nil, err
	}
	if !outcome.ok {
		return nil, nil
	}
	version := jsNumber(outcome.result.Get("version"))
	return &version, nil
}

// issuedValue is the engine's credential, validated against the secret's format and the size limit.
func issuedValue(server *ServerContext, format string, issued *EngineIssued) (string, *string, error) {
	if issued == nil {
		return "", nil, errors.New("The engine returned no credential")
	}
	settings, err := vaultSettingsOf(server)
	if err != nil {
		return "", nil, err
	}
	var raw any = core.Undefined
	if issued.Value != nil {
		raw = *issued.Value
	}
	var value string
	if format == "json" {
		if issued.Fields != nil {
			value, err = SecretValue(settings, "json", core.NewObject("fields", issued.Fields))
		} else {
			value, err = SecretValue(settings, "json", core.NewObject("value", raw))
		}
	} else {
		value, err = SecretValue(settings, "text", core.NewObject("value", raw))
	}
	if err != nil {
		return "", nil, err
	}
	if issued.Handle != nil && utf16Len(*issued.Handle) > 4096 {
		return "", nil, errors.New("The engine returned an invalid handle")
	}
	return value, issued.Handle, nil
}

// engineConfigOf is `secret?.engineConfig ?? {}`.
func engineConfigOf(secret *core.Object) any {
	if secret != nil {
		if config := secret.Get("engineConfig"); !nullish(config) {
			return config
		}
	}
	return core.NewObject()
}

// openLeaseHandle opens a dynamic lease's sealed revocation handle, nil when it has none.
func openLeaseHandle(server *ServerContext, lease *core.Object) (*string, error) {
	sealed := lease.Get("handleSealed")
	if !truthy(sealed) {
		return nil, nil
	}
	context, err := LeaseHandleContext(jsString(lease.Get("id")))
	if err != nil {
		return nil, err
	}
	handle, err := VaultOpenValue(server, jsString(sealed), context)
	if err != nil {
		return nil, err
	}
	return &handle, nil
}

// sealLeaseHandle seals a dynamic lease's revocation handle.
func sealLeaseHandle(server *ServerContext, leaseID string, handle string) (string, error) {
	context, err := LeaseHandleContext(leaseID)
	if err != nil {
		return "", err
	}
	return VaultSealValue(server, handle, context)
}

// revokeAtEngine ends a dynamic lease at its engine; the caller records the outcome. Fails with the redacted message.
func revokeAtEngine(ctx context.Context, server *ServerContext, lease *core.Object, secret *core.Object) error {
	var engineName string
	if secret != nil {
		engineName, _ = secret.Get("engine").(string)
	}
	if engineName == "" {
		return nil
	}
	settings, err := vaultSettingsOf(server)
	if err != nil {
		return err
	}
	engine, ok := vaultEnginesOf(settings)[engineName]
	if !ok || engine.Revoke == nil {
		return nil
	}
	handle, err := openLeaseHandle(server, lease)
	if err != nil {
		return err
	}
	_, err = WithTimeout(ctx, server, "The engine "+engineName, func(callCtx context.Context) (any, error) {
		return nil, engine.Revoke(callCtx, EngineLeaseInput{
			TenantID: jsString(lease.Get("tenantId")),
			Name:     jsString(lease.Get("name")),
			LeaseID:  jsString(lease.Get("id")),
			Config:   engineConfigOf(secret),
			Handle:   handle,
		})
	})
	if err != nil {
		values := []string{}
		if handle != nil {
			values = append(values, *handle)
		}
		message, redactErr := RedactedMessage(err, values)
		if redactErr != nil {
			return redactErr
		}
		return errors.New(message)
	}
	return nil
}

// revokeAndRecord revokes a dynamic lease at its engine and records the outcome: the lease ends in its `endState`
// (default `ended`), or stays `revoking` with a retry scheduled (one minute, doubling up to six hours) for
// `iam.vault.expireLeases`. The lease must already be `revoking`. Engines without `revoke` end the lease at once.
// Returns whether it ended, and the failure message when not.
func revokeAndRecord(ctx context.Context, server *ServerContext, leaseID string) (bool, string, error) {
	lease, err := server.Store.Get(ctx, VaultCollections.Leases, leaseID)
	if err != nil {
		return false, "", err
	}
	if lease == nil || lease.Get("state") != "revoking" {
		return true, "", nil
	}
	secret, err := server.Store.Get(ctx, VaultCollections.Secrets, jsString(lease.Get("secretId")))
	if err != nil {
		return false, "", err
	}
	var failure *string
	if err := revokeAtEngine(ctx, server, lease, secret); err != nil {
		message := err.Error()
		failure = &message
	}
	if err := server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		current, err := tx.Get(ctx, VaultCollections.Leases, leaseID)
		if err != nil {
			return err
		}
		if current == nil || current.Get("state") != "revoking" {
			return nil
		}
		now := float64(server.Now())
		if failure == nil {
			rest := current.Spread()
			rest.Delete("retryAt")
			rest.Delete("endState")
			endState := current.Get("endState")
			if nullish(endState) {
				endState = "ended"
			}
			endedAt := current.Get("endedAt")
			if nullish(endedAt) {
				endedAt = now
			}
			rest.Set("state", endState)
			rest.Set("endedAt", endedAt)
			_, err := tx.Put(ctx, VaultCollections.Leases, rest)
			return err
		}
		attempts := 1.0
		if count := current.Get("revokeAttempts"); !nullish(count) {
			attempts = jsNumber(count) + 1
		}
		startedAt := current.Get("revokeStartedAt")
		if nullish(startedAt) {
			startedAt = now
		}
		_, err = tx.Put(ctx, VaultCollections.Leases, current.Spread(core.NewObject(
			"revokeAttempts", attempts,
			"revokeStartedAt", startedAt,
			"retryAt", now+math.Min(6*60*VaultTime.MINUTE, VaultTime.MINUTE*math.Pow(2, math.Min(attempts-1, 9))),
			"lastError", *failure,
		)))
		return err
	}); err != nil {
		return false, "", err
	}
	if failure != nil {
		return false, *failure, nil
	}
	return true, "", nil
}

// principalRecorder is who acted, as the vault's audit recorder for a principal.
func principalRecorder(server *ServerContext, principal *Principal, tenantID, name string) vaultRecorder {
	return func(ctx context.Context, tx core.IamStore, action, outcome string, metadata *core.Object) error {
		return server.Events.Audit(ctx, tx, principal, action, tenantID, vaultSecretResource(name), outcome, false, metadata)
	}
}

// operatorRecorder is the scheduler's audit recorder.
func operatorRecorder(server *ServerContext, tenantID, name string) vaultRecorder {
	return func(ctx context.Context, tx core.IamStore, action, outcome string, metadata *core.Object) error {
		return server.Events.RecordAudit(ctx, tx, core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"actorId", VaultOperator,
			"action", action,
			"resourceId", vaultSecretResource(name),
			"timestamp", float64(server.Now()),
			"outcome", outcome,
			"metadata", metadata,
		))
	}
}

// vaultOut wraps an answer.
func vaultOut[T any](value any, err error) (Out[T], error) {
	if err != nil {
		return Out[T]{}, err
	}
	return Answer[T](value), nil
}

// --- the API -------------------------------------------------------------------------------------

// VaultAPI is the `vault` API group (packages/server/src/api/vault.ts createVaultApi): every method runs through the
// operation envelope; the router maps POST {basePath}/vault/{method} onto it.
type VaultAPI struct {
	server *ServerContext
}

// CreateVaultAPI builds the `vault` API group.
func CreateVaultAPI(server *ServerContext) *VaultAPI {
	return &VaultAPI{server: server}
}

func (api *VaultAPI) views(ctx context.Context, tx core.IamStore, secret *core.Object) (*core.Object, error) {
	leases, err := LiveLeases(ctx, api.server, tx, secret)
	if err != nil {
		return nil, err
	}
	return secretView(secret, leases, float64(api.server.Now())), nil
}

// usableKey is a customer-managed key the caller may bind secrets to: an enabled encryption key of the tenant (id
// or `alias/{name}`) on which they hold `iam:kms:encrypt`, so vault rights cannot put values under a key they cannot
// use.
func (api *VaultAPI) usableKey(ctx context.Context, tx core.IamStore, principal *Principal, realm *core.Object, reference any) (string, error) {
	key, err := FindKey(ctx, tx, jsString(realm.Get("id")), reference)
	if err != nil {
		return "", err
	}
	if err := AssertUsable(key, "encrypt"); err != nil {
		return "", err
	}
	// The KMS service helpers envelope-encrypt with AES-256-GCM keys only; refuse others when binding, not later.
	if key.Get("keySpec") != "aes-256-gcm" {
		return "", invalidInput("Customer-managed keys for the vault are aes-256-gcm encryption keys")
	}
	if err := api.requireKeyAction(ctx, tx, principal, realm, jsString(key.Get("id")), "iam:kms:encrypt"); err != nil {
		return "", err
	}
	return jsString(key.Get("id")), nil
}

// requireSecretKey is the key-owner's say over a customer-managed secret, as with AWS KMS: values come out only for
// callers who may also decrypt with its key, and go in only for callers who may encrypt with it. Jobs and
// `iam.vault` are not asked.
func (api *VaultAPI) requireSecretKey(ctx context.Context, tx core.IamStore, principal *Principal, realm *core.Object, secret *core.Object, actions ...string) error {
	keyID := secret.Get("kmsKeyId")
	if isUndefined(keyID) {
		return nil
	}
	for _, action := range actions {
		if err := api.requireKeyAction(ctx, tx, principal, realm, jsString(keyID), action); err != nil {
			return err
		}
	}
	return nil
}

// requireKeyAction refuses with ACCESS_DENIED unless the caller (and, in "view as", the administrator behind the
// session) may perform `action` on the KMS key: binding a secret to a key, and taking a secret's values out from
// under one.
func (api *VaultAPI) requireKeyAction(ctx context.Context, tx core.IamStore, principal *Principal, realm *core.Object, keyID string, action string) error {
	server := api.server
	key, err := FindKey(ctx, tx, jsString(realm.Get("id")), keyID)
	if err != nil {
		return err
	}
	aliases, err := AliasNames(ctx, tx, key)
	if err != nil {
		return err
	}
	attributes, err := KeyAttributes(key, aliases, nil)
	if err != nil {
		return err
	}
	resource := ResolvedResource{
		TenantID:   jsString(realm.Get("id")),
		Type:       "iam",
		ID:         "kms/" + jsString(key.Get("id")),
		Attributes: attributes,
	}
	actor, err := ImpersonatingActor(ctx, tx, principal)
	if err != nil {
		return err
	}
	subjects := []*Principal{principal}
	if actor != nil {
		subjects = append(subjects, actor)
	}
	for _, subject := range subjects {
		prepared, err := server.Decisions.PrepareDecision(ctx, tx, subject, realm, action)
		if err != nil {
			return err
		}
		decision, err := DecideOn(prepared, resource, action)
		if err != nil {
			return err
		}
		if !decision.Allowed {
			if action == "iam:kms:encrypt" {
				return NewOperationDenied("This needs iam:kms:encrypt on the secret’s customer-managed key")
			}
			return NewOperationDenied("This needs iam:kms:decrypt on the secret’s customer-managed key")
		}
	}
	// A delegation that holds the key action back for the person's confirmation: this call uses the approval up.
	return UseConfirmation(ctx, tx, principal, action, "iam", resource.ID, server.Now())
}

// requireStill re-decides `action` on a secret as it is now inside the transaction (after its attributes changed, or
// a second action one call also needs), for the caller and any "view as" administrator. An allowed call uses up a
// delegation's confirmation of that action, as the operation's own action does.
func (api *VaultAPI) requireStill(ctx context.Context, tx core.IamStore, principal *Principal, realm *core.Object, name, action, message string) error {
	server := api.server
	actor, err := ImpersonatingActor(ctx, tx, principal)
	if err != nil {
		return err
	}
	subjects := []*Principal{principal}
	if actor != nil {
		subjects = append(subjects, actor)
	}
	for _, subject := range subjects {
		decision, err := server.Decisions.Decide(ctx, tx, subject, AuthorizationRequest{
			TenantID: jsString(realm.Get("id")), Action: action,
			Resource: ResourceTarget{Type: "iam", ID: vaultSecretResource(name)},
		}, true)
		if err != nil {
			return err
		}
		if !decision.Allowed {
			return NewOperationDenied(message)
		}
	}
	return UseConfirmation(ctx, tx, principal, action, "iam", vaultSecretResource(name), server.Now())
}

// reach is the vault actions the caller, and any "view as" administrator behind the session, may perform on a secret
// as it is stored now (one set per subject), to compare before and after a change of its attributes.
func (api *VaultAPI) reach(ctx context.Context, tx core.IamStore, principal *Principal, realm *core.Object, name string) ([]map[string]bool, error) {
	actor, err := ImpersonatingActor(ctx, tx, principal)
	if err != nil {
		return nil, err
	}
	subjects := []*Principal{principal}
	if actor != nil {
		subjects = append(subjects, actor)
	}
	result := []map[string]bool{}
	for _, subject := range subjects {
		allowed := map[string]bool{}
		for _, action := range secretActions {
			decision, err := api.server.Decisions.Decide(ctx, tx, subject, AuthorizationRequest{
				TenantID: jsString(realm.Get("id")), Action: action,
				Resource: ResourceTarget{Type: "iam", ID: vaultSecretResource(name)},
			}, true)
			if err != nil {
				return nil, err
			}
			if decision.Allowed {
				allowed[action] = true
			}
		}
		result = append(result, allowed)
	}
	return result, nil
}

// requireNoWider refuses a change of a secret's attributes (tags, settings, key) that opens an action on it to the
// caller that the secret as it was did not: managing a secret must not move it into what the caller may reveal, lease
// or rotate.
func (api *VaultAPI) requireNoWider(ctx context.Context, tx core.IamStore, principal *Principal, realm *core.Object, name string, before []map[string]bool) error {
	after, err := api.reach(ctx, tx, principal, realm, name)
	if err != nil {
		return err
	}
	for index, allowed := range after {
		for _, action := range secretActions {
			if !allowed[action] {
				continue
			}
			if index >= len(before) || !before[index][action] {
				return NewOperationDenied("The change would give you " + action + " on the secret, which you do not have on it now")
			}
		}
	}
	return nil
}

// valueOperation is an operation whose answer carries secret values: plugins' `afterOperation` hooks see the answer
// without them, as with the KMS's plaintexts. fn returns the answer and the values apart; the caller gets both.
func (api *VaultAPI) valueOperation(ctx context.Context, credential core.CredentialInput, tenantID any, action, resourceID string, fn func(ctx context.Context, call MutationContext) (*core.Object, *core.Object, error)) (*core.Object, error) {
	var values *core.Object
	answer, err := Operate(ctx, api.server.Operations, credential, tenantID, action, resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		answer, split, err := fn(ctx, call)
		if err != nil {
			return nil, err
		}
		values = split
		return answer, nil
	}, false)
	if err != nil {
		return nil, err
	}
	return answer.Spread(values), nil
}

// leaseCall is what onLease hands its function.
type leaseCall struct {
	Tx        core.IamStore
	Principal *Principal
	Lease     *core.Object
	// Secret is nil when the lease's secret is gone.
	Secret *core.Object
	Holder bool
}

// onLease is a call on a lease by its holder (no further permission: returning a check-out must always be possible)
// or, for anyone else, an `iam:vault:manage` operation on the secret.
func (api *VaultAPI) onLease(ctx context.Context, credential core.CredentialInput, body *core.Object, verb string, fn func(ctx context.Context, call leaseCall) (*core.Object, error)) (*core.Object, error) {
	server := api.server
	tenantID, err := Text(body.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	leaseID, err := Text(body.Get("leaseId"), "leaseId")
	if err != nil {
		return nil, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return nil, err
	}
	peek, err := server.Store.Get(ctx, VaultCollections.Leases, leaseID)
	if err != nil {
		return nil, err
	}
	if peek == nil || peek.Get("tenantId") != tenantID {
		return nil, core.NewIamError("NOT_FOUND", "Lease not found", 404)
	}
	load := func(ctx context.Context, tx core.IamStore) (*core.Object, *core.Object, error) {
		lease, err := tx.Get(ctx, VaultCollections.Leases, leaseID)
		if err != nil {
			return nil, nil, err
		}
		if lease == nil || lease.Get("tenantId") != tenantID {
			return nil, nil, core.NewIamError("NOT_FOUND", "Lease not found", 404)
		}
		secret, err := tx.Get(ctx, VaultCollections.Secrets, jsString(lease.Get("secretId")))
		if err != nil {
			return nil, nil, err
		}
		return lease, secret, nil
	}
	if core.StrictEquals(peek.Get("holderId"), authenticated.Identity.Get("id")) {
		return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
			principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
			if err != nil {
				return nil, err
			}
			if _, err := server.Tenant(ctx, tx, tenantID); err != nil {
				return nil, err
			}
			if truthy(principal.Session.Get("impersonatorId")) {
				return nil, core.NewIamError("ACCESS_DENIED", "Leases cannot be changed while viewing as another member", 403)
			}
			lease, secret, err := load(ctx, tx)
			if err != nil {
				return nil, err
			}
			// The session that took the lease may always return it. Another session of the holder (a delegated
			// session, an API key a session policy narrows) acts on it only while it could take the lease itself.
			if !core.StrictEquals(lease.Get("sessionId"), principal.Session.Get("id")) {
				realm, err := server.Tenant(ctx, tx, tenantID)
				if err != nil {
					return nil, err
				}
				if err := api.requireStill(ctx, tx, principal, realm, jsString(lease.Get("name")), "iam:vault:lease",
					"This session may not lease the secret; use the session that took the lease"); err != nil {
					return nil, err
				}
			}
			value, err := fn(ctx, leaseCall{Tx: tx, Principal: principal, Lease: lease, Secret: secret, Holder: true})
			if err != nil {
				return nil, err
			}
			if err := server.Events.Audit(ctx, tx, principal, "vault:"+verb, tenantID, vaultSecretResource(jsString(lease.Get("name"))), "allow", false,
				core.NewObject("leaseId", lease.Get("id"), "kind", lease.Get("kind"))); err != nil {
				return nil, err
			}
			return value, nil
		})
	}
	return Operate(ctx, server.Operations, credential, tenantID, "iam:vault:manage", vaultSecretResource(jsString(peek.Get("name"))),
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			lease, secret, err := load(ctx, call.Tx)
			if err != nil {
				return nil, err
			}
			value, err := fn(ctx, leaseCall{Tx: call.Tx, Principal: call.Principal, Lease: lease, Secret: secret, Holder: false})
			if err != nil {
				return nil, err
			}
			if err := server.Events.Audit(ctx, call.Tx, call.Principal, "vault:"+verb, tenantID, vaultSecretResource(jsString(lease.Get("name"))), "allow", false,
				core.NewObject("leaseId", lease.Get("id"), "kind", lease.Get("kind"), "holderId", lease.Get("holderId"))); err != nil {
				return nil, err
			}
			return value, nil
		}, false)
}

// rotateAfterCheckin is rotation after a check-out ends, when the secret asks for it; failures are recorded, never
// returned.
func (api *VaultAPI) rotateAfterCheckin(ctx context.Context, tenantID, secretID, actorID string, record func(name string) vaultRecorder) (*float64, error) {
	return rotateReturned(ctx, api.server, tenantID, secretID, actorID, record)
}

// Create is POST {basePath}/vault/create. Creates a secret. Static secrets may start with a value (`value`, or
// `fields` for `json` secrets), a generated one (`generate: true` or a generator), or none yet. Dynamic secrets name
// an `engine` from the `vault.engines` option and have no stored value: each `vault.lease` mints a credential.
// Requires iam:vault:manage on `iam/vault/secrets/{name}`; audited as `vault:create`.
func (api *VaultAPI) Create(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultCreateInput]) (Out[apitypes.VaultCreateOutput], error) {
	server := api.server
	name, err := SecretName(input.Get("name"))
	if err != nil {
		return Out[apitypes.VaultCreateOutput]{}, err
	}
	return vaultOut[apitypes.VaultCreateOutput](Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:vault:manage", vaultSecretResource(name),
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := vaultWritable(realm); err != nil {
				return nil, err
			}
			vault, err := vaultSettingsOf(server)
			if err != nil {
				return nil, err
			}
			kind := "static"
			if raw := input.Get("kind"); !nullish(raw) {
				kind = jsString(raw)
				if _, isString := raw.(string); !isString {
					kind = ""
				}
			}
			if kind == "dynamic" && !isUndefined(input.Get("kmsKey")) {
				return nil, invalidInput("Dynamic secrets store no values to encrypt")
			}
			if kind != "static" && kind != "dynamic" {
				return nil, invalidInput("kind must be static or dynamic")
			}
			format, err := SecretFormat(input.Get("format"))
			if err != nil {
				return nil, err
			}
			realmID := jsString(realm.Get("id"))
			existing, err := FindSecret(ctx, tx, realmID, name)
			if err != nil {
				return nil, err
			}
			if existing != nil {
				message := "A secret with this name already exists"
				if existing.Get("status") == "pending-deletion" {
					message = "A secret with this name is scheduled for deletion; restore it or wait until it is purged"
				}
				return nil, core.NewIamError("CONFLICT", message, 409)
			}
			all, err := tx.Find(ctx, VaultCollections.Secrets, core.NewObject("tenantId", realmID), nil)
			if err != nil {
				return nil, err
			}
			maxSecrets := jsNumber(vault.Get("maxSecretsPerTenant"))
			if float64(len(all)) >= maxSecrets {
				return nil, core.NewIamError("LIMIT_EXCEEDED", "A tenant can hold at most "+core.NumberString(maxSecrets)+" secrets", 409)
			}
			now := float64(server.Now())
			tags, err := SecretTags(input.Get("tags"))
			if err != nil {
				return nil, err
			}
			maxVersions, err := vaultMaxVersions(input.Get("maxVersions"))
			if err != nil {
				return nil, err
			}
			actorID := principal.Identity.Get("id")
			secret := core.NewObject(
				"id", ID(),
				"tenantId", realmID,
				"uniqueKey", name,
				"name", name,
				"kind", kind,
				"format", format,
				"tags", tags,
				"status", "active",
				"stages", core.NewObject(),
				"latestVersion", 0.0,
				"maxVersions", maxVersions,
				"createdAt", now,
				"createdBy", actorID,
				"updatedAt", now,
				"updatedBy", actorID,
			)
			if raw := input.Get("description"); !isUndefined(raw) {
				description, err := Text(raw, "description", 1024)
				if err != nil {
					return nil, err
				}
				secret.Set("description", core.JSTrim(description))
			}
			if kind == "dynamic" {
				engine, err := Text(input.Get("engine"), "engine", 64)
				if err != nil {
					return nil, err
				}
				if _, known := vaultEnginesOf(vault)[engine]; !known {
					return nil, invalidInput("Unknown engine " + engine)
				}
				for _, key := range []string{"value", "fields", "generate", "rotation", "checkout"} {
					if !isUndefined(input.Get(key)) {
						return nil, invalidInput("Dynamic secrets take no " + key)
					}
				}
				secret.Set("engine", engine)
				config, err := EngineConfig(input.Get("engineConfig"))
				if err != nil {
					return nil, err
				}
				secret.Set("engineConfig", config)
				lease, err := LeaseSettings(input.Get("lease"), nil)
				if err != nil {
					return nil, err
				}
				secret.Set("lease", lease)
			} else {
				if !isUndefined(input.Get("engine")) || !isUndefined(input.Get("engineConfig")) || truthy(input.Get("lease")) {
					return nil, invalidInput("engine settings are for dynamic secrets")
				}
				settings, err := RotationSettings(vault, format, input.Get("rotation"), nil)
				if err != nil {
					return nil, err
				}
				rotation, err := ScheduleRotation(settings, now, server.Now())
				if err != nil {
					return nil, err
				}
				if rotation != nil {
					secret.Set("rotation", rotation)
				}
				checkout, err := CheckoutPolicy(input.Get("checkout"), nil)
				if err != nil {
					return nil, err
				}
				if checkout != nil {
					secret.Set("checkout", checkout)
				}
				if raw := input.Get("kmsKey"); !isUndefined(raw) {
					keyID, err := api.usableKey(ctx, tx, principal, realm, raw)
					if err != nil {
						return nil, err
					}
					secret.Set("kmsKeyId", keyID)
				}
				if err := checkoutFits(secret); err != nil {
					return nil, err
				}
			}
			if _, err := tx.Insert(ctx, VaultCollections.Secrets, secret); err != nil {
				return nil, err
			}
			// Decided again with the new secret's attributes (tags, kind, engine, settings), which the first decision
			// could not see: a name nobody uses yet has none.
			if err := api.requireStill(ctx, tx, principal, realm, name, "iam:vault:manage", "You may not create a secret with these attributes"); err != nil {
				return nil, err
			}
			var initial any = core.Undefined
			generate := input.Get("generate")
			value, fields := input.Get("value"), input.Get("fields")
			if kind == "static" && (!isUndefined(value) || !isUndefined(fields) || truthy(generate)) {
				if truthy(generate) && (!isUndefined(value) || !isUndefined(fields)) {
					return nil, invalidInput("Pass a value or generate, not both")
				}
				var stored string
				if truthy(generate) {
					generator, err := PasswordGenerator(generate)
					if err != nil {
						return nil, err
					}
					generated, err := GenerateValue(generator)
					if err != nil {
						return nil, err
					}
					if format == "json" {
						field := member(secret.Get("rotation"), "field")
						if !truthy(field) {
							return nil, invalidInput("json secrets generate into rotation.field; set it or pass fields")
						}
						stored = core.MustStringify(core.NewObject(jsString(field), generated))
					} else {
						stored = generated
					}
				} else if stored, err = SecretValue(vault, format, input.Body); err != nil {
					return nil, err
				}
				source := "put"
				if truthy(generate) {
					source = "generated"
				}
				added, err := AddVersion(ctx, server, tx, secret, stored, source, jsString(actorID), principal)
				if err != nil {
					return nil, err
				}
				addedVersion := vaultObject(added.Get("version"))
				if secret, err = PromoteVersion(ctx, server, tx, vaultObject(added.Get("secret")), jsNumber(addedVersion.Get("version")), jsString(actorID), false); err != nil {
					return nil, err
				}
				initial = addedVersion.Get("version")
				if err := RecordAccess(ctx, server, tx, secret, vaultAccessEntry(principal, "action", "put", "version", initial)); err != nil {
					return nil, err
				}
			}
			metadata := core.NewObject("name", name, "kind", kind, "format", format, "tags", secret.Get("tags"))
			if !isUndefined(initial) {
				metadata.Set("version", initial)
			}
			for _, key := range []string{"engine", "kmsKeyId"} {
				if value := secret.Get(key); !isUndefined(value) {
					metadata.Set(key, value)
				}
			}
			if err := server.Events.Audit(ctx, tx, principal, "vault:create", realmID, vaultSecretResource(name), "allow", false, metadata); err != nil {
				return nil, err
			}
			return api.views(ctx, tx, secret)
		}, false))
}

// Update is POST {basePath}/vault/update. Changes a secret's settings: `description` (`null` clears), `tags`
// (replaced as a whole), `maxVersions`, `rotation` and `checkout` (`null` removes them), and a dynamic secret's
// `engineConfig` and `lease`; `kmsKey` moves the values under a customer-managed key (every kept version is
// re-encrypted), or back under the deployment secret with `null`. Values change through `put` and `rotate`.
// Requires iam:vault:manage; audited as `vault:update`.
func (api *VaultAPI) Update(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultUpdateInput]) (Out[apitypes.VaultUpdateOutput], error) {
	server := api.server
	name, err := SecretName(input.Get("name"))
	if err != nil {
		return Out[apitypes.VaultUpdateOutput]{}, err
	}
	return vaultOut[apitypes.VaultUpdateOutput](Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:vault:manage", vaultSecretResource(name),
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := vaultWritable(realm); err != nil {
				return nil, err
			}
			realmID := jsString(realm.Get("id"))
			secret, err := existingSecret(ctx, tx, realmID, name)
			if err != nil {
				return nil, err
			}
			if secret, err = activeSecret(secret); err != nil {
				return nil, err
			}
			before, err := api.reach(ctx, tx, principal, realm, name)
			if err != nil {
				return nil, err
			}
			vault, err := vaultSettingsOf(server)
			if err != nil {
				return nil, err
			}
			now := float64(server.Now())
			next := secret.Spread()
			next.Delete("description")
			next.Delete("rotation")
			next.Delete("checkout")
			next.Set("updatedAt", now)
			next.Set("updatedBy", principal.Identity.Get("id"))
			if raw := input.Get("description"); isUndefined(raw) {
				if description := secret.Get("description"); !isUndefined(description) {
					next.Set("description", description)
				}
			} else if raw != nil {
				description, err := Text(raw, "description", 1024)
				if err != nil {
					return nil, err
				}
				next.Set("description", core.JSTrim(description))
			}
			if raw := input.Get("tags"); !isUndefined(raw) {
				tags, err := SecretTags(raw)
				if err != nil {
					return nil, err
				}
				next.Set("tags", tags)
			}
			if raw := input.Get("maxVersions"); !isUndefined(raw) {
				maxVersions, err := vaultMaxVersions(raw)
				if err != nil {
					return nil, err
				}
				next.Set("maxVersions", maxVersions)
			}
			if secret.Get("kind") == "dynamic" {
				if !isUndefined(input.Get("rotation")) || !isUndefined(input.Get("checkout")) {
					return nil, invalidInput("Dynamic secrets are not rotated or checked out")
				}
				if raw := input.Get("engineConfig"); !isUndefined(raw) {
					config, err := EngineConfig(raw)
					if err != nil {
						return nil, err
					}
					next.Set("engineConfig", config)
				}
				if raw := input.Get("lease"); !isUndefined(raw) {
					lease, err := LeaseSettings(raw, nil)
					if err != nil {
						return nil, err
					}
					next.Set("lease", lease)
				}
			} else {
				if !isUndefined(input.Get("engineConfig")) || !isUndefined(input.Get("lease")) {
					return nil, invalidInput("engine settings are for dynamic secrets")
				}
				settings, err := RotationSettings(vault, jsString(secret.Get("format")), input.Get("rotation"), vaultObject(secret.Get("rotation")))
				if err != nil {
					return nil, err
				}
				rotation, err := ScheduleRotation(settings, jsNumber(secret.Get("createdAt")), server.Now())
				if err != nil {
					return nil, err
				}
				if rotation != nil {
					next.Set("rotation", rotation)
				}
				checkout, err := CheckoutPolicy(input.Get("checkout"), vaultObject(secret.Get("checkout")))
				if err != nil {
					return nil, err
				}
				if checkout != nil {
					next.Set("checkout", checkout)
				}
			}
			reencrypted := 0.0
			if raw := input.Get("kmsKey"); !isUndefined(raw) {
				if secret.Get("kind") == "dynamic" {
					return nil, invalidInput("Dynamic secrets store no values to encrypt")
				}
				target := next.Spread()
				target.Delete("kmsKeyId")
				if raw != nil {
					keyID, err := api.usableKey(ctx, tx, principal, realm, raw)
					if err != nil {
						return nil, err
					}
					target.Set("kmsKeyId", keyID)
				}
				if !core.StrictEquals(target.Get("kmsKeyId"), secret.Get("kmsKeyId")) {
					// Taking values out from under a customer-managed key is a decryption with it.
					if previous := secret.Get("kmsKeyId"); !isUndefined(previous) {
						if err := api.requireKeyAction(ctx, tx, principal, realm, jsString(previous), "iam:kms:decrypt"); err != nil {
							return nil, err
						}
					}
					versions, err := SecretVersions(ctx, tx, secret)
					if err != nil {
						return nil, err
					}
					for _, version := range versions {
						if isUndefined(version.Get("sealed")) {
							continue
						}
						value, err := OpenStored(ctx, server, tx, version, principal)
						if err != nil {
							return nil, err
						}
						encrypted, err := EncryptVersion(ctx, server, tx, target, version, value, principal)
						if err != nil {
							return nil, err
						}
						if _, err := tx.Put(ctx, VaultCollections.Versions, encrypted); err != nil {
							return nil, err
						}
						reencrypted++
					}
				}
				next.Assign(target)
				if isUndefined(target.Get("kmsKeyId")) {
					next.Delete("kmsKeyId")
				}
			}
			if err := checkoutFits(next); err != nil {
				return nil, err
			}
			stored, err := tx.Put(ctx, VaultCollections.Secrets, next)
			if err != nil {
				return nil, err
			}
			// New tags and settings are new attributes: the caller must still be allowed to manage the secret with
			// them, and may not gain any other action on it by the change.
			if err := api.requireStill(ctx, tx, principal, realm, name, "iam:vault:manage", "The change puts the secret outside what you may manage"); err != nil {
				return nil, err
			}
			if err := api.requireNoWider(ctx, tx, principal, realm, name, before); err != nil {
				return nil, err
			}
			if _, err := PruneVersions(ctx, tx, stored); err != nil {
				return nil, err
			}
			nullable := func(value any) any {
				if nullish(value) {
					return nil
				}
				return value
			}
			metadata := core.NewObject(
				"name", name,
				"tags", stored.Get("tags"),
				"maxVersions", stored.Get("maxVersions"),
				"rotation", nullable(member(stored.Get("rotation"), "intervalDays")),
				"rotator", nullable(member(stored.Get("rotation"), "rotator")),
				"checkout", truthy(stored.Get("checkout")),
				"kmsKeyId", nullable(stored.Get("kmsKeyId")),
			)
			if reencrypted != 0 {
				metadata.Set("reencrypted", reencrypted)
			}
			if err := server.Events.Audit(ctx, tx, principal, "vault:update", realmID, vaultSecretResource(name), "allow", false, metadata); err != nil {
				return nil, err
			}
			return api.views(ctx, tx, stored)
		}, false))
}

// Delete is POST {basePath}/vault/delete. Schedules a secret for deletion after a recovery window of `recoveryDays`
// (7-30, default 30), during which it can be restored but not read; `recoveryDays: 0` deletes it at once (versions,
// leases and access records; live dynamic leases are revoked at their engine first). Live check-outs end. Requires
// iam:vault:manage; audited as `vault:delete`.
func (api *VaultAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultDeleteInput]) (Out[apitypes.VaultDeleteOutput], error) {
	server := api.server
	name, err := SecretName(input.Get("name"))
	if err != nil {
		return Out[apitypes.VaultDeleteOutput]{}, err
	}
	days := 30.0
	if raw := input.Get("recoveryDays"); !isUndefined(raw) {
		if number, isNumber := raw.(float64); isNumber && number == 0 {
			days = 0
		} else if days, err = Integer(raw, "recoveryDays", 7, 30); err != nil {
			return Out[apitypes.VaultDeleteOutput]{}, err
		}
	}
	scheduled, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:vault:manage", vaultSecretResource(name),
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			// Deleting at once destroys every value for good: only from a recently signed-in session.
			if days == 0 {
				if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
					return nil, err
				}
			}
			realmID := jsString(realm.Get("id"))
			secret, err := existingSecret(ctx, tx, realmID, name)
			if err != nil {
				return nil, err
			}
			if secret.Get("status") == "pending-deletion" && days != 0 {
				return nil, core.NewIamError("SECRET_PENDING_DELETION", "This secret is already scheduled for deletion", 409)
			}
			now := float64(server.Now())
			deletionAt := now + days*VaultTime.DAY
			actorID := principal.Identity.Get("id")
			stored, err := tx.Put(ctx, VaultCollections.Secrets, secret.Spread(core.NewObject(
				"status", "pending-deletion",
				"deletionAt", deletionAt,
				"deletionRequestedBy", actorID,
				"updatedAt", now,
				"updatedBy", actorID,
			)))
			if err != nil {
				return nil, err
			}
			live, err := LiveLeases(ctx, server, tx, secret)
			if err != nil {
				return nil, err
			}
			for _, lease := range live {
				if lease.Get("kind") == "checkout" {
					if _, err := tx.Put(ctx, VaultCollections.Leases, lease.Spread(core.NewObject(
						"state", "ended", "endedAt", now, "endedBy", actorID,
					))); err != nil {
						return nil, err
					}
				}
			}
			if err := server.Events.Audit(ctx, tx, principal, "vault:delete", realmID, vaultSecretResource(name), "allow", false,
				core.NewObject("name", name, "recoveryDays", days, "deletionAt", deletionAt)); err != nil {
				return nil, err
			}
			return core.NewObject("secretId", stored.Get("id"), "tenantId", realmID, "deletionAt", deletionAt), nil
		}, false)
	if err != nil {
		return Out[apitypes.VaultDeleteOutput]{}, err
	}
	if days == 0 {
		if _, err := purgeSecret(ctx, server, jsString(scheduled.Get("secretId"))); err != nil {
			return Out[apitypes.VaultDeleteOutput]{}, err
		}
		return Answer[apitypes.VaultDeleteOutput](core.NewObject("name", name, "status", "deleted", "deletionAt", scheduled.Get("deletionAt"))), nil
	}
	return Answer[apitypes.VaultDeleteOutput](core.NewObject("name", name, "status", "pending-deletion", "deletionAt", scheduled.Get("deletionAt"))), nil
}

// Restore is POST {basePath}/vault/restore. Cancels a scheduled deletion. Requires iam:vault:manage; audited as
// `vault:restore`.
func (api *VaultAPI) Restore(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultRestoreInput]) (Out[apitypes.VaultRestoreOutput], error) {
	server := api.server
	name, err := SecretName(input.Get("name"))
	if err != nil {
		return Out[apitypes.VaultRestoreOutput]{}, err
	}
	return vaultOut[apitypes.VaultRestoreOutput](Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:vault:manage", vaultSecretResource(name),
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := vaultWritable(realm); err != nil {
				return nil, err
			}
			realmID := jsString(realm.Get("id"))
			secret, err := existingSecret(ctx, tx, realmID, name)
			if err != nil {
				return nil, err
			}
			if secret.Get("status") != "pending-deletion" {
				return nil, core.NewIamError("INVALID_TRANSITION", "This secret is not scheduled for deletion")
			}
			rest := secret.Spread()
			rest.Delete("deletionAt")
			rest.Delete("deletionRequestedBy")
			rest.Set("status", "active")
			rest.Set("updatedAt", float64(server.Now()))
			rest.Set("updatedBy", principal.Identity.Get("id"))
			stored, err := tx.Put(ctx, VaultCollections.Secrets, rest)
			if err != nil {
				return nil, err
			}
			if err := server.Events.Audit(ctx, tx, principal, "vault:restore", realmID, vaultSecretResource(name), "allow", false,
				core.NewObject("name", name)); err != nil {
				return nil, err
			}
			return api.views(ctx, tx, stored)
		}, false))
}

// Get is POST {basePath}/vault/get. A secret's metadata and live check-outs. Requires iam:vault:read.
func (api *VaultAPI) Get(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultGetInput]) (Out[apitypes.VaultGetOutput], error) {
	name, err := SecretName(input.Get("name"))
	if err != nil {
		return Out[apitypes.VaultGetOutput]{}, err
	}
	return vaultOut[apitypes.VaultGetOutput](Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:vault:read", vaultSecretResource(name),
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			secret, err := existingSecret(ctx, call.Tx, jsString(call.Tenant.Get("id")), name)
			if err != nil {
				return nil, err
			}
			return api.views(ctx, call.Tx, secret)
		}, false))
}

// List is POST {basePath}/vault/list. The secrets the caller may read (`iam:vault:read` on each), sorted by name:
// optionally under `prefix`, with all of `tags`, and by `status` (default `active`; `all` includes pending deletions).
// At most `limit` (1-500, default 100) from `offset`, with the `total` the caller may see. Needs only a session of
// the tenant; the listing itself is not audited.
func (api *VaultAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultListInput]) (Out[apitypes.VaultListOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.VaultListOutput], error) { return Out[apitypes.VaultListOutput]{}, err }
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return fail(err)
	}
	prefix, err := SecretPrefix(input.Get("prefix"))
	if err != nil {
		return fail(err)
	}
	tags := core.NewObject()
	if raw := input.Get("tags"); !isUndefined(raw) {
		if tags, err = SecretTags(raw); err != nil {
			return fail(err)
		}
	}
	var status any = "active"
	if raw := input.Get("status"); !nullish(raw) {
		status = raw
	}
	if status != "active" && status != "pending-deletion" && status != "all" {
		return fail(invalidInput("status must be active, pending-deletion or all"))
	}
	limit := 100.0
	if raw := input.Get("limit"); !isUndefined(raw) {
		if limit, err = Integer(raw, "limit", 1, 500); err != nil {
			return fail(err)
		}
	}
	offset := 0.0
	if raw := input.Get("offset"); !isUndefined(raw) {
		if offset, err = Integer(raw, "offset", 0, 1_000_000); err != nil {
			return fail(err)
		}
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return fail(err)
	}
	return vaultOut[apitypes.VaultListOutput](core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		realm, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		prepared, err := server.Decisions.PrepareDecision(ctx, tx, principal, realm, "iam:vault:read")
		if err != nil {
			return nil, err
		}
		actor, err := ImpersonatingActor(ctx, tx, principal)
		if err != nil {
			return nil, err
		}
		var own *PreparedDecision
		if actor != nil {
			if own, err = server.Decisions.PrepareDecision(ctx, tx, actor, realm, "iam:vault:read"); err != nil {
				return nil, err
			}
		}
		realmID := jsString(realm.Get("id"))
		allows := func(evaluator *PreparedDecision, secret *core.Object) (bool, error) {
			attributes, err := SecretAttributes(secret)
			if err != nil {
				return false, err
			}
			decision, err := DecideOn(evaluator, ResolvedResource{
				TenantID: realmID, Type: "iam", ID: vaultSecretResource(jsString(secret.Get("name"))), Attributes: attributes,
			}, "iam:vault:read")
			if err != nil {
				return false, err
			}
			return decision.Allowed, nil
		}
		secrets, err := tx.Find(ctx, VaultCollections.Secrets, core.NewObject("tenantId", realmID), nil)
		if err != nil {
			return nil, err
		}
		visible := []*core.Object{}
		for _, secret := range secrets {
			if status != "all" && secret.Get("status") != status {
				continue
			}
			secretName := jsString(secret.Get("name"))
			if len(secretName) < len(prefix) || secretName[:len(prefix)] != prefix {
				continue
			}
			secretTags := vaultObject(secret.Get("tags"))
			matches := true
			tags.Entries(func(key string, value any) bool {
				if secretTags == nil || !core.StrictEquals(secretTags.Get(key), value) {
					matches = false
					return false
				}
				return true
			})
			if !matches {
				continue
			}
			allowed, err := allows(prepared, secret)
			if err != nil {
				return nil, err
			}
			if allowed && own != nil {
				if allowed, err = allows(own, secret); err != nil {
					return nil, err
				}
			}
			if allowed {
				visible = append(visible, secret)
			}
		}
		sortStable(visible, func(a, b *core.Object) int {
			return compareUTF16(jsString(a.Get("name")), jsString(b.Get("name")))
		})
		page := []any{}
		start := int(math.Min(offset, float64(len(visible))))
		end := int(math.Min(offset+limit, float64(len(visible))))
		for _, secret := range visible[start:end] {
			view, err := api.views(ctx, tx, secret)
			if err != nil {
				return nil, err
			}
			page = append(page, view)
		}
		return core.NewObject("secrets", page, "total", float64(len(visible))), nil
	}))
}

// Reveal is POST {basePath}/vault/reveal. A secret's value: the `current` version, or `version` / `stage`. Refused
// while viewing as another member, for dynamic secrets (use `lease`), for disabled (VERSION_DISABLED) and destroyed
// (VERSION_DESTROYED) versions, and with CHECKOUT_REQUIRED when the secret is handed out only through check-outs (the
// holder of a live check-out may reveal the version they checked out). Requires iam:vault:reveal; audited as
// `vault:reveal`.
func (api *VaultAPI) Reveal(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultRevealInput]) (Out[apitypes.VaultRevealOutput], error) {
	server := api.server
	name, err := SecretName(input.Get("name"))
	if err != nil {
		return Out[apitypes.VaultRevealOutput]{}, err
	}
	return vaultOut[apitypes.VaultRevealOutput](api.valueOperation(ctx, credential, input.Get("tenantId"), "iam:vault:reveal", vaultSecretResource(name),
		func(ctx context.Context, call MutationContext) (*core.Object, *core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := refuseVaultImpersonation(principal); err != nil {
				return nil, nil, err
			}
			realmID := jsString(realm.Get("id"))
			secret, err := existingStatic(ctx, tx, realmID, name, true)
			if err != nil {
				return nil, nil, err
			}
			if err := api.requireSecretKey(ctx, tx, principal, realm, secret, "iam:kms:decrypt"); err != nil {
				return nil, nil, err
			}
			version, err := SelectVersion(ctx, tx, secret, input.Body)
			if err != nil {
				return nil, nil, err
			}
			if truthy(member(secret.Get("checkout"), "required")) {
				live, err := LiveLeases(ctx, server, tx, secret)
				if err != nil {
					return nil, nil, err
				}
				var held *core.Object
				for _, lease := range live {
					if lease.Get("kind") == "checkout" && core.StrictEquals(lease.Get("holderId"), principal.Identity.Get("id")) {
						held = lease
						break
					}
				}
				if held == nil {
					return nil, nil, core.NewIamError("CHECKOUT_REQUIRED", "This secret is handed out only through check-outs (vault.checkout)", 409)
				}
				if isUndefined(input.Get("version")) && isUndefined(input.Get("stage")) && !isUndefined(held.Get("version")) {
					heldVersion, err := VersionOf(ctx, tx, secret, jsNumber(held.Get("version")))
					if err != nil {
						return nil, nil, err
					}
					if heldVersion != nil {
						version = heldVersion
					}
				}
				if !core.StrictEquals(version.Get("version"), held.Get("version")) {
					return nil, nil, core.NewIamError("CHECKOUT_REQUIRED", "A check-out reveals only the version it handed out", 409)
				}
			}
			value, err := OpenVersion(ctx, server, tx, version, principal)
			if err != nil {
				return nil, nil, err
			}
			if err := RecordAccess(ctx, server, tx, secret, vaultAccessEntry(principal, "action", "reveal", "version", version.Get("version"))); err != nil {
				return nil, nil, err
			}
			if err := server.Events.Audit(ctx, tx, principal, "vault:reveal", realmID, vaultSecretResource(name), "allow", false,
				core.NewObject("name", name, "version", version.Get("version"))); err != nil {
				return nil, nil, err
			}
			shown, err := revealedSecret(secret, version, value)
			if err != nil {
				return nil, nil, err
			}
			answer, values := splitSecretValues(shown)
			return answer, values, nil
		}))
}

// Put is POST {basePath}/vault/put. Stores a new version (`value`, `fields` for json secrets, or `generate`). It
// becomes `current` (the old one `previous`) unless `stage` names another label: `pending` stages it for a later
// `promote` or `rotate`, any custom label just points at it. Versions past `maxVersions` that no stage names are
// deleted. Requires iam:vault:write; audited as `vault:put`.
func (api *VaultAPI) Put(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultPutInput]) (Out[apitypes.VaultPutOutput], error) {
	server := api.server
	name, err := SecretName(input.Get("name"))
	if err != nil {
		return Out[apitypes.VaultPutOutput]{}, err
	}
	stage := "current"
	if raw := input.Get("stage"); !isUndefined(raw) {
		if stage, err = StageName(raw); err != nil {
			return Out[apitypes.VaultPutOutput]{}, err
		}
	}
	if stage == "previous" {
		return Out[apitypes.VaultPutOutput]{}, invalidInput("previous moves by itself when a version becomes current")
	}
	return vaultOut[apitypes.VaultPutOutput](Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:vault:write", vaultSecretResource(name),
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := vaultWritable(realm); err != nil {
				return nil, err
			}
			realmID := jsString(realm.Get("id"))
			secret, err := existingStatic(ctx, tx, realmID, name, true)
			if err != nil {
				return nil, err
			}
			generate := input.Get("generate")
			// Generating into a json secret reads its current fields, which is a decryption as well.
			keyActions := []string{"iam:kms:encrypt"}
			if truthy(generate) && secret.Get("format") == "json" {
				keyActions = []string{"iam:kms:encrypt", "iam:kms:decrypt"}
			}
			if err := api.requireSecretKey(ctx, tx, principal, realm, secret, keyActions...); err != nil {
				return nil, err
			}
			var value string
			if truthy(generate) {
				if !isUndefined(input.Get("value")) || !isUndefined(input.Get("fields")) {
					return nil, invalidInput("Pass a value or generate, not both")
				}
				generator, err := PasswordGenerator(generate)
				if err != nil {
					return nil, err
				}
				generated, err := GenerateValue(generator)
				if err != nil {
					return nil, err
				}
				if secret.Get("format") == "json" {
					field := member(secret.Get("rotation"), "field")
					if !truthy(field) {
						return nil, invalidInput("json secrets generate into rotation.field")
					}
					var current *core.Object
					if label := vaultStages(secret).Get("current"); !isUndefined(label) {
						if current, err = VersionOf(ctx, tx, secret, jsNumber(label)); err != nil {
							return nil, err
						}
					}
					fields := core.NewObject()
					if current != nil && current.Get("state") == "enabled" {
						opened, err := OpenVersion(ctx, server, tx, current, principal)
						if err != nil {
							return nil, err
						}
						if fields, err = ParseFields(opened); err != nil {
							return nil, err
						}
					}
					fields.Set(jsString(field), generated)
					value = core.MustStringify(fields)
				} else {
					value = generated
				}
			} else {
				settings, err := vaultSettingsOf(server)
				if err != nil {
					return nil, err
				}
				if value, err = SecretValue(settings, jsString(secret.Get("format")), input.Body); err != nil {
					return nil, err
				}
			}
			source := "put"
			if truthy(generate) {
				source = "generated"
			}
			actorID := jsString(principal.Identity.Get("id"))
			added, err := AddVersion(ctx, server, tx, secret, value, source, actorID, principal)
			if err != nil {
				return nil, err
			}
			addedSecret, addedVersion := vaultObject(added.Get("secret")), vaultObject(added.Get("version"))
			if stage == "current" {
				if secret, err = PromoteVersion(ctx, server, tx, addedSecret, jsNumber(addedVersion.Get("version")), actorID, false); err != nil {
					return nil, err
				}
			} else {
				stages := vaultStages(addedSecret).Spread()
				stages.Set(stage, addedVersion.Get("version"))
				custom := 0
				for _, label := range stages.Keys() {
					if !SystemStages.Has(label) {
						custom++
					}
				}
				if custom > 8 {
					return nil, core.NewIamError("LIMIT_EXCEEDED", "A secret has at most 8 custom stage labels", 409)
				}
				if secret, err = tx.Put(ctx, VaultCollections.Secrets, addedSecret.Spread(core.NewObject(
					"stages", stages, "updatedAt", float64(server.Now()), "updatedBy", actorID,
				))); err != nil {
					return nil, err
				}
				if _, err := PruneVersions(ctx, tx, secret); err != nil {
					return nil, err
				}
			}
			if err := RecordAccess(ctx, server, tx, secret, vaultAccessEntry(principal, "action", "put", "version", addedVersion.Get("version"))); err != nil {
				return nil, err
			}
			if err := server.Events.Audit(ctx, tx, principal, "vault:put", realmID, vaultSecretResource(name), "allow", false,
				core.NewObject("name", name, "version", addedVersion.Get("version"), "stage", stage)); err != nil {
				return nil, err
			}
			return secretVersionView(secret, addedVersion), nil
		}, false))
}

// ListVersions is POST {basePath}/vault/listVersions. Every kept version, newest first, with its state and stage
// labels. Requires iam:vault:read.
func (api *VaultAPI) ListVersions(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultListVersionsInput]) (Out[apitypes.VaultListVersionsOutput], error) {
	name, err := SecretName(input.Get("name"))
	if err != nil {
		return Out[apitypes.VaultListVersionsOutput]{}, err
	}
	return vaultOut[apitypes.VaultListVersionsOutput](Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:vault:read", vaultSecretResource(name),
		func(ctx context.Context, call MutationContext) ([]any, error) {
			secret, err := existingSecret(ctx, call.Tx, jsString(call.Tenant.Get("id")), name)
			if err != nil {
				return nil, err
			}
			versions, err := SecretVersions(ctx, call.Tx, secret)
			if err != nil {
				return nil, err
			}
			views := make([]any, len(versions))
			for index, version := range versions {
				views[index] = secretVersionView(secret, version)
			}
			return views, nil
		}, false))
}

// Promote is POST {basePath}/vault/promote. Makes an enabled version `current` (the old one becomes `previous`);
// rolls back as well as forward. Requires iam:vault:write; audited as `vault:promote`.
func (api *VaultAPI) Promote(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultPromoteInput]) (Out[apitypes.VaultPromoteOutput], error) {
	server := api.server
	name, err := SecretName(input.Get("name"))
	if err != nil {
		return Out[apitypes.VaultPromoteOutput]{}, err
	}
	number, err := Integer(input.Get("version"), "version", 1, maxSafeInteger)
	if err != nil {
		return Out[apitypes.VaultPromoteOutput]{}, err
	}
	return vaultOut[apitypes.VaultPromoteOutput](Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:vault:write", vaultSecretResource(name),
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := vaultWritable(realm); err != nil {
				return nil, err
			}
			realmID := jsString(realm.Get("id"))
			secret, err := existingStatic(ctx, tx, realmID, name, true)
			if err != nil {
				return nil, err
			}
			version, err := VersionOf(ctx, tx, secret, number)
			if err != nil {
				return nil, err
			}
			if version == nil {
				return nil, core.NewIamError("NOT_FOUND", "Version not found", 404)
			}
			if version.Get("state") != "enabled" {
				return nil, core.NewIamError("VERSION_DISABLED", "Only enabled versions can become current", 409)
			}
			stored, err := PromoteVersion(ctx, server, tx, secret, number, jsString(principal.Identity.Get("id")), false)
			if err != nil {
				return nil, err
			}
			var previous any = vaultStages(secret).Get("current")
			if isUndefined(previous) {
				previous = nil
			}
			if err := server.Events.Audit(ctx, tx, principal, "vault:promote", realmID, vaultSecretResource(name), "allow", false,
				core.NewObject("name", name, "version", number, "previous", previous)); err != nil {
				return nil, err
			}
			return api.views(ctx, tx, stored)
		}, false))
}

// SetStage is POST {basePath}/vault/setStage. Points a custom stage label (or `pending`) at a version, or removes it
// with `version: null`. `current` and `previous` move only through `put`, `promote` and `rotate`. At most 8 custom
// labels. Requires iam:vault:write; audited as `vault:stage`.
func (api *VaultAPI) SetStage(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultSetStageInput]) (Out[apitypes.VaultSetStageOutput], error) {
	server := api.server
	name, err := SecretName(input.Get("name"))
	if err != nil {
		return Out[apitypes.VaultSetStageOutput]{}, err
	}
	stage, err := StageName(input.Get("stage"))
	if err != nil {
		return Out[apitypes.VaultSetStageOutput]{}, err
	}
	if stage == "current" || stage == "previous" {
		return Out[apitypes.VaultSetStageOutput]{}, invalidInput("Use promote to change the current version")
	}
	return vaultOut[apitypes.VaultSetStageOutput](Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:vault:write", vaultSecretResource(name),
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := vaultWritable(realm); err != nil {
				return nil, err
			}
			realmID := jsString(realm.Get("id"))
			secret, err := existingStatic(ctx, tx, realmID, name, true)
			if err != nil {
				return nil, err
			}
			stages := vaultStages(secret).Spread()
			raw := input.Get("version")
			if raw == nil {
				stages.Delete(stage)
			} else {
				number, err := Integer(raw, "version", 1, maxSafeInteger)
				if err != nil {
					return nil, err
				}
				version, err := VersionOf(ctx, tx, secret, number)
				if err != nil {
					return nil, err
				}
				if version == nil || version.Get("state") == "destroyed" {
					return nil, core.NewIamError("NOT_FOUND", "Version not found", 404)
				}
				stages.Set(stage, number)
				custom := 0
				for _, label := range stages.Keys() {
					if !SystemStages.Has(label) {
						custom++
					}
				}
				if custom > 8 {
					return nil, core.NewIamError("LIMIT_EXCEEDED", "A secret has at most 8 custom stage labels", 409)
				}
			}
			stored, err := tx.Put(ctx, VaultCollections.Secrets, secret.Spread(core.NewObject(
				"stages", stages, "updatedAt", float64(server.Now()), "updatedBy", principal.Identity.Get("id"),
			)))
			if err != nil {
				return nil, err
			}
			if _, err := PruneVersions(ctx, tx, stored); err != nil {
				return nil, err
			}
			var version any
			if raw != nil {
				version = stages.Get(stage)
			}
			if err := server.Events.Audit(ctx, tx, principal, "vault:stage", realmID, vaultSecretResource(name), "allow", false,
				core.NewObject("name", name, "stage", stage, "version", version)); err != nil {
				return nil, err
			}
			return api.views(ctx, tx, stored)
		}, false))
}

// SetVersionState is POST {basePath}/vault/setVersionState. Disables a version (`state: 'disabled'`: kept, but not
// revealed) or enables it again. The current version cannot be disabled. Requires iam:vault:manage; audited as
// `vault:version-state`.
func (api *VaultAPI) SetVersionState(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultSetVersionStateInput]) (Out[apitypes.VaultSetVersionStateOutput], error) {
	server := api.server
	name, err := SecretName(input.Get("name"))
	if err != nil {
		return Out[apitypes.VaultSetVersionStateOutput]{}, err
	}
	number, err := Integer(input.Get("version"), "version", 1, maxSafeInteger)
	if err != nil {
		return Out[apitypes.VaultSetVersionStateOutput]{}, err
	}
	state := input.Get("state")
	if state != "enabled" && state != "disabled" {
		return Out[apitypes.VaultSetVersionStateOutput]{}, invalidInput("state must be enabled or disabled")
	}
	return vaultOut[apitypes.VaultSetVersionStateOutput](Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:vault:manage", vaultSecretResource(name),
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := vaultWritable(realm); err != nil {
				return nil, err
			}
			realmID := jsString(realm.Get("id"))
			secret, err := existingStatic(ctx, tx, realmID, name, false)
			if err != nil {
				return nil, err
			}
			version, err := VersionOf(ctx, tx, secret, number)
			if err != nil {
				return nil, err
			}
			if version == nil {
				return nil, core.NewIamError("NOT_FOUND", "Version not found", 404)
			}
			if version.Get("state") == "destroyed" {
				return nil, core.NewIamError("VERSION_DESTROYED", "This version was destroyed", 410)
			}
			if state == "disabled" && core.StrictEquals(vaultStages(secret).Get("current"), number) {
				return nil, core.NewIamError("INVALID_TRANSITION", "The current version cannot be disabled; promote another version first")
			}
			rest := version.Spread()
			rest.Delete("disabledAt")
			rest.Set("state", state)
			if state == "disabled" {
				rest.Set("disabledAt", float64(server.Now()))
			}
			next, err := tx.Put(ctx, VaultCollections.Versions, rest)
			if err != nil {
				return nil, err
			}
			if err := server.Events.Audit(ctx, tx, principal, "vault:version-state", realmID, vaultSecretResource(name), "allow", false,
				core.NewObject("name", name, "version", number, "state", state)); err != nil {
				return nil, err
			}
			return secretVersionView(secret, next), nil
		}, false))
}

// DestroyVersion is POST {basePath}/vault/destroyVersion. Destroys a version's value for good (the record stays as
// history); stage labels on it are removed. The current version cannot be destroyed. Requires iam:vault:manage;
// audited as `vault:destroy-version`.
func (api *VaultAPI) DestroyVersion(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultDestroyVersionInput]) (Out[apitypes.VaultDestroyVersionOutput], error) {
	server := api.server
	name, err := SecretName(input.Get("name"))
	if err != nil {
		return Out[apitypes.VaultDestroyVersionOutput]{}, err
	}
	number, err := Integer(input.Get("version"), "version", 1, maxSafeInteger)
	if err != nil {
		return Out[apitypes.VaultDestroyVersionOutput]{}, err
	}
	return vaultOut[apitypes.VaultDestroyVersionOutput](Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:vault:manage", vaultSecretResource(name),
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
				return nil, err
			}
			realmID := jsString(realm.Get("id"))
			secret, err := existingStatic(ctx, tx, realmID, name, false)
			if err != nil {
				return nil, err
			}
			version, err := VersionOf(ctx, tx, secret, number)
			if err != nil {
				return nil, err
			}
			if version == nil {
				return nil, core.NewIamError("NOT_FOUND", "Version not found", 404)
			}
			if core.StrictEquals(vaultStages(secret).Get("current"), number) {
				return nil, core.NewIamError("INVALID_TRANSITION", "The current version cannot be destroyed; promote another version first")
			}
			now := float64(server.Now())
			rest := version.Spread()
			rest.Delete("sealed")
			rest.Set("state", "destroyed")
			rest.Set("destroyedAt", now)
			next, err := tx.Put(ctx, VaultCollections.Versions, rest)
			if err != nil {
				return nil, err
			}
			stages := core.NewObject()
			vaultStages(secret).Entries(func(label string, value any) bool {
				if !core.StrictEquals(value, number) {
					stages.Set(label, value)
				}
				return true
			})
			stored, err := tx.Put(ctx, VaultCollections.Secrets, secret.Spread(core.NewObject(
				"stages", stages, "updatedAt", float64(server.Now()), "updatedBy", principal.Identity.Get("id"),
			)))
			if err != nil {
				return nil, err
			}
			if err := server.Events.Audit(ctx, tx, principal, "vault:destroy-version", realmID, vaultSecretResource(name), "allow", false,
				core.NewObject("name", name, "version", number)); err != nil {
				return nil, err
			}
			return secretVersionView(stored, next), nil
		}, false))
}

// Rotate is POST {basePath}/vault/rotate. Rotates a static secret now: stages a new version as `pending` (generated,
// or `value` / `fields` when given), lets the secret's rotator apply it to the system it unlocks, then makes it
// current. A failing rotator leaves the pending version for the next attempt, records the error, and fails with
// ROTATION_FAILED (502). Requires iam:vault:rotate; audited as `vault:rotate` (outcome deny on failure).
func (api *VaultAPI) Rotate(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultRotateInput]) (Out[apitypes.VaultRotateOutput], error) {
	server := api.server
	name, err := SecretName(input.Get("name"))
	if err != nil {
		return Out[apitypes.VaultRotateOutput]{}, err
	}
	var principal *Principal
	var staged *stagedRotation
	if _, err := api.valueOperation(ctx, credential, input.Get("tenantId"), "iam:vault:rotate", vaultSecretResource(name),
		func(ctx context.Context, call MutationContext) (*core.Object, *core.Object, error) {
			tx, realm, caller := call.Tx, call.Tenant, call.Principal
			if err := vaultWritable(realm); err != nil {
				return nil, nil, err
			}
			principal = caller
			secret, err := existingSecret(ctx, tx, jsString(realm.Get("id")), name)
			if err != nil {
				return nil, nil, err
			}
			if hasExplicitValue(input.Body) {
				// A value the caller chooses is one they know, and the rotator makes it live: never for secrets that
				// leave only through check-outs, and otherwise only for callers who may write and reveal it anyway.
				if truthy(member(secret.Get("checkout"), "required")) {
					return nil, nil, invalidInput("Secrets handed out only through check-outs rotate to generated values")
				}
				if err := api.requireStill(ctx, tx, caller, realm, name, "iam:vault:write", "Rotating to a value you choose needs iam:vault:write on the secret"); err != nil {
					return nil, nil, err
				}
				if err := api.requireStill(ctx, tx, caller, realm, name, "iam:vault:reveal", "Rotating to a value you choose needs iam:vault:reveal on the secret"); err != nil {
					return nil, nil, err
				}
			}
			if err := api.requireSecretKey(ctx, tx, caller, realm, secret, "iam:kms:encrypt", "iam:kms:decrypt"); err != nil {
				return nil, nil, err
			}
			stagedNow, err := stageRotation(ctx, server, tx, secret, jsString(caller.Identity.Get("id")), input.Body, caller)
			if err != nil {
				return nil, nil, err
			}
			staged = stagedNow
			return stagedNow.answer(), stagedNow.values(), nil
		}); err != nil {
		return Out[apitypes.VaultRotateOutput]{}, err
	}
	outcome, err := completeRotation(ctx, server, staged, jsString(principal.Identity.Get("id")),
		principalRecorder(server, principal, staged.TenantID, name))
	if err != nil {
		return Out[apitypes.VaultRotateOutput]{}, err
	}
	if !outcome.ok {
		return Out[apitypes.VaultRotateOutput]{}, core.NewIamError("ROTATION_FAILED", outcome.message, 502)
	}
	return Answer[apitypes.VaultRotateOutput](outcome.result), nil
}

// Checkout is POST {basePath}/vault/checkout. Checks out a static secret: its current value with a lease of
// `durationMs` (default and at most the policy's `maxDurationMs`). An exclusive secret has one holder at a time
// (SECRET_CHECKED_OUT otherwise); `reason` is required when the policy says so. Refused while viewing as another
// member. Requires iam:vault:lease; audited as `vault:checkout`.
func (api *VaultAPI) Checkout(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultCheckoutInput]) (Out[apitypes.VaultCheckoutOutput], error) {
	server := api.server
	name, err := SecretName(input.Get("name"))
	if err != nil {
		return Out[apitypes.VaultCheckoutOutput]{}, err
	}
	return vaultOut[apitypes.VaultCheckoutOutput](api.valueOperation(ctx, credential, input.Get("tenantId"), "iam:vault:lease", vaultSecretResource(name),
		func(ctx context.Context, call MutationContext) (*core.Object, *core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := refuseVaultImpersonation(principal); err != nil {
				return nil, nil, err
			}
			realmID := jsString(realm.Get("id"))
			secret, err := existingStatic(ctx, tx, realmID, name, true)
			if err != nil {
				return nil, nil, err
			}
			if err := api.requireSecretKey(ctx, tx, principal, realm, secret, "iam:kms:decrypt"); err != nil {
				return nil, nil, err
			}
			// Without a policy there is nothing to check out: iam:vault:lease granted for dynamic secrets must not
			// hand out stored values that iam:vault:reveal guards.
			policy := secret.Get("checkout")
			if !truthy(policy) {
				return nil, nil, invalidInput("This secret has no check-out policy; reveal it with vault.reveal")
			}
			reason := ""
			if raw := input.Get("reason"); !isUndefined(raw) && raw != "" {
				text, err := Text(raw, "reason", 512)
				if err != nil {
					return nil, nil, err
				}
				reason = core.JSTrim(text)
			}
			if truthy(member(policy, "requireReason")) && reason == "" {
				return nil, nil, invalidInput("A check-out of this secret needs a reason")
			}
			maxDuration := jsNumber(member(policy, "maxDurationMs"))
			duration := maxDuration
			if raw := input.Get("durationMs"); !isUndefined(raw) {
				if duration, err = Integer(raw, "durationMs", VaultTime.MINUTE, maxDuration); err != nil {
					return nil, nil, err
				}
			}
			live, err := LiveLeases(ctx, server, tx, secret)
			if err != nil {
				return nil, nil, err
			}
			holders := []*core.Object{}
			for _, lease := range live {
				if lease.Get("kind") == "checkout" {
					holders = append(holders, lease)
				}
			}
			for _, lease := range holders {
				if core.StrictEquals(lease.Get("holderId"), principal.Identity.Get("id")) {
					return nil, nil, core.NewIamError("SECRET_CHECKED_OUT", "You already hold a check-out of this secret; check it in or renew it", 409)
				}
			}
			if truthy(member(policy, "exclusive")) && len(holders) > 0 {
				return nil, nil, core.NewIamError("SECRET_CHECKED_OUT", "Someone else has this secret checked out; try again when it is checked in", 409)
			}
			version, err := SelectVersion(ctx, tx, secret, core.NewObject())
			if err != nil {
				return nil, nil, err
			}
			value, err := OpenVersion(ctx, server, tx, version, principal)
			if err != nil {
				return nil, nil, err
			}
			now := float64(server.Now())
			lease := core.NewObject(
				"id", ID(),
				"tenantId", realmID,
				"secretId", secret.Get("id"),
				"name", name,
				"kind", "checkout",
				"holderId", principal.Identity.Get("id"),
				"sessionId", principal.Session.Get("id"),
			)
			vaultLeaseActor(lease, principal)
			lease.Set("version", version.Get("version"))
			if reason != "" {
				lease.Set("reason", reason)
			}
			lease.Set("state", "active")
			lease.Set("issuedAt", now)
			lease.Set("expiresAt", now+duration)
			lease.Set("maxExpiresAt", now+maxDuration)
			lease.Set("ttlMs", duration)
			if _, err := tx.Insert(ctx, VaultCollections.Leases, lease); err != nil {
				return nil, nil, err
			}
			if err := RecordAccess(ctx, server, tx, secret, vaultAccessEntry(principal,
				"action", "checkout", "version", version.Get("version"), "leaseId", lease.Get("id"))); err != nil {
				return nil, nil, err
			}
			metadata := core.NewObject("name", name, "version", version.Get("version"), "leaseId", lease.Get("id"), "expiresAt", lease.Get("expiresAt"))
			if reason != "" {
				metadata.Set("reason", reason)
			}
			if err := server.Events.Audit(ctx, tx, principal, "vault:checkout", realmID, vaultSecretResource(name), "allow", false, metadata); err != nil {
				return nil, nil, err
			}
			shown, err := revealedSecret(secret, version, value)
			if err != nil {
				return nil, nil, err
			}
			shown.Set("leaseId", lease.Get("id"))
			shown.Set("expiresAt", lease.Get("expiresAt"))
			shown.Set("maxExpiresAt", lease.Get("maxExpiresAt"))
			answer, values := splitSecretValues(shown)
			return answer, values, nil
		}))
}

// Checkin is POST {basePath}/vault/checkin. Returns a check-out (its holder needs no further permission; anyone else
// needs iam:vault:manage). A secret with `rotateOnCheckin` rotates once its last holder returns it; `rotated` says to
// which version. Audited as `vault:checkin`.
func (api *VaultAPI) Checkin(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultCheckinInput]) (Out[apitypes.VaultCheckinOutput], error) {
	server := api.server
	var actor *Principal
	ended, err := api.onLease(ctx, credential, input.Body, "checkin", func(ctx context.Context, call leaseCall) (*core.Object, error) {
		tx, principal, lease, secret := call.Tx, call.Principal, call.Lease, call.Secret
		if lease.Get("kind") != "checkout" {
			return nil, invalidInput("This is a dynamic lease; use revokeLease")
		}
		now := float64(server.Now())
		if lease.Get("state") != "active" || jsNumber(lease.Get("expiresAt")) <= now {
			return nil, core.NewIamError("INVALID_TRANSITION", "This check-out has already ended")
		}
		actor = principal
		if _, err := tx.Put(ctx, VaultCollections.Leases, lease.Spread(core.NewObject(
			"state", "ended", "endedAt", float64(server.Now()), "endedBy", principal.Identity.Get("id"),
		))); err != nil {
			return nil, err
		}
		if secret != nil {
			if err := RecordAccess(ctx, server, tx, secret, vaultAccessEntry(principal,
				"action", "checkin", "leaseId", lease.Get("id"), "version", lease.Get("version"))); err != nil {
				return nil, err
			}
		}
		return core.NewObject("tenantId", lease.Get("tenantId"), "secretId", lease.Get("secretId")), nil
	})
	if err != nil {
		return Out[apitypes.VaultCheckinOutput]{}, err
	}
	tenantID := jsString(ended.Get("tenantId"))
	rotated, err := api.rotateAfterCheckin(ctx, tenantID, jsString(ended.Get("secretId")), jsString(actor.Identity.Get("id")),
		func(name string) vaultRecorder { return principalRecorder(server, actor, tenantID, name) })
	if err != nil {
		return Out[apitypes.VaultCheckinOutput]{}, err
	}
	result := core.NewObject("leaseId", input.Get("leaseId"), "state", "ended")
	if rotated != nil {
		result.Set("rotated", *rotated)
	}
	return Answer[apitypes.VaultCheckinOutput](result), nil
}

// Lease is POST {basePath}/vault/lease. A dynamic secret's credential, minted by its engine for the caller with a
// lease of `ttlMs` (default and maximum from the secret's `lease` settings). The value is returned once and never
// stored; the lease is revoked at the engine by `revokeLease`, or by `iam.vault.expireLeases` once it expires. Engine
// failures fail with ENGINE_FAILED (502). Refused while viewing as another member. Requires iam:vault:lease; audited
// as `vault:lease`.
func (api *VaultAPI) Lease(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultLeaseInput]) (Out[apitypes.VaultLeaseOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.VaultLeaseOutput], error) { return Out[apitypes.VaultLeaseOutput]{}, err }
	name, err := SecretName(input.Get("name"))
	if err != nil {
		return fail(err)
	}
	var caller *Principal
	issuing, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:vault:lease", vaultSecretResource(name),
		func(ctx context.Context, call MutationContext) (*core.Object, error) {
			tx, realm, principal := call.Tx, call.Tenant, call.Principal
			if err := refuseVaultImpersonation(principal); err != nil {
				return nil, err
			}
			secret, err := existingSecret(ctx, tx, jsString(realm.Get("id")), name)
			if err != nil {
				return nil, err
			}
			if secret, err = activeSecret(secret); err != nil {
				return nil, err
			}
			if secret.Get("kind") != "dynamic" {
				return nil, invalidInput("Static secrets are revealed or checked out, not leased")
			}
			settings := vaultObject(secret.Get("lease"))
			if settings == nil {
				if settings, err = LeaseSettings(core.Undefined, nil); err != nil {
					return nil, err
				}
			}
			maxTtl := jsNumber(settings.Get("maxTtlMs"))
			ttl := jsNumber(settings.Get("defaultTtlMs"))
			if raw := input.Get("ttlMs"); !isUndefined(raw) {
				if ttl, err = Integer(raw, "ttlMs", VaultTime.MINUTE, maxTtl); err != nil {
					return nil, err
				}
			}
			now := float64(server.Now())
			record := core.NewObject(
				"id", ID(),
				"tenantId", realm.Get("id"),
				"secretId", secret.Get("id"),
				"name", name,
				"kind", "dynamic",
				"holderId", principal.Identity.Get("id"),
				"sessionId", principal.Session.Get("id"),
			)
			vaultLeaseActor(record, principal)
			record.Set("state", "issuing")
			record.Set("issuedAt", now)
			record.Set("expiresAt", now+ttl)
			record.Set("maxExpiresAt", now+maxTtl)
			record.Set("ttlMs", ttl)
			if _, err := tx.Insert(ctx, VaultCollections.Leases, record); err != nil {
				return nil, err
			}
			caller = principal
			kind := principal.Identity.Get("kind")
			if nullish(kind) {
				kind = "user"
			}
			holder := core.NewObject("id", principal.Identity.Get("id"), "kind", kind, "name", principal.Identity.Get("name"))
			if email := principal.Identity.Get("email"); truthy(email) {
				holder.Set("email", email)
			}
			return core.NewObject("lease", record, "secret", secret, "holder", holder, "ttl", ttl), nil
		}, false)
	if err != nil {
		return fail(err)
	}
	lease, secret, holder := vaultObject(issuing.Get("lease")), vaultObject(issuing.Get("secret")), vaultObject(issuing.Get("holder"))
	ttl := jsNumber(issuing.Get("ttl"))
	leaseID := jsString(lease.Get("id"))
	tenantID := jsString(lease.Get("tenantId"))
	format := jsString(secret.Get("format"))
	settings, err := vaultSettingsOf(server)
	if err != nil {
		return fail(err)
	}
	engineName := jsString(secret.Get("engine"))
	engine, hasEngine := vaultEnginesOf(settings)[engineName]
	var raw *EngineIssued
	var issuedText string
	var issuedHandle *string
	issued := false
	var failure *string
	if !hasEngine {
		message := "The engine " + engineName + " is not configured"
		failure = &message
	} else {
		value, err := WithTimeout(ctx, server, "The engine "+engineName, func(callCtx context.Context) (any, error) {
			engineHolder := EngineHolder{
				ID: jsString(holder.Get("id")), Kind: jsString(holder.Get("kind")), Name: jsString(holder.Get("name")),
			}
			if email, ok := holder.Get("email").(string); ok {
				engineHolder.Email = email
			}
			return engine.Issue(callCtx, EngineIssueInput{
				TenantID: tenantID, Name: name, LeaseID: leaseID, Config: engineConfigOf(secret), TtlMs: ttl, Holder: engineHolder,
			})
		})
		if minted, ok := value.(*EngineIssued); ok && err == nil {
			raw = minted
		}
		if err == nil {
			issuedText, issuedHandle, err = issuedValue(server, format, raw)
			issued = err == nil
		}
		if err != nil {
			values := []string{"", ""}
			if raw != nil && raw.Value != nil {
				values[0] = *raw.Value
			}
			if raw != nil && raw.Fields != nil {
				values[1] = core.MustStringify(raw.Fields)
			}
			message, redactErr := RedactedMessage(err, values)
			if redactErr != nil {
				return fail(redactErr)
			}
			failure = &message
		}
	}
	// Once `issue` was called, a credential may exist even when the call failed or timed out: such leases are revoked
	// at the engine by id (with the handle when one came back), and retried until the engine confirms.
	var handle *string
	if raw != nil && raw.Handle != nil && utf16Len(*raw.Handle) <= 4096 {
		handle = raw.Handle
	}
	record := principalRecorder(server, caller, tenantID, name)
	stored, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		current, err := tx.Get(ctx, VaultCollections.Leases, leaseID)
		if err != nil {
			return nil, err
		}
		if failure != nil || !issued || current == nil || current.Get("state") != "issuing" {
			if current != nil {
				next := current.Spread()
				if hasEngine {
					next.Set("state", "revoking")
				} else {
					next.Set("state", "failed")
				}
				next.Set("endedAt", float64(server.Now()))
				endedBy := current.Get("endedBy")
				if nullish(endedBy) {
					endedBy = VaultOperator
				}
				next.Set("endedBy", endedBy)
				if hasEngine {
					if failure != nil {
						next.Set("endState", "failed")
					} else {
						next.Set("endState", "ended")
					}
				}
				if handle != nil {
					sealed, err := sealLeaseHandle(server, jsString(current.Get("id")), *handle)
					if err != nil {
						return nil, err
					}
					next.Set("handleSealed", sealed)
				}
				lastError := "The lease was ended while it was issued"
				if failure != nil {
					lastError = *failure
				}
				next.Set("lastError", lastError)
				if _, err := tx.Put(ctx, VaultCollections.Leases, next); err != nil {
					return nil, err
				}
			}
			reason := "ended while issuing"
			if failure != nil {
				reason = *failure
			}
			if err := record(ctx, tx, "vault:lease", "deny", core.NewObject("name", name, "leaseId", leaseID, "error", reason)); err != nil {
				return nil, err
			}
			return nil, nil
		}
		next := current.Spread(core.NewObject("state", "active"))
		if issuedHandle != nil {
			sealed, err := sealLeaseHandle(server, jsString(current.Get("id")), *issuedHandle)
			if err != nil {
				return nil, err
			}
			next.Set("handleSealed", sealed)
		}
		if _, err := tx.Put(ctx, VaultCollections.Leases, next); err != nil {
			return nil, err
		}
		if err := RecordAccess(ctx, server, tx, secret, vaultAccessEntry(caller, "action", "lease", "leaseId", current.Get("id"))); err != nil {
			return nil, err
		}
		if err := record(ctx, tx, "vault:lease", "allow", core.NewObject(
			"name", name, "leaseId", current.Get("id"), "expiresAt", current.Get("expiresAt"),
		)); err != nil {
			return nil, err
		}
		return next, nil
	})
	if err != nil {
		return fail(err)
	}
	if stored == nil {
		// Take back whatever the engine may have minted now; a refusal is retried by iam.vault.expireLeases.
		if hasEngine {
			if _, _, err := revokeAndRecord(ctx, server, leaseID); err != nil {
				return fail(err)
			}
		}
		message := "The lease was ended while it was issued"
		if failure != nil {
			message = *failure
		}
		return fail(core.NewIamError("ENGINE_FAILED", message, 502))
	}
	result := core.NewObject("leaseId", stored.Get("id"), "name", name, "format", format, "value", issuedText)
	if format == "json" {
		fields, err := ParseFields(issuedText)
		if err != nil {
			return fail(err)
		}
		result.Set("fields", fields)
	}
	result.Set("issuedAt", stored.Get("issuedAt"))
	result.Set("expiresAt", stored.Get("expiresAt"))
	result.Set("maxExpiresAt", stored.Get("maxExpiresAt"))
	result.Set("renewable", jsNumber(stored.Get("expiresAt")) < jsNumber(stored.Get("maxExpiresAt")))
	return Answer[apitypes.VaultLeaseOutput](result), nil
}

// RenewLease is POST {basePath}/vault/renewLease. Extends a live check-out or dynamic lease by `ttlMs` from now
// (default: its original length), never past its `maxExpiresAt`; a dynamic lease's engine is told through `renew`
// when it has one. Holder only. Audited as `vault:renew`.
func (api *VaultAPI) RenewLease(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultRenewLeaseInput]) (Out[apitypes.VaultRenewLeaseOutput], error) {
	server := api.server
	var renewed, renewedSecret *core.Object
	var renewedTtl float64
	result, err := api.onLease(ctx, credential, input.Body, "renew", func(ctx context.Context, call leaseCall) (*core.Object, error) {
		tx, principal, lease, secret := call.Tx, call.Principal, call.Lease, call.Secret
		if !call.Holder {
			return nil, core.NewIamError("ACCESS_DENIED", "Only the holder renews a lease", 403)
		}
		now := float64(server.Now())
		if lease.Get("state") != "active" || jsNumber(lease.Get("expiresAt")) <= now {
			return nil, core.NewIamError("INVALID_TRANSITION", "This lease has already ended")
		}
		if secret == nil || secret.Get("status") != "active" {
			return nil, core.NewIamError("SECRET_PENDING_DELETION", "This secret is scheduled for deletion", 409)
		}
		// Extending access is using it again: the holder must still be allowed to lease the secret.
		realm, err := server.Tenant(ctx, tx, lease.Get("tenantId"))
		if err != nil {
			return nil, err
		}
		if err := api.requireStill(ctx, tx, principal, realm, jsString(lease.Get("name")), "iam:vault:lease", "Renewing needs iam:vault:lease on the secret"); err != nil {
			return nil, err
		}
		var length float64
		if raw := input.Get("ttlMs"); isUndefined(raw) {
			if ttl := lease.Get("ttlMs"); !nullish(ttl) {
				length = jsNumber(ttl)
			} else {
				length = jsNumber(lease.Get("expiresAt")) - jsNumber(lease.Get("issuedAt"))
			}
		} else if length, err = Integer(raw, "ttlMs", VaultTime.MINUTE, 30*VaultTime.DAY); err != nil {
			return nil, err
		}
		expiresAt := math.Min(now+length, jsNumber(lease.Get("maxExpiresAt")))
		if expiresAt <= jsNumber(lease.Get("expiresAt")) {
			return nil, core.NewIamError("LIMIT_EXCEEDED", "This lease has reached its longest allowed length", 409)
		}
		next, err := tx.Put(ctx, VaultCollections.Leases, lease.Spread(core.NewObject("expiresAt", expiresAt)))
		if err != nil {
			return nil, err
		}
		if err := RecordAccess(ctx, server, tx, secret, vaultAccessEntry(principal, "action", "renew", "leaseId", lease.Get("id"))); err != nil {
			return nil, err
		}
		renewed, renewedSecret, renewedTtl = next, secret, expiresAt-now
		return core.NewObject("leaseId", next.Get("id"), "expiresAt", next.Get("expiresAt"), "maxExpiresAt", next.Get("maxExpiresAt")), nil
	})
	if err != nil {
		return Out[apitypes.VaultRenewLeaseOutput]{}, err
	}
	var engine VaultEngine
	hasEngine := false
	if renewed != nil && renewedSecret != nil {
		if engineName, ok := renewedSecret.Get("engine").(string); ok && engineName != "" {
			settings, err := vaultSettingsOf(server)
			if err != nil {
				return Out[apitypes.VaultRenewLeaseOutput]{}, err
			}
			engine, hasEngine = vaultEnginesOf(settings)[engineName]
		}
	}
	if renewed != nil && renewed.Get("kind") == "dynamic" && hasEngine && engine.Renew != nil {
		handle, err := openLeaseHandle(server, renewed)
		if err != nil {
			return Out[apitypes.VaultRenewLeaseOutput]{}, err
		}
		ttl := renewedTtl
		if _, err := WithTimeout(ctx, server, "The engine "+jsString(renewedSecret.Get("engine")), func(callCtx context.Context) (any, error) {
			return nil, engine.Renew(callCtx, EngineLeaseInput{
				TenantID: jsString(renewed.Get("tenantId")),
				Name:     jsString(renewed.Get("name")),
				LeaseID:  jsString(renewed.Get("id")),
				Config:   engineConfigOf(renewedSecret),
				TtlMs:    &ttl,
				Handle:   handle,
			})
		}); err != nil {
			values := []string{}
			if handle != nil {
				values = append(values, *handle)
			}
			message, redactErr := RedactedMessage(err, values)
			if redactErr != nil {
				return Out[apitypes.VaultRenewLeaseOutput]{}, redactErr
			}
			return Out[apitypes.VaultRenewLeaseOutput]{}, core.NewIamError("ENGINE_FAILED", message, 502)
		}
	}
	return Answer[apitypes.VaultRenewLeaseOutput](result), nil
}

// RevokeLease is POST {basePath}/vault/revokeLease. Ends a lease now: a check-out ends like a check-in (a secret with
// `rotateOnCheckin` rotates once its last holder is gone, reported as `rotated`), a dynamic lease is revoked at its
// engine. Holder, or iam:vault:manage for anyone's. A revocation the engine refuses stays `revoking` and is retried by
// `iam.vault.expireLeases`. Audited as `vault:revoke`.
func (api *VaultAPI) RevokeLease(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultRevokeLeaseInput]) (Out[apitypes.VaultRevokeLeaseOutput], error) {
	server := api.server
	var actor *Principal
	outcome, err := api.onLease(ctx, credential, input.Body, "revoke", func(ctx context.Context, call leaseCall) (*core.Object, error) {
		tx, principal, lease, secret := call.Tx, call.Principal, call.Lease, call.Secret
		state := lease.Get("state")
		if state != "active" && state != "revoking" && state != "issuing" {
			return nil, core.NewIamError("INVALID_TRANSITION", "This lease has already ended")
		}
		actor = principal
		now := float64(server.Now())
		if secret != nil {
			if err := RecordAccess(ctx, server, tx, secret, vaultAccessEntry(principal, "action", "revoke", "leaseId", lease.Get("id"))); err != nil {
				return nil, err
			}
		}
		if lease.Get("kind") == "checkout" {
			if _, err := tx.Put(ctx, VaultCollections.Leases, lease.Spread(core.NewObject(
				"state", "ended", "endedAt", now, "endedBy", principal.Identity.Get("id"),
			))); err != nil {
				return nil, err
			}
			return core.NewObject("kind", "checkout", "lease", lease), nil
		}
		// A lease still being issued is marked here; the issue sees it and revokes what the engine minted.
		next := lease.Spread()
		if state == "issuing" {
			next.Set("state", "ended")
		} else {
			next.Set("state", "revoking")
		}
		endedAt := lease.Get("endedAt")
		if nullish(endedAt) {
			endedAt = now
		}
		next.Set("endedAt", endedAt)
		endedBy := lease.Get("endedBy")
		if nullish(endedBy) {
			endedBy = principal.Identity.Get("id")
		}
		next.Set("endedBy", endedBy)
		if state != "issuing" {
			endState := lease.Get("endState")
			if nullish(endState) {
				endState = "ended"
			}
			next.Set("endState", endState)
		}
		if _, err := tx.Put(ctx, VaultCollections.Leases, next); err != nil {
			return nil, err
		}
		kind := "dynamic"
		if state == "issuing" {
			kind = "issuing"
		}
		return core.NewObject("kind", kind, "lease", lease), nil
	})
	if err != nil {
		return Out[apitypes.VaultRevokeLeaseOutput]{}, err
	}
	lease := vaultObject(outcome.Get("lease"))
	leaseID := lease.Get("id")
	switch outcome.Get("kind") {
	case "checkout":
		// Ending someone's check-out is returning it: a secret that rotates on check-in rotates now too.
		tenantID := jsString(lease.Get("tenantId"))
		rotated, err := rotateReturned(ctx, server, tenantID, jsString(lease.Get("secretId")), jsString(actor.Identity.Get("id")),
			func(name string) vaultRecorder { return principalRecorder(server, actor, tenantID, name) })
		if err != nil {
			return Out[apitypes.VaultRevokeLeaseOutput]{}, err
		}
		result := core.NewObject("leaseId", leaseID, "state", "ended")
		if rotated != nil {
			result.Set("rotated", *rotated)
		}
		return Answer[apitypes.VaultRevokeLeaseOutput](result), nil
	case "issuing":
		return Answer[apitypes.VaultRevokeLeaseOutput](core.NewObject("leaseId", leaseID, "state", "ended")), nil
	}
	ok, message, err := revokeAndRecord(ctx, server, jsString(leaseID))
	if err != nil {
		return Out[apitypes.VaultRevokeLeaseOutput]{}, err
	}
	if ok {
		return Answer[apitypes.VaultRevokeLeaseOutput](core.NewObject("leaseId", leaseID, "state", "ended")), nil
	}
	return Answer[apitypes.VaultRevokeLeaseOutput](core.NewObject("leaseId", leaseID, "state", "revoking", "error", message)), nil
}

// holderNames looks up the names of the identities behind records' `key` member, once each.
func holderNames(ctx context.Context, tx core.IamStore, records []*core.Object, key string) (map[string]string, error) {
	names := map[string]string{}
	looked := map[string]bool{}
	for _, record := range records {
		identityID := jsString(record.Get(key))
		if looked[identityID] {
			continue
		}
		identity, err := tx.Get(ctx, "identities", identityID)
		if err != nil {
			return nil, err
		}
		if identity != nil {
			looked[identityID] = true
			names[identityID] = jsString(identity.Get("name"))
		}
	}
	return names, nil
}

// ListLeases is POST {basePath}/vault/listLeases. A secret's leases and check-outs, newest first: live ones, or all
// kept history with `includeEnded`. Requires iam:vault:read.
func (api *VaultAPI) ListLeases(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultListLeasesInput]) (Out[apitypes.VaultListLeasesOutput], error) {
	server := api.server
	name, err := SecretName(input.Get("name"))
	if err != nil {
		return Out[apitypes.VaultListLeasesOutput]{}, err
	}
	return vaultOut[apitypes.VaultListLeasesOutput](Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:vault:read", vaultSecretResource(name),
		func(ctx context.Context, call MutationContext) ([]any, error) {
			tx := call.Tx
			realmID := jsString(call.Tenant.Get("id"))
			secret, err := existingSecret(ctx, tx, realmID, name)
			if err != nil {
				return nil, err
			}
			now := float64(server.Now())
			found, err := tx.Find(ctx, VaultCollections.Leases, core.NewObject("tenantId", realmID, "secretId", secret.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			includeEnded := input.Get("includeEnded") == true
			leases := []*core.Object{}
			for _, lease := range found {
				state := lease.Get("state")
				if includeEnded || (state == "active" && jsNumber(lease.Get("expiresAt")) > now) || state == "revoking" {
					leases = append(leases, lease)
				}
			}
			vaultSorted(leases, "issuedAt", true)
			names, err := holderNames(ctx, tx, leases, "holderId")
			if err != nil {
				return nil, err
			}
			views := make([]any, len(leases))
			for index, lease := range leases {
				var holderName *string
				if name, ok := names[jsString(lease.Get("holderId"))]; ok {
					holderName = &name
				}
				views[index] = secretLeaseView(lease, holderName)
			}
			return views, nil
		}, false))
}

// ListMine is POST {basePath}/vault/listMine. The caller's own live check-outs and leases in the tenant. Needs only
// a session of the tenant.
func (api *VaultAPI) ListMine(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultListMineInput]) (Out[apitypes.VaultListMineOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.VaultListMineOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.VaultListMineOutput]{}, err
	}
	return vaultOut[apitypes.VaultListMineOutput](core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]any, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		if _, err := server.Tenant(ctx, tx, tenantID); err != nil {
			return nil, err
		}
		now := float64(server.Now())
		found, err := tx.Find(ctx, VaultCollections.Leases, core.NewObject("tenantId", tenantID, "holderId", principal.Identity.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		leases := []*core.Object{}
		for _, lease := range found {
			if lease.Get("state") == "active" && jsNumber(lease.Get("expiresAt")) > now {
				leases = append(leases, lease)
			}
		}
		vaultSorted(leases, "issuedAt", true)
		holderName := jsString(principal.Identity.Get("name"))
		views := make([]any, len(leases))
		for index, lease := range leases {
			views[index] = secretLeaseView(lease, &holderName)
		}
		return views, nil
	}))
}

// AccessLog is POST {basePath}/vault/accessLog. Who used a secret, newest first: reveals, check-outs and returns,
// leases, renewals, revocations, new versions and rotations, kept `vault.accessRetentionDays` (default 90). At most
// `limit` (1-500, default 100), optionally for one `identityId`. Requires iam:vault:read.
func (api *VaultAPI) AccessLog(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultAccessLogInput]) (Out[apitypes.VaultAccessLogOutput], error) {
	name, err := SecretName(input.Get("name"))
	if err != nil {
		return Out[apitypes.VaultAccessLogOutput]{}, err
	}
	limit := 100.0
	if raw := input.Get("limit"); !isUndefined(raw) {
		if limit, err = Integer(raw, "limit", 1, 500); err != nil {
			return Out[apitypes.VaultAccessLogOutput]{}, err
		}
	}
	return vaultOut[apitypes.VaultAccessLogOutput](Operate(ctx, api.server.Operations, credential, input.Get("tenantId"), "iam:vault:read", vaultSecretResource(name),
		func(ctx context.Context, call MutationContext) ([]any, error) {
			tx := call.Tx
			realmID := jsString(call.Tenant.Get("id"))
			secret, err := existingSecret(ctx, tx, realmID, name)
			if err != nil {
				return nil, err
			}
			filter := core.NewObject("tenantId", realmID, "secretId", secret.Get("id"))
			if raw := input.Get("identityId"); !isUndefined(raw) {
				identityID, err := Text(raw, "identityId")
				if err != nil {
					return nil, err
				}
				filter.Set("identityId", identityID)
			}
			count := int(limit)
			records, err := core.FindOrdered(ctx, tx, VaultCollections.Access, filter, core.OrderOptions{Field: "at", Direction: "desc", Limit: &count}, nil)
			if err != nil {
				return nil, err
			}
			names, err := holderNames(ctx, tx, records, "identityId")
			if err != nil {
				return nil, err
			}
			views := make([]any, len(records))
			for index, record := range records {
				view := core.NewObject("at", record.Get("at"), "identityId", record.Get("identityId"))
				if name, ok := names[jsString(record.Get("identityId"))]; ok {
					view.Set("identityName", name)
				}
				view.Set("action", record.Get("action"))
				for _, key := range []string{"version", "leaseId", "sessionKind", "agentId"} {
					if value := record.Get(key); !isUndefined(value) {
						view.Set(key, value)
					}
				}
				views[index] = view
			}
			return views, nil
		}, false))
}

// Generate is POST {basePath}/vault/generate. A value from a generator without storing it (a password for a form,
// say): `length` 8-256, `charset` (alphanumeric, ascii, hex, base64url, numeric), `exclude`, `eachClass`. Needs only
// a session.
func (api *VaultAPI) Generate(ctx context.Context, credential core.CredentialInput, input In[apitypes.VaultGenerateInput]) (Out[apitypes.VaultGenerateOutput], error) {
	if _, err := api.server.Principals.Authenticate(ctx, credential); err != nil {
		return Out[apitypes.VaultGenerateOutput]{}, err
	}
	generator, err := PasswordGenerator(input.Get("generator"))
	if err != nil {
		return Out[apitypes.VaultGenerateOutput]{}, err
	}
	value, err := GenerateValue(generator)
	if err != nil {
		return Out[apitypes.VaultGenerateOutput]{}, err
	}
	return Answer[apitypes.VaultGenerateOutput](core.NewObject("value", value)), nil
}

// --- maintenance ---------------------------------------------------------------------------------

// vaultScan is up to `limit` records of a collection that match `filter` and `keep`, read in keyset pages (id order),
// so a crowd of records that do not qualify can never hide the ones that do from a job.
func vaultScan(ctx context.Context, store core.IamStore, collection string, filter *core.Object, keep func(record *core.Object) (bool, error), limit int) ([]*core.Object, error) {
	found := []*core.Object{}
	var after *string
	for {
		pageSize := vaultScanPage
		options := &core.FindOptions{Limit: &pageSize}
		if after != nil {
			options.After = after
		}
		page, err := store.Find(ctx, collection, filter, options)
		if err != nil {
			return nil, err
		}
		for _, record := range page {
			kept, err := keep(record)
			if err != nil {
				return nil, err
			}
			if kept {
				found = append(found, record)
				if len(found) >= limit {
					return found, nil
				}
			}
		}
		if len(page) < vaultScanPage {
			return found, nil
		}
		last := jsString(page[len(page)-1].Get("id"))
		after = &last
	}
}

// purgeSecret deletes a secret with its versions, leases and access records, once every live dynamic lease has been
// revoked at its engine: a revocation that fails keeps the secret (still pending deletion) for the next run, so no
// credential outlives the records that could take it back. Audited as `vault:purge`.
func purgeSecret(ctx context.Context, server *ServerContext, secretID string) (bool, error) {
	live, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]string, error) {
		secret, err := tx.Get(ctx, VaultCollections.Secrets, secretID)
		if err != nil {
			return nil, err
		}
		if secret == nil || secret.Get("status") != "pending-deletion" {
			return nil, nil
		}
		found, err := tx.Find(ctx, VaultCollections.Leases, core.NewObject("tenantId", secret.Get("tenantId"), "secretId", secret.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		ids := []string{}
		for _, lease := range found {
			state := lease.Get("state")
			if lease.Get("kind") != "dynamic" || (state != "active" && state != "revoking" && state != "issuing") {
				continue
			}
			if state != "revoking" {
				endedAt := lease.Get("endedAt")
				if nullish(endedAt) {
					endedAt = float64(server.Now())
				}
				endedBy := lease.Get("endedBy")
				if nullish(endedBy) {
					endedBy = VaultOperator
				}
				if _, err := tx.Put(ctx, VaultCollections.Leases, lease.Spread(core.NewObject(
					"state", "revoking", "endedAt", endedAt, "endedBy", endedBy, "endState", "ended",
				))); err != nil {
					return nil, err
				}
			}
			ids = append(ids, jsString(lease.Get("id")))
		}
		return ids, nil
	})
	if err != nil {
		return false, err
	}
	if live == nil {
		return false, nil
	}
	revoked := true
	for _, leaseID := range live {
		ok, _, err := revokeAndRecord(ctx, server, leaseID)
		if err != nil {
			return false, err
		}
		if !ok {
			revoked = false
		}
	}
	if !revoked {
		return false, nil
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (bool, error) {
		secret, err := tx.Get(ctx, VaultCollections.Secrets, secretID)
		if err != nil {
			return false, err
		}
		if secret == nil || secret.Get("status") != "pending-deletion" {
			return false, nil
		}
		scope := core.NewObject("tenantId", secret.Get("tenantId"), "secretId", secret.Get("id"))
		versions := 0.0
		for _, collection := range []string{VaultCollections.Versions, VaultCollections.Leases, VaultCollections.Access} {
			records, err := tx.Find(ctx, collection, scope, nil)
			if err != nil {
				return false, err
			}
			for _, record := range records {
				if err := tx.Delete(ctx, collection, jsString(record.Get("id"))); err != nil {
					return false, err
				}
				if collection == VaultCollections.Versions {
					versions++
				}
			}
		}
		if err := tx.Delete(ctx, VaultCollections.Secrets, jsString(secret.Get("id"))); err != nil {
			return false, err
		}
		if err := operatorRecorder(server, jsString(secret.Get("tenantId")), jsString(secret.Get("name")))(ctx, tx, "vault:purge", "allow",
			core.NewObject("name", secret.Get("name"), "versions", versions)); err != nil {
			return false, err
		}
		return true, nil
	})
}

// IamVault is api/vault.ts IamVault: trusted, credential-free access for the deployment's own code (`iam.vault`),
// and the vault's scheduler jobs.
type IamVault struct {
	server *ServerContext
}

// boundedLimit is a job's `limit` option: 1-100000, fallback when absent.
func (s *IamVault) boundedLimit(options *core.Object, fallback float64) (int, error) {
	var value any = core.Undefined
	if options != nil {
		value = options.Get("limit")
	}
	if isUndefined(value) {
		return int(fallback), nil
	}
	limit, err := Integer(value, "limit", 1, 100_000)
	return int(limit), err
}

// read is the trusted read behind get and resolve.
func (s *IamVault) read(ctx context.Context, tenantID any, name any, options *core.Object) (*core.Object, error) {
	server := s.server
	if options == nil {
		options = core.NewObject()
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		id, err := Text(tenantID, "tenantId")
		if err != nil {
			return nil, err
		}
		realm, err := server.Tenant(ctx, tx, id)
		if err != nil {
			return nil, err
		}
		secretName, err := SecretName(name)
		if err != nil {
			return nil, err
		}
		secret, err := FindSecret(ctx, tx, jsString(realm.Get("id")), secretName)
		if err != nil {
			return nil, err
		}
		if secret == nil || secret.Get("status") != "active" {
			return nil, core.NewIamError("NOT_FOUND", "Secret not found", 404)
		}
		if _, err := staticSecret(secret); err != nil {
			return nil, err
		}
		version, err := SelectVersion(ctx, tx, secret, options)
		if err != nil {
			return nil, err
		}
		value, err := OpenVersion(ctx, server, tx, version, nil)
		if err != nil {
			return nil, err
		}
		return revealedSecret(secret, version, value)
	})
}

// Get (api/vault.ts IamVault.get): A static secret's value for server code: the `current` version, or `version` /
// `stage`. No credential and no audit event (the access log records nothing either); check-out rules do not apply.
// NOT_FOUND for secrets pending deletion.
func (s *IamVault) Get(ctx context.Context, tenantID string, name string, options *core.Object) (result *core.Object, err error) {
	return s.read(ctx, tenantID, name, options)
}

// Resolve (api/vault.ts IamVault.resolve): Replaces every string of the form `vault://{name}` (the value) or
// `vault://{name}#{field}` (one field of a json secret) inside a JSON value, for configuration objects. Each secret
// is read once per call.
func (s *IamVault) Resolve(ctx context.Context, tenantID string, value any) (result any, err error) {
	type cached struct {
		secret *core.Object
		err    error
	}
	cache := map[string]cached{}
	var walk func(item any) (any, error)
	walk = func(item any) (any, error) {
		switch typed := item.(type) {
		case string:
			match := vaultReference.FindStringSubmatchIndex(typed)
			if match == nil {
				return typed, nil
			}
			name := typed[match[2]:match[3]]
			entry, seen := cache[name]
			if !seen {
				secret, err := s.read(ctx, tenantID, name, nil)
				entry = cached{secret: secret, err: err}
				cache[name] = entry
			}
			if entry.err != nil {
				return nil, entry.err
			}
			if match[4] < 0 {
				return entry.secret.Get("value"), nil
			}
			fieldName := typed[match[4]:match[5]]
			field, err := OwnField(vaultObject(entry.secret.Get("fields")), fieldName)
			if err != nil {
				return nil, err
			}
			if isUndefined(field) {
				return nil, core.NewIamError("NOT_FOUND", "The secret "+name+" has no field "+fieldName, 404)
			}
			return field, nil
		case []any:
			out := make([]any, len(typed))
			for index, entry := range typed {
				walked, err := walk(entry)
				if err != nil {
					return nil, err
				}
				out[index] = walked
			}
			return out, nil
		case *core.Object:
			if typed == nil {
				return typed, nil
			}
			out := core.NewObject()
			var failure error
			typed.Entries(func(key string, entry any) bool {
				walked, err := walk(entry)
				if err != nil {
					failure = err
					return false
				}
				out.Set(key, walked)
				return true
			})
			if failure != nil {
				return nil, failure
			}
			return out, nil
		}
		return item, nil
	}
	return walk(core.Normalize(value))
}

// RotateDue (api/vault.ts IamVault.rotateDue): Rotates every static secret whose scheduled rotation (or a retry of a
// failed one) is due (hourly job): generated values and rotators run as `deployment-operator`; secrets with neither
// are recorded once per due date as `vault:rotation-due`.
func (s *IamVault) RotateDue(ctx context.Context, options *core.Object) (result *core.Object, err error) {
	server := s.server
	limit, err := s.boundedLimit(options, 1000)
	if err != nil {
		return nil, err
	}
	now := float64(server.Now())
	rotated, failed, reminded := []any{}, []any{}, []any{}
	filter := core.NewObject()
	if options != nil {
		if raw := options.Get("tenantId"); !isUndefined(raw) {
			tenantID, err := Text(raw, "tenantId")
			if err != nil {
				return nil, err
			}
			filter.Set("tenantId", tenantID)
		}
	}
	secrets, err := server.Store.Find(ctx, VaultCollections.Secrets, filter, nil)
	if err != nil {
		return nil, err
	}
	due := []*core.Object{}
	for _, secret := range secrets {
		next := member(secret.Get("rotation"), "nextRotationAt")
		if secret.Get("status") == "active" && secret.Get("kind") == "static" && !isUndefined(next) && jsNumber(next) <= now {
			due = append(due, secret)
		}
	}
	sortStable(due, func(a, b *core.Object) int {
		difference := jsNumber(member(a.Get("rotation"), "nextRotationAt")) - jsNumber(member(b.Get("rotation"), "nextRotationAt"))
		switch {
		case difference < 0:
			return -1
		case difference > 0:
			return 1
		}
		return 0
	})
	if len(due) > limit {
		due = due[:limit]
	}
	for _, candidate := range due {
		tenantID, name := jsString(candidate.Get("tenantId")), jsString(candidate.Get("name"))
		rotation := candidate.Get("rotation")
		// Rotations the vault can run itself: a generator, a rotator, or a check-out return that failed to rotate.
		automatic := truthy(member(rotation, "generator")) || truthy(member(rotation, "rotator")) ||
			truthy(member(candidate.Get("checkout"), "rotateOnCheckin"))
		if !automatic {
			remindedNow, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (bool, error) {
				secret, err := tx.Get(ctx, VaultCollections.Secrets, jsString(candidate.Get("id")))
				if err != nil {
					return false, err
				}
				if secret == nil {
					return false, nil
				}
				rotation := vaultObject(secret.Get("rotation"))
				dueAt := member(rotation, "nextRotationAt")
				if !truthy(dueAt) || jsNumber(dueAt) > now {
					return false, nil
				}
				notified := 0.0
				if value := member(rotation, "dueNotifiedAt"); !nullish(value) {
					notified = jsNumber(value)
				}
				if notified >= jsNumber(dueAt) {
					return false, nil
				}
				if _, err := tx.Put(ctx, VaultCollections.Secrets, secret.Spread(core.NewObject(
					"rotation", rotation.Spread(core.NewObject("dueNotifiedAt", now)),
				))); err != nil {
					return false, err
				}
				if err := operatorRecorder(server, jsString(secret.Get("tenantId")), jsString(secret.Get("name")))(ctx, tx, "vault:rotation-due", "allow",
					core.NewObject("name", secret.Get("name"), "dueAt", dueAt)); err != nil {
					return false, err
				}
				return true, nil
			})
			if err != nil {
				return nil, err
			}
			if remindedNow {
				reminded = append(reminded, core.NewObject("tenantId", tenantID, "name", name))
			}
			continue
		}
		failure := func(cause error) {
			// Refused before the rotator ran (a json secret without rotation.field, say): recorded and retried later.
			message, err := RedactedMessage(cause, nil)
			if err != nil {
				message = errorMessage(err)
			}
			_ = server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
				secret, err := tx.Get(ctx, VaultCollections.Secrets, jsString(candidate.Get("id")))
				if err != nil {
					return err
				}
				if secret == nil || secret.Get("status") != "active" {
					return nil
				}
				if err := recordRotationFailure(ctx, server, tx, secret, message); err != nil {
					return err
				}
				return operatorRecorder(server, jsString(secret.Get("tenantId")), jsString(secret.Get("name")))(ctx, tx, "vault:rotate", "deny",
					core.NewObject("name", secret.Get("name"), "error", message))
			})
			failed = append(failed, core.NewObject("tenantId", tenantID, "name", name, "message", message))
		}
		staged, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*stagedRotation, error) {
			secret, err := tx.Get(ctx, VaultCollections.Secrets, jsString(candidate.Get("id")))
			if err != nil {
				return nil, err
			}
			if secret == nil || secret.Get("status") != "active" {
				return nil, nil
			}
			next := member(secret.Get("rotation"), "nextRotationAt")
			if isUndefined(next) || jsNumber(next) > now {
				return nil, nil
			}
			// A shared credential that is checked out rotates when it comes back, not under its holder.
			if truthy(member(secret.Get("checkout"), "rotateOnCheckin")) {
				live, err := LiveLeases(ctx, server, tx, secret)
				if err != nil {
					return nil, err
				}
				for _, lease := range live {
					if lease.Get("kind") == "checkout" {
						return nil, nil
					}
				}
			}
			return stageRotation(ctx, server, tx, secret, VaultOperator, core.NewObject(), nil)
		})
		if err != nil {
			failure(err)
			continue
		}
		if staged == nil {
			continue
		}
		outcome, err := completeRotation(ctx, server, staged, VaultOperator, operatorRecorder(server, staged.TenantID, staged.Name))
		if err != nil {
			failure(err)
			continue
		}
		if outcome.ok {
			rotated = append(rotated, core.NewObject("tenantId", staged.TenantID, "name", staged.Name, "version", outcome.result.Get("version")))
		} else {
			failed = append(failed, core.NewObject("tenantId", staged.TenantID, "name", staged.Name, "message", outcome.message))
		}
	}
	return core.NewObject("rotated", rotated, "failed", failed, "reminded", reminded), nil
}

// ExpireLeases (api/vault.ts IamVault.expireLeases): Ends expired check-outs (rotating `rotateOnCheckin` secrets),
// revokes expired dynamic leases and those of people who are no longer active at their engine, retries failed
// revocations with backoff for seven days, and deletes lease history past `accessRetentionDays` (every few minutes).
func (s *IamVault) ExpireLeases(ctx context.Context, options *core.Object) (result *core.Object, err error) {
	server := s.server
	limit, err := s.boundedLimit(options, 1000)
	if err != nil {
		return nil, err
	}
	nowMs := server.Now()
	now := float64(nowMs)
	var expired, retrying, abandoned, pruned, rotatedCount float64
	to := now
	candidates, err := core.FindOrdered(ctx, server.Store, VaultCollections.Leases, core.NewObject("state", "active"),
		core.OrderOptions{Field: "expiresAt", To: &to, Limit: &limit}, nil)
	if err != nil {
		return nil, err
	}
	revoking, err := vaultScan(ctx, server.Store, VaultCollections.Leases, core.NewObject("state", "revoking"), func(lease *core.Object) (bool, error) {
		retryAt := 0.0
		if value := lease.Get("retryAt"); !nullish(value) {
			retryAt = jsNumber(value)
		}
		return retryAt <= now, nil
	}, limit)
	if err != nil {
		return nil, err
	}
	candidates = append(candidates, revoking...)
	issuing, err := vaultScan(ctx, server.Store, VaultCollections.Leases, core.NewObject("state", "issuing"), func(lease *core.Object) (bool, error) {
		return jsNumber(lease.Get("issuedAt")) <= now-10*VaultTime.MINUTE, nil
	}, limit)
	if err != nil {
		return nil, err
	}
	candidates = append(candidates, issuing...)
	// Live leases whose holder may no longer have them end too: a person or agent who is no longer active, an agent
	// whose sponsor left, and a lease an agent took for a person under a delegation that has ended. Every active lease
	// is looked at, however many there are; at most `limit` of them end per run.
	type verdict struct {
		ok  bool
		err error
	}
	verdicts := map[string]verdict{}
	cachedVerdict := func(key string, check func() (bool, error)) (bool, error) {
		if known, ok := verdicts[key]; ok {
			return known.ok, known.err
		}
		ok, err := check()
		verdicts[key] = verdict{ok, err}
		return ok, err
	}
	mayAct := func(identityID string) (bool, error) {
		return cachedVerdict("identity:"+identityID, func() (bool, error) {
			identity, err := server.Store.Get(ctx, "identities", identityID)
			if err != nil {
				return false, err
			}
			if identity == nil || identity.Get("status") != "active" || server.IdentityExpired(identity) {
				return false, nil
			}
			if identity.Get("kind") != "agent" {
				return true, nil
			}
			standing, err := AgentStanding(ctx, server, server.Store, identity)
			if err != nil {
				return false, err
			}
			return standing == "ok", nil
		})
	}
	delegationStands := func(delegationID string) (bool, error) {
		return cachedVerdict("delegation:"+delegationID, func() (bool, error) {
			delegation, err := server.Store.Get(ctx, "delegations", delegationID)
			if err != nil {
				return false, err
			}
			if delegation == nil {
				return false, nil
			}
			live, err := DelegationLive(delegation, nowMs)
			if err != nil || !live {
				return false, err
			}
			ancestors, err := DelegationAncestors(ctx, server.Store, delegation, nowMs)
			if err != nil {
				return false, err
			}
			return ancestors != nil, nil
		})
	}
	stranded, err := vaultScan(ctx, server.Store, VaultCollections.Leases, core.NewObject("state", "active"), func(lease *core.Object) (bool, error) {
		if jsNumber(lease.Get("expiresAt")) <= now {
			return false, nil
		}
		holderOK, err := mayAct(jsString(lease.Get("holderId")))
		if err != nil {
			return false, err
		}
		if !holderOK {
			return true, nil
		}
		if agentID := lease.Get("agentId"); !isUndefined(agentID) {
			agentOK, err := mayAct(jsString(agentID))
			if err != nil {
				return false, err
			}
			if !agentOK {
				return true, nil
			}
		}
		if delegationID := lease.Get("delegationId"); !isUndefined(delegationID) {
			stands, err := delegationStands(jsString(delegationID))
			if err != nil {
				return false, err
			}
			if !stands {
				return true, nil
			}
		}
		return false, nil
	}, limit)
	if err != nil {
		return nil, err
	}
	candidates = append(candidates, stranded...)
	seen := map[string]bool{}
	for _, candidate := range candidates {
		candidateID := jsString(candidate.Get("id"))
		if seen[candidateID] {
			continue
		}
		seen[candidateID] = true
		if candidate.Get("state") == "issuing" {
			// An issue that never finished (the process stopped): whatever the engine minted is revoked by id.
			if jsNumber(candidate.Get("issuedAt")) > now-10*VaultTime.MINUTE {
				continue
			}
			marked, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (bool, error) {
				lease, err := tx.Get(ctx, VaultCollections.Leases, candidateID)
				if err != nil {
					return false, err
				}
				if lease == nil || lease.Get("state") != "issuing" {
					return false, nil
				}
				_, err = tx.Put(ctx, VaultCollections.Leases, lease.Spread(core.NewObject(
					"state", "revoking", "endedAt", now, "endedBy", VaultOperator, "endState", "failed",
					"lastError", "The issue never completed",
				)))
				return err == nil, err
			})
			if err != nil {
				return nil, err
			}
			if !marked {
				continue
			}
			ok, _, err := revokeAndRecord(ctx, server, candidateID)
			if err != nil {
				return nil, err
			}
			if ok {
				expired++
			} else {
				retrying++
			}
			continue
		}
		if candidate.Get("kind") == "checkout" {
			ended, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (bool, error) {
				lease, err := tx.Get(ctx, VaultCollections.Leases, candidateID)
				if err != nil {
					return false, err
				}
				if lease == nil || lease.Get("state") != "active" {
					return false, nil
				}
				if _, err := tx.Put(ctx, VaultCollections.Leases, lease.Spread(core.NewObject(
					"state", "expired", "endedAt", now, "endedBy", VaultOperator,
				))); err != nil {
					return false, err
				}
				if err := operatorRecorder(server, jsString(lease.Get("tenantId")), jsString(lease.Get("name")))(ctx, tx, "vault:checkout-expired", "allow",
					core.NewObject("name", lease.Get("name"), "leaseId", lease.Get("id"), "holderId", lease.Get("holderId"))); err != nil {
					return false, err
				}
				return true, nil
			})
			if err != nil {
				return nil, err
			}
			if !ended {
				continue
			}
			expired++
			tenantID := jsString(candidate.Get("tenantId"))
			rotated, err := rotateReturned(ctx, server, tenantID, jsString(candidate.Get("secretId")), VaultOperator,
				func(name string) vaultRecorder { return operatorRecorder(server, tenantID, name) })
			if err != nil {
				return nil, err
			}
			if rotated != nil {
				rotatedCount++
			}
			continue
		}
		// Dynamic: mark the revocation (an expiry, or the end for a holder who left), then revoke at the engine.
		lease, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
			current, err := tx.Get(ctx, VaultCollections.Leases, candidateID)
			if err != nil {
				return nil, err
			}
			if current == nil || (current.Get("state") != "active" && current.Get("state") != "revoking") {
				return nil, nil
			}
			if current.Get("state") == "active" {
				endState := "ended"
				if jsNumber(current.Get("expiresAt")) <= now {
					endState = "expired"
				}
				return tx.Put(ctx, VaultCollections.Leases, current.Spread(core.NewObject(
					"state", "revoking", "endedAt", now, "endedBy", VaultOperator, "endState", endState,
				)))
			}
			// Given up after seven days of refusals: recorded, so someone revokes it by hand.
			if started := current.Get("revokeStartedAt"); !isUndefined(started) && now-jsNumber(started) > revokePatienceMs {
				endedAt := current.Get("endedAt")
				if nullish(endedAt) {
					endedAt = now
				}
				if _, err := tx.Put(ctx, VaultCollections.Leases, current.Spread(core.NewObject("state", "failed", "endedAt", endedAt))); err != nil {
					return nil, err
				}
				lastError := current.Get("lastError")
				if nullish(lastError) {
					lastError = "unknown"
				}
				if err := operatorRecorder(server, jsString(current.Get("tenantId")), jsString(current.Get("name")))(ctx, tx, "vault:revoke-failed", "deny",
					core.NewObject("name", current.Get("name"), "leaseId", current.Get("id"), "error", lastError)); err != nil {
					return nil, err
				}
				abandoned++
				return nil, nil
			}
			return current, nil
		})
		if err != nil {
			return nil, err
		}
		if lease == nil {
			continue
		}
		ok, _, err := revokeAndRecord(ctx, server, jsString(lease.Get("id")))
		if err != nil {
			return nil, err
		}
		if !ok {
			retrying++
			continue
		}
		expired++
		if err := server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			return operatorRecorder(server, jsString(lease.Get("tenantId")), jsString(lease.Get("name")))(ctx, tx, "vault:lease-expired", "allow",
				core.NewObject("name", lease.Get("name"), "leaseId", lease.Get("id"), "holderId", lease.Get("holderId")))
		}); err != nil {
			return nil, err
		}
	}
	// Lease history past the access retention.
	settings, err := vaultSettingsOf(server)
	if err != nil {
		return nil, err
	}
	cutoff := now - jsNumber(settings.Get("accessRetentionMs"))
	for _, state := range []string{"ended", "expired", "failed"} {
		old, err := vaultScan(ctx, server.Store, VaultCollections.Leases, core.NewObject("state", state), func(lease *core.Object) (bool, error) {
			endedAt := lease.Get("endedAt")
			if nullish(endedAt) {
				endedAt = lease.Get("expiresAt")
			}
			return jsNumber(endedAt) < cutoff, nil
		}, limit)
		if err != nil {
			return nil, err
		}
		for _, lease := range old {
			if err := server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
				return tx.Delete(ctx, VaultCollections.Leases, jsString(lease.Get("id")))
			}); err != nil {
				return nil, err
			}
			pruned++
		}
	}
	return core.NewObject("expired", expired, "retrying", retrying, "abandoned", abandoned, "pruned", pruned, "rotated", rotatedCount), nil
}

// PurgeDeleted (api/vault.ts IamVault.purgeDeleted): Deletes secrets whose recovery window has ended, once their
// dynamic leases are revoked (daily).
func (s *IamVault) PurgeDeleted(ctx context.Context, options *core.Object) (result *core.Object, err error) {
	server := s.server
	limit, err := s.boundedLimit(options, 1000)
	if err != nil {
		return nil, err
	}
	now := float64(server.Now())
	purged := 0.0
	secrets, err := server.Store.Find(ctx, VaultCollections.Secrets, core.NewObject("status", "pending-deletion"), nil)
	if err != nil {
		return nil, err
	}
	due := []*core.Object{}
	for _, secret := range secrets {
		deletionAt := 0.0
		if value := secret.Get("deletionAt"); !nullish(value) {
			deletionAt = jsNumber(value)
		}
		if deletionAt <= now {
			due = append(due, secret)
		}
	}
	if len(due) > limit {
		due = due[:limit]
	}
	for _, secret := range due {
		done, err := purgeSecret(ctx, server, jsString(secret.Get("id")))
		if err != nil {
			return nil, err
		}
		if done {
			purged++
		}
	}
	return core.NewObject("purged", purged), nil
}

// CreateVaultRuntime builds the IamVault (api/vault.ts createVaultRuntime). TypeScript validates the `vault` option
// here so a bad one fails construction; the composition root has no error path for it, so the settings are validated
// (and cached) on first use, and every vault call fails with INVALID_CONFIG then.
func CreateVaultRuntime(server *ServerContext) *IamVault {
	_, _ = vaultSettingsOf(server)
	return &IamVault{server: server}
}
