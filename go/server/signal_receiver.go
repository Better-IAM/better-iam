package server

// Port of packages/server/src/signal-receiver.ts: the Shared Signals receiver (OpenID SSF 1.0 with CAEP and RISC):
// security events an upstream identity provider sends about the tenant's people. Each tenant registers its
// transmitters as signal sources (`signals` API group); events arrive by push (RFC 8935, the
// `{signals.pushPath}/{sourceId}` protocol mount) or by poll (RFC 8936, `iam.signals.poll()`), are verified against
// the source's keys, deduplicated on issuer and `jti`, mapped to an identity of the source's tenant, recorded
// (`signalEvents`), and audited as `signal:received`, which threat detection reads. The only action taken directly is
// ending sessions, and only for event types a source configures that way; containment is left to threat-detection
// playbooks.

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/text/cases"
	"golang.org/x/text/language"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// SignalCollections is signal-receiver.ts signalCollections: where the receiver keeps its records; both are
// tenant-scoped and purged with the tenant (lifecycle.ts).
var SignalCollections = struct {
	Sources string
	Events  string
}{"signalSources", "signalEvents"}

// DefaultSignalAlgorithms is signal-receiver.ts DEFAULT_SIGNAL_ALGORITHMS: used when a source does not name its
// algorithms. Symmetric algorithms and `none` are never accepted.
var DefaultSignalAlgorithms = []string{"RS256", "ES256", "PS256", "EdDSA"}

// MaxSignalSourcesPerTenant is signal-receiver.ts maxSignalSourcesPerTenant: signal sources one tenant may register.
const MaxSignalSourcesPerTenant = 20

const (
	signalDay              = 86_400_000
	signalRetentionMs      = 90 * signalDay
	signalMaxSetBytes      = 16_384
	signalMaxPushBytes     = 65_536
	signalMaxClaimsChars   = 4096
	signalMaxSubjectChars  = 8192
	signalClockTolerance   = 300
	signalMaxSetAgeSeconds = 7 * 86_400
	// signalPushesPerWindow is the pushes per source per rate-limit window.
	signalPushesPerWindow     = 3000
	signalPollRequestsPerRun  = 5
	signalPollTimeoutMs       = 10_000
	signalPollMaxBytes        = 1_048_576
	signalJwksMaxBytes        = 262_144
	signalDiscoveryMaxBytes   = 65_536
	signalFetchTimeoutMs      = 5000
	signalNegativeCacheMs     = 30_000
	signalRediscoverMs        = signalDay
	signalMaxCachedSources    = 1000
	signalMaxCandidateKeys    = 20
	signalNoteErrorIntervalMs = 60_000
)

var (
	signalCompactJws  = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$`)
	signalSourceShape = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	// signalBearer is /^Bearer[ ]+([^\s]+)$/i.
	signalBearer = regexp.MustCompile(`^(?i:Bearer)[ ]+([^` + jsWhitespace + `]+)$`)
)

var signalForbiddenHeaders = []string{"jwk", "jku", "x5u", "x5c"}

// signalLenientTypes are the token types a source that does not require `secevent+jwt` still accepts (as well as
// none at all).
var signalLenientTypes = map[string]bool{"secevent+jwt": true, "jwt": true}

var signalUnsafeKeys = map[string]bool{"__proto__": true, "constructor": true, "prototype": true}

func signalTrimSlashes(value string) string { return strings.TrimRight(value, "/") }

// signalClip is `value.length > max ? value.slice(0, max) : value` over UTF-16 code units.
func signalClip(value string, max int) string {
	if utf16Len(value) > max {
		return webIdentitySlice(value, 0, max)
	}
	return value
}

// signalPlain is a plain object, or nil.
func signalPlain(value any) *core.Object {
	if object, ok := value.(*core.Object); ok && object != nil {
		return object
	}
	return nil
}

// signalNormalizedTyp lowercases a token type and drops an `application/` prefix.
func signalNormalizedTyp(value string) string {
	lower := core.JSLower(value)
	return strings.TrimPrefix(lower, "application/")
}

// signalUpper is String.prototype.toUpperCase: the full Unicode uppercase mapping.
func signalUpper(value string) string {
	for index := 0; index < len(value); index++ {
		if value[index] >= utf8.RuneSelf {
			return cases.Upper(language.Und).String(value)
		}
	}
	return strings.ToUpper(value)
}

// signalActor is the system actor of the receiver's own audit events: `signal:{sourceId}`.
func signalActor(sourceID string) string { return "signal:" + sourceID }

// pollTokenContext is the encryption context of a poll source's bearer token: binds the ciphertext to its source.
func pollTokenContext(sourceID string) string { return "signal-poll:" + sourceID }

// SealPollToken (signal-receiver.ts sealPollToken): Seals a poll source's bearer token with the current deployment
// secret.
func SealPollToken(server *ServerContext, sourceID string, token string) (result string, err error) {
	return auth.EncryptSecret(token, server.Options.Secret, pollTokenContext(sourceID)), nil
}

// openPollToken opens a poll source's bearer token with the current secret or a previous one.
func openPollToken(server *ServerContext, source *core.Object) (string, error) {
	sealed, ok := member(source.Get("poll"), "tokenSealed").(string)
	if !ok {
		return "", &core.TypeError{Message: "The sealed value must be a string"}
	}
	secrets := append([]string{server.Options.Secret}, server.Options.PreviousSecrets...)
	return auth.DecryptSecret(sealed, secrets, pollTokenContext(jsString(source.Get("id"))))
}

// signalStrings is a stored list of strings (other entries are left out).
func signalStrings(value any) []string {
	list, _ := value.([]any)
	result := make([]string, 0, len(list))
	for _, item := range list {
		if text, ok := item.(string); ok {
			result = append(result, text)
		}
	}
	return result
}

// signalIssuerForms are the issuer and its aliases, without trailing slashes.
func signalIssuerForms(source *core.Object) []string {
	forms := []string{signalTrimSlashes(jsString(source.Get("issuer")))}
	for _, alias := range signalStrings(source.Get("issuerAliases")) {
		forms = append(forms, signalTrimSlashes(alias))
	}
	return unique(forms)
}

// namesSignalSource reports whether an issuer names the source (its issuer or an alias, with or without a trailing
// slash).
func namesSignalSource(source *core.Object, issuer string) bool {
	return containsString(signalIssuerForms(source), signalTrimSlashes(issuer))
}

// signalEventKey is the received event's natural key: the SHA-256 of the source's issuer and the `jti`.
func signalEventKey(issuer, jti string) string {
	return "jti:" + Hash(signalTrimSlashes(issuer)+"|"+jti)
}

// signalJSONCopy is a plain JSON copy without prototype-polluting keys (storage refuses them), non-finite numbers or
// deep nesting; core.Undefined for a value that is dropped.
func signalJSONCopy(value any, depth int) any {
	switch typed := value.(type) {
	case nil, string, bool:
		return typed
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return core.Undefined
		}
		return typed
	}
	if depth >= 16 {
		return core.Undefined
	}
	switch typed := value.(type) {
	case []any:
		copied := make([]any, len(typed))
		for index, entry := range typed {
			item := signalJSONCopy(entry, depth+1)
			if isUndefined(item) {
				item = nil
			}
			copied[index] = item
		}
		return copied
	case *core.Object:
		result := core.NewObject()
		if typed == nil {
			return core.Undefined
		}
		typed.Entries(func(key string, entry any) bool {
			if signalUnsafeKeys[key] {
				return true
			}
			if copied := signalJSONCopy(entry, depth+1); !isUndefined(copied) {
				result.Set(key, copied)
			}
			return true
		})
		return result
	}
	return core.Undefined
}

// signalJSONLength is JSON.stringify(value).length.
func signalJSONLength(value any) int {
	text, _, _ := core.Stringify(value)
	return utf16Len(text)
}

// signalStoredClaims are the event claims as stored: all of them up to 4 KiB, else the members that fit (long strings
// shortened).
func signalStoredClaims(event *core.Object) *core.Object {
	copy, _ := signalJSONCopy(event, 0).(*core.Object)
	if copy == nil {
		copy = core.NewObject()
	}
	if signalJSONLength(copy) <= signalMaxClaimsChars {
		return copy
	}
	kept := core.NewObject("_truncated", true)
	size := signalJSONLength(kept)
	copy.Entries(func(key string, value any) bool {
		entry := value
		if text, ok := value.(string); ok {
			entry = signalClip(text, 256)
		}
		cost := signalJSONLength(core.NewObject(key, entry))
		if size+cost > signalMaxClaimsChars {
			return true
		}
		kept.Set(key, entry)
		size += cost
		return true
	})
	return kept
}

func signalStoredSubject(subject *core.SubjectIdentifier) *core.Object {
	if subject == nil {
		return nil
	}
	copy, _ := signalJSONCopy(subject.ToValue(), 0).(*core.Object)
	if signalJSONLength(copy) <= signalMaxSubjectChars {
		return copy
	}
	return core.NewObject("format", subject.Format, "_truncated", true)
}

// signalLocalized is a localized claim (CAEP `reason_admin` is a language map; some transmitters send a plain
// string), or "" when there is none.
func signalLocalized(value any) (string, bool) {
	if text, ok := value.(string); ok {
		return text, true
	}
	languages := signalPlain(value)
	if languages == nil {
		return "", false
	}
	if english, ok := languages.Get("en").(string); ok {
		return english, true
	}
	found, ok := "", false
	languages.Entries(func(_ string, entry any) bool {
		if text, isText := entry.(string); isText {
			found, ok = text, true
			return false
		}
		return true
	})
	return found, ok
}

// signalPerson is a person of the source's tenant (not a service account or agent, not deleted), or nil.
func signalPerson(ctx context.Context, tx core.IamStore, source *core.Object, identityID any) (*core.Object, error) {
	id, ok := identityID.(string)
	if !ok || id == "" {
		return nil, nil
	}
	identity, err := tx.Get(ctx, "identities", id)
	if err != nil || identity == nil {
		return nil, err
	}
	kind := identity.Get("kind")
	if !core.StrictEquals(identity.Get("tenantId"), source.Get("tenantId")) || identity.Get("status") == "deleted" ||
		kind == "service" || kind == "agent" {
		return nil, nil
	}
	return identity, nil
}

// signalLinkIssuers: federation links store the connection's issuer spelled as its tokens did, so every spelling the
// source accepts is tried.
func signalLinkIssuers(source *core.Object, iss string) []string {
	spellings := []string{iss, signalTrimSlashes(iss), signalTrimSlashes(iss) + "/"}
	for _, form := range signalIssuerForms(source) {
		spellings = append(spellings, form, form+"/")
	}
	return unique(spellings)
}

func signalSubjects(source *core.Object) *core.Object {
	subjects, _ := source.Get("subjects").(*core.Object)
	if subjects == nil {
		return core.NewObject()
	}
	return subjects
}

func signalByFederationLink(ctx context.Context, tx core.IamStore, source *core.Object, iss, sub string) (string, error) {
	for _, connectionID := range signalStrings(signalSubjects(source).Get("connectionIds")) {
		for _, issuer := range signalLinkIssuers(source, iss) {
			key, _, err := core.Stringify([]any{connectionID, issuer, sub})
			if err != nil {
				return "", err
			}
			links, err := tx.Find(ctx, "externalIdentities", core.NewObject("tenantId", source.Get("tenantId"), "uniqueKey", key), nil)
			if err != nil {
				return "", err
			}
			if len(links) == 0 {
				continue
			}
			identity, err := signalPerson(ctx, tx, source, links[0].Get("identityId"))
			if err != nil {
				return "", err
			}
			if identity != nil {
				return jsString(identity.Get("id")), nil
			}
		}
	}
	return "", nil
}

func signalByScimExternalID(ctx context.Context, tx core.IamStore, source *core.Object, externalID string) (string, error) {
	for _, connectionID := range signalStrings(signalSubjects(source).Get("scimConnectionIds")) {
		links, err := tx.Find(ctx, "scimUsers", core.NewObject("tenantId", source.Get("tenantId"), "connectionId", connectionID,
			"externalId", externalID), nil)
		if err != nil {
			return "", err
		}
		for _, link := range links {
			identity, err := signalPerson(ctx, tx, source, link.Get("identityId"))
			if err != nil {
				return "", err
			}
			if identity != nil {
				return jsString(identity.Get("id")), nil
			}
		}
	}
	return "", nil
}

func signalByVerifiedEmail(ctx context.Context, tx core.IamStore, source *core.Object, address string) (string, error) {
	if signalSubjects(source).Get("matchEmail") != true {
		return "", nil
	}
	normalized, err := Email(address)
	if err != nil {
		return "", nil
	}
	// Only a domain the tenant proved it controls: anyone can hold an address at a domain the tenant does not own.
	domain := normalized[strings.LastIndex(normalized, "@")+1:]
	claims, err := tx.Find(ctx, "tenantDomains", core.NewObject("tenantId", source.Get("tenantId"), "uniqueKey", domain), nil)
	if err != nil {
		return "", err
	}
	if len(claims) == 0 || claims[0].Get("status") != "verified" || claims[0].Get("domain") != domain {
		return "", nil
	}
	identities, err := tx.Find(ctx, "identities", core.NewObject("tenantId", source.Get("tenantId"), "email", normalized), nil)
	if err != nil {
		return "", err
	}
	for _, identity := range identities {
		match, err := signalPerson(ctx, tx, source, identity.Get("id"))
		if err != nil {
			return "", err
		}
		if match != nil {
			return jsString(match.Get("id")), nil
		}
	}
	return "", nil
}

// resolveSubject is the identity of the source's tenant an event's subject names, or "". Every identifier that may
// name a person (the subject itself, a complex subject's `user`, each alias) is tried in order: `iss_sub` of the
// source's issuer (or an alias) through the federation links of `subjects.connectionIds`, then the `externalId` of
// users provisioned through `subjects.scimConnectionIds`; `opaque` through the SCIM `externalId`; `email` and `acct:`
// by email when `subjects.matchEmail` is on and the tenant verified the domain. Deleted identities, service accounts
// and agents never match, nor does anyone in another tenant.
func resolveSubject(ctx context.Context, tx core.IamStore, source *core.Object, subject *core.SubjectIdentifier) (string, error) {
	for _, identifier := range core.UserSubjects(subject) {
		identityID := ""
		var err error
		switch identifier.Format {
		case "iss_sub":
			if !namesSignalSource(source, identifier.Iss) {
				break
			}
			if identityID, err = signalByFederationLink(ctx, tx, source, identifier.Iss, identifier.Sub); err == nil && identityID == "" {
				identityID, err = signalByScimExternalID(ctx, tx, source, identifier.Sub)
			}
		case "opaque":
			identityID, err = signalByScimExternalID(ctx, tx, source, identifier.ID)
		case "email":
			identityID, err = signalByVerifiedEmail(ctx, tx, source, identifier.Email)
		case "account":
			address, decodeErr := decodeURIComponent(identifier.URI[len("acct:"):])
			if decodeErr != nil {
				break
			}
			identityID, err = signalByVerifiedEmail(ctx, tx, source, address)
		}
		if err != nil {
			return "", err
		}
		if identityID != "" {
			return identityID, nil
		}
	}
	return "", nil
}

// signalEndSessions ends an identity's sessions except its API keys: user, role and session-token sessions (with the
// impersonations opened through them), role sessions it assumed elsewhere, and its pending sign-in challenges.
// Remembered devices stay, so the person's next sign-in is as usual. Returns the number of sessions ended.
func signalEndSessions(ctx context.Context, server *ServerContext, tx core.IamStore, identityID string) (int, error) {
	revoked := 0
	sessions, err := tx.Find(ctx, "sessions", core.NewObject("identityId", identityID), nil)
	if err != nil {
		return 0, err
	}
	for _, session := range sessions {
		if session.Get("kind") == "api-key" {
			continue
		}
		if err := server.Auth.EndSession(ctx, tx, jsString(session.Get("id"))); err != nil {
			return 0, err
		}
		revoked++
	}
	assumed, err := tx.Find(ctx, "sessions", core.NewObject("originalIdentityId", identityID), nil)
	if err != nil {
		return 0, err
	}
	for _, session := range assumed {
		if session.Get("kind") == "api-key" {
			continue
		}
		if err := tx.Delete(ctx, "sessions", jsString(session.Get("id"))); err != nil {
			return 0, err
		}
		revoked++
	}
	challenges, err := tx.Find(ctx, "authChallenges", core.NewObject("identityId", identityID), nil)
	if err != nil {
		return 0, err
	}
	for _, challenge := range challenges {
		if err := tx.Delete(ctx, "authChallenges", jsString(challenge.Get("id"))); err != nil {
			return 0, err
		}
	}
	return revoked, nil
}

func signalAudit(ctx context.Context, server *ServerContext, tx core.IamStore, source *core.Object, action, resourceID string, metadata *core.Object) error {
	return server.Events.RecordAudit(ctx, tx, core.NewObject(
		"id", ID(),
		"tenantId", source.Get("tenantId"),
		"actorId", signalActor(jsString(source.Get("id"))),
		"action", action,
		"resourceId", resourceID,
		"timestamp", float64(server.Now()),
		"outcome", "allow",
		"metadata", metadata,
	))
}

// signalInput is what processing needs from a security event (signal-receiver.ts SignalInput).
type signalInput struct {
	eventType string
	subject   *core.SubjectIdentifier
	// event is the event's own claims.
	event *core.Object
	jti   string
}

// signalOutcome is the result of applySignal; source carries the bookkeeping a control event changed (the same
// pointer when nothing changed).
type signalOutcome struct {
	status     string
	identityID string
	reason     string
	source     *core.Object
}

// ApplySignal (signal-receiver.ts applySignal): Handles one event inside the caller's transaction. Control events
// touch only the source: `verification` records `lastVerifiedAt`; `stream-updated` to paused or disabled records the
// transmitter's status in `lastError`. Unknown event types are ignored. Otherwise the subject is mapped
// (`resolveSubject`); for a match with the action `revoke-sessions` configured for the event type, the person's
// sessions end (`signal:revoke-sessions`), except for a root administrator unless the source belongs to the root
// tenant (ignored, reason `protected`). signal is `{ eventType, subject?, event, jti }`; the result is
// `{ status, identityId?, reason?, source }`.
func ApplySignal(ctx context.Context, server *ServerContext, tx core.IamStore, source *core.Object, signal *core.Object) (result *core.Object, err error) {
	input := signalInput{eventType: jsString(signal.Get("eventType")), jti: jsString(signal.Get("jti"))}
	input.event, _ = signal.Get("event").(*core.Object)
	if input.event == nil {
		input.event = core.NewObject()
	}
	if subject := signal.Get("subject"); !nullish(subject) {
		input.subject = core.ParseSubjectIdentifier(subject)
	}
	outcome, err := applySignal(ctx, server, tx, source, input)
	if err != nil {
		return nil, err
	}
	result = core.NewObject("status", outcome.status)
	if outcome.identityID != "" {
		result.Set("identityId", outcome.identityID)
	}
	if outcome.reason != "" {
		result.Set("reason", outcome.reason)
	}
	return result.Set("source", outcome.source), nil
}

func applySignal(ctx context.Context, server *ServerContext, tx core.IamStore, source *core.Object, signal signalInput) (signalOutcome, error) {
	now := float64(server.Now())
	switch signal.eventType {
	case "verification":
		return signalOutcome{status: "recorded", source: source.Spread(core.NewObject("lastVerifiedAt", now))}, nil
	case "stream-updated":
		status := signal.event.Get("status")
		if status == "paused" || status == "disabled" {
			reason, _ := signalLocalized(signal.event.Get("reason"))
			verb := "disabled"
			if status == "paused" {
				verb = "paused"
			}
			message := "The transmitter " + verb + " the stream"
			if reason != "" {
				message += ": " + signalClip(reason, 200)
			}
			return signalOutcome{status: "recorded", source: source.Spread(core.NewObject(
				"lastError", core.NewObject("at", now, "message", message),
			))}, nil
		}
		return signalOutcome{status: "recorded", source: source}, nil
	case "unknown":
		return signalOutcome{status: "ignored", reason: "unsupported-event", source: source}, nil
	}
	identityID, err := resolveSubject(ctx, tx, source, signal.subject)
	if err != nil {
		return signalOutcome{}, err
	}
	if identityID == "" {
		reason := "no-subject"
		if signal.subject != nil {
			reason = "no-match"
		}
		return signalOutcome{status: "unmatched", reason: reason, source: source}, nil
	}
	if member(source.Get("actions"), signal.eventType) != "revoke-sessions" {
		return signalOutcome{status: "recorded", identityID: identityID, source: source}, nil
	}
	identity, err := tx.Get(ctx, "identities", identityID)
	if err != nil {
		return signalOutcome{}, err
	}
	if truthy(identity.Get("rootAdmin")) {
		tenant, err := tx.Get(ctx, "tenants", jsString(source.Get("tenantId")))
		if err != nil {
			return signalOutcome{}, err
		}
		if tenant == nil || tenant.Get("type") != "root" || tenant.Get("parentId") != nil {
			return signalOutcome{status: "ignored", identityID: identityID, reason: "protected", source: source}, nil
		}
	}
	revoked, err := signalEndSessions(ctx, server, tx, jsString(identity.Get("id")))
	if err != nil {
		return signalOutcome{}, err
	}
	// A name of its own: the transmitter maps `identity:revoke-sessions` and would echo the revocation upstream.
	if err := signalAudit(ctx, server, tx, source, "signal:revoke-sessions", jsString(identity.Get("id")), core.NewObject(
		"sourceId", source.Get("id"),
		"eventType", signal.eventType,
		"jti", signal.jti,
		"revoked", float64(revoked),
	)); err != nil {
		return signalOutcome{}, err
	}
	return signalOutcome{status: "applied", identityID: identityID, source: source}, nil
}

// RecordSignalReceived (signal-receiver.ts recordSignalReceived): Audits a received (or reprocessed) event as
// `signal:received` for threat detection: actor `signal:{sourceId}`, the matched identity (else the source) as
// resource, and `{ sourceId, eventType, jti, status, identityId?, reasonAdmin?, currentLevel?, credentialType? }`
// (`currentLevel` upper-cased, for `risk-level-change`).
func RecordSignalReceived(ctx context.Context, server *ServerContext, tx core.IamStore, source *core.Object, record *core.Object, event *core.Object) (err error) {
	if event == nil {
		event = core.NewObject()
	}
	metadata := core.NewObject(
		"sourceId", source.Get("id"),
		"eventType", record.Get("eventType"),
		"jti", record.Get("jti"),
		"status", record.Get("status"),
	)
	identityID := record.Get("identityId")
	if truthy(identityID) {
		metadata.Set("identityId", identityID)
	}
	if reasonAdmin, ok := signalLocalized(event.Get("reason_admin")); ok && reasonAdmin != "" {
		metadata.Set("reasonAdmin", signalClip(reasonAdmin, 256))
	}
	if level, ok := event.Get("current_level").(string); ok && record.Get("eventType") == "risk-level-change" && level != "" {
		metadata.Set("currentLevel", signalClip(signalUpper(level), 32))
	}
	if credentialType, ok := event.Get("credential_type").(string); ok && credentialType != "" {
		metadata.Set("credentialType", signalClip(credentialType, 64))
	}
	resourceID := "signals/sources/" + jsString(source.Get("id"))
	if truthy(identityID) {
		resourceID = jsString(identityID)
	}
	return signalAudit(ctx, server, tx, source, "signal:received", resourceID, metadata)
}

func signalReceiptOf(record *core.Object, duplicate bool) *core.Object {
	receipt := core.NewObject("eventId", record.Get("id"), "status", record.Get("status"), "duplicate", duplicate)
	if identityID := record.Get("identityId"); truthy(identityID) {
		receipt.Set("identityId", identityID)
	}
	return receipt
}

func signalSourceGone() *core.IamError {
	return core.NewIamError("NOT_FOUND", "Signal source not found", 404)
}

// liveSource is the source inside a transaction, when it is active and its tenant (and every ancestor) is too; else
// NOT_FOUND.
func liveSource(ctx context.Context, server *ServerContext, tx core.IamStore, sourceID string) (*core.Object, error) {
	source, err := tx.Get(ctx, SignalCollections.Sources, sourceID)
	if err != nil {
		return nil, err
	}
	if source == nil || source.Get("status") != "active" {
		return nil, signalSourceGone()
	}
	if err := server.Auth.AssertTenantActive(ctx, tx, source.Get("tenantId")); err != nil {
		if known, ok := asIamError(err); ok && known.Status == 403 {
			return nil, signalSourceGone()
		}
		return nil, err
	}
	return source, nil
}

func signalReceivedByKey(ctx context.Context, tx core.IamStore, tenantID any, uniqueKey string) (*core.Object, error) {
	found, err := tx.Find(ctx, SignalCollections.Events, core.NewObject("tenantId", tenantID, "uniqueKey", uniqueKey), nil)
	if err != nil || len(found) == 0 {
		return nil, err
	}
	return found[0], nil
}

// signalRound is Math.round.
func signalRound(value float64) float64 { return math.Floor(value + 0.5) }

func signalReceivedRecord(source *core.Object, claims *core.SecurityEventClaims, uniqueKey string, now float64, outcome signalOutcome) *core.Object {
	subject := signalStoredSubject(claims.Subject)
	record := core.NewObject(
		"id", ID(),
		"tenantId", source.Get("tenantId"),
		"uniqueKey", uniqueKey,
		"sourceId", source.Get("id"),
		"streamId", source.Get("id"),
		"jti", claims.Jti,
		"eventType", claims.EventType,
		"eventUri", claims.EventURI,
		"issuedAt", signalRound(claims.Iat*1000),
	)
	if claims.EventTimestamp != nil {
		record.Set("eventTimestamp", *claims.EventTimestamp)
	}
	if claims.Txn != "" {
		record.Set("txn", claims.Txn)
	}
	if subject != nil {
		record.Set("subject", subject)
	}
	if outcome.identityID != "" {
		record.Set("identityId", outcome.identityID)
	}
	record.Set("status", outcome.status)
	if outcome.reason != "" {
		record.Set("reason", outcome.reason)
	}
	event := claims.Event
	if event == nil {
		event = core.NewObject()
	}
	return record.Set("claims", signalStoredClaims(event)).
		Set("receivedAt", now).
		Set("timestamp", now).
		Set("expiresAt", now+signalRetentionMs)
}

// processSignal records a verified event for a source in one transaction: deduplicates on issuer and `jti` (a repeat
// returns the first receipt with `duplicate: true`), applies it (`applySignal`), stores it, audits `signal:received`
// and notes `lastEventAt`. When applying fails, the event is stored as `failed` in a transaction of its own instead,
// so an administrator can reprocess it and the transmitter is not asked for it again. Fails with NOT_FOUND when the
// source is gone or disabled, and storage contention (503) as is, so the caller can have the event delivered again.
func processSignal(ctx context.Context, server *ServerContext, sourceID string, claims *core.SecurityEventClaims) (*core.Object, error) {
	event := claims.Event
	if event == nil {
		event = core.NewObject()
	}
	receipt, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		source, err := liveSource(ctx, server, tx, sourceID)
		if err != nil {
			return nil, err
		}
		uniqueKey := signalEventKey(jsString(source.Get("issuer")), claims.Jti)
		existing, err := signalReceivedByKey(ctx, tx, source.Get("tenantId"), uniqueKey)
		if err != nil {
			return nil, err
		}
		if existing != nil {
			return signalReceiptOf(existing, true), nil
		}
		now := float64(server.Now())
		outcome, err := applySignal(ctx, server, tx, source, signalInput{
			eventType: claims.EventType, subject: claims.Subject, event: event, jti: claims.Jti,
		})
		if err != nil {
			return nil, err
		}
		record, err := tx.Insert(ctx, SignalCollections.Events, signalReceivedRecord(source, claims, uniqueKey, now, outcome))
		if err != nil {
			return nil, err
		}
		if err := RecordSignalReceived(ctx, server, tx, source, record, event); err != nil {
			return nil, err
		}
		if _, err := tx.Put(ctx, SignalCollections.Sources, outcome.source.Spread(core.NewObject("lastEventAt", now))); err != nil {
			return nil, err
		}
		return signalReceiptOf(record, false), nil
	})
	if err == nil {
		return receipt, nil
	}
	if known, ok := asIamError(err); ok && (known.Status == 404 || known.Status >= 500) {
		return nil, err
	}
	// The same event committed concurrently (the natural key collided), or applying it failed.
	reason := "INTERNAL_ERROR"
	if known, ok := asIamError(err); ok {
		reason = known.Code
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		source, err := liveSource(ctx, server, tx, sourceID)
		if err != nil {
			return nil, err
		}
		uniqueKey := signalEventKey(jsString(source.Get("issuer")), claims.Jti)
		existing, err := signalReceivedByKey(ctx, tx, source.Get("tenantId"), uniqueKey)
		if err != nil {
			return nil, err
		}
		if existing != nil {
			return signalReceiptOf(existing, true), nil
		}
		now := float64(server.Now())
		record, err := tx.Insert(ctx, SignalCollections.Events, signalReceivedRecord(source, claims, uniqueKey, now,
			signalOutcome{status: "failed", reason: reason}))
		if err != nil {
			return nil, err
		}
		if err := RecordSignalReceived(ctx, server, tx, source, record, event); err != nil {
			return nil, err
		}
		if _, err := tx.Put(ctx, SignalCollections.Sources, source.Spread(core.NewObject("lastEventAt", now))); err != nil {
			return nil, err
		}
		return signalReceiptOf(record, false), nil
	})
}

// SignalRejectedError is a refused security event token (signal-receiver.ts SignalRejectedError): SIGNAL_REJECTED
// (400). Err is the RFC 8935 error code (invalid_request, invalid_key, invalid_issuer or invalid_audience), the message
// its description. Temporary marks a refusal that may pass later (the source's keys could not be fetched): pushes
// answer 503 and polls leave the event unacknowledged, so the transmitter delivers it again.
type SignalRejectedError struct {
	*core.IamError
	Err       string
	Temporary bool
}

// NewSignalRejectedError builds a SignalRejectedError.
func NewSignalRejectedError(code, description string, temporary bool) *SignalRejectedError {
	return &SignalRejectedError{IamError: core.NewIamError("SIGNAL_REJECTED", description, 400), Err: code, Temporary: temporary}
}

func (e *SignalRejectedError) Unwrap() error { return e.IamError }

// Name is the JavaScript error name.
func (e *SignalRejectedError) Name() string { return "SignalRejectedError" }

// signalKeysUnavailable is raised by the key resolver when the source's keys cannot be obtained right now.
type signalKeysUnavailable struct{}

func (signalKeysUnavailable) Error() string { return "The source's keys are unavailable" }

// signalPollFailure is a failed poll request; the message is safe to store as the source's `lastError`.
type signalPollFailure struct{ message string }

func (e *signalPollFailure) Error() string { return e.message }

func signalRejectionFor(err error, remoteKeys bool) *SignalRejectedError {
	var rejected *SignalRejectedError
	if errors.As(err, &rejected) {
		return rejected
	}
	var unavailable signalKeysUnavailable
	class := sjwtClassOf(err)
	if errors.As(err, &unavailable) || class == "JWKSTimeout" {
		return NewSignalRejectedError("invalid_key", "The source's signing keys could not be obtained", true)
	}
	switch class {
	case "JWKSInvalid":
		return NewSignalRejectedError("invalid_key", "The source's key set is invalid", true)
	case "JWKSNoMatchingKey":
		// A transmitter that rotated its keys moments ago is retried once the key set may be fetched again.
		return NewSignalRejectedError("invalid_key", "No key of the source matches the token", remoteKeys)
	case "JWKSMultipleMatchingKeys":
		return NewSignalRejectedError("invalid_key", "Several keys of the source match the token", false)
	case "JWSSignatureVerificationFailed":
		return NewSignalRejectedError("invalid_key", "The token signature is invalid", false)
	case "JOSEAlgNotAllowed", "JOSENotSupported":
		return NewSignalRejectedError("invalid_key", "The token algorithm or key is not accepted", false)
	case "JWTExpired":
		return NewSignalRejectedError("invalid_request", "The token has expired", false)
	case "JWTClaimValidationFailed":
		var failure *sjwtError
		errors.As(err, &failure)
		switch failure.Claim {
		case "iss":
			return NewSignalRejectedError("invalid_issuer", "The token's issuer is not the source's issuer", false)
		case "aud":
			return NewSignalRejectedError("invalid_audience", "The token is not addressed to this receiver", false)
		case "typ":
			return NewSignalRejectedError("invalid_request", "The token type must be secevent+jwt", false)
		}
		return NewSignalRejectedError("invalid_request", "The token's "+failure.Claim+" claim is missing or invalid", false)
	}
	var format *core.SignalFormatError
	if errors.As(err, &format) {
		return NewSignalRejectedError("invalid_request", format.Message, false)
	}
	return NewSignalRejectedError("invalid_request", "The security event token is malformed", false)
}

// signalKeys is a source's key resolver (jose's JWTVerifyGetKey) and the key set it selects from, for trying each
// candidate when several keys match a token.
type signalKeys struct {
	resolve  sjwtResolver
	snapshot func() *sjwtLocalSet
}

// signalCachedKeys are the cached keys of one source version.
type signalCachedKeys struct {
	updatedAt     any
	keys          *signalKeys
	discoveredAt  float64
	hasDiscovered bool
	pending       *signalKeysFlight
	failedAt      float64
	hasFailed     bool
}

type signalKeysFlight struct {
	done chan struct{}
	keys *signalKeys
	err  error
}

// signalRoundTripper sends requests through a guarded fetch.
type signalRoundTripper struct{ fetch *auth.GuardedFetch }

func (t signalRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return t.fetch.Do(request)
}

// SignalReceiver is signal-receiver.ts SignalReceiver: the receiver's per-deployment state (key caches, guarded
// transports) and the push endpoint.
type SignalReceiver struct {
	server         *ServerContext
	addressRules   auth.SafeFetchAddressOptions
	jwksFetch      *auth.GuardedFetch
	discoveryFetch *auth.GuardedFetch
	pollFetch      *auth.GuardedFetch
	prefix         string

	mu    sync.Mutex
	cache map[string]*signalCachedKeys
	order []string
}

func guardedFetchWithin(rules auth.SafeFetchAddressOptions, maxBytes int64) *auth.GuardedFetch {
	return auth.CreateGuardedFetch(auth.GuardedFetchOptions{SafeFetchAddressOptions: rules, MaxBytes: &maxBytes})
}

func createSignalReceiver(server *ServerContext) *SignalReceiver {
	settings := server.Config.Signals
	rules := auth.SafeFetchAddressOptions{
		AnyPort: true, AllowPrivateNetworks: settings.AllowPrivateNetworks, AllowInsecureLocalhost: settings.AllowInsecureLocalhost,
	}
	return &SignalReceiver{
		server:         server,
		addressRules:   rules,
		jwksFetch:      guardedFetchWithin(rules, signalJwksMaxBytes),
		discoveryFetch: guardedFetchWithin(rules, signalDiscoveryMaxBytes),
		pollFetch:      guardedFetchWithin(rules, signalPollMaxBytes),
		prefix:         settings.PushPath + "/",
		cache:          map[string]*signalCachedKeys{},
	}
}

// receivers holds the receiver of each context (signal-receiver.ts receivers, a WeakMap keyed by the context).
var receivers sync.Map

// SignalReceiverOf (signal-receiver.ts signalReceiverOf): The deployment's signal receiver (one per server context,
// created on first use).
func SignalReceiverOf(server *ServerContext) *SignalReceiver {
	if found, ok := receivers.Load(server); ok {
		return found.(*SignalReceiver)
	}
	found, _ := receivers.LoadOrStore(server, createSignalReceiver(server))
	return found.(*SignalReceiver)
}

func (s *SignalReceiver) wall() float64 { return float64(s.server.Wall()) }

// entryFor is the cache entry of a source version (a changed `updatedAt` starts a new one).
func (s *SignalReceiver) entryFor(source *core.Object) *signalCachedKeys {
	s.mu.Lock()
	defer s.mu.Unlock()
	id := jsString(source.Get("id"))
	entry, ok := s.cache[id]
	if !ok || !core.StrictEquals(entry.updatedAt, source.Get("updatedAt")) {
		if !ok && len(s.cache) >= signalMaxCachedSources && len(s.order) > 0 {
			delete(s.cache, s.order[0])
			s.order = s.order[1:]
		}
		entry = &signalCachedKeys{updatedAt: source.Get("updatedAt")}
		if !ok {
			s.order = append(s.order, id)
		}
		s.cache[id] = entry
	}
	return entry
}

func localSignalKeys(set *sjwtLocalSet) *signalKeys {
	return &signalKeys{resolve: set.resolve, snapshot: func() *sjwtLocalSet { return set }}
}

// remoteKeys is a remote key set fetched through the guarded transport; transport failures read as unavailable keys.
func (s *SignalReceiver) remoteKeys(u *auth.FetchURL) *signalKeys {
	fetch := s.jwksFetch
	set := &sjwtRemoteSet{
		href: u.Href, timeout: signalFetchTimeoutMs * time.Millisecond, cooldownDuration: 30_000, cacheMaxAge: 600_000,
		client: &http.Client{Transport: signalRoundTripper{fetch: fetch}, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}},
	}
	return &signalKeys{
		resolve: func(ctx context.Context, header *core.Object) (*sjwtPublicKey, error) {
			key, err := set.resolve(ctx, header)
			if err != nil {
				// Which key signed the token is the token's matter. A key set that could not be fetched or read (a
				// timeout, a status other than 200, a body that is not a public key set) is the transmitter's, and may
				// pass later.
				switch sjwtClassOf(err) {
				case "JWKSNoMatchingKey", "JWKSMultipleMatchingKeys", "JOSENotSupported":
					return nil, err
				}
				return nil, signalKeysUnavailable{}
			}
			return key, nil
		},
		snapshot: func() *sjwtLocalSet {
			set.mu.Lock()
			defer set.mu.Unlock()
			if set.local == nil {
				return &sjwtLocalSet{}
			}
			return set.local
		},
	}
}

// getJSON reads a discovery document.
func (s *SignalReceiver) getJSON(ctx context.Context, u *auth.FetchURL) (any, error) {
	ctx, cancel := context.WithTimeout(ctx, signalFetchTimeoutMs*time.Millisecond)
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, u.Href, nil)
	if err != nil {
		return nil, err
	}
	request.Header.Set("accept", "application/json")
	response, err := s.discoveryFetch.DoRedirectError(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || !strings.Contains(core.JSLower(response.Header.Get("content-type")), "json") {
		_, _ = io.ReadAll(response.Body)
		return nil, signalKeysUnavailable{}
	}
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	return core.ParseJSONString(strings.TrimPrefix(decodeUTF8(body), string(rune(0xFEFF))))
}

// discover is SSF discovery (`/.well-known/ssf-configuration{path}`, then the legacy RISC document): the `jwks_uri`.
func (s *SignalReceiver) discover(ctx context.Context, source *core.Object) (*auth.FetchURL, error) {
	issuer, err := auth.ParseFetchURL(jsString(source.Get("issuer")))
	if err != nil {
		return nil, &core.TypeError{Message: "Invalid URL"}
	}
	path := signalTrimSlashes(urlPathname(issuer))
	for _, name := range []string{"ssf-configuration", "risc-configuration"} {
		target, err := auth.ParseFetchURL(urlOrigin(issuer) + "/.well-known/" + name + path)
		if err != nil {
			continue
		}
		value, err := s.getJSON(ctx, target)
		if err != nil {
			continue
		}
		document := signalPlain(value)
		if document == nil {
			continue
		}
		documentIssuer, ok := document.Get("issuer").(string)
		if !ok || !namesSignalSource(source, documentIssuer) {
			continue
		}
		jwksURI, ok := document.Get("jwks_uri").(string)
		if !ok {
			continue
		}
		checked, err := auth.CheckFetchURL(jwksURI, s.addressRules)
		if err != nil {
			continue
		}
		return checked, nil
	}
	return nil, signalKeysUnavailable{}
}

// keysFor are the source's keys: static ones, its key URL, or discovered (single-flight, 30 s negative cache, daily
// refresh).
func (s *SignalReceiver) keysFor(ctx context.Context, source *core.Object) (*signalKeys, error) {
	entry := s.entryFor(source)
	now := s.wall()
	s.mu.Lock()
	if entry.keys != nil && (!entry.hasDiscovered || now-entry.discoveredAt < signalRediscoverMs) {
		keys := entry.keys
		s.mu.Unlock()
		return keys, nil
	}
	s.mu.Unlock()
	if jwks := source.Get("jwks"); truthy(jwks) {
		set, err := sjwtNewLocalSet(core.NewObject("keys", member(jwks, "keys")))
		if err != nil {
			return nil, err
		}
		keys := localSignalKeys(set)
		s.mu.Lock()
		entry.keys = keys
		s.mu.Unlock()
		return keys, nil
	}
	if jwksURI := source.Get("jwksUri"); truthy(jwksURI) {
		u, err := auth.CheckFetchURL(jsString(jwksURI), s.addressRules)
		if err != nil {
			// Stored under looser deployment settings than the current ones: it stays refused until an update fixes it.
			return nil, NewSignalRejectedError("invalid_key", "The source's key URL is not allowed", false)
		}
		keys := s.remoteKeys(u)
		s.mu.Lock()
		entry.keys = keys
		s.mu.Unlock()
		return keys, nil
	}
	// A daily rediscovery that fails keeps the keys found before, so a brief outage of the discovery document does not
	// refuse events the known keys still verify.
	s.mu.Lock()
	stale := entry.keys
	if entry.hasFailed && now-entry.failedAt < signalNegativeCacheMs && entry.pending == nil {
		s.mu.Unlock()
		if stale != nil {
			return stale, nil
		}
		return nil, signalKeysUnavailable{}
	}
	flight := entry.pending
	if flight == nil {
		flight = &signalKeysFlight{done: make(chan struct{})}
		entry.pending = flight
		s.mu.Unlock()
		u, err := s.discover(context.WithoutCancel(ctx), source)
		s.mu.Lock()
		if err == nil {
			keys := s.remoteKeys(u)
			entry.keys = keys
			entry.discoveredAt, entry.hasDiscovered = s.wall(), true
			entry.hasFailed = false
			flight.keys = keys
		} else {
			entry.failedAt, entry.hasFailed = s.wall(), true
			if entry.keys != nil {
				flight.keys = entry.keys
			} else {
				flight.err = signalKeysUnavailable{}
			}
		}
		entry.pending = nil
		close(flight.done)
	}
	s.mu.Unlock()
	<-flight.done
	return flight.keys, flight.err
}

// signalVerifiedPayload is jose's jwtVerify, trying each candidate when several keys of the set could have signed the
// token (keys without a `kid`, or a token without one): the first that verifies wins, and none verifying is a bad
// signature.
func signalVerifiedPayload(ctx context.Context, token string, keys *signalKeys, options sjwtVerifyOptions) (*core.Object, error) {
	payload, _, err := sjwtJwtVerify(ctx, token, keys.resolve, options)
	if err == nil {
		return payload, nil
	}
	if sjwtClassOf(err) != "JWKSMultipleMatchingKeys" {
		return nil, err
	}
	header, headerErr := sjwtDecodeProtectedHeader(token)
	if headerErr != nil {
		return nil, headerErr
	}
	alg, _ := header.Get("alg").(string)
	entry := sjwtAlgorithms[alg]
	kid := header.Get("kid")
	tried := 0
	for _, jwk := range keys.snapshot().keys {
		if !sjwtUsableJwk(jwk, entry, alg, kid) {
			continue
		}
		key, importErr := sjwtImportJwk(entry, jwk)
		if importErr != nil {
			continue
		}
		tried++
		if tried > signalMaxCandidateKeys {
			break
		}
		payload, _, inner := sjwtJwtVerify(ctx, token, func(context.Context, *core.Object) (*sjwtPublicKey, error) { return key, nil }, options)
		if inner == nil {
			return payload, nil
		}
		if sjwtClassOf(inner) != "JWSSignatureVerificationFailed" {
			return nil, inner
		}
	}
	return nil, sjwtFail("JWSSignatureVerificationFailed", "signature verification failed")
}

// Verify (signal-receiver.ts SignalReceiver.verify): Verifies a compact SET for a source (signature, issuer,
// audience, type, age, claims) or fails with a *SignalRejectedError. The result is the SET's claims.
func (s *SignalReceiver) Verify(ctx context.Context, source *core.Object, set any) (result *core.Object, err error) {
	claims, err := s.verify(ctx, source, set)
	if err != nil {
		return nil, err
	}
	return claims.ToValue(), nil
}

func (s *SignalReceiver) verify(ctx context.Context, source *core.Object, set any) (*core.SecurityEventClaims, error) {
	remote := isUndefined(source.Get("jwks"))
	claims, err := s.verifyClaims(ctx, source, set)
	if err != nil {
		return nil, signalRejectionFor(err, remote)
	}
	return claims, nil
}

func (s *SignalReceiver) verifyClaims(ctx context.Context, source *core.Object, set any) (*core.SecurityEventClaims, error) {
	text, ok := set.(string)
	if !ok {
		return nil, NewSignalRejectedError("invalid_request", "Expected a compact security event token", false)
	}
	token := core.JSTrim(text)
	if len(token) > signalMaxSetBytes {
		return nil, NewSignalRejectedError("invalid_request", "The security event token is larger than 16 KiB", false)
	}
	if !signalCompactJws.MatchString(token) {
		return nil, NewSignalRejectedError("invalid_request", "Expected a compact signed JWT", false)
	}
	header, err := sjwtDecodeProtectedHeader(token)
	if err != nil {
		return nil, NewSignalRejectedError("invalid_request", "The token header is malformed", false)
	}
	// Keys come from the source's configuration only, never from the token itself.
	for _, name := range signalForbiddenHeaders {
		if !isUndefined(header.Get(name)) {
			return nil, NewSignalRejectedError("invalid_request", "The token header must not carry "+name, false)
		}
	}
	if !isUndefined(header.Get("crit")) {
		return nil, NewSignalRejectedError("invalid_request", "The token names critical header parameters", false)
	}
	algorithms, _ := source.Get("algorithms").([]any)
	alg, isText := header.Get("alg").(string)
	allowed := false
	for _, item := range algorithms {
		allowed = allowed || (isText && item == alg)
	}
	if !isText || !allowed {
		return nil, NewSignalRejectedError("invalid_key", "The token algorithm is not allowed for this source", false)
	}
	if kid := header.Get("kid"); !isUndefined(kid) {
		if _, ok := kid.(string); !ok {
			return nil, NewSignalRejectedError("invalid_request", "The token header is malformed", false)
		}
	}
	requireTyp := truthy(source.Get("requireTyp"))
	typ := header.Get("typ")
	if requireTyp {
		value, ok := typ.(string)
		if !ok || signalNormalizedTyp(value) != "secevent+jwt" {
			return nil, NewSignalRejectedError("invalid_request", "The token type must be secevent+jwt", false)
		}
	} else if !isUndefined(typ) {
		value, ok := typ.(string)
		if !ok || !signalLenientTypes[signalNormalizedTyp(value)] {
			return nil, NewSignalRejectedError("invalid_request", "The token type is not a security event token", false)
		}
	}
	now := float64(s.server.Now())
	keys, err := s.keysFor(ctx, source)
	if err != nil {
		return nil, err
	}
	issuers := []string{}
	for _, form := range signalIssuerForms(source) {
		issuers = append(issuers, form, form+"/")
	}
	options := sjwtVerifyOptions{
		algorithms: signalStrings(source.Get("algorithms")), hasIssuer: true, issuers: issuers,
		audience: signalStrings(source.Get("audiences")), clockTolerance: float64(signalClockTolerance), currentDate: now,
		requiredClaims: []string{"iss", "aud", "iat", "jti", "events"}, maxTokenAge: core.Undefined,
	}
	if requireTyp {
		options.typ = "secevent+jwt"
	}
	payload, err := signalVerifiedPayload(ctx, token, keys, options)
	if err != nil {
		return nil, err
	}
	claims, err := core.ReadSecurityEvent(payload)
	if err != nil {
		return nil, err
	}
	if tenantClaim := source.Get("tenantClaim"); !isUndefined(tenantClaim) && !core.StrictEquals(payload.Get("tenant_id"), tenantClaim) {
		return nil, NewSignalRejectedError("invalid_audience", "The token is for another organization of its issuer", false)
	}
	// No maxTokenAge (a polled event can wait in the transmitter's queue), but nothing older than a week.
	seconds := now / 1000
	if claims.Iat > seconds+signalClockTolerance {
		return nil, NewSignalRejectedError("invalid_request", "The token was issued in the future", false)
	}
	if claims.Iat < seconds-signalMaxSetAgeSeconds {
		return nil, NewSignalRejectedError("invalid_request", "The token is older than seven days", false)
	}
	return claims, nil
}

// noteError notes a refusal or transport failure on the source, at most once a minute per message.
func (s *SignalReceiver) noteError(ctx context.Context, sourceID, message string) {
	// Bookkeeping never hides the refusal itself.
	_ = s.server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		current, err := tx.Get(ctx, SignalCollections.Sources, sourceID)
		if err != nil || current == nil {
			return err
		}
		now := float64(s.server.Now())
		if last, ok := current.Get("lastError").(*core.Object); ok && last != nil && last.Get("message") == message {
			if at, isNumber := last.Get("at").(float64); isNumber && now-at < signalNoteErrorIntervalMs {
				return nil
			}
		}
		_, err = tx.Put(ctx, SignalCollections.Sources, current.Spread(core.NewObject(
			"lastError", core.NewObject("at", now, "message", signalClip(message, 512)),
		)))
		return err
	})
}

// Accept (signal-receiver.ts SignalReceiver.accept): Verifies and processes a SET; a refusal is noted on the source
// as `lastError`. The result is the receipt `{ eventId, status, duplicate, identityId? }`.
func (s *SignalReceiver) Accept(ctx context.Context, source *core.Object, set any) (result *core.Object, err error) {
	claims, err := s.verify(ctx, source, set)
	if err != nil {
		rejection := signalRejectionFor(err, isUndefined(source.Get("jwks")))
		s.noteError(ctx, jsString(source.Get("id")), "Refused an event: "+rejection.Message)
		return nil, rejection
	}
	return processSignal(ctx, s.server, jsString(source.Get("id")), claims)
}

// activeSource is the source when it is active and its tenant is, read in a short transaction; nil otherwise.
func (s *SignalReceiver) activeSource(ctx context.Context, sourceID string) (*core.Object, error) {
	source, err := core.Transact(ctx, s.server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return liveSource(ctx, s.server, tx, sourceID)
	})
	if err != nil {
		if known, ok := asIamError(err); ok && known.Status == 404 {
			return nil, nil
		}
		return nil, err
	}
	return source, nil
}

// signalPushError answers `{ err, description }` with no-store and the extra headers.
func signalPushError(w http.ResponseWriter, status int, code, description string, headers ...string) {
	text, _, _ := core.Stringify(core.NewObject("err", code, "description", description))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	for index := 0; index+1 < len(headers); index += 2 {
		w.Header().Set(headers[index], headers[index+1])
	}
	w.WriteHeader(status)
	_, _ = io.WriteString(w, text)
}

// signalBoundedBody reads at most limit bytes of a request body; ok false when it is larger.
func signalBoundedBody(request *http.Request, limit int64) (string, bool, error) {
	if request.Body == nil || request.Body == http.NoBody {
		return "", true, nil
	}
	data, err := io.ReadAll(io.LimitReader(request.Body, limit+1))
	if err != nil {
		return "", false, err
	}
	if int64(len(data)) > limit {
		return "", false, nil
	}
	return decodeUTF8(data), true, nil
}

// serve is the RFC 8935 push endpoint; false passes the request on.
func (s *SignalReceiver) serve(w http.ResponseWriter, request *http.Request) bool {
	pathname := request.URL.EscapedPath()
	if !strings.HasPrefix(pathname, s.prefix) {
		return false
	}
	sourceID := pathname[len(s.prefix):]
	if !signalSourceShape.MatchString(sourceID) {
		return false
	}
	if err := s.push(w, request, sourceID); err != nil {
		if known, ok := asIamError(err); ok && known.Status == 404 {
			signalPushError(w, 404, "invalid_request", "Unknown stream")
		} else if ok && known.Status == 503 {
			signalPushError(w, 503, "invalid_request", "The receiver is busy; try again later", "Retry-After", "1")
		} else {
			signalPushError(w, 500, "invalid_request", "The event could not be processed")
		}
	}
	return true
}

// push answers one push; an error is answered by serve.
func (s *SignalReceiver) push(w http.ResponseWriter, request *http.Request, sourceID string) error {
	ctx := request.Context()
	if request.Method != http.MethodPost {
		signalPushError(w, 405, "invalid_request", "Use POST", "Allow", "POST")
		return nil
	}
	contentType := core.JSLower(core.JSTrim(strings.SplitN(strings.Join(request.Header.Values("Content-Type"), ", "), ";", 2)[0]))
	if contentType != "application/secevent+jwt" {
		signalPushError(w, 415, "invalid_request", "The content type must be application/secevent+jwt")
		return nil
	}
	declared := 0.0
	if values := request.Header.Values("Content-Length"); len(values) > 0 {
		declared = jsNumber(strings.Join(values, ", "))
	} else if request.ContentLength > 0 {
		declared = float64(request.ContentLength)
	}
	if !math.IsNaN(declared) && !math.IsInf(declared, 0) && declared > signalMaxPushBytes {
		signalPushError(w, 413, "invalid_request", "The request body is too large")
		return nil
	}
	source, err := s.activeSource(ctx, sourceID)
	if err != nil {
		return err
	}
	if source == nil || source.Get("delivery") != "push" {
		signalPushError(w, 404, "invalid_request", "Unknown stream")
		return nil
	}
	limit := int64(signalPushesPerWindow)
	if err := s.server.Auth.LimitAttempt(ctx, jsString(source.Get("tenantId")), "signals:"+jsString(source.Get("id")),
		auth.LimitAttemptOptions{Limit: &limit}); err != nil {
		known, ok := asIamError(err)
		if !ok {
			return err
		}
		if known.Status == 429 {
			var limited *auth.RateLimitedError
			if errors.As(err, &limited) {
				signalPushError(w, 429, "invalid_request", "Too many events; try again later",
					"Retry-After", strconv.FormatInt(int64(math.Ceil(float64(limited.RetryAfterMs)/1000)), 10))
			} else {
				signalPushError(w, 429, "invalid_request", "Too many events; try again later")
			}
			return nil
		}
		if known.Status == 403 {
			signalPushError(w, 403, "access_denied", "The sender is not allowed")
			return nil
		}
		return err
	}
	if hashed := source.Get("pushTokenHash"); !isUndefined(hashed) {
		match := signalBearer.FindStringSubmatch(strings.Join(request.Header.Values("Authorization"), ", "))
		if match == nil || !SameHash(Hash(match[1]), hashed) {
			signalPushError(w, 401, "authentication_failed", "The bearer token is missing or invalid", "WWW-Authenticate", "Bearer")
			return nil
		}
	}
	body, ok, err := signalBoundedBody(request, signalMaxPushBytes)
	if err != nil {
		return err
	}
	if !ok {
		signalPushError(w, 413, "invalid_request", "The request body is too large")
		return nil
	}
	if _, err := s.Accept(ctx, source, body); err != nil {
		var rejected *SignalRejectedError
		if !errors.As(err, &rejected) {
			return err
		}
		if rejected.Temporary {
			signalPushError(w, 503, rejected.Err, rejected.Message, "Retry-After", "30")
		} else {
			signalPushError(w, 400, rejected.Err, rejected.Message)
		}
		return nil
	}
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(http.StatusAccepted)
	return nil
}

// Handle (signal-receiver.ts SignalReceiver.handle): The RFC 8935 push endpoint; nil for a request it does not
// answer.
func (s *SignalReceiver) Handle(ctx context.Context, request *http.Request) (result *http.Response, err error) {
	buffer := &recorder{header: http.Header{}}
	if !s.serve(buffer, request.WithContext(ctx)) {
		return nil, nil
	}
	if !buffer.wrote {
		buffer.status = http.StatusOK
	}
	body := buffer.body.Bytes()
	return &http.Response{
		StatusCode: buffer.status, Status: strconv.Itoa(buffer.status) + " " + http.StatusText(buffer.status),
		Header: buffer.header, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)),
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Request: request,
	}, nil
}

// pollAnswer is what one poll request returned.
type pollAnswer struct {
	jtis          []string
	sets          []any
	moreAvailable bool
}

// pollRequest is one RFC 8936 poll request: acknowledgements and errors out, `{ sets, moreAvailable }` back.
func (s *SignalReceiver) pollRequest(ctx context.Context, source *core.Object, token string, body *core.Object) (*pollAnswer, error) {
	text, _, err := core.Stringify(body)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, signalPollTimeoutMs*time.Millisecond)
	defer cancel()
	endpoint := jsString(member(source.Get("poll"), "endpoint"))
	var response *http.Response
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(text))
	if err == nil {
		request.Header.Set("content-type", "application/json")
		request.Header.Set("accept", "application/json")
		request.Header.Set("authorization", "Bearer "+token)
		request.Header.Set("user-agent", "better-iam-signals/1")
		response, err = s.pollFetch.DoRedirectError(request)
	}
	if err != nil {
		var failed *auth.FetchFailedError
		var refused *auth.SafeFetchError
		if errors.As(err, &failed) && errors.As(failed.Cause, &refused) {
			return nil, &signalPollFailure{"The poll endpoint was refused (" + refused.Reason + ")"}
		}
		return nil, &signalPollFailure{"The poll endpoint could not be reached"}
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		_, _ = io.ReadAll(response.Body)
		return nil, &signalPollFailure{"The poll endpoint answered " + strconv.Itoa(response.StatusCode)}
	}
	var parsed *core.Object
	if data, err := io.ReadAll(response.Body); err == nil {
		if value, err := core.ParseJSONString(strings.TrimPrefix(decodeUTF8(data), string(rune(0xFEFF)))); err == nil {
			parsed = signalPlain(value)
		}
	}
	unreadable := &signalPollFailure{"The poll endpoint sent an unreadable response"}
	if parsed == nil {
		return nil, unreadable
	}
	sets := signalPlain(parsed.Get("sets"))
	more := parsed.Get("moreAvailable")
	if !isUndefined(parsed.Get("sets")) && sets == nil {
		return nil, unreadable
	}
	if _, isBool := more.(bool); !isUndefined(more) && !isBool {
		return nil, unreadable
	}
	answer := &pollAnswer{moreAvailable: more == true}
	if sets != nil {
		sets.Entries(func(key string, value any) bool {
			answer.jtis = append(answer.jtis, key)
			answer.sets = append(answer.sets, value)
			return true
		})
	}
	return answer, nil
}

// pollBookkeeping stores the acknowledgements and errors the next request carries, and the poll outcome.
func (s *SignalReceiver) pollBookkeeping(ctx context.Context, sourceID, endpoint string, acks []string, setErrs *core.Object, failure string) error {
	return s.server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		current, err := tx.Get(ctx, SignalCollections.Sources, sourceID)
		if err != nil {
			return err
		}
		// A source deleted, switched to another endpoint or turned into a push source meanwhile keeps its own state.
		if current == nil {
			return nil
		}
		poll, _ := current.Get("poll").(*core.Object)
		if poll == nil || poll.Get("endpoint") != endpoint {
			return nil
		}
		now := float64(s.server.Now())
		state := poll.Clone()
		state.Delete("pendingErrors")
		state.Set("pendingAcks", stringsOf(acks))
		if setErrs.Len() > 0 {
			state.Set("pendingErrors", setErrs)
		}
		state.Set("lastPolledAt", now)
		next := current.Spread(core.NewObject("poll", state))
		if failure != "" {
			next.Set("lastError", core.NewObject("at", now, "message", failure))
		}
		_, err = tx.Put(ctx, SignalCollections.Sources, next)
		return err
	})
}

func (s *SignalReceiver) pollSource(ctx context.Context, source *core.Object, result *signalPollResult) error {
	state, _ := source.Get("poll").(*core.Object)
	sourceID := jsString(source.Get("id"))
	endpoint := jsString(state.Get("endpoint"))
	token, err := openPollToken(s.server, source)
	if err != nil {
		result.errors++
		s.noteError(ctx, sourceID, "The poll token cannot be opened: it was sealed with a secret that is gone")
		return nil
	}
	acks := signalStrings(state.Get("pendingAcks"))
	setErrs := core.NewObject()
	if pending, ok := state.Get("pendingErrors").(*core.Object); ok && pending != nil {
		setErrs = pending.Clone()
	}
	maxEvents := state.Get("maxEvents")
	for request := 0; request < signalPollRequestsPerRun; request++ {
		body := core.NewObject("maxEvents", maxEvents, "returnImmediately", true, "ack", stringsOf(acks))
		if setErrs.Len() > 0 {
			body.Set("setErrs", setErrs)
		}
		answer, err := s.pollRequest(ctx, source, token, body)
		if err != nil {
			result.errors++
			message := "The poll request failed"
			var failure *signalPollFailure
			if errors.As(err, &failure) {
				message = failure.message
			}
			return s.pollBookkeeping(ctx, sourceID, endpoint, acks, setErrs, message)
		}
		// The transmitter answered, so it has the acknowledgements and errors this request carried.
		result.acknowledged += len(acks)
		acks = []string{}
		setErrs = core.NewObject()
		count := len(answer.jtis)
		if limit, ok := maxEvents.(float64); ok && limit >= 0 && float64(count) > limit {
			count = int(limit)
		}
		for index := 0; index < count; index++ {
			jti, set := answer.jtis[index], answer.sets[index]
			if jti == "" || utf16Len(jti) > 512 {
				continue
			}
			receipt, err := s.verify(ctx, source, set)
			var processed *core.Object
			if err == nil && receipt.Jti != jti {
				err = NewSignalRejectedError("invalid_request", "The token jti does not match its key in sets", false)
			}
			if err == nil {
				processed, err = processSignal(ctx, s.server, sourceID, receipt)
			}
			if err == nil {
				// Acknowledged with the next request, now that the event is committed.
				acks = append(acks, jti)
				if processed.Get("duplicate") != true {
					result.received++
				}
				continue
			}
			var rejected *SignalRejectedError
			if errors.As(err, &rejected) && !rejected.Temporary {
				setErrs.Set(jti, core.NewObject("err", rejected.Err, "description", rejected.Message))
				s.noteError(ctx, sourceID, "Refused an event: "+rejected.Message)
			} else if known, ok := asIamError(err); ok && known.Status == 404 {
				// The source was deleted or disabled while polling: stop without touching its state.
				return nil
			} else {
				result.errors++
			}
		}
		if err := s.pollBookkeeping(ctx, sourceID, endpoint, acks, setErrs, ""); err != nil {
			return err
		}
		if !answer.moreAvailable {
			break
		}
	}
	return nil
}

// signalPollResult is what one poll run did (signal-receiver.ts SignalPollResult).
type signalPollResult struct {
	// sources is the poll sources polled.
	sources int
	// received is the new events recorded (duplicates excluded).
	received int
	// acknowledged is the events acknowledged to transmitters.
	acknowledged int
	// errors is the failed poll requests and events left unacknowledged for redelivery.
	errors int
}

func (r *signalPollResult) value() *core.Object {
	return core.NewObject("sources", float64(r.sources), "received", float64(r.received),
		"acknowledged", float64(r.acknowledged), "errors", float64(r.errors))
}

// Poll (signal-receiver.ts SignalReceiver.poll): Polls every active poll source (or `input.sourceId`), and returns
// `{ sources, received, acknowledged, errors }`.
func (s *SignalReceiver) Poll(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	outcome := &signalPollResult{}
	var candidates []*core.Object
	var requested any = core.Undefined
	if input != nil {
		requested = input.Get("sourceId")
	}
	if !isUndefined(requested) {
		sourceID, ok := requested.(string)
		if !ok || !signalSourceShape.MatchString(sourceID) {
			return nil, invalidInput("Invalid sourceId")
		}
		source, err := s.activeSource(ctx, sourceID)
		if err != nil {
			return nil, err
		}
		if source != nil {
			candidates = []*core.Object{source}
		}
	} else {
		candidates, err = s.server.Store.Find(ctx, SignalCollections.Sources, core.NewObject("delivery", "poll", "status", "active"), nil)
		if err != nil {
			return nil, err
		}
	}
	sort.SliceStable(candidates, func(i, j int) bool { return ByID(candidates[i], candidates[j]) < 0 })
	for _, candidate := range candidates {
		if candidate.Get("delivery") != "poll" || candidate.Get("status") != "active" || !truthy(candidate.Get("poll")) {
			continue
		}
		// Re-read under the tenant checks: a whole-collection scan also lists sources of suspended tenants.
		source := candidate
		if isUndefined(requested) {
			if source, err = s.activeSource(ctx, jsString(candidate.Get("id"))); err != nil {
				return nil, err
			}
		}
		if source == nil || !truthy(source.Get("poll")) || source.Get("delivery") != "poll" {
			continue
		}
		outcome.sources++
		if err := s.pollSource(ctx, source, outcome); err != nil {
			return nil, err
		}
	}
	return outcome.value(), nil
}

// Forget (signal-receiver.ts SignalReceiver.forget): Drops the cached keys of a source (after an update or
// deletion).
func (s *SignalReceiver) Forget(sourceID string) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.cache[sourceID]; ok {
		delete(s.cache, sourceID)
		for index, id := range s.order {
			if id == sourceID {
				s.order = append(s.order[:index:index], s.order[index+1:]...)
				break
			}
		}
	}
	return nil
}

// CreateSignalsProtocol (signal-receiver.ts createSignalsProtocol): the Shared Signals push endpoint, `POST
// {signals.pushPath}/{sourceId}` (default `{basePath}/signals/push/{sourceId}`, RFC 8935), mounted beside the HTTP
// API: `application/secevent+jwt` bodies of at most 64 KiB, rate limited per source, the source's bearer token when it
// has one, then verification and processing. Answers 202 with no body, or `{ err, description }`: 400 for a refused
// SET, 401 for a bad bearer token, 404 for an unknown, disabled or poll source, 405, 413, 415, 429, and 503 while the
// source's keys cannot be fetched. Other paths pass through.
func CreateSignalsProtocol(server *ServerContext) ProtocolMount {
	return ProtocolMount{Handle: func(w http.ResponseWriter, r *http.Request) bool {
		return SignalReceiverOf(server).serve(w, r)
	}}
}

// IamSignals is signal-receiver.ts IamSignals: `iam.signals`, the poll job and in-process delivery.
type IamSignals struct {
	server *ServerContext
}

// Poll (signal-receiver.ts IamSignals.poll): Polls every active poll source (or one): acknowledges what earlier runs
// committed, then fetches, verifies and records events, following `moreAvailable` for at most five requests per
// source. A scheduler job; run it every minute or so. input is `{ sourceId? }` (nil for every source).
func (s *IamSignals) Poll(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	return SignalReceiverOf(s.server).Poll(ctx, input)
}

// Receive (signal-receiver.ts IamSignals.receive): Verifies and records one compact security event token for a
// source, as the push endpoint does: for custom transports and tests. Fails with *SignalRejectedError for a refused
// token and NOT_FOUND for an unknown or disabled source.
func (s *IamSignals) Receive(ctx context.Context, sourceID string, set string) (result *core.Object, err error) {
	if !signalSourceShape.MatchString(sourceID) {
		return nil, signalSourceGone()
	}
	receiver := SignalReceiverOf(s.server)
	source, err := core.Transact(ctx, s.server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return liveSource(ctx, s.server, tx, sourceID)
	})
	if err != nil {
		return nil, err
	}
	return receiver.Accept(ctx, source, set)
}

// CreateSignalsRuntime builds the IamSignals (signal-receiver.ts createSignalsRuntime).
func CreateSignalsRuntime(server *ServerContext) *IamSignals {
	return &IamSignals{server: server}
}
