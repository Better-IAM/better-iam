package server

// Port of packages/server/src/privacy.ts: privacy and consent management (GDPR, UK GDPR, CCPA/CPRA, LGPD, PIPEDA):
// the purposes a tenant processes personal data for, each person's consent to them with a signed receipt and an
// append-only history, data-subject requests with statutory deadlines, legal holds that stop erasure, and restriction
// of processing.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"math"
	"regexp"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// DefaultPrivacySettings (privacy.ts defaultPrivacySettings): the settings of a tenant that never saved any (one
// record per tenant, id `privacy:{tenantId}`).
func DefaultPrivacySettings(tenantID string) *core.Object {
	return core.NewObject(
		"id", "privacy:"+tenantID,
		"tenantId", tenantID,
		"defaultRegulation", "gdpr",
		"publicIntake", false,
		"exportLifetimeDays", 14.0,
		"updatedAt", 0.0,
	)
}

// PrivacySettings (privacy.ts privacySettings): the tenant's stored settings, or the defaults.
func PrivacySettings(ctx context.Context, tx core.IamStore, tenantID string) (result *core.Object, err error) {
	stored, err := tx.Get(ctx, "privacySettings", "privacy:"+tenantID)
	if err != nil {
		return nil, err
	}
	if stored != nil {
		return stored, nil
	}
	return DefaultPrivacySettings(tenantID), nil
}

// ExternalSubjectID (privacy.ts externalSubjectId): Application-side subject identifiers: 1-256 visible characters
// (a customer number, a visitor ID, an email hash).
func ExternalSubjectID(value any) (result string, err error) {
	result, err = Text(value, "externalId", 256)
	if err != nil {
		return "", err
	}
	if core.JSTrim(result) != result {
		return "", invalidInput("Invalid externalId")
	}
	return result, nil
}

// ResolveSubject (privacy.ts resolveSubject): Resolves a subject reference inside a tenant. Identities must be
// people (service accounts and agents have no privacy rights of their own) and, unless `allowDeleted`, not
// tombstones. The result is a ResolvedSubject: `key`, then `externalId`, or `identityId` and `identity`.
func ResolveSubject(ctx context.Context, tx core.IamStore, tenantID string, value any, allowDeleted bool) (result *core.Object, err error) {
	if !truthy(value) || !isPlainObject(value) {
		return nil, invalidInput("subject must name an identityId or an externalId")
	}
	input := value.(*core.Object)
	hasIdentity := !isUndefined(input.Get("identityId"))
	hasExternal := !isUndefined(input.Get("externalId"))
	if hasIdentity == hasExternal {
		return nil, invalidInput("subject must name exactly one of identityId or externalId")
	}
	if hasExternal {
		externalID, err := ExternalSubjectID(input.Get("externalId"))
		if err != nil {
			return nil, err
		}
		return core.NewObject("key", "external:"+externalID, "externalId", externalID), nil
	}
	identityID, err := Text(input.Get("identityId"), "identityId")
	if err != nil {
		return nil, err
	}
	identity, err := tx.Get(ctx, "identities", identityID)
	if err != nil {
		return nil, err
	}
	if identity == nil || identity.Get("tenantId") != tenantID || (!allowDeleted && identity.Get("status") == "deleted") {
		return nil, core.NewIamError("NOT_FOUND", "Identity not found", 404)
	}
	if identity.Get("kind") != "user" {
		return nil, invalidInput("Only people are data subjects")
	}
	return core.NewObject("key", "identity:"+jsString(identity.Get("id")), "identityId", identity.Get("id"), "identity", identity), nil
}

// IdentitySubject (privacy.ts identitySubject): the subject key of a person with an account.
func IdentitySubject(identityID string) (result string, err error) {
	return privacyIdentitySubject(identityID), nil
}

func privacyIdentitySubject(identityID string) string { return "identity:" + identityID }

// EmailSubject (privacy.ts emailSubject): The subject of a request from someone without an account: a keyed hash of
// their address, so a redacted request cannot be matched back to an email by hashing guesses.
func EmailSubject(secret string, address string) (result string, err error) {
	key := sha256.Sum256(utf8Bytes("better-iam:privacy-subject:" + secret))
	mac := hmac.New(sha256.New, key[:])
	mac.Write(utf8Bytes(core.JSLower(address)))
	return "email:" + hex.EncodeToString(mac.Sum(nil)), nil
}

// ConsentContextKey is privacy.ts consentContextKey.
const ConsentContextKey = "principal.consents"

// Decidable (privacy.ts decidable): Purposes a person decides on: consent (opt-in or opt-out) and legitimate
// interests (objection).
func Decidable(purpose *core.Object) (result bool, err error) {
	return privacyDecidable(purpose), nil
}

func privacyDecidable(purpose *core.Object) bool {
	basis := purpose.Get("legalBasis")
	return basis == "consent" || basis == "legitimate-interests"
}

// privacyStateOf is `{ allowed, reason }`.
func privacyStateOf(allowed bool, reason string) *core.Object {
	return core.NewObject("allowed", allowed, "reason", reason)
}

// ConsentState (privacy.ts consentState): The processing decision for one purpose and subject. Restriction holds
// back everything except legal obligations and vital interests; bases other than consent and legitimate interests
// are allowed without a record. Opt-out purposes and legitimate interests are allowed until the person withdraws or
// objects; opt-in consent needs a live grant for the current version (unless the purpose keeps older grants valid).
// restricted is false, true or "erased" (see RestrictionState).
func ConsentState(purpose *core.Object, consent *core.Object, restricted any, now int64) (result *core.Object, err error) {
	return privacyConsentState(purpose, consent, restricted, now), nil
}

func privacyConsentState(purpose *core.Object, consent *core.Object, restricted any, now int64) *core.Object {
	if truthy(purpose.Get("archived")) {
		return privacyStateOf(false, "PURPOSE_ARCHIVED")
	}
	basis := purpose.Get("legalBasis")
	if truthy(restricted) && basis != "legal-obligation" && basis != "vital-interests" {
		if restricted == "erased" {
			return privacyStateOf(false, "ERASED")
		}
		return privacyStateOf(false, "RESTRICTED")
	}
	withdrawn := consent != nil && !truthy(consent.Get("granted"))
	if basis == "legitimate-interests" {
		if withdrawn {
			return privacyStateOf(false, "OBJECTED")
		}
		return privacyStateOf(true, "LEGITIMATE_INTERESTS")
	}
	if basis != "consent" {
		return privacyStateOf(true, "LEGAL_BASIS")
	}
	if withdrawn {
		return privacyStateOf(false, "CONSENT_WITHDRAWN")
	}
	if purpose.Get("mode") == "opt-out" {
		return privacyStateOf(true, "NOT_OPTED_OUT")
	}
	if consent == nil {
		return privacyStateOf(false, "NO_CONSENT")
	}
	if expiresAt := consent.Get("expiresAt"); !isUndefined(expiresAt) && privacyLessOrEqual(expiresAt, float64(now)) {
		return privacyStateOf(false, "CONSENT_EXPIRED")
	}
	if truthy(purpose.Get("reconsentOnVersion")) && jsLess(consent.Get("purposeVersion"), purpose.Get("version")) {
		return privacyStateOf(false, "CONSENT_OUTDATED")
	}
	return privacyStateOf(true, "CONSENT_GIVEN")
}

// privacyLessOrEqual is the JavaScript `a <= b` over record members.
func privacyLessOrEqual(a, b any) bool {
	left, leftString := a.(string)
	right, rightString := b.(string)
	if leftString && rightString {
		return compareUTF16(left, right) <= 0
	}
	return jsNumber(a) <= jsNumber(b)
}

// RestrictionOf (privacy.ts restrictionOf): the subject's restriction record, if any.
func RestrictionOf(ctx context.Context, tx core.IamStore, tenantID string, subject string) (result *core.Object, err error) {
	found, err := tx.Find(ctx, "privacyRestrictions", core.NewObject("tenantId", tenantID, "subject", subject), nil)
	if err != nil || len(found) == 0 {
		return nil, err
	}
	return found[0], nil
}

// RestrictionState (privacy.ts restrictionState): How a restriction record feeds `consentState`: none (false), an
// ordinary restriction (true), or an erasure's suppression marker ("erased").
func RestrictionState(restriction *core.Object) (result any, err error) {
	return privacyRestrictionState(restriction), nil
}

func privacyRestrictionState(restriction *core.Object) any {
	if restriction == nil {
		return false
	}
	if truthy(restriction.Get("erased")) {
		return "erased"
	}
	return true
}

// ConsentsOf (privacy.ts consentsOf): The subject's current decision on every purpose, keyed by purpose ID.
func ConsentsOf(ctx context.Context, tx core.IamStore, tenantID string, subject string) (result map[string]*core.Object, err error) {
	consents, err := tx.Find(ctx, "privacyConsents", core.NewObject("tenantId", tenantID, "subject", subject), nil)
	if err != nil {
		return nil, err
	}
	result = make(map[string]*core.Object, len(consents))
	for _, consent := range consents {
		result[jsString(consent.Get("purposeId"))] = consent
	}
	return result, nil
}

// MentionsConsents (privacy.ts mentionsConsents): whether any statement of the documents names `principal.consents`
// in a condition.
func MentionsConsents(documents []any) bool {
	return anyConditionNames(documents, ConsentContextKey)
}

// ConsentContext (privacy.ts consentContext): Policy context for a person in their own tenant: `principal.consents`
// lists the keys of the consent and legitimate-interest purposes that may be processed for them right now (granted,
// not opted out, not objected to, not restricted). Service accounts and agents are not data subjects, so theirs is
// empty.
func ConsentContext(ctx context.Context, tx core.IamStore, tenantID string, identity *core.Object, now int64) (result *core.Object, err error) {
	empty := core.NewObject(ConsentContextKey, []any{})
	if identity.Get("kind") != "user" || identity.Get("tenantId") != tenantID {
		return empty, nil
	}
	all, err := tx.Find(ctx, "privacyPurposes", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	var purposes []*core.Object
	for _, purpose := range all {
		if privacyDecidable(purpose) && !truthy(purpose.Get("archived")) {
			purposes = append(purposes, purpose)
		}
	}
	if len(purposes) == 0 {
		return empty, nil
	}
	subject := privacyIdentitySubject(jsString(identity.Get("id")))
	consents, err := ConsentsOf(ctx, tx, tenantID, subject)
	if err != nil {
		return nil, err
	}
	restriction, err := RestrictionOf(ctx, tx, tenantID, subject)
	if err != nil {
		return nil, err
	}
	restricted := restriction != nil
	keys := []any{}
	for _, purpose := range purposes {
		if truthy(privacyConsentState(purpose, consents[jsString(purpose.Get("id"))], restricted, now).Get("allowed")) {
			keys = append(keys, purpose.Get("key"))
		}
	}
	privacySortDefault(keys)
	return core.NewObject(ConsentContextKey, keys), nil
}

// privacySortDefault is Array.prototype.sort without a comparator: undefined last, everything else by String() in UTF-16
// code unit order (stable).
func privacySortDefault(items []any) {
	sort.SliceStable(items, func(i, j int) bool {
		a, b := items[i], items[j]
		if isUndefined(a) || isUndefined(b) {
			return !isUndefined(a) && isUndefined(b)
		}
		return compareUTF16(jsString(a), jsString(b)) < 0
	})
}

// privacyReceiptKey is the HMAC key consent receipts are signed with.
func privacyReceiptKey(secret string) []byte {
	key := sha256.Sum256(utf8Bytes("better-iam:privacy-receipt:" + secret))
	return key[:]
}

// ReceiptFromEvent (privacy.ts receiptFromEvent): The receipt of a recorded decision; receipts are deterministic, so
// they are rebuilt rather than stored.
func ReceiptFromEvent(secret string, event *core.Object) (result *core.Object, err error) {
	body := core.NewObject(
		"version", 1.0,
		"receiptId", event.Get("receiptId"),
		"tenantId", event.Get("tenantId"),
		"subject", event.Get("subject"),
		"purpose", core.NewObject(
			"key", event.Get("purposeKey"),
			"name", event.Get("purposeName"),
			"version", event.Get("purposeVersion"),
			"legalBasis", event.Get("legalBasis"),
		),
		"granted", event.Get("granted"),
		"recordedAt", event.Get("recordedAt"),
		"source", event.Get("source"),
	)
	if method := event.Get("method"); truthy(method) {
		body.Set("method", method)
	}
	return SignReceipt(secret, body), nil
}

// SignReceipt (privacy.ts signReceipt): the body with its `signature` (HMAC-SHA256 over the canonical JSON,
// base64url).
func SignReceipt(secret string, body *core.Object) *core.Object {
	mac := hmac.New(sha256.New, privacyReceiptKey(secret))
	mac.Write(utf8Bytes(core.CanonicalJSON(body)))
	signature := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return body.Spread(core.NewObject("signature", signature))
}

// ReceiptSignatureValid (privacy.ts receiptSignatureValid): Whether a receipt was signed with one of the
// deployment's secrets (the current one or a previous one).
func ReceiptSignatureValid(secrets []string, receipt *core.Object) (result bool, err error) {
	if receipt == nil {
		return false, &core.TypeError{Message: "Cannot destructure 'receipt' as it is null."}
	}
	signature, ok := receipt.Get("signature").(string)
	if !ok {
		return false, nil
	}
	body := receipt.Spread()
	body.Delete("signature")
	for _, secret := range secrets {
		if SameHash(SignReceipt(secret, body).Get("signature"), signature) {
			return true, nil
		}
	}
	return false, nil
}

// privacyRequestAlphabet is Crockford base32.
const privacyRequestAlphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// RequestNumber (privacy.ts requestNumber): A request reference: `DSR-` and eight characters of Crockford base32.
func RequestNumber() (result string, err error) {
	var bytes [8]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", err
	}
	var out strings.Builder
	out.WriteString("DSR-")
	for _, b := range bytes {
		out.WriteByte(privacyRequestAlphabet[b&31])
	}
	return out.String(), nil
}

// ResponseWindow (privacy.ts responseWindow): The response window for a regulation, shortened by the tenant's own
// `responseDays` when set: `{ responseDays, extensionDays }`.
func ResponseWindow(regulation string, settings *core.Object) (result *core.Object, err error) {
	statutory, ok := RegulationDeadlines.Object(regulation)
	if !ok {
		return nil, &core.TypeError{Message: "Cannot read properties of undefined (reading 'responseDays')"}
	}
	statutoryDays := jsNumber(statutory.Get("responseDays"))
	responseDays := statutoryDays
	if own := member(settings.Get("responseDays"), regulation); !isUndefined(own) {
		responseDays = privacyMin(jsNumber(own), statutoryDays)
	}
	return core.NewObject("responseDays", responseDays, "extensionDays", statutory.Get("extensionDays")), nil
}

// privacyMin is Math.min over two numbers (NaN wins).
func privacyMin(a, b float64) float64 {
	if math.IsNaN(a) || math.IsNaN(b) {
		return math.NaN()
	}
	return math.Min(a, b)
}

// DayMs is privacy.ts dayMs.
const DayMs = 86400000

// RequestOverdue (privacy.ts requestOverdue): A request is overdue once its deadline passed while it is still being
// handled.
func RequestOverdue(request *core.Object, now int64) (result bool, err error) {
	dueAt := request.Get("dueAt")
	return request.Get("status") == "open" && !isUndefined(dueAt) && privacyLessOrEqual(dueAt, float64(now)), nil
}

// privacyHoldLive is `hold.expiresAt === undefined || hold.expiresAt > now`.
func privacyHoldLive(hold *core.Object, now int64) bool {
	expiresAt := hold.Get("expiresAt")
	return isUndefined(expiresAt) || jsLess(float64(now), expiresAt)
}

// ActiveHold (privacy.ts activeHold): The live legal hold on a subject, if any.
func ActiveHold(ctx context.Context, tx core.IamStore, tenantID string, subject string, now int64) (result *core.Object, err error) {
	holds, err := tx.Find(ctx, "privacyHolds", core.NewObject("tenantId", tenantID, "subject", subject), nil)
	if err != nil {
		return nil, err
	}
	for _, hold := range holds {
		if privacyHoldLive(hold, now) {
			return hold, nil
		}
	}
	return nil, nil
}

// AssertNoLegalHold (privacy.ts assertNoLegalHold): Refuses to delete a person under a legal hold (`LEGAL_HOLD`,
// 409). Called from identity deletion, so every path that deletes (an administrator, an erasure request, a workflow,
// agent removal) is refused; offboarding and SCIM deprovisioning only disable the account, so its data stays anyway.
func AssertNoLegalHold(ctx context.Context, tx core.IamStore, identity *core.Object, now int64) (err error) {
	if identity.Get("kind") != "user" {
		return nil
	}
	hold, err := ActiveHold(ctx, tx, jsString(identity.Get("tenantId")), privacyIdentitySubject(jsString(identity.Get("id"))), now)
	if err != nil {
		return err
	}
	if hold != nil {
		return core.NewIamError("LEGAL_HOLD", "This person is under a legal hold; release the hold before deleting them", 409)
	}
	return nil
}

// AssertNoTenantLegalHold (privacy.ts assertNoTenantLegalHold): Refuses to delete an organization (or the one above
// it) while a legal hold on anyone in it, or in a tenant below it, is active (`LEGAL_HOLD`, 409): deleting the
// tenant would purge the held people with it.
func AssertNoTenantLegalHold(ctx context.Context, tx core.IamStore, tenantID string, now int64, maxDepth float64) (err error) {
	realms, err := tx.Find(ctx, "tenants", nil, nil)
	if err != nil {
		return err
	}
	subtree := newOrderedSet(tenantID)
	for depth := 0.0; depth < maxDepth; depth++ {
		for _, realm := range realms {
			parentID, ok := realm.Get("parentId").(string)
			if ok && parentID != "" && subtree.Has(parentID) {
				subtree.Add(jsString(realm.Get("id")))
			}
		}
	}
	for _, id := range subtree.Values() {
		holds, err := tx.Find(ctx, "privacyHolds", core.NewObject("tenantId", id), nil)
		if err != nil {
			return err
		}
		for _, hold := range holds {
			if privacyHoldLive(hold, now) {
				return core.NewIamError("LEGAL_HOLD",
					"People in this organization are under a legal hold; release the holds before deleting it", 409)
			}
		}
	}
	return nil
}

// ReleasePrivacyRecords (privacy.ts releasePrivacyRecords): Removes a deleted person's current consent decisions and
// restriction. The consent history stays as proof of what was recorded (erasure redacts it separately), and
// data-subject requests stay as the record of their handling.
func ReleasePrivacyRecords(ctx context.Context, tx core.IamStore, identity *core.Object) (err error) {
	subject := privacyIdentitySubject(jsString(identity.Get("id")))
	consents, err := tx.Find(ctx, "privacyConsents", core.NewObject("tenantId", identity.Get("tenantId"), "subject", subject), nil)
	if err != nil {
		return err
	}
	for _, consent := range consents {
		if err := tx.Delete(ctx, "privacyConsents", jsString(consent.Get("id"))); err != nil {
			return err
		}
	}
	restrictions, err := tx.Find(ctx, "privacyRestrictions", core.NewObject("tenantId", identity.Get("tenantId"), "subject", subject), nil)
	if err != nil {
		return err
	}
	for _, restriction := range restrictions {
		if err := tx.Delete(ctx, "privacyRestrictions", jsString(restriction.Get("id"))); err != nil {
			return err
		}
	}
	return nil
}

// privacyProseControl is /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/.
func privacyProseControl(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c <= 0x08 || c == 0x0b || c == 0x0c || (c >= 0x0e && c <= 0x1f) || c == 0x7f {
			return true
		}
	}
	return false
}

// Prose (privacy.ts prose): Free text up to `max` characters over several lines (tabs and line breaks allowed, other
// controls not).
func Prose(value any, name string, maxValue float64) (result string, err error) {
	s, ok := value.(string)
	if !ok || core.JSTrim(s) == "" || float64(utf16Len(s)) > maxValue || privacyProseControl(s) {
		return "", invalidInput("Invalid " + name)
	}
	return s, nil
}

var purposeKeyPattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{0,63}$`)

// PurposeKey (privacy.ts purposeKey): A purpose key: 1-64 lowercase letters, digits, dots, underscores or hyphens,
// starting with a letter.
func PurposeKey(value any) (result string, err error) {
	key, err := Text(value, "purposeKey", 64)
	if err != nil {
		return "", err
	}
	if !purposeKeyPattern.MatchString(key) {
		return "", invalidInput("Purpose keys use lowercase letters, digits, dots, underscores or hyphens")
	}
	return key, nil
}

// OneOf (privacy.ts oneOf): the value when it is one of the allowed strings.
func OneOf(value any, allowed []any, name string) (result any, err error) {
	if s, ok := value.(string); ok {
		for _, candidate := range allowed {
			if candidate == s {
				return s, nil
			}
		}
	}
	parts := make([]string, len(allowed))
	for index, candidate := range allowed {
		parts[index] = jsString(candidate)
	}
	return nil, invalidInput(name + " must be one of " + strings.Join(parts, ", "))
}

// Days (privacy.ts days): a whole number of days from 1 to maxValue (the TypeScript default, 3650, when maxValue is
// 0).
func Days(value any, name string, maxValue float64) (result float64, err error) {
	if maxValue == 0 {
		maxValue = 3650
	}
	return Integer(value, name, 1, maxValue)
}

// LegalBases is privacy.ts legalBases.
var LegalBases = []string{"consent", "contract", "legal-obligation", "vital-interests", "public-task", "legitimate-interests"}

// RegulationDeadlines is privacy.ts regulationDeadlines.
var RegulationDeadlines = mustObject(`{"gdpr":{"responseDays":30,"extensionDays":60},"uk-gdpr":{"responseDays":30,"extensionDays":60},"ccpa":{"responseDays":45,"extensionDays":45},"lgpd":{"responseDays":15,"extensionDays":0},"pipeda":{"responseDays":30,"extensionDays":30},"other":{"responseDays":30,"extensionDays":30}}`)

// Regulations is privacy.ts regulations.
var Regulations = []string{"gdpr", "uk-gdpr", "ccpa", "lgpd", "pipeda", "other"}

// RejectionReasons is privacy.ts rejectionReasons.
var RejectionReasons = []string{"unverified", "unfounded", "excessive", "exempt", "duplicate", "no-data", "other"}

// SubjectRequestTypes is privacy.ts subjectRequestTypes.
var SubjectRequestTypes = []string{"access", "portability", "erasure", "rectification", "restriction", "objection", "opt-out"}
