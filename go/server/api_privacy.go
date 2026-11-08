package server

// Port of packages/server/src/api/privacy.ts: privacy and consent management. Processing purposes with their lawful
// basis, each person's consent (recorded by the person, by an administrator, or by the application for its own
// customers), signed consent receipts and an append-only history, data-subject requests (access, portability,
// erasure, rectification, restriction, objection, opt-out) with statutory deadlines and automated fulfilment, legal
// holds, and restriction of processing. Policies see `principal.consents`. Managing purposes and settings needs
// `iam:privacy:manage`; reading consents, requests and reports `iam:privacy:read`; recording consents for application
// subjects `iam:privacy:record`; checking them `iam:privacy:check`; handling requests `iam:privacy:handle`. People
// manage their own choices without a permission.

import (
	"context"
	"math"
	"regexp"
	"sort"
	"strings"
	"unicode/utf16"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// PrivacyAPI is the `privacy` API group (packages/server/src/api/privacy.ts createPrivacyApi): every method runs through the
// operation envelope; the router maps POST {basePath}/privacy/{method} onto it.
type PrivacyAPI struct {
	server *ServerContext
}

// CreatePrivacyAPI builds the `privacy` API group.
func CreatePrivacyAPI(server *ServerContext) *PrivacyAPI {
	return &PrivacyAPI{server: server}
}

const (
	pvMaxPurposes            = 200
	pvMaxEvents              = 100
	pvVerificationLifetimeMs = 7 * DayMs
)

// pvMethodPattern is /^[\w .:/-]+$/.
var pvMethodPattern = regexp.MustCompile(`^[A-Za-z0-9_ .:/-]+$`)

// pvCategoryPattern is /^[a-z][a-z0-9_-]{0,63}$/.
var pvCategoryPattern = regexp.MustCompile(`^[a-z][a-z0-9_-]{0,63}$`)

// pvMethod validates the method recorded with a decision: a short label ("" when absent).
func pvMethod(value any) (string, error) {
	if nullish(value) || value == "" {
		return "", nil
	}
	result, err := Text(value, "method", 64)
	if err != nil {
		return "", err
	}
	if !pvMethodPattern.MatchString(result) {
		return "", invalidInput("Invalid method")
	}
	return result, nil
}

// pvEvidence validates the evidence recorded with a decision: free text ("" when absent).
func pvEvidence(value any) (string, error) {
	if nullish(value) || value == "" {
		return "", nil
	}
	return Prose(value, "evidence", 2000)
}

// pvCategories validates a purpose's data categories: at most 32 lowercase identifiers, deduplicated and sorted.
func pvCategories(value any) ([]string, error) {
	if isUndefined(value) {
		return []string{}, nil
	}
	items, err := Strings(value, "dataCategories")
	if err != nil {
		return nil, err
	}
	list := unique(items)
	invalid := len(list) > 32
	for _, item := range list {
		if !pvCategoryPattern.MatchString(item) {
			invalid = true
		}
	}
	if invalid {
		return nil, invalidInput("dataCategories must hold at most 32 lowercase identifiers such as contact or usage")
	}
	sortStable(list, compareUTF16)
	return list, nil
}

// pvOneOf is privacy.ts oneOf over a list of strings.
func pvOneOf(value any, allowed []string, name string) (string, error) {
	result, err := OneOf(value, stringsOf(allowed), name)
	if err != nil {
		return "", err
	}
	return jsString(result), nil
}

// pvSelfSession: privacy self-service is the person's own business, refused for role sessions, delegated agents and
// other tenants.
func pvSelfSession(principal *Principal, tenantID string) error {
	if !ActsInOwnRight(principal.Session) ||
		principal.Session.Get("kind") != "user" ||
		principal.Session.Get("tenantId") != tenantID ||
		principal.Identity.Get("tenantId") != tenantID ||
		principal.Identity.Get("kind") != "user" {
		return core.NewIamError("ACCESS_DENIED", "Privacy choices are made by the person, from a signed-in session of their organization", 403)
	}
	if truthy(principal.Session.Get("impersonatorId")) {
		return core.NewIamError("IMPERSONATION_RESTRICTED", "Privacy choices cannot be made while impersonating", 403)
	}
	return nil
}

// pvPurposeFields validates a purpose input over the previous version (nil when creating).
func pvPurposeFields(input *core.Object, previous *core.Object) (*core.Object, error) {
	var key string
	if previous != nil {
		key = jsString(previous.Get("key"))
	} else {
		validated, err := PurposeKey(input.Get("key"))
		if err != nil {
			return nil, err
		}
		key = validated
	}
	if previous != nil && !isUndefined(input.Get("key")) && input.Get("key") != previous.Get("key") {
		return nil, invalidInput("A purpose key cannot change; create a new purpose")
	}
	name, err := Text(coalesce(input.Get("name"), previousMember(previous, "name")), "name", 120)
	if err != nil {
		return nil, err
	}
	name = core.JSTrim(name)
	description, err := Prose(coalesce(input.Get("description"), previousMember(previous, "description")), "description", 5000)
	if err != nil {
		return nil, err
	}
	legalBasis, err := pvOneOf(coalesce(input.Get("legalBasis"), previousMember(previous, "legalBasis")), LegalBases, "legalBasis")
	if err != nil {
		return nil, err
	}
	mode, err := pvOneOf(coalesce(coalesce(input.Get("mode"), previousMember(previous, "mode")), "opt-in"), []string{"opt-in", "opt-out"}, "mode")
	if err != nil {
		return nil, err
	}
	if mode == "opt-out" && legalBasis != "consent" {
		return nil, invalidInput("Only consent purposes can be opt-out")
	}
	var retention any = core.Undefined
	switch raw := input.Get("retentionDays"); {
	case isUndefined(raw):
		retention = previousMember(previous, "retentionDays")
	case raw == nil:
	default:
		if retention, err = Days(raw, "retentionDays", 36500); err != nil {
			return nil, err
		}
	}
	var lifetime any = core.Undefined
	switch raw := input.Get("consentLifetimeDays"); {
	case isUndefined(raw):
		lifetime = previousMember(previous, "consentLifetimeDays")
	case raw == nil:
	default:
		if lifetime, err = Days(raw, "consentLifetimeDays", 3650); err != nil {
			return nil, err
		}
	}
	if !isUndefined(lifetime) && legalBasis != "consent" {
		return nil, invalidInput("consentLifetimeDays applies to consent purposes only")
	}
	reconsent := coalesce(coalesce(input.Get("reconsentOnVersion"), previousMember(previous, "reconsentOnVersion")), true)
	if _, ok := reconsent.(bool); !ok {
		return nil, invalidInput("reconsentOnVersion must be a boolean")
	}
	values := core.NewObject(
		"uniqueKey", "key:"+key,
		"key", key,
		"name", name,
		"description", description,
		"legalBasis", legalBasis,
		"mode", mode,
	)
	if raw := input.Get("dataCategories"); isUndefined(raw) {
		values.Set("dataCategories", coalesce(previousMember(previous, "dataCategories"), []any{}))
	} else {
		list, err := pvCategories(raw)
		if err != nil {
			return nil, err
		}
		values.Set("dataCategories", stringsOf(list))
	}
	if !isUndefined(retention) {
		values.Set("retentionDays", retention)
	}
	if !isUndefined(lifetime) {
		values.Set("consentLifetimeDays", lifetime)
	}
	values.Set("reconsentOnVersion", reconsent)
	return values, nil
}

// pvPurposeByKey finds a purpose of the tenant by its key.
func pvPurposeByKey(ctx context.Context, tx core.IamStore, tenantID string, key any) (*core.Object, error) {
	validated, err := PurposeKey(key)
	if err != nil {
		return nil, err
	}
	found, err := tx.Find(ctx, "privacyPurposes", core.NewObject("tenantId", tenantID, "uniqueKey", "key:"+validated), nil)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, core.NewIamError("NOT_FOUND", "Purpose not found", 404)
	}
	return found[0], nil
}

// pvConsentRef is the `consent` member of a check or a person's purpose: the decision without its bookkeeping.
func pvConsentRef(consent *core.Object) *core.Object {
	ref := core.NewObject(
		"granted", consent.Get("granted"),
		"purposeVersion", consent.Get("purposeVersion"),
		"recordedAt", consent.Get("recordedAt"),
	)
	if !isUndefined(consent.Get("expiresAt")) {
		ref.Set("expiresAt", consent.Get("expiresAt"))
	}
	ref.Set("receiptId", consent.Get("receiptId"))
	return ref
}

func pvConsentView(consent, purpose *core.Object, restricted bool, now int64) (*core.Object, error) {
	view := core.NewObject(
		"id", consent.Get("id"),
		"purposeKey", consent.Get("purposeKey"),
		"subject", consent.Get("subject"),
	)
	if truthy(consent.Get("identityId")) {
		view.Set("identityId", consent.Get("identityId"))
	}
	if !isUndefined(consent.Get("externalId")) {
		view.Set("externalId", consent.Get("externalId"))
	}
	view.Set("granted", consent.Get("granted"))
	view.Set("purposeVersion", consent.Get("purposeVersion"))
	view.Set("source", consent.Get("source"))
	if truthy(consent.Get("method")) {
		view.Set("method", consent.Get("method"))
	}
	view.Set("recordedAt", consent.Get("recordedAt"))
	view.Set("recordedBy", consent.Get("recordedBy"))
	if !isUndefined(consent.Get("expiresAt")) {
		view.Set("expiresAt", consent.Get("expiresAt"))
	}
	view.Set("receiptId", consent.Get("receiptId"))
	state, err := ConsentState(purpose, consent, restricted, now)
	if err != nil {
		return nil, err
	}
	view.Set("state", state)
	return view, nil
}

func pvHistoryEntry(event *core.Object) *core.Object {
	entry := core.NewObject(
		"receiptId", event.Get("receiptId"),
		"purposeKey", event.Get("purposeKey"),
		"purposeVersion", event.Get("purposeVersion"),
		"subject", event.Get("subject"),
		"granted", event.Get("granted"),
		"source", event.Get("source"),
	)
	for _, key := range []string{"method", "evidence", "ip", "userAgent"} {
		if truthy(event.Get(key)) {
			entry.Set(key, event.Get(key))
		}
	}
	entry.Set("recordedAt", event.Get("recordedAt"))
	entry.Set("recordedBy", event.Get("recordedBy"))
	if truthy(event.Get("redacted")) {
		entry.Set("redacted", true)
	}
	return entry
}

// pvHistory is a decision history newest first (at most limit entries), optionally for one purpose key.
func pvHistory(events []*core.Object, key any, limit int) []any {
	var kept []*core.Object
	for _, event := range events {
		if isUndefined(key) || event.Get("purposeKey") == key {
			kept = append(kept, event)
		}
	}
	sortStable(kept, pvNewestRecorded)
	if len(kept) > limit {
		kept = kept[:limit]
	}
	out := make([]any, len(kept))
	for index, event := range kept {
		out[index] = pvHistoryEntry(event)
	}
	return out
}

// pvNewestRecorded is `b.recordedAt - a.recordedAt || (a.id < b.id ? -1 : 1)`.
func pvNewestRecorded(a, b *core.Object) int {
	if difference := jsNumber(b.Get("recordedAt")) - jsNumber(a.Get("recordedAt")); difference != 0 {
		return pvSign(difference)
	}
	if compareUTF16(jsString(a.Get("id")), jsString(b.Get("id"))) < 0 {
		return -1
	}
	return 1
}

func pvSign(value float64) int {
	switch {
	case value < 0:
		return -1
	case value > 0:
		return 1
	}
	return 0
}

// pvByID is `a.id < b.id ? -1 : 1` over a member.
func pvByMember(key string) func(a, b *core.Object) int {
	return func(a, b *core.Object) int {
		if compareUTF16(jsString(a.Get(key)), jsString(b.Get(key))) < 0 {
			return -1
		}
		return 1
	}
}

// pvRequestView is a request without its confirmation token and reminder bookkeeping, with `overdue`.
func pvRequestView(request *core.Object, now int64, subjectName string) (*core.Object, error) {
	view := core.NewObject(
		"id", request.Get("id"),
		"tenantId", request.Get("tenantId"),
		"number", request.Get("number"),
		"type", request.Get("type"),
		"regulation", request.Get("regulation"),
		"status", request.Get("status"),
		"subject", request.Get("subject"),
	)
	if truthy(request.Get("identityId")) {
		view.Set("identityId", request.Get("identityId"))
	}
	if !isUndefined(request.Get("externalId")) {
		view.Set("externalId", request.Get("externalId"))
	}
	if subjectName != "" {
		view.Set("subjectName", subjectName)
	}
	for _, key := range []string{"requesterEmail", "requesterName", "details"} {
		if truthy(request.Get(key)) {
			view.Set(key, request.Get(key))
		}
	}
	if keys, ok := request.Get("purposeKeys").([]any); ok && len(keys) > 0 {
		view.Set("purposeKeys", keys)
	}
	view.Set("channel", request.Get("channel"))
	view.Set("verification", request.Get("verification"))
	view.Set("submittedAt", request.Get("submittedAt"))
	for _, key := range []string{"receivedAt", "dueAt", "extendedAt"} {
		if !isUndefined(request.Get(key)) {
			view.Set(key, request.Get(key))
		}
	}
	if truthy(request.Get("extensionReason")) {
		view.Set("extensionReason", request.Get("extensionReason"))
	}
	if truthy(request.Get("assigneeId")) {
		view.Set("assigneeId", request.Get("assigneeId"))
	}
	if !isUndefined(request.Get("closedAt")) {
		view.Set("closedAt", request.Get("closedAt"))
	}
	for _, key := range []string{"closedBy", "rejectionReason"} {
		if truthy(request.Get(key)) {
			view.Set(key, request.Get(key))
		}
	}
	if actions, ok := request.Get("actions").([]any); ok && len(actions) > 0 {
		view.Set("actions", actions)
	}
	if truthy(request.Get("exportId")) {
		view.Set("exportId", request.Get("exportId"))
	}
	if truthy(request.Get("redacted")) {
		view.Set("redacted", true)
	}
	overdue, err := RequestOverdue(request, now)
	if err != nil {
		return nil, err
	}
	view.Set("overdue", overdue)
	view.Set("events", request.Get("events"))
	return view, nil
}

// pvMineView is the subject's own view of a request: staff notes and assignment stay internal.
func pvMineView(request *core.Object, now int64) (*core.Object, error) {
	view, err := pvRequestView(request, now, "")
	if err != nil {
		return nil, err
	}
	rest := view.Spread()
	rest.Delete("assigneeId")
	rest.Delete("closedBy")
	events, _ := view.Get("events").([]any)
	shown := []any{}
	for _, item := range events {
		event, _ := item.(*core.Object)
		if event == nil {
			continue
		}
		what := event.Get("what")
		if what == "note" || what == "assigned" {
			continue
		}
		note := event.Get("note")
		out := event.Spread()
		out.Delete("note")
		out.Delete("by")
		out.Set("by", "organization")
		if (what == "rejected" || what == "extended" || what == "completed") && truthy(note) {
			out.Set("note", note)
		}
		shown = append(shown, out)
	}
	rest.Set("events", shown)
	return rest, nil
}

// pvPushEvent appends an event to a request's timeline, keeping the last 100.
func pvPushEvent(request *core.Object, event *core.Object) []any {
	events, _ := request.Get("events").([]any)
	next := append(append([]any{}, events...), event)
	if len(next) > pvMaxEvents {
		next = next[len(next)-pvMaxEvents:]
	}
	return next
}

// pvEvent is a request timeline event: at, by, what and an optional note ("" when absent).
func pvEvent(at int64, by any, what string, note string) *core.Object {
	event := core.NewObject("at", float64(at), "by", by, "what", what)
	if note != "" {
		event.Set("note", note)
	}
	return event
}

// pvCanEmail is whether an email delivery callback exists; privacy emails are optional niceties otherwise.
func pvCanEmail(server *ServerContext) bool {
	options := server.Options
	return options != nil && options.Authentication != nil && options.Authentication.SendEmail != nil
}

// pvNotifyContact tells the privacy contact about a request that now needs handling.
func pvNotifyContact(ctx context.Context, server *ServerContext, tx core.IamStore, tenant, request *core.Object) error {
	tenantID := jsString(tenant.Get("id"))
	settings, err := PrivacySettings(ctx, tx, tenantID)
	if err != nil {
		return err
	}
	if !truthy(settings.Get("contactEmail")) || !pvCanEmail(server) {
		return nil
	}
	payload := core.NewObject(
		"tenantId", tenantID,
		"tenantName", tenant.Get("name"),
		"requestId", request.Get("id"),
		"number", request.Get("number"),
		"type", request.Get("type"),
		"regulation", request.Get("regulation"),
	)
	if dueAt := request.Get("dueAt"); !isUndefined(dueAt) {
		payload.Set("dueAt", jsString(dueAt))
	}
	payload.Set("channel", request.Get("channel"))
	_, err = server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
		TenantID: tenantID, Kind: "email", To: jsString(settings.Get("contactEmail")), Template: "privacy-request-received", Payload: payload,
	})
	return err
}

// pvSubjectAddress is where the subject hears back: their account's address, or the requester's (nil when none).
func pvSubjectAddress(ctx context.Context, tx core.IamStore, request *core.Object) (*string, error) {
	if identityID := request.Get("identityId"); truthy(identityID) {
		identity, err := tx.Get(ctx, "identities", jsString(identityID))
		if err != nil {
			return nil, err
		}
		if identity != nil && truthy(identity.Get("email")) && identity.Get("status") != "deleted" {
			address := jsString(identity.Get("email"))
			return &address, nil
		}
	}
	if requester := request.Get("requesterEmail"); !isUndefined(requester) {
		address := jsString(requester)
		return &address, nil
	}
	return nil, nil
}

// pvNotifySubject emails the subject about a completed, rejected or extended request; to (nil: look it up) is the
// address.
func pvNotifySubject(ctx context.Context, server *ServerContext, tx core.IamStore, tenant, request *core.Object, event string, to *string) error {
	address := to
	if address == nil {
		found, err := pvSubjectAddress(ctx, tx, request)
		if err != nil {
			return err
		}
		address = found
	}
	if address == nil || *address == "" || !pvCanEmail(server) {
		return nil
	}
	tenantID := jsString(tenant.Get("id"))
	payload := core.NewObject(
		"tenantId", tenantID,
		"tenantName", tenant.Get("name"),
		"requestId", request.Get("id"),
		"number", request.Get("number"),
		"type", request.Get("type"),
		"event", event,
	)
	if dueAt := request.Get("dueAt"); !isUndefined(dueAt) {
		payload.Set("dueAt", jsString(dueAt))
	}
	if event == "rejected" && truthy(request.Get("rejectionReason")) {
		payload.Set("reason", request.Get("rejectionReason"))
	}
	if event == "completed" && truthy(request.Get("exportId")) {
		payload.Set("exportReady", "true")
	}
	if truthy(request.Get("identityId")) && event == "completed" && request.Get("type") != "erasure" {
		payload.Set("account", "true")
	}
	_, err := server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
		TenantID: tenantID, Kind: "email", To: *address, Template: "privacy-request-update", Payload: payload,
	})
	return err
}

// pvConsentInput is one decision to record.
type pvConsentInput struct {
	tenantID   string
	purpose    *core.Object
	subject    *core.Object
	granted    bool
	source     string
	method     string
	evidence   string
	recordedBy string
	at         float64
	// version is the purpose version decided on when hasVersion (otherwise the current one).
	hasVersion bool
	version    any
	client     *core.SessionClientInfo
}

// pvSliceUTF16 is `value.slice(0, n)` over UTF-16 code units.
func pvSliceUTF16(value string, n int) string {
	if utf16Len(value) <= n {
		return value
	}
	return string(utf16.Decode(utf16.Encode([]rune(value))[:n]))
}

// pvWriteConsent records one decision: the current state (unless a newer decision is already recorded, as imports
// can be older) and an entry in the consent history. Returns the signed receipt.
func pvWriteConsent(ctx context.Context, server *ServerContext, tx core.IamStore, input pvConsentInput) (*core.Object, bool, error) {
	purpose, subject := input.purpose, input.subject
	decidable, err := Decidable(purpose)
	if err != nil {
		return nil, false, err
	}
	if !decidable {
		return nil, false, invalidInput("Purpose " + jsString(purpose.Get("key")) + " relies on " + jsString(purpose.Get("legalBasis")) + ", not on consent")
	}
	if truthy(purpose.Get("archived")) && input.granted {
		return nil, false, core.NewIamError("CONFLICT", "Purpose "+jsString(purpose.Get("key"))+" is archived", 409)
	}
	var purposeVersion any = purpose.Get("version")
	if input.hasVersion {
		version, err := Integer(input.version, "version", 1, jsNumber(purpose.Get("version")))
		if err != nil {
			return nil, false, err
		}
		purposeVersion = version
	}
	receiptID := ID()
	var expiresAt any = core.Undefined
	if lifetime := purpose.Get("consentLifetimeDays"); input.granted && !isUndefined(lifetime) {
		expiresAt = input.at + jsNumber(lifetime)*DayMs
	}
	uniqueKey := jsString(purpose.Get("id")) + ":" + jsString(subject.Get("key"))
	found, err := tx.Find(ctx, "privacyConsents", core.NewObject("tenantId", input.tenantID, "uniqueKey", uniqueKey), nil)
	if err != nil {
		return nil, false, err
	}
	var existing *core.Object
	if len(found) > 0 {
		existing = found[0]
	}
	event := core.NewObject(
		"id", receiptID,
		"tenantId", input.tenantID,
		"receiptId", receiptID,
		"purposeId", purpose.Get("id"),
		"purposeKey", purpose.Get("key"),
		"purposeName", purpose.Get("name"),
		"legalBasis", purpose.Get("legalBasis"),
		"purposeVersion", purposeVersion,
		"subject", subject.Get("key"),
	)
	if truthy(subject.Get("identityId")) {
		event.Set("identityId", subject.Get("identityId"))
	}
	if !isUndefined(subject.Get("externalId")) {
		event.Set("externalId", subject.Get("externalId"))
	}
	event.Set("granted", input.granted)
	event.Set("source", input.source)
	if input.method != "" {
		event.Set("method", input.method)
	}
	if input.evidence != "" {
		event.Set("evidence", input.evidence)
	}
	if input.client != nil && input.client.IP != "" {
		event.Set("ip", input.client.IP)
	}
	if input.client != nil && input.client.UserAgent != "" {
		event.Set("userAgent", pvSliceUTF16(input.client.UserAgent, 512))
	}
	event.Set("recordedAt", input.at)
	event.Set("recordedBy", input.recordedBy)
	current := existing == nil || jsNumber(existing.Get("recordedAt")) <= input.at
	if current {
		var recordID any
		if existing != nil {
			recordID = coalesce(existing.Get("id"), nil)
		}
		if nullish(recordID) {
			recordID = ID()
		}
		record := core.NewObject(
			"id", recordID,
			"tenantId", input.tenantID,
			"uniqueKey", uniqueKey,
			"purposeId", purpose.Get("id"),
			"purposeKey", purpose.Get("key"),
			"subject", subject.Get("key"),
		)
		if truthy(subject.Get("identityId")) {
			record.Set("identityId", subject.Get("identityId"))
		}
		if !isUndefined(subject.Get("externalId")) {
			record.Set("externalId", subject.Get("externalId"))
		}
		record.Set("granted", input.granted)
		record.Set("purposeVersion", purposeVersion)
		record.Set("source", input.source)
		if input.method != "" {
			record.Set("method", input.method)
		}
		record.Set("recordedAt", input.at)
		record.Set("recordedBy", input.recordedBy)
		if !isUndefined(expiresAt) {
			record.Set("expiresAt", expiresAt)
		}
		record.Set("receiptId", receiptID)
		if existing != nil {
			_, err = tx.Put(ctx, "privacyConsents", record)
		} else {
			_, err = tx.Insert(ctx, "privacyConsents", record)
		}
		if err != nil {
			return nil, false, err
		}
	}
	if _, err := tx.Insert(ctx, "privacyConsentEvents", event); err != nil {
		return nil, false, err
	}
	receipt, err := ReceiptFromEvent(server.Options.Secret, event)
	if err != nil {
		return nil, false, err
	}
	return receipt, current, nil
}

// pvConsentsOrdered is consentsOf with the Map's insertion order kept: the subject's current decision on every
// purpose, keyed by purpose ID.
func pvConsentsOrdered(ctx context.Context, tx core.IamStore, tenantID, subject string) ([]string, map[string]*core.Object, error) {
	found, err := tx.Find(ctx, "privacyConsents", core.NewObject("tenantId", tenantID, "subject", subject), nil)
	if err != nil {
		return nil, nil, err
	}
	var order []string
	byPurpose := map[string]*core.Object{}
	for _, consent := range found {
		purposeID := jsString(consent.Get("purposeId"))
		if _, seen := byPurpose[purposeID]; !seen {
			order = append(order, purposeID)
		}
		byPurpose[purposeID] = consent
	}
	return order, byPurpose, nil
}

// pvISO is `new Date(value).toISOString()`.
func pvISO(value any) string { return isoString(jsNumber(value)) }

// pvBuildExport is everything the tenant holds about a subject, as JSON: the answer to an access or portability
// request. includeActivity adds the person's own activity from the audit log (only when the handler may read it).
func pvBuildExport(ctx context.Context, server *ServerContext, tx core.IamStore, tenant, request *core.Object, scope string, includeActivity bool) (*core.Object, error) {
	tenantID := jsString(tenant.Get("id"))
	subject := jsString(request.Get("subject"))
	now := server.Now()
	purposeList, err := tx.Find(ctx, "privacyPurposes", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	var purposeOrder []string
	purposes := map[string]*core.Object{}
	for _, purpose := range purposeList {
		purposeID := jsString(purpose.Get("id"))
		if _, seen := purposes[purposeID]; !seen {
			purposeOrder = append(purposeOrder, purposeID)
		}
		purposes[purposeID] = purpose
	}
	restriction, err := RestrictionOf(ctx, tx, tenantID, subject)
	if err != nil {
		return nil, err
	}
	restricted, err := RestrictionState(restriction)
	if err != nil {
		return nil, err
	}
	consentOrder, consentMap, err := pvConsentsOrdered(ctx, tx, tenantID, subject)
	if err != nil {
		return nil, err
	}
	consents := []any{}
	for _, purposeID := range consentOrder {
		consent := consentMap[purposeID]
		purpose := purposes[jsString(consent.Get("purposeId"))]
		entry := core.NewObject("purpose", consent.Get("purposeKey"))
		if purpose != nil {
			entry.Set("purposeName", coalesce(purpose.Get("name"), consent.Get("purposeKey")))
		} else {
			entry.Set("purposeName", consent.Get("purposeKey"))
		}
		entry.Set("granted", consent.Get("granted"))
		entry.Set("purposeVersion", consent.Get("purposeVersion"))
		entry.Set("recordedAt", pvISO(consent.Get("recordedAt")))
		if expires := consent.Get("expiresAt"); !isUndefined(expires) {
			entry.Set("expiresAt", pvISO(expires))
		}
		entry.Set("source", consent.Get("source"))
		if purpose != nil {
			state, err := ConsentState(purpose, consent, restricted, now)
			if err != nil {
				return nil, err
			}
			entry.Set("state", state.Get("reason"))
		}
		consents = append(consents, entry)
	}
	events, err := tx.Find(ctx, "privacyConsentEvents", core.NewObject("tenantId", tenantID, "subject", subject), nil)
	if err != nil {
		return nil, err
	}
	sortStable(events, func(a, b *core.Object) int {
		return pvSign(jsNumber(a.Get("recordedAt")) - jsNumber(b.Get("recordedAt")))
	})
	history := make([]any, 0, len(events))
	for _, event := range events {
		entry := core.NewObject(
			"purpose", event.Get("purposeKey"),
			"granted", event.Get("granted"),
			"purposeVersion", event.Get("purposeVersion"),
			"recordedAt", pvISO(event.Get("recordedAt")),
			"source", event.Get("source"),
		)
		for _, key := range []string{"method", "evidence", "ip"} {
			if truthy(event.Get(key)) {
				entry.Set(key, event.Get(key))
			}
		}
		entry.Set("receiptId", event.Get("receiptId"))
		history = append(history, entry)
	}
	processing := []any{}
	for _, purposeID := range purposeOrder {
		purpose := purposes[purposeID]
		if truthy(purpose.Get("archived")) {
			continue
		}
		entry := core.NewObject(
			"purpose", purpose.Get("key"),
			"name", purpose.Get("name"),
			"description", purpose.Get("description"),
			"legalBasis", purpose.Get("legalBasis"),
			"dataCategories", purpose.Get("dataCategories"),
		)
		if retention := purpose.Get("retentionDays"); !isUndefined(retention) {
			entry.Set("retentionDays", retention)
		}
		processing = append(processing, entry)
	}
	requestRows, err := tx.Find(ctx, "privacyRequests", core.NewObject("tenantId", tenantID, "subject", subject), nil)
	if err != nil {
		return nil, err
	}
	requests := make([]any, 0, len(requestRows))
	for _, item := range requestRows {
		entry := core.NewObject(
			"number", item.Get("number"),
			"type", item.Get("type"),
			"status", item.Get("status"),
			"submittedAt", pvISO(item.Get("submittedAt")),
		)
		if closed := item.Get("closedAt"); !isUndefined(closed) {
			entry.Set("closedAt", pvISO(closed))
		}
		requests = append(requests, entry)
	}
	var subjectRef *core.Object
	switch {
	case truthy(request.Get("identityId")):
		subjectRef = core.NewObject("kind", "account", "id", request.Get("identityId"))
	case !isUndefined(request.Get("externalId")):
		subjectRef = core.NewObject("kind", "external", "id", request.Get("externalId"))
	default:
		subjectRef = core.NewObject("kind", "requester", "email", coalesce(request.Get("requesterEmail"), ""))
	}
	base := core.NewObject(
		"format", "better-iam.privacy-export",
		"version", 1.0,
		"scope", scope,
		"generatedAt", isoString(float64(now)),
		"organization", core.NewObject("id", tenant.Get("id"), "name", tenant.Get("name")),
		"request", core.NewObject("number", request.Get("number"), "type", request.Get("type"), "regulation", request.Get("regulation")),
		"subject", subjectRef,
		"consents", consents,
		"consentHistory", history,
	)
	var identity *core.Object
	if identityID := request.Get("identityId"); truthy(identityID) {
		if identity, err = tx.Get(ctx, "identities", jsString(identityID)); err != nil {
			return nil, err
		}
	}
	if identity == nil || identity.Get("status") == "deleted" {
		result := base.Spread()
		if scope == "full" {
			result.Set("processing", processing)
			result.Set("requests", requests)
		}
		return result, nil
	}
	identityID := jsString(identity.Get("id"))
	profile := PublicIdentity(identity)
	progress, err := tx.Find(ctx, "onboardingProgress", core.NewObject("tenantId", tenantID, "subjectId", identityID), nil)
	if err != nil {
		return nil, err
	}
	onboarding := make([]any, 0, len(progress))
	for _, row := range progress {
		rest := row.Spread()
		rest.Delete("id")
		rest.Delete("tenantId")
		rest.Delete("uniqueKey")
		onboarding = append(onboarding, rest)
	}
	acceptances, err := tx.Find(ctx, "agreementAcceptances", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	agreements := make([]any, 0, len(acceptances))
	for _, acceptance := range acceptances {
		agreement, err := tx.Get(ctx, "agreements", jsString(acceptance.Get("agreementId")))
		if err != nil {
			return nil, err
		}
		name := acceptance.Get("agreementId")
		if agreement != nil {
			name = coalesce(agreement.Get("name"), acceptance.Get("agreementId"))
		}
		agreements = append(agreements, core.NewObject(
			"agreement", name,
			"version", acceptance.Get("version"),
			"acceptedAt", pvISO(acceptance.Get("acceptedAt")),
		))
	}
	if scope == "provided" {
		profileOut := core.NewObject("name", profile.Get("name"))
		for _, key := range []string{"email", "phone", "attributes"} {
			if truthy(profile.Get(key)) {
				profileOut.Set(key, profile.Get(key))
			}
		}
		result := base.Spread()
		result.Set("profile", profileOut)
		result.Set("onboarding", onboarding)
		result.Set("agreements", agreements)
		return result, nil
	}
	groups := []any{}
	memberships, err := tx.Find(ctx, "groupMembers", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	for _, membership := range memberships {
		group, err := tx.Get(ctx, "groups", jsString(membership.Get("groupId")))
		if err != nil {
			return nil, err
		}
		if group != nil && group.Get("tenantId") == tenantID {
			entry := core.NewObject("id", group.Get("id"), "name", group.Get("name"))
			if expires := membership.Get("expiresAt"); !isUndefined(expires) {
				entry.Set("until", pvISO(expires))
			}
			groups = append(groups, entry)
		}
	}
	signIns, err := tx.Get(ctx, "authSignIns", identityID)
	if err != nil {
		return nil, err
	}
	var activity []any
	if includeActivity {
		auditEvents, err := tx.Find(ctx, "audit", core.NewObject("tenantId", tenantID, "actorId", identityID), nil)
		if err != nil {
			return nil, err
		}
		sortStable(auditEvents, func(a, b *core.Object) int {
			if difference := jsNumber(b.Get("timestamp")) - jsNumber(a.Get("timestamp")); difference != 0 {
				return pvSign(difference)
			}
			if compareUTF16(jsString(a.Get("id")), jsString(b.Get("id"))) < 0 {
				return -1
			}
			return 1
		})
		if len(auditEvents) > 5000 {
			auditEvents = auditEvents[:5000]
		}
		activity = make([]any, 0, len(auditEvents))
		for _, event := range auditEvents {
			activity = append(activity, core.NewObject(
				"at", pvISO(event.Get("timestamp")),
				"action", event.Get("action"),
				"resource", event.Get("resourceId"),
				"outcome", event.Get("outcome"),
			))
		}
	}
	bindings, err := server.Decisions.EffectiveBindings(ctx, tx, tenantID, identityID)
	if err != nil {
		return nil, err
	}
	access := make([]any, 0, len(bindings))
	for _, binding := range bindings {
		var role any = binding.Binding.Get("roleId")
		if binding.Role != nil {
			role = coalesce(binding.Role.Get("name"), binding.Binding.Get("roleId"))
		}
		via := "group"
		if binding.ViaGroupID == "" {
			via = "direct"
		}
		entry := core.NewObject("role", role, "via", via)
		if expires := binding.Binding.Get("expiresAt"); !isUndefined(expires) {
			entry.Set("until", pvISO(expires))
		}
		access = append(access, entry)
	}
	sessionRows, err := tx.Find(ctx, "sessions", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	sessions := make([]any, 0, len(sessionRows))
	for _, session := range sessionRows {
		entry := core.NewObject(
			"kind", session.Get("kind"),
			"createdAt", pvISO(session.Get("createdAt")),
			"lastSeenAt", pvISO(session.Get("lastSeenAt")),
			"expiresAt", pvISO(session.Get("expiresAt")),
		)
		if truthy(session.Get("client")) {
			entry.Set("client", session.Get("client"))
		}
		sessions = append(sessions, entry)
	}
	mfa, err := tx.Get(ctx, "authMfa", identityID)
	if err != nil {
		return nil, err
	}
	passkeyRows, err := tx.Find(ctx, "authPasskeys", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	passkeys := make([]any, 0, len(passkeyRows))
	for _, key := range passkeyRows {
		entry := core.NewObject()
		if truthy(key.Get("name")) {
			entry.Set("name", key.Get("name"))
		}
		for _, member := range []string{"createdAt", "lastUsedAt"} {
			if value, ok := key.Get(member).(float64); ok {
				entry.Set(member, isoString(value))
			}
		}
		passkeys = append(passkeys, entry)
	}
	mappings, err := tx.Find(ctx, "externalIdentities", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	linked := make([]any, 0, len(mappings))
	for _, mapping := range mappings {
		linked = append(linked, core.NewObject("issuer", mapping.Get("issuer"), "subject", mapping.Get("subject")))
	}
	// The app launcher's history (applications.ts): which apps, how often, first and last time.
	launchRows, err := tx.Find(ctx, "appLaunches", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	launches := make([]any, 0, len(launchRows))
	for _, launch := range launchRows {
		application, err := tx.Get(ctx, "applications", jsString(launch.Get("appId")))
		if err != nil {
			return nil, err
		}
		var app any = launch.Get("appId")
		if application != nil {
			app = coalesce(application.Get("name"), launch.Get("appId"))
		}
		launches = append(launches, core.NewObject(
			"app", jsString(app),
			"count", jsNumber(launch.Get("count")),
			"firstAt", isoString(jsNumber(launch.Get("firstAt"))),
			"lastAt", isoString(jsNumber(launch.Get("lastAt"))),
		))
	}
	accessRows, err := tx.Find(ctx, "accessRequests", core.NewObject("tenantId", tenantID, "requesterId", identityID), nil)
	if err != nil {
		return nil, err
	}
	packageRows, err := tx.Find(ctx, "packageRequests", core.NewObject("tenantId", tenantID, "identityId", identityID), nil)
	if err != nil {
		return nil, err
	}
	accessRequests := make([]any, 0, len(accessRows)+len(packageRows))
	for _, item := range accessRows {
		entry := core.NewObject("kind", "access", "status", item.Get("status"))
		if at, ok := item.Get("createdAt").(float64); ok {
			entry.Set("at", isoString(at))
		}
		accessRequests = append(accessRequests, entry)
	}
	for _, item := range packageRows {
		entry := core.NewObject("kind", "package", "status", item.Get("status"))
		if at, ok := item.Get("requestedAt").(float64); ok {
			entry.Set("at", isoString(at))
		}
		accessRequests = append(accessRequests, entry)
	}
	result := base.Spread()
	result.Set("profile", profile)
	result.Set("groups", groups)
	result.Set("access", access)
	result.Set("sessions", sessions)
	if signIns != nil {
		summary := core.NewObject()
		if lastAt, ok := signIns.Get("lastAt").(float64); ok {
			summary.Set("lastAt", isoString(lastAt))
		}
		if truthy(signIns.Get("lastClient")) {
			summary.Set("lastClient", signIns.Get("lastClient"))
		}
		summary.Set("failedAttempts", coalesce(signIns.Get("failedAttempts"), 0.0))
		result.Set("signIns", summary)
	}
	result.Set("mfa", core.NewObject("enabled", mfa != nil && truthy(mfa.Get("enabled"))))
	result.Set("passkeys", passkeys)
	result.Set("linkedSignIns", linked)
	result.Set("appLaunches", launches)
	result.Set("agreements", agreements)
	result.Set("onboarding", onboarding)
	result.Set("accessRequests", accessRequests)
	result.Set("processing", processing)
	result.Set("requests", requests)
	if activity != nil {
		result.Set("activity", activity)
	} else {
		result.Set("activityOmitted", true)
	}
	return result, nil
}

// pvEraseSubject erases what the tenant holds about a subject: the account (through identity deletion, which revokes
// and removes every credential and grant), then the tombstone's name and remaining details, consent decisions and
// history, restrictions, exports, sign-in records and queued messages, and the contact details on the subject's
// requests.
func pvEraseSubject(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenant, request *core.Object) ([]string, error) {
	tenantID := jsString(tenant.Get("id"))
	actions := []string{}
	if identityRef := request.Get("identityId"); truthy(identityRef) {
		identity, err := tx.Get(ctx, "identities", jsString(identityRef))
		if err != nil {
			return nil, err
		}
		if identity != nil && identity.Get("tenantId") == tenantID {
			identityID := jsString(identity.Get("id"))
			address := coalesce(identity.Get("email"), identity.Get("deletedEmail"))
			if identity.Get("status") != "deleted" {
				if _, err := DeleteIdentity(ctx, server, tx, principal, identity); err != nil {
					return nil, err
				}
				// Webhooks, outbound SCIM and Shared Signals remove the account downstream on identity:delete; the
				// address stays out of the permanent audit record.
				if err := server.Events.Audit(ctx, tx, principal, "identity:delete", tenantID, identityID, "allow", false,
					core.NewObject("kind", identity.Get("kind"), "erasure", true)); err != nil {
					return nil, err
				}
				actions = append(actions, "account-deleted")
			}
			tombstone, err := tx.Get(ctx, "identities", identityID)
			if err != nil {
				return nil, err
			}
			if tombstone != nil {
				kept := tombstone.Spread()
				for _, key := range []string{"deletedEmail", "attributes", "description", "phone"} {
					kept.Delete(key)
				}
				kept.Set("name", "Erased person")
				if _, err := tx.Put(ctx, "identities", kept); err != nil {
					return nil, err
				}
			}
			signIns, err := tx.Get(ctx, "authSignIns", identityID)
			if err != nil {
				return nil, err
			}
			if signIns != nil {
				if err := tx.Delete(ctx, "authSignIns", identityID); err != nil {
					return nil, err
				}
			}
			if err := pvDeleteAll(ctx, tx, "authDevices", core.NewObject("tenantId", tenantID, "identityId", identityID)); err != nil {
				return nil, err
			}
			if err := pvDeleteAll(ctx, tx, "onboardingProgress", core.NewObject("tenantId", tenantID, "subjectId", identityID)); err != nil {
				return nil, err
			}
			if truthy(address) {
				if err := pvDeleteAll(ctx, tx, "outbox", core.NewObject("tenantId", tenantID, "to", address)); err != nil {
					return nil, err
				}
			}
			actions = append(actions, "account-details-erased")
		}
	}
	subject := request.Get("subject")
	consentRows, err := tx.Find(ctx, "privacyConsents", core.NewObject("tenantId", tenantID, "subject", subject), nil)
	if err != nil {
		return nil, err
	}
	consents := 0
	for _, consent := range consentRows {
		if err := tx.Delete(ctx, "privacyConsents", jsString(consent.Get("id"))); err != nil {
			return nil, err
		}
		consents++
	}
	eventRows, err := tx.Find(ctx, "privacyConsentEvents", core.NewObject("tenantId", tenantID, "subject", subject), nil)
	if err != nil {
		return nil, err
	}
	history := 0
	for _, event := range eventRows {
		if truthy(event.Get("redacted")) {
			continue
		}
		kept := event.Spread()
		kept.Delete("evidence")
		kept.Delete("ip")
		kept.Delete("userAgent")
		kept.Set("redacted", true)
		if _, err := tx.Put(ctx, "privacyConsentEvents", kept); err != nil {
			return nil, err
		}
		history++
	}
	if err := pvDeleteAll(ctx, tx, "privacyRestrictions", core.NewObject("tenantId", tenantID, "subject", subject)); err != nil {
		return nil, err
	}
	// An application subject keeps a suppression marker: the application may ask about the same identifier again,
	// and an opt-out or objection the erased records held must not turn back into "allowed".
	if externalID := request.Get("externalId"); !isUndefined(externalID) {
		if _, err := tx.Insert(ctx, "privacyRestrictions", core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"subject", subject,
			"externalId", externalID,
			"requestId", request.Get("id"),
			"erased", true,
			"restrictedAt", float64(server.Now()),
			"restrictedBy", principal.Identity.Get("id"),
		)); err != nil {
			return nil, err
		}
	}
	if err := pvDeleteAll(ctx, tx, "privacyExports", core.NewObject("tenantId", tenantID, "subject", subject)); err != nil {
		return nil, err
	}
	others, err := tx.Find(ctx, "privacyRequests", core.NewObject("tenantId", tenantID, "subject", subject), nil)
	if err != nil {
		return nil, err
	}
	for _, other := range others {
		if other.Get("id") != request.Get("id") && !truthy(other.Get("redacted")) {
			if _, err := tx.Put(ctx, "privacyRequests", pvRedact(other)); err != nil {
				return nil, err
			}
		}
	}
	if consents > 0 {
		actions = append(actions, "consents-deleted:"+jsString(float64(consents)))
	}
	if history > 0 {
		actions = append(actions, "history-redacted:"+jsString(float64(history)))
	}
	if len(actions) == 0 {
		actions = append(actions, "nothing-held")
	}
	return actions, nil
}

// pvDeleteAll deletes every record of a collection matching the filter.
func pvDeleteAll(ctx context.Context, tx core.IamStore, collection string, filter *core.Object) error {
	rows, err := tx.Find(ctx, collection, filter, nil)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if err := tx.Delete(ctx, collection, jsString(row.Get("id"))); err != nil {
			return err
		}
	}
	return nil
}

// pvRedact removes the requester's contact details and the timeline notes from a request.
func pvRedact(request *core.Object) *core.Object {
	kept := request.Spread()
	kept.Delete("requesterEmail")
	kept.Delete("requesterName")
	kept.Delete("details")
	kept.Set("redacted", true)
	events, _ := request.Get("events").([]any)
	stripped := make([]any, 0, len(events))
	for _, item := range events {
		if event, ok := item.(*core.Object); ok && event != nil {
			copied := event.Spread()
			copied.Delete("note")
			stripped = append(stripped, copied)
		} else {
			stripped = append(stripped, item)
		}
	}
	kept.Set("events", stripped)
	return kept
}

func pvRegulationOf(value any, settings *core.Object) (string, error) {
	if isUndefined(value) {
		return jsString(settings.Get("defaultRegulation")), nil
	}
	return pvOneOf(value, Regulations, "regulation")
}

// pvPurposeKeysOf validates a request's purpose keys (nil when absent or empty).
func pvPurposeKeysOf(value any) ([]string, error) {
	if isUndefined(value) {
		return nil, nil
	}
	items, err := Strings(value, "purposeKeys")
	if err != nil {
		return nil, err
	}
	validated := make([]string, len(items))
	for index, item := range items {
		if validated[index], err = PurposeKey(item); err != nil {
			return nil, err
		}
	}
	keys := unique(validated)
	if len(keys) > 50 {
		return nil, invalidInput("At most 50 purposeKeys")
	}
	if len(keys) == 0 {
		return nil, nil
	}
	sortStable(keys, compareUTF16)
	return keys, nil
}

// pvOpened opens a verified request: the response window starts now.
func pvOpened(request, settings *core.Object, now int64, verification *core.Object) (*core.Object, error) {
	window, err := ResponseWindow(jsString(request.Get("regulation")), settings)
	if err != nil {
		return nil, err
	}
	kept := request.Spread()
	kept.Delete("tokenHash")
	kept.Delete("tokenExpiresAt")
	kept.Set("status", "open")
	kept.Set("verification", verification)
	kept.Set("receivedAt", float64(now))
	kept.Set("dueAt", float64(now)+jsNumber(window.Get("responseDays"))*DayMs)
	return kept, nil
}

// pvIdentitySubject is the privacy subject of the principal's identity.
func pvIdentitySubject(principal *Principal) (string, error) {
	return IdentitySubject(jsString(principal.Identity.Get("id")))
}

// asPerson runs a self-service call as the signed-in person of tenantID.
func pvAsPerson[T any](ctx context.Context, server *ServerContext, credential core.CredentialInput, tenantID string, fn func(ctx context.Context, tx core.IamStore, principal *Principal, tenant *core.Object) (T, error)) (T, error) {
	var zero T
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return zero, err
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (T, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return zero, err
		}
		if err := pvSelfSession(principal, tenantID); err != nil {
			return zero, err
		}
		tenant, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return zero, err
		}
		if tenant.Get("status") != "active" {
			return zero, core.NewIamError("TENANT_INACTIVE", "Tenant inactive", 403)
		}
		return fn(ctx, tx, principal, tenant)
	})
}

// pvSubjectNames is the display name (email or name) of every identity subject of the requests that still exists.
func pvSubjectNames(ctx context.Context, tx core.IamStore, requests []*core.Object) (map[string]string, error) {
	names := map[string]string{}
	for _, request := range requests {
		identityID := request.Get("identityId")
		if !truthy(identityID) {
			continue
		}
		if _, seen := names[jsString(identityID)]; seen {
			continue
		}
		identity, err := tx.Get(ctx, "identities", jsString(identityID))
		if err != nil {
			return nil, err
		}
		if identity != nil {
			names[jsString(identity.Get("id"))] = jsString(coalesce(identity.Get("email"), identity.Get("name")))
		}
	}
	return names, nil
}

// pvOpenRequest loads a request of the tenant.
func pvOpenRequest(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, requestID any) (*core.Object, error) {
	validated, err := Text(requestID, "requestId")
	if err != nil {
		return nil, err
	}
	return server.Scoped(ctx, tx, "privacyRequests", validated, tenantID)
}

// pvNameOf is the subject name of a request for a view ("" when none).
func pvNameOf(names map[string]string, request *core.Object) string {
	if identityID := request.Get("identityId"); truthy(identityID) {
		return names[jsString(identityID)]
	}
	return ""
}

// pvDecideIam is ctx.decisions.decide on an `iam` resource (internal) and its `allowed`.
func pvDecideIam(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID, action, resourceID string) (bool, error) {
	decision, err := server.Decisions.Decide(ctx, tx, principal, AuthorizationRequest{
		TenantID: tenantID, Action: action, Resource: ResourceTarget{Type: "iam", ID: resourceID},
	}, true)
	if err != nil {
		return false, err
	}
	return decision.Allowed, nil
}

// pvSlice is `items.slice(offset, offset + limit)`.
func pvSlice[T any](items []T, offset, limit float64) []T {
	start := int(math.Min(offset, float64(len(items))))
	end := int(math.Min(offset+limit, float64(len(items))))
	if end < start {
		end = start
	}
	return items[start:end]
}

func pvList(records []*core.Object) []any {
	out := make([]any, len(records))
	for index, record := range records {
		out[index] = record
	}
	return out
}

// pvSettingsView is the tenant's privacy settings with the statutory windows.
func pvSettingsView(settings *core.Object) *core.Object {
	view := core.NewObject()
	if truthy(settings.Get("contactEmail")) {
		view.Set("contactEmail", settings.Get("contactEmail"))
	}
	if truthy(settings.Get("contactName")) {
		view.Set("contactName", settings.Get("contactName"))
	}
	view.Set("defaultRegulation", settings.Get("defaultRegulation"))
	if truthy(settings.Get("responseDays")) {
		view.Set("responseDays", settings.Get("responseDays"))
	}
	view.Set("publicIntake", settings.Get("publicIntake"))
	view.Set("exportLifetimeDays", settings.Get("exportLifetimeDays"))
	view.Set("statutory", RegulationDeadlines.Clone())
	return view
}

// pvCheckSubject is the processing decision for a subject and purpose, shared by the API and the credential-free
// runtime.
func pvCheckSubject(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string, subjectInput any, key any) (*core.Object, error) {
	purpose, err := pvPurposeByKey(ctx, tx, tenantID, key)
	if err != nil {
		return nil, err
	}
	subject, err := ResolveSubject(ctx, tx, tenantID, subjectInput, false)
	if err != nil {
		return nil, err
	}
	found, err := tx.Find(ctx, "privacyConsents", core.NewObject("tenantId", tenantID, "uniqueKey", jsString(purpose.Get("id"))+":"+jsString(subject.Get("key"))), nil)
	if err != nil {
		return nil, err
	}
	var consent *core.Object
	if len(found) > 0 {
		consent = found[0]
	}
	restriction, err := RestrictionOf(ctx, tx, tenantID, jsString(subject.Get("key")))
	if err != nil {
		return nil, err
	}
	restricted, err := RestrictionState(restriction)
	if err != nil {
		return nil, err
	}
	state, err := ConsentState(purpose, consent, restricted, server.Now())
	if err != nil {
		return nil, err
	}
	result := core.NewObject("purposeKey", purpose.Get("key"), "purposeVersion", purpose.Get("version"))
	result.Assign(state)
	if consent != nil {
		result.Set("consent", pvConsentRef(consent))
	}
	return result, nil
}

// pvRestrictedSubjects is the set of restricted subjects of the tenant.
func pvRestrictedSubjects(ctx context.Context, tx core.IamStore, tenantID string) (*orderedSet, error) {
	rows, err := tx.Find(ctx, "privacyRestrictions", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	set := newOrderedSet()
	for _, restriction := range rows {
		set.Add(jsString(restriction.Get("subject")))
	}
	return set, nil
}

// pvClosedStatus reports whether a request is no longer being handled.
func pvHandling(request *core.Object) bool {
	status := request.Get("status")
	return status == "open" || status == "pending-verification"
}

// ── Purposes ──────────────────────────────────────────────────────────────────────────────────────────────────────

// CreatePurpose is POST {basePath}/privacy/createPurpose. Adds a processing purpose at version 1. Keys are permanent;
// names and descriptions can change.
func (api *PrivacyAPI) CreatePurpose(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyCreatePurposeInput]) (Out[apitypes.PrivacyCreatePurposeOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:privacy:manage", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant := call.Tx, jsString(call.Tenant.Get("id"))
		values, err := pvPurposeFields(input.Body, nil)
		if err != nil {
			return nil, err
		}
		existing, err := tx.Find(ctx, "privacyPurposes", core.NewObject("tenantId", tenant), nil)
		if err != nil {
			return nil, err
		}
		for _, purpose := range existing {
			if purpose.Get("uniqueKey") == values.Get("uniqueKey") {
				return nil, core.NewIamError("CONFLICT", "A purpose with this key exists", 409)
			}
		}
		if len(existing) >= pvMaxPurposes {
			return nil, core.NewIamError("LIMIT_EXCEEDED", "At most 200 purposes", 409)
		}
		now := float64(server.Now())
		record := values.Spread()
		record.Set("id", ID())
		record.Set("tenantId", tenant)
		record.Set("version", 1.0)
		record.Set("archived", false)
		record.Set("createdAt", now)
		record.Set("updatedAt", now)
		return tx.Insert(ctx, "privacyPurposes", record)
	}, false)
	return Out[apitypes.PrivacyCreatePurposeOutput]{Value: result}, err
}

// UpdatePurpose is POST {basePath}/privacy/updatePurpose. Edits a purpose. `newVersion: true` publishes the change as
// the next version: opt-in grants given to older versions stop counting (unless `reconsentOnVersion` is false), so
// people are asked again. `archived: true` stops all processing for it; decisions are kept.
func (api *PrivacyAPI) UpdatePurpose(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyUpdatePurposeInput]) (Out[apitypes.PrivacyUpdatePurposeOutput], error) {
	server := api.server
	resourceID, err := Text(input.Get("purposeId"), "purposeId")
	if err != nil {
		return Out[apitypes.PrivacyUpdatePurposeOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:privacy:manage", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		previous, err := server.Scoped(ctx, tx, "privacyPurposes", input.Get("purposeId"), jsString(call.Tenant.Get("id")))
		if err != nil {
			return nil, err
		}
		values, err := pvPurposeFields(input.Body, previous)
		if err != nil {
			return nil, err
		}
		// A new basis or mode changes who may be processed (opt-in to opt-out makes everyone never asked
		// processable), so it is published as a new version people can see.
		if (values.Get("legalBasis") != previous.Get("legalBasis") || values.Get("mode") != previous.Get("mode")) && input.Get("newVersion") != true {
			return nil, invalidInput("Changing the legal basis or consent mode is a material change: publish it with newVersion")
		}
		archived := input.Get("archived")
		if !isUndefined(archived) {
			if _, ok := archived.(bool); !ok {
				return nil, invalidInput("archived must be a boolean")
			}
		}
		kept := previous.Spread()
		kept.Delete("retentionDays")
		kept.Delete("consentLifetimeDays")
		record := kept.Assign(values)
		version := jsNumber(previous.Get("version"))
		if input.Get("newVersion") == true {
			version++
		}
		record.Set("version", version)
		record.Set("archived", coalesce(archived, previous.Get("archived")))
		record.Set("updatedAt", float64(server.Now()))
		return tx.Put(ctx, "privacyPurposes", record)
	}, false)
	return Out[apitypes.PrivacyUpdatePurposeOutput]{Value: result}, err
}

// DeletePurpose is POST {basePath}/privacy/deletePurpose. Deletes a purpose nobody has decided on yet; purposes with
// recorded decisions are archived instead.
func (api *PrivacyAPI) DeletePurpose(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyDeletePurposeInput]) (Out[apitypes.PrivacyDeletePurposeOutput], error) {
	server := api.server
	resourceID, err := Text(input.Get("purposeId"), "purposeId")
	if err != nil {
		return Out[apitypes.PrivacyDeletePurposeOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:privacy:manage", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenantID := call.Tx, jsString(call.Tenant.Get("id"))
		purpose, err := server.Scoped(ctx, tx, "privacyPurposes", input.Get("purposeId"), tenantID)
		if err != nil {
			return nil, err
		}
		events, err := tx.Find(ctx, "privacyConsentEvents", core.NewObject("tenantId", tenantID, "purposeId", purpose.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		if len(events) > 0 {
			return nil, core.NewIamError("RESOURCE_IN_USE", "Decisions are recorded for this purpose; archive it instead so the proof is kept", 409)
		}
		if err := tx.Delete(ctx, "privacyPurposes", jsString(purpose.Get("id"))); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	return Out[apitypes.PrivacyDeletePurposeOutput]{Value: result}, err
}

// ListPurposes is POST {basePath}/privacy/listPurposes. Lists the tenant's purposes by name.
func (api *PrivacyAPI) ListPurposes(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyListPurposesInput]) (Out[apitypes.PrivacyListPurposesOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:privacy:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		found, err := call.Tx.Find(ctx, "privacyPurposes", core.NewObject("tenantId", call.Tenant.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		var kept []*core.Object
		for _, purpose := range found {
			if input.Get("includeArchived") == true || !truthy(purpose.Get("archived")) {
				kept = append(kept, purpose)
			}
		}
		sortStable(kept, func(a, b *core.Object) int {
			return localeCompare(jsString(a.Get("name")), jsString(b.Get("name")))
		})
		return pvList(kept), nil
	}, false)
	return Out[apitypes.PrivacyListPurposesOutput]{Value: result}, err
}

// ── The person's own choices ──────────────────────────────────────────────────────────────────────────────────────

// Mine is POST {basePath}/privacy/mine. The caller's privacy page: every purpose with their decision and its effect,
// whether processing is restricted, their data-subject requests, and the privacy contact. Needs only a signed-in
// session of the organization.
func (api *PrivacyAPI) Mine(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyMineInput]) (Out[apitypes.PrivacyMineOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.PrivacyMineOutput]{}, err
	}
	result, err := pvAsPerson(ctx, server, credential, tenantID, func(ctx context.Context, tx core.IamStore, principal *Principal, _ *core.Object) (*core.Object, error) {
		now := server.Now()
		subject, err := pvIdentitySubject(principal)
		if err != nil {
			return nil, err
		}
		consents, err := ConsentsOf(ctx, tx, tenantID, subject)
		if err != nil {
			return nil, err
		}
		restriction, err := RestrictionOf(ctx, tx, tenantID, subject)
		if err != nil {
			return nil, err
		}
		restricted := restriction != nil
		settings, err := PrivacySettings(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		found, err := tx.Find(ctx, "privacyPurposes", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		var active []*core.Object
		decidable := map[*core.Object]bool{}
		for _, purpose := range found {
			if truthy(purpose.Get("archived")) {
				continue
			}
			if decidable[purpose], err = Decidable(purpose); err != nil {
				return nil, err
			}
			active = append(active, purpose)
		}
		sortStable(active, func(a, b *core.Object) int {
			if difference := pvBit(decidable[b]) - pvBit(decidable[a]); difference != 0 {
				return difference
			}
			return localeCompare(jsString(a.Get("name")), jsString(b.Get("name")))
		})
		purposes := make([]any, 0, len(active))
		for _, purpose := range active {
			consent := consents[jsString(purpose.Get("id"))]
			entry := core.NewObject(
				"id", purpose.Get("id"),
				"key", purpose.Get("key"),
				"name", purpose.Get("name"),
				"description", purpose.Get("description"),
				"legalBasis", purpose.Get("legalBasis"),
				"mode", purpose.Get("mode"),
				"version", purpose.Get("version"),
				"dataCategories", purpose.Get("dataCategories"),
			)
			if retention := purpose.Get("retentionDays"); !isUndefined(retention) {
				entry.Set("retentionDays", retention)
			}
			entry.Set("decidable", decidable[purpose])
			state, err := ConsentState(purpose, consent, restricted, now)
			if err != nil {
				return nil, err
			}
			entry.Set("state", state)
			if consent != nil {
				entry.Set("consent", pvConsentRef(consent))
			}
			purposes = append(purposes, entry)
		}
		rows, err := tx.Find(ctx, "privacyRequests", core.NewObject("tenantId", tenantID, "subject", subject), nil)
		if err != nil {
			return nil, err
		}
		sortStable(rows, func(a, b *core.Object) int {
			return pvSign(jsNumber(b.Get("submittedAt")) - jsNumber(a.Get("submittedAt")))
		})
		requests := make([]any, 0, len(rows))
		for _, request := range rows {
			view, err := pvMineView(request, now)
			if err != nil {
				return nil, err
			}
			requests = append(requests, view)
		}
		page := core.NewObject("purposes", purposes, "restricted", restricted, "requests", requests)
		if truthy(settings.Get("contactEmail")) {
			contact := core.NewObject("email", settings.Get("contactEmail"))
			if truthy(settings.Get("contactName")) {
				contact.Set("name", settings.Get("contactName"))
			}
			page.Set("contact", contact)
		}
		return page, nil
	})
	return Out[apitypes.PrivacyMineOutput]{Value: result}, err
}

func pvBit(value bool) int {
	if value {
		return 1
	}
	return 0
}

// Decide is POST {basePath}/privacy/decide. Records the caller's decision on a purpose: `granted: true` consents (or
// withdraws an objection), `false` withdraws consent, opts out, or objects to a legitimate-interest purpose.
// `version` must be the purpose's current version, so nobody agrees to text they were not shown. Returns a signed
// receipt; audited as `privacy:consent`.
func (api *PrivacyAPI) Decide(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyDecideInput]) (Out[apitypes.PrivacyDecideOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.PrivacyDecideOutput]{}, err
	}
	granted, ok := input.Get("granted").(bool)
	if !ok {
		return Out[apitypes.PrivacyDecideOutput]{}, invalidInput("granted must be a boolean")
	}
	version, err := Integer(input.Get("version"), "version", 1, 1_000_000)
	if err != nil {
		return Out[apitypes.PrivacyDecideOutput]{}, err
	}
	result, err := pvAsPerson(ctx, server, credential, tenantID, func(ctx context.Context, tx core.IamStore, principal *Principal, _ *core.Object) (*core.Object, error) {
		purpose, err := pvPurposeByKey(ctx, tx, tenantID, input.Get("purposeKey"))
		if err != nil {
			return nil, err
		}
		if jsNumber(purpose.Get("version")) != version {
			return nil, core.NewIamError("VERSION_CONFLICT", "The purpose changed; review the current version before deciding", 409)
		}
		subject, err := ResolveSubject(ctx, tx, tenantID, core.NewObject("identityId", principal.Identity.Get("id")), false)
		if err != nil {
			return nil, err
		}
		method, err := pvMethod(input.Get("method"))
		if err != nil {
			return nil, err
		}
		if method == "" {
			method = "self-service"
		}
		evidence, err := pvEvidence(input.Get("evidence"))
		if err != nil {
			return nil, err
		}
		receipt, _, err := pvWriteConsent(ctx, server, tx, pvConsentInput{
			tenantID:   tenantID,
			purpose:    purpose,
			subject:    subject,
			granted:    granted,
			source:     "self",
			method:     method,
			evidence:   evidence,
			recordedBy: jsString(principal.Identity.Get("id")),
			at:         float64(server.Now()),
			client:     server.Auth.CurrentClient(ctx),
		})
		if err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "privacy:consent", tenantID, jsString(principal.Identity.Get("id")), "allow", false, core.NewObject(
			"purposeKey", purpose.Get("key"),
			"granted", granted,
			"purposeVersion", version,
			"source", "self",
			"receiptId", receipt.Get("receiptId"),
		)); err != nil {
			return nil, err
		}
		return receipt, nil
	})
	return Out[apitypes.PrivacyDecideOutput]{Value: result}, err
}

// pvOptionalPurposeKey is `value === undefined ? undefined : purposeKey(value)`.
func pvOptionalPurposeKey(value any) (any, error) {
	if isUndefined(value) {
		return core.Undefined, nil
	}
	return PurposeKey(value)
}

// MyHistory is POST {basePath}/privacy/myHistory. The caller's decision history (newest first, at most 500 entries).
func (api *PrivacyAPI) MyHistory(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyMyHistoryInput]) (Out[apitypes.PrivacyMyHistoryOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.PrivacyMyHistoryOutput]{}, err
	}
	result, err := pvAsPerson(ctx, server, credential, tenantID, func(ctx context.Context, tx core.IamStore, principal *Principal, _ *core.Object) ([]any, error) {
		key, err := pvOptionalPurposeKey(input.Get("purposeKey"))
		if err != nil {
			return nil, err
		}
		subject, err := pvIdentitySubject(principal)
		if err != nil {
			return nil, err
		}
		events, err := tx.Find(ctx, "privacyConsentEvents", core.NewObject("tenantId", tenantID, "subject", subject), nil)
		if err != nil {
			return nil, err
		}
		return pvHistory(events, key, 500), nil
	})
	return Out[apitypes.PrivacyMyHistoryOutput]{Value: result}, err
}

// MyReceipt is POST {basePath}/privacy/myReceipt. A signed receipt for one of the caller's own decisions.
func (api *PrivacyAPI) MyReceipt(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyMyReceiptInput]) (Out[apitypes.PrivacyMyReceiptOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.PrivacyMyReceiptOutput]{}, err
	}
	result, err := pvAsPerson(ctx, server, credential, tenantID, func(ctx context.Context, tx core.IamStore, principal *Principal, _ *core.Object) (*core.Object, error) {
		receiptID, err := Text(input.Get("receiptId"), "receiptId")
		if err != nil {
			return nil, err
		}
		event, err := tx.Get(ctx, "privacyConsentEvents", receiptID)
		if err != nil {
			return nil, err
		}
		subject, err := pvIdentitySubject(principal)
		if err != nil {
			return nil, err
		}
		if event == nil || event.Get("tenantId") != tenantID || event.Get("subject") != subject {
			return nil, core.NewIamError("NOT_FOUND", "Receipt not found", 404)
		}
		return ReceiptFromEvent(server.Options.Secret, event)
	})
	return Out[apitypes.PrivacyMyReceiptOutput]{Value: result}, err
}

// SubmitRequest is POST {basePath}/privacy/submitRequest. Files a data-subject request for the caller. Signing in
// verified who they are, so the response window starts at once; the privacy contact is emailed. One open request
// per type at a time. Audited as `privacy:request:submit`.
func (api *PrivacyAPI) SubmitRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacySubmitRequestInput]) (Out[apitypes.PrivacySubmitRequestOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.PrivacySubmitRequestOutput]{}, err
	}
	requestType, err := pvOneOf(input.Get("type"), SubjectRequestTypes, "type")
	if err != nil {
		return Out[apitypes.PrivacySubmitRequestOutput]{}, err
	}
	details := ""
	if raw := input.Get("details"); !isUndefined(raw) {
		if details, err = Prose(raw, "details", 5000); err != nil {
			return Out[apitypes.PrivacySubmitRequestOutput]{}, err
		}
	}
	purposeKeys, err := pvPurposeKeysOf(input.Get("purposeKeys"))
	if err != nil {
		return Out[apitypes.PrivacySubmitRequestOutput]{}, err
	}
	result, err := pvAsPerson(ctx, server, credential, tenantID, func(ctx context.Context, tx core.IamStore, principal *Principal, tenant *core.Object) (*core.Object, error) {
		subject, err := pvIdentitySubject(principal)
		if err != nil {
			return nil, err
		}
		settings, err := PrivacySettings(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		regulation, err := pvRegulationOf(input.Get("regulation"), settings)
		if err != nil {
			return nil, err
		}
		existing, err := tx.Find(ctx, "privacyRequests", core.NewObject("tenantId", tenantID, "subject", subject), nil)
		if err != nil {
			return nil, err
		}
		for _, request := range existing {
			if request.Get("type") == requestType && pvHandling(request) {
				return nil, core.NewIamError("CONFLICT", "You already have an open request of this type", 409)
			}
		}
		for _, key := range purposeKeys {
			if _, err := pvPurposeByKey(ctx, tx, tenantID, key); err != nil {
				return nil, err
			}
		}
		now := server.Now()
		number, err := RequestNumber()
		if err != nil {
			return nil, err
		}
		identityID := principal.Identity.Get("id")
		draft := core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"uniqueKey", "number:"+number,
			"number", number,
			"type", requestType,
			"regulation", regulation,
			"status", "pending-verification",
			"subject", subject,
			"identityId", identityID,
		)
		if details != "" {
			draft.Set("details", details)
		}
		if purposeKeys != nil {
			draft.Set("purposeKeys", stringsOf(purposeKeys))
		}
		draft.Set("channel", "self-service")
		draft.Set("verification", core.NewObject("status", "pending"))
		draft.Set("submittedAt", float64(now))
		draft.Set("events", []any{pvEvent(now, identityID, "submitted", "")})
		request, err := pvOpened(draft, settings, now, core.NewObject("status", "verified", "method", "authenticated-session", "verifiedAt", float64(now)))
		if err != nil {
			return nil, err
		}
		if _, err := tx.Insert(ctx, "privacyRequests", request); err != nil {
			return nil, err
		}
		if err := pvNotifyContact(ctx, server, tx, tenant, request); err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "privacy:request:submit", tenantID, jsString(request.Get("id")), "allow", false,
			core.NewObject("number", number, "type", requestType, "regulation", regulation, "channel", "self-service")); err != nil {
			return nil, err
		}
		return pvMineView(request, now)
	})
	return Out[apitypes.PrivacySubmitRequestOutput]{Value: result}, err
}

// CancelMyRequest is POST {basePath}/privacy/cancelMyRequest. Withdraws one of the caller's own requests while it is
// still being handled.
func (api *PrivacyAPI) CancelMyRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyCancelMyRequestInput]) (Out[apitypes.PrivacyCancelMyRequestOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.PrivacyCancelMyRequestOutput]{}, err
	}
	result, err := pvAsPerson(ctx, server, credential, tenantID, func(ctx context.Context, tx core.IamStore, principal *Principal, _ *core.Object) (*core.Object, error) {
		request, err := pvOpenRequest(ctx, server, tx, tenantID, input.Get("requestId"))
		if err != nil {
			return nil, err
		}
		subject, err := pvIdentitySubject(principal)
		if err != nil {
			return nil, err
		}
		if request.Get("subject") != subject {
			return nil, core.NewIamError("NOT_FOUND", "Resource not found", 404)
		}
		if !pvHandling(request) {
			return nil, core.NewIamError("INVALID_TRANSITION", "This request is already closed", 409)
		}
		now := server.Now()
		identityID := principal.Identity.Get("id")
		cancelled := request.Spread()
		cancelled.Set("status", "cancelled")
		cancelled.Set("closedAt", float64(now))
		cancelled.Set("closedBy", identityID)
		cancelled.Set("events", pvPushEvent(request, pvEvent(now, identityID, "cancelled", "")))
		if _, err := tx.Put(ctx, "privacyRequests", cancelled); err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "privacy:request:cancel", tenantID, jsString(request.Get("id")), "allow", false,
			core.NewObject("number", request.Get("number"), "type", request.Get("type"))); err != nil {
			return nil, err
		}
		return pvMineView(cancelled, now)
	})
	return Out[apitypes.PrivacyCancelMyRequestOutput]{Value: result}, err
}

// pvDownload is the outcome of the download transaction: a refusal is returned rather than failed, so the
// transaction commits its deny audit record.
type pvDownload struct {
	denied bool
	result *core.Object
}

// DownloadExport is POST {basePath}/privacy/downloadExport. Downloads the export an access or portability request
// produced: by the person it is about, or by a request handler (`iam:privacy:handle`, recently signed in) who must
// deliver it another way. Audited as `privacy:export:download`.
func (api *PrivacyAPI) DownloadExport(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyDownloadExportInput]) (Out[apitypes.PrivacyDownloadExportOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.PrivacyDownloadExportOutput]{}, err
	}
	requestID, err := Text(input.Get("requestId"), "requestId")
	if err != nil {
		return Out[apitypes.PrivacyDownloadExportOutput]{}, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return Out[apitypes.PrivacyDownloadExportOutput]{}, err
	}
	outcome, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (pvDownload, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return pvDownload{}, err
		}
		request, err := tx.Get(ctx, "privacyRequests", requestID)
		if err != nil {
			return pvDownload{}, err
		}
		if request == nil || request.Get("tenantId") != tenantID || !truthy(request.Get("exportId")) {
			return pvDownload{}, core.NewIamError("NOT_FOUND", "Export not found", 404)
		}
		own := ActsInOwnRight(principal.Session) &&
			principal.Session.Get("kind") == "user" &&
			!truthy(principal.Session.Get("impersonatorId")) &&
			principal.Session.Get("tenantId") == tenantID
		if own {
			subject, err := pvIdentitySubject(principal)
			if err != nil {
				return pvDownload{}, err
			}
			own = request.Get("subject") == subject
		}
		if !own {
			type check struct{ action, id string }
			checks := []check{{"iam:privacy:handle", jsString(request.Get("id"))}}
			// A handler reads everything about the person, as identities.export would let them.
			if identityID := request.Get("identityId"); truthy(identityID) {
				checks = append(checks, check{"iam:identities:read", jsString(identityID)})
			}
			for _, item := range checks {
				decision, err := server.Operations.RecordedDecision(ctx, tx, principal, AuthorizationRequest{
					TenantID: tenantID, Action: item.action, Resource: ResourceTarget{Type: "iam", ID: item.id},
				})
				if err != nil {
					return pvDownload{}, err
				}
				if !decision.Allowed {
					return pvDownload{denied: true}, nil
				}
			}
			if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
				return pvDownload{}, err
			}
		}
		item, err := tx.Get(ctx, "privacyExports", jsString(request.Get("exportId")))
		if err != nil {
			return pvDownload{}, err
		}
		if item == nil || jsNumber(item.Get("expiresAt")) <= float64(server.Now()) {
			return pvDownload{}, core.NewIamError("NOT_FOUND", "The export has expired; file a new request", 404)
		}
		updated := item.Spread()
		updated.Set("downloads", jsNumber(item.Get("downloads"))+1)
		if _, err := tx.Put(ctx, "privacyExports", updated); err != nil {
			return pvDownload{}, err
		}
		by := "handler"
		if own {
			by = "subject"
		}
		if err := server.Events.Audit(ctx, tx, principal, "privacy:export:download", tenantID, jsString(request.Get("id")), "allow", false,
			core.NewObject("number", request.Get("number"), "by", by)); err != nil {
			return pvDownload{}, err
		}
		return pvDownload{result: core.NewObject(
			"number", request.Get("number"),
			"createdAt", item.Get("createdAt"),
			"expiresAt", item.Get("expiresAt"),
			"sha256", item.Get("sha256"),
			"data", item.Get("data"),
		)}, nil
	})
	if err != nil {
		return Out[apitypes.PrivacyDownloadExportOutput]{}, err
	}
	if outcome.denied {
		return Out[apitypes.PrivacyDownloadExportOutput]{}, core.NewIamError("ACCESS_DENIED", "Access denied", 403)
	}
	return Out[apitypes.PrivacyDownloadExportOutput]{Value: outcome.result}, nil
}

// ── Consent records kept by the application ───────────────────────────────────────────────────────────────────────

// pvClientOf is the client recorded with a decision: `ip` and `userAgent` when given (nil when neither is).
func pvClientOf(ip, userAgent any, always bool) (*core.SessionClientInfo, error) {
	if !always && isUndefined(ip) && isUndefined(userAgent) {
		return nil, nil
	}
	client := &core.SessionClientInfo{}
	if !isUndefined(ip) {
		value, err := Text(ip, "ip", 64)
		if err != nil {
			return nil, err
		}
		client.IP = value
	}
	if !isUndefined(userAgent) {
		value, err := Text(userAgent, "userAgent", 512)
		if err != nil {
			return nil, err
		}
		client.UserAgent = value
	}
	return client, nil
}

// Record is POST {basePath}/privacy/record. Records a decision for a subject: a person here (`{ identityId }`) or one
// the application names (`{ externalId }`, such as a customer number or a visitor ID). `source` is `api` (default),
// `admin` or `import`; imports may carry an earlier `recordedAt` and `version`, and never overwrite a newer decision.
// Returns the receipt.
func (api *PrivacyAPI) Record(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyRecordInput]) (Out[apitypes.PrivacyRecordOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:privacy:record", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant, principal := call.Tx, jsString(call.Tenant.Get("id")), call.Principal
		granted, ok := input.Get("granted").(bool)
		if !ok {
			return nil, invalidInput("granted must be a boolean")
		}
		source, err := pvOneOf(coalesce(input.Get("source"), "api"), []string{"api", "admin", "import"}, "source")
		if err != nil {
			return nil, err
		}
		now := float64(server.Now())
		at := now
		if raw := input.Get("recordedAt"); !isUndefined(raw) {
			if at, err = Integer(raw, "recordedAt", 0, now); err != nil {
				return nil, err
			}
		}
		if at != now && source != "import" {
			return nil, invalidInput("recordedAt is accepted for imports only")
		}
		// An imported grant counts for the version the person saw, never silently for today's text.
		version := input.Get("version")
		if source == "import" && isUndefined(version) {
			return nil, invalidInput("Imports must state the purpose version decided on")
		}
		purpose, err := pvPurposeByKey(ctx, tx, tenant, input.Get("purposeKey"))
		if err != nil {
			return nil, err
		}
		subject, err := ResolveSubject(ctx, tx, tenant, input.Get("subject"), false)
		if err != nil {
			return nil, err
		}
		client, err := pvClientOf(input.Get("ip"), input.Get("userAgent"), false)
		if err != nil {
			return nil, err
		}
		method, err := pvMethod(input.Get("method"))
		if err != nil {
			return nil, err
		}
		evidence, err := pvEvidence(input.Get("evidence"))
		if err != nil {
			return nil, err
		}
		receipt, current, err := pvWriteConsent(ctx, server, tx, pvConsentInput{
			tenantID:   tenant,
			purpose:    purpose,
			subject:    subject,
			granted:    granted,
			source:     source,
			method:     method,
			evidence:   evidence,
			recordedBy: jsString(principal.Identity.Get("id")),
			at:         at,
			hasVersion: !isUndefined(version),
			version:    version,
			client:     client,
		})
		if err != nil {
			return nil, err
		}
		metadata := core.NewObject(
			"purposeKey", purpose.Get("key"),
			"granted", granted,
			"purposeVersion", member(receipt.Get("purpose"), "version"),
			"source", source,
			"receiptId", receipt.Get("receiptId"),
		)
		if externalID := subject.Get("externalId"); !isUndefined(externalID) {
			metadata.Set("externalId", externalID)
		}
		if err := server.Events.Audit(ctx, tx, principal, "privacy:consent", tenant, jsString(coalesce(subject.Get("identityId"), subject.Get("key"))), "allow", false, metadata); err != nil {
			return nil, err
		}
		return receipt.Spread(core.NewObject("current", current)), nil
	}, false)
	return Out[apitypes.PrivacyRecordOutput]{Value: result}, err
}

// ImportDecisions is POST {basePath}/privacy/importDecisions. Imports up to 500 decisions in one transaction (all or
// nothing), for moving consent records from another system. Entries follow `record` with `source: 'import'`; one
// `privacy:consent-import` audit event summarizes them.
func (api *PrivacyAPI) ImportDecisions(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyImportDecisionsInput]) (Out[apitypes.PrivacyImportDecisionsOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:privacy:record", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant, principal := call.Tx, jsString(call.Tenant.Get("id")), call.Principal
		decisions, ok := input.Get("decisions").([]any)
		if !ok || len(decisions) == 0 || len(decisions) > 500 {
			return nil, invalidInput("Provide 1-500 decisions")
		}
		now := float64(server.Now())
		purposes := map[string]*core.Object{}
		purposeOrder := []string{}
		current := 0
		for _, raw := range decisions {
			entry, err := Object(raw)
			if err != nil {
				return nil, err
			}
			granted, ok := entry.Get("granted").(bool)
			if !ok {
				return nil, invalidInput("granted must be a boolean")
			}
			if isUndefined(entry.Get("version")) {
				return nil, invalidInput("Each imported decision must state its purpose version")
			}
			key, err := PurposeKey(entry.Get("purposeKey"))
			if err != nil {
				return nil, err
			}
			purpose := purposes[key]
			if purpose == nil {
				if purpose, err = pvPurposeByKey(ctx, tx, tenant, key); err != nil {
					return nil, err
				}
			}
			if _, seen := purposes[key]; !seen {
				purposeOrder = append(purposeOrder, key)
			}
			purposes[key] = purpose
			subject, err := ResolveSubject(ctx, tx, tenant, entry.Get("subject"), false)
			if err != nil {
				return nil, err
			}
			method, err := pvMethod(entry.Get("method"))
			if err != nil {
				return nil, err
			}
			evidence, err := pvEvidence(entry.Get("evidence"))
			if err != nil {
				return nil, err
			}
			at, err := Integer(entry.Get("recordedAt"), "recordedAt", 0, now)
			if err != nil {
				return nil, err
			}
			_, written, err := pvWriteConsent(ctx, server, tx, pvConsentInput{
				tenantID:   tenant,
				purpose:    purpose,
				subject:    subject,
				granted:    granted,
				source:     "import",
				method:     method,
				evidence:   evidence,
				recordedBy: jsString(principal.Identity.Get("id")),
				at:         at,
				hasVersion: true,
				version:    entry.Get("version"),
			})
			if err != nil {
				return nil, err
			}
			if written {
				current++
			}
		}
		keys := append([]string{}, purposeOrder...)
		sortStable(keys, compareUTF16)
		if err := server.Events.Audit(ctx, tx, principal, "privacy:consent-import", tenant, tenant, "allow", false, core.NewObject(
			"count", float64(len(decisions)),
			"current", float64(current),
			"purposes", stringsOf(keys),
		)); err != nil {
			return nil, err
		}
		return core.NewObject("imported", float64(len(decisions)), "current", float64(current)), nil
	}, false)
	return Out[apitypes.PrivacyImportDecisionsOutput]{Value: result}, err
}

// Check is POST {basePath}/privacy/check. Whether a purpose may be processed for a subject right now, and why
// (`CONSENT_GIVEN`, `NO_CONSENT`, `CONSENT_WITHDRAWN`, `CONSENT_EXPIRED`, `CONSENT_OUTDATED`, `OBJECTED`, `RESTRICTED`,
// `LEGAL_BASIS`, ...). Server code can call `iam.privacy.check` without a credential.
func (api *PrivacyAPI) Check(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyCheckInput]) (Out[apitypes.PrivacyCheckOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:privacy:check", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		return pvCheckSubject(ctx, server, call.Tx, jsString(call.Tenant.Get("id")), input.Get("subject"), input.Get("purposeKey"))
	}, false)
	return Out[apitypes.PrivacyCheckOutput]{Value: result}, err
}

// FilterSubjects is POST {basePath}/privacy/filterSubjects. Splits up to 1 000 subjects into those a purpose may be
// processed for and those it may not (with the reason), for batch jobs such as a marketing send.
func (api *PrivacyAPI) FilterSubjects(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyFilterSubjectsInput]) (Out[apitypes.PrivacyFilterSubjectsOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:privacy:check", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant := call.Tx, jsString(call.Tenant.Get("id"))
		subjects, ok := input.Get("subjects").([]any)
		if !ok || len(subjects) > 1000 {
			return nil, invalidInput("Provide at most 1000 subjects")
		}
		purpose, err := pvPurposeByKey(ctx, tx, tenant, input.Get("purposeKey"))
		if err != nil {
			return nil, err
		}
		now := server.Now()
		allowed, refused := []any{}, []any{}
		for _, raw := range subjects {
			resolved, err := ResolveSubject(ctx, tx, tenant, raw, false)
			if err != nil {
				if known, ok := asIamError(err); ok && known.Code == "NOT_FOUND" {
					refused = append(refused, core.NewObject("subject", raw, "reason", "UNKNOWN_SUBJECT"))
					continue
				}
				return nil, err
			}
			key := jsString(resolved.Get("key"))
			found, err := tx.Find(ctx, "privacyConsents", core.NewObject("tenantId", tenant, "uniqueKey", jsString(purpose.Get("id"))+":"+key), nil)
			if err != nil {
				return nil, err
			}
			var consent *core.Object
			if len(found) > 0 {
				consent = found[0]
			}
			restriction, err := RestrictionOf(ctx, tx, tenant, key)
			if err != nil {
				return nil, err
			}
			restricted, err := RestrictionState(restriction)
			if err != nil {
				return nil, err
			}
			state, err := ConsentState(purpose, consent, restricted, now)
			if err != nil {
				return nil, err
			}
			if state.Get("allowed") == true {
				allowed = append(allowed, raw)
			} else {
				refused = append(refused, core.NewObject("subject", raw, "reason", state.Get("reason")))
			}
		}
		return core.NewObject("purposeKey", purpose.Get("key"), "allowed", allowed, "refused", refused), nil
	}, false)
	return Out[apitypes.PrivacyFilterSubjectsOutput]{Value: result}, err
}

// Audience is POST {basePath}/privacy/audience. The subjects a purpose may currently be processed for: people of the
// tenant (every active person for opt-out and legitimate-interest purposes, those who consented for opt-in ones) and
// application subjects with a recorded decision. Paged by `offset` (at most 1 000 per page). People's emails and
// names are included only when the caller may also read identities (`iam:identities:read`); otherwise they are
// listed by ID.
func (api *PrivacyAPI) Audience(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyAudienceInput]) (Out[apitypes.PrivacyAudienceOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:privacy:read", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant, principal := call.Tx, jsString(call.Tenant.Get("id")), call.Principal
		directory, err := pvDecideIam(ctx, server, tx, principal, tenant, "iam:identities:read", tenant)
		if err != nil {
			return nil, err
		}
		limit, err := Integer(coalesce(input.Get("limit"), 1000.0), "limit", 1, 1000)
		if err != nil {
			return nil, err
		}
		offset, err := Integer(coalesce(input.Get("offset"), 0.0), "offset", 0, 10_000_000)
		if err != nil {
			return nil, err
		}
		purpose, err := pvPurposeByKey(ctx, tx, tenant, input.Get("purposeKey"))
		if err != nil {
			return nil, err
		}
		now := server.Now()
		consentRows, err := tx.Find(ctx, "privacyConsents", core.NewObject("tenantId", tenant, "purposeId", purpose.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		consents := map[string]*core.Object{}
		consentOrder := []string{}
		for _, consent := range consentRows {
			subject := jsString(consent.Get("subject"))
			if _, seen := consents[subject]; !seen {
				consentOrder = append(consentOrder, subject)
			}
			consents[subject] = consent
		}
		restricted, err := pvRestrictedSubjects(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		members := []any{}
		identities, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenant), nil)
		if err != nil {
			return nil, err
		}
		var people []*core.Object
		for _, identity := range identities {
			if identity.Get("kind") == "user" && identity.Get("status") == "active" {
				people = append(people, identity)
			}
		}
		sortStable(people, pvByMember("id"))
		for _, person := range people {
			key, err := IdentitySubject(jsString(person.Get("id")))
			if err != nil {
				return nil, err
			}
			state, err := ConsentState(purpose, consents[key], restricted.Has(key), now)
			if err != nil {
				return nil, err
			}
			if state.Get("allowed") == true {
				entry := core.NewObject("subject", key, "identityId", person.Get("id"))
				if directory && truthy(person.Get("email")) {
					entry.Set("email", person.Get("email"))
				}
				if directory {
					entry.Set("name", person.Get("name"))
				}
				members = append(members, entry)
			}
		}
		ordered := make([]*core.Object, 0, len(consentOrder))
		for _, subject := range consentOrder {
			ordered = append(ordered, consents[subject])
		}
		sortStable(ordered, pvByMember("subject"))
		for _, consent := range ordered {
			if isUndefined(consent.Get("externalId")) {
				continue
			}
			state, err := ConsentState(purpose, consent, restricted.Has(jsString(consent.Get("subject"))), now)
			if err != nil {
				return nil, err
			}
			if state.Get("allowed") == true {
				members = append(members, core.NewObject("subject", consent.Get("subject"), "externalId", consent.Get("externalId")))
			}
		}
		return core.NewObject(
			"purposeKey", purpose.Get("key"),
			"total", float64(len(members)),
			"subjects", pvSlice(members, offset, limit),
		), nil
	}, false)
	return Out[apitypes.PrivacyAudienceOutput]{Value: result}, err
}

// ListConsents is POST {basePath}/privacy/listConsents. Current decisions, filtered by purpose, subject or outcome;
// newest first.
func (api *PrivacyAPI) ListConsents(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyListConsentsInput]) (Out[apitypes.PrivacyListConsentsOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:privacy:read", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant := call.Tx, jsString(call.Tenant.Get("id"))
		limit, err := Integer(coalesce(input.Get("limit"), 100.0), "limit", 1, 1000)
		if err != nil {
			return nil, err
		}
		offset, err := Integer(coalesce(input.Get("offset"), 0.0), "offset", 0, 10_000_000)
		if err != nil {
			return nil, err
		}
		purposeRows, err := tx.Find(ctx, "privacyPurposes", core.NewObject("tenantId", tenant), nil)
		if err != nil {
			return nil, err
		}
		purposes := map[string]*core.Object{}
		for _, purpose := range purposeRows {
			purposes[jsString(purpose.Get("id"))] = purpose
		}
		filter := core.NewObject("tenantId", tenant)
		if raw := input.Get("purposeKey"); !isUndefined(raw) {
			purpose, err := pvPurposeByKey(ctx, tx, tenant, raw)
			if err != nil {
				return nil, err
			}
			filter.Set("purposeId", purpose.Get("id"))
		}
		if raw := input.Get("subject"); !isUndefined(raw) {
			subject, err := ResolveSubject(ctx, tx, tenant, raw, true)
			if err != nil {
				return nil, err
			}
			filter.Set("subject", subject.Get("key"))
		}
		if raw := input.Get("granted"); !isUndefined(raw) {
			granted, ok := raw.(bool)
			if !ok {
				return nil, invalidInput("granted must be a boolean")
			}
			filter.Set("granted", granted)
		}
		restricted, err := pvRestrictedSubjects(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		now := server.Now()
		rows, err := tx.Find(ctx, "privacyConsents", filter, nil)
		if err != nil {
			return nil, err
		}
		sortStable(rows, pvNewestRecorded)
		views := []any{}
		for _, consent := range pvSlice(rows, offset, limit) {
			purpose := purposes[jsString(consent.Get("purposeId"))]
			if purpose == nil {
				continue
			}
			view, err := pvConsentView(consent, purpose, restricted.Has(jsString(consent.Get("subject"))), now)
			if err != nil {
				return nil, err
			}
			views = append(views, view)
		}
		return core.NewObject("total", float64(len(rows)), "consents", views), nil
	}, false)
	return Out[apitypes.PrivacyListConsentsOutput]{Value: result}, err
}

// History is POST {basePath}/privacy/history. A subject's decision history (newest first, at most 1 000 entries).
func (api *PrivacyAPI) History(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyHistoryInput]) (Out[apitypes.PrivacyHistoryOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:privacy:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		tx, tenant := call.Tx, jsString(call.Tenant.Get("id"))
		subject, err := ResolveSubject(ctx, tx, tenant, input.Get("subject"), true)
		if err != nil {
			return nil, err
		}
		key, err := pvOptionalPurposeKey(input.Get("purposeKey"))
		if err != nil {
			return nil, err
		}
		events, err := tx.Find(ctx, "privacyConsentEvents", core.NewObject("tenantId", tenant, "subject", subject.Get("key")), nil)
		if err != nil {
			return nil, err
		}
		return pvHistory(events, key, 1000), nil
	}, false)
	return Out[apitypes.PrivacyHistoryOutput]{Value: result}, err
}

// VerifyReceipt is POST {basePath}/privacy/verifyReceipt. Checks a consent receipt someone presents: the signature
// (current or previous deployment secret), that the decision is in the history with the same content, and whether
// it is still the subject's current decision.
func (api *PrivacyAPI) VerifyReceipt(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyVerifyReceiptInput]) (Out[apitypes.PrivacyVerifyReceiptOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:privacy:read", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant := call.Tx, jsString(call.Tenant.Get("id"))
		receipt, err := Object(input.Get("receipt"))
		if err != nil {
			return nil, err
		}
		secrets := append([]string{server.Options.Secret}, server.Options.PreviousSecrets...)
		invalid := func(reason string) *core.Object { return core.NewObject("valid", false, "reason", reason) }
		if receipt.Get("tenantId") != tenant {
			return invalid("SIGNATURE_INVALID"), nil
		}
		signed, err := ReceiptSignatureValid(secrets, receipt)
		if err != nil {
			return nil, err
		}
		if !signed {
			return invalid("SIGNATURE_INVALID"), nil
		}
		var event *core.Object
		if receiptID, ok := receipt.Get("receiptId").(string); ok {
			if event, err = tx.Get(ctx, "privacyConsentEvents", receiptID); err != nil {
				return nil, err
			}
		}
		if event == nil || event.Get("tenantId") != tenant {
			return invalid("NOT_RECORDED"), nil
		}
		// Rebuilt with the secret the receipt verified under, so receipts from before a rotation still match.
		var rebuilt *core.Object
		for _, secret := range secrets {
			candidate, err := ReceiptFromEvent(secret, event)
			if err != nil {
				return nil, err
			}
			if candidate.Get("signature") == receipt.Get("signature") {
				rebuilt = candidate
				break
			}
		}
		if rebuilt == nil || core.CanonicalJSON(rebuilt) != core.CanonicalJSON(receipt) {
			return invalid("CONTENT_MISMATCH"), nil
		}
		found, err := tx.Find(ctx, "privacyConsents", core.NewObject("tenantId", tenant, "uniqueKey", jsString(event.Get("purposeId"))+":"+jsString(event.Get("subject"))), nil)
		if err != nil {
			return nil, err
		}
		current := len(found) > 0 && found[0].Get("receiptId") == event.Get("receiptId")
		answer := core.NewObject("valid", true, "current", current)
		if truthy(event.Get("redacted")) {
			answer.Set("redacted", true)
		}
		return answer, nil
	}, false)
	return Out[apitypes.PrivacyVerifyReceiptOutput]{Value: result}, err
}

// ── Data-subject requests ─────────────────────────────────────────────────────────────────────────────────────────

// pvOptionalProse is `value !== undefined ? prose(value, name, max) : undefined` ("" when absent).
func pvOptionalProse(value any, name string, max float64) (string, error) {
	if isUndefined(value) {
		return "", nil
	}
	return Prose(value, name, max)
}

// CreateRequest is POST {basePath}/privacy/createRequest. Files a request on a subject's behalf (received by phone,
// mail or a support ticket). With `verified` (how the handler confirmed who is asking) it opens at once; otherwise it
// waits for `verifyRequest`.
func (api *PrivacyAPI) CreateRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyCreateRequestInput]) (Out[apitypes.PrivacyCreateRequestOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:privacy:handle", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant, principal := call.Tx, call.Tenant, call.Principal
		tenantKey := jsString(tenant.Get("id"))
		requestType, err := pvOneOf(input.Get("type"), SubjectRequestTypes, "type")
		if err != nil {
			return nil, err
		}
		settings, err := PrivacySettings(ctx, tx, tenantKey)
		if err != nil {
			return nil, err
		}
		regulation, err := pvRegulationOf(input.Get("regulation"), settings)
		if err != nil {
			return nil, err
		}
		requesterEmail := ""
		if raw := input.Get("requesterEmail"); !isUndefined(raw) {
			if requesterEmail, err = Email(raw); err != nil {
				return nil, err
			}
		}
		requesterName := ""
		if raw := input.Get("requesterName"); !isUndefined(raw) {
			if requesterName, err = Text(raw, "requesterName", 200); err != nil {
				return nil, err
			}
		}
		var subject *core.Object
		if raw := input.Get("subject"); !isUndefined(raw) {
			if subject, err = ResolveSubject(ctx, tx, tenantKey, raw, false); err != nil {
				return nil, err
			}
		} else if requesterEmail != "" {
			key, err := EmailSubject(server.Options.Secret, requesterEmail)
			if err != nil {
				return nil, err
			}
			subject = core.NewObject("key", key)
		}
		if subject == nil {
			return nil, invalidInput("Name the subject or the requester’s email")
		}
		purposeKeys, err := pvPurposeKeysOf(input.Get("purposeKeys"))
		if err != nil {
			return nil, err
		}
		for _, key := range purposeKeys {
			if _, err := pvPurposeByKey(ctx, tx, tenantKey, key); err != nil {
				return nil, err
			}
		}
		now := server.Now()
		number, err := RequestNumber()
		if err != nil {
			return nil, err
		}
		identityID := principal.Identity.Get("id")
		request := core.NewObject(
			"id", ID(),
			"tenantId", tenantKey,
			"uniqueKey", "number:"+number,
			"number", number,
			"type", requestType,
			"regulation", regulation,
			"status", "pending-verification",
			"subject", subject.Get("key"),
		)
		if truthy(subject.Get("identityId")) {
			request.Set("identityId", subject.Get("identityId"))
		}
		if !isUndefined(subject.Get("externalId")) {
			request.Set("externalId", subject.Get("externalId"))
		}
		if requesterEmail != "" {
			request.Set("requesterEmail", requesterEmail)
		}
		if requesterName != "" {
			request.Set("requesterName", requesterName)
		}
		if raw := input.Get("details"); !isUndefined(raw) {
			details, err := Prose(raw, "details", 5000)
			if err != nil {
				return nil, err
			}
			request.Set("details", details)
		}
		if purposeKeys != nil {
			request.Set("purposeKeys", stringsOf(purposeKeys))
		}
		request.Set("channel", "staff")
		request.Set("verification", core.NewObject("status", "pending"))
		request.Set("submittedAt", float64(now))
		request.Set("events", []any{pvEvent(now, identityID, "submitted", "")})
		if raw := input.Get("verified"); !isUndefined(raw) {
			verified, err := Object(raw)
			if err != nil {
				return nil, err
			}
			how, err := Text(verified.Get("method"), "verified.method", 120)
			if err != nil {
				return nil, err
			}
			if request, err = pvOpened(request, settings, now, core.NewObject(
				"status", "verified", "method", how, "verifiedAt", float64(now), "verifiedBy", identityID,
			)); err != nil {
				return nil, err
			}
			note, err := pvOptionalProse(verified.Get("note"), "verified.note", 2000)
			if err != nil {
				return nil, err
			}
			event := core.NewObject("at", float64(now), "by", identityID, "what", "verified")
			if !isUndefined(verified.Get("note")) {
				event.Set("note", note)
			}
			request.Set("events", pvPushEvent(request, event))
		}
		if _, err := tx.Insert(ctx, "privacyRequests", request); err != nil {
			return nil, err
		}
		if request.Get("status") == "open" {
			if err := pvNotifyContact(ctx, server, tx, tenant, request); err != nil {
				return nil, err
			}
		}
		if err := server.Events.Audit(ctx, tx, principal, "privacy:request:submit", tenantKey, jsString(request.Get("id")), "allow", false,
			core.NewObject("number", number, "type", requestType, "regulation", regulation, "channel", "staff")); err != nil {
			return nil, err
		}
		return pvRequestView(request, now, "")
	}, false)
	return Out[apitypes.PrivacyCreateRequestOutput]{Value: result}, err
}

// pvHandle runs a request-handling operation (`iam:privacy:handle` on the request) with the loaded request.
func pvHandle[T any](ctx context.Context, server *ServerContext, credential core.CredentialInput, input *core.Object, fn func(ctx context.Context, call MutationContext, request *core.Object) (T, error)) (T, error) {
	var zero T
	resourceID, err := Text(input.Get("requestId"), "requestId")
	if err != nil {
		return zero, err
	}
	return Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:privacy:handle", resourceID, func(ctx context.Context, call MutationContext) (T, error) {
		request, err := pvOpenRequest(ctx, server, call.Tx, jsString(call.Tenant.Get("id")), input.Get("requestId"))
		if err != nil {
			return zero, err
		}
		return fn(ctx, call, request)
	}, false)
}

// VerifyRequest is POST {basePath}/privacy/verifyRequest. Records how the requester's identity was confirmed, which
// starts the response window.
func (api *PrivacyAPI) VerifyRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyVerifyRequestInput]) (Out[apitypes.PrivacyVerifyRequestOutput], error) {
	server := api.server
	result, err := pvHandle(ctx, server, credential, input.Body, func(ctx context.Context, call MutationContext, request *core.Object) (*core.Object, error) {
		tx, tenant, principal := call.Tx, call.Tenant, call.Principal
		tenantID := jsString(tenant.Get("id"))
		if request.Get("status") != "pending-verification" {
			return nil, core.NewIamError("INVALID_TRANSITION", "Only unverified requests can be verified", 409)
		}
		now := server.Now()
		settings, err := PrivacySettings(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		method, err := Text(input.Get("method"), "method", 120)
		if err != nil {
			return nil, err
		}
		identityID := principal.Identity.Get("id")
		verified, err := pvOpened(request, settings, now, core.NewObject(
			"status", "verified", "method", method, "verifiedAt", float64(now), "verifiedBy", identityID,
		))
		if err != nil {
			return nil, err
		}
		note, err := pvOptionalProse(input.Get("note"), "note", 2000)
		if err != nil {
			return nil, err
		}
		event := core.NewObject("at", float64(now), "by", identityID, "what", "verified")
		if !isUndefined(input.Get("note")) {
			event.Set("note", note)
		}
		verified.Set("events", pvPushEvent(request, event))
		if _, err := tx.Put(ctx, "privacyRequests", verified); err != nil {
			return nil, err
		}
		if err := pvNotifyContact(ctx, server, tx, tenant, verified); err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "privacy:request:verify", tenantID, jsString(request.Get("id")), "allow", false,
			core.NewObject("number", request.Get("number"), "method", coalesce(member(verified.Get("verification"), "method"), ""))); err != nil {
			return nil, err
		}
		return pvRequestView(verified, now, "")
	})
	return Out[apitypes.PrivacyVerifyRequestOutput]{Value: result}, err
}

// LinkRequest is POST {basePath}/privacy/linkRequest. Links a request filed by email (someone the intake could not
// match to an account) to the account or application subject it is about, once the handler has established that.
// Linking to an account also needs `iam:identities:read` on it. Audited as `privacy:request:link`.
func (api *PrivacyAPI) LinkRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyLinkRequestInput]) (Out[apitypes.PrivacyLinkRequestOutput], error) {
	server := api.server
	result, err := pvHandle(ctx, server, credential, input.Body, func(ctx context.Context, call MutationContext, request *core.Object) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		if !pvHandling(request) {
			return nil, core.NewIamError("INVALID_TRANSITION", "This request is closed", 409)
		}
		if !strings.HasPrefix(jsString(request.Get("subject")), "email:") {
			return nil, core.NewIamError("CONFLICT", "This request is already linked to its subject", 409)
		}
		subject, err := ResolveSubject(ctx, tx, tenantID, input.Get("subject"), false)
		if err != nil {
			return nil, err
		}
		if identityID := subject.Get("identityId"); truthy(identityID) {
			allowed, err := pvDecideIam(ctx, server, tx, principal, tenantID, "iam:identities:read", jsString(identityID))
			if err != nil {
				return nil, err
			}
			if !allowed {
				return nil, NewOperationDenied("Linking a request to an account also needs iam:identities:read")
			}
		}
		now := server.Now()
		note, err := pvOptionalProse(input.Get("note"), "note", 2000)
		if err != nil {
			return nil, err
		}
		linked := request.Spread()
		linked.Set("subject", subject.Get("key"))
		if truthy(subject.Get("identityId")) {
			linked.Set("identityId", subject.Get("identityId"))
		}
		if !isUndefined(subject.Get("externalId")) {
			linked.Set("externalId", subject.Get("externalId"))
		}
		linked.Set("events", pvPushEvent(request, pvEvent(now, principal.Identity.Get("id"), "linked", note)))
		if _, err := tx.Put(ctx, "privacyRequests", linked); err != nil {
			return nil, err
		}
		subjectKind := "external"
		if truthy(subject.Get("identityId")) {
			subjectKind = "account"
		}
		if err := server.Events.Audit(ctx, tx, principal, "privacy:request:link", tenantID, jsString(request.Get("id")), "allow", false,
			core.NewObject("number", request.Get("number"), "subjectKind", subjectKind)); err != nil {
			return nil, err
		}
		return pvRequestView(linked, now, "")
	})
	return Out[apitypes.PrivacyLinkRequestOutput]{Value: result}, err
}

// AssignRequest is POST {basePath}/privacy/assignRequest. Hands a request to a handler (a person of the tenant), or
// clears the assignment with `null`.
func (api *PrivacyAPI) AssignRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyAssignRequestInput]) (Out[apitypes.PrivacyAssignRequestOutput], error) {
	server := api.server
	result, err := pvHandle(ctx, server, credential, input.Body, func(ctx context.Context, call MutationContext, request *core.Object) (*core.Object, error) {
		tx, principal := call.Tx, call.Principal
		tenantID := jsString(call.Tenant.Get("id"))
		if !pvHandling(request) {
			return nil, core.NewIamError("INVALID_TRANSITION", "This request is closed", 409)
		}
		now := server.Now()
		var assignee *core.Object
		if raw := input.Get("assigneeId"); raw != nil {
			assigneeID, err := Text(raw, "assigneeId")
			if err != nil {
				return nil, err
			}
			if assignee, err = server.ActiveIdentity(ctx, tx, assigneeID, tenantID); err != nil {
				return nil, err
			}
			if assignee.Get("kind") != "user" || assignee.Get("status") != "active" {
				return nil, invalidInput("Assign requests to an active person")
			}
		}
		updated := request.Spread()
		updated.Delete("assigneeId")
		if assignee != nil {
			updated.Set("assigneeId", assignee.Get("id"))
		}
		note := "unassigned"
		if assignee != nil {
			note = jsString(coalesce(assignee.Get("email"), assignee.Get("name")))
		}
		event := core.NewObject("at", float64(now), "by", principal.Identity.Get("id"), "what", "assigned", "note", note)
		updated.Set("events", pvPushEvent(request, event))
		if _, err := tx.Put(ctx, "privacyRequests", updated); err != nil {
			return nil, err
		}
		return pvRequestView(updated, now, "")
	})
	return Out[apitypes.PrivacyAssignRequestOutput]{Value: result}, err
}

// ExtendRequest is POST {basePath}/privacy/extendRequest. Extends the response window once by the regulation's
// extension (GDPR two months, CCPA 45 days; LGPD allows none), telling the subject why. Audited as
// `privacy:request:extend`.
func (api *PrivacyAPI) ExtendRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyExtendRequestInput]) (Out[apitypes.PrivacyExtendRequestOutput], error) {
	server := api.server
	result, err := pvHandle(ctx, server, credential, input.Body, func(ctx context.Context, call MutationContext, request *core.Object) (*core.Object, error) {
		tx, tenant, principal := call.Tx, call.Tenant, call.Principal
		tenantID := jsString(tenant.Get("id"))
		if request.Get("status") != "open" || isUndefined(request.Get("dueAt")) {
			return nil, core.NewIamError("INVALID_TRANSITION", "Only open requests can be extended", 409)
		}
		if !isUndefined(request.Get("extendedAt")) {
			return nil, core.NewIamError("CONFLICT", "This request was already extended", 409)
		}
		regulation := jsString(request.Get("regulation"))
		extension := member(RegulationDeadlines.Get(regulation), "extensionDays")
		if !truthy(extension) {
			return nil, core.NewIamError("CONFLICT", regulation+" allows no extension", 409)
		}
		reason, err := Prose(input.Get("reason"), "reason", 2000)
		if err != nil {
			return nil, err
		}
		now := server.Now()
		extended := request.Spread()
		extended.Set("dueAt", jsNumber(request.Get("dueAt"))+jsNumber(extension)*DayMs)
		extended.Set("extendedAt", float64(now))
		extended.Set("extensionReason", reason)
		extended.Set("reminded", []any{})
		extended.Set("events", pvPushEvent(request, pvEvent(now, principal.Identity.Get("id"), "extended", reason)))
		if _, err := tx.Put(ctx, "privacyRequests", extended); err != nil {
			return nil, err
		}
		if err := pvNotifySubject(ctx, server, tx, tenant, extended, "extended", nil); err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "privacy:request:extend", tenantID, jsString(request.Get("id")), "allow", false,
			core.NewObject("number", request.Get("number"), "dueAt", extended.Get("dueAt"))); err != nil {
			return nil, err
		}
		return pvRequestView(extended, now, "")
	})
	return Out[apitypes.PrivacyExtendRequestOutput]{Value: result}, err
}

// AddNote is POST {basePath}/privacy/addNote. Adds an internal note to a request's timeline (not shown to the
// subject).
func (api *PrivacyAPI) AddNote(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyAddNoteInput]) (Out[apitypes.PrivacyAddNoteOutput], error) {
	server := api.server
	result, err := pvHandle(ctx, server, credential, input.Body, func(ctx context.Context, call MutationContext, request *core.Object) (*core.Object, error) {
		if truthy(request.Get("redacted")) {
			return nil, core.NewIamError("CONFLICT", "This request was redacted", 409)
		}
		now := server.Now()
		note, err := Prose(input.Get("note"), "note", 2000)
		if err != nil {
			return nil, err
		}
		updated := request.Spread()
		updated.Set("events", pvPushEvent(request, core.NewObject("at", float64(now), "by", call.Principal.Identity.Get("id"), "what", "note", "note", note)))
		if _, err := call.Tx.Put(ctx, "privacyRequests", updated); err != nil {
			return nil, err
		}
		return pvRequestView(updated, now, "")
	})
	return Out[apitypes.PrivacyAddNoteOutput]{Value: result}, err
}

// FulfilRequest is POST {basePath}/privacy/fulfilRequest. Fulfils an open request. Access and portability build the
// export (portability: only what the person provided); erasure deletes the account (which also needs
// `iam:identities:delete` on it) and erases privacy records, refused under a legal hold (`LEGAL_HOLD`); restriction
// restricts processing; objection and opt-out withdraw the named purposes (or every purpose the person has a say in,
// opt-out: every opt-out purpose); rectification is done by hand and needs a `note`. The subject is emailed; audited
// as `privacy:request:complete` (and `privacy:erasure`).
func (api *PrivacyAPI) FulfilRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyFulfilRequestInput]) (Out[apitypes.PrivacyFulfilRequestOutput], error) {
	server := api.server
	result, err := pvHandle(ctx, server, credential, input.Body, func(ctx context.Context, call MutationContext, request *core.Object) (*core.Object, error) {
		tx, tenant, principal := call.Tx, call.Tenant, call.Principal
		tenantID := jsString(tenant.Get("id"))
		requestType := jsString(request.Get("type"))
		subjectKey := jsString(request.Get("subject"))
		if request.Get("status") != "open" {
			message := "This request is closed"
			if request.Get("status") == "pending-verification" {
				message = "Verify who is asking before fulfilling the request"
			}
			return nil, core.NewIamError("INVALID_TRANSITION", message, 409)
		}
		note, err := pvOptionalProse(input.Get("note"), "note", 2000)
		if err != nil {
			return nil, err
		}
		now := server.Now()
		settings, err := PrivacySettings(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		actions := []string{}
		exportID := ""
		var notifyTo *string
		identityAllowed := func(action string) (bool, error) {
			identityID := request.Get("identityId")
			if !truthy(identityID) {
				return true, nil
			}
			return pvDecideIam(ctx, server, tx, principal, tenantID, action, jsString(identityID))
		}
		if requestType == "access" || requestType == "portability" || requestType == "erasure" {
			// A request from an address nobody linked would answer "nothing held" while an account may exist.
			if strings.HasPrefix(subjectKey, "email:") {
				return nil, invalidInput("Link the request to an account or an application subject (linkRequest), or decline it as no-data")
			}
			// Exporting or erasing everything about someone is as sensitive as identities.export / delete.
			if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
				return nil, err
			}
		}
		switch requestType {
		case "access", "portability":
			allowed, err := identityAllowed("iam:identities:read")
			if err != nil {
				return nil, err
			}
			if !allowed {
				return nil, NewOperationDenied("Exporting a person’s data also needs iam:identities:read")
			}
			scope := "provided"
			if requestType == "access" {
				scope = "full"
			}
			auditAllowed, err := pvDecideIam(ctx, server, tx, principal, tenantID, "iam:audit:read", tenantID)
			if err != nil {
				return nil, err
			}
			data, err := pvBuildExport(ctx, server, tx, tenant, request, scope, auditAllowed)
			if err != nil {
				return nil, err
			}
			exportID = ID()
			record := core.NewObject(
				"id", exportID,
				"tenantId", tenantID,
				"requestId", request.Get("id"),
				"subject", request.Get("subject"),
			)
			if truthy(request.Get("identityId")) {
				record.Set("identityId", request.Get("identityId"))
			}
			record.Set("scope", scope)
			record.Set("createdAt", float64(now))
			record.Set("expiresAt", float64(now)+jsNumber(settings.Get("exportLifetimeDays"))*DayMs)
			record.Set("sha256", Hash(core.CanonicalJSON(data)))
			record.Set("data", data)
			record.Set("downloads", 0.0)
			if _, err := tx.Insert(ctx, "privacyExports", record); err != nil {
				return nil, err
			}
			actions = append(actions, "export:"+scope)
		case "erasure":
			hold, err := ActiveHold(ctx, tx, tenantID, subjectKey, now)
			if err != nil {
				return nil, err
			}
			if hold != nil {
				return nil, core.NewIamError("LEGAL_HOLD", "This subject is under a legal hold; release it or reject the request as exempt", 409)
			}
			allowed, err := identityAllowed("iam:identities:delete")
			if err != nil {
				return nil, err
			}
			if !allowed {
				return nil, NewOperationDenied("Erasing an account also needs iam:identities:delete")
			}
			if notifyTo, err = pvSubjectAddress(ctx, tx, request); err != nil {
				return nil, err
			}
			erased, err := pvEraseSubject(ctx, server, tx, principal, tenant, request)
			if err != nil {
				return nil, err
			}
			actions = append(actions, erased...)
		case "restriction":
			if strings.HasPrefix(subjectKey, "email:") {
				return nil, invalidInput("Link the request to an account or an application subject before restricting processing")
			}
			restriction, err := RestrictionOf(ctx, tx, tenantID, subjectKey)
			if err != nil {
				return nil, err
			}
			if restriction == nil {
				record := core.NewObject("id", ID(), "tenantId", tenantID, "subject", request.Get("subject"))
				if truthy(request.Get("identityId")) {
					record.Set("identityId", request.Get("identityId"))
				}
				if !isUndefined(request.Get("externalId")) {
					record.Set("externalId", request.Get("externalId"))
				}
				record.Set("requestId", request.Get("id"))
				record.Set("restrictedAt", float64(now))
				record.Set("restrictedBy", principal.Identity.Get("id"))
				if _, err := tx.Insert(ctx, "privacyRestrictions", record); err != nil {
					return nil, err
				}
			}
			actions = append(actions, "restricted")
		case "objection", "opt-out":
			if strings.HasPrefix(subjectKey, "email:") {
				return nil, invalidInput("Link the request to an account or an application subject before withdrawing consent")
			}
			all, err := tx.Find(ctx, "privacyPurposes", core.NewObject("tenantId", tenantID), nil)
			if err != nil {
				return nil, err
			}
			named, _ := request.Get("purposeKeys").([]any)
			var targets []*core.Object
			for _, purpose := range all {
				var include bool
				if len(named) > 0 {
					for _, key := range named {
						if key == purpose.Get("key") {
							include = true
							break
						}
					}
				} else if requestType == "opt-out" {
					include = purpose.Get("legalBasis") == "consent" && purpose.Get("mode") == "opt-out"
				} else if include, err = Decidable(purpose); err != nil {
					return nil, err
				}
				if include {
					targets = append(targets, purpose)
				}
			}
			subject := core.NewObject("key", request.Get("subject"))
			if truthy(request.Get("identityId")) {
				subject.Set("identityId", request.Get("identityId"))
			}
			if !isUndefined(request.Get("externalId")) {
				subject.Set("externalId", request.Get("externalId"))
			}
			withdrawn := 0
			for _, purpose := range targets {
				decidable, err := Decidable(purpose)
				if err != nil {
					return nil, err
				}
				if !decidable {
					continue
				}
				if _, _, err := pvWriteConsent(ctx, server, tx, pvConsentInput{
					tenantID:   tenantID,
					purpose:    purpose,
					subject:    subject,
					granted:    false,
					source:     "request",
					method:     "request:" + jsString(request.Get("number")),
					recordedBy: jsString(principal.Identity.Get("id")),
					at:         float64(now),
				}); err != nil {
					return nil, err
				}
				withdrawn++
			}
			actions = append(actions, "consents-withdrawn:"+jsString(float64(withdrawn)))
		case "rectification":
			if note == "" {
				return nil, invalidInput("Describe what was corrected in the note")
			}
			actions = append(actions, "rectified")
		}
		base := request
		if requestType == "erasure" {
			base = pvRedact(request)
		}
		identityID := principal.Identity.Get("id")
		completed := base.Spread()
		completed.Set("status", "completed")
		completed.Set("closedAt", float64(now))
		completed.Set("closedBy", identityID)
		completed.Set("actions", stringsOf(actions))
		if exportID != "" {
			completed.Set("exportId", exportID)
		}
		completedNote := ""
		if requestType != "erasure" {
			completedNote = note
		}
		completed.Set("events", pvPushEvent(base, pvEvent(now, identityID, "completed", completedNote)))
		if _, err := tx.Put(ctx, "privacyRequests", completed); err != nil {
			return nil, err
		}
		if err := pvNotifySubject(ctx, server, tx, tenant, completed, "completed", notifyTo); err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "privacy:request:complete", tenantID, jsString(request.Get("id")), "allow", false,
			core.NewObject("number", request.Get("number"), "type", requestType, "actions", stringsOf(actions))); err != nil {
			return nil, err
		}
		if requestType == "erasure" {
			subjectKind := "requester"
			if truthy(request.Get("identityId")) {
				subjectKind = "account"
			} else if !isUndefined(request.Get("externalId")) {
				subjectKind = "external"
			}
			metadata := core.NewObject("requestId", request.Get("id"), "subjectKind", subjectKind)
			if externalID := request.Get("externalId"); !isUndefined(externalID) {
				metadata.Set("externalId", externalID)
			}
			if err := server.Events.Audit(ctx, tx, principal, "privacy:erasure", tenantID, jsString(coalesce(request.Get("identityId"), request.Get("subject"))), "allow", false, metadata); err != nil {
				return nil, err
			}
		}
		return pvRequestView(completed, now, "")
	})
	return Out[apitypes.PrivacyFulfilRequestOutput]{Value: result}, err
}

// RejectRequest is POST {basePath}/privacy/rejectRequest. Refuses a request (`unverified`, `unfounded`, `excessive`,
// `exempt`, `duplicate`, `other`) with a note the subject is told. Audited as `privacy:request:reject`.
func (api *PrivacyAPI) RejectRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyRejectRequestInput]) (Out[apitypes.PrivacyRejectRequestOutput], error) {
	server := api.server
	result, err := pvHandle(ctx, server, credential, input.Body, func(ctx context.Context, call MutationContext, request *core.Object) (*core.Object, error) {
		tx, tenant, principal := call.Tx, call.Tenant, call.Principal
		tenantID := jsString(tenant.Get("id"))
		if !pvHandling(request) {
			return nil, core.NewIamError("INVALID_TRANSITION", "This request is closed", 409)
		}
		reason, err := pvOneOf(input.Get("reason"), RejectionReasons, "reason")
		if err != nil {
			return nil, err
		}
		now := server.Now()
		identityID := principal.Identity.Get("id")
		rejected := request.Spread()
		rejected.Delete("tokenHash")
		rejected.Delete("tokenExpiresAt")
		rejected.Set("status", "rejected")
		rejected.Set("rejectionReason", reason)
		rejected.Set("closedAt", float64(now))
		rejected.Set("closedBy", identityID)
		note, err := pvOptionalProse(input.Get("note"), "note", 2000)
		if err != nil {
			return nil, err
		}
		event := core.NewObject("at", float64(now), "by", identityID, "what", "rejected")
		if !isUndefined(input.Get("note")) {
			event.Set("note", note)
		}
		rejected.Set("events", pvPushEvent(request, event))
		if _, err := tx.Put(ctx, "privacyRequests", rejected); err != nil {
			return nil, err
		}
		if err := pvNotifySubject(ctx, server, tx, tenant, rejected, "rejected", nil); err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, principal, "privacy:request:reject", tenantID, jsString(request.Get("id")), "allow", false,
			core.NewObject("number", request.Get("number"), "type", request.Get("type"), "reason", reason)); err != nil {
			return nil, err
		}
		return pvRequestView(rejected, now, "")
	})
	return Out[apitypes.PrivacyRejectRequestOutput]{Value: result}, err
}

// ListRequests is POST {basePath}/privacy/listRequests. Requests, filtered by status, type, assignee or `overdue`;
// open ones by deadline, then newest first.
func (api *PrivacyAPI) ListRequests(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyListRequestsInput]) (Out[apitypes.PrivacyListRequestsOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:privacy:read", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant := call.Tx, jsString(call.Tenant.Get("id"))
		limit, err := Integer(coalesce(input.Get("limit"), 100.0), "limit", 1, 500)
		if err != nil {
			return nil, err
		}
		offset, err := Integer(coalesce(input.Get("offset"), 0.0), "offset", 0, 10_000_000)
		if err != nil {
			return nil, err
		}
		filter := core.NewObject("tenantId", tenant)
		if raw := input.Get("status"); !isUndefined(raw) {
			status, err := pvOneOf(raw, []string{"pending-verification", "open", "completed", "rejected", "cancelled"}, "status")
			if err != nil {
				return nil, err
			}
			filter.Set("status", status)
		}
		if raw := input.Get("type"); !isUndefined(raw) {
			requestType, err := pvOneOf(raw, SubjectRequestTypes, "type")
			if err != nil {
				return nil, err
			}
			filter.Set("type", requestType)
		}
		if raw := input.Get("assigneeId"); !isUndefined(raw) {
			assigneeID, err := Text(raw, "assigneeId")
			if err != nil {
				return nil, err
			}
			filter.Set("assigneeId", assigneeID)
		}
		if raw := input.Get("subject"); !isUndefined(raw) {
			subject, err := ResolveSubject(ctx, tx, tenant, raw, true)
			if err != nil {
				return nil, err
			}
			filter.Set("subject", subject.Get("key"))
		}
		now := server.Now()
		found, err := tx.Find(ctx, "privacyRequests", filter, nil)
		if err != nil {
			return nil, err
		}
		var rows []*core.Object
		for _, request := range found {
			if input.Get("overdue") == true {
				overdue, err := RequestOverdue(request, now)
				if err != nil {
					return nil, err
				}
				if !overdue {
					continue
				}
			}
			rows = append(rows, request)
		}
		sortStable(rows, func(a, b *core.Object) int {
			aOpen, bOpen := a.Get("status") == "open", b.Get("status") == "open"
			if difference := pvBit(bOpen) - pvBit(aOpen); difference != 0 {
				return difference
			}
			var difference float64
			if aOpen && bOpen {
				difference = jsNumber(coalesce(a.Get("dueAt"), 0.0)) - jsNumber(coalesce(b.Get("dueAt"), 0.0))
			} else {
				difference = jsNumber(b.Get("submittedAt")) - jsNumber(a.Get("submittedAt"))
			}
			if difference != 0 && !math.IsNaN(difference) {
				return pvSign(difference)
			}
			if compareUTF16(jsString(a.Get("id")), jsString(b.Get("id"))) < 0 {
				return -1
			}
			return 1
		})
		page := pvSlice(rows, offset, limit)
		names, err := pvSubjectNames(ctx, tx, page)
		if err != nil {
			return nil, err
		}
		requests := make([]any, 0, len(page))
		for _, request := range page {
			view, err := pvRequestView(request, now, pvNameOf(names, request))
			if err != nil {
				return nil, err
			}
			requests = append(requests, view)
		}
		return core.NewObject("total", float64(len(rows)), "requests", requests), nil
	}, false)
	return Out[apitypes.PrivacyListRequestsOutput]{Value: result}, err
}

// GetRequest is POST {basePath}/privacy/getRequest. Returns one request with the subject's legal hold and restriction
// status.
func (api *PrivacyAPI) GetRequest(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyGetRequestInput]) (Out[apitypes.PrivacyGetRequestOutput], error) {
	server := api.server
	resourceID, err := Text(input.Get("requestId"), "requestId")
	if err != nil {
		return Out[apitypes.PrivacyGetRequestOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:privacy:read", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenantID := call.Tx, jsString(call.Tenant.Get("id"))
		request, err := pvOpenRequest(ctx, server, tx, tenantID, input.Get("requestId"))
		if err != nil {
			return nil, err
		}
		names, err := pvSubjectNames(ctx, tx, []*core.Object{request})
		if err != nil {
			return nil, err
		}
		subject := jsString(request.Get("subject"))
		hold, err := ActiveHold(ctx, tx, tenantID, subject, server.Now())
		if err != nil {
			return nil, err
		}
		view, err := pvRequestView(request, server.Now(), pvNameOf(names, request))
		if err != nil {
			return nil, err
		}
		view.Set("legalHold", hold != nil)
		restriction, err := RestrictionOf(ctx, tx, tenantID, subject)
		if err != nil {
			return nil, err
		}
		view.Set("restricted", restriction != nil)
		return view, nil
	}, false)
	return Out[apitypes.PrivacyGetRequestOutput]{Value: result}, err
}

// ── Public intake ─────────────────────────────────────────────────────────────────────────────────────────────────

// SubmitPublic is POST {basePath}/privacy/submitPublic (public: no request credential). Public request form for people
// without an account (or who cannot sign in), when the organization turned on `publicIntake`. The requester confirms
// their email address through the emailed link (`confirmPublic`) before anyone handles it; unconfirmed requests lapse
// after seven days. Rate limited per organization and address.
func (api *PrivacyAPI) SubmitPublic(ctx context.Context, input In[apitypes.PrivacySubmitPublicInput]) (Out[apitypes.PrivacySubmitPublicOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.PrivacySubmitPublicOutput], error) {
		return Out[apitypes.PrivacySubmitPublicOutput]{}, err
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return fail(err)
	}
	address, err := Email(input.Get("email"))
	if err != nil {
		return fail(err)
	}
	requestType, err := pvOneOf(input.Get("type"), SubjectRequestTypes, "type")
	if err != nil {
		return fail(err)
	}
	details, err := pvOptionalProse(input.Get("details"), "details", 5000)
	if err != nil {
		return fail(err)
	}
	name := ""
	if raw := input.Get("name"); !isUndefined(raw) {
		if name, err = Text(raw, "name", 200); err != nil {
			return fail(err)
		}
	}
	var externalID any = core.Undefined
	if raw := input.Get("externalId"); !isUndefined(raw) {
		if externalID, err = ExternalSubjectID(raw); err != nil {
			return fail(err)
		}
	}
	purposeKeys, err := pvPurposeKeysOf(input.Get("purposeKeys"))
	if err != nil {
		return fail(err)
	}
	// Counted outside the transaction, so a refusal cannot roll the counters back. The per-address budget is the main
	// control (with the per-IP counter when `rateLimits.ipAttempts` is on); the organization-wide one only caps floods,
	// so it is generous enough that one sender cannot lock others out.
	tenantBudget, addressBudget := int64(500), int64(3)
	if err := server.Auth.LimitAttempt(ctx, tenantID, "privacy-intake", auth.LimitAttemptOptions{Limit: &tenantBudget}); err != nil {
		return fail(err)
	}
	if err := server.Auth.LimitAttempt(ctx, tenantID, "privacy-intake:"+address, auth.LimitAttemptOptions{Limit: &addressBudget}); err != nil {
		return fail(err)
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		tenant, err := tx.Get(ctx, "tenants", tenantID)
		if err != nil {
			return nil, err
		}
		var settings *core.Object
		if tenant != nil {
			if settings, err = PrivacySettings(ctx, tx, tenantID); err != nil {
				return nil, err
			}
		}
		if tenant == nil || tenant.Get("status") != "active" || settings == nil || !truthy(settings.Get("publicIntake")) {
			return nil, core.NewIamError("NOT_FOUND", "Not found", 404)
		}
		if !pvCanEmail(server) {
			return nil, core.NewIamError("DELIVERY_REQUIRED", "Public requests need an email delivery callback")
		}
		for _, key := range purposeKeys {
			if _, err := pvPurposeByKey(ctx, tx, tenantID, key); err != nil {
				return nil, err
			}
		}
		now := server.Now()
		number, err := RequestNumber()
		if err != nil {
			return nil, err
		}
		secret := Token()
		regulation, err := pvRegulationOf(input.Get("regulation"), settings)
		if err != nil {
			return nil, err
		}
		var subject string
		if !isUndefined(externalID) {
			subject = "external:" + jsString(externalID)
		} else if subject, err = EmailSubject(server.Options.Secret, address); err != nil {
			return nil, err
		}
		request := core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"uniqueKey", "number:"+number,
			"number", number,
			"type", requestType,
			"regulation", regulation,
			"status", "pending-verification",
			"subject", subject,
		)
		if !isUndefined(externalID) {
			request.Set("externalId", externalID)
		}
		request.Set("requesterEmail", address)
		if name != "" {
			request.Set("requesterName", name)
		}
		if details != "" {
			request.Set("details", details)
		}
		if purposeKeys != nil {
			request.Set("purposeKeys", stringsOf(purposeKeys))
		}
		request.Set("channel", "public")
		request.Set("verification", core.NewObject("status", "pending"))
		request.Set("tokenHash", Hash(secret))
		request.Set("tokenExpiresAt", float64(now)+pvVerificationLifetimeMs)
		request.Set("submittedAt", float64(now))
		request.Set("events", []any{
			pvEvent(now, "requester", "submitted", ""),
			pvEvent(now, "requester", "verification-sent", ""),
		})
		if _, err := tx.Insert(ctx, "privacyRequests", request); err != nil {
			return nil, err
		}
		if _, err := server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
			TenantID: tenantID, Kind: "email", To: address, Template: "privacy-request-verify",
			Payload: core.NewObject(
				"tenantId", tenantID,
				"tenantName", tenant.Get("name"),
				"requestId", request.Get("id"),
				"number", number,
				"type", requestType,
				"token", secret,
			),
		}); err != nil {
			return nil, err
		}
		if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"actorId", "public-intake",
			"action", "privacy:request:submit",
			"resourceId", request.Get("id"),
			"timestamp", float64(now),
			"outcome", "allow",
			"metadata", core.NewObject("number", number, "type", requestType, "regulation", regulation, "channel", "public"),
		)); err != nil {
			return nil, err
		}
		return core.NewObject("number", number, "status", request.Get("status")), nil
	})
	return Out[apitypes.PrivacySubmitPublicOutput]{Value: result}, err
}

// ConfirmPublic is POST {basePath}/privacy/confirmPublic (public: no request credential). Confirms a public request
// from the emailed link. The response window starts now; when the address belongs to a person here with a verified
// email, the request is linked to their account. A request naming an application identifier (`externalId`) stays
// unverified: owning the address does not prove owning the identifier, so a handler checks it (`verifyRequest`)
// before anything is exported, withdrawn or erased.
func (api *PrivacyAPI) ConfirmPublic(ctx context.Context, input In[apitypes.PrivacyConfirmPublicInput]) (Out[apitypes.PrivacyConfirmPublicOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.PrivacyConfirmPublicOutput], error) {
		return Out[apitypes.PrivacyConfirmPublicOutput]{}, err
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return fail(err)
	}
	requestID, err := Text(input.Get("requestId"), "requestId")
	if err != nil {
		return fail(err)
	}
	presented, err := Text(input.Get("token"), "token", 512)
	if err != nil {
		return fail(err)
	}
	budget := int64(10)
	if err := server.Auth.LimitAttempt(ctx, tenantID, "privacy-confirm:"+requestID, auth.LimitAttemptOptions{Limit: &budget}); err != nil {
		return fail(err)
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		request, err := tx.Get(ctx, "privacyRequests", requestID)
		if err != nil {
			return nil, err
		}
		now := server.Now()
		if request == nil ||
			request.Get("tenantId") != tenantID ||
			request.Get("status") != "pending-verification" ||
			!truthy(request.Get("tokenHash")) ||
			!SameHash(request.Get("tokenHash"), Hash(presented)) ||
			jsNumber(coalesce(request.Get("tokenExpiresAt"), 0.0)) <= float64(now) {
			return nil, core.NewIamError("CONFIRMATION_INVALID", "This confirmation link is invalid or has expired", 400)
		}
		tenant, err := server.Tenant(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		settings, err := PrivacySettings(ctx, tx, tenantID)
		if err != nil {
			return nil, err
		}
		if !isUndefined(request.Get("externalId")) {
			confirmed := request.Spread()
			confirmed.Delete("tokenHash")
			confirmed.Delete("tokenExpiresAt")
			confirmed.Set("emailConfirmedAt", float64(now))
			confirmed.Set("events", pvPushEvent(request, pvEvent(now, "requester", "email-confirmed", "The address is confirmed; a handler must still confirm the identifier")))
			if _, err := tx.Put(ctx, "privacyRequests", confirmed); err != nil {
				return nil, err
			}
			if err := pvNotifyContact(ctx, server, tx, tenant, confirmed); err != nil {
				return nil, err
			}
			if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
				"id", ID(),
				"tenantId", tenantID,
				"actorId", "public-intake",
				"action", "privacy:request:email-confirmed",
				"resourceId", request.Get("id"),
				"timestamp", float64(now),
				"outcome", "allow",
				"metadata", core.NewObject("number", request.Get("number")),
			)); err != nil {
				return nil, err
			}
			return core.NewObject("number", confirmed.Get("number"), "status", confirmed.Get("status")), nil
		}
		linked := request
		if requester := request.Get("requesterEmail"); truthy(requester) {
			people, err := tx.Find(ctx, "identities", core.NewObject("tenantId", tenantID, "email", requester), nil)
			if err != nil {
				return nil, err
			}
			for _, identity := range people {
				if identity.Get("kind") == "user" && identity.Get("status") != "deleted" && truthy(identity.Get("emailVerified")) {
					subject, err := IdentitySubject(jsString(identity.Get("id")))
					if err != nil {
						return nil, err
					}
					linked = request.Spread()
					linked.Set("subject", subject)
					linked.Set("identityId", identity.Get("id"))
					break
				}
			}
		}
		verified, err := pvOpened(linked, settings, now, core.NewObject("status", "verified", "method", "email-link", "verifiedAt", float64(now)))
		if err != nil {
			return nil, err
		}
		verified.Set("events", pvPushEvent(request, pvEvent(now, "requester", "verified", "")))
		if _, err := tx.Put(ctx, "privacyRequests", verified); err != nil {
			return nil, err
		}
		if err := pvNotifyContact(ctx, server, tx, tenant, verified); err != nil {
			return nil, err
		}
		if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"actorId", "public-intake",
			"action", "privacy:request:verify",
			"resourceId", request.Get("id"),
			"timestamp", float64(now),
			"outcome", "allow",
			"metadata", core.NewObject("number", request.Get("number"), "method", "email-link", "linked", truthy(verified.Get("identityId"))),
		)); err != nil {
			return nil, err
		}
		answer := core.NewObject("number", verified.Get("number"), "status", verified.Get("status"))
		if dueAt := verified.Get("dueAt"); !isUndefined(dueAt) {
			answer.Set("dueAt", dueAt)
		}
		return answer, nil
	})
	return Out[apitypes.PrivacyConfirmPublicOutput]{Value: result}, err
}

// ── Holds and restriction ─────────────────────────────────────────────────────────────────────────────────────────

// PlaceHold is POST {basePath}/privacy/placeHold. Places a legal hold: erasure of the subject (and deletion of their
// account) is refused until it is released.
func (api *PrivacyAPI) PlaceHold(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyPlaceHoldInput]) (Out[apitypes.PrivacyPlaceHoldOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:privacy:manage", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant, principal := call.Tx, jsString(call.Tenant.Get("id")), call.Principal
		subject, err := ResolveSubject(ctx, tx, tenant, input.Get("subject"), false)
		if err != nil {
			return nil, err
		}
		now := server.Now()
		var expiresAt any = core.Undefined
		if raw := input.Get("expiresAt"); !isUndefined(raw) {
			if expiresAt, err = server.BindingExpiry(raw); err != nil {
				return nil, err
			}
		}
		hold := core.NewObject("id", ID(), "tenantId", tenant, "subject", subject.Get("key"))
		if truthy(subject.Get("identityId")) {
			hold.Set("identityId", subject.Get("identityId"))
		}
		if !isUndefined(subject.Get("externalId")) {
			hold.Set("externalId", subject.Get("externalId"))
		}
		reason, err := Prose(input.Get("reason"), "reason", 2000)
		if err != nil {
			return nil, err
		}
		hold.Set("reason", reason)
		hold.Set("placedBy", principal.Identity.Get("id"))
		hold.Set("placedAt", float64(now))
		if !isUndefined(expiresAt) {
			hold.Set("expiresAt", expiresAt)
		}
		if _, err := tx.Insert(ctx, "privacyHolds", hold); err != nil {
			return nil, err
		}
		metadata := core.NewObject("holdId", hold.Get("id"))
		if !isUndefined(expiresAt) {
			metadata.Set("expiresAt", expiresAt)
		}
		if err := server.Events.Audit(ctx, tx, principal, "privacy:hold:place", tenant, jsString(coalesce(subject.Get("identityId"), subject.Get("key"))), "allow", false, metadata); err != nil {
			return nil, err
		}
		return hold, nil
	}, false)
	return Out[apitypes.PrivacyPlaceHoldOutput]{Value: result}, err
}

// ReleaseHold is POST {basePath}/privacy/releaseHold. Releases a legal hold.
func (api *PrivacyAPI) ReleaseHold(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyReleaseHoldInput]) (Out[apitypes.PrivacyReleaseHoldOutput], error) {
	server := api.server
	resourceID, err := Text(input.Get("holdId"), "holdId")
	if err != nil {
		return Out[apitypes.PrivacyReleaseHoldOutput]{}, err
	}
	result, err := Operate(ctx, server.Operations, credential, input.Get("tenantId"), "iam:privacy:manage", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant := call.Tx, jsString(call.Tenant.Get("id"))
		hold, err := server.Scoped(ctx, tx, "privacyHolds", input.Get("holdId"), tenant)
		if err != nil {
			return nil, err
		}
		if err := tx.Delete(ctx, "privacyHolds", jsString(hold.Get("id"))); err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, call.Principal, "privacy:hold:release", tenant, jsString(coalesce(hold.Get("identityId"), hold.Get("subject"))), "allow", false,
			core.NewObject("holdId", hold.Get("id"))); err != nil {
			return nil, err
		}
		return core.NewObject("released", true), nil
	}, false)
	return Out[apitypes.PrivacyReleaseHoldOutput]{Value: result}, err
}

// ListHolds is POST {basePath}/privacy/listHolds. Lists the tenant's legal holds, newest first.
func (api *PrivacyAPI) ListHolds(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyListHoldsInput]) (Out[apitypes.PrivacyListHoldsOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:privacy:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		now := float64(server.Now())
		found, err := call.Tx.Find(ctx, "privacyHolds", core.NewObject("tenantId", call.Tenant.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		holds := make([]*core.Object, 0, len(found))
		for _, hold := range found {
			expiresAt := hold.Get("expiresAt")
			holds = append(holds, hold.Spread(core.NewObject("active", isUndefined(expiresAt) || jsNumber(expiresAt) > now)))
		}
		sortStable(holds, func(a, b *core.Object) int {
			return pvSign(jsNumber(b.Get("placedAt")) - jsNumber(a.Get("placedAt")))
		})
		return pvList(holds), nil
	}, false)
	return Out[apitypes.PrivacyListHoldsOutput]{Value: result}, err
}

// ListRestrictions is POST {basePath}/privacy/listRestrictions. Subjects whose processing is restricted, newest
// first.
func (api *PrivacyAPI) ListRestrictions(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyListRestrictionsInput]) (Out[apitypes.PrivacyListRestrictionsOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:privacy:read", jsString(tenantID), func(ctx context.Context, call MutationContext) ([]any, error) {
		found, err := call.Tx.Find(ctx, "privacyRestrictions", core.NewObject("tenantId", call.Tenant.Get("id")), nil)
		if err != nil {
			return nil, err
		}
		sortStable(found, func(a, b *core.Object) int {
			return pvSign(jsNumber(b.Get("restrictedAt")) - jsNumber(a.Get("restrictedAt")))
		})
		return pvList(found), nil
	}, false)
	return Out[apitypes.PrivacyListRestrictionsOutput]{Value: result}, err
}

// LiftRestriction is POST {basePath}/privacy/liftRestriction. Ends a restriction of processing (the subject should be
// told before it ends).
func (api *PrivacyAPI) LiftRestriction(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyLiftRestrictionInput]) (Out[apitypes.PrivacyLiftRestrictionOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:privacy:handle", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant := call.Tx, jsString(call.Tenant.Get("id"))
		subject, err := ResolveSubject(ctx, tx, tenant, input.Get("subject"), true)
		if err != nil {
			return nil, err
		}
		restriction, err := RestrictionOf(ctx, tx, tenant, jsString(subject.Get("key")))
		if err != nil {
			return nil, err
		}
		if restriction == nil {
			return nil, core.NewIamError("NOT_FOUND", "No restriction for this subject", 404)
		}
		if err := tx.Delete(ctx, "privacyRestrictions", jsString(restriction.Get("id"))); err != nil {
			return nil, err
		}
		if err := server.Events.Audit(ctx, tx, call.Principal, "privacy:restriction:lift", tenant, jsString(coalesce(subject.Get("identityId"), subject.Get("key"))), "allow", false, nil); err != nil {
			return nil, err
		}
		return core.NewObject("lifted", true), nil
	}, false)
	return Out[apitypes.PrivacyLiftRestrictionOutput]{Value: result}, err
}

// ── Settings and reporting ────────────────────────────────────────────────────────────────────────────────────────

// GetSettings is POST {basePath}/privacy/getSettings. Returns the tenant's privacy settings with the statutory
// windows.
func (api *PrivacyAPI) GetSettings(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyGetSettingsInput]) (Out[apitypes.PrivacyGetSettingsOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:privacy:read", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		settings, err := PrivacySettings(ctx, call.Tx, jsString(call.Tenant.Get("id")))
		if err != nil {
			return nil, err
		}
		return pvSettingsView(settings), nil
	}, false)
	return Out[apitypes.PrivacyGetSettingsOutput]{Value: result}, err
}

// UpdateSettings is POST {basePath}/privacy/updateSettings. Updates the privacy contact, the default regulation,
// shorter internal response windows, public intake and how long exports stay downloadable. `null` clears an optional
// field.
func (api *PrivacyAPI) UpdateSettings(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacyUpdateSettingsInput]) (Out[apitypes.PrivacyUpdateSettingsOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:privacy:manage", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		previous, err := PrivacySettings(ctx, tx, jsString(call.Tenant.Get("id")))
		if err != nil {
			return nil, err
		}
		next := previous.Spread(core.NewObject("updatedAt", float64(server.Now())))
		switch raw := input.Get("contactEmail"); {
		case raw == nil:
			next.Delete("contactEmail")
		case !isUndefined(raw):
			address, err := Email(raw)
			if err != nil {
				return nil, err
			}
			next.Set("contactEmail", address)
		}
		switch raw := input.Get("contactName"); {
		case raw == nil:
			next.Delete("contactName")
		case !isUndefined(raw):
			name, err := Text(raw, "contactName", 200)
			if err != nil {
				return nil, err
			}
			next.Set("contactName", name)
		}
		if raw := input.Get("defaultRegulation"); !isUndefined(raw) {
			regulation, err := pvOneOf(raw, Regulations, "defaultRegulation")
			if err != nil {
				return nil, err
			}
			next.Set("defaultRegulation", regulation)
		}
		switch raw := input.Get("responseDays"); {
		case raw == nil:
			next.Delete("responseDays")
		case !isUndefined(raw):
			entries, err := Object(raw)
			if err != nil {
				return nil, err
			}
			days := core.NewObject()
			var failure error
			entries.Entries(func(key string, value any) bool {
				regulation, err := pvOneOf(key, Regulations, "responseDays key")
				if err != nil {
					failure = err
					return false
				}
				statutory := jsNumber(member(RegulationDeadlines.Get(regulation), "responseDays"))
				number, err := Integer(value, "responseDays."+regulation, 1, statutory)
				if err != nil {
					failure = err
					return false
				}
				days.Set(regulation, number)
				return true
			})
			if failure != nil {
				return nil, failure
			}
			if days.Len() > 0 {
				next.Set("responseDays", days)
			} else {
				next.Delete("responseDays")
			}
		}
		if raw := input.Get("publicIntake"); !isUndefined(raw) {
			intake, ok := raw.(bool)
			if !ok {
				return nil, invalidInput("publicIntake must be a boolean")
			}
			if intake && !pvCanEmail(server) {
				return nil, core.NewIamError("DELIVERY_REQUIRED", "Public requests need an email delivery callback to confirm addresses")
			}
			next.Set("publicIntake", intake)
		}
		if raw := input.Get("exportLifetimeDays"); !isUndefined(raw) {
			lifetime, err := Integer(raw, "exportLifetimeDays", 1, 90)
			if err != nil {
				return nil, err
			}
			next.Set("exportLifetimeDays", lifetime)
		}
		stored, err := tx.Get(ctx, "privacySettings", jsString(next.Get("id")))
		if err != nil {
			return nil, err
		}
		if stored != nil {
			_, err = tx.Put(ctx, "privacySettings", next)
		} else {
			_, err = tx.Insert(ctx, "privacySettings", next)
		}
		if err != nil {
			return nil, err
		}
		return pvSettingsView(next), nil
	}, false)
	return Out[apitypes.PrivacyUpdateSettingsOutput]{Value: result}, err
}

// Summary is POST {basePath}/privacy/summary. Consent counts per purpose, the request queue, holds and restrictions at
// a glance.
func (api *PrivacyAPI) Summary(ctx context.Context, credential core.CredentialInput, input In[apitypes.PrivacySummaryInput]) (Out[apitypes.PrivacySummaryOutput], error) {
	server := api.server
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:privacy:read", jsString(tenantID), func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx, tenant := call.Tx, jsString(call.Tenant.Get("id"))
		now := server.Now()
		nowMs := float64(now)
		restricted, err := pvRestrictedSubjects(ctx, tx, tenant)
		if err != nil {
			return nil, err
		}
		consents, err := tx.Find(ctx, "privacyConsents", core.NewObject("tenantId", tenant), nil)
		if err != nil {
			return nil, err
		}
		purposeRows, err := tx.Find(ctx, "privacyPurposes", core.NewObject("tenantId", tenant), nil)
		if err != nil {
			return nil, err
		}
		sortStable(purposeRows, func(a, b *core.Object) int {
			return localeCompare(jsString(a.Get("name")), jsString(b.Get("name")))
		})
		purposes := make([]any, 0, len(purposeRows))
		for _, purpose := range purposeRows {
			var granted, withdrawn, expired, outdated float64
			for _, consent := range consents {
				if consent.Get("purposeId") != purpose.Get("id") {
					continue
				}
				state, err := ConsentState(purpose, consent, restricted.Has(jsString(consent.Get("subject"))), now)
				if err != nil {
					return nil, err
				}
				reason := state.Get("reason")
				switch {
				case state.Get("allowed") == true:
					granted++
				case reason == "CONSENT_EXPIRED":
					expired++
				case reason == "CONSENT_OUTDATED":
					outdated++
				case reason == "CONSENT_WITHDRAWN" || reason == "OBJECTED":
					withdrawn++
				}
			}
			purposes = append(purposes, core.NewObject(
				"id", purpose.Get("id"),
				"key", purpose.Get("key"),
				"name", purpose.Get("name"),
				"legalBasis", purpose.Get("legalBasis"),
				"mode", purpose.Get("mode"),
				"version", purpose.Get("version"),
				"archived", purpose.Get("archived"),
				"granted", granted,
				"withdrawn", withdrawn,
				"expired", expired,
				"outdated", outdated,
			))
		}
		requests, err := tx.Find(ctx, "privacyRequests", core.NewObject("tenantId", tenant), nil)
		if err != nil {
			return nil, err
		}
		byType := core.NewObject()
		for _, requestType := range SubjectRequestTypes {
			byType.Set(requestType, 0.0)
		}
		var durations []float64
		completedLast30Days := 0.0
		var pending, open, overdue, dueSoon float64
		for _, request := range requests {
			status := request.Get("status")
			if status == "open" || status == "pending-verification" {
				key := jsString(request.Get("type"))
				byType.Set(key, jsNumber(byType.Get(key))+1)
			}
			if status == "completed" && jsNumber(coalesce(request.Get("closedAt"), 0.0)) > nowMs-30*DayMs {
				completedLast30Days++
			}
			closedAt, receivedAt := request.Get("closedAt"), request.Get("receivedAt")
			if !isUndefined(closedAt) && !isUndefined(receivedAt) && jsNumber(closedAt) > nowMs-90*DayMs && (status == "completed" || status == "rejected") {
				durations = append(durations, (jsNumber(closedAt)-jsNumber(receivedAt))/DayMs)
			}
		}
		for _, request := range requests {
			if request.Get("status") == "pending-verification" {
				pending++
			}
		}
		for _, request := range requests {
			if request.Get("status") == "open" {
				open++
			}
		}
		for _, request := range requests {
			late, err := RequestOverdue(request, now)
			if err != nil {
				return nil, err
			}
			if late {
				overdue++
			}
		}
		for _, request := range requests {
			dueAt := request.Get("dueAt")
			if request.Get("status") == "open" && !isUndefined(dueAt) && jsNumber(dueAt) > nowMs && jsNumber(dueAt) <= nowMs+7*DayMs {
				dueSoon++
			}
		}
		sort.Float64s(durations)
		queue := core.NewObject(
			"pendingVerification", pending,
			"open", open,
			"overdue", overdue,
			"dueSoon", dueSoon,
			"completedLast30Days", completedLast30Days,
		)
		if count := len(durations); count > 0 {
			var median float64
			if count%2 == 1 {
				median = durations[(count-1)/2]
			} else {
				median = (durations[count/2-1] + durations[count/2]) / 2
			}
			queue.Set("medianDaysToClose", math.Floor(median*10+0.5)/10)
		}
		queue.Set("byType", byType)
		holdRows, err := tx.Find(ctx, "privacyHolds", core.NewObject("tenantId", tenant), nil)
		if err != nil {
			return nil, err
		}
		holds := 0.0
		for _, hold := range holdRows {
			if expiresAt := hold.Get("expiresAt"); isUndefined(expiresAt) || jsNumber(expiresAt) > nowMs {
				holds++
			}
		}
		return core.NewObject(
			"purposes", purposes,
			"requests", queue,
			"holds", holds,
			"restrictions", float64(restricted.Len()),
		), nil
	}, false)
	return Out[apitypes.PrivacySummaryOutput]{Value: result}, err
}

// PrivacyRuntime is api/privacy.ts createPrivacyRuntime(): privacy for the deployment's own server code
// (`iam.privacy`): credential-free consent checks and recording (for an application's own customers), and the
// deadline job.
type PrivacyRuntime struct {
	server *ServerContext
}

// CreatePrivacyRuntime builds the PrivacyRuntime (api/privacy.ts createPrivacyRuntime).
func CreatePrivacyRuntime(server *ServerContext) *PrivacyRuntime {
	return &PrivacyRuntime{server: server}
}

// pvInput is the runtime input object (nil reads as `{}`).
func pvInput(input *core.Object) *core.Object {
	if input == nil {
		return core.NewObject()
	}
	return input
}

// Check (api/privacy.ts createPrivacyRuntime().check): Whether a purpose may be processed for a subject right now;
// not audited.
func (s *PrivacyRuntime) Check(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	input = pvInput(input)
	return core.Transact(ctx, s.server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		tenantID, err := Text(input.Get("tenantId"), "tenantId")
		if err != nil {
			return nil, err
		}
		return pvCheckSubject(ctx, s.server, tx, tenantID, input.Get("subject"), input.Get("purposeKey"))
	})
}

// Record (api/privacy.ts createPrivacyRuntime().record): Records a decision the application captured itself (a
// cookie banner, a signup form), attributed to `application`. Audited as `privacy:consent`; returns the receipt.
func (s *PrivacyRuntime) Record(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	server := s.server
	input = pvInput(input)
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		tenantID, err := Text(input.Get("tenantId"), "tenantId")
		if err != nil {
			return nil, err
		}
		granted, ok := input.Get("granted").(bool)
		if !ok {
			return nil, invalidInput("granted must be a boolean")
		}
		if _, err := server.Tenant(ctx, tx, tenantID); err != nil {
			return nil, err
		}
		purpose, err := pvPurposeByKey(ctx, tx, tenantID, input.Get("purposeKey"))
		if err != nil {
			return nil, err
		}
		subject, err := ResolveSubject(ctx, tx, tenantID, input.Get("subject"), false)
		if err != nil {
			return nil, err
		}
		now := server.Now()
		method, err := pvMethod(input.Get("method"))
		if err != nil {
			return nil, err
		}
		evidence, err := pvEvidence(input.Get("evidence"))
		if err != nil {
			return nil, err
		}
		client, err := pvClientOf(input.Get("ip"), input.Get("userAgent"), true)
		if err != nil {
			return nil, err
		}
		receipt, _, err := pvWriteConsent(ctx, server, tx, pvConsentInput{
			tenantID:   tenantID,
			purpose:    purpose,
			subject:    subject,
			granted:    granted,
			source:     "api",
			method:     method,
			evidence:   evidence,
			recordedBy: "application",
			at:         float64(now),
			client:     client,
		})
		if err != nil {
			return nil, err
		}
		metadata := core.NewObject(
			"purposeKey", purpose.Get("key"),
			"granted", granted,
			"purposeVersion", member(receipt.Get("purpose"), "version"),
			"source", "api",
			"receiptId", receipt.Get("receiptId"),
		)
		if externalID := subject.Get("externalId"); !isUndefined(externalID) {
			metadata.Set("externalId", externalID)
		}
		if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"actorId", "application",
			"action", "privacy:consent",
			"resourceId", coalesce(subject.Get("identityId"), subject.Get("key")),
			"timestamp", float64(now),
			"outcome", "allow",
			"metadata", metadata,
		)); err != nil {
			return nil, err
		}
		return receipt, nil
	})
}

// SendDeadlineReminders (api/privacy.ts createPrivacyRuntime().sendDeadlineReminders): Deadline job (daily or
// hourly): emails the assignee (or the privacy contact) once when an open request is due within `withinDays`
// (default 7) and once when it becomes overdue, audited as `privacy:request:due-soon` / `privacy:request:overdue` so
// webhooks can alert too; cancels public requests nobody confirmed within seven days.
func (s *PrivacyRuntime) SendDeadlineReminders(ctx context.Context, input *core.Object) (result *core.Object, err error) {
	server := s.server
	input = pvInput(input)
	withinDays, err := Integer(coalesce(input.Get("withinDays"), 7.0), "withinDays", 1, 60)
	if err != nil {
		return nil, err
	}
	tenantFilter := func(members ...any) *core.Object { return core.NewObject(members...) }
	if raw := input.Get("tenantId"); !isUndefined(raw) {
		tenantID, err := Text(raw, "tenantId")
		if err != nil {
			return nil, err
		}
		tenantFilter = func(members ...any) *core.Object {
			return core.NewObject(append([]any{"tenantId", tenantID}, members...)...)
		}
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		now := server.Now()
		nowMs := float64(now)
		reminded := []any{}
		lapsed := 0.0
		tenants := map[string]*core.Object{}
		tenantOf := func(tenantID string) (*core.Object, error) {
			if tenant, seen := tenants[tenantID]; seen {
				return tenant, nil
			}
			tenant, err := tx.Get(ctx, "tenants", tenantID)
			if err != nil {
				return nil, err
			}
			tenants[tenantID] = tenant
			return tenant, nil
		}
		pending, err := tx.Find(ctx, "privacyRequests", tenantFilter("status", "pending-verification"), nil)
		if err != nil {
			return nil, err
		}
		for _, request := range pending {
			if request.Get("channel") != "public" || isUndefined(request.Get("tokenHash")) || jsNumber(request.Get("submittedAt"))+pvVerificationLifetimeMs > nowMs {
				continue
			}
			cancelled := request.Spread()
			cancelled.Delete("tokenHash")
			cancelled.Delete("tokenExpiresAt")
			cancelled.Set("status", "cancelled")
			cancelled.Set("closedAt", nowMs)
			cancelled.Set("closedBy", "deployment-operator")
			cancelled.Set("events", pvPushEvent(request, pvEvent(now, "deployment-operator", "cancelled", "The requester did not confirm their email address within seven days")))
			if _, err := tx.Put(ctx, "privacyRequests", cancelled); err != nil {
				return nil, err
			}
			lapsed++
		}
		open, err := tx.Find(ctx, "privacyRequests", tenantFilter("status", "open"), nil)
		if err != nil {
			return nil, err
		}
		for _, request := range open {
			dueAt := request.Get("dueAt")
			if isUndefined(dueAt) {
				continue
			}
			var kind string
			switch {
			case jsNumber(dueAt) <= nowMs:
				kind = "overdue"
			case jsNumber(dueAt) <= nowMs+withinDays*DayMs:
				kind = "due-soon"
			}
			if kind == "" {
				continue
			}
			already, _ := request.Get("reminded").([]any)
			if pvIncludes(already, kind) {
				continue
			}
			tenant, err := tenantOf(jsString(request.Get("tenantId")))
			if err != nil {
				return nil, err
			}
			if tenant == nil || tenant.Get("status") != "active" {
				continue
			}
			tenantID := jsString(tenant.Get("id"))
			settings, err := PrivacySettings(ctx, tx, tenantID)
			if err != nil {
				return nil, err
			}
			var assignee *core.Object
			if assigneeID := request.Get("assigneeId"); truthy(assigneeID) {
				if assignee, err = tx.Get(ctx, "identities", jsString(assigneeID)); err != nil {
					return nil, err
				}
			}
			to := settings.Get("contactEmail")
			if assignee != nil && assignee.Get("status") == "active" && truthy(assignee.Get("email")) {
				to = assignee.Get("email")
			}
			if truthy(to) && pvCanEmail(server) {
				overdue := "false"
				if kind == "overdue" {
					overdue = "true"
				}
				if _, err := server.Auth.EnqueueDelivery(ctx, tx, auth.EnqueueInput{
					TenantID: tenantID, Kind: "email", To: jsString(to), Template: "privacy-request-due",
					Payload: core.NewObject(
						"tenantId", tenantID,
						"tenantName", tenant.Get("name"),
						"requestId", request.Get("id"),
						"number", request.Get("number"),
						"type", request.Get("type"),
						"dueAt", jsString(dueAt),
						"overdue", overdue,
					),
				}); err != nil {
					return nil, err
				}
			}
			updated := request.Spread()
			updated.Set("reminded", append(append([]any{}, already...), kind))
			updated.Set("events", pvPushEvent(request, pvEvent(now, "deployment-operator", "reminded", kind)))
			if _, err := tx.Put(ctx, "privacyRequests", updated); err != nil {
				return nil, err
			}
			if err := server.Events.RecordAudit(ctx, tx, core.NewObject(
				"id", ID(),
				"tenantId", tenantID,
				"actorId", "deployment-operator",
				"action", "privacy:request:"+kind,
				"resourceId", request.Get("id"),
				"timestamp", nowMs,
				"outcome", "allow",
				"metadata", core.NewObject("number", request.Get("number"), "type", request.Get("type"), "dueAt", dueAt),
			)); err != nil {
				return nil, err
			}
			reminded = append(reminded, core.NewObject("tenantId", tenantID, "requestId", request.Get("id"), "kind", kind))
		}
		return core.NewObject("reminded", reminded, "lapsed", lapsed), nil
	})
}

// pvIncludes is `items.includes(item)` over a model array.
func pvIncludes(items []any, item any) bool {
	for _, candidate := range items {
		if candidate == item {
			return true
		}
	}
	return false
}
