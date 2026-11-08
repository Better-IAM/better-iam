package oauth

// Port of packages/oauth/src/ssf.ts: an OpenID Shared Signals Framework transmitter that turns IAM audit events into
// signed Security Event Tokens (RFC 8417) with CAEP and RISC event types and pushes them to each tenant's receivers
// (RFC 8935) with retries.

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

const (
	caepEventType = "https://schemas.openid.net/secevent/caep/event-type"
	riscEventType = "https://schemas.openid.net/secevent/risc/event-type"
	ssfEventType  = "https://schemas.openid.net/secevent/ssf/event-type"
	pushDelivery  = "urn:ietf:rfc:8935"
)

// SharedSignalEvents are the security event types the transmitter emits (CAEP and RISC).
var SharedSignalEvents = struct {
	SessionRevoked    string
	CredentialChange  string
	IdentifierChanged string
	AccountDisabled   string
	AccountPurged     string
}{
	SessionRevoked:    caepEventType + "/session-revoked",
	CredentialChange:  caepEventType + "/credential-change",
	IdentifierChanged: riscEventType + "/identifier-changed",
	AccountDisabled:   riscEventType + "/account-disabled",
	AccountPurged:     riscEventType + "/account-purged",
}

var supportedSignals = []string{SharedSignalEvents.SessionRevoked, SharedSignalEvents.CredentialChange,
	SharedSignalEvents.IdentifierChanged, SharedSignalEvents.AccountDisabled, SharedSignalEvents.AccountPurged}

type signalMapping struct {
	eventType string
	claims    [][2]string
}

func credentialClaims(credentialType, changeType string) [][2]string {
	return [][2]string{{"credential_type", credentialType}, {"change_type", changeType}}
}

// signalMappingOrder is the order of the mapping's keys (the subscription patterns).
var signalMappingOrder = []string{
	"auth:session:revoke", "auth:session:revoke-others", "identity:revoke-sessions", "tenant:revoke-sessions",
	"auth:password:change", "auth:password:reset", "auth:mfa:enable", "auth:mfa:disable", "auth:passkey:create",
	"auth:passkey:delete", "auth:email:change", "identity:email-change", "identity:offboard", "identity:expire",
	"identity:delete", "threat:revoke-sessions", "threat:contain",
}

// signalMappings says which IAM audit events become which security event, and the event-specific claims.
var signalMappings = map[string]signalMapping{
	"auth:session:revoke":        {eventType: SharedSignalEvents.SessionRevoked},
	"auth:session:revoke-others": {eventType: SharedSignalEvents.SessionRevoked},
	"identity:revoke-sessions":   {eventType: SharedSignalEvents.SessionRevoked},
	"tenant:revoke-sessions":     {eventType: SharedSignalEvents.SessionRevoked},
	"auth:password:change":       {eventType: SharedSignalEvents.CredentialChange, claims: credentialClaims("password", "update")},
	"auth:password:reset":        {eventType: SharedSignalEvents.CredentialChange, claims: credentialClaims("password", "update")},
	"auth:mfa:enable":            {eventType: SharedSignalEvents.CredentialChange, claims: credentialClaims("app", "create")},
	"auth:mfa:disable":           {eventType: SharedSignalEvents.CredentialChange, claims: credentialClaims("app", "delete")},
	"auth:passkey:create":        {eventType: SharedSignalEvents.CredentialChange, claims: credentialClaims("fido2-platform", "create")},
	"auth:passkey:delete":        {eventType: SharedSignalEvents.CredentialChange, claims: credentialClaims("fido2-platform", "delete")},
	"auth:email:change":          {eventType: SharedSignalEvents.IdentifierChanged},
	"identity:email-change":      {eventType: SharedSignalEvents.IdentifierChanged},
	"identity:offboard":          {eventType: SharedSignalEvents.AccountDisabled},
	"identity:expire":            {eventType: SharedSignalEvents.AccountDisabled},
	"identity:delete":            {eventType: SharedSignalEvents.AccountPurged},
	// Identity threat detection and response (server threat-response.ts): ended sessions and containment.
	"threat:revoke-sessions": {eventType: SharedSignalEvents.SessionRevoked},
	"threat:contain":         {eventType: SharedSignalEvents.AccountDisabled},
}

// SharedSignalsConfig configures the transmitter.
type SharedSignalsConfig struct {
	Store core.IamStore
	// Authorize requires `iam:ssf:streams:*` on `ssf/{streamId}`; `iam.protocolHost` supplies it.
	Authorize func(ctx context.Context, credential core.CredentialInput, action string, resource core.ResourceRef) error
	// Authenticate resolves the credential to its principal.
	Authenticate func(ctx context.Context, credential core.CredentialInput) (*auth.Principal, error)
	// Issuer is the transmitter's issuer (usually the OAuth issuer); receivers check `iss` against it.
	Issuer string
	// JWKS holds private signing keys; the first key with `alg` (and `d`) signs.
	JWKS any
	// JWKSURI is where receivers fetch the public keys; defaults to `{issuer}/jwks`.
	JWKSURI string
	// EncryptionKey is the base64 32-byte key encrypting receivers' authorization headers at rest.
	EncryptionKey string
	// AllowInsecureLocalhost allows http:// delivery to loopback addresses (development and tests only).
	AllowInsecureLocalhost bool
	// AllowPrivateNetworks lets receiver endpoints resolve to private and reserved addresses.
	AllowPrivateNetworks bool
	// TimeoutMs is the per-delivery timeout (default 10 seconds).
	TimeoutMs int64
	// Fetch replaces the default guarded transport; a replacement must enforce its own address rules.
	Fetch func(request *http.Request) (*http.Response, error)
	// Now overrides the clock (epoch milliseconds).
	Now func() int64
}

// StreamInput is createStream's input.
type StreamInput struct {
	TenantID string
	Name     string
	// EndpointURL is the receiver's push endpoint (RFC 8935).
	EndpointURL string
	// Audience is the `aud` of the events; defaults to the endpoint URL.
	Audience *string
	// Authorization is sent as the `Authorization` header with every delivery. Write-only.
	Authorization *string
	// Events are the event types to send; nil means every supported type.
	Events []string
	// SubjectFormat is `iss_sub` (default) or `email`.
	SubjectFormat *string
	Enabled       *bool
}

// UpdateStreamInput is updateStream's input: nil members keep their value.
type UpdateStreamInput struct {
	TenantID      string
	StreamID      string
	Name          *string
	EndpointURL   *string
	Audience      *string
	Events        []string
	SubjectFormat *string
	Enabled       *bool
	// Authorization replaces the stored header; RemoveAuthorization (authorization: null) drops it.
	Authorization       *string
	RemoveAuthorization bool
}

// SharedSignalStream is a stream as administrators see it.
type SharedSignalStream struct {
	ID               string   `json:"id"`
	TenantID         string   `json:"tenantId"`
	Name             string   `json:"name"`
	EndpointURL      string   `json:"endpointUrl"`
	Audience         string   `json:"audience"`
	Events           []string `json:"events"`
	SubjectFormat    string   `json:"subjectFormat"`
	Enabled          bool     `json:"enabled"`
	HasAuthorization bool     `json:"hasAuthorization"`
	CreatedAt        float64  `json:"createdAt"`
	UpdatedAt        float64  `json:"updatedAt"`
	// Pending counts deliveries waiting or retrying.
	Pending         int      `json:"pending"`
	LastDeliveredAt *float64 `json:"lastDeliveredAt,omitempty"`
	LastError       string   `json:"lastError,omitempty"`
}

// SharedSignalDelivery is one delivery of a stream.
type SharedSignalDelivery struct {
	ID            string   `json:"id"`
	StreamID      string   `json:"streamId"`
	EventType     string   `json:"eventType"`
	JTI           string   `json:"jti"`
	Status        string   `json:"status"`
	Attempts      float64  `json:"attempts"`
	CreatedAt     float64  `json:"createdAt"`
	NextAttemptAt *float64 `json:"nextAttemptAt,omitempty"`
	DeliveredAt   *float64 `json:"deliveredAt,omitempty"`
	FailedAt      *float64 `json:"failedAt,omitempty"`
	LastError     string   `json:"lastError,omitempty"`
}

const ssfMaxAttempts = 8

// ssfBackoff is the delay after each failed attempt: 30 s, 2 min, 8 min, ~30 min, then 2 h.
func ssfBackoff(attempts float64) float64 {
	return math.Min(30_000*math.Pow(4, attempts-1), 2*3600_000)
}

// SharedSignalsTransmitter is createSharedSignalsTransmitter's result.
type SharedSignalsTransmitter struct {
	config      SharedSignalsConfig
	crypt       *Cipher
	signer      *core.Object
	signingKey  *joseSigner
	signingErr  error
	issuer      string
	jwksURI     string
	addressRule auth.SafeFetchAddressOptions
	request     func(request *http.Request) (*http.Response, error)
	timeout     time.Duration
	now         func() int64
	discovery   string
}

// CreateSharedSignalsTransmitter is createSharedSignalsTransmitter.
func CreateSharedSignalsTransmitter(config SharedSignalsConfig) (*SharedSignalsTransmitter, error) {
	key := nodeBase64Decode(config.EncryptionKey)
	if len(key) != 32 {
		return nil, core.NewIamError("configuration", "SSF encryptionKey must encode exactly 32 bytes.")
	}
	crypt, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	var signer *core.Object
	if jwks, ok := core.Normalize(config.JWKS).(*core.Object); ok && jwks != nil {
		for _, candidate := range jwks.Get("keys").([]any) {
			if key, ok := candidate.(*core.Object); ok && truthy(key.Get("alg")) && truthy(key.Get("d")) {
				signer = key
				break
			}
		}
	}
	if signer == nil {
		return nil, core.NewIamError("configuration", "SSF needs a private signing key with an `alg` in jwks.")
	}
	issuer := strings.TrimSuffix(config.Issuer, "/")
	t := &SharedSignalsTransmitter{config: config, crypt: crypt, signer: signer, issuer: issuer, now: config.Now}
	if t.now == nil {
		t.now = wallNow
	}
	t.jwksURI = config.JWKSURI
	if t.jwksURI == "" {
		t.jwksURI = issuer + "/jwks"
	}
	// Reported when an event is signed; never a failure at startup.
	t.signingKey, t.signingErr = joseImportPrivate(signer)
	t.addressRule = auth.SafeFetchAddressOptions{AnyPort: true, AllowInsecureLocalhost: config.AllowInsecureLocalhost,
		AllowPrivateNetworks: config.AllowPrivateNetworks}
	if config.Fetch != nil {
		t.request = config.Fetch
	} else {
		limit := int64(64 * 1024)
		guarded := auth.CreateGuardedFetch(auth.GuardedFetchOptions{SafeFetchAddressOptions: t.addressRule, MaxBytes: &limit})
		t.request = guarded.DoRedirectError
	}
	t.timeout = 10 * time.Second
	if config.TimeoutMs > 0 {
		t.timeout = time.Duration(config.TimeoutMs) * time.Millisecond
	}
	issuerURL, err := parseURL(issuer)
	if err != nil {
		return nil, &core.TypeError{Message: "Invalid URL"}
	}
	t.discovery = "/.well-known/ssf-configuration" + strings.TrimSuffix(urlPathname(issuerURL), "/")
	return t, nil
}

func (t *SharedSignalsTransmitter) seal(value string) string { return t.crypt.Seal(value) }

func (t *SharedSignalsTransmitter) open(value string) (string, error) {
	opened, err := t.crypt.Open(value)
	if err != nil {
		return "", err
	}
	text, _ := opened.(string)
	return text, nil
}

func (t *SharedSignalsTransmitter) endpoint(value string) (string, error) {
	invalid := core.NewIamError("INVALID_INPUT", "The receiver endpoint must be an absolute HTTPS URL.")
	parsed, err := parseURL(value)
	if err != nil {
		return "", invalid
	}
	local := t.config.AllowInsecureLocalhost && parsed.Protocol == "http:" && contains(loopbacks, parsed.Hostname)
	if (parsed.Protocol != "https:" && !local) || urlHasCredentials(parsed) || urlHasHash(parsed) {
		return "", invalid
	}
	// IP literals are judged now; hostnames are judged by the transport each time it connects.
	if _, err := auth.CheckFetchURL(parsed.Href, t.addressRule); err != nil {
		return "", core.NewIamError("INVALID_INPUT", "The receiver endpoint must point at a public address (see allowPrivateNetworks).")
	}
	return parsed.Href, nil
}

type streamSettings struct {
	name, endpointURL, audience, subjectFormat string
	events                                     []string
	enabled                                    bool
}

func (t *SharedSignalsTransmitter) settings(name, endpointURL, audience *string, events []string, subjectFormat *string,
	enabled *bool, authorization *string, current *core.Object) (*streamSettings, error) {
	pick := func(value *string, key string) (string, bool) {
		if value != nil {
			return *value, true
		}
		if current != nil {
			text, ok := current.Get(key).(string)
			return text, ok
		}
		return "", false
	}
	nameValue, hasName := pick(name, "name")
	endpointValue, _ := pick(endpointURL, "endpointUrl")
	endpoint, err := t.endpoint(endpointValue)
	if err != nil {
		return nil, err
	}
	audienceValue, hasAudience := pick(audience, "audience")
	if !hasAudience {
		audienceValue = endpoint
	}
	eventList := events
	if eventList == nil && current != nil {
		eventList = stringList(current.Get("events"))
	}
	if eventList == nil {
		eventList = supportedSignals
	}
	format, hasFormat := pick(subjectFormat, "subjectFormat")
	if !hasFormat {
		format = "iss_sub"
	}
	enabledValue := true
	if enabled != nil {
		enabledValue = *enabled
	} else if current != nil {
		if value, ok := current.Get("enabled").(bool); ok {
			enabledValue = value
		}
	}
	if !hasName || core.JSTrim(nameValue) == "" || core.UTF16Len(nameValue) > 200 {
		return nil, core.NewIamError("INVALID_INPUT", "A stream name of at most 200 characters is required.")
	}
	if audienceValue == "" || core.UTF16Len(audienceValue) > 2048 {
		return nil, core.NewIamError("INVALID_INPUT", "The audience must be a non-empty string.")
	}
	if len(eventList) == 0 || func() bool {
		for _, item := range eventList {
			if !contains(supportedSignals, item) {
				return true
			}
		}
		return false
	}() {
		return nil, core.NewIamError("INVALID_INPUT", "Supported event types: "+strings.Join(supportedSignals, ", ")+".")
	}
	if format != "iss_sub" && format != "email" {
		return nil, core.NewIamError("INVALID_INPUT", "subjectFormat must be iss_sub or email.")
	}
	if authorization != nil && (core.UTF16Len(*authorization) > 4096 || strings.ContainsAny(*authorization, "\r\n")) {
		return nil, core.NewIamError("INVALID_INPUT", "The authorization header value is invalid.")
	}
	return &streamSettings{name: core.JSTrim(nameValue), endpointURL: endpoint, audience: audienceValue,
		events: unique(eventList), subjectFormat: format, enabled: enabledValue}, nil
}

func (t *SharedSignalsTransmitter) authorized(ctx context.Context, credential core.CredentialInput, action, tenantID, id string) (*auth.Principal, error) {
	if err := t.config.Authorize(ctx, credential, action, core.ResourceRef{TenantID: tenantID, Type: "ssf", ID: id}); err != nil {
		return nil, err
	}
	return t.config.Authenticate(ctx, credential)
}

func (t *SharedSignalsTransmitter) owned(ctx context.Context, store core.IamStore, tenantID, streamID string) (*core.Object, error) {
	var stream *core.Object
	if streamID != "" {
		var err error
		if stream, err = store.Get(ctx, "ssfStreams", streamID); err != nil {
			return nil, err
		}
	}
	if stream == nil || str(stream, "tenantId") != tenantID {
		return nil, core.NewIamError("NOT_FOUND", "Stream not found.", 404)
	}
	return stream, nil
}

func (t *SharedSignalsTransmitter) audit(ctx context.Context, tx core.IamStore, tenantID, actorID, action, id string) error {
	_, err := core.AppendAuditEvent(ctx, tx, core.NewObject("id", randomUUID(), "tenantId", tenantID, "actorId", actorID,
		"action", action, "resourceId", id, "timestamp", t.now(), "outcome", "allow"))
	return err
}

func (t *SharedSignalsTransmitter) summary(ctx context.Context, stream *core.Object, store core.IamStore) (*SharedSignalStream, error) {
	if store == nil {
		store = t.config.Store
	}
	pending, err := store.Find(ctx, "ssfDeliveries", core.NewObject("streamId", stream.Get("id"), "status", "pending"), nil)
	if err != nil {
		return nil, err
	}
	out := &SharedSignalStream{ID: str(stream, "id"), TenantID: str(stream, "tenantId"), Name: str(stream, "name"),
		EndpointURL: str(stream, "endpointUrl"), Audience: str(stream, "audience"), Events: stringList(stream.Get("events")),
		SubjectFormat: str(stream, "subjectFormat"), HasAuthorization: truthy(stream.Get("sealedAuthorization")),
		Pending: len(pending)}
	out.Enabled, _ = stream.Get("enabled").(bool)
	out.CreatedAt, _ = num(stream, "createdAt")
	out.UpdatedAt, _ = num(stream, "updatedAt")
	if value, ok := num(stream, "lastDeliveredAt"); ok && value != 0 {
		out.LastDeliveredAt = &value
	}
	out.LastError = str(stream, "lastError")
	return out, nil
}

// securityEvent is a signed Security Event Token for one receiver.
func (t *SharedSignalsTransmitter) securityEvent(stream *core.Object, eventType string, subject, claims *core.Object, txn string) (string, string, error) {
	if t.signingErr != nil {
		return "", "", t.signingErr
	}
	jti := randomUUID()
	payload := core.NewObject("sub_id", subject, "events", core.NewObject(eventType, claims),
		// Every tenant's events share this issuer and key: receivers serving one organization check `tenant_id`.
		"tenant_id", stream.Get("tenantId"))
	if txn != "" {
		payload.Set("txn", txn)
	}
	payload.Set("iss", t.issuer)
	payload.Set("aud", stream.Get("audience"))
	payload.Set("iat", epoch(t.now()))
	payload.Set("jti", jti)
	header := core.NewObject("alg", t.signer.Get("alg"), "typ", "secevent+jwt")
	if truthy(t.signer.Get("kid")) {
		header.Set("kid", t.signer.Get("kid"))
	}
	set, err := joseSignCompact(header, payload, t.signingKey, str(t.signer, "alg"))
	return jti, set, err
}

func (t *SharedSignalsTransmitter) enqueue(ctx context.Context, stream *core.Object, eventType, jti, set string) error {
	now := t.now()
	return t.config.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		_, err := tx.Insert(ctx, "ssfDeliveries", core.NewObject("id", randomUUID(), "tenantId", stream.Get("tenantId"),
			"streamId", stream.Get("id"), "eventType", eventType, "jti", jti, "set", set, "status", "pending", "attempts", 0,
			"createdAt", now, "nextAttemptAt", now))
		return err
	})
}

// subjectOf is the subject of an event in the stream's format; email falls back to `iss_sub` when the address is
// gone.
func (t *SharedSignalsTransmitter) subjectOf(ctx context.Context, stream, event *core.Object) (*core.Object, error) {
	if str(event, "action") == "tenant:revoke-sessions" {
		return core.NewObject("format", "complex", "tenant", core.NewObject("format", "opaque", "id", event.Get("tenantId"))), nil
	}
	if str(stream, "subjectFormat") == "email" {
		identity, err := t.config.Store.Get(ctx, "identities", str(event, "resourceId"))
		if err != nil {
			return nil, err
		}
		// Only a verified address of the stream's own tenant names someone.
		if identity != nil && truthy(identity.Get("email")) && identity.Get("emailVerified") == true &&
			jsEq(identity.Get("tenantId"), stream.Get("tenantId")) {
			return core.NewObject("format", "email", "email", identity.Get("email")), nil
		}
	}
	return core.NewObject("format", "iss_sub", "iss", t.issuer, "sub", event.Get("resourceId")), nil
}

// Publish turns one audit event into SETs for every stream of its tenant that wants the event type. Returns the
// number of streams addressed.
func (t *SharedSignalsTransmitter) Publish(ctx context.Context, event *core.Object) (int, error) {
	mapped, ok := signalMappings[str(event, "action")]
	if !ok || str(event, "outcome") != "allow" {
		return 0, nil
	}
	all, err := t.config.Store.Find(ctx, "ssfStreams", core.NewObject("tenantId", event.Get("tenantId")), nil)
	if err != nil {
		return 0, err
	}
	// Paused streams keep receiving events; their deliveries wait until the stream is enabled again.
	var streams []*core.Object
	for _, stream := range all {
		if contains(stringList(stream.Get("events")), mapped.eventType) {
			streams = append(streams, stream)
		}
	}
	timestamp, _ := num(event, "timestamp")
	eventTimestamp := math.Floor(timestamp / 1000)
	for _, stream := range streams {
		initiating := "admin"
		if jsEq(event.Get("actorId"), event.Get("resourceId")) {
			initiating = "user"
		}
		claims := core.NewObject("event_timestamp", eventTimestamp, "initiating_entity", initiating)
		for _, pair := range mapped.claims {
			claims.Set(pair[0], pair[1])
		}
		subject, err := t.subjectOf(ctx, stream, event)
		if err != nil {
			return 0, err
		}
		jti, set, err := t.securityEvent(stream, mapped.eventType, subject, claims, str(event, "id"))
		if err != nil {
			return 0, err
		}
		if err := t.enqueue(ctx, stream, mapped.eventType, jti, set); err != nil {
			return 0, err
		}
	}
	return len(streams), nil
}

func (t *SharedSignalsTransmitter) deliver(ctx context.Context, record, stream *core.Object) (bool, error) {
	failure := ""
	if stream == nil {
		failure = "The stream was deleted."
	} else if enabled, _ := stream.Get("enabled").(bool); !enabled {
		return false, nil
	} else if active, err := core.TenantTreeActive(ctx, t.config.Store, str(stream, "tenantId")); err != nil {
		return false, err
	} else if !active {
		failure = "The tenant is unavailable."
	} else {
		failure = t.post(ctx, record, stream)
	}
	now := t.now()
	attempts, _ := num(record, "attempts")
	attempts++
	err := t.config.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		failed := failure != "" && (attempts >= ssfMaxAttempts || stream == nil)
		next := record.Clone()
		next.Set("attempts", attempts)
		switch {
		case failure == "":
			next.Set("status", "delivered")
		case failed:
			next.Set("status", "failed")
		default:
			next.Set("status", "pending")
		}
		if failure != "" {
			next.Set("nextAttemptAt", float64(now)+ssfBackoff(attempts))
			next.Set("lastError", failure)
		} else {
			next.Set("deliveredAt", now)
		}
		// When it was abandoned: retention sweeps keep failed deliveries for a period from here.
		if failed {
			next.Set("failedAt", now)
		}
		if _, err := tx.Put(ctx, "ssfDeliveries", next); err != nil {
			return err
		}
		if stream != nil {
			current, err := tx.Get(ctx, "ssfStreams", str(stream, "id"))
			if err != nil {
				return err
			}
			if current != nil {
				updated := current.Clone()
				if failure != "" {
					updated.Set("lastError", failure)
				} else {
					updated.Set("lastDeliveredAt", now)
					updated.Set("lastError", core.Undefined)
				}
				if _, err := tx.Put(ctx, "ssfStreams", updated); err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		return false, err
	}
	return failure == "", nil
}

// post sends one SET; it returns the failure ("" when the receiver accepted it).
func (t *SharedSignalsTransmitter) post(ctx context.Context, record, stream *core.Object) string {
	authorization := ""
	if sealed := str(stream, "sealedAuthorization"); sealed != "" {
		opened, err := t.open(sealed)
		if err != nil {
			return "The receiver is unreachable."
		}
		authorization = opened
	}
	deadline, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()
	request, err := http.NewRequestWithContext(deadline, http.MethodPost, str(stream, "endpointUrl"), strings.NewReader(str(record, "set")))
	if err != nil {
		return "The receiver is unreachable."
	}
	request.Header.Set("content-type", "application/secevent+jwt")
	request.Header.Set("accept", "application/json")
	if authorization != "" {
		request.Header.Set("authorization", authorization)
	}
	response, err := t.request(request)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) || deadline.Err() == context.DeadlineExceeded {
			return "The receiver did not answer in time."
		}
		return "The receiver is unreachable."
	}
	defer response.Body.Close()
	status := response.StatusCode
	if status != 202 && status != 200 && status != 204 {
		raw, _ := io.ReadAll(response.Body)
		text := decodeUTF8(raw)
		if core.UTF16Len(text) > 300 {
			text = core.FromUTF16(core.ToUTF16(text)[:300])
		}
		detail := ""
		if parsed, err := jsonParse(text); err == nil {
			var errValue, description any = core.Undefined, core.Undefined
			if body, ok := parsed.(*core.Object); ok && body != nil {
				errValue, description = body.Get("err"), body.Get("description")
			} else if parsed == nil {
				// JSON.parse('null').err throws: no detail.
				return "HTTP " + itoa(status)
			}
			detail = strings.TrimRight(": "+nullishString(errValue)+" "+nullishString(description), " \t\n\r")
		}
		return "HTTP " + itoa(status) + detail
	}
	_, _ = io.Copy(io.Discard, response.Body)
	return ""
}

// nullishString is String(value ?? ”).
func nullishString(value any) string {
	if value == nil || isUndefined(value) {
		return ""
	}
	return jsString(value)
}

// Dispatch sends every due delivery (at most limit, default 200) and prunes delivered records older than a week.
func (t *SharedSignalsTransmitter) Dispatch(ctx context.Context, limit int) (delivered int, failed int, err error) {
	now := float64(t.now())
	pending, err := t.config.Store.Find(ctx, "ssfDeliveries", core.NewObject("status", "pending"), nil)
	if err != nil {
		return 0, 0, err
	}
	var due []*core.Object
	for _, record := range pending {
		if next, _ := num(record, "nextAttemptAt"); next <= now {
			due = append(due, record)
		}
	}
	sort.SliceStable(due, func(i, j int) bool {
		a, _ := num(due[i], "createdAt")
		b, _ := num(due[j], "createdAt")
		return a < b
	})
	if limit <= 0 {
		limit = 200
	}
	if len(due) > limit {
		due = due[:limit]
	}
	streams := map[string]*core.Object{}
	loaded := map[string]bool{}
	for _, record := range due {
		streamID := str(record, "streamId")
		if !loaded[streamID] {
			stream, err := t.config.Store.Get(ctx, "ssfStreams", streamID)
			if err != nil {
				return delivered, failed, err
			}
			streams[streamID], loaded[streamID] = stream, true
		}
		stream := streams[streamID]
		if stream != nil {
			if enabled, _ := stream.Get("enabled").(bool); !enabled {
				continue
			}
		}
		ok, err := t.deliver(ctx, record, stream)
		if err != nil {
			return delivered, failed, err
		}
		if ok {
			delivered++
		} else {
			failed++
		}
	}
	weekAgo := now - 7*86400_000
	err = t.config.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		old, err := tx.Find(ctx, "ssfDeliveries", core.NewObject("status", "delivered"), nil)
		if err != nil {
			return err
		}
		for _, record := range old {
			deliveredAt, _ := num(record, "deliveredAt")
			if deliveredAt < weekAgo {
				if err := tx.Delete(ctx, "ssfDeliveries", str(record, "id")); err != nil {
					return err
				}
			}
		}
		return nil
	})
	return delivered, failed, err
}

// Metadata is the SSF transmitter metadata (served by Handler at `/.well-known/ssf-configuration{issuer path}`).
func (t *SharedSignalsTransmitter) Metadata() *core.Object {
	return core.NewObject("spec_version", "1_0", "issuer", t.issuer, "jwks_uri", t.jwksURI,
		"delivery_methods_supported", []any{pushDelivery}, "critical_subject_members", []any{}, "default_subjects", "ALL")
}

// Handler serves the transmitter metadata; nil for every other request.
func (t *SharedSignalsTransmitter) Handler(request *http.Request) *Response {
	if request.URL.EscapedPath() != t.discovery {
		return nil
	}
	if request.Method != http.MethodGet && request.Method != http.MethodHead {
		header := http.Header{}
		header.Set("allow", "GET, HEAD")
		return &Response{Status: 405, Header: header}
	}
	return jsonResponse(200, t.Metadata(), map[string]string{"cache-control": "public, max-age=3600", "access-control-allow-origin": "*"})
}

func randomHex(n int) string {
	buffer := make([]byte, n)
	_, _ = rand.Read(buffer)
	return hex.EncodeToString(buffer)
}

func randomB64URL(n int) string {
	buffer := make([]byte, n)
	_, _ = rand.Read(buffer)
	return base64.RawURLEncoding.EncodeToString(buffer)
}

// CreateStream adds a receiver for the tenant's security events (`iam:ssf:streams:create`).
func (t *SharedSignalsTransmitter) CreateStream(ctx context.Context, credential core.CredentialInput, input StreamInput) (*SharedSignalStream, error) {
	id := "ssf-" + randomHex(8)
	principal, err := t.authorized(ctx, credential, "iam:ssf:streams:create", input.TenantID, id)
	if err != nil {
		return nil, err
	}
	values, err := t.settings(&input.Name, &input.EndpointURL, input.Audience, input.Events, input.SubjectFormat, input.Enabled, input.Authorization, nil)
	if err != nil {
		return nil, err
	}
	return core.Transact(ctx, t.config.Store, func(ctx context.Context, tx core.IamStore) (*SharedSignalStream, error) {
		active, err := core.TenantTreeActive(ctx, tx, input.TenantID)
		if err != nil {
			return nil, err
		}
		if !active {
			return nil, core.NewIamError("TENANT_INACTIVE", "Tenant unavailable.", 403)
		}
		now := t.now()
		record := core.NewObject("id", id, "tenantId", input.TenantID, "name", values.name, "endpointUrl", values.endpointURL,
			"audience", values.audience, "events", anyList(values.events), "subjectFormat", values.subjectFormat, "enabled", values.enabled)
		if input.Authorization != nil && *input.Authorization != "" {
			record.Set("sealedAuthorization", t.seal(*input.Authorization))
		}
		record.Set("createdAt", now)
		record.Set("updatedAt", now)
		if _, err := tx.Insert(ctx, "ssfStreams", record); err != nil {
			return nil, err
		}
		if err := t.audit(ctx, tx, input.TenantID, str(principal.Identity, "id"), "iam:ssf:CreateStream", id); err != nil {
			return nil, err
		}
		return t.summary(ctx, record, tx)
	})
}

// ListStreams lists a tenant's streams (`iam:ssf:streams:read`).
func (t *SharedSignalsTransmitter) ListStreams(ctx context.Context, credential core.CredentialInput, tenantID string) ([]*SharedSignalStream, error) {
	if _, err := t.authorized(ctx, credential, "iam:ssf:streams:read", tenantID, "*"); err != nil {
		return nil, err
	}
	streams, err := t.config.Store.Find(ctx, "ssfStreams", core.NewObject("tenantId", tenantID), nil)
	if err != nil {
		return nil, err
	}
	sort.SliceStable(streams, func(i, j int) bool {
		a, _ := num(streams[i], "createdAt")
		b, _ := num(streams[j], "createdAt")
		if a != b {
			return a < b
		}
		return str(streams[i], "id") < str(streams[j], "id")
	})
	out := make([]*SharedSignalStream, 0, len(streams))
	for _, stream := range streams {
		summary, err := t.summary(ctx, stream, nil)
		if err != nil {
			return nil, err
		}
		out = append(out, summary)
	}
	return out, nil
}

// GetStream reads one stream (`iam:ssf:streams:read`).
func (t *SharedSignalsTransmitter) GetStream(ctx context.Context, credential core.CredentialInput, tenantID, streamID string) (*SharedSignalStream, error) {
	if _, err := t.authorized(ctx, credential, "iam:ssf:streams:read", tenantID, streamID); err != nil {
		return nil, err
	}
	stream, err := t.owned(ctx, t.config.Store, tenantID, streamID)
	if err != nil {
		return nil, err
	}
	return t.summary(ctx, stream, nil)
}

// UpdateStream changes a stream; RemoveAuthorization removes the header. Pausing holds deliveries until resumed.
func (t *SharedSignalsTransmitter) UpdateStream(ctx context.Context, credential core.CredentialInput, input UpdateStreamInput) (*SharedSignalStream, error) {
	principal, err := t.authorized(ctx, credential, "iam:ssf:streams:update", input.TenantID, input.StreamID)
	if err != nil {
		return nil, err
	}
	return core.Transact(ctx, t.config.Store, func(ctx context.Context, tx core.IamStore) (*SharedSignalStream, error) {
		current, err := t.owned(ctx, tx, input.TenantID, input.StreamID)
		if err != nil {
			return nil, err
		}
		authorization := input.Authorization
		if input.RemoveAuthorization {
			authorization = nil
		}
		values, err := t.settings(input.Name, input.EndpointURL, input.Audience, input.Events, input.SubjectFormat, input.Enabled, authorization, current)
		if err != nil {
			return nil, err
		}
		// The stored authorization is write-only: pointing the stream somewhere else must not send it along.
		if values.endpointURL != str(current, "endpointUrl") && truthy(current.Get("sealedAuthorization")) &&
			input.Authorization == nil && !input.RemoveAuthorization {
			return nil, core.NewIamError("INVALID_INPUT", "Changing the receiver endpoint needs the authorization header again (or null to remove it).")
		}
		record := current.Clone()
		record.Set("name", values.name)
		record.Set("endpointUrl", values.endpointURL)
		record.Set("audience", values.audience)
		record.Set("events", anyList(values.events))
		record.Set("subjectFormat", values.subjectFormat)
		record.Set("enabled", values.enabled)
		record.Set("updatedAt", t.now())
		if input.RemoveAuthorization {
			record.Delete("sealedAuthorization")
		} else if input.Authorization != nil {
			record.Set("sealedAuthorization", t.seal(*input.Authorization))
		}
		if _, err := tx.Put(ctx, "ssfStreams", record); err != nil {
			return nil, err
		}
		if err := t.audit(ctx, tx, input.TenantID, str(principal.Identity, "id"), "iam:ssf:UpdateStream", str(current, "id")); err != nil {
			return nil, err
		}
		return t.summary(ctx, record, tx)
	})
}

// DeleteStream removes a stream and drops its undelivered events.
func (t *SharedSignalsTransmitter) DeleteStream(ctx context.Context, credential core.CredentialInput, tenantID, streamID string) error {
	principal, err := t.authorized(ctx, credential, "iam:ssf:streams:delete", tenantID, streamID)
	if err != nil {
		return err
	}
	return t.config.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		current, err := t.owned(ctx, tx, tenantID, streamID)
		if err != nil {
			return err
		}
		deliveries, err := tx.Find(ctx, "ssfDeliveries", core.NewObject("streamId", current.Get("id")), nil)
		if err != nil {
			return err
		}
		for _, record := range deliveries {
			if err := tx.Delete(ctx, "ssfDeliveries", str(record, "id")); err != nil {
				return err
			}
		}
		if err := tx.Delete(ctx, "ssfStreams", str(current, "id")); err != nil {
			return err
		}
		return t.audit(ctx, tx, tenantID, str(principal.Identity, "id"), "iam:ssf:DeleteStream", str(current, "id"))
	})
}

// VerifyResult is verifyStream's result.
type VerifyResult struct {
	Delivered bool   `json:"delivered"`
	JTI       string `json:"jti"`
	Error     string `json:"error,omitempty"`
}

// VerifyStream sends an SSF verification event (`state` echoes back) straight away. state "" generates one.
func (t *SharedSignalsTransmitter) VerifyStream(ctx context.Context, credential core.CredentialInput, tenantID, streamID string, state *string) (*VerifyResult, error) {
	if _, err := t.authorized(ctx, credential, "iam:ssf:streams:update", tenantID, streamID); err != nil {
		return nil, err
	}
	stream, err := t.owned(ctx, t.config.Store, tenantID, streamID)
	if err != nil {
		return nil, err
	}
	stateValue := randomB64URL(12)
	if state != nil {
		stateValue = *state
	}
	eventType := ssfEventType + "/verification"
	jti, set, err := t.securityEvent(stream, eventType, core.NewObject("format", "opaque", "id", stream.Get("id")),
		core.NewObject("state", stateValue), "")
	if err != nil {
		return nil, err
	}
	if err := t.enqueue(ctx, stream, eventType, jti, set); err != nil {
		return nil, err
	}
	records, err := t.config.Store.Find(ctx, "ssfDeliveries", core.NewObject("jti", jti), nil)
	if err != nil {
		return nil, err
	}
	record := records[0]
	delivered, err := t.deliver(ctx, record, stream)
	if err != nil {
		return nil, err
	}
	after, err := t.config.Store.Get(ctx, "ssfDeliveries", str(record, "id"))
	if err != nil {
		return nil, err
	}
	result := &VerifyResult{Delivered: delivered, JTI: jti}
	if after != nil && truthy(after.Get("lastError")) && !delivered {
		result.Error = str(after, "lastError")
	}
	return result, nil
}

// ListDeliveriesInput filters listDeliveries.
type ListDeliveriesInput struct {
	TenantID string
	StreamID string
	// Status filters by pending, delivered or failed ("" for all).
	Status string
	// Limit defaults to 50 and is at most 500.
	Limit *int
}

// ListDeliveries lists recent deliveries of a stream, newest first (`iam:ssf:streams:read`).
func (t *SharedSignalsTransmitter) ListDeliveries(ctx context.Context, credential core.CredentialInput, input ListDeliveriesInput) ([]*SharedSignalDelivery, error) {
	if _, err := t.authorized(ctx, credential, "iam:ssf:streams:read", input.TenantID, input.StreamID); err != nil {
		return nil, err
	}
	if _, err := t.owned(ctx, t.config.Store, input.TenantID, input.StreamID); err != nil {
		return nil, err
	}
	records, err := t.config.Store.Find(ctx, "ssfDeliveries", core.NewObject("streamId", input.StreamID), nil)
	if err != nil {
		return nil, err
	}
	var filtered []*core.Object
	for _, record := range records {
		if input.Status == "" || str(record, "status") == input.Status {
			filtered = append(filtered, record)
		}
	}
	sort.SliceStable(filtered, func(i, j int) bool {
		a, _ := num(filtered[i], "createdAt")
		b, _ := num(filtered[j], "createdAt")
		return b < a
	})
	limit := 50
	if input.Limit != nil {
		limit = *input.Limit
	}
	if limit > 500 {
		limit = 500
	}
	if limit < 0 {
		limit = len(filtered) + limit
		if limit < 0 {
			limit = 0
		}
	}
	if len(filtered) > limit {
		filtered = filtered[:limit]
	}
	out := make([]*SharedSignalDelivery, 0, len(filtered))
	for _, record := range filtered {
		delivery := &SharedSignalDelivery{ID: str(record, "id"), StreamID: str(record, "streamId"), EventType: str(record, "eventType"),
			JTI: str(record, "jti"), Status: str(record, "status"), LastError: str(record, "lastError")}
		delivery.Attempts, _ = num(record, "attempts")
		delivery.CreatedAt, _ = num(record, "createdAt")
		if delivery.Status == "pending" {
			next, _ := num(record, "nextAttemptAt")
			delivery.NextAttemptAt = &next
		}
		if value, ok := num(record, "deliveredAt"); ok && value != 0 {
			delivery.DeliveredAt = &value
		}
		if value, ok := num(record, "failedAt"); ok && value != 0 {
			delivery.FailedAt = &value
		}
		out = append(out, delivery)
	}
	return out, nil
}

// EventSubscriber is `iam.events`.
type EventSubscriber interface {
	Subscribe(pattern any, handler func(ctx context.Context, event *core.Object) error) (func(), error)
}

// Subscribe publishes matching IAM events as they are dispatched, then delivers them. Pair it with a periodic
// Dispatch for retries. onError receives failures.
func (t *SharedSignalsTransmitter) Subscribe(events EventSubscriber, onError func(err error)) (func(), error) {
	return events.Subscribe(anyList(signalMappingOrder), func(ctx context.Context, event *core.Object) error {
		count, err := t.Publish(ctx, event)
		if err == nil && count > 0 {
			_, _, err = t.Dispatch(ctx, 0)
		}
		if err != nil && onError != nil {
			onError(err)
		}
		return nil
	})
}

func itoa(n int) string {
	return core.NumberString(float64(n))
}
