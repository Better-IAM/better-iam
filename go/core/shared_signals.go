package core

import (
	"math"
	"regexp"
	"strings"
)

// Shared Signals (OpenID SSF 1.0 with CAEP and RISC): the pure pieces of receiving security events from an upstream
// identity provider. Event-type URIs, subject identifiers (RFC 9493, the SSF complex format and the legacy RISC
// subject), and a reader for the claims of a Security Event Token (RFC 8417) whose signature, issuer, audience and typ
// the caller has already verified.

const (
	caepPrefix = "https://schemas.openid.net/secevent/caep/event-type/"
	riscPrefix = "https://schemas.openid.net/secevent/risc/event-type/"
	ssfPrefix  = "https://schemas.openid.net/secevent/ssf/event-type/"
	ssePrefix  = "https://schemas.openid.net/secevent/sse/event-type/"
)

// SignalEventType names a known security event, or "unknown".
type SignalEventType = string

// SignalEventTypes are the known event types in TypeScript order.
var SignalEventTypes = []SignalEventType{
	"session-revoked", "credential-change", "token-claims-change", "assurance-level-change", "device-compliance-change",
	"risk-level-change", "account-disabled", "account-enabled", "account-purged", "account-credential-change-required",
	"credential-compromise", "identifier-changed", "identifier-recycled", "sessions-revoked", "verification",
	"stream-updated",
}

// SignalEventURIs is the event-type URI of each known security event, as SSF 1.0, CAEP 1.0 and RISC 1.0 name them.
var SignalEventURIs = map[SignalEventType]string{
	"session-revoked":                    caepPrefix + "session-revoked",
	"credential-change":                  caepPrefix + "credential-change",
	"token-claims-change":                caepPrefix + "token-claims-change",
	"assurance-level-change":             caepPrefix + "assurance-level-change",
	"device-compliance-change":           caepPrefix + "device-compliance-change",
	"risk-level-change":                  caepPrefix + "risk-level-change",
	"account-disabled":                   riscPrefix + "account-disabled",
	"account-enabled":                    riscPrefix + "account-enabled",
	"account-purged":                     riscPrefix + "account-purged",
	"account-credential-change-required": riscPrefix + "account-credential-change-required",
	"credential-compromise":              riscPrefix + "credential-compromise",
	"identifier-changed":                 riscPrefix + "identifier-changed",
	"identifier-recycled":                riscPrefix + "identifier-recycled",
	"sessions-revoked":                   riscPrefix + "sessions-revoked",
	"verification":                       ssfPrefix + "verification",
	"stream-updated":                     ssfPrefix + "stream-updated",
}

var signalEventTypes = func() map[string]SignalEventType {
	out := map[string]SignalEventType{}
	for eventType, uri := range SignalEventURIs {
		out[uri] = eventType
	}
	// Before SSF 1.0 the control events lived under the RISC namespace and, briefly, under the SSE drafts' namespace.
	out[riscPrefix+"verification"] = "verification"
	out[riscPrefix+"stream-updated"] = "stream-updated"
	out[ssePrefix+"verification"] = "verification"
	out[ssePrefix+"stream-updated"] = "stream-updated"
	return out
}()

// SignalEventTypeOf is the event type an event-type URI names (exact match), or "unknown" (signalEventType).
func SignalEventTypeOf(uri string) SignalEventType {
	if eventType, ok := signalEventTypes[uri]; ok {
		return eventType
	}
	return "unknown"
}

// SubjectIdentifier is an RFC 9493 subject identifier (or the SSF complex format). Format selects the members used.
type SubjectIdentifier struct {
	Format      string               `json:"format"`
	Iss         string               `json:"iss,omitempty"`
	Sub         string               `json:"sub,omitempty"`
	Email       string               `json:"email,omitempty"`
	ID          string               `json:"id,omitempty"`
	URI         string               `json:"uri,omitempty"`
	PhoneNumber string               `json:"phone_number,omitempty"`
	URL         string               `json:"url,omitempty"`
	Identifiers []*SubjectIdentifier `json:"identifiers,omitempty"`
	User        *SubjectIdentifier   `json:"user,omitempty"`
	Session     *SubjectIdentifier   `json:"session,omitempty"`
	Device      *SubjectIdentifier   `json:"device,omitempty"`
	Tenant      *SubjectIdentifier   `json:"tenant,omitempty"`
	Group       *SubjectIdentifier   `json:"group,omitempty"`
	Application *SubjectIdentifier   `json:"application,omitempty"`
	OrgUnit     *SubjectIdentifier   `json:"org_unit,omitempty"`
}

// ToValue is the identifier as a model value.
func (s *SubjectIdentifier) ToValue() *Object {
	o := NewObject("format", s.Format)
	switch s.Format {
	case "iss_sub":
		o.Set("iss", s.Iss).Set("sub", s.Sub)
	case "email":
		o.Set("email", s.Email)
	case "opaque":
		o.Set("id", s.ID)
	case "account", "uri":
		o.Set("uri", s.URI)
	case "phone_number":
		o.Set("phone_number", s.PhoneNumber)
	case "did":
		o.Set("url", s.URL)
	case "aliases":
		list := make([]any, len(s.Identifiers))
		for index, item := range s.Identifiers {
			list[index] = item.ToValue()
		}
		o.SetRaw("identifiers", list)
	case "complex":
		for _, member := range complexMembers {
			if part := s.complexMember(member); part != nil {
				o.SetRaw(member, part.ToValue())
			}
		}
	}
	return o
}

// MarshalJSON writes the identifier as TypeScript builds it.
func (s SubjectIdentifier) MarshalJSON() ([]byte, error) { return s.ToValue().MarshalJSON() }

var complexMembers = []string{"user", "session", "device", "tenant", "group", "application", "org_unit"}

func (s *SubjectIdentifier) complexMember(name string) *SubjectIdentifier {
	switch name {
	case "user":
		return s.User
	case "session":
		return s.Session
	case "device":
		return s.Device
	case "tenant":
		return s.Tenant
	case "group":
		return s.Group
	case "application":
		return s.Application
	case "org_unit":
		return s.OrgUnit
	}
	return nil
}

func (s *SubjectIdentifier) setComplexMember(name string, value *SubjectIdentifier) {
	switch name {
	case "user":
		s.User = value
	case "session":
		s.Session = value
	case "device":
		s.Device = value
	case "tenant":
		s.Tenant = value
	case "group":
		s.Group = value
	case "application":
		s.Application = value
	case "org_unit":
		s.OrgUnit = value
	}
}

const (
	maxSignalString = 512
	maxAliases      = 10
	maxSubjectDepth = 3
	maxAudiences    = 20
	maxEventDepth   = 10
	maxSeconds      = 1e11
)

// signalText is a string of 1 to 512 characters with no control characters (C0, DEL or C1).
func signalText(value any) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	length := UTF16Len(text)
	if length == 0 || length > maxSignalString {
		return false
	}
	for i := 0; i < len(text); {
		r, size := decodeUnit(text, i)
		if r < 0x20 || (r >= 0x7f && r <= 0x9f) {
			return false
		}
		i += size
	}
	return true
}

// emailAddress is an address with a local part and a domain around its last @, and no whitespace.
func emailAddress(value any) bool {
	if !signalText(value) {
		return false
	}
	text := value.(string)
	if hasJSSpace(text) {
		return false
	}
	at := strings.LastIndex(text, "@")
	return at > 0 && at < len(text)-1
}

var accountPrefix = regexp.MustCompile(`(?i)^acct:`)

func accountURI(value any) bool {
	return signalText(value) && accountPrefix.MatchString(value.(string)) && emailAddress(value.(string)[5:])
}

var didPrefix = regexp.MustCompile(`^did:[a-z0-9]+:`)
var uriScheme = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9+.-]*:`)

// nonSpaceRest reports whether the rest is one or more characters without JavaScript whitespace (\S+$).
func nonSpaceRest(rest string) bool { return rest != "" && !hasJSSpace(rest) }

func didURL(value any) bool {
	if !signalText(value) {
		return false
	}
	text := value.(string)
	prefix := didPrefix.FindString(text)
	return prefix != "" && nonSpaceRest(text[len(prefix):])
}

func genericURI(value any) bool {
	if !signalText(value) {
		return false
	}
	text := value.(string)
	prefix := uriScheme.FindString(text)
	return prefix != "" && nonSpaceRest(text[len(prefix):])
}

type subjectScope struct {
	depth     int
	inAliases bool
	inComplex bool
}

func readSubject(value any, scope subjectScope) *SubjectIdentifier {
	if scope.depth > maxSubjectDepth {
		return nil
	}
	subject, ok := value.(*Object)
	if !ok || subject == nil {
		return nil
	}
	switch subject.Get("format") {
	case "iss_sub":
		iss, sub := subject.Get("iss"), subject.Get("sub")
		if signalText(iss) && signalText(sub) {
			return &SubjectIdentifier{Format: "iss_sub", Iss: iss.(string), Sub: sub.(string)}
		}
	case "email":
		if email := subject.Get("email"); emailAddress(email) {
			return &SubjectIdentifier{Format: "email", Email: email.(string)}
		}
	case "opaque":
		if id := subject.Get("id"); signalText(id) {
			return &SubjectIdentifier{Format: "opaque", ID: id.(string)}
		}
	case "account":
		if uri := subject.Get("uri"); accountURI(uri) {
			return &SubjectIdentifier{Format: "account", URI: uri.(string)}
		}
	case "phone_number":
		if phone := subject.Get("phone_number"); signalText(phone) {
			return &SubjectIdentifier{Format: "phone_number", PhoneNumber: phone.(string)}
		}
	case "did":
		if url := subject.Get("url"); didURL(url) {
			return &SubjectIdentifier{Format: "did", URL: url.(string)}
		}
	case "uri":
		if uri := subject.Get("uri"); genericURI(uri) {
			return &SubjectIdentifier{Format: "uri", URI: uri.(string)}
		}
	case "aliases":
		// RFC 9493 section 3.2.8: an alias list never nests another, directly or through a complex subject.
		if scope.inAliases {
			return nil
		}
		listed, ok := subject.Get("identifiers").([]any)
		if !ok || len(listed) == 0 || len(listed) > maxAliases {
			return nil
		}
		identifiers := make([]*SubjectIdentifier, 0, len(listed))
		for _, entry := range listed {
			identifier := readSubject(entry, subjectScope{depth: scope.depth + 1, inAliases: true, inComplex: scope.inComplex})
			if identifier == nil {
				return nil
			}
			identifiers = append(identifiers, identifier)
		}
		return &SubjectIdentifier{Format: "aliases", Identifiers: identifiers}
	case "complex":
		// Each member names one part of the subject (a person, a session); a complex part is not one.
		if scope.inComplex {
			return nil
		}
		complex := &SubjectIdentifier{Format: "complex"}
		members := 0
		for _, member := range complexMembers {
			entry := subject.Get(member)
			if IsUndefined(entry) {
				continue
			}
			identifier := readSubject(entry, subjectScope{depth: scope.depth + 1, inAliases: scope.inAliases, inComplex: true})
			if identifier == nil {
				return nil
			}
			complex.setComplexMember(member, identifier)
			members++
		}
		if members > 0 {
			return complex
		}
	}
	return nil
}

// ParseSubjectIdentifier reads an RFC 9493 subject identifier (or an SSF complex one) strictly; nil for anything
// else.
func ParseSubjectIdentifier(value any) *SubjectIdentifier {
	return readSubject(Normalize(value), subjectScope{depth: 1})
}

// LegacyRiscSubject reads the subject of a legacy RISC event (events[type].subject with a hyphenated subject_type);
// nil for other types and malformed values.
func LegacyRiscSubject(value any) *SubjectIdentifier {
	subject, ok := Normalize(value).(*Object)
	if !ok || subject == nil {
		return nil
	}
	iss, sub, email, phone := subject.Get("iss"), subject.Get("sub"), subject.Get("email"), subject.Get("phone")
	switch subject.Get("subject_type") {
	case "iss-sub", "iss_sub":
		if signalText(iss) && signalText(sub) {
			return &SubjectIdentifier{Format: "iss_sub", Iss: iss.(string), Sub: sub.(string)}
		}
	case "email":
		if emailAddress(email) {
			return &SubjectIdentifier{Format: "email", Email: email.(string)}
		}
	case "phone":
		if signalText(phone) {
			return &SubjectIdentifier{Format: "phone_number", PhoneNumber: phone.(string)}
		}
	case "id_token_claims", "id-token-claims":
		var identifiers []*SubjectIdentifier
		if !IsUndefined(iss) || !IsUndefined(sub) {
			if !signalText(iss) || !signalText(sub) {
				return nil
			}
			identifiers = append(identifiers, &SubjectIdentifier{Format: "iss_sub", Iss: iss.(string), Sub: sub.(string)})
		}
		if !IsUndefined(email) {
			if !emailAddress(email) {
				return nil
			}
			identifiers = append(identifiers, &SubjectIdentifier{Format: "email", Email: email.(string)})
		}
		if !IsUndefined(phone) {
			if !signalText(phone) {
				return nil
			}
			identifiers = append(identifiers, &SubjectIdentifier{Format: "phone_number", PhoneNumber: phone.(string)})
		}
		if len(identifiers) < 2 {
			if len(identifiers) == 1 {
				return identifiers[0]
			}
			return nil
		}
		return &SubjectIdentifier{Format: "aliases", Identifiers: identifiers}
	}
	return nil
}

// SignalFormatError is why a SET's claims were refused: Reason is events, subject, nonce, claims or size.
type SignalFormatError struct {
	Reason  string
	Message string
}

func (e *SignalFormatError) Error() string { return e.Message }

// SecurityEventClaims are the claims of a verified Security Event Token, normalized.
type SecurityEventClaims struct {
	Iss string `json:"iss"`
	// Aud is the audiences it names, without repeats.
	Aud []string `json:"aud"`
	// Iat is issued-at, in seconds as the SET carries it.
	Iat float64 `json:"iat"`
	Jti string  `json:"jti"`
	// Txn is the transaction id ("" when absent).
	Txn       string          `json:"txn,omitempty"`
	EventURI  string          `json:"eventUri"`
	EventType SignalEventType `json:"eventType"`
	// Event is the event's own claims, without a legacy subject.
	Event   *Object            `json:"event"`
	Subject *SubjectIdentifier `json:"subject,omitempty"`
	// EventTimestamp is when the event happened, in epoch milliseconds (nil when the SET does not say).
	EventTimestamp *float64 `json:"eventTimestamp,omitempty"`
}

// ToValue is the claims as a model value with TypeScript's member order.
func (c *SecurityEventClaims) ToValue() *Object {
	aud := make([]any, len(c.Aud))
	for index, item := range c.Aud {
		aud[index] = item
	}
	o := NewObject("iss", c.Iss).SetRaw("aud", aud).Set("iat", c.Iat).Set("jti", c.Jti)
	if c.Txn != "" {
		o.Set("txn", c.Txn)
	}
	o.Set("eventUri", c.EventURI).Set("eventType", c.EventType).SetRaw("event", c.Event)
	if c.Subject != nil {
		o.SetRaw("subject", c.Subject.ToValue())
	}
	if c.EventTimestamp != nil {
		o.Set("eventTimestamp", *c.EventTimestamp)
	}
	return o
}

func stringClaim(claims *Object, name string, required bool) (string, bool, error) {
	value := claims.Get(name)
	if IsUndefined(value) {
		if required {
			return "", false, &SignalFormatError{"claims", "The security event token has no " + name + " claim"}
		}
		return "", false, nil
	}
	text, ok := value.(string)
	if !ok || text == "" {
		return "", false, &SignalFormatError{"claims", "The security event token's " + name + " claim is invalid"}
	}
	if UTF16Len(text) > maxSignalString {
		return "", false, &SignalFormatError{"size", "The security event token's " + name + " claim is too long"}
	}
	if !signalText(text) {
		return "", false, &SignalFormatError{"claims", "The security event token's " + name + " claim is invalid"}
	}
	return text, true, nil
}

// numericDate is a NumericDate (seconds), nil when absent; it fails for anything but a positive finite number.
func numericDate(value any, name string) (*float64, error) {
	if IsUndefined(value) {
		return nil, nil
	}
	number, ok := value.(float64)
	if !ok || math.IsNaN(number) || math.IsInf(number, 0) || number <= 0 || number > maxSeconds {
		return nil, &SignalFormatError{"claims", "The security event token's " + name + " is invalid"}
	}
	return &number, nil
}

func audiences(value any) ([]string, error) {
	if IsUndefined(value) {
		return nil, &SignalFormatError{"claims", "The security event token has no aud claim"}
	}
	listed, isList := value.([]any)
	if text, ok := value.(string); ok {
		listed, isList = []any{text}, true
	}
	if !isList || len(listed) == 0 {
		return nil, &SignalFormatError{"claims", "The security event token's aud claim is invalid"}
	}
	if len(listed) > maxAudiences {
		return nil, &SignalFormatError{"size", "The security event token names too many audiences"}
	}
	for _, audience := range listed {
		if text, ok := audience.(string); ok && UTF16Len(text) > maxSignalString {
			return nil, &SignalFormatError{"size", "An audience of the security event token is too long"}
		}
		if !signalText(audience) {
			return nil, &SignalFormatError{"claims", "The security event token's aud claim is invalid"}
		}
	}
	seen := map[string]bool{}
	out := []string{}
	for _, audience := range listed {
		text := audience.(string)
		if !seen[text] {
			seen[text] = true
			out = append(out, text)
		}
	}
	return out, nil
}

// nestedTooDeep reports whether objects and arrays inside value go deeper than maxEventDepth levels.
func nestedTooDeep(value any, depth int) bool {
	var entries []any
	switch v := value.(type) {
	case []any:
		entries = v
	case *Object:
		if v == nil {
			return false
		}
		for _, key := range v.keys {
			entries = append(entries, v.values[key])
		}
	default:
		return false
	}
	if depth > maxEventDepth {
		return true
	}
	for _, entry := range entries {
		if nestedTooDeep(entry, depth+1) {
			return true
		}
	}
	return false
}

func withoutTrailingSlash(issuer string) string { return strings.TrimRight(issuer, "/") }

func canonicalSubject(subject *SubjectIdentifier) string {
	text, _ := CanonicalizeJSON(subject.ToValue())
	return text
}

// ReadSecurityEvent reads the claims of a Security Event Token after its signature, issuer, audience and typ were
// verified (and before it is acted on). Fails with *SignalFormatError.
func ReadSecurityEvent(payload any) (*SecurityEventClaims, error) {
	claims, ok := Normalize(payload).(*Object)
	if !ok || claims == nil {
		return nil, &SignalFormatError{"claims", "The security event token has no claims"}
	}
	if !IsUndefined(claims.Get("nonce")) {
		return nil, &SignalFormatError{"nonce", "A security event token must not carry a nonce"}
	}
	iss, _, err := stringClaim(claims, "iss", true)
	if err != nil {
		return nil, err
	}
	jti, _, err := stringClaim(claims, "jti", true)
	if err != nil {
		return nil, err
	}
	txn, _, err := stringClaim(claims, "txn", false)
	if err != nil {
		return nil, err
	}
	iat, err := numericDate(claims.Get("iat"), "iat claim")
	if err != nil {
		return nil, err
	}
	if iat == nil {
		return nil, &SignalFormatError{"claims", "The security event token has no iat claim"}
	}
	aud, err := audiences(claims.Get("aud"))
	if err != nil {
		return nil, err
	}

	events, ok := claims.Get("events").(*Object)
	if !ok || events == nil {
		return nil, &SignalFormatError{"events", "The security event token has no events claim"}
	}
	uris := events.Keys()
	if len(uris) != 1 {
		return nil, &SignalFormatError{"events", "A security event token carries exactly one event, not " + itoa(len(uris))}
	}
	eventURI := uris[0]
	if UTF16Len(eventURI) > maxSignalString {
		return nil, &SignalFormatError{"size", "The event type of the security event token is too long"}
	}
	if !signalText(eventURI) {
		return nil, &SignalFormatError{"events", "The event type of the security event token is invalid"}
	}
	payloadEvent, ok := events.Get(eventURI).(*Object)
	if !ok || payloadEvent == nil {
		return nil, &SignalFormatError{"events", "The event of the security event token is not an object"}
	}
	if nestedTooDeep(payloadEvent, 1) {
		return nil, &SignalFormatError{"size", "The event of the security event token is nested too deeply"}
	}
	legacySubject := payloadEvent.Get("subject")
	event := payloadEvent.Spread()
	event.Delete("subject")

	var subject *SubjectIdentifier
	if subID := claims.Get("sub_id"); !IsUndefined(subID) {
		subject = ParseSubjectIdentifier(subID)
		if subject == nil {
			return nil, &SignalFormatError{"subject", "The sub_id claim is not a valid subject identifier"}
		}
	}
	if payloadEvent.Has("subject") {
		var parsed *SubjectIdentifier
		if legacy, ok := legacySubject.(*Object); ok && legacy != nil && legacy.Has("format") {
			parsed = ParseSubjectIdentifier(legacy)
		} else {
			parsed = LegacyRiscSubject(legacySubject)
		}
		if parsed == nil {
			return nil, &SignalFormatError{"subject", "The subject of the event is not a valid subject identifier"}
		}
		if subject != nil && canonicalSubject(subject) != canonicalSubject(parsed) {
			return nil, &SignalFormatError{"subject", "The sub_id claim and the event name different subjects"}
		}
		if subject == nil {
			subject = parsed
		}
	}
	if sub := claims.Get("sub"); !IsUndefined(sub) {
		if text, ok := sub.(string); ok && UTF16Len(text) > maxSignalString {
			return nil, &SignalFormatError{"size", "The security event token's sub claim is too long"}
		}
		if !signalText(sub) {
			return nil, &SignalFormatError{"claims", "The security event token's sub claim is invalid"}
		}
		issuer := withoutTrailingSlash(iss)
		for _, identifier := range UserSubjects(subject) {
			if identifier.Format == "iss_sub" && withoutTrailingSlash(identifier.Iss) == issuer && identifier.Sub != sub.(string) {
				return nil, &SignalFormatError{"subject", "The sub and sub_id claims name different subjects"}
			}
		}
	}

	eventSeconds, err := numericDate(event.Get("event_timestamp"), "event_timestamp")
	if err != nil {
		return nil, err
	}
	toe, err := numericDate(claims.Get("toe"), "toe claim")
	if err != nil {
		return nil, err
	}
	seconds := eventSeconds
	if seconds == nil {
		seconds = toe
	}
	out := &SecurityEventClaims{Iss: iss, Aud: aud, Iat: *iat, Jti: jti, Txn: txn, EventURI: eventURI, EventType: SignalEventTypeOf(eventURI), Event: event, Subject: subject}
	if seconds != nil {
		millis := jsRound(*seconds * 1000)
		out.EventTimestamp = &millis
	}
	return out, nil
}

// jsRound is Math.round: halves round toward +Infinity.
func jsRound(value float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return value
	}
	floor := math.Floor(value)
	if value-floor >= 0.5 {
		return floor + 1
	}
	return floor
}

// UserSubjects lists the identifiers in a subject that may name a person, without repeats.
func UserSubjects(subject *SubjectIdentifier) []*SubjectIdentifier {
	found := []*SubjectIdentifier{}
	seen := map[string]bool{}
	var visit func(identifier *SubjectIdentifier)
	visit = func(identifier *SubjectIdentifier) {
		if identifier == nil {
			return
		}
		switch identifier.Format {
		case "aliases":
			for _, entry := range identifier.Identifiers {
				visit(entry)
			}
		case "complex":
			visit(identifier.User)
		case "iss_sub", "email", "opaque", "account", "phone_number":
			key := canonicalSubject(identifier)
			if seen[key] {
				return
			}
			seen[key] = true
			found = append(found, identifier)
		}
	}
	visit(subject)
	return found
}
