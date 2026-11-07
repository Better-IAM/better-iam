package core

import (
	"math"
	"regexp"
	"strings"
)

// Delegation tokens: short-lived signed JWTs with which an AI agent acting for a person shows a service outside
// Better IAM that it does so. The subject is the person; the actor (act, RFC 8693 section 4.1) is the agent acting now,
// with the agents that handed the work to it nested inside. This file only reads the claims (no cryptography).

// DelegationTokenType is the JWT typ header of delegation tokens: verifiers refuse any other.
const DelegationTokenType = "biam-delegation+jwt"

// DelegationTokenLimits are the lifetimes (seconds) and the longest chain of actors a delegation token carries.
var DelegationTokenLimits = struct {
	MinSeconds, MaxSeconds, DefaultSeconds, MaxActors int
}{30, 3600, 300, 4}

// DelegationActor is an actor (RFC 8693 act): the agent acting, and in Act the agent that handed the work on to it.
type DelegationActor struct {
	Sub string           `json:"sub"`
	Act *DelegationActor `json:"act,omitempty"`
}

// DelegationTokenSummary is a delegation token as a verifier reports it.
type DelegationTokenSummary struct {
	Issuer       string   `json:"issuer"`
	PersonID     string   `json:"personId"`
	TenantID     string   `json:"tenantId"`
	DelegationID string   `json:"delegationId"`
	AgentID      string   `json:"agentId"`
	Chain        []string `json:"chain"`
	Scopes       []string `json:"scopes"`
	Audience     string   `json:"audience"`
	TokenID      string   `json:"tokenId"`
	IssuedAt     float64  `json:"issuedAt"`
	ExpiresAt    float64  `json:"expiresAt"`
	// Claims are the token's claims as read.
	Claims *Object `json:"claims"`
}

// DelegationTokenRejection is malformed, issuer, audience, tenant, expired, not-yet-valid or lifetime.
type DelegationTokenRejection = string

// DelegationTokenExpectations is what a verifier expects of a token.
type DelegationTokenExpectations struct {
	// Issuers to accept.
	Issuers []string
	// Audience the verifier answers to; the token's aud must be exactly this.
	Audience string
	// TenantID, when set, accepts only tokens of this organization.
	TenantID *string
	// Now is epoch milliseconds.
	Now float64
	// ClockToleranceSeconds is the allowed clock difference (nil: 30).
	ClockToleranceSeconds *float64
}

// DelegationTokenResult is either Token or a rejection with its message.
type DelegationTokenResult struct {
	Token    *DelegationTokenSummary
	Rejected DelegationTokenRejection
	Message  string
}

// ToValue is the result as TypeScript returns it ({ token } or { rejected, message }).
func (r DelegationTokenResult) ToValue() *Object {
	if r.Token != nil {
		return NewObject("token", r.Token)
	}
	return NewObject("rejected", r.Rejected, "message", r.Message)
}

var delegationIDPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

// DelegationTokenScopePattern is one scope a delegation token may carry: an action, or an action pattern whose only
// wildcard is *.
var DelegationTokenScopePattern = regexp.MustCompile(`^[A-Za-z0-9*][A-Za-z0-9:_*./-]{0,127}$`)

func positiveSeconds(value any) bool {
	return IsSafeInteger(value) && value.(float64) > 0
}

// ReadDelegationTokenClaims checks the claims of a (signature-verified) delegation token against what the verifier
// expects: well formed, from an accepted issuer, for exactly this audience (and tenant), current within the clock
// tolerance, and issued for at most DelegationTokenLimits.MaxSeconds. It fails (with a *TypeError) only for invalid
// expectations.
func ReadDelegationTokenClaims(claims any, expected DelegationTokenExpectations) (DelegationTokenResult, error) {
	malformed := func(message string) (DelegationTokenResult, error) {
		return DelegationTokenResult{Rejected: "malformed", Message: message}, nil
	}
	value, ok := Normalize(claims).(*Object)
	if !ok || value == nil {
		return malformed("The token has no claims object")
	}
	for _, field := range []string{"iss", "sub", "aud", "jti", "tenant_id", "delegation_id"} {
		if text, ok := value.Get(field).(string); !ok || text == "" {
			return malformed("The token has no " + field)
		}
	}
	for _, field := range []string{"sub", "tenant_id", "delegation_id"} {
		if !delegationIDPattern.MatchString(value.Get(field).(string)) {
			return malformed("The token's " + field + " is invalid")
		}
	}
	if !positiveSeconds(value.Get("iat")) || !positiveSeconds(value.Get("nbf")) || !positiveSeconds(value.Get("exp")) {
		return malformed("The token has no valid iat, nbf and exp")
	}
	var actors []string
	actor := value.Get("act")
	for !IsUndefined(actor) {
		entry, ok := actor.(*Object)
		if !ok || entry == nil {
			return malformed("The token has an invalid act claim")
		}
		sub, ok := entry.Get("sub").(string)
		if !ok || !delegationIDPattern.MatchString(sub) {
			return malformed("The token has an invalid act claim")
		}
		actors = append(actors, sub)
		if len(actors) > DelegationTokenLimits.MaxActors {
			return malformed("The token names too many actors")
		}
		actor = entry.Get("act")
	}
	if len(actors) == 0 {
		return malformed("The token names no actor (act)")
	}
	person := value.Get("sub").(string)
	seen := map[string]bool{}
	for _, item := range actors {
		if seen[item] || item == person {
			return malformed("The token repeats an actor")
		}
		seen[item] = true
	}
	scopes := []string{}
	if scope := value.Get("scope"); !IsUndefined(scope) {
		text, ok := scope.(string)
		if !ok {
			return malformed("The token has an invalid scope")
		}
		for _, item := range strings.Split(text, " ") {
			if item != "" {
				scopes = append(scopes, item)
			}
		}
		if len(scopes) > 50 {
			return malformed("The token has an invalid scope")
		}
		for _, item := range scopes {
			if !DelegationTokenScopePattern.MatchString(item) {
				return malformed("The token has an invalid scope")
			}
		}
	}
	iss := value.Get("iss").(string)
	accepted := false
	for _, issuer := range expected.Issuers {
		if issuer == iss {
			accepted = true
			break
		}
	}
	if !accepted {
		return DelegationTokenResult{Rejected: "issuer", Message: "The token was issued by " + iss}, nil
	}
	if value.Get("aud") != expected.Audience {
		return DelegationTokenResult{Rejected: "audience", Message: "The token is for another audience"}, nil
	}
	if expected.TenantID != nil && value.Get("tenant_id") != *expected.TenantID {
		return DelegationTokenResult{Rejected: "tenant", Message: "The token is from another organization"}, nil
	}
	iat := value.Get("iat").(float64)
	nbf := value.Get("nbf").(float64)
	exp := value.Get("exp").(float64)
	if exp <= iat || nbf < iat || exp-iat > float64(DelegationTokenLimits.MaxSeconds) {
		return DelegationTokenResult{Rejected: "lifetime", Message: "The token lives longer than a delegation token may"}, nil
	}
	// A NaN or infinite tolerance (or clock) would make every time comparison below false and accept any token.
	toleranceSeconds := 30.0
	if expected.ClockToleranceSeconds != nil {
		toleranceSeconds = *expected.ClockToleranceSeconds
	}
	if math.IsNaN(toleranceSeconds) || math.IsInf(toleranceSeconds, 0) || toleranceSeconds < 0 || toleranceSeconds > 300 ||
		math.IsNaN(expected.Now) || math.IsInf(expected.Now, 0) {
		return DelegationTokenResult{}, &TypeError{"clockToleranceSeconds must be 0 to 300 seconds and now a finite time"}
	}
	tolerance := toleranceSeconds * 1000
	if exp*1000 <= expected.Now-tolerance {
		return DelegationTokenResult{Rejected: "expired", Message: "The token has expired"}, nil
	}
	if nbf*1000 > expected.Now+tolerance || iat*1000 > expected.Now+tolerance {
		return DelegationTokenResult{Rejected: "not-yet-valid", Message: "The token is not valid yet"}, nil
	}
	chain := make([]string, len(actors))
	for index, item := range actors {
		chain[len(actors)-1-index] = item
	}
	return DelegationTokenResult{Token: &DelegationTokenSummary{
		Issuer:       iss,
		PersonID:     person,
		TenantID:     value.Get("tenant_id").(string),
		DelegationID: value.Get("delegation_id").(string),
		AgentID:      actors[0],
		Chain:        chain,
		Scopes:       scopes,
		Audience:     value.Get("aud").(string),
		TokenID:      value.Get("jti").(string),
		IssuedAt:     iat * 1000,
		ExpiresAt:    exp * 1000,
		Claims:       value,
	}}, nil
}

// NewDelegationActor is the act claim for a chain of agents, the person's own delegate first and the agent acting now
// last (delegationActor).
func NewDelegationActor(chain []string) (*DelegationActor, error) {
	if len(chain) == 0 {
		return nil, &TypeError{"A delegation token needs at least one actor"}
	}
	var actor *DelegationActor
	for _, sub := range chain {
		if actor == nil {
			actor = &DelegationActor{Sub: sub}
		} else {
			actor = &DelegationActor{Sub: sub, Act: actor}
		}
	}
	return actor, nil
}
