package a2a

// Port of packages/a2a/src/delegation-tokens.ts: delegation tokens for services outside Better IAM. An agent acting
// for a person gets one from delegations.issueToken and presents it (typically as a bearer token); the service checks
// it here, offline, with the issuing deployment's public keys (the same JWKS as its agent cards). The token says who
// the person is (PersonID), which agent acts for them (AgentID, and Chain when the work was handed on between agents),
// which organization, and which scopes of the delegation it carries. The service still decides what that person may
// do.

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strings"
	"sync"

	"github.com/Better-IAM/better-iam/go/core"
)

// DelegationTokenErrorReason is a core.DelegationTokenRejection, or type, untrusted-key, signature, replay or fetch.
type DelegationTokenErrorReason = string

// DelegationTokenError is why VerifyDelegationToken refused a token: Reason is malformed, type, issuer,
// untrusted-key, signature, audience, tenant, expired, not-yet-valid, lifetime, replay or fetch.
type DelegationTokenError struct {
	Reason  DelegationTokenErrorReason
	Message string
}

func (e *DelegationTokenError) Error() string { return e.Message }

// Name is the JavaScript error name.
func (e *DelegationTokenError) Name() string { return "DelegationTokenError" }

func tokenError(reason DelegationTokenErrorReason, message string) *DelegationTokenError {
	return &DelegationTokenError{Reason: reason, Message: message}
}

// VerifyDelegationTokenOptions configures VerifyDelegationToken.
type VerifyDelegationTokenOptions struct {
	// Audience is the audience your service answers to: the token's aud must be exactly this.
	Audience string
	// TrustedIssuers are the Better IAM deployments you trust, by issuer (their a2a issuer): each one's JWKS URL
	// (a2a.jwksUrl) or its JWKS. A token is checked only with the keys of the issuer it names.
	TrustedIssuers map[string]JwksSource
	// TenantID accepts only tokens of this organization (tenant id).
	TenantID *string
	// Replay records a verified token's id until it expires; return false when the id was seen before to refuse the
	// replay. Without it a token may be used again until it expires (at most an hour, usually five minutes).
	Replay func(ctx context.Context, tokenID string, expiresAt float64) (bool, error)
	// ClockToleranceSeconds is the allowed clock difference in seconds (nil: 30).
	ClockToleranceSeconds *float64
	// JwksCacheSeconds is how long fetched key sets are kept, in seconds (nil: 300).
	JwksCacheSeconds *float64
	// Now is epoch milliseconds (nil: the system clock).
	Now func() float64
	// Fetch makes the key set requests (nil: an http.Client that refuses redirects).
	Fetch Fetcher
}

var compactPart = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// decodeJSON is JSON.parse of a base64url part, undefined when it does not decode.
func decodeJSON(part string) any {
	value, err := decodeJSONPart(part)
	if err != nil {
		return core.Undefined
	}
	return value
}

// VerifyDelegationToken verifies a delegation token: a compact JWT of type biam-delegation+jwt, signed (EdDSA or
// ES256) by a key of the trusted issuer it names, for exactly Audience (and TenantID), current, and issued for at
// most an hour. It returns who acts for whom and fails with a *DelegationTokenError otherwise (a *core.TypeError for
// invalid options). Revocation reaches a token only when it expires, so keep lifetimes short, or verify inside the
// deployment with iam.A2a.VerifyDelegationToken and live.
func VerifyDelegationToken(ctx context.Context, token string, options VerifyDelegationTokenOptions) (*core.DelegationTokenSummary, error) {
	if options.TrustedIssuers == nil || options.Audience == "" {
		return nil, &core.TypeError{Message: "verifyDelegationToken needs audience and trustedIssuers"}
	}
	if core.UTF16Len(token) > 16_384 {
		return nil, tokenError("malformed", "Not a delegation token")
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, tokenError("malformed", "Not a compact JWT")
	}
	for _, part := range parts {
		if !compactPart.MatchString(part) {
			return nil, tokenError("malformed", "Not a compact JWT")
		}
	}
	protectedHeader, payload, signaturePart := parts[0], parts[1], parts[2]
	header, headerOK := plain(decodeJSON(protectedHeader))
	claims, claimsOK := plain(decodeJSON(payload))
	if !headerOK || !claimsOK {
		return nil, tokenError("malformed", "The token is not a JWT")
	}
	if header.Get("typ") != core.DelegationTokenType {
		return nil, tokenError("type", "The token is not a delegation token")
	}
	alg, _ := header.Get("alg").(string)
	kid, kidIsString := header.Get("kid").(string)
	if (alg != "EdDSA" && alg != "ES256") || !kidIsString || !core.IsUndefined(header.Get("crit")) || !core.IsUndefined(header.Get("b64")) {
		return nil, tokenError("malformed", "The token header is not acceptable")
	}
	// The issuer is read before the signature is checked only to pick its keys; the signature then binds the two.
	issuer, issuerIsString := claims.Get("iss").(string)
	source, trusted := options.TrustedIssuers[issuer]
	if !issuerIsString || !trusted {
		return nil, tokenError("issuer", "The token was issued by "+jsString(claims.Get("iss")))
	}
	now := nowOf(options.Now)
	fetcher := fetcherOr(options.Fetch)
	jwk, err := func() (*core.Object, error) {
		if !source.isURL() {
			return pickKey(source.Keys, kid, alg)
		}
		cache := newJwksCache(fetcher)
		cacheSeconds := numberOr(options.JwksCacheSeconds, 300)
		jwks, err := fetchJwks(ctx, source.URL, fetcher, cache, now, cacheSeconds, false)
		if err != nil {
			return nil, err
		}
		key, err := pickKey(jwks, kid, alg)
		if err != nil || key != nil {
			return key, err
		}
		jwks, err = fetchJwks(ctx, source.URL, fetcher, cache, now, cacheSeconds, true)
		if err != nil {
			return nil, err
		}
		return pickKey(jwks, kid, alg)
	}()
	if err != nil {
		var refused *AgentCardError
		if errors.As(err, &refused) && refused.Reason != "fetch" {
			return nil, tokenError("untrusted-key", refused.Message)
		}
		return nil, tokenError("fetch", "Could not fetch the keys of "+issuer)
	}
	if jwk == nil {
		return nil, tokenError("untrusted-key", "The token is not signed with a trusted key")
	}
	signature, err := fromBase64URL(signaturePart)
	if err != nil {
		return nil, tokenError("malformed", "The token signature is not base64url")
	}
	if !verifySignature(jwk, alg, utf8Bytes(protectedHeader+"."+payload), signature) {
		return nil, tokenError("signature", "The token signature does not verify")
	}
	read, err := core.ReadDelegationTokenClaims(claims, core.DelegationTokenExpectations{
		Issuers: []string{issuer}, Audience: options.Audience, Now: now, TenantID: options.TenantID,
		ClockToleranceSeconds: options.ClockToleranceSeconds,
	})
	if err != nil {
		return nil, err
	}
	if read.Token == nil {
		return nil, tokenError(read.Rejected, read.Message)
	}
	if options.Replay != nil {
		fresh, err := options.Replay(ctx, read.Token.TokenID, read.Token.ExpiresAt)
		if err != nil {
			return nil, err
		}
		if !fresh {
			return nil, tokenError("replay", "The token was used before")
		}
	}
	return read.Token, nil
}

// IssuedDelegationToken is a token delegations.issueToken issued: the token and when it expires (epoch ms).
type IssuedDelegationToken struct {
	Token     string
	ExpiresAt float64
}

// DelegationTokenCacheOptions configures CreateDelegationTokenCache.
type DelegationTokenCacheOptions struct {
	// Issue gets a new token, for example with iam.API.Delegations.IssueToken and the delegated session. scopes is nil
	// when the caller named none.
	Issue func(ctx context.Context, audience string, scopes []string) (IssuedDelegationToken, error)
	// RefreshShare gets a new token once less than this share of its lifetime is left (nil: 0.2), or 15 seconds.
	RefreshShare *float64
	// Now is epoch milliseconds (nil: the system clock).
	Now func() float64
}

type cachedDelegationToken struct {
	token               string
	issuedAt, expiresAt float64
}

type tokenFlight struct {
	done  chan struct{}
	token string
	err   error
}

// CreateDelegationTokenCache is for the agent side: it returns a function yielding a current delegation token for an
// audience (and scopes, nil for none), issuing one on first use and again when it nears its end, so an agent calling
// a service repeatedly does not ask for a token on every call. Concurrent calls for the same audience share one
// request.
func CreateDelegationTokenCache(options DelegationTokenCacheOptions) func(ctx context.Context, audience string, scopes []string) (string, error) {
	share := numberOr(options.RefreshShare, 0.2)
	var (
		mu      sync.Mutex
		tokens  = map[string]cachedDelegationToken{}
		order   []string
		pending = map[string]*tokenFlight{}
	)
	return func(ctx context.Context, audience string, scopes []string) (string, error) {
		var sorted any
		if scopes != nil {
			copied := append([]string{}, scopes...)
			sort.SliceStable(copied, func(i, j int) bool { return compareUTF16(copied[i], copied[j]) < 0 })
			list := make([]any, len(copied))
			for index, scope := range copied {
				list[index] = scope
			}
			sorted = list
		}
		key := core.MustStringify([]any{audience, sorted})
		at := nowOf(options.Now)
		mu.Lock()
		if current, ok := tokens[key]; ok {
			left := current.expiresAt - at
			if left > max(15_000, (current.expiresAt-current.issuedAt)*share) {
				mu.Unlock()
				return current.token, nil
			}
		}
		if running := pending[key]; running != nil {
			mu.Unlock()
			<-running.done
			return running.token, running.err
		}
		flight := &tokenFlight{done: make(chan struct{})}
		pending[key] = flight
		mu.Unlock()
		issued, err := options.Issue(ctx, audience, scopes)
		mu.Lock()
		if err == nil {
			if _, exists := tokens[key]; !exists {
				order = append(order, key)
			}
			tokens[key] = cachedDelegationToken{token: issued.Token, issuedAt: at, expiresAt: issued.ExpiresAt}
			if len(tokens) > 256 {
				oldest := order[0]
				order = order[1:]
				delete(tokens, oldest)
			}
			flight.token = issued.Token
		} else {
			flight.err = err
		}
		delete(pending, key)
		mu.Unlock()
		close(flight.done)
		return flight.token, flight.err
	}
}
