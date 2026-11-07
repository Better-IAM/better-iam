package server

// Partial port of packages/server/src/web-identity.ts: the issuer validation resolveConfig needs
// (sts.webIdentity.allowedIssuers). The verifier (WebIdentityVerifier, declared in contracts.go), JWKS fetching and
// the other validators are ported with the STS module.

import (
	"context"
	"strings"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

var webIdentityLoopbackHosts = map[string]bool{"localhost": true, "127.0.0.1": true, "[::1]": true}

// webIdentityControl is /[\u0000-\u001f\u007f]/.
func webIdentityControl(s string) bool {
	return hasControl(s) || strings.IndexByte(s, 0x7f) >= 0
}

// WebIdentityIssuerOptions are the rules of WebIdentityIssuer.
type WebIdentityIssuerOptions struct {
	AllowInsecureLocalhost bool
	// SelfIssuer is IAM's own issuer, which is refused ("" when unset).
	SelfIssuer *string
	// AllowedIssuers pins the accepted issuers (nil when unset).
	AllowedIssuers []string
}

// WebIdentityIssuer validates an issuer: an absolute https URL without credentials, query or fragment, at most 512
// characters (http only for loopback hosts with AllowInsecureLocalhost). IAM's own issuer is refused, and when
// AllowedIssuers is set the issuer must be one of them. Fails with INVALID_INPUT.
func WebIdentityIssuer(value any, options WebIdentityIssuerOptions) (string, error) {
	text, ok := value.(string)
	if !ok || text == "" || utf16Len(text) > 512 || webIdentityControl(text) {
		return "", invalidInput("Invalid issuer")
	}
	u, err := auth.ParseFetchURL(text)
	if err != nil {
		return "", invalidInput("The issuer must be an absolute URL")
	}
	insecureLocal := options.AllowInsecureLocalhost && webIdentityLoopbackHosts[u.Hostname]
	if u.Protocol != "https:" && !(insecureLocal && u.Protocol == "http:") {
		return "", invalidInput("The issuer must use https")
	}
	if urlUsername(u) != "" || urlPassword(u) != "" || u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(text, "?#") {
		return "", invalidInput("The issuer cannot carry credentials, a query or a fragment")
	}
	trimmed := func(issuer string) string { return strings.TrimRight(issuer, "/") }
	if options.SelfIssuer != nil && trimmed(text) == trimmed(*options.SelfIssuer) {
		return "", invalidInput("IAM cannot trust its own issuer as a web identity provider")
	}
	if options.AllowedIssuers != nil && !containsString(options.AllowedIssuers, text) {
		return "", invalidInput("The issuer is not in sts.webIdentity.allowedIssuers")
	}
	return text, nil
}

// urlUsername is URL#username.
func urlUsername(u *auth.FetchURL) string {
	if u.User == nil {
		return ""
	}
	return u.User.Username()
}

// urlPassword is URL#password.
func urlPassword(u *auth.FetchURL) string {
	if u.User == nil {
		return ""
	}
	password, _ := u.User.Password()
	return password
}

// urlOrigin is URL#origin: scheme://host[:port] for the special schemes, "null" otherwise.
func urlOrigin(u *auth.FetchURL) string {
	switch u.Protocol {
	case "http:", "https:", "ws:", "wss:", "ftp:":
	default:
		return "null"
	}
	origin := u.Protocol + "//" + u.Hostname
	if u.Port != "" {
		origin += ":" + u.Port
	}
	return origin
}

// urlPathname is URL#pathname (the percent-encoded path; "/" for an empty path of a special URL).
func urlPathname(u *auth.FetchURL) string {
	path := u.URL.EscapedPath()
	if path == "" {
		return "/"
	}
	return path
}

// WebIdentityFailure is web-identity.ts WebIdentityFailure.
// TypeScript: super(`The web identity token was not accepted (${reason})`);
type WebIdentityFailure struct {
	Reason string
}

// WebIdentityVerifier is web-identity.ts WebIdentityVerifier.
type WebIdentityVerifier struct {
	server *ServerContext
}

// Verify (web-identity.ts WebIdentityVerifier.verify): Verifies an external token against a provider, or throws
// `WebIdentityFailure`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *WebIdentityVerifier) Verify(ctx context.Context, provider *core.Object, token string) (result *core.Object, err error) {
	err = notImplemented("web-identity.ts WebIdentityVerifier.verify")
	return
}

// Forget (web-identity.ts WebIdentityVerifier.forget): Drops the cached keys of a provider (after an update or
// deletion).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func (s *WebIdentityVerifier) Forget(providerID string) (err error) {
	err = notImplemented("web-identity.ts WebIdentityVerifier.forget")
	return
}

// CreateWebIdentityVerifier builds the WebIdentityVerifier (web-identity.ts createWebIdentityVerifier). Its methods are stubs until the module is ported.
func CreateWebIdentityVerifier(options *WebIdentityVerifierOptions) *WebIdentityVerifier {
	return &WebIdentityVerifier{}
}

// MatchWebIdentityConditions (web-identity.ts matchWebIdentityConditions): Evaluates trust conditions against
// flattened claims with the core policy engine (an allow statement for `sts:AssumeRoleWithWebIdentity` on
// `trust/{trustId}`). `failed` lists each unmet entry as `Operator:key`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func MatchWebIdentityConditions(conditions *core.Object, context *core.Object, trustID string) (result *core.Object, err error) {
	err = notImplemented("web-identity.ts matchWebIdentityConditions")
	return
}

// WebIdentityWebIdentityAlgorithms (web-identity.ts webIdentityAlgorithms): Validates an algorithm allowlist: a
// non-empty subset of `WEB_IDENTITY_ALGORITHMS` (default RS256 and ES256).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func WebIdentityWebIdentityAlgorithms(value any) (result []string, err error) {
	err = notImplemented("web-identity.ts webIdentityAlgorithms")
	return
}

// WebIdentityAudiences (web-identity.ts webIdentityAudiences): Validates the accepted audiences: 1 to 10 strings of
// 1 to 256 characters.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func WebIdentityAudiences(value any) (result []string, err error) {
	err = notImplemented("web-identity.ts webIdentityAudiences")
	return
}

// WebIdentityClaimName (web-identity.ts webIdentityClaimName): Validates a flattened claim name as used in
// conditions, `tagClaims` and `sourceIdentityClaim`: `token.<claim>`.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func WebIdentityClaimName(value any) (result string, err error) {
	err = notImplemented("web-identity.ts webIdentityClaimName")
	return
}

// WebIdentityConditions (web-identity.ts webIdentityConditions): Validates web-identity trust conditions: the core
// condition grammar over `token.<claim>` keys, at most 20 operator/key entries, no policy variables, and a mandatory
// subject pin — a `StringEquals` or `StringLike` entry on `token.sub` whose values are non-empty and, for
// `StringLike`, put any wildcard only after two complete segments (see `pinsSubject`; else WEAK_TRUST_CONDITIONS).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func WebIdentityConditions(value any) (result *core.Object, err error) {
	err = notImplemented("web-identity.ts webIdentityConditions")
	return
}

// WebIdentityJwksURI (web-identity.ts webIdentityJwksUri): Validates a JWKS URL: https on port 443 without
// credentials or a fragment (loopback http with the dev option).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func WebIdentityJwksURI(value any, options *core.Object) (result string, err error) {
	err = notImplemented("web-identity.ts webIdentityJwksUri")
	return
}

// WebIdentityKeys (web-identity.ts webIdentityKeys): Validates static provider keys: 1 to 20 public keys (RSA of at
// least 2048 bits, EC P-256/P-384/P-521, OKP Ed25519), `use` absent or `sig`. Returns an allowlisted copy.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func WebIdentityKeys(value any) (result *core.Object, err error) {
	err = notImplemented("web-identity.ts webIdentityKeys")
	return
}

// WebIdentityReplayID (web-identity.ts webIdentityReplayId): The replay-cache key of a token at a provider (hex): by
// `jti` when present, else by the hash of the token's signed content (`header.payload`). The signature segment is
// left out on purpose: it is malleable without the key (unused trailing base64url bits, and ECDSA's (r, s) / (r, n -
// s) pair), so hashing the whole token would let one token be redeemed several times under different spellings.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func WebIdentityReplayID(providerID string, jti string, token string) (result string, err error) {
	err = notImplemented("web-identity.ts webIdentityReplayId")
	return
}

// WebIdentityAlgorithms is web-identity.ts WEB_IDENTITY_ALGORITHMS.
var WebIdentityAlgorithms = []string{"RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "EdDSA"}

// WebIdentityVerifierOptions is web-identity.ts WebIdentityVerifierOptions.
type WebIdentityVerifierOptions struct {
	// JwksCacheSeconds How long fetched keys are used before they are fetched again, in seconds.
	JwksCacheSeconds       float64
	FetchTimeoutMs         float64
	MaxJwksBytes           float64
	AllowPrivateNetworks   bool
	AllowInsecureLocalhost bool
	// FetchJSON A host transport replacing the guarded fetch; the host is responsible for its safety.
	FetchJSON func(context.Context, *auth.FetchURL) (any, error)
	// Now The clock, in epoch milliseconds.
	Now func() float64
	// SelfIssuer IAM's own session token issuer, never accepted from a provider.
	SelfIssuer string
}

// Error is the failure reason (the module's messages are ported with web-identity.ts).
func (e *WebIdentityFailure) Error() string { return e.Reason }
