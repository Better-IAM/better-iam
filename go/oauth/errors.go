package oauth

// The oidc-provider error classes (lib/helpers/errors.js) the provider throws: an OAuth error code, an HTTP status,
// the public error_description and a private detail.

import (
	"errors"
	"strings"
)

// OIDCError is an oidc-provider error: Code is the OAuth `error` value.
type OIDCError struct {
	// Class is the oidc-provider class name (InvalidGrant, InvalidRequest, ...).
	Class       string
	Code        string
	Description string
	// HasDescription is false when the error carries no error_description.
	HasDescription bool
	Detail         string
	Scope          string
	HasScope       bool
	Status         int
	// AllowRedirect is false for errors the authorization endpoint must not redirect with.
	AllowRedirect bool
	// Expose is false for server errors (status 500 and up).
	Expose bool
	// rerender marks a device flow ReRenderError (rendered as the input page with status 200).
	rerender bool
	userCode string
}

func (e *OIDCError) Error() string { return e.Code }

func newOIDCError(class string, status int, code string) *OIDCError {
	return &OIDCError{Class: class, Code: code, Status: status, AllowRedirect: true, Expose: status < 500}
}

func withDescription(e *OIDCError, description string) *OIDCError {
	e.Description, e.HasDescription = description, true
	return e
}

// errSimple is E(message, errorDescription): the description argument replaces the default one.
func errSimple(class, code, fallback string) func(description ...string) *OIDCError {
	return func(description ...string) *OIDCError {
		e := newOIDCError(class, 400, code)
		if len(description) > 0 && description[0] != "" {
			return withDescription(e, description[0])
		}
		if fallback != "" {
			return withDescription(e, fallback)
		}
		return e
	}
}

var (
	errAccessDenied          = errSimple("AccessDenied", "access_denied", "")
	errAuthorizationPending  = errSimple("AuthorizationPending", "authorization_pending", "authorization request is still pending as the end-user hasn't yet completed the user interaction steps")
	errExpiredToken          = errSimple("ExpiredToken", "expired_token", "")
	errInvalidClient         = errSimple("InvalidClient", "invalid_client", "")
	errInvalidDpopProof      = errSimple("InvalidDpopProof", "invalid_dpop_proof", "")
	errInvalidRequestObject  = errSimple("InvalidRequestObject", "invalid_request_object", "")
	errInvalidRequestURI     = errSimple("InvalidRequestUri", "invalid_request_uri", "")
	errInvalidTarget         = errSimple("InvalidTarget", "invalid_target", "resource indicator is missing, or unknown")
	errLoginRequired         = errSimple("LoginRequired", "login_required", "")
	errRegistrationNotSupp   = errSimple("RegistrationNotSupported", "registration_not_supported", "")
	errRequestNotSupported   = errSimple("RequestNotSupported", "request_not_supported", "")
	errRequestURINotSupp     = errSimple("RequestUriNotSupported", "request_uri_not_supported", "")
	errUnsupportedGrantType  = errSimple("UnsupportedGrantType", "unsupported_grant_type", "unsupported grant_type requested")
	errUnsupportedRespMode   = errSimple("UnsupportedResponseMode", "unsupported_response_mode", "unsupported response_mode requested")
	errUnsupportedRespType   = errSimple("UnsupportedResponseType", "unsupported_response_type", "unsupported response_type requested")
	errUseDpopNonce          = errSimple("UseDpopNonce", "use_dpop_nonce", "")
	errUnsupportedTokenType  = errSimple("UnsupportedTokenType", "unsupported_token_type", "")
	errConsentRequired       = errSimple("ConsentRequired", "consent_required", "")
	errInteractionRequired   = errSimple("InteractionRequired", "interaction_required", "")
	errUnauthorizedClient    = errSimple("UnauthorizedClient", "unauthorized_client", "")
	errTemporarilyUnavailble = errSimple("TemporarilyUnavailable", "temporarily_unavailable", "")
)

// errInvalidRequest is InvalidRequest(description, code).
func errInvalidRequest(description string, status ...int) *OIDCError {
	code := 400
	if len(status) > 0 {
		code = status[0]
	}
	if description == "" {
		description = "request is invalid"
	}
	e := withDescription(newOIDCError("InvalidRequest", code, "invalid_request"), description)
	e.Expose = true
	return e
}

// errSessionNotFound is SessionNotFound (an InvalidRequest).
func errSessionNotFound(description string) *OIDCError {
	e := errInvalidRequest(description)
	e.Class = "SessionNotFound"
	return e
}

// errInvalidGrant is InvalidGrant(detail): the description stays the generic one.
func errInvalidGrant(detail string) *OIDCError {
	e := withDescription(newOIDCError("InvalidGrant", 400, "invalid_grant"), "grant request is invalid")
	e.Detail = detail
	return e
}

// errInvalidClientAuth is InvalidClientAuth(detail).
func errInvalidClientAuth(detail string) *OIDCError {
	e := withDescription(newOIDCError("InvalidClientAuth", 401, "invalid_client"), "client authentication failed")
	e.Detail = detail
	return e
}

// errInvalidToken is InvalidToken(detail).
func errInvalidToken(detail string) *OIDCError {
	e := withDescription(newOIDCError("InvalidToken", 401, "invalid_token"), "invalid token provided")
	e.Detail = detail
	return e
}

// errNoAccessToken is NoAccessTokenProvided.
func errNoAccessToken() *OIDCError {
	e := errInvalidToken("no access token provided")
	e.Class = "NoAccessTokenProvided"
	e.Description = "no access token provided"
	return e
}

// errInvalidScope is InvalidScope(description, scope).
func errInvalidScope(description, scope string) *OIDCError {
	e := withDescription(newOIDCError("InvalidScope", 400, "invalid_scope"), description)
	e.Scope, e.HasScope = scope, true
	return e
}

// errInsufficientScope is InsufficientScope(description, scope).
func errInsufficientScope(description, scope string) *OIDCError {
	e := withDescription(newOIDCError("InsufficientScope", 403, "insufficient_scope"), description)
	e.Scope, e.HasScope = scope, true
	return e
}

// errInvalidClientMetadata is InvalidClientMetadata(description).
func errInvalidClientMetadata(description string) *OIDCError {
	code := "invalid_client_metadata"
	if strings.HasPrefix(description, "redirect_uris") {
		code = "invalid_redirect_uri"
	}
	return withDescription(newOIDCError("InvalidClientMetadata", 400, code), description)
}

// errInvalidRedirectURI is InvalidRedirectUri.
func errInvalidRedirectURI() *OIDCError {
	e := withDescription(newOIDCError("InvalidRedirectUri", 400, "invalid_redirect_uri"), "redirect_uri did not match any of the client's registered redirect_uris")
	e.AllowRedirect = false
	return e
}

// errCustom is CustomOIDCProviderError(message, description).
func errCustom(code, description string) *OIDCError {
	return withDescription(newOIDCError("CustomOIDCProviderError", 400, code), description)
}

// errByCode is the errorMap lookup used for interaction and async grant results: the named class when one exists,
// a CustomOIDCProviderError otherwise.
func errByCode(code, description string) *OIDCError {
	switch code {
	case "access_denied":
		return errAccessDenied(description)
	case "authorization_pending":
		return errAuthorizationPending(description)
	case "consent_required":
		return errConsentRequired(description)
	case "expired_token":
		return errExpiredToken(description)
	case "interaction_required":
		return errInteractionRequired(description)
	case "invalid_client":
		return errInvalidClient(description)
	case "invalid_dpop_proof":
		return errInvalidDpopProof(description)
	case "invalid_request_object":
		return errInvalidRequestObject(description)
	case "invalid_request_uri":
		return errInvalidRequestURI(description)
	case "invalid_target":
		return errInvalidTarget(description)
	case "login_required":
		return errLoginRequired(description)
	case "registration_not_supported":
		return errRegistrationNotSupp(description)
	case "request_not_supported":
		return errRequestNotSupported(description)
	case "request_uri_not_supported":
		return errRequestURINotSupp(description)
	case "temporarily_unavailable":
		return errTemporarilyUnavailble(description)
	case "unauthorized_client":
		return errUnauthorizedClient(description)
	case "unsupported_grant_type":
		return errUnsupportedGrantType(description)
	case "unsupported_response_mode":
		return errUnsupportedRespMode(description)
	case "unsupported_response_type":
		return errUnsupportedRespType(description)
	case "use_dpop_nonce":
		return errUseDpopNonce(description)
	case "unsupported_token_type":
		return errUnsupportedTokenType(description)
	case "invalid_request":
		return errInvalidRequest(description)
	case "invalid_grant":
		e := errInvalidGrant(description)
		return e
	case "invalid_token":
		return errInvalidToken(description)
	case "invalid_scope":
		return errInvalidScope(description, "")
	}
	return errCustom(code, description)
}

// asOIDC returns err as an *OIDCError when it is one.
func asOIDC(err error) (*OIDCError, bool) {
	var target *OIDCError
	if errors.As(err, &target) {
		return target, true
	}
	return nil, false
}

// rerenderError is a device flow ReRenderError (helpers/re_render_errors.js).
func rerenderError(class, message, userCode string) *OIDCError {
	return &OIDCError{Class: class, Code: message, Status: 200, Expose: true, rerender: true, userCode: userCode}
}

// errOut is helpers/err_out.js: the response body of an error.
func errOut(err error, state string, hasState bool) *outBody {
	if e, ok := asOIDC(err); ok && e.Expose {
		out := &outBody{Error: e.Code}
		if e.HasDescription {
			out.Description, out.HasDescription = e.Description, true
		}
		if e.HasScope {
			out.Scope, out.HasScope = e.Scope, true
		}
		if hasState {
			out.State, out.HasState = state, true
		}
		return out
	}
	out := &outBody{Error: "server_error", Description: "oops! something went wrong", HasDescription: true}
	if hasState && state != "" {
		out.State, out.HasState = state, true
	}
	return out
}

// outBody is an error response body.
type outBody struct {
	Error          string
	Description    string
	HasDescription bool
	Scope          string
	HasScope       bool
	State          string
	HasState       bool
}

func (o *outBody) object() *orderedPairs {
	pairs := &orderedPairs{}
	pairs.add("error", o.Error)
	if o.HasDescription {
		pairs.add("error_description", o.Description)
	}
	if o.HasScope {
		pairs.add("scope", o.Scope)
	}
	if o.HasState {
		pairs.add("state", o.State)
	}
	return pairs
}

// orderedPairs is an ordered list of string members (URL parameters, form inputs, JSON bodies of strings).
type orderedPairs struct{ items [][2]string }

func (p *orderedPairs) add(key, value string) { p.items = append(p.items, [2]string{key, value}) }

func (p *orderedPairs) set(key, value string) {
	for index, item := range p.items {
		if item[0] == key {
			p.items[index][1] = value
			return
		}
	}
	p.add(key, value)
}
