package oauth

// The authorization endpoint and its resume route (oidc-provider actions/authorization): parameter checks, pushed
// request loading, the login and consent interaction policy, and the authorization code response.

import (
	"errors"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

var paramList = []string{"acr_values", "claims_locales", "client_id", "code_challenge", "code_challenge_method", "display",
	"id_token_hint", "login_hint", "max_age", "nonce", "prompt", "redirect_uri", "registration", "request", "request_uri",
	"response_mode", "response_type", "scope", "state", "ui_locales"}

var frontchannelParams = []string{"web_message_uri", "response_type", "response_mode", "code_challenge_method", "code_challenge", "state", "redirect_uri", "prompt"}

// authorizationParams is getAuthorizationParams: the parameters each authorization route accepts.
func authorizationParams(route string) []string {
	allow := append(append([]string{}, paramList...), "resource")
	if route == "device_authorization" || route == "code_verification" || route == "device_resume" {
		filtered := []string{}
		for _, name := range allow {
			if !contains(frontchannelParams, name) {
				filtered = append(filtered, name)
			}
		}
		allow = filtered
	}
	if route == "authorization" || route == "resume" || route == "pushed_authorization_request" {
		allow = append(allow, "dpop_jkt")
	}
	return allow
}

const pushedRequestURN = "urn:ietf:params:oauth:request_uri:"

var scopeSyntax = regexp.MustCompile(`^[\x21\x23-\x5B\x5D-\x7E]+(?: [\x21\x23-\x5B\x5D-\x7E]+)*$`)

func validScope(value any) bool {
	if isUndefined(value) {
		return true
	}
	text, ok := value.(string)
	return ok && scopeSyntax.MatchString(text)
}

// prompts are the requested prompt values.
func (oc *oidcCtx) prompts() []string {
	prompt := oc.param("prompt")
	if prompt == "" {
		return []string{}
	}
	return unique(strings.Split(prompt, " "))
}

func (oc *oidcCtx) requestParamScopes() []string {
	scope := oc.param("scope")
	if scope == "" {
		return []string{}
	}
	return unique(strings.Split(scope, " "))
}

func (oc *oidcCtx) requestParamOIDCScopes() []string {
	out := []string{}
	for _, scope := range oc.requestParamScopes() {
		if contains(oc.p.supportedScopes, scope) {
			out = append(out, scope)
		}
	}
	return out
}

// promptPending is OIDCContext#promptPending.
func (oc *oidcCtx) promptPending(name string) bool {
	if strings.HasSuffix(oc.route, "resume") {
		for _, prompt := range oc.prompts() {
			if prompt == name {
				return oc.result == nil || !oc.result.Has(name)
			}
		}
		return false
	}
	return contains(oc.prompts(), name)
}

func (oc *oidcCtx) responseMode() string {
	if mode, ok := oc.params.Get("response_mode").(string); ok {
		return mode
	}
	if responseType := oc.params.Get("response_type"); !isUndefined(responseType) {
		return resolveResponseMode(jsString(responseType))
	}
	return ""
}

func resolveResponseMode(responseType string) string {
	if strings.Contains(responseType, "token") {
		return "fragment"
	}
	return "query"
}

// authorizationEndpoint runs the authorization and resume routes under the authorization error handler.
func (p *Provider) authorizationEndpoint(oc *oidcCtx) error {
	oc.noCache()
	err := p.authorizationStack(oc)
	if err != nil {
		if errors.Is(err, errInsecureCookie) {
			return err
		}
		p.authorizationError(oc, err)
	}
	return nil
}

func (p *Provider) authorizationStack(oc *oidcCtx) error {
	if err := p.loadSession(oc); err != nil {
		return err
	}
	err := p.authorizationSteps(oc)
	if finishErr := p.finishSession(oc); finishErr != nil {
		return finishErr
	}
	return err
}

func (p *Provider) authorizationSteps(oc *oidcCtx) error {
	resume := oc.route == "resume"
	if resume {
		done, err := p.resumeInteraction(oc)
		if err != nil || done {
			return err
		}
	} else {
		if oc.method == http.MethodPost {
			if err := oc.parseBody("application/x-www-form-urlencoded"); err != nil {
				return err
			}
		}
		oc.assembleParams(authorizationParams(oc.route))
		if err := oc.rejectDupes([]string{"resource"}, nil); err != nil {
			return err
		}
		if err := p.rejectUnsupported(oc); err != nil {
			return err
		}
	}
	if err := p.checkClient(oc); err != nil {
		return err
	}
	if !resume {
		if err := p.loadPushedAuthorizationRequest(oc); err != nil {
			return err
		}
		if err := p.processRequestObject(oc); err != nil {
			return err
		}
		if err := p.checkResponseMode(oc); err != nil {
			return err
		}
		p.oneRedirectURIClients(oc)
		if err := oc.presence("response_type", "client_id"); err != nil {
			return err
		}
		if oc.hasParam("registration") {
			return errRegistrationNotSupp()
		}
		if err := p.checkResponseType(oc); err != nil {
			return err
		}
		required := []string{"redirect_uri"}
		if strings.Contains(oc.param("response_type"), "id_token") {
			required = append(required, "nonce")
		}
		if err := oc.presence(required...); err != nil {
			return err
		}
		p.assignDefaults(oc)
		if err := p.checkPrompt(oc); err != nil {
			return err
		}
		if err := p.checkScope(oc); err != nil {
			return err
		}
		if err := p.checkOpenIDScope(oc); err != nil {
			return err
		}
		if !oc.client.redirectURIAllowed(oc.param("redirect_uri")) {
			return errInvalidRedirectURI()
		}
		oc.redirectURIChecked = true
		if err := checkPKCEParams(oc); err != nil {
			return err
		}
	}
	if err := p.checkResource(oc); err != nil {
		return err
	}
	if !resume {
		if err := p.checkMaxAge(oc); err != nil {
			return err
		}
		if err := p.checkIDTokenHint(oc); err != nil {
			return err
		}
	}
	p.assignClaims(oc)
	if err := p.loadAccountAndGrant(oc); err != nil {
		return err
	}
	done, err := p.interactions(oc)
	if err != nil || done {
		return err
	}
	return p.respond(oc)
}

// authorizationError is shared/authorization_error_handler.js.
func (p *Provider) authorizationError(oc *oidcCtx, caught error) {
	err := caught
	oc.setStatus(statusOf(err))
	params := oc.params
	if params == nil {
		params = oc.query
		if oc.method == http.MethodPost {
			params = oc.body
		}
		if params == nil {
			params = core.NewObject()
		}
	}
	safe := func(name string) string {
		value, _ := params.Get(name).(string)
		return value
	}
	if oc.client == nil && safe("client_id") != "" && !oc.noClient {
		if client, findErr := p.findClient(oc.ctx, safe("client_id")); findErr == nil {
			oc.client = client
		}
	}
	if e, ok := asOIDC(err); (!ok || e.Class != "InvalidRedirectUri") && oc.client != nil && !oc.redirectURIChecked {
		if safe("redirect_uri") == "" {
			if uris := oc.client.redirectURIs(); len(uris) == 1 {
				oc.redirectURIChecked = true
				params.Set("redirect_uri", uris[0])
			}
		}
		if safe("redirect_uri") != "" && !oc.client.redirectURIAllowed(safe("redirect_uri")) {
			err = errInvalidRedirectURI()
			oc.setStatus(400)
		}
	}
	state := safe("state")
	out := errOut(err, state, state != "")
	pairs := out.object()
	pairs.add("iss", p.issuer)
	allowRedirect := true
	if e, ok := asOIDC(err); ok {
		allowRedirect = e.AllowRedirect
	}
	if safe("client_id") == "" || oc.client == nil || safe("redirect_uri") == "" || !allowRedirect {
		oc.renderError(out)
		return
	}
	mode := safe("response_mode")
	if !contains(responseModesHandled, mode) {
		mode = resolveResponseMode(safe("response_type"))
	}
	p.respondWithMode(oc, mode, safe("redirect_uri"), pairs)
}

// respondWithMode delivers authorization response parameters (response_modes/*.js).
func (p *Provider) respondWithMode(oc *oidcCtx, mode, redirectURI string, pairs *orderedPairs) {
	switch mode {
	case "form_post":
		oc.formPost(redirectURI, pairs.items)
	case "fragment":
		target, err := parseURL(redirectURI)
		if err != nil {
			oc.setStatus(500)
			oc.setJSON(outObject(errOut(err, "", false)))
			return
		}
		copy := *target.URL
		copy.Fragment, copy.RawFragment = "", formEncode(pairs.items)
		oc.redirect(copy.String())
	default:
		target, err := parseURL(redirectURI)
		if err != nil {
			oc.setStatus(500)
			oc.setJSON(outObject(errOut(err, "", false)))
			return
		}
		params := newSearchParams(target.RawQuery)
		for _, pair := range pairs.items {
			params.set(pair[0], pair[1])
		}
		copy := *target.URL
		copy.RawQuery = params.String()
		oc.redirect(copy.String())
	}
}

func (p *Provider) rejectUnsupported(oc *oidcCtx) error {
	if oc.hasParam("request") {
		return errRequestNotSupported()
	}
	if oc.hasParam("request_uri") && oc.route != "authorization" {
		return errRequestURINotSupp()
	}
	return nil
}

// checkClient is actions/authorization/client.js checkClient.
func (p *Provider) checkClient(oc *oidcCtx) error {
	if err := oc.presence("client_id"); err != nil {
		return err
	}
	client, err := p.findClient(oc.ctx, jsString(oc.params.Get("client_id")))
	if err != nil {
		return err
	}
	if client == nil {
		oc.noClient = true
		return errInvalidClient("client is invalid")
	}
	return oc.assignClient(client)
}

// loadPushedAuthorizationRequest loads a pushed request named by request_uri.
func (p *Provider) loadPushedAuthorizationRequest(oc *oidcCtx) error {
	if oc.hasParam("request") && oc.hasParam("request_uri") {
		return errInvalidRequest("request and request_uri parameters MUST NOT be used together")
	}
	if !oc.hasParam("request_uri") {
		return nil
	}
	uri := jsString(oc.params.Get("request_uri"))
	if !strings.HasPrefix(uri, pushedRequestURN) {
		return errRequestURINotSupp()
	}
	if !canParseURL(uri) {
		return errInvalidRequestURI("invalid request_uri")
	}
	id := strings.SplitN(uri, pushedRequestURN, 2)[1]
	if index := strings.Index(id, pushedRequestURN); index >= 0 {
		id = id[:index]
	}
	request, err := p.find(oc.ctx, "PushedAuthorizationRequest", id, true)
	if err != nil {
		return err
	}
	if request == nil || truthy(request.get("consumed")) || request.isExpired(p.now()) {
		return errInvalidRequestURI("request_uri is invalid, expired, or was already used")
	}
	oc.par = request
	oc.params.Set("request", request.get("request"))
	return nil
}

// decodeUnsecured is helpers/jwt.js decode: the header and payload of a compact JWT.
func decodeUnsecured(token string) (*core.Object, *core.Object, error) {
	header, err := joseDecodeProtectedHeader(token)
	if err != nil {
		return nil, nil, err
	}
	payload, err := joseDecodePayload(token)
	if err != nil {
		return nil, nil, err
	}
	return header, payload, nil
}

// processRequestObject handles the request object of a pushed authorization request.
func (p *Provider) processRequestObject(oc *oidcCtx) error {
	pushed := oc.par != nil
	if oc.client.requirePAR() && oc.route == "authorization" && !pushed {
		return errInvalidRequest("Pushed Authorization Request must be used")
	}
	if !oc.hasParam("request") {
		return nil
	}
	_, payload, err := decodeUnsecured(jsString(oc.params.Get("request")))
	if err != nil {
		return errInvalidRequestObject("could not parse Request Object")
	}
	allow := oc.allowList
	request := core.NewObject()
	payload.Entries(func(key string, value any) bool {
		if !contains(allow, key) {
			return true
		}
		switch v := value.(type) {
		case []any:
			request.Set(key, v)
		case string:
			request.Set(key, v)
		default:
			if key == "claims" {
				request.Set(key, stringify(v))
			} else {
				request.Set(key, jsString(v))
			}
		}
		return true
	})
	saved := oc.params
	oc.params = request
	err = oc.rejectDupes([]string{"resource"}, nil)
	oc.params = saved
	if err != nil {
		return err
	}
	original := map[string]any{}
	for _, name := range []string{"state", "response_mode", "response_type"} {
		original[name] = oc.params.Get(name)
		if value := request.Get(name); !isUndefined(value) {
			oc.params.Set(name, value)
		}
	}
	if !isUndefined(request.Get("request")) || !isUndefined(request.Get("request_uri")) {
		return errInvalidRequestObject("Request Object must not contain request or request_uri properties")
	}
	if truthy(original["response_type"]) && !isUndefined(request.Get("response_type")) && !jsEq(request.Get("response_type"), original["response_type"]) {
		return errInvalidRequestObject("request response_type must equal the one in request parameters")
	}
	if truthy(oc.params.Get("client_id")) && !isUndefined(request.Get("client_id")) && !jsEq(request.Get("client_id"), oc.params.Get("client_id")) {
		return errInvalidRequestObject("request client_id must equal the one in request parameters")
	}
	if oc.route == "pushed_authorization_request" && !jsEq(request.Get("client_id"), oc.client.clientID()) {
		return errInvalidRequestObject("request client_id must equal the authenticated client's client_id")
	}
	if !isUndefined(request.Get("client_id")) && !jsEq(request.Get("client_id"), oc.client.clientID()) {
		return errInvalidRequestObject("request client_id mismatch")
	}
	if !pushed {
		return errInvalidRequestObject("unsupported signed request alg")
	}
	if !p.assertRequestObject(payload, oc.client.clientID()) {
		return errInvalidRequestObject("Request Object claims are invalid")
	}
	if trusted, ok := oc.par.get("trusted").(bool); ok && trusted {
		oc.trusted = request.Keys()
	}
	oc.params.Set("request", core.Undefined)
	for _, key := range oc.params.Keys() {
		if request.Has(key) {
			value := request.Get(key)
			if !truthy(value) {
				value = core.Undefined
			}
			oc.params.Set(key, value)
		} else {
			oc.params.Set(key, core.Undefined)
		}
	}
	if jkt := oc.par.str("dpopJkt"); jkt != "" {
		oc.params.Set("dpop_jkt", jkt)
		if oc.trusted != nil {
			oc.trusted = append(oc.trusted, "dpop_jkt")
		}
	}
	return nil
}

// assertRequestObject is JWT.assertPayload(payload, { issuer: clientId, audience: issuer, clockTolerance: 15 }).
func (p *Provider) assertRequestObject(payload *core.Object, clientID string) bool {
	if !p.assertPayload(payload, false) {
		return false
	}
	switch aud := payload.Get("aud").(type) {
	case string:
		if aud != p.issuer {
			return false
		}
	case []any:
		if !contains(stringList(aud), p.issuer) {
			return false
		}
	default:
		return false
	}
	return jsEq(payload.Get("iss"), clientID)
}

func (p *Provider) checkResponseMode(oc *oidcCtx) error {
	mode := oc.responseMode()
	if mode != "" && !contains(responseModesHandled, mode) {
		oc.params.Set("response_mode", core.Undefined)
		return errUnsupportedRespMode()
	}
	if mode == "query" && resolveResponseMode(jsString(oc.params.Get("response_type"))) == "fragment" && !isUndefined(oc.params.Get("response_type")) {
		return errInvalidRequest("requested response_mode is not allowed for the requested response_type")
	}
	return nil
}

func (p *Provider) oneRedirectURIClients(oc *oidcCtx) {
	if isUndefined(oc.params.Get("redirect_uri")) {
		if uris := oc.client.redirectURIs(); len(uris) == 1 {
			oc.redirectURIChecked = true
			oc.params.Set("redirect_uri", uris[0])
		}
	}
}

func (p *Provider) checkResponseType(oc *oidcCtx) error {
	normalized := strings.Join(sortedStrings(unique(strings.Split(jsString(oc.params.Get("response_type")), " "))), " ")
	oc.params.Set("response_type", normalized)
	if normalized != "code" {
		return errUnsupportedRespType()
	}
	if !oc.client.responseTypeAllowed(normalized) {
		return errInvalidRequest("requested response_type is not allowed for this client")
	}
	return nil
}

func (p *Provider) assignDefaults(oc *oidcCtx) {
	if !truthy(oc.params.Get("acr_values")) {
		if values := oc.client.defaultAcrValues(); len(values) > 0 {
			oc.params.Set("acr_values", strings.Join(values, " "))
		}
	}
	if isUndefined(oc.params.Get("max_age")) {
		if value, ok := oc.client.defaultMaxAge(); ok {
			oc.params.Set("max_age", core.NumberString(value))
		}
	}
}

func (p *Provider) checkPrompt(oc *oidcCtx) error {
	if isUndefined(oc.params.Get("prompt")) {
		return nil
	}
	prompts := oc.prompts()
	for _, prompt := range prompts {
		if prompt != "none" && prompt != "login" && prompt != "consent" {
			return errInvalidRequest("unsupported prompt value requested")
		}
	}
	if contains(prompts, "none") && len(prompts) != 1 {
		return errInvalidRequest("prompt none must only be used alone")
	}
	return nil
}

// checkScope is actions/authorization/scopes.js checkScope.
func (p *Provider) checkScope(oc *oidcCtx) error {
	if !validScope(oc.params.Get("scope")) {
		return errInvalidScope("scope contains invalid characters", "")
	}
	scopes := oc.requestParamScopes()
	if contains(scopes, "offline_access") {
		frontChannelChecks := oc.route != "device_authorization" && oc.route != "code_verification" && oc.route != "device_resume"
		if (frontChannelChecks && !strings.Contains(jsString(oc.params.Get("response_type")), "code")) ||
			(frontChannelChecks && !contains(oc.prompts(), "consent")) || !oc.client.grantTypeAllowed("refresh_token") {
			filtered := []string{}
			removed := false
			for _, scope := range scopes {
				if scope == "offline_access" && !removed {
					removed = true
					continue
				}
				filtered = append(filtered, scope)
			}
			scopes = filtered
		}
	}
	if len(scopes) > 0 {
		oc.params.Set("scope", strings.Join(scopes, " "))
	} else {
		oc.params.Set("scope", core.Undefined)
	}
	if clientScope := oc.client.scope(); clientScope != "" {
		allow := strings.Split(clientScope, " ")
		for _, scope := range scopes {
			if contains(p.supportedScopes, scope) && !contains(allow, scope) {
				return errInvalidScope("requested scope is not allowed", scope)
			}
		}
	}
	return nil
}

func (p *Provider) checkOpenIDScope(oc *oidcCtx) error {
	if contains(oc.requestParamScopes(), "openid") {
		return nil
	}
	if contains(oc.allowList, "response_type") && strings.Contains(oc.param("response_type"), "id_token") {
		return errInvalidRequest("openid scope must be requested for this response_type")
	}
	if len(oc.client.defaultAcrValues()) > 0 {
		return errInvalidRequest("openid scope must be requested for clients with default_acr_values")
	}
	if _, ok := oc.client.defaultMaxAge(); ok {
		return errInvalidRequest("openid scope must be requested for clients with default_max_age")
	}
	if oc.client.requireAuthTime() {
		return errInvalidRequest("openid scope must be requested for clients with require_auth_time")
	}
	for _, name := range []string{"acr_values", "claims", "claims_locales", "id_token_hint", "max_age", "nonce"} {
		if oc.params.Has(name) && !isUndefined(oc.params.Get(name)) {
			return errInvalidRequest("openid scope must be requested when using the " + name + " parameter")
		}
	}
	return nil
}

var pkceCharacters = regexp.MustCompile(`[^\w.\-~]`)

func pkceFormat(input, name string) error {
	if len(input) < 43 {
		return errInvalidRequest(name + " must be a string with a minimum length of 43 characters")
	}
	if len(input) > 128 {
		return errInvalidRequest(name + " must be a string with a maximum length of 128 characters")
	}
	if pkceCharacters.MatchString(input) {
		return errInvalidRequest(name + " contains invalid characters")
	}
	return nil
}

func checkPKCEParams(oc *oidcCtx) error {
	method, challenge := oc.params.Get("code_challenge_method"), oc.params.Get("code_challenge")
	if isUndefined(method) && !isUndefined(challenge) {
		return errInvalidRequest("code_challenge_method must be provided")
	}
	if !isUndefined(method) {
		if method != "S256" {
			return errInvalidRequest("not supported value of code_challenge_method")
		}
		if isUndefined(challenge) {
			return errInvalidRequest("code_challenge must be provided with code_challenge_method")
		}
	}
	if strings.Contains(jsString(oc.params.Get("response_type")), "code") && isUndefined(challenge) {
		return errInvalidRequest("Authorization Server policy requires PKCE to be used for this request")
	}
	if !isUndefined(challenge) {
		return pkceFormat(jsString(challenge), "code_challenge")
	}
	return nil
}

// checkResource is shared/check_resource.js resolveRequestedResources.
func (p *Provider) checkResource(oc *oidcCtx) error {
	resource := oc.params.Get("resource")
	empty := !truthy(resource)
	if list, ok := resource.([]any); ok && len(list) == 0 {
		empty = true
	}
	if truthy(oc.params.Get("scope")) && empty {
		oc.params.Set("scope", strings.Join(oc.requestParamOIDCScopes(), " "))
		return nil
	}
	if isUndefined(resource) {
		return nil
	}
	identifiers := []string{}
	switch value := resource.(type) {
	case []any:
		for _, item := range value {
			identifiers = append(identifiers, jsString(item))
		}
	default:
		identifiers = append(identifiers, jsString(value))
	}
	for _, identifier := range identifiers {
		parsed, err := parseURL(identifier)
		if err != nil {
			return errInvalidTarget("resource indicator must be an absolute URI")
		}
		if strings.Contains(parsed.Href, "#") {
			return errInvalidTarget("resource indicator must not contain a fragment component")
		}
		server, err := p.resourceServerInfo(oc, identifier, oc.client)
		if err != nil {
			return err
		}
		oc.addResourceServer(server)
	}
	return nil
}

func (oc *oidcCtx) addResourceServer(server *resourceServerInfo) {
	for index, existing := range oc.resourceServers {
		if existing.identifier == server.identifier {
			oc.resourceServers[index] = server
			return
		}
	}
	oc.resourceServers = append(oc.resourceServers, server)
}

func (oc *oidcCtx) resourceServer(identifier string) *resourceServerInfo {
	for _, server := range oc.resourceServers {
		if server.identifier == identifier {
			return server
		}
	}
	return nil
}

// resourceServerInfo is the configured getResourceServerInfo.
func (p *Provider) resourceServerInfo(oc *oidcCtx, indicator string, client *oidcClient) (*resourceServerInfo, error) {
	server, ok := p.resourceServers[indicator]
	row, err := p.config.Store.Get(oc.ctx, "oauthClients", hash(client.clientID()))
	if err != nil {
		return nil, err
	}
	if !ok || row == nil || !contains(stringList(row.Get("resources")), indicator) {
		return nil, errInvalidTarget("The client may not request this resource.")
	}
	info := &resourceServerInfo{identifier: indicator, scope: strings.Join(server.Scopes, " "), audience: server.Audience,
		accessTokenTTL: 900, format: server.AccessTokenFormat}
	if info.audience == "" {
		info.audience = indicator
	}
	if server.AccessTokenTTL != nil {
		info.accessTokenTTL = *server.AccessTokenTTL
	}
	if info.format == "" {
		info.format = "jwt"
	}
	return info, nil
}

func (p *Provider) checkMaxAge(oc *oidcCtx) error {
	value := oc.params.Get("max_age")
	if isUndefined(value) {
		return nil
	}
	maxAge := jsNumberValue(value)
	if !isSafeInteger(maxAge) || maxAge < 0 {
		return errInvalidRequest("invalid max_age parameter value")
	}
	if maxAge == 0 {
		oc.params.Set("max_age", core.Undefined)
		prompts := oc.prompts()
		if !contains(prompts, "login") {
			prompts = append(prompts, "login")
			oc.params.Set("prompt", strings.Join(prompts, " "))
		}
	}
	return nil
}

// jsNumberValue is +value.
func jsNumberValue(value any) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case string:
		trimmed := core.JSTrim(v)
		if trimmed == "" {
			return 0
		}
		number, err := strconv.ParseFloat(trimmed, 64)
		if err != nil {
			if strings.HasPrefix(trimmed, "0x") || strings.HasPrefix(trimmed, "0X") {
				if parsed, err := strconv.ParseInt(trimmed[2:], 16, 64); err == nil {
					return float64(parsed)
				}
			}
			return math.NaN()
		}
		return number
	case []any:
		if len(v) == 0 {
			return 0
		}
		if len(v) == 1 {
			return jsNumberValue(jsString(v[0]))
		}
	}
	return math.NaN()
}

// checkIDTokenHint validates id_token_hint (IdToken.validate).
func (p *Provider) checkIDTokenHint(oc *oidcCtx) error {
	hint := oc.params.Get("id_token_hint")
	if isUndefined(hint) {
		return nil
	}
	payload, err := p.validateIDToken(oc, jsString(hint), oc.client)
	if err != nil {
		return errInvalidRequest("could not validate id_token_hint")
	}
	oc.idTokenHint = payload
	return nil
}

func (p *Provider) assignClaims(oc *oidcCtx) {
	oc.claims = core.NewObject()
	idToken := func() *core.Object {
		container := obj(oc.claims, "id_token")
		if container == nil {
			container = core.NewObject()
			oc.claims.Set("id_token", container)
		}
		return container
	}
	if !isUndefined(oc.params.Get("max_age")) || oc.client.requireAuthTime() || contains(oc.prompts(), "login") {
		idToken().Set("auth_time", core.NewObject("essential", true))
	}
	if acr := oc.param("acr_values"); acr != "" {
		idToken().Set("acr", core.NewObject("values", anyList(strings.Split(acr, " "))))
	}
}

// loadAccountAndGrant is actions/authorization/session.js loadAccount + loadGrant.
func (p *Provider) loadAccountAndGrant(oc *oidcCtx) error {
	accountID := oc.session.str("accountId")
	if accountID == "" {
		return nil
	}
	account, err := p.findAccount(oc, accountID)
	if err != nil {
		return err
	}
	oc.account = account
	if account == nil {
		return nil
	}
	grantID := ""
	if consent := obj(oc.result, "consent"); consent != nil {
		grantID = truthyString(consent.Get("grantId"))
	}
	if grantID == "" {
		grantID = sessionGrantID(oc.session, oc.client.clientID())
	}
	var grant *model
	if grantID != "" {
		if grant, err = p.find(oc.ctx, "Grant", grantID, false); err != nil {
			return err
		}
	}
	if grant != nil {
		if grant.str("accountId") != account.id {
			return errors.New("accountId mismatch")
		}
		if grant.str("clientId") != oc.client.clientID() {
			return errors.New("clientId mismatch")
		}
		clientID := jsString(oc.params.Get("client_id"))
		ensureClientContainer(oc.session, clientID)
		setSessionGrantID(oc.session, clientID, grant.jti())
	} else {
		grant = newModel("Grant", "accountId", account.id, "clientId", oc.client.clientID())
	}
	oc.grant = grant
	return nil
}

type promptResult struct {
	name    string
	reasons []string
	details *core.Object
	err     *OIDCError
}

// interactions is actions/authorization/interactions.js: the login and consent policy.
func (p *Provider) interactions(oc *oidcCtx) (bool, error) {
	prompt := p.loginPrompt(oc)
	if prompt == nil {
		prompt = p.consentPrompt(oc)
	}
	if prompt == nil {
		if oc.session.str("accountId") == "" {
			return false, errAccessDenied()
		}
		if grantOIDCScopeFiltered(oc.grant.data, oc.requestParamOIDCScopes()) == "" {
			anyResource := false
			for _, server := range oc.resourceServers {
				if grantResourceScopeFiltered(oc.grant.data, server.identifier, oc.requestParamScopes()) != "" {
					anyResource = true
				}
			}
			if !anyResource {
				return false, errAccessDenied()
			}
		}
		return false, nil
	}
	if oc.promptPending("none") {
		e := errByCode(prompt.err.Code, prompt.err.Description)
		code := 303
		if strings.HasPrefix(oc.route, "code_") || strings.HasPrefix(oc.route, "device_") {
			code = 400
		}
		e.Status, e.Expose = code, true
		return false, e
	}
	uid := nanoid(43)
	resumeRoute := "resume"
	if strings.HasPrefix(oc.route, "code_") || strings.HasPrefix(oc.route, "device_") {
		resumeRoute = "device_resume"
	}
	returnTo := oc.urlFor(resumeRoute, map[string]string{"uid": uid}, nil)
	promptObject := core.NewObject("name", prompt.name, "reasons", anyList(prompt.reasons), "details", prompt.details)
	interaction := newModel("Interaction", "jti", uid, "returnTo", returnTo, "prompt", promptObject)
	if oc.result != nil {
		interaction.set("lastSubmission", oc.result)
	} else {
		interaction.set("lastSubmission", core.Undefined)
	}
	interaction.set("params", oc.plainParams())
	if oc.trusted != nil {
		interaction.set("trusted", anyList(oc.trusted))
	} else {
		interaction.set("trusted", core.Undefined)
	}
	if accountID := oc.session.str("accountId"); accountID != "" {
		session := core.NewObject("accountId", accountID)
		if uid := oc.session.str("uid"); uid != "" {
			session.Set("uid", uid)
		}
		if jti := oc.session.jti(); jti != "" {
			session.Set("cookie", jti)
		}
		if acr := oc.session.get("acr"); truthy(acr) {
			session.Set("acr", acr)
		}
		if amr := oc.session.get("amr"); truthy(amr) {
			session.Set("amr", amr)
		}
		interaction.set("session", session)
	} else {
		interaction.set("session", core.Undefined)
	}
	cid := ""
	if oc.interaction != nil {
		cid = oc.interaction.str("cid")
	}
	if cid == "" {
		cid = nanoid(43)
	}
	interaction.set("cid", cid)
	if oc.deviceCode != nil {
		interaction.set("deviceCode", oc.deviceCode.jti())
	}
	parJTI := ""
	if oc.par != nil {
		parJTI = oc.par.jti()
	} else if oc.interaction != nil {
		parJTI = oc.interaction.str("parJti")
	}
	if parJTI != "" {
		interaction.set("parJti", parJTI)
	}
	if oc.grant != nil && oc.grant.jti() != "" {
		interaction.set("grantId", oc.grant.jti())
	}
	interaction.data.Delete("kind")
	interaction.data.Delete("jti")
	interaction.set("kind", "Interaction")
	interaction.set("jti", uid)
	if _, err := p.save(oc.ctx, oc, interaction, 600); err != nil {
		return false, err
	}
	oc.interaction = interaction
	destination := p.config.InteractionURL(uid)
	destinationPath := "/"
	if base, err := parseURL(p.issuer); err == nil {
		if target, err := base.URL.Parse(destination); err == nil {
			if parsed, err := parseURL(target.String()); err == nil {
				destinationPath = urlPathname(parsed)
			}
		}
	}
	if err := oc.setCookie("_interaction", uid, p.shortCookie(destinationPath, 600*1000)); err != nil {
		return false, err
	}
	resumePath := "/"
	if parsed, err := parseURL(returnTo); err == nil {
		resumePath = urlPathname(parsed)
	}
	if err := oc.setCookie("_interaction_resume", uid, p.shortCookie(resumePath, 600*1000)); err != nil {
		return false, err
	}
	oc.redirect(destination)
	return true, nil
}

func (p *Provider) loginPrompt(oc *oidcCtx) *promptResult {
	details := core.NewObject()
	if value := oc.params.Get("max_age"); !isUndefined(value) {
		details.Set("max_age", value)
	}
	if value := oc.params.Get("login_hint"); !isUndefined(value) {
		details.Set("login_hint", value)
	}
	if value := oc.params.Get("id_token_hint"); !isUndefined(value) {
		details.Set("id_token_hint", value)
	}
	var reasons []string
	first := ""
	add := func(reason, description string) {
		reasons = append(reasons, reason)
		if first == "" {
			first = description
		}
	}
	accountID := oc.session.str("accountId")
	if contains(oc.prompts(), "login") && oc.promptPending("login") {
		add("login_prompt", "login prompt was not resolved")
	}
	if accountID == "" {
		add("no_session", "End-User authentication is required")
	}
	if value := oc.params.Get("max_age"); !isUndefined(value) {
		if accountID == "" || (p.sessionPast(oc.session, jsNumberValue(value)) && obj(oc.result, "login") == nil) {
			add("max_age", "End-User authentication could not be obtained")
		}
	}
	if oc.idTokenHint != nil && (accountID == "" || !jsEq(oc.idTokenHint.Get("sub"), accountID)) {
		add("id_token_hint", "id_token_hint and authenticated subject do not match")
	}
	if len(reasons) == 0 {
		return nil
	}
	return &promptResult{name: "login", reasons: reasons, details: details, err: errCustom("login_required", first)}
}

func (p *Provider) consentPrompt(oc *oidcCtx) *promptResult {
	details := core.NewObject()
	var reasons []string
	var first *OIDCError
	add := func(reason, code, description string) {
		reasons = append(reasons, reason)
		if first == nil {
			first = errCustom(code, description)
		}
	}
	if contains(oc.prompts(), "consent") && oc.promptPending("consent") {
		add("consent_prompt", "consent_required", "consent prompt was not resolved")
	}
	if oc.client.applicationType() == "native" && oc.param("response_type") != "none" && obj(oc.result, "consent") == nil {
		add("native_client_prompt", "interaction_required", "native clients require End-User interaction")
	}
	encountered := grantOIDCScopeEncountered(oc.grant.data)
	var missingScope []string
	for _, scope := range oc.requestParamOIDCScopes() {
		if !contains(encountered, scope) {
			missingScope = append(missingScope, scope)
		}
	}
	if len(missingScope) > 0 {
		add("op_scopes_missing", "consent_required", "requested scopes not granted")
		details.Set("missingOIDCScope", anyList(missingScope))
	}
	missingResources := core.NewObject()
	for _, server := range oc.resourceServers {
		encounteredResource := grantResourceScopeEncountered(oc.grant.data, server.identifier)
		for _, scope := range oc.requestParamScopes() {
			if contains(server.scopes(), scope) && !contains(encounteredResource, scope) {
				list, _ := missingResources.Get(server.identifier).([]any)
				missingResources.Set(server.identifier, append(list, scope))
			}
		}
	}
	if missingResources.Len() > 0 {
		add("rs_scopes_missing", "consent_required", "requested scopes not granted")
		details.Set("missingResourceScopes", missingResources)
	}
	if len(reasons) == 0 {
		return nil
	}
	return &promptResult{name: "consent", reasons: reasons, details: details, err: first}
}

// respond is actions/authorization/respond.js: the code response.
func (p *Provider) respond(oc *oidcCtx) error {
	par := oc.par
	if par == nil && oc.interaction != nil && oc.interaction.str("parJti") != "" {
		found, err := p.find(oc.ctx, "PushedAuthorizationRequest", oc.interaction.str("parJti"), true)
		if err != nil {
			return err
		}
		par = found
	}
	if par != nil {
		if truthy(par.get("consumed")) {
			return errInvalidRequestURI("request_uri is invalid, expired, or was already used")
		}
		if err := p.consume(oc.ctx, par); err != nil {
			return err
		}
	}
	code, err := p.issueCode(oc)
	if err != nil {
		return err
	}
	pairs := &orderedPairs{}
	pairs.add("code", code)
	if state, ok := oc.params.Get("state").(string); ok {
		pairs.add("state", state)
	}
	mode := oc.responseMode()
	if !strings.Contains(mode, "jwt") {
		pairs.add("iss", p.issuer)
	}
	p.respondWithMode(oc, mode, oc.param("redirect_uri"), pairs)
	return nil
}

// combinedScope is helpers/combined_scope.js.
func combinedScope(grant *core.Object, requested []string, servers []*resourceServerInfo) []string {
	out := splitFilter(grantOIDCScopeFiltered(grant, requested))
	for _, server := range servers {
		out = append(out, splitFilter(grantResourceScopeFiltered(grant, server.identifier, requested))...)
	}
	return unique(out)
}

// issueCode is process_response_types.js codeHandler.
func (p *Provider) issueCode(oc *oidcCtx) (string, error) {
	clientID := oc.client.clientID()
	resources := make([]any, 0, len(oc.resourceServers))
	for _, server := range oc.resourceServers {
		resources = append(resources, server.identifier)
	}
	code := newModel("AuthorizationCode",
		"accountId", oc.session.get("accountId"),
		"acr", oc.session.get("acr"),
		"amr", oc.session.get("amr"),
		"authTime", oc.session.get("loginTs"),
		"claims", oc.claims,
		"codeChallenge", oc.params.Get("code_challenge"),
		"codeChallengeMethod", oc.params.Get("code_challenge_method"),
		"grantId", nonEmpty(sessionGrantID(oc.session, clientID)),
		"nonce", oc.params.Get("nonce"),
		"redirectUri", oc.params.Get("redirect_uri"),
		"resource", resources,
		"scope", strings.Join(combinedScope(oc.grant.data, oc.requestParamScopes(), oc.resourceServers), " "),
		"sessionUid", oc.session.get("uid"),
		"dpopJkt", oc.params.Get("dpop_jkt"),
	)
	code.setClient(oc.client)
	if claims := obj(code.data, "claims"); claims == nil || claims.Len() == 0 {
		code.data.Delete("claims")
	}
	switch len(resources) {
	case 0:
		code.data.Delete("resource")
	case 1:
		code.set("resource", resources[0])
	}
	if !code.hasScope("offline_access") {
		code.set("expiresWithSession", true)
	} else {
		sessionAuthorization(oc.session, clientID, true).Set("persistsLogout", true)
		oc.session.touched = true
	}
	if oc.client.includeSid() || hasIDTokenClaim(oc.claims, "sid") {
		code.set("sid", nonEmpty(sessionSid(oc.session, clientID)))
	}
	oc.authorizationCode = code
	return p.save(oc.ctx, oc, code, 0)
}

func hasIDTokenClaim(claims *core.Object, name string) bool {
	return obj(claims, "id_token") != nil && obj(claims, "id_token").Has(name)
}

// nonEmpty is a string or undefined.
func nonEmpty(value string) any {
	if value == "" {
		return core.Undefined
	}
	return value
}

// resumeInteraction is actions/authorization/resume.js. done is true when it answered the request itself.
func (p *Provider) resumeInteraction(oc *oidcCtx) (bool, error) {
	resumeRoute := "resume"
	if oc.route == "device_resume" {
		resumeRoute = "device_resume"
	}
	cookieID := oc.getCookie("_interaction_resume")
	if cookieID == "" {
		return false, errSessionNotFound("authorization request has expired")
	}
	interaction, err := p.find(oc.ctx, "Interaction", cookieID, false)
	if err != nil {
		return false, err
	}
	if interaction == nil {
		return false, errSessionNotFound("interaction session not found")
	}
	oc.interaction = interaction
	if cookieID != interaction.jti() {
		return false, errSessionNotFound("authorization session and cookie identifier mismatch")
	}
	result := obj(interaction.data, "result")
	storedParams := obj(interaction.data, "params")
	if storedParams == nil {
		storedParams = core.NewObject()
	}
	trusted := stringList(interaction.get("trusted"))
	origin := obj(interaction.data, "session")
	if uid := str(origin, "uid"); uid != "" && uid != oc.session.str("uid") {
		return false, errSessionNotFound("interaction session and authentication session mismatch")
	}
	if login := obj(result, "login"); login != nil && oc.session.str("accountId") != "" && !jsEq(oc.session.get("accountId"), login.Get("accountId")) {
		if origin != nil && truthy(origin.Get("uid")) {
			origin.Delete("uid")
			exp, _ := interaction.data.Get("exp").(float64)
			if _, err := p.save(oc.ctx, oc, interaction, int64(exp)-epoch(p.now())); err != nil {
				return false, err
			}
		}
		sessionSet(oc.session, "state", core.NewObject("secret", nanoid(43), "clientId", storedParams.Get("client_id"),
			"postLogoutRedirectUri", oc.urlFor(oc.route, oc.routeParams, nil)))
		oc.formPost(oc.urlFor("end_session_confirm", nil, nil), [][2]string{{"xsrf", str(obj(oc.session.data, "state"), "secret")}, {"logout", "yes"}})
		return true, nil
	}
	if err := p.destroy(oc.ctx, interaction); err != nil {
		return false, err
	}
	oc.query = storedParams
	saved := oc.method
	oc.method = http.MethodGet
	oc.assembleParams(authorizationParams(resumeRoute))
	oc.method = saved
	oc.trusted = trusted
	oc.redirectURIChecked = true
	resumePath := "/"
	if parsed, err := parseURL(oc.urlFor(resumeRoute, map[string]string{"uid": interaction.jti()}, nil)); err == nil {
		resumePath = urlPathname(parsed)
	}
	if err := oc.setCookie("_interaction_resume", "", p.shortCookie(resumePath, 0)); err != nil {
		return false, err
	}
	if result != nil && truthy(result.Get("error")) {
		return false, errByCode(jsString(result.Get("error")), nullishString(result.Get("error_description")))
	}
	if login := obj(result, "login"); login != nil {
		remember := true
		if value, ok := login.Get("remember").(bool); ok {
			remember = value
		}
		loginTs := login.Get("ts")
		if isUndefined(loginTs) {
			loginTs = epoch(p.now())
		}
		sessionSet(oc.session, "accountId", login.Get("accountId"))
		sessionSet(oc.session, "loginTs", loginTs)
		sessionSet(oc.session, "amr", login.Get("amr"))
		sessionSet(oc.session, "acr", login.Get("acr"))
		if !remember {
			sessionSet(oc.session, "transient", true)
		}
	}
	oc.result = result
	if !oc.session.isNew {
		oc.session.oldID = oc.session.jti()
		oc.session.data.Set("jti", nanoid(43))
		oc.session.touched = true
	}
	return false, nil
}
