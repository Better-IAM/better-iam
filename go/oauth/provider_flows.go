package oauth

// Pushed authorization requests, the device flow, RP-initiated logout, dynamic registration (with the tenant
// registration gate) and the interaction API the application's login and consent pages call.

import (
	"context"
	"crypto/rand"
	"errors"
	"net/http"
	"regexp"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// --- pushed authorization requests ------------------------------------------------------------------------------------

// clientAuthenticatedRoute runs the shared start of the PAR and device authorization endpoints.
func (p *Provider) clientAuthenticatedRoute(oc *oidcCtx) error {
	oc.noCache()
	if err := oc.parseBody("application/x-www-form-urlencoded"); err != nil {
		return err
	}
	oc.assembleParams(clientAuthParams)
	if err := p.authenticateClient(oc); err != nil {
		return err
	}
	if oc.route == "device_authorization" && !truthy(oc.body.Get("client_id")) {
		oc.body.Set("client_id", oc.client.clientID())
	}
	oc.assembleParams(authorizationParams(oc.route))
	if err := oc.rejectDupes([]string{"resource"}, nil); err != nil {
		return err
	}
	if err := p.rejectUnsupported(oc); err != nil {
		return err
	}
	if oc.route == "pushed_authorization_request" && truthy(oc.params.Get("request")) {
		for _, key := range oc.params.Keys() {
			if key != "client_id" && key != "request" && !isUndefined(oc.params.Get(key)) {
				oc.params.Set(key, core.Undefined)
			}
		}
	}
	authenticated := oc.client
	if err := p.checkClientIfNeeded(oc); err != nil {
		return err
	}
	oc.client = authenticated
	return nil
}

// checkClientIfNeeded is checkClient for the device route (PAR keeps the authenticated client).
func (p *Provider) checkClientIfNeeded(oc *oidcCtx) error {
	if oc.route != "device_authorization" {
		return nil
	}
	return p.checkClient(oc)
}

func (p *Provider) parEndpoint(oc *oidcCtx) error {
	if err := p.clientAuthenticatedRoute(oc); err != nil {
		return err
	}
	err := p.parSteps(oc)
	if e, ok := asOIDC(err); ok && e.Class == "InvalidRedirectUri" {
		e.Code = "invalid_request"
	}
	return err
}

func (p *Provider) parSteps(oc *oidcCtx) error {
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
	if err := oc.presence("redirect_uri"); err != nil {
		return err
	}
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
	if err := p.checkResource(oc); err != nil {
		return err
	}
	if err := p.checkMaxAge(oc); err != nil {
		return err
	}
	if err := p.checkIDTokenHint(oc); err != nil {
		return err
	}
	dpop, err := p.validateDPoP(oc, "")
	if err != nil {
		return err
	}
	if dpop != nil {
		if err := p.checkDPoPReplay(oc, dpop, oc.client.clientID(), func(message string) *OIDCError { return errInvalidRequest(message) }); err != nil {
			return err
		}
		if jkt := oc.param("dpop_jkt"); jkt != "" && jkt != dpop.thumbprint {
			return errInvalidRequest("DPoP proof key thumbprint does not match dpop_jkt")
		} else if jkt == "" {
			oc.params.Set("dpop_jkt", dpop.thumbprint)
		}
	}
	now := epoch(p.now())
	ttl := int64(60)
	var request string
	var dpopJKT any
	if body := oc.body.Get("request"); truthy(body) {
		request = jsString(body)
		_, payload, err := decodeUnsecured(request)
		if err != nil {
			return err
		}
		if exp, ok := payload.Get("exp").(float64); ok && exp == float64(int64(exp)) && int64(exp)-now <= 60 {
			ttl = int64(exp) - now
		}
		dpopJKT = payload.Get("dpop_jkt")
		if !truthy(dpopJKT) {
			dpopJKT = oc.params.Get("dpop_jkt")
		}
	} else {
		payload := oc.plainParams()
		if claims, ok := payload.Get("claims").(string); ok {
			if parsed, err := jsonParse(claims); err == nil {
				payload.Set("claims", parsed)
			} else {
				return err
			}
		}
		payload.Set("iat", now)
		payload.Set("iss", oc.client.clientID())
		payload.Set("aud", p.issuer)
		payload.Set("exp", now+60)
		payload.Set("nbf", now)
		request = b64url([]byte(`{"alg":"none"}`)) + "." + b64url(utf8Bytes(stringify(payload))) + "."
		dpopJKT = oc.params.Get("dpop_jkt")
	}
	trusted := oc.client.authMethod() != "none" || len(oc.trusted) > 0
	record := newModel("PushedAuthorizationRequest", "request", request, "dpopJkt", dpopJKT, "trusted", trusted)
	id, err := p.save(oc.ctx, oc, record, ttl)
	if err != nil {
		return err
	}
	oc.setStatus(201)
	oc.setJSON(core.NewObject("expires_in", ttl, "request_uri", pushedRequestURN+id))
	return nil
}

// --- the device flow --------------------------------------------------------------------------------------------------

const deviceCharset = "BCDFGHJKLMNPQRSTVWXZ"

// generateUserCode is helpers/user_codes.js generate('base-20', '****-****').
func generateUserCode() string {
	out := make([]byte, 0, 9)
	buffer := make([]byte, 1)
	for len(out) < 8 {
		_, _ = rand.Read(buffer)
		index := int(buffer[0] & 31)
		if index < len(deviceCharset) {
			out = append(out, deviceCharset[index])
		}
	}
	return string(out[:4]) + "-" + string(out[4:])
}

var nonWord = regexp.MustCompile(`\W`)

// normalizeUserCode is helpers/user_codes.js normalize.
func normalizeUserCode(input string) string {
	upper := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' {
			return r - 32
		}
		return r
	}, input)
	return nonWord.ReplaceAllString(upper, "")
}

func denormalizeUserCode(normalized string) string {
	chars := []rune(normalized)
	var out strings.Builder
	for _, mask := range "****-****" {
		if mask == '*' {
			if len(chars) > 0 {
				out.WriteRune(chars[0])
				chars = chars[1:]
			} else {
				out.WriteString("undefined")
			}
			continue
		}
		out.WriteRune(mask)
	}
	return out.String()
}

func userCodeInputForm(action, csrf, code string) string {
	value := ""
	if code != "" {
		value = `value="` + htmlSafe(code) + `" `
	}
	return `<form id="op.deviceInputForm" novalidate method="post" action="` + action + `">
  <input type="hidden" name="xsrf" value="` + csrf + `"/>
  <input
    ` + value + `type="text" name="user_code" placeholder="Enter code" onfocus="this.select(); this.onfocus = undefined;" autofocus autocomplete="off"></input>
  </form>`
}

func userCodeConfirmForm(action, csrf, code string) string {
	return `<form id="op.deviceConfirmForm" method="post" action="` + action + `">
<input type="hidden" name="xsrf" value="` + csrf + `"/>
<input type="hidden" name="user_code" value="` + htmlSafe(code) + `"/>
<input type="hidden" name="confirm" value="yes"/>
</form>`
}

func (p *Provider) deviceAuthorizationEndpoint(oc *oidcCtx) error {
	if err := p.clientAuthenticatedRoute(oc); err != nil {
		return err
	}
	if !oc.client.grantTypeAllowed(deviceCodeGrant) {
		return errInvalidRequest(deviceCodeGrant + " is not allowed for this client")
	}
	if err := p.processRequestObject(oc); err != nil {
		return err
	}
	if oc.hasParam("registration") {
		return errRegistrationNotSupp()
	}
	p.assignDefaults(oc)
	if err := p.checkScope(oc); err != nil {
		return err
	}
	if err := p.checkOpenIDScope(oc); err != nil {
		return err
	}
	if err := p.checkResource(oc); err != nil {
		return err
	}
	if err := p.checkMaxAge(oc); err != nil {
		return err
	}
	if err := p.checkIDTokenHint(oc); err != nil {
		return err
	}
	userCode := generateUserCode()
	deviceInfo := core.NewObject("ip", oc.ip(), "ua", nonEmpty(oc.r.Header.Get("user-agent")))
	code := newModel("DeviceCode", "deviceInfo", deviceInfo, "params", oc.plainParams(), "userCode", normalizeUserCode(userCode))
	code.setClient(oc.client)
	oc.deviceCode = code
	deviceCode, err := p.save(oc.ctx, oc, code, 0)
	if err != nil {
		return err
	}
	oc.setJSON(core.NewObject("device_code", deviceCode, "user_code", userCode,
		"verification_uri", oc.urlFor("code_verification", nil, nil),
		"verification_uri_complete", oc.urlFor("code_verification", nil, [][2]string{{"user_code", userCode}}),
		"expires_in", p.expiration(oc, code)))
	return nil
}

func (p *Provider) devicePage(oc *oidcCtx, input DevicePageInput) error {
	page, err := p.config.RenderDevicePage(oc.ctx, input)
	if err != nil {
		return err
	}
	oc.setHTML(page)
	return nil
}

func (p *Provider) codeVerificationEndpoint(oc *oidcCtx) error {
	if err := p.loadSession(oc); err != nil {
		return err
	}
	err := p.codeVerificationSteps(oc)
	if finishErr := p.finishSession(oc); finishErr != nil {
		return finishErr
	}
	return err
}

func (p *Provider) codeVerificationSteps(oc *oidcCtx) error {
	action := oc.urlFor("code_verification", nil, nil)
	if oc.method != http.MethodPost {
		oc.assembleParams([]string{"user_code"})
		oc.generateXsrf()
		secret := str(obj(oc.session.data, "state"), "secret")
		if userCode := oc.param("user_code"); userCode != "" {
			oc.formPost(action, [][2]string{{"xsrf", secret}, {"user_code", userCode}})
			return nil
		}
		return p.devicePage(oc, DevicePageInput{Kind: "input", Form: userCodeInputForm(action, secret, "")})
	}
	if err := oc.parseBody("application/x-www-form-urlencoded"); err != nil {
		return err
	}
	oc.assembleParams([]string{"xsrf", "user_code", "confirm", "abort"})
	if err := oc.rejectDupes(nil, nil); err != nil {
		return err
	}
	if err := oc.checkXsrf("could not find device form details"); err != nil {
		return err
	}
	userCode := oc.param("user_code")
	if userCode == "" {
		return rerenderError("NoCodeError", "no code submitted", "")
	}
	normalized := normalizeUserCode(userCode)
	stored, err := p.adapter.Model("DeviceCode").FindByUserCode(oc.ctx, normalized)
	if err != nil {
		return err
	}
	var code *model
	if stored != nil && p.assertPayload(stored, true) && constantEquals(normalized, str(stored, "userCode")) {
		code = &model{kind: "DeviceCode", data: stored}
	}
	if code == nil {
		return rerenderError("NotFoundError", "the code was not found", userCode)
	}
	if code.isExpired(p.now()) {
		return rerenderError("ExpiredError", "the code has expired", userCode)
	}
	if truthy(code.get("error")) || truthy(code.get("accountId")) || truthy(code.get("inFlight")) {
		return rerenderError("AlreadyUsedError", "code has already been used", userCode)
	}
	oc.deviceCode = code
	if truthy(oc.params.Get("abort")) {
		code.set("error", "access_denied")
		code.set("errorDescription", "End-User aborted interaction")
		if _, err := p.save(oc.ctx, oc, code, 0); err != nil {
			return err
		}
		return rerenderError("AbortedError", "the interaction was aborted", "")
	}
	if !truthy(oc.params.Get("confirm")) {
		client, err := p.findClient(oc.ctx, code.str("clientId"))
		if err != nil {
			return err
		}
		if client == nil {
			return errInvalidClient("client is invalid")
		}
		oc.client = client
		name := client.clientName()
		return p.devicePage(oc, DevicePageInput{Kind: "confirm", Form: userCodeConfirmForm(action, str(obj(oc.session.data, "state"), "secret"), userCode),
			UserCode: denormalizeUserCode(normalized), ClientName: name})
	}
	code.set("inFlight", true)
	if _, err := p.save(oc.ctx, oc, code, 0); err != nil {
		return err
	}
	sessionSet(oc.session, "state", core.Undefined)
	oc.noCache()
	return p.deviceUserFlow(oc, false)
}

func (p *Provider) deviceResumeEndpoint(oc *oidcCtx) error {
	oc.noCache()
	if err := p.loadSession(oc); err != nil {
		return err
	}
	err := p.deviceResumeSteps(oc)
	if finishErr := p.finishSession(oc); finishErr != nil {
		return finishErr
	}
	return err
}

func (p *Provider) deviceResumeSteps(oc *oidcCtx) error {
	err := func() error {
		done, err := p.resumeInteraction(oc)
		if err != nil || done {
			return err
		}
		return p.deviceUserFlow(oc, true)
	}()
	return p.deviceUserFlowErrors(oc, err)
}

// deviceUserFlowErrors records a failed device flow on its device code.
func (p *Provider) deviceUserFlowErrors(oc *oidcCtx, cause error) error {
	if cause == nil {
		return nil
	}
	if e, ok := asOIDC(cause); ok && e.rerender {
		return cause
	}
	out := errOut(cause, "", false)
	code := oc.deviceCode
	if code == nil && oc.interaction != nil && oc.interaction.str("deviceCode") != "" {
		found, err := p.findToken(oc.ctx, "DeviceCode", oc.interaction.str("deviceCode"), true, true)
		if err != nil {
			return err
		}
		code = found
	}
	if code != nil {
		code.set("error", out.Error)
		if out.HasDescription {
			code.set("errorDescription", out.Description)
		} else {
			code.set("errorDescription", core.Undefined)
		}
		if _, err := p.save(oc.ctx, oc, code, 0); err != nil {
			return err
		}
		if e, ok := asOIDC(cause); ok && e.Class == "AccessDenied" {
			return rerenderError("AbortedError", "the interaction was aborted", "")
		}
	}
	return cause
}

// deviceUserFlow continues a device authorization through the interaction policy to the success page.
func (p *Provider) deviceUserFlow(oc *oidcCtx, resume bool) error {
	run := func() error {
		if resume {
			code, err := p.findToken(oc.ctx, "DeviceCode", oc.interaction.str("deviceCode"), true, true)
			if err != nil {
				return err
			}
			if code == nil {
				return rerenderError("NotFoundError", "the code was not found", "")
			}
			if code.isExpired(p.now()) {
				return rerenderError("ExpiredError", "the code has expired", "")
			}
			if truthy(code.get("error")) || truthy(code.get("accountId")) {
				return rerenderError("AlreadyUsedError", "code has already been used", "")
			}
			oc.deviceCode = code
		} else {
			oc.query = obj(oc.deviceCode.data, "params")
			if oc.query == nil {
				oc.query = core.NewObject()
			}
			saved := oc.method
			oc.method = http.MethodGet
			oc.assembleParams(authorizationParams(oc.route))
			oc.method = saved
		}
		if err := p.checkClient(oc); err != nil {
			return err
		}
		if err := p.checkResource(oc); err != nil {
			return err
		}
		p.assignClaims(oc)
		if err := p.loadAccountAndGrant(oc); err != nil {
			return err
		}
		done, err := p.interactions(oc)
		if err != nil || done {
			return err
		}
		return p.deviceVerificationResponse(oc)
	}
	err := run()
	if resume {
		return err
	}
	return p.deviceUserFlowErrors(oc, err)
}

func (p *Provider) deviceVerificationResponse(oc *oidcCtx) error {
	code := oc.deviceCode
	clientID := oc.client.clientID()
	resources := make([]any, 0, len(oc.resourceServers))
	for _, server := range oc.resourceServers {
		resources = append(resources, server.identifier)
	}
	code.set("accountId", oc.session.get("accountId"))
	code.set("acr", oc.session.get("acr"))
	code.set("amr", oc.session.get("amr"))
	code.set("authTime", oc.session.get("loginTs"))
	code.set("claims", oc.claims)
	code.set("grantId", nonEmpty(sessionGrantID(oc.session, clientID)))
	code.set("scope", strings.Join(combinedScope(oc.grant.data, oc.requestParamScopes(), oc.resourceServers), " "))
	code.set("sessionUid", oc.session.get("uid"))
	code.set("resource", resources)
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
	if _, err := p.save(oc.ctx, oc, code, 0); err != nil {
		return err
	}
	return p.devicePage(oc, DevicePageInput{Kind: "success", Form: ""})
}

// --- RP-initiated logout ----------------------------------------------------------------------------------------------

func (p *Provider) endSessionInit(oc *oidcCtx) error {
	oc.noCache()
	if err := p.loadSession(oc); err != nil {
		return err
	}
	err := p.endSessionInitSteps(oc)
	if finishErr := p.finishSession(oc); finishErr != nil {
		return finishErr
	}
	return err
}

func (p *Provider) endSessionInitSteps(oc *oidcCtx) error {
	oc.assembleParams([]string{"id_token_hint", "post_logout_redirect_uri", "state", "ui_locales", "client_id", "logout_hint"})
	if err := oc.rejectDupes(nil, nil); err != nil {
		return err
	}
	var client *oidcClient
	if hint := oc.param("id_token_hint"); hint != "" {
		_, payload, err := decodeUnsecured(hint)
		if err != nil {
			return errInvalidRequest("could not decode id_token_hint")
		}
		clientID := jsString(payload.Get("aud"))
		if requested := oc.param("client_id"); requested != "" && requested != clientID {
			return errInvalidRequest("client_id does not match the provided id_token_hint")
		}
		client, err = p.findClient(oc.ctx, clientID)
		if err != nil {
			return err
		}
		if client == nil {
			return errInvalidClient("unrecognized id_token_hint audience")
		}
		if _, err := p.validateIDToken(oc, hint, client); err != nil {
			return errInvalidRequest("could not validate id_token_hint")
		}
		oc.client = client
	} else if clientID := oc.param("client_id"); clientID != "" {
		found, err := p.findClient(oc.ctx, clientID)
		if err != nil {
			return err
		}
		if found == nil {
			return errInvalidClient("client is invalid")
		}
		client = found
		oc.client = client
	}
	if client != nil && oc.hasParam("post_logout_redirect_uri") {
		if !client.postLogoutRedirectURIAllowed(oc.param("post_logout_redirect_uri")) {
			return errInvalidRequest("post_logout_redirect_uri not registered")
		}
	} else if oc.hasParam("post_logout_redirect_uri") {
		oc.params.Set("post_logout_redirect_uri", core.Undefined)
	}
	oc.generateXsrf()
	state := obj(oc.session.data, "state")
	secret := str(state, "secret")
	if client != nil {
		state.Set("clientId", client.clientID())
	} else {
		state.Set("clientId", core.Undefined)
	}
	state.Set("state", oc.params.Get("state"))
	state.Set("postLogoutRedirectUri", oc.params.Get("post_logout_redirect_uri"))
	action := oc.urlFor("end_session_confirm", nil, nil)
	if oc.session.str("accountId") != "" {
		oc.setStatus(200)
		form := `<form id="op.logoutForm" method="post" action="` + action + `"><input type="hidden" name="xsrf" value="` + secret + `"/></form>`
		page, err := p.config.RenderLogoutPage(oc.ctx, form)
		if err != nil {
			return err
		}
		oc.setHTML(page)
		return nil
	}
	oc.formPost(action, [][2]string{{"xsrf", secret}, {"logout", "yes"}})
	return nil
}

func (p *Provider) endSessionConfirm(oc *oidcCtx) error {
	oc.noCache()
	if err := p.loadSession(oc); err != nil {
		return err
	}
	err := p.endSessionConfirmSteps(oc)
	if finishErr := p.finishSession(oc); finishErr != nil {
		return finishErr
	}
	return err
}

func (p *Provider) clientForLogout(oc *oidcCtx, clientID string) (*oidcClient, error) {
	client, err := p.findClient(oc.ctx, clientID)
	if err != nil {
		if e, ok := asOIDC(err); ok && e.Class == "InvalidClient" {
			return nil, nil
		}
		return nil, err
	}
	return client, nil
}

func (p *Provider) endSessionConfirmSteps(oc *oidcCtx) error {
	if err := oc.parseBody("application/x-www-form-urlencoded"); err != nil {
		return err
	}
	oc.assembleParams([]string{"xsrf", "logout"})
	if err := oc.rejectDupes(nil, nil); err != nil {
		return err
	}
	if err := oc.checkXsrf("could not find logout details"); err != nil {
		return err
	}
	session := oc.session
	state := obj(session.data, "state")
	stateClientID := str(state, "clientId")
	logout := truthy(oc.params.Get("logout"))
	authorizations := obj(session.data, "authorizations")
	for _, clientID := range authorizations.Keys() {
		if !logout && clientID != stateClientID {
			continue
		}
		client, err := p.clientForLogout(oc, clientID)
		if err != nil {
			return err
		}
		if client != nil && client.backchannelLogoutURI() != "" {
			_ = p.backchannelLogout(oc.ctx, client, session.str("accountId"), sessionSid(session, client.clientID()))
		}
	}
	if stateClientID != "" {
		client, err := p.clientForLogout(oc, stateClientID)
		if err != nil {
			return err
		}
		oc.client = client
	}
	if logout {
		for _, clientID := range authorizations.Keys() {
			entry := obj(authorizations, clientID)
			if grantID := str(entry, "grantId"); grantID != "" && entry.Get("persistsLogout") != true {
				if err := p.revoke(oc, grantID); err != nil {
					return err
				}
			}
		}
		if err := p.destroy(oc.ctx, session); err != nil {
			return err
		}
		session.destroyed = true
		session.touched = false
		if err := oc.setCookie("_session", "", p.longCookie()); err != nil {
			return err
		}
	} else if stateClientID != "" {
		entry := obj(authorizations, stateClientID)
		if grantID := str(entry, "grantId"); grantID != "" && entry.Get("persistsLogout") != true {
			if err := p.revoke(oc, grantID); err != nil {
				return err
			}
		}
		sessionSet(session, "state", core.Undefined)
		if authorizations != nil {
			authorizations.Delete(stateClientID)
		}
		session.oldID = session.jti()
		session.data.Set("jti", nanoid(43))
		session.touched = true
	}
	postLogout := str(state, "postLogoutRedirectUri")
	forwardClientID := postLogout == "" && !logout && stateClientID != ""
	target := postLogout
	if target == "" {
		target = oc.urlFor("end_session_success", nil, nil)
	}
	parsed, err := parseURL(target)
	if err != nil {
		return err
	}
	params := newSearchParams(parsed.RawQuery)
	if postLogout != "" && state.Get("state") != nil && !isUndefined(state.Get("state")) {
		params.set("state", jsString(state.Get("state")))
	}
	if forwardClientID {
		params.set("client_id", stateClientID)
	}
	copy := *parsed.URL
	copy.RawQuery = params.String()
	oc.redirect(copy.String())
	return nil
}

func (p *Provider) endSessionSuccess(oc *oidcCtx) error {
	oc.noCache()
	oc.assembleParams([]string{"client_id"})
	if clientID := oc.param("client_id"); clientID != "" {
		client, err := p.findClient(oc.ctx, clientID)
		if err != nil {
			return err
		}
		if client == nil {
			return errInvalidClient("client is invalid")
		}
		oc.client = client
	}
	display := ""
	if oc.client != nil {
		name := oc.client.clientName()
		if name == "" {
			name = oc.client.clientID()
		}
		display = "with " + htmlSafe(name)
	}
	oc.setHTML(`<!DOCTYPE html>
    <html>
    <head>
      <meta http-equiv="X-UA-Compatible" content="IE=edge">
      <meta charset="utf-8">
      <title>Sign-out Success</title>
      <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">
      <style>
        @import url(https://fonts.googleapis.com/css?family=Roboto:400,100);h1,h1+p{font-weight:100;text-align:center}body{font-family:Roboto,sans-serif;margin-top:25px;margin-bottom:25px}.container{padding:0 40px 10px;width:274px;background-color:#F7F7F7;margin:0 auto 10px;border-radius:2px;box-shadow:0 2px 2px rgba(0,0,0,.3);overflow:hidden}h1{font-size:2.3em}
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Sign-out Success</h1>
        <p>Your sign-out ` + display + ` was successful.</p>
      </div>
    </body>
    </html>`)
	return nil
}

// --- dynamic registration ---------------------------------------------------------------------------------------------

var registrationBearer = regexp.MustCompile(`^Bearer ([A-Za-z0-9_-]{20,200})$`)

// registrationGate admits `POST /reg` only with a live tenant registration token or a request the anonymous hook
// maps to a tenant (installRegistrationGate). done is true when it refused the request.
func (p *Provider) registrationGate(oc *oidcCtx) (bool, error) {
	refuse := func(description string) (bool, error) {
		oc.setStatus(401)
		oc.header.Set("www-authenticate", `Bearer error="invalid_token"`)
		oc.header.Set("cache-control", "no-store")
		oc.setJSON(core.NewObject("error", "invalid_token", "error_description", description))
		return true, nil
	}
	header := oc.r.Header.Get("authorization")
	var context *registrationContext
	if header != "" {
		var record *core.Object
		if match := registrationBearer.FindStringSubmatch(header); match != nil {
			var err error
			if record, err = p.config.Store.Get(oc.ctx, "oauthRegistrationTokens", hash(match[1])); err != nil {
				return false, err
			}
		}
		if record == nil || !p.usableRegistrationToken(record) {
			return refuse("The registration token is invalid, expired, or used up.")
		}
		maxClients, _ := num(record, "maxClients")
		allowConfidential, _ := record.Get("allowConfidential").(bool)
		context = &registrationContext{tenantID: str(record, "tenantId"), scopes: stringList(record.Get("scopes")),
			resources: nonNil(stringList(record.Get("resources"))), allowConfidential: allowConfidential,
			maxClients: int64(maxClients), tokenID: str(record, "id"), actorID: str(record, "createdBy")}
	} else {
		var policy *RegistrationPolicy
		if p.config.Registration.Anonymous != nil {
			var err error
			if policy, err = p.config.Registration.Anonymous(oc.ctx, AnonymousRegistrationRequest{Headers: oc.r.Header.Clone(), IP: oc.ip()}); err != nil {
				return false, err
			}
		}
		if policy == nil {
			return refuse("Registration requires a registration token.")
		}
		normalized, err := p.registrationLimits(*policy)
		if err != nil {
			return false, err
		}
		normalized.actorID = "dynamic-registration"
		context = normalized
	}
	active, err := core.TenantTreeActive(oc.ctx, p.config.Store, context.tenantID)
	if err != nil {
		return false, err
	}
	if !active {
		return refuse("The tenant is unavailable.")
	}
	oc.registration = context
	oc.ctx = contextWithRegistration(oc.ctx, context)
	return false, nil
}

func contextWithRegistration(ctx context.Context, registering *registrationContext) context.Context {
	return context.WithValue(ctx, registrationKey{}, registering)
}

// isRegistrationPath matches the provider router's spellings of `/reg` (case, trailing slashes, escapes).
func isRegistrationPath(path string) bool {
	decoded, ok := decodeURIComponent(path)
	if !ok {
		decoded = path
	}
	return strings.TrimRight(strings.ToLower(decoded), "/") == "/reg"
}

func (p *Provider) registrationEndpoint(oc *oidcCtx) error {
	oc.noCache()
	if err := oc.parseBody("application/json"); err != nil {
		return err
	}
	if oc.body == nil || oc.bodyNotObject {
		return errInvalidRequest("client registration request must be a JSON object")
	}
	clientID := nanoid(43)
	properties := oc.body.Clone()
	properties.Set("client_id", clientID)
	properties.Set("client_id_issued_at", epoch(p.now()))
	if clientNeedsSecret(properties) {
		properties.Set("client_secret", randomB64URL(64))
		properties.Set("client_secret_expires_at", 0)
	} else {
		properties.Delete("client_secret")
		properties.Delete("client_secret_expires_at")
	}
	metadata, err := p.clientSchema(oc.ctx, properties)
	if err != nil {
		return err
	}
	if err := p.adapter.Model("Client").Upsert(oc.ctx, clientID, metadata, 0); err != nil {
		return err
	}
	oc.setStatus(201)
	oc.setJSON(metadata)
	return nil
}

func (p *Provider) clientReadEndpoint(oc *oidcCtx) error {
	oc.noCache()
	err := func() error {
		oc.params = core.NewObject()
		if _, err := oc.getAccessToken(false); err != nil {
			return err
		}
		return errInvalidToken("registration access token not found")
	}()
	if err != nil {
		return p.wwwAuthenticate(oc, err, true, false)
	}
	return nil
}

// --- the interaction API ----------------------------------------------------------------------------------------------

// interactionFromRequest is provider.#getInteraction: the pending interaction of the `_interaction` cookie.
func (p *Provider) interactionFromRequest(ctx context.Context, r *http.Request) (*model, error) {
	oc := &oidcCtx{p: p, ctx: ctx, r: r, header: http.Header{}}
	id := oc.getCookie("_interaction")
	if id == "" {
		return nil, errSessionNotFound("interaction session id cookie not found")
	}
	interaction, err := p.find(ctx, "Interaction", id, false)
	if err != nil {
		return nil, err
	}
	if interaction == nil {
		return nil, errSessionNotFound("interaction session not found")
	}
	if session := obj(interaction.data, "session"); session != nil && truthy(session.Get("uid")) {
		found, err := p.sessionByUID(ctx, str(session, "uid"))
		if err != nil {
			return nil, err
		}
		if found == nil {
			return nil, errSessionNotFound("session not found")
		}
		if !jsEq(session.Get("accountId"), found.get("accountId")) {
			return nil, errSessionNotFound("session principal changed")
		}
	}
	return interaction, nil
}

// InteractionClient is the consent screen's view of the client.
type InteractionClient struct {
	Name       string `json:"name"`
	LogoURI    string `json:"logoUri,omitempty"`
	ClientURI  string `json:"clientUri,omitempty"`
	PolicyURI  string `json:"policyUri,omitempty"`
	TosURI     string `json:"tosUri,omitempty"`
	FirstParty bool   `json:"firstParty"`
}

// InteractionDetails is the immutable tenant/client binding of a pending interaction.
type InteractionDetails struct {
	UID        string            `json:"uid"`
	Prompt     string            `json:"prompt"`
	TenantID   string            `json:"tenantId"`
	ClientID   string            `json:"clientId"`
	ClientName string            `json:"clientName"`
	Client     InteractionClient `json:"client"`
	Scopes     []string          `json:"scopes"`
	Resources  []string          `json:"resources"`
	Details    *core.Object      `json:"details"`
}

// InteractionDetails reads the pending interaction for the application's login and consent page.
func (p *Provider) InteractionDetails(ctx context.Context, r *http.Request) (*InteractionDetails, error) {
	interaction, err := p.interactionFromRequest(ctx, r)
	if err != nil {
		return nil, err
	}
	params := obj(interaction.data, "params")
	row, err := p.clientRow(ctx, jsString(get(params, "client_id")))
	if err != nil {
		return nil, err
	}
	summary, err := p.summary(row)
	if err != nil {
		return nil, err
	}
	scopes := []string{}
	if scope, ok := get(params, "scope").(string); ok {
		scopes = strings.Split(scope, " ")
	}
	resources := []string{}
	switch value := get(params, "resource").(type) {
	case []any:
		for _, item := range value {
			resources = append(resources, jsString(item))
		}
	case string:
		if value != "" {
			resources = []string{value}
		}
	}
	prompt := obj(interaction.data, "prompt")
	details := obj(prompt, "details")
	if details == nil {
		details = core.NewObject()
	}
	return &InteractionDetails{UID: interaction.jti(), Prompt: str(prompt, "name"), TenantID: str(row, "tenantId"),
		ClientID: str(row, "clientId"), ClientName: summary.Name,
		Client: InteractionClient{Name: summary.Name, LogoURI: summary.LogoURI, ClientURI: summary.ClientURI,
			PolicyURI: summary.PolicyURI, TosURI: summary.TosURI, FirstParty: summary.FirstParty},
		Scopes: scopes, Resources: resources, Details: details}, nil
}

// CompleteInteractionInput is what completeInteraction receives: an actual IAM credential and the consent decision.
type CompleteInteractionInput struct {
	Credential core.CredentialInput
	Consent    bool
}

// CompleteInteraction finishes a pending interaction for the signed-in person and redirects (303) back to the
// provider. No accountId or tenant is accepted from form data.
func (p *Provider) CompleteInteraction(ctx context.Context, w http.ResponseWriter, r *http.Request, input CompleteInteractionInput) error {
	origin := r.Header.Get("origin")
	if r.Method != http.MethodPost || origin == "" || !contains(p.config.TrustedOrigins, origin) {
		return core.NewIamError("CSRF", "A trusted Origin is required.", 403)
	}
	var returnTo string
	err := p.config.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		principal, err := p.config.Authenticate(ctx, input.Credential)
		if err != nil {
			return err
		}
		if str(principal.Session, "kind") != "user" {
			return core.NewIamError("INVALID_SESSION", "A user session is required.", 403)
		}
		if truthy(principal.Session.Get("impersonatorId")) {
			return core.NewIamError("IMPERSONATION_RESTRICTED", "Consent cannot be granted while impersonating a member.", 403)
		}
		interaction, err := p.interactionFromRequest(ctx, r)
		if err != nil {
			return err
		}
		params := obj(interaction.data, "params")
		client, err := p.clientRow(ctx, jsString(get(params, "client_id")))
		if err != nil {
			return err
		}
		if str(client, "tenantId") != str(principal.Identity, "tenantId") {
			return core.NewIamError("TENANT_MISMATCH", "Sign in to the client tenant before continuing.", 403)
		}
		if !input.Consent {
			returnTo, err = p.interactionResult(ctx, interaction, core.NewObject("error", "access_denied", "error_description", "Consent denied."))
			return err
		}
		// The provider takes any login result as fresh, so `prompt=login` and `max_age` are judged here against the
		// session's own sign-in time.
		authenticatedAt, _ := num(principal.Session, "authenticatedAt")
		var maxAge *float64
		switch value := get(params, "max_age").(type) {
		case string, float64:
			number := jsNumberValue(value)
			maxAge = &number
		}
		started := float64(p.now())
		if iat, ok := interaction.data.Get("iat").(float64); ok {
			started = (iat + 1) * 1000
		}
		prompts := strings.Split(nullishString(get(params, "prompt")), " ")
		if (maxAge != nil && !isNaNOrInf(*maxAge) && float64(p.now())-authenticatedAt > *maxAge*1000) ||
			(contains(prompts, "login") && authenticatedAt < started) {
			return core.NewIamError("LOGIN_REQUIRED", "The application asked for a fresh sign-in: sign in again, then continue.", 401)
		}
		// Extend the account's existing consent for this client instead of accumulating grants.
		var grant *model
		if grantID := interaction.str("grantId"); grantID != "" {
			if grant, err = p.find(ctx, "Grant", grantID, false); err != nil {
				return err
			}
		}
		identityID := str(principal.Identity, "id")
		if grant == nil || grant.str("accountId") != identityID || grant.str("clientId") != str(client, "clientId") {
			grant = newModel("Grant", "accountId", identityID, "clientId", str(client, "clientId"))
		}
		scope := "openid"
		if value := get(params, "scope"); !isUndefined(value) && value != nil {
			scope = jsString(value)
		}
		addOIDCScope(grant.data, scope)
		details := obj(obj(interaction.data, "prompt"), "details")
		if missing, ok := get(details, "missingOIDCClaims").([]any); ok {
			addOIDCClaims(grant.data, stringList(missing))
		}
		// Requested resources receive the requested scopes their resource server defines.
		requestedScopes := strings.Split(nullishString(get(params, "scope")), " ")
		var indicators []string
		switch value := get(params, "resource").(type) {
		case []any:
			for _, item := range value {
				indicators = append(indicators, jsString(item))
			}
		case string:
			if value != "" {
				indicators = []string{value}
			}
		}
		for _, indicator := range indicators {
			server, ok := p.resourceServers[indicator]
			var scopes []string
			if ok {
				for _, item := range server.Scopes {
					if contains(requestedScopes, item) {
						scopes = append(scopes, item)
					}
				}
			}
			if ok && contains(stringList(client.Get("resources")), indicator) && len(scopes) > 0 {
				addResourceScope(grant.data, indicator, scopes)
			}
		}
		if missing := obj(details, "missingResourceScopes"); missing != nil {
			missing.Entries(func(indicator string, value any) bool {
				if list, ok := value.([]any); ok {
					addResourceScope(grant.data, indicator, stringList(list))
				}
				return true
			})
		}
		grantID, err := p.save(ctx, nil, grant, 0)
		if err != nil {
			return err
		}
		binding := core.NewObject("id", hash(grantID), "tenantId", principal.Identity.Get("tenantId"),
			"sessionId", principal.Session.Get("id"), "identityId", identityID)
		existing, err := tx.Get(ctx, "oauthGrantSessions", str(binding, "id"))
		if err != nil {
			return err
		}
		if existing != nil {
			_, err = tx.Put(ctx, "oauthGrantSessions", binding)
		} else {
			_, err = tx.Insert(ctx, "oauthGrantSessions", binding)
		}
		if err != nil {
			return err
		}
		if err := p.audit(ctx, tx, str(principal.Identity, "tenantId"), identityID, "iam:oauth:Consent", str(client, "clientId")); err != nil {
			return err
		}
		amr := []any{"pwd"}
		if truthy(principal.Session.Get("mfa")) {
			amr = []any{"pwd", "mfa"}
		}
		returnTo, err = p.interactionResult(ctx, interaction, core.NewObject(
			"login", core.NewObject("accountId", identityID, "ts", epoch(int64(authenticatedAt)), "amr", amr),
			"consent", core.NewObject("grantId", grantID)))
		return err
	})
	if err != nil {
		return err
	}
	w.Header().Set("Location", returnTo)
	w.Header().Set("Content-Length", "0")
	w.WriteHeader(303)
	return nil
}

func isNaNOrInf(value float64) bool { return value != value || value > 1e308 || value < -1e308 }

// interactionResult is provider.interactionResult with mergeWithLastSubmission false.
func (p *Provider) interactionResult(ctx context.Context, interaction *model, result *core.Object) (string, error) {
	interaction.set("result", result)
	exp, _ := interaction.data.Get("exp").(float64)
	if _, err := p.save(ctx, nil, interaction, int64(exp)-epoch(p.now())); err != nil {
		return "", err
	}
	return interaction.str("returnTo"), nil
}

var _ = errors.New
