// Package mcp is the Go port of @better-iam/mcp (packages/mcp/src/index.ts): tool-level authorization for Model
// Context Protocol servers.
//
// NewGate sits in front of any Streamable HTTP MCP endpoint: it authenticates the caller, answers unauthenticated
// requests with a WWW-Authenticate challenge that points at the endpoint's protected resource metadata (RFC 9728,
// served by the gate), refuses tools/call requests the caller may not make, and removes the tools the caller may not
// use from tools/list answers, in JSON and in event streams.
//
// Callers present either a Better IAM credential (a person's session, a service account or AI agent key, or a
// delegated agent session acting for a person), decided by the Better IAM policy engine as `action` on `resource`, or
// an OAuth access token from the Better IAM authorization server, decided by its scopes. NewAuthorizer exposes the
// same decisions for tool handlers written with an MCP SDK.
package mcp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

// ResourceRef is a resource the policy engine decides on.
type ResourceRef = server.ResourceTarget

// ToolRule is how one tool is authorized.
type ToolRule struct {
	// Action is the Better IAM action a call needs (Better IAM credentials).
	Action string
	// Resource is the fixed resource the call acts on. Without it (and without DeriveResource) the resource is
	// `{ type: ToolResourceType, id: toolName }`.
	Resource *ResourceRef
	// DeriveResource derives the resource from the call's arguments (it wins over Resource); an error refuses the
	// call. Tools with derived resources are listed for everyone the rule could allow (their ListAs resource, when
	// given, decides the listing).
	DeriveResource func(args *core.Object) (ResourceRef, error)
	// ListAs is the resource that decides whether a tool with a derived resource appears in tools/list.
	ListAs *ResourceRef
	// Scopes are the scopes an OAuth access token needs for the tool (OAuth callers).
	Scopes []string
	// Public lets any authenticated caller use the tool.
	Public bool
}

// IAM is the part of a Better IAM instance (*server.BetterIam satisfies it) the gate needs.
type IAM interface {
	Authenticate(ctx context.Context, credential core.CredentialInput) (*server.Principal, error)
	Authorize(ctx context.Context, request server.AuthorizationRequest) (core.Decision, error)
	AuthorizeMany(ctx context.Context, request server.BatchAuthorizationRequest) (*core.Object, error)
}

// ConfirmationInput is the input of a confirmation request.
type ConfirmationInput struct {
	TenantID string
	Action   string
	Resource ResourceRef
	Reason   string
}

// Delegations is the part of the delegations API the gate uses for per-action confirmations.
type Delegations interface {
	// GetDelegation is delegations.get: the delegation (its `confirm` patterns).
	GetDelegation(ctx context.Context, credential core.CredentialInput, tenantID, delegationID string) (*core.Object, error)
	// RequestConfirmation is delegations.requestConfirmation: `{ id, status, expiresAt }`.
	RequestConfirmation(ctx context.Context, credential core.CredentialInput, input ConfirmationInput) (*core.Object, error)
}

// DelegationsProvider is an IAM that lets the gate ask a person to confirm an agent's action (api.delegations).
// A *server.BetterIam is used through its delegations API directly.
type DelegationsProvider interface {
	McpDelegations() Delegations
}

// serverDelegations is the delegations API of a composed server.
type serverDelegations struct{ api *server.DelegationsAPI }

func (d serverDelegations) GetDelegation(ctx context.Context, credential core.CredentialInput, tenantID, delegationID string) (*core.Object, error) {
	answer, err := d.api.Get(ctx, credential, server.Input[apitypes.DelegationsGetInput](core.NewObject("tenantId", tenantID, "delegationId", delegationID)))
	if err != nil {
		return nil, err
	}
	delegation, _ := answer.Value.(*core.Object)
	return delegation, nil
}

func (d serverDelegations) RequestConfirmation(ctx context.Context, credential core.CredentialInput, input ConfirmationInput) (*core.Object, error) {
	answer, err := d.api.RequestConfirmation(ctx, credential, server.Input[apitypes.DelegationsRequestConfirmationInput](core.NewObject(
		"tenantId", input.TenantID, "action", input.Action,
		"resource", core.NewObject("type", input.Resource.Type, "id", input.Resource.ID), "reason", input.Reason,
	)))
	if err != nil {
		return nil, err
	}
	request, _ := answer.Value.(*core.Object)
	return request, nil
}

// OAuthRequest is what an access-token verifier checks ("" for an absent header).
type OAuthRequest struct {
	Authorization string
	DPoP          string
	Method        string
	URL           string
}

// OAuthRequirement is what a token must carry.
type OAuthRequirement struct {
	Scopes []string
}

// OAuthToken is a verified access token.
type OAuthToken struct {
	Subject  string
	ClientID string
	// TenantID is the organization the token was issued for (nil when it names none).
	TenantID *string
	Scopes   []string
}

// OAuthVerifier is the access-token verifier of the OAuth authorization server.
type OAuthVerifier interface {
	VerifyRequest(ctx context.Context, request OAuthRequest, requirement *OAuthRequirement) (*OAuthToken, error)
}

// Caller kinds.
const (
	CallerIAM   = "iam"
	CallerOAuth = "oauth"
)

// Caller is who is calling the MCP server.
type Caller struct {
	// Kind is CallerIAM (a Better IAM credential) or CallerOAuth (an access token).
	Kind string

	// Credential, IdentityID, IdentityKind and SessionKind describe an IAM caller.
	Credential   core.CredentialInput
	IdentityID   string
	IdentityKind string
	SessionKind  string
	// AgentID is the agent behind an IAM credential: its own key, or the agent of a delegated session ("" when none).
	AgentID      string
	DelegationID string

	// TenantID is the tenant decisions are made in (IAM callers), or the token's organization ("" when none).
	TenantID string

	// Subject, ClientID and Scopes describe an OAuth caller.
	Subject  string
	ClientID string
	Scopes   []string
}

// AuthorizerOptions are the options of the authorizer (and the gate).
type AuthorizerOptions struct {
	// IAM authenticates credentials and decides.
	IAM IAM
	// Tools are the rules by tool name.
	Tools map[string]ToolRule
	// Unlisted is what happens to tools without a rule: refused and hidden ("deny", the default) or open to any
	// authenticated caller ("allow").
	Unlisted string
	// ToolResourceType is the resource type of the default per-tool resource (default mcp-tool).
	ToolResourceType string
	// TenantID is the tenant decisions are made in: the organization that runs this MCP server (required unless
	// TenantFunc is given). Deciding in each caller's own tenant would let any organization grant itself access.
	TenantID string
	// TenantFunc chooses the tenant per caller instead; "" refuses the caller.
	TenantFunc func(identityID, sessionTenantID string) string
	// OAuth accepts OAuth access tokens too, decided by each tool's Scopes. A token naming a tenant other than a fixed
	// TenantID is refused.
	OAuth OAuthVerifier
	// Confirmations: when an agent acting for a person (a delegated session) calls a tool whose action the person
	// confirms one call at a time (the delegation's `confirm`), ask the person on the agent's behalf and tell the agent
	// to retry after the approval. On by default when the IAM has a delegations API; false turns it off.
	Confirmations *bool
	// ConfirmationReason is the reason shown to the person in a confirmation request (default: which tool the agent
	// wants to run).
	ConfirmationReason func(tool string, args *core.Object) string
}

// Confirmation is a confirmation request the person decides on.
type Confirmation struct {
	ID        string
	ExpiresAt float64
}

// Decision is whether a caller may call a tool.
type Decision struct {
	Allowed bool
	// Reason is ALLOWED, PUBLIC, ACCESS_DENIED, UNKNOWN_TOOL, NO_RULE_FOR_CALLER, INSUFFICIENT_SCOPE, or
	// CONFIRMATION_REQUESTED (the person was asked to confirm; retry after they approve).
	Reason string
	// Confirmation is the request the person decides on (CONFIRMATION_REQUESTED).
	Confirmation *Confirmation
}

// presented is the credential in a request: `Authorization: Bearer …` (or `DPoP …`), else x-api-key.
func presented(r *http.Request) (token, scheme string, ok bool) {
	authorization, _ := headerGet(r.Header, "authorization")
	if match := credentialPattern.FindStringSubmatch(authorization); match != nil {
		return match[2], match[1], true
	}
	if key, _ := headerGet(r.Header, "x-api-key"); key != "" {
		return key, "Bearer", true
	}
	return "", "", false
}

const jsSpaces = `\t\n\v\f\r \x{a0}\x{1680}\x{2000}-\x{200a}\x{2028}\x{2029}\x{202f}\x{205f}\x{3000}\x{feff}`

var credentialPattern = regexp.MustCompile(`(?i)^(Bearer|DPoP)[` + jsSpaces + `]+([^` + jsSpaces + `]+)$`)

// headerGet is Headers#get: a header's values joined with ", ", and whether it is present.
func headerGet(header http.Header, name string) (string, bool) {
	values := header.Values(name)
	if len(values) == 0 {
		return "", false
	}
	return strings.Join(values, ", "), true
}

// Authorizer is the decisions shared by the gate and by tool handlers written with an MCP SDK.
type Authorizer struct {
	options      AuthorizerOptions
	resourceType string
}

// NewAuthorizer is createMcpAuthorizer.
func NewAuthorizer(options AuthorizerOptions) *Authorizer {
	resourceType := options.ToolResourceType
	if resourceType == "" {
		resourceType = "mcp-tool"
	}
	return &Authorizer{options: options, resourceType: resourceType}
}

func (a *Authorizer) rule(name string) *ToolRule {
	if found, ok := a.options.Tools[name]; ok {
		return &found
	}
	if a.options.Unlisted == "allow" {
		return &ToolRule{Public: true}
	}
	return nil
}

func (a *Authorizer) resourceOf(name string, found *ToolRule, args *core.Object) (resource ResourceRef, err error) {
	if found.DeriveResource != nil {
		defer func() {
			if recovered := recover(); recovered != nil {
				err = fmt.Errorf("%v", recovered)
			}
		}()
		return found.DeriveResource(args)
	}
	if found.Resource != nil {
		return *found.Resource, nil
	}
	return ResourceRef{Type: a.resourceType, ID: name}, nil
}

func (a *Authorizer) delegations() Delegations {
	switch iam := a.options.IAM.(type) {
	case DelegationsProvider:
		return iam.McpDelegations()
	case *server.BetterIam:
		if iam.API != nil && iam.API.Delegations != nil {
			return serverDelegations{api: iam.API.Delegations}
		}
	}
	return nil
}

// requestConfirmation files a confirmation request with the person for a delegated caller refused an action its
// delegation holds back for confirmation, and returns it. Nil when that does not apply or the request cannot be made
// (the call is then simply refused).
func (a *Authorizer) requestConfirmation(ctx context.Context, caller *Caller, tool, action string, resource ResourceRef, args *core.Object) *Confirmation {
	delegations := a.delegations()
	if (a.options.Confirmations != nil && !*a.options.Confirmations) || delegations == nil || caller.Kind != CallerIAM ||
		caller.SessionKind != "delegated" || caller.DelegationID == "" {
		return nil
	}
	delegation, err := delegations.GetDelegation(ctx, caller.Credential, caller.TenantID, caller.DelegationID)
	if err != nil || delegation == nil {
		return nil
	}
	patterns, _ := delegation.Get("confirm").([]any)
	held := false
	for _, pattern := range patterns {
		if text, ok := pattern.(string); ok && core.MatchPattern(text, action, nil) {
			held = true
			break
		}
	}
	if !held {
		return nil
	}
	reason := fmt.Sprintf("Your agent wants to run the tool %s (%s on %s/%s).", tool, action, resource.Type, resource.ID)
	if a.options.ConfirmationReason != nil {
		reason = a.options.ConfirmationReason(tool, args)
	}
	request, err := delegations.RequestConfirmation(ctx, caller.Credential, ConfirmationInput{
		TenantID: caller.TenantID, Action: action, Resource: resource, Reason: reason,
	})
	if err != nil || request == nil {
		return nil
	}
	id, _ := request.Get("id").(string)
	expiresAt, _ := request.Get("expiresAt").(float64)
	return &Confirmation{ID: id, ExpiresAt: expiresAt}
}

// requestURL is the absolute URL of a request (Request#url).
func requestURL(r *http.Request) string {
	if r.URL.IsAbs() {
		return r.URL.String()
	}
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host := r.Host
	if host == "" {
		host = r.URL.Host
	}
	return scheme + "://" + host + r.URL.RequestURI()
}

// Authenticate authenticates a request's credential: a Better IAM credential first, then (with OAuth) an OAuth access
// token. Nil when the request carries none or it is not valid.
func (a *Authorizer) Authenticate(ctx context.Context, r *http.Request) *Caller {
	token, scheme, ok := presented(r)
	if !ok {
		return nil
	}
	if strings.EqualFold(scheme, "bearer") {
		credential := core.CredentialInput{Token: token, Headers: r.Header}
		principal, err := a.options.IAM.Authenticate(ctx, credential)
		if err == nil {
			identity := principal.Identity
			session := principal.Session
			identityID, _ := identity.Get("id").(string)
			sessionTenantID, _ := session.Get("tenantId").(string)
			tenantID := a.options.TenantID
			if a.options.TenantFunc != nil {
				tenantID = a.options.TenantFunc(identityID, sessionTenantID)
			}
			if tenantID == "" {
				return nil
			}
			identityKind, _ := identity.Get("kind").(string)
			sessionKind, _ := session.Get("kind").(string)
			agentID := ""
			if sessionKind == "delegated" {
				agentID, _ = session.Get("agentId").(string)
			} else if identityKind == "agent" {
				agentID = identityID
			}
			delegationID, _ := session.Get("delegationId").(string)
			return &Caller{
				Kind: CallerIAM, Credential: credential, TenantID: tenantID, IdentityID: identityID,
				IdentityKind: identityKind, SessionKind: sessionKind, AgentID: agentID, DelegationID: delegationID,
			}
		}
		if a.options.OAuth == nil {
			return nil
		}
	}
	if a.options.OAuth == nil {
		return nil
	}
	authorization, _ := headerGet(r.Header, "authorization")
	dpop, _ := headerGet(r.Header, "dpop")
	verified, err := a.options.OAuth.VerifyRequest(ctx, OAuthRequest{Authorization: authorization, DPoP: dpop, Method: r.Method, URL: requestURL(r)}, nil)
	if err != nil || verified == nil {
		return nil
	}
	// A token issued for another organization is not a token for this server.
	if a.options.TenantFunc == nil && verified.TenantID != nil && *verified.TenantID != a.options.TenantID {
		return nil
	}
	caller := &Caller{Kind: CallerOAuth, ClientID: verified.ClientID, Scopes: append([]string{}, verified.Scopes...), Subject: verified.Subject}
	if verified.TenantID != nil {
		caller.TenantID = *verified.TenantID
	}
	return caller
}

func includes(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// CanCall is whether the caller may call name with args (Better IAM denials are audited by the server). args nil is
// `{}`.
func (a *Authorizer) CanCall(ctx context.Context, caller *Caller, name string, args *core.Object) (Decision, error) {
	if args == nil {
		args = core.NewObject()
	}
	found := a.rule(name)
	if found == nil {
		return Decision{Allowed: false, Reason: "UNKNOWN_TOOL"}, nil
	}
	if found.Public {
		return Decision{Allowed: true, Reason: "PUBLIC"}, nil
	}
	if caller.Kind == CallerOAuth {
		if len(found.Scopes) == 0 {
			return Decision{Allowed: false, Reason: "NO_RULE_FOR_CALLER"}, nil
		}
		for _, scope := range found.Scopes {
			if !includes(caller.Scopes, scope) {
				return Decision{Allowed: false, Reason: "INSUFFICIENT_SCOPE"}, nil
			}
		}
		return Decision{Allowed: true, Reason: "ALLOWED"}, nil
	}
	if found.Action == "" {
		return Decision{Allowed: false, Reason: "NO_RULE_FOR_CALLER"}, nil
	}
	resource, err := a.resourceOf(name, found, args)
	if err != nil {
		return Decision{Allowed: false, Reason: "ACCESS_DENIED"}, nil
	}
	decision, err := a.options.IAM.Authorize(ctx, server.AuthorizationRequest{
		Credential: caller.Credential, TenantID: caller.TenantID, Action: found.Action, Resource: resource,
	})
	if err != nil {
		return Decision{}, err
	}
	if decision.Allowed {
		return Decision{Allowed: true, Reason: "ALLOWED"}, nil
	}
	if confirmation := a.requestConfirmation(ctx, caller, name, found.Action, resource, args); confirmation != nil {
		return Decision{Allowed: false, Reason: "CONFIRMATION_REQUESTED", Confirmation: confirmation}, nil
	}
	return Decision{Allowed: false, Reason: "ACCESS_DENIED"}, nil
}

// VisibleTools is the names of the tools the caller may see, in their original order (checked 50 at a time).
func (a *Authorizer) VisibleTools(ctx context.Context, caller *Caller, names []string) ([]string, error) {
	visible, err := a.visible(ctx, caller, names)
	if err != nil {
		return nil, err
	}
	result := make([]string, 0, len(names))
	for _, name := range names {
		if visible[name] {
			result = append(result, name)
		}
	}
	return result, nil
}

// FilterTools is the tools the caller may see, in their original order (visibleTools for any tool type).
func FilterTools[T any](ctx context.Context, a *Authorizer, caller *Caller, tools []T, nameOf func(tool T) string) ([]T, error) {
	names := make([]string, len(tools))
	for index, tool := range tools {
		names[index] = nameOf(tool)
	}
	visible, err := a.visible(ctx, caller, names)
	if err != nil {
		return nil, err
	}
	result := make([]T, 0, len(tools))
	for index, tool := range tools {
		if visible[names[index]] {
			result = append(result, tool)
		}
	}
	return result, nil
}

func (a *Authorizer) visible(ctx context.Context, caller *Caller, names []string) (map[string]bool, error) {
	visible := map[string]bool{}
	type check struct {
		name     string
		action   string
		resource ResourceRef
	}
	var checks []check
	for _, name := range names {
		found := a.rule(name)
		if found == nil {
			continue
		}
		switch {
		case found.Public:
			visible[name] = true
		case caller.Kind == CallerOAuth:
			if len(found.Scopes) > 0 {
				every := true
				for _, scope := range found.Scopes {
					every = every && includes(caller.Scopes, scope)
				}
				if every {
					visible[name] = true
				}
			}
		case found.Action != "":
			if found.DeriveResource != nil && found.ListAs == nil {
				visible[name] = true
				continue
			}
			resource := ResourceRef{Type: a.resourceType, ID: name}
			if found.DeriveResource != nil {
				resource = *found.ListAs
			} else if found.Resource != nil {
				resource = *found.Resource
			}
			checks = append(checks, check{name: name, action: found.Action, resource: resource})
		}
	}
	if caller.Kind == CallerIAM {
		for index := 0; index < len(checks); index += 50 {
			batch := checks[index:min(index+50, len(checks))]
			request := make([]server.AuthorizationCheck, len(batch))
			for position, item := range batch {
				request[position] = server.AuthorizationCheck{Action: item.action, Resource: item.resource}
			}
			answer, err := a.options.IAM.AuthorizeMany(ctx, server.BatchAuthorizationRequest{
				Credential: caller.Credential, TenantID: caller.TenantID, Checks: request,
			})
			if err != nil {
				return nil, err
			}
			var results []any
			if answer != nil {
				results, _ = answer.Get("results").([]any)
			}
			for position, item := range batch {
				if position < len(results) {
					if result, ok := results[position].(*core.Object); ok && truthy(result.Get("allowed")) {
						visible[item.name] = true
					}
				}
			}
		}
	}
	return visible, nil
}

func truthy(value any) bool {
	switch v := value.(type) {
	case nil, core.UndefinedType:
		return false
	case bool:
		return v
	case float64:
		return v != 0 && !math.IsNaN(v)
	case string:
		return v != ""
	}
	return true
}

// ResourceMetadata is RFC 9728 protected resource metadata the gate serves and names in its challenges.
type ResourceMetadata struct {
	// Resource is the MCP endpoint's resource identifier (its canonical URL), the audience of OAuth tokens for it.
	Resource string
	// AuthorizationServers are the issuer URLs of the authorization servers that issue tokens for it.
	AuthorizationServers []string
	Scopes               []string
	ResourceName         string
	Documentation        string
}

// GateOptions are the options of the gate.
type GateOptions struct {
	AuthorizerOptions
	// Metadata serves protected resource metadata and points 401 challenges at it (for OAuth-capable MCP clients).
	Metadata *ResourceMetadata
	// MaxBodyBytes is the largest accepted JSON-RPC body in bytes (default 4 MiB).
	MaxBodyBytes int64
}

// ProtectedResourceMetadataURL is where RFC 9728 metadata lives for a resource:
// /.well-known/oauth-protected-resource + the resource path.
func ProtectedResourceMetadataURL(resource string) (string, error) {
	parsed, err := auth.ParseFetchURL(resource)
	if err != nil {
		return "", &TypeError{Message: "Invalid URL"}
	}
	pathname := parsed.URL.EscapedPath()
	if pathname == "" {
		pathname = "/"
	}
	path := ""
	if pathname != "/" {
		path = strings.TrimSuffix(pathname, "/")
	}
	return urlOrigin(parsed) + "/.well-known/oauth-protected-resource" + path, nil
}

// TypeError is an invalid option (a JavaScript TypeError).
type TypeError struct{ Message string }

func (e *TypeError) Error() string { return e.Message }

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

// Next is the MCP server's handler: it answers the request the gate passes on, with the authenticated caller.
type Next func(r *http.Request, caller *Caller) (*http.Response, error)

// Gate is the gate (createMcpGate): Handle answers a request itself (metadata, challenges, refused calls) or passes it
// to the MCP server's handler with the authenticated caller, filtering tools/list answers on the way back.
type Gate struct {
	authorizer       *Authorizer
	maxBodyBytes     int64
	metadataURL      string
	metadataPath     string
	metadataDocument string
}

// NewGate is createMcpGate. It fails when the metadata's resource is not an absolute URL.
func NewGate(options GateOptions) (*Gate, error) {
	gate := &Gate{authorizer: NewAuthorizer(options.AuthorizerOptions), maxBodyBytes: options.MaxBodyBytes}
	if gate.maxBodyBytes == 0 {
		gate.maxBodyBytes = 4 * 1024 * 1024
	}
	if metadata := options.Metadata; metadata != nil {
		metadataURL, err := ProtectedResourceMetadataURL(metadata.Resource)
		if err != nil {
			return nil, err
		}
		parsed, err := auth.ParseFetchURL(metadataURL)
		if err != nil {
			return nil, &TypeError{Message: "Invalid URL"}
		}
		gate.metadataURL = metadataURL
		gate.metadataPath = parsed.URL.EscapedPath()
		servers := make([]any, len(metadata.AuthorizationServers))
		for index, value := range metadata.AuthorizationServers {
			servers[index] = value
		}
		document := core.NewObject("resource", metadata.Resource, "authorization_servers", servers)
		if len(metadata.Scopes) > 0 {
			scopes := make([]any, len(metadata.Scopes))
			for index, value := range metadata.Scopes {
				scopes[index] = value
			}
			document.Set("scopes_supported", scopes)
		}
		document.Set("bearer_methods_supported", []any{"header"})
		if metadata.ResourceName != "" {
			document.Set("resource_name", metadata.ResourceName)
		}
		if metadata.Documentation != "" {
			document.Set("resource_documentation", metadata.Documentation)
		}
		gate.metadataDocument = core.MustStringify(document)
	}
	return gate, nil
}

// Authorizer is the gate's authorizer (for tool handlers).
func (g *Gate) Authorizer() *Authorizer { return g.authorizer }

// newResponse is `new Response(body, { status, headers })`.
func newResponse(status int, header http.Header, body []byte) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{
		Status: strconv.Itoa(status) + " " + http.StatusText(status), StatusCode: status,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: header,
		Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)),
	}
}

// jsonResponse is a JSON answer.
func jsonResponse(body any, status int) *http.Response {
	return newResponse(status, http.Header{"Content-Type": {"application/json"}}, []byte(core.MustStringify(body)))
}

func (g *Gate) challenge(failure string) *http.Response {
	code := failure
	if code == "" {
		code = "unauthorized"
	}
	var params []string
	if failure != "" {
		params = append(params, `error="`+failure+`"`)
	}
	if g.metadataURL != "" {
		params = append(params, `resource_metadata="`+g.metadataURL+`"`)
	}
	authenticate := "Bearer"
	if joined := strings.Join(params, ", "); joined != "" {
		authenticate += " " + joined
	}
	body := core.MustStringify(core.NewObject("error", code, "error_description", "Present a Better IAM credential or an OAuth access token"))
	return newResponse(401, http.Header{
		"Content-Type": {"application/json"}, "Cache-Control": {"no-store"}, "Www-Authenticate": {authenticate},
	}, []byte(body))
}

// jsonRPC is the message when value is a JSON-RPC request (an object with a string method).
func jsonRPC(value any) *core.Object {
	message, ok := value.(*core.Object)
	if !ok {
		return nil
	}
	if _, isString := message.Get("method").(string); !isString {
		return nil
	}
	return message
}

// idOf is `message.id ?? null`.
func idOf(message *core.Object) any {
	value, present := message.Lookup("id")
	if !present || value == nil || core.IsUndefined(value) {
		return nil
	}
	return value
}

// Handle is the gate: it answers the request itself or passes it to next.
func (g *Gate) Handle(r *http.Request, next Next) (*http.Response, error) {
	ctx := r.Context()
	if g.metadataDocument != "" && r.URL.EscapedPath() == g.metadataPath {
		if r.Method == http.MethodOptions {
			return newResponse(204, http.Header{
				"Access-Control-Allow-Origin": {"*"}, "Access-Control-Allow-Methods": {"GET, OPTIONS"},
			}, nil), nil
		}
		return newResponse(200, http.Header{
			"Content-Type": {"application/json"}, "Access-Control-Allow-Origin": {"*"},
			"Cache-Control": {"public, max-age=3600"},
		}, []byte(g.metadataDocument)), nil
	}
	if _, _, ok := presented(r); !ok {
		return g.challenge(""), nil
	}
	caller := g.authorizer.Authenticate(ctx, r)
	if caller == nil {
		return g.challenge("invalid_token"), nil
	}
	// Streamable HTTP also uses GET (the server's event stream) and DELETE (ending a session): authenticated only.
	if r.Method != http.MethodPost {
		return next(r, caller)
	}
	text, within, err := boundedBody(r, g.maxBodyBytes)
	if err != nil {
		return nil, err
	}
	if !within {
		return jsonResponse(core.NewObject("error", "request too large"), 413), nil
	}
	parsed, err := core.ParseJSONString(text)
	if err != nil {
		return jsonResponse(core.NewObject("jsonrpc", "2.0", "id", nil, "error", core.NewObject("code", float64(-32700), "message", "Parse error")), 400), nil
	}
	// The server receives the request exactly as the gate read it (no duplicate keys a different parser could pick).
	serialized := core.MustStringify(parsed)
	forward := r.Clone(ctx)
	forward.Header.Del("Content-Length")
	forward.Body = io.NopCloser(strings.NewReader(serialized))
	forward.ContentLength = int64(len(serialized))
	forward.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(serialized)), nil }
	if batch, ok := parsed.([]any); ok {
		// Batches (dropped from MCP in 2025-06-18) may not carry tool traffic past the gate.
		for _, item := range batch {
			if message := jsonRPC(item); message != nil {
				if method := message.Get("method"); method == "tools/call" || method == "tools/list" {
					return jsonResponse(core.NewObject("jsonrpc", "2.0", "id", nil, "error", core.NewObject(
						"code", float64(-32600), "message", "Batched tool requests are not supported",
					)), 400), nil
				}
			}
		}
		return next(forward, caller)
	}
	message := jsonRPC(parsed)
	if message != nil && message.Get("method") == "tools/call" {
		params, _ := message.Get("params").(*core.Object)
		var name string
		isString := false
		if params != nil {
			name, isString = params.Get("name").(string)
		}
		// A name that is not a string (an array, a number) would be judged as no tool at all (and allowed with
		// unlisted "allow") while the server may coerce it to a real tool's name: refuse it.
		if !isString {
			return jsonResponse(core.NewObject("jsonrpc", "2.0", "id", idOf(message), "error", core.NewObject(
				"code", float64(-32602), "message", "The tool name must be a string",
			)), 400), nil
		}
		args := argumentsOf(params.Get("arguments"))
		decision, err := g.authorizer.CanCall(ctx, caller, name, args)
		if err != nil {
			var known *core.IamError
			if errors.As(err, &known) && (known.Status == 401 || known.Code == "UNAUTHENTICATED") {
				return g.challenge("invalid_token"), nil
			}
			return nil, err
		}
		if !decision.Allowed {
			text := "Access denied: you may not call " + name
			if decision.Reason == "UNKNOWN_TOOL" {
				text = "Unknown tool: " + name
			} else if decision.Confirmation != nil {
				expires, err := isoString(decision.Confirmation.ExpiresAt)
				if err != nil {
					return nil, err
				}
				text = "The person you act for must confirm this call first. A confirmation request was sent to them (it expires at " +
					expires + "). Call " + name + " again once they approve it."
			}
			result := core.NewObject("content", []any{core.NewObject("type", "text", "text", text)}, "isError", true)
			if decision.Confirmation != nil {
				result.Set("_meta", core.NewObject(
					"better-iam/confirmationId", decision.Confirmation.ID,
					"better-iam/confirmationExpiresAt", decision.Confirmation.ExpiresAt,
				))
			}
			return jsonResponse(core.NewObject("jsonrpc", "2.0", "id", idOf(message), "result", result), 200), nil
		}
		return next(forward, caller)
	}
	if message != nil && message.Get("method") == "tools/list" {
		response, err := next(forward, caller)
		if err != nil {
			return nil, err
		}
		id, present := message.Lookup("id")
		if !present {
			id = core.Undefined
		}
		return g.filterList(ctx, response, id, caller)
	}
	return next(forward, caller)
}

// argumentsOf is the call's arguments when they are an object (arrays count, as in JavaScript), else `{}`.
func argumentsOf(value any) *core.Object {
	switch arguments := value.(type) {
	case *core.Object:
		return arguments
	case []any:
		record := core.NewObject()
		for index, item := range arguments {
			record.Set(strconv.Itoa(index), item)
		}
		return record
	}
	return core.NewObject()
}

// isoString is Date#toISOString for a millisecond timestamp (a RangeError for an invalid date).
func isoString(ms float64) (string, error) {
	if math.IsNaN(ms) || math.IsInf(ms, 0) || math.Abs(ms) > 8.64e15 {
		return "", errors.New("Invalid time value")
	}
	at := time.UnixMilli(int64(ms)).UTC()
	year := at.Year()
	prefix := fmt.Sprintf("%04d", year)
	if year < 0 || year > 9999 {
		sign := "+"
		if year < 0 {
			sign, year = "-", -year
		}
		prefix = fmt.Sprintf("%s%06d", sign, year)
	}
	return prefix + at.Format("-01-02T15:04:05.000Z"), nil
}

// strictEqual is `===` for JSON values (objects and arrays are never equal to a parsed copy).
func strictEqual(a, b any) bool {
	switch left := a.(type) {
	case nil:
		return b == nil
	case core.UndefinedType:
		return core.IsUndefined(b)
	case string:
		right, ok := b.(string)
		return ok && left == right
	case float64:
		right, ok := b.(float64)
		return ok && left == right
	case bool:
		right, ok := b.(bool)
		return ok && left == right
	}
	return false
}

// rewrite is a tools/list result for id with the hidden tools removed; ok false when payload is not one.
func (g *Gate) rewrite(ctx context.Context, payload string, id any, caller *Caller) (string, bool, error) {
	parsed, err := core.ParseJSONString(payload)
	if err != nil {
		return "", false, nil
	}
	message, ok := parsed.(*core.Object)
	if !ok {
		return "", false, nil
	}
	messageID, present := message.Lookup("id")
	if !present {
		messageID = core.Undefined
	}
	result, _ := message.Get("result").(*core.Object)
	if !strictEqual(messageID, id) || result == nil {
		return "", false, nil
	}
	list, isList := result.Get("tools").([]any)
	if !isList {
		return "", false, nil
	}
	tools := make([]*core.Object, 0, len(list))
	for _, item := range list {
		if tool, ok := item.(*core.Object); ok {
			if _, named := tool.Get("name").(string); named {
				tools = append(tools, tool)
			}
		}
	}
	visible, err := FilterTools(ctx, g.authorizer, caller, tools, func(tool *core.Object) string {
		name, _ := tool.Get("name").(string)
		return name
	})
	if err != nil {
		return "", false, err
	}
	kept := make([]any, len(visible))
	for index, tool := range visible {
		kept[index] = tool
	}
	rewrittenResult := result.Clone()
	rewrittenResult.Set("tools", kept)
	rewritten := message.Clone()
	rewritten.Set("result", rewrittenResult)
	return core.MustStringify(rewritten), true, nil
}

// filterList removes hidden tools from a tools/list result for id, in a JSON body or an event stream.
func (g *Gate) filterList(ctx context.Context, response *http.Response, id any, caller *Caller) (*http.Response, error) {
	contentType, _ := headerGet(response.Header, "content-type")
	header := response.Header.Clone()
	if header == nil {
		header = http.Header{}
	}
	header.Del("Content-Length")
	if strings.Contains(contentType, "application/json") {
		var data []byte
		if response.Body != nil {
			read, err := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil {
				return nil, err
			}
			data = read
		}
		text := decodeText(data)
		rewritten, ok, err := g.rewrite(ctx, text, id, caller)
		if err != nil {
			return nil, err
		}
		if ok {
			text = rewritten
		}
		filtered := newResponse(response.StatusCode, header, []byte(text))
		filtered.Status = response.Status
		return filtered, nil
	}
	if !strings.Contains(contentType, "text/event-stream") || response.Body == nil || response.Body == http.NoBody {
		return response, nil
	}
	reader, writer := io.Pipe()
	go g.filterStream(ctx, response.Body, writer, id, caller)
	filtered := newResponse(response.StatusCode, header, nil)
	filtered.Status = response.Status
	filtered.Body = reader
	filtered.ContentLength = -1
	return filtered, nil
}

var eventBoundary = regexp.MustCompile(`\r?\n\r?\n`)

var lineBreak = regexp.MustCompile(`\r?\n`)

// filterStream rewrites the events of an event stream as they arrive.
func (g *Gate) filterStream(ctx context.Context, body io.ReadCloser, out *io.PipeWriter, id any, caller *Caller) {
	defer func() { _ = body.Close() }()
	emit := func(event string) error {
		lines := lineBreak.Split(event, -1)
		var data, others []string
		for _, line := range lines {
			if strings.HasPrefix(line, "data:") {
				data = append(data, strings.TrimPrefix(line[5:], " "))
			} else {
				others = append(others, line)
			}
		}
		result := event
		if len(data) > 0 {
			rewritten, ok, err := g.rewrite(ctx, strings.Join(data, "\n"), id, caller)
			if err != nil {
				return err
			}
			if ok {
				result = strings.Join(append(others, "data: "+rewritten), "\n")
			}
		}
		_, err := io.WriteString(out, result+"\n\n")
		return err
	}
	// Events are split on the raw bytes (a UTF-8 sequence never contains CR or LF) and decoded whole.
	var buffer []byte
	chunk := make([]byte, 32*1024)
	for {
		count, readErr := body.Read(chunk)
		buffer = append(buffer, chunk[:count]...)
		for {
			boundary := eventBoundary.FindIndex(buffer)
			if boundary == nil {
				break
			}
			event := decodeUTF8(buffer[:boundary[0]])
			buffer = buffer[boundary[1]:]
			if err := emit(event); err != nil {
				out.CloseWithError(err)
				return
			}
		}
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			out.CloseWithError(readErr)
			return
		}
	}
	rest := decodeUTF8(buffer)
	if core.JSTrim(rest) != "" {
		if err := emit(strings.TrimRightFunc(rest, jsSpace)); err != nil {
			out.CloseWithError(err)
			return
		}
	}
	_ = out.Close()
}

// jsSpace is JavaScript whitespace (/\s/).
func jsSpace(r rune) bool {
	switch r {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xA0, 0x1680, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000, 0xFEFF:
		return true
	}
	return r >= 0x2000 && r <= 0x200A
}

// boundedBody is the request body as text, or within false when it is larger than maxBytes (read no further than
// that).
func boundedBody(r *http.Request, maxBytes int64) (string, bool, error) {
	declared, _ := headerGet(r.Header, "content-length")
	if jsNumber(declared) > float64(maxBytes) || r.ContentLength > maxBytes {
		return "", false, nil
	}
	if r.Body == nil || r.Body == http.NoBody {
		return "", true, nil
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, maxBytes+1))
	if err != nil {
		return "", false, err
	}
	if int64(len(data)) > maxBytes {
		_ = r.Body.Close()
		return "", false, nil
	}
	return decodeText(data), true, nil
}

// jsNumber is Number(string): "" is 0, anything else not numeric is NaN.
func jsNumber(value string) float64 {
	trimmed := core.JSTrim(value)
	if trimmed == "" {
		return 0
	}
	number, err := strconv.ParseFloat(trimmed, 64)
	if err != nil {
		return math.NaN()
	}
	return number
}

// decodeText is `new TextDecoder().decode(bytes)`: a leading BOM dropped, invalid UTF-8 replaced.
func decodeText(data []byte) string {
	return decodeUTF8(bytes.TrimPrefix(data, []byte{0xEF, 0xBB, 0xBF}))
}

// decodeUTF8 is the WHATWG UTF-8 decoder: each maximal subpart of an invalid sequence becomes one U+FFFD.
func decodeUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	var out strings.Builder
	out.Grow(len(b))
	i := 0
	for i < len(b) {
		c := b[i]
		if c < 0x80 {
			out.WriteByte(c)
			i++
			continue
		}
		var need int
		lower, upper := byte(0x80), byte(0xBF)
		switch {
		case c >= 0xC2 && c <= 0xDF:
			need = 1
		case c >= 0xE0 && c <= 0xEF:
			need = 2
			if c == 0xE0 {
				lower = 0xA0
			} else if c == 0xED {
				upper = 0x9F
			}
		case c >= 0xF0 && c <= 0xF4:
			need = 3
			if c == 0xF0 {
				lower = 0x90
			} else if c == 0xF4 {
				upper = 0x8F
			}
		default:
			out.WriteRune(utf8.RuneError)
			i++
			continue
		}
		j := i + 1
		ok := true
		for k := 0; k < need; k++ {
			if j >= len(b) {
				ok = false
				break
			}
			d := b[j]
			if k == 0 {
				if d < lower || d > upper {
					ok = false
					break
				}
			} else if d < 0x80 || d > 0xBF {
				ok = false
				break
			}
			j++
		}
		if ok {
			out.Write(b[i:j])
		} else {
			out.WriteRune(utf8.RuneError)
		}
		i = j
	}
	return out.String()
}
