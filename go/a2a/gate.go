package a2a

// Port of packages/a2a/src/gate.ts: authorization for Agent2Agent (A2A) servers speaking JSON-RPC over HTTP.
//
// CreateGate sits in front of an A2A endpoint. It serves the agent card at /.well-known/agent-card.json without
// authentication, authenticates every other request (a Better IAM credential: a person's session, an agent's key, or
// a delegated session in which an agent acts for a person; or an OAuth access token), decides message/send and
// message/stream by the skill a message names (its metadata.skillId) or the agent-wide message rule, and makes tasks
// private to the caller who started them: tasks/get, tasks/cancel, tasks/resubscribe and push notification settings
// for a task another caller started answer "task not found". agent/getAuthenticatedExtendedCard lists only the
// skills the caller may use.
//
// The gate is fetch-style like the TypeScript one (Gate.Serve takes a request and the server's handler and returns
// the response); Gate.Middleware wraps an http.Handler instead.

import (
	"bytes"
	"container/list"
	"context"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/Better-IAM/better-iam/go/core"
)

// ResourceRef is a resource the policy engine decides on.
type ResourceRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Rule is how one skill (or the agent's messages as a whole) is authorized.
type Rule struct {
	// Action is the Better IAM action a message needs (Better IAM credentials); "" for none.
	Action string
	// Resource is the resource the message acts on; default { type: 'a2a-skill', id: skillId } (a2a-agent/agent for
	// the message rule).
	Resource *ResourceRef
	// ResourceFunc derives the resource from the request params instead (it takes precedence over Resource).
	ResourceFunc func(params *core.Object) (ResourceRef, error)
	// Scopes an OAuth access token needs (OAuth callers).
	Scopes []string
	// Public lets any authenticated caller send such messages.
	Public bool
}

// PrincipalIdentity is the identity of an authenticated credential.
type PrincipalIdentity struct {
	ID, TenantID, Kind string
}

// PrincipalSession is the session of an authenticated credential; AgentID and DelegationID are "" when absent.
type PrincipalSession struct {
	ID, TenantID, Kind, AgentID, DelegationID string
}

// Principal is who a Better IAM credential authenticates as.
type Principal struct {
	Identity PrincipalIdentity
	Session  PrincipalSession
}

// Decision is one authorization decision.
type Decision struct {
	Allowed bool
	Reason  string
}

// AuthorizeRequest is one authorization question.
type AuthorizeRequest struct {
	Credential core.CredentialInput
	TenantID   string
	Action     string
	Resource   ResourceRef
}

// AuthorizeCheck is one check of a batch.
type AuthorizeCheck struct {
	Action   string
	Resource ResourceRef
}

// AuthorizeManyRequest is up to 50 checks for one tenant.
type AuthorizeManyRequest struct {
	Credential core.CredentialInput
	TenantID   string
	Checks     []AuthorizeCheck
}

// Iam is the part of a Better IAM instance (betterIam()) or client the gate needs. Server(iam) adapts a
// *server.BetterIam.
type Iam interface {
	Authenticate(ctx context.Context, credential core.CredentialInput) (*Principal, error)
	Authorize(ctx context.Context, request AuthorizeRequest) (Decision, error)
	// AuthorizeMany answers the checks in order.
	AuthorizeMany(ctx context.Context, request AuthorizeManyRequest) ([]Decision, error)
}

// ConfirmationInput asks the person a delegated session acts for to confirm one request.
type ConfirmationInput struct {
	TenantID string
	Action   string
	Resource ResourceRef
	Reason   string
}

// ConfirmationRequest is a filed confirmation request.
type ConfirmationRequest struct {
	ID        string
	Status    string
	ExpiresAt float64
}

// Delegations is the optional part of Iam (iam.api.delegations on a betterIam() instance) that lets the gate ask a
// person to confirm an agent's request.
type Delegations interface {
	// DelegationConfirm is delegations.get's confirm: the action patterns the person confirms one request at a time
	// (nil when none).
	DelegationConfirm(ctx context.Context, credential core.CredentialInput, tenantID, delegationID string) ([]string, error)
	// RequestConfirmation is delegations.requestConfirmation.
	RequestConfirmation(ctx context.Context, credential core.CredentialInput, input ConfirmationInput) (ConfirmationRequest, error)
}

// OAuthRequest is what an access-token verifier reads from a request; Authorization and DPoP are "" when absent.
type OAuthRequest struct {
	Authorization string
	DPoP          string
	Method        string
	URL           string
}

// OAuthToken is a verified access token; Subject and TenantID are "" when absent.
type OAuthToken struct {
	Subject  string
	ClientID string
	TenantID string
	Scopes   []string
}

// OAuthVerifier is the access-token verifier of the oauth package (createAccessTokenVerifier or a resource guard's
// verifier), behind an adapter.
type OAuthVerifier interface {
	VerifyRequest(ctx context.Context, request OAuthRequest) (*OAuthToken, error)
}

// OAuthVerifierFunc adapts a function to OAuthVerifier.
type OAuthVerifierFunc func(ctx context.Context, request OAuthRequest) (*OAuthToken, error)

// VerifyRequest calls the function.
func (f OAuthVerifierFunc) VerifyRequest(ctx context.Context, request OAuthRequest) (*OAuthToken, error) {
	return f(ctx, request)
}

// Caller is who is calling the A2A server: Kind "iam" (a Better IAM credential) or "oauth" (an access token).
type Caller struct {
	Kind string
	// Better IAM callers.
	Credential   core.CredentialInput
	TenantID     string
	IdentityID   string
	IdentityKind string
	SessionKind  string
	// AgentID is the agent behind the credential: its own key, or the agent of a delegated session ("" for none).
	AgentID      string
	DelegationID string
	// OAuth callers (TenantID is "" when the token names none).
	Subject  string
	ClientID string
	Scopes   []string
}

// TaskOwners are who started each task and each conversation (A2A context), by key task:{id} or context:{id}. The
// default keeps owners in this process's memory.
type TaskOwners interface {
	// Get is the owner of a key; ok is false when unknown.
	Get(ctx context.Context, key string) (owner string, ok bool, err error)
	Set(ctx context.Context, key, owner string) error
}

// MemoryTaskOwnersOptions configures MemoryTaskOwners.
type MemoryTaskOwnersOptions struct {
	// MaxTasks is the most entries kept (0: 100000).
	MaxTasks int
	// TTLMs is how long each entry is kept (0: seven days).
	TTLMs float64
	// Now is epoch milliseconds (nil: the system clock).
	Now func() float64
}

type memoryOwner struct {
	key   string
	owner string
	until float64
}

type memoryTaskOwners struct {
	mu       sync.Mutex
	now      func() float64
	maxTasks int
	ttlMs    float64
	owners   map[string]*list.Element
	order    *list.List
}

// MemoryTaskOwners keeps owners in memory: at most MaxTasks entries, each kept TTLMs.
func MemoryTaskOwners(options MemoryTaskOwnersOptions) TaskOwners {
	maxTasks := options.MaxTasks
	if maxTasks == 0 {
		maxTasks = 100_000
	}
	ttlMs := options.TTLMs
	if ttlMs == 0 {
		ttlMs = 7 * 24 * 3600 * 1000
	}
	return &memoryTaskOwners{now: options.Now, maxTasks: maxTasks, ttlMs: ttlMs, owners: map[string]*list.Element{}, order: list.New()}
}

func (m *memoryTaskOwners) remove(key string) {
	if element, ok := m.owners[key]; ok {
		m.order.Remove(element)
		delete(m.owners, key)
	}
}

func (m *memoryTaskOwners) Get(_ context.Context, key string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	element, ok := m.owners[key]
	if !ok {
		return "", false, nil
	}
	found := element.Value.(memoryOwner)
	if found.until <= nowOf(m.now) {
		m.remove(key)
		return "", false, nil
	}
	return found.owner, true, nil
}

func (m *memoryTaskOwners) Set(_ context.Context, key, owner string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.remove(key)
	m.owners[key] = m.order.PushBack(memoryOwner{key: key, owner: owner, until: nowOf(m.now) + m.ttlMs})
	for len(m.owners) > m.maxTasks {
		oldest := m.order.Front()
		m.order.Remove(oldest)
		delete(m.owners, oldest.Value.(memoryOwner).key)
	}
	return nil
}

// TenantCaller is what a TenantIDFunc chooses the decision tenant by.
type TenantCaller struct {
	IdentityID      string
	SessionTenantID string
}

// GateOptions configures CreateGate and CreateAuthorizer.
type GateOptions struct {
	Iam Iam
	// Message is the rule for every message that names no skill (and for all messages when skills are not used).
	Message Rule
	// Skills are rules by skill id, for messages that name a skill (metadata.skillId).
	Skills map[string]Rule
	// UnlistedSkills decides messages naming a skill without a rule: refused ("deny", the default) or decided by
	// Message ("message").
	UnlistedSkills string
	// SkillOf is how a request names its skill (default: params.message.metadata.skillId, then
	// params.metadata.skillId); ok is false for none.
	SkillOf func(params *core.Object) (skill string, ok bool)
	// Card is served at /.well-known/agent-card.json (CardFunc builds it instead, for example CreateCardAttestor).
	Card     *core.Object
	CardFunc func(ctx context.Context) (*core.Object, error)
	// ExtendedCard is answered to agent/getAuthenticatedExtendedCard, with only the skills the caller may use.
	ExtendedCard     *core.Object
	ExtendedCardFunc func(ctx context.Context) (*core.Object, error)
	// Tasks are who started each task and conversation; supply a shared store when several instances serve the
	// agent. Unknown tasks and conversations belong to no one, so a restart with the in-memory default ends access to
	// earlier ones.
	Tasks TaskOwners
	// TaskAdminAction lets callers allowed this action on the Message rule's resource read and cancel every task
	// (operators).
	TaskAdminAction string
	// OtherMethods decides JSON-RPC methods A2A does not define: refused ("deny", the default) or passed on ("allow").
	OtherMethods string
	// OtherHTTPMethods decides HTTP methods other than POST (besides the agent card): refused with 405 ("deny", the
	// default) or passed on to the server unchecked apart from authentication ("allow", for servers that serve more
	// than JSON-RPC at this address).
	OtherHTTPMethods string
	// TenantID is the tenant decisions are made in: the organization that runs this agent (required, unless
	// TenantIDFunc chooses it per caller and returns "" to refuse the caller). Deciding in each caller's own tenant
	// would let any organization grant itself access.
	TenantID     string
	TenantIDFunc func(caller TenantCaller) (string, error)
	// OAuth accepts OAuth access tokens too, decided by each rule's Scopes. A token naming a tenant other than a fixed
	// TenantID is refused.
	OAuth OAuthVerifier
	// OnError is called with unexpected errors before the gate answers JSON-RPC -32603 (HTTP 500).
	OnError func(err error)
	// Confirmations: when an agent acting for a person (a delegated session) sends a message whose action the person
	// confirms one request at a time (the delegation's confirm), ask the person (delegations.requestConfirmation) and
	// answer with A2AConfirmationRequested. On by default when Iam implements Delegations; false turns it off.
	Confirmations *bool
	// ConfirmationReason words the confirmation request (skill is nil for the message rule); ok false uses the
	// default wording.
	ConfirmationReason func(skill *string, params *core.Object) (reason string, ok bool)
	// MaxBodyBytes is the largest accepted JSON-RPC body in bytes (0: 4 MiB).
	MaxBodyBytes int64
}

// A2AAccessDenied is the JSON-RPC error code (HTTP 403) of a message the caller may not send: error.data.reason says
// why (ACCESS_DENIED, UNKNOWN_SKILL, NO_RULE_FOR_CALLER, INSUFFICIENT_SCOPE). Tasks of other callers answer A2A's own
// -32001.
const A2AAccessDenied = -32050

// A2AConfirmationRequested is the JSON-RPC error code (HTTP 403) telling an agent that acts for a person that the
// person must confirm this request first: a confirmation request was filed (error.data.confirmationId,
// error.data.expiresAt); retry once approved.
const A2AConfirmationRequested = -32051

// Confirmation is a filed confirmation request a decision names.
type Confirmation struct {
	ID        string
	ExpiresAt float64
}

// A2aDecision is whether a caller may send a message. Reason is ALLOWED, PUBLIC, ACCESS_DENIED, UNKNOWN_SKILL,
// AMBIGUOUS_SKILL, NO_RULE_FOR_CALLER, INSUFFICIENT_SCOPE, or CONFIRMATION_REQUESTED.
type A2aDecision struct {
	Allowed      bool
	Reason       string
	Confirmation *Confirmation
}

var taskMethods = map[string]bool{
	"tasks/get":                           true,
	"tasks/cancel":                        true,
	"tasks/resubscribe":                   true,
	"tasks/pushNotificationConfig/set":    true,
	"tasks/pushNotificationConfig/get":    true,
	"tasks/pushNotificationConfig/list":   true,
	"tasks/pushNotificationConfig/delete": true,
}

var messageMethods = map[string]bool{"message/send": true, "message/stream": true}

const extendedCardMethod = "agent/getAuthenticatedExtendedCard"

// found is a rule and, for a skill's own rule, the skill its default resource is named after.
type found struct {
	rule  Rule
	named *string
}

// presentedCredential is the credential a request presents: a Bearer or DPoP authorization, or an x-api-key.
type presentedCredential struct {
	token, scheme string
}

// latinSpace is JavaScript's \s over a header value (a ByteString: one character per byte).
func latinSpace(c byte) bool {
	switch c {
	case '\t', '\n', '\v', '\f', '\r', ' ', 0xA0:
		return true
	}
	return false
}

func hasLatinSpace(value string) bool {
	for index := 0; index < len(value); index++ {
		if latinSpace(value[index]) {
			return true
		}
	}
	return false
}

func presented(request *http.Request) *presentedCredential {
	// /^(Bearer|DPoP)\s+(\S+)$/i
	authorization := strings.Join(request.Header.Values("authorization"), ", ")
	for _, scheme := range []string{"Bearer", "DPoP"} {
		if len(authorization) <= len(scheme) || !strings.EqualFold(authorization[:len(scheme)], scheme) {
			continue
		}
		rest := authorization[len(scheme):]
		if !latinSpace(rest[0]) {
			continue
		}
		start := 0
		for start < len(rest) && latinSpace(rest[start]) {
			start++
		}
		token := rest[start:]
		if token == "" || hasLatinSpace(token) {
			continue
		}
		return &presentedCredential{scheme: authorization[:len(scheme)], token: token}
	}
	if key := strings.Join(request.Header.Values("x-api-key"), ", "); key != "" {
		return &presentedCredential{scheme: "Bearer", token: key}
	}
	return nil
}

// namedSkills are the skill ids a request names: in the message's metadata and in the request's.
func namedSkills(params *core.Object) []any {
	var names []any
	var fromMessage any = core.Undefined
	if message, ok := plain(params.Get("message")); ok {
		if metadata, ok := plain(message.Get("metadata")); ok {
			fromMessage = metadata.Get("skillId")
		}
	}
	var fromRequest any = core.Undefined
	if metadata, ok := plain(params.Get("metadata")); ok {
		fromRequest = metadata.Get("skillId")
	}
	for _, value := range []any{fromMessage, fromRequest} {
		if !core.IsUndefined(value) {
			names = append(names, value)
		}
	}
	return names
}

func defaultSkillOf(params *core.Object) (string, bool) {
	names := namedSkills(params)
	if len(names) == 0 {
		return "", false
	}
	skill, ok := names[0].(string)
	return skill, ok
}

// HandoffMetadataKey is the A2A message metadata key that carries a Better IAM hand-off (delegations.handoff) from the
// calling agent to the agent it calls, so the called agent can act for the same person with delegations.assume.
const HandoffMetadataKey = "better-iam/handoff"

// WithHandoff adds a hand-off to an A2A message's metadata (the calling side); the message is not changed.
func WithHandoff(message *core.Object, delegationID string) *core.Object {
	metadata := core.NewObject()
	if existing, ok := plain(message.Get("metadata")); ok {
		metadata = existing.Spread()
	}
	metadata.Set(HandoffMetadataKey, delegationID)
	return message.Spread(core.NewObject("metadata", metadata))
}

// HandoffOf is the hand-off an A2A request carries (the called side): the delegation id in the message's metadata,
// else in the request's ("" for none). Open a session for it with the called agent's own key (delegations.assume),
// which refuses hand-offs that are not this agent's.
func HandoffOf(params *core.Object) string {
	var value any = core.Undefined
	if message, ok := plain(params.Get("message")); ok {
		if metadata, ok := plain(message.Get("metadata")); ok {
			value = metadata.Get(HandoffMetadataKey)
		}
	}
	if value == nil || core.IsUndefined(value) {
		value = core.Undefined
		if metadata, ok := plain(params.Get("metadata")); ok {
			value = metadata.Get(HandoffMetadataKey)
		}
	}
	text, _ := value.(string)
	return text
}

// TaskOwnerOf is the owner key of a caller: the same person through the same agent (or none), or the same OAuth
// client and subject.
func TaskOwnerOf(caller *Caller) string {
	if caller.Kind == "iam" {
		return "iam:" + caller.TenantID + ":" + caller.IdentityID + ":" + caller.AgentID
	}
	return "oauth:" + caller.ClientID + ":" + caller.Subject
}

// Authorizer is the decisions shared by the gate and by handlers written with an A2A SDK.
type Authorizer struct {
	options GateOptions
}

// CreateAuthorizer builds the decisions of a gate without the gate.
func CreateAuthorizer(options GateOptions) *Authorizer {
	return &Authorizer{options: options}
}

// SkillOf is the skill a message/send or message/stream request names, if any.
func (a *Authorizer) SkillOf(params *core.Object) (string, bool) {
	if a.options.SkillOf != nil {
		return a.options.SkillOf(params)
	}
	return defaultSkillOf(params)
}

func (a *Authorizer) skillOf(params *core.Object) *string {
	if skill, ok := a.SkillOf(params); ok {
		return &skill
	}
	return nil
}

// ruleFor is the rule for a skill (or for messages naming none), and the skill its default resource is named after.
func (a *Authorizer) ruleFor(skill *string) *found {
	if skill != nil && a.options.Skills != nil {
		if rule, ok := a.options.Skills[*skill]; ok {
			named := *skill
			return &found{rule: rule, named: &named}
		}
	}
	if skill == nil || a.options.UnlistedSkills == "message" {
		return &found{rule: a.options.Message}
	}
	return nil
}

func (a *Authorizer) resourceOf(found *found, params *core.Object) (ResourceRef, error) {
	if found.rule.ResourceFunc != nil {
		return found.rule.ResourceFunc(params)
	}
	if found.rule.Resource != nil {
		return *found.rule.Resource, nil
	}
	if found.named != nil {
		return ResourceRef{Type: "a2a-skill", ID: *found.named}, nil
	}
	return ResourceRef{Type: "a2a-agent", ID: "agent"}, nil
}

func (a *Authorizer) requestConfirmation(ctx context.Context, caller *Caller, skill *string, action string, resource ResourceRef,
	params *core.Object) *Confirmation {
	delegations, ok := a.options.Iam.(Delegations)
	if (a.options.Confirmations != nil && !*a.options.Confirmations) || !ok || caller.Kind != "iam" ||
		caller.SessionKind != "delegated" || caller.DelegationID == "" {
		return nil
	}
	confirm, err := delegations.DelegationConfirm(ctx, caller.Credential, caller.TenantID, caller.DelegationID)
	if err != nil {
		return nil
	}
	held := false
	for _, pattern := range confirm {
		if core.MatchPattern(pattern, action, nil) {
			held = true
			break
		}
	}
	if !held {
		return nil
	}
	reason, custom := "", false
	if a.options.ConfirmationReason != nil {
		reason, custom = a.options.ConfirmationReason(skill, params)
	}
	if !custom {
		if skill != nil && *skill != "" {
			reason = "Your agent wants to use the skill " + *skill + " of another agent (" + action + ")."
		} else {
			reason = "Your agent wants to send a message to another agent (" + action + ")."
		}
	}
	request, err := delegations.RequestConfirmation(ctx, caller.Credential, ConfirmationInput{
		TenantID: caller.TenantID, Action: action, Resource: resource, Reason: reason,
	})
	if err != nil {
		return nil
	}
	return &Confirmation{ID: request.ID, ExpiresAt: request.ExpiresAt}
}

func hasScopes(granted, required []string) bool {
	for _, scope := range required {
		if !contains(granted, scope) {
			return false
		}
	}
	return true
}

func (a *Authorizer) decide(ctx context.Context, caller *Caller, found *found, skill *string, params *core.Object, confirm bool) (A2aDecision, error) {
	if found == nil {
		return A2aDecision{Reason: "UNKNOWN_SKILL"}, nil
	}
	rule := found.rule
	if rule.Public {
		return A2aDecision{Allowed: true, Reason: "PUBLIC"}, nil
	}
	if caller.Kind == "oauth" {
		if len(rule.Scopes) == 0 {
			return A2aDecision{Reason: "NO_RULE_FOR_CALLER"}, nil
		}
		if hasScopes(caller.Scopes, rule.Scopes) {
			return A2aDecision{Allowed: true, Reason: "ALLOWED"}, nil
		}
		return A2aDecision{Reason: "INSUFFICIENT_SCOPE"}, nil
	}
	if rule.Action == "" {
		return A2aDecision{Reason: "NO_RULE_FOR_CALLER"}, nil
	}
	resource, err := a.resourceOf(found, params)
	if err != nil {
		return A2aDecision{Reason: "ACCESS_DENIED"}, nil
	}
	decision, err := a.options.Iam.Authorize(ctx, AuthorizeRequest{Credential: caller.Credential, TenantID: caller.TenantID,
		Action: rule.Action, Resource: resource})
	if err != nil {
		return A2aDecision{}, err
	}
	if decision.Allowed {
		return A2aDecision{Allowed: true, Reason: "ALLOWED"}, nil
	}
	if confirm {
		if confirmation := a.requestConfirmation(ctx, caller, skill, rule.Action, resource, params); confirmation != nil {
			return A2aDecision{Reason: "CONFIRMATION_REQUESTED", Confirmation: confirmation}, nil
		}
	}
	return A2aDecision{Reason: "ACCESS_DENIED"}, nil
}

// requestURL is request.url: the absolute URL of an incoming request.
func requestURL(request *http.Request) string {
	if request.URL.IsAbs() {
		return request.URL.String()
	}
	scheme := "http"
	if request.TLS != nil {
		scheme = "https"
	}
	return scheme + "://" + request.Host + request.URL.RequestURI()
}

// Authenticate reads a Better IAM credential first, then (with OAuth) an OAuth access token; nil when neither is
// valid.
func (a *Authorizer) Authenticate(request *http.Request) *Caller {
	ctx := request.Context()
	presented := presented(request)
	if presented == nil {
		return nil
	}
	if strings.ToLower(presented.scheme) == "bearer" {
		credential := core.CredentialInput{Token: presented.token, Headers: request.Header}
		caller, err := func() (*Caller, error) {
			principal, err := a.options.Iam.Authenticate(ctx, credential)
			if err != nil {
				return nil, err
			}
			tenantID := a.options.TenantID
			if a.options.TenantIDFunc != nil {
				tenantID, err = a.options.TenantIDFunc(TenantCaller{IdentityID: principal.Identity.ID, SessionTenantID: principal.Session.TenantID})
				if err != nil {
					return nil, err
				}
			}
			if tenantID == "" {
				return nil, nil
			}
			agentID := ""
			if principal.Session.Kind == "delegated" {
				agentID = principal.Session.AgentID
			} else if principal.Identity.Kind == "agent" {
				agentID = principal.Identity.ID
			}
			return &Caller{Kind: "iam", Credential: credential, TenantID: tenantID, IdentityID: principal.Identity.ID,
				IdentityKind: principal.Identity.Kind, SessionKind: principal.Session.Kind, AgentID: agentID,
				DelegationID: principal.Session.DelegationID}, nil
		}()
		if err == nil || a.options.OAuth == nil {
			return caller
		}
	}
	if a.options.OAuth == nil {
		return nil
	}
	token, err := a.options.OAuth.VerifyRequest(ctx, OAuthRequest{
		Authorization: strings.Join(request.Header.Values("authorization"), ", "),
		DPoP:          strings.Join(request.Header.Values("dpop"), ", "),
		Method:        request.Method,
		URL:           requestURL(request),
	})
	if err != nil || token == nil {
		return nil
	}
	// A token issued for another organization is not a token for this agent.
	if a.options.TenantIDFunc == nil && token.TenantID != "" && token.TenantID != a.options.TenantID {
		return nil
	}
	return &Caller{Kind: "oauth", ClientID: token.ClientID, Scopes: append([]string{}, token.Scopes...), Subject: token.Subject,
		TenantID: token.TenantID}
}

// CanSend is whether the caller may send a message with these params (asking for a confirmation when that applies).
// A request naming two different skills (in the message's and the request's metadata) is refused as
// AMBIGUOUS_SKILL, so the gate and the server cannot disagree on which skill runs.
func (a *Authorizer) CanSend(ctx context.Context, caller *Caller, params *core.Object) (A2aDecision, error) {
	// A skill id that is not a string (an array, a number) would pass as "no skill" (the message rule) while the
	// server may still coerce it to a skill name: refuse it like two different skills.
	if a.options.SkillOf == nil {
		names := namedSkills(params)
		for _, name := range names {
			if _, isString := name.(string); !isString {
				return A2aDecision{Reason: "AMBIGUOUS_SKILL"}, nil
			}
		}
		if len(names) == 2 && names[0] != names[1] {
			return A2aDecision{Reason: "AMBIGUOUS_SKILL"}, nil
		}
	}
	skill := a.skillOf(params)
	return a.decide(ctx, caller, a.ruleFor(skill), skill, params, true)
}

// IsTaskAdmin is whether the caller may read and cancel every task (TaskAdminAction).
func (a *Authorizer) IsTaskAdmin(ctx context.Context, caller *Caller) (bool, error) {
	if a.options.TaskAdminAction == "" || caller.Kind != "iam" {
		return false, nil
	}
	rule := a.options.Message
	rule.Action = a.options.TaskAdminAction
	rule.Public = false
	decision, err := a.decide(ctx, caller, &found{rule: rule}, nil, core.NewObject(), false)
	return decision.Allowed, err
}

// skillKey identifies a skill id value (Set membership by value).
func skillKey(value any) string {
	if core.IsUndefined(value) {
		return "undefined"
	}
	text, _, err := core.Stringify(value)
	if err != nil {
		return jsString(value)
	}
	return text
}

// VisibleSkills are the skills the caller may use, in order (checked 50 at a time). Skills are model values with an
// id (a card's skills).
func (a *Authorizer) VisibleSkills(ctx context.Context, caller *Caller, skills []any) ([]any, error) {
	type check struct {
		key      string
		action   string
		resource ResourceRef
	}
	visible := map[string]bool{}
	var checks []check
	idOf := func(skill any) (any, error) {
		if skill == nil || core.IsUndefined(skill) {
			return nil, &core.TypeError{Message: "Cannot read properties of null (reading 'id')"}
		}
		if object, ok := plain(skill); ok {
			return object.Get("id"), nil
		}
		return core.Undefined, nil
	}
	for _, skill := range skills {
		id, err := idOf(skill)
		if err != nil {
			return nil, err
		}
		var name *string
		if !core.IsUndefined(id) {
			text := jsString(id)
			name = &text
		}
		found := a.ruleFor(name)
		if found == nil {
			continue
		}
		rule := found.rule
		key := skillKey(id)
		if rule.Public {
			visible[key] = true
		} else if caller.Kind == "oauth" {
			if len(rule.Scopes) > 0 && hasScopes(caller.Scopes, rule.Scopes) {
				visible[key] = true
			}
		} else if rule.Action != "" {
			if rule.ResourceFunc != nil {
				visible[key] = true
			} else {
				resource, err := a.resourceOf(found, core.NewObject())
				if err != nil {
					return nil, err
				}
				checks = append(checks, check{key: key, action: rule.Action, resource: resource})
			}
		}
	}
	if caller.Kind == "iam" {
		for index := 0; index < len(checks); index += 50 {
			batch := checks[index:min(index+50, len(checks))]
			request := AuthorizeManyRequest{Credential: caller.Credential, TenantID: caller.TenantID}
			for _, item := range batch {
				request.Checks = append(request.Checks, AuthorizeCheck{Action: item.action, Resource: item.resource})
			}
			results, err := a.options.Iam.AuthorizeMany(ctx, request)
			if err != nil {
				return nil, err
			}
			for position, item := range batch {
				if position < len(results) && results[position].Allowed {
					visible[item.key] = true
				}
			}
		}
	}
	out := []any{}
	for _, skill := range skills {
		id, _ := idOf(skill)
		if visible[skillKey(id)] {
			out = append(out, skill)
		}
	}
	return out, nil
}

var errNoResponse = errors.New("a2a: the server's handler returned no response")

// Next is the A2A server's handler behind the gate: it answers the forwarded request for the authenticated caller.
type Next func(request *http.Request, caller *Caller) (*http.Response, error)

// Gate is createA2aGate: Serve answers the request itself (the agent card, challenges, refusals) or passes it to
// next with the authenticated caller, recording who started each task on the way back.
type Gate struct {
	options      GateOptions
	authorizer   *Authorizer
	owners       TaskOwners
	maxBodyBytes int64
}

// CreateGate builds the gate.
func CreateGate(options GateOptions) *Gate {
	owners := options.Tasks
	if owners == nil {
		owners = MemoryTaskOwners(MemoryTaskOwnersOptions{})
	}
	maxBodyBytes := options.MaxBodyBytes
	if maxBodyBytes == 0 {
		maxBodyBytes = 4 * 1024 * 1024
	}
	return &Gate{options: options, authorizer: CreateAuthorizer(options), owners: owners, maxBodyBytes: maxBodyBytes}
}

// Authorizer is the gate's decisions.
func (g *Gate) Authorizer() *Authorizer { return g.authorizer }

// newResponse is new Response(body, { status, headers }).
func newResponse(status int, header http.Header, body []byte) *http.Response {
	return &http.Response{
		Status: strconv.Itoa(status) + " " + http.StatusText(status), StatusCode: status, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: header, Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)),
	}
}

// jsonResponse is json(body, status, headers): JSON.stringify(body) as application/json.
func jsonResponse(body any, status int, headers ...string) *http.Response {
	header := http.Header{}
	header.Set("content-type", "application/json")
	for index := 0; index+1 < len(headers); index += 2 {
		header.Set(headers[index], headers[index+1])
	}
	text, ok, err := core.Stringify(body)
	if err != nil || !ok {
		text = ""
	}
	return newResponse(status, header, []byte(text))
}

// rpcError is a JSON-RPC error answer.
func rpcError(id any, code int, message string, data *core.Object, status int) *http.Response {
	if id == nil || core.IsUndefined(id) {
		id = nil
	}
	errorBody := core.NewObject("code", float64(code), "message", message)
	if data != nil {
		errorBody.Set("data", data)
	}
	return jsonResponse(core.NewObject("jsonrpc", "2.0", "id", id, "error", errorBody), status)
}

func (g *Gate) challenge(errorCode string) *http.Response {
	authenticate := "Bearer"
	body := "unauthorized"
	if errorCode != "" {
		authenticate = `Bearer error="` + errorCode + `"`
		body = errorCode
	}
	return jsonResponse(core.NewObject("error", body, "error_description", "Present a Better IAM credential or an OAuth access token"), 401,
		"cache-control", "no-store", "www-authenticate", authenticate)
}

func (g *Gate) onError(err error) {
	if g.options.OnError != nil {
		g.options.OnError(err)
	}
}

func cardOf(ctx context.Context, card *core.Object, build func(context.Context) (*core.Object, error)) (*core.Object, error) {
	if build != nil {
		return build(ctx)
	}
	return card, nil
}

// ownedKeysOf are the owner keys a JSON-RPC result names: its task (a task's id, or the taskId of a message or task
// event) and its conversation (contextId).
func ownedKeysOf(result any) []string {
	object, ok := plain(result)
	if !ok {
		return nil
	}
	var keys []string
	taskID := object.Get("taskId")
	if object.Get("kind") == "task" {
		taskID = object.Get("id")
	}
	if text, ok := taskID.(string); ok && text != "" {
		keys = append(keys, "task:"+text)
	}
	if text, ok := object.Get("contextId").(string); ok && text != "" {
		keys = append(keys, "context:"+text)
	}
	return keys
}

func (g *Gate) remember(ctx context.Context, keys []string, owner string) error {
	for _, key := range keys {
		_, known, err := g.owners.Get(ctx, key)
		if err != nil {
			return err
		}
		if !known {
			if err := g.owners.Set(ctx, key, owner); err != nil {
				return err
			}
		}
	}
	return nil
}

// rememberMessage records the owner of the task and conversation a JSON-RPC message (JSON text) names; unparseable
// messages and store failures are passed over.
func (g *Gate) rememberMessage(ctx context.Context, text string, owner string) {
	parsed, err := core.ParseJSONString(text)
	if err != nil || parsed == nil {
		return
	}
	var result any = core.Undefined
	if object, ok := plain(parsed); ok {
		result = object.Get("result")
	}
	_ = g.remember(ctx, ownedKeysOf(result), owner)
}

func contentType(response *http.Response) string {
	return strings.Join(response.Header.Values("content-type"), ", ")
}

// observe records the owner of every task and conversation a response names, in a JSON body or an event stream,
// without changing it.
func (g *Gate) observe(ctx context.Context, response *http.Response, owner string) (*http.Response, error) {
	kind := contentType(response)
	if strings.Contains(kind, "application/json") {
		var raw []byte
		if response.Body != nil {
			var err error
			raw, err = io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil {
				return nil, err
			}
		}
		text := textDecode(raw)
		g.rememberMessage(ctx, text, owner)
		return newResponse(response.StatusCode, response.Header, utf8Bytes(text)), nil
	}
	if !strings.Contains(kind, "text/event-stream") || response.Body == nil || response.Body == http.NoBody {
		return response, nil
	}
	observed := *response
	observed.Body = &eventObserver{ctx: ctx, gate: g, owner: owner, source: response.Body, first: true}
	return &observed, nil
}

var eventBoundary = regexp.MustCompile(`\r?\n\r?\n`)
var lineBreak = regexp.MustCompile(`\r?\n`)

// eventObserver passes an event stream on unchanged, recording the owners each event names before the bytes that
// complete it reach the reader.
type eventObserver struct {
	ctx     context.Context
	gate    *Gate
	owner   string
	source  io.ReadCloser
	buffer  []byte
	first   bool
	flushed bool
}

func (o *eventObserver) inspect(event []byte) {
	var lines []string
	for _, line := range lineBreak.Split(textDecode(event), -1) {
		if strings.HasPrefix(line, "data:") {
			lines = append(lines, strings.TrimPrefix(line[5:], " "))
		}
	}
	data := strings.Join(lines, "\n")
	if data == "" {
		return
	}
	o.gate.rememberMessage(o.ctx, data, o.owner)
}

func (o *eventObserver) Read(p []byte) (int, error) {
	n, err := o.source.Read(p)
	if n > 0 {
		chunk := p[:n]
		if o.first {
			o.first = false
			// TextDecoder drops a leading byte order mark.
			if bytes.HasPrefix(chunk, []byte{0xEF, 0xBB, 0xBF}) {
				o.buffer = append(o.buffer, chunk[3:]...)
			} else {
				o.buffer = append(o.buffer, chunk...)
			}
		} else {
			o.buffer = append(o.buffer, chunk...)
		}
		for {
			boundary := eventBoundary.FindIndex(o.buffer)
			if boundary == nil {
				break
			}
			event := append([]byte{}, o.buffer[:boundary[0]]...)
			o.buffer = o.buffer[boundary[1]:]
			// Recorded before the event reaches the caller, so a follow-up request can already use the task.
			o.inspect(event)
		}
	}
	if err == io.EOF && !o.flushed {
		o.flushed = true
		if core.JSTrim(textDecode(o.buffer)) != "" {
			o.inspect(o.buffer)
		}
		o.buffer = nil
	}
	return n, err
}

func (o *eventObserver) Close() error { return o.source.Close() }

// ownsTask is whether the caller started the task (or is a task administrator); unknown tasks belong to no one.
func (g *Gate) ownsTask(ctx context.Context, caller *Caller, taskID any) (bool, error) {
	text, ok := taskID.(string)
	if !ok || text == "" {
		return false, nil
	}
	owner, known, err := g.owners.Get(ctx, "task:"+text)
	if err != nil {
		return false, err
	}
	if known && owner == TaskOwnerOf(caller) {
		return true, nil
	}
	return g.authorizer.IsTaskAdmin(ctx, caller)
}

// mayJoin is whether the caller may add to a conversation: one they started, or as a task administrator.
// Conversations are started by the server (its answers name them), so an unknown one belongs to no one.
func (g *Gate) mayJoin(ctx context.Context, caller *Caller, contextID any) (bool, error) {
	text, ok := contextID.(string)
	if !ok || text == "" {
		return false, nil
	}
	owner, known, err := g.owners.Get(ctx, "context:"+text)
	if err != nil {
		return false, err
	}
	if known && owner == TaskOwnerOf(caller) {
		return true, nil
	}
	return g.authorizer.IsTaskAdmin(ctx, caller)
}

// jsNumber is Number(value) for a header value: "" is 0, an unparseable value NaN (never larger than a limit).
func headerNumber(value string) (float64, bool) {
	trimmed := core.JSTrim(value)
	if trimmed == "" {
		return 0, true
	}
	number, err := strconv.ParseFloat(trimmed, 64)
	if err != nil {
		return 0, false
	}
	return number, true
}

// boundedBody is the request body as text, or ok false when it is larger than maxBytes (read no further than that).
func boundedBody(request *http.Request, maxBytes int64) (string, bool, error) {
	if declared, ok := headerNumber(request.Header.Get("content-length")); ok && declared > float64(maxBytes) {
		return "", false, nil
	}
	if request.Body == nil || request.Body == http.NoBody {
		return "", true, nil
	}
	raw, err := io.ReadAll(io.LimitReader(request.Body, maxBytes+1))
	if err != nil {
		return "", false, err
	}
	if int64(len(raw)) > maxBytes {
		_ = request.Body.Close()
		return "", false, nil
	}
	return textDecode(raw), true, nil
}

// Serve answers the request itself (the agent card, challenges, refusals) or passes it to next (the A2A server's
// handler) with the authenticated caller, recording who started each task on the way back. Errors of next on the
// paths that pass requests on unchecked (OtherMethods and OtherHTTPMethods "allow") are returned as they are.
func (g *Gate) Serve(request *http.Request, next Next) (*http.Response, error) {
	ctx := request.Context()
	if g.options.Card != nil || g.options.CardFunc != nil {
		// url.pathname is the percent-encoded path.
		path := request.URL.EscapedPath()
		if path == "/.well-known/agent-card.json" || path == "/.well-known/agent.json" {
			if request.Method == http.MethodOptions {
				header := http.Header{}
				header.Set("access-control-allow-origin", "*")
				header.Set("access-control-allow-methods", "GET, OPTIONS")
				return newResponse(204, header, nil), nil
			}
			if request.Method != http.MethodGet && request.Method != http.MethodHead {
				return jsonResponse(core.NewObject("error", "method not allowed"), 405, "allow", "GET, OPTIONS"), nil
			}
			card, err := cardOf(ctx, g.options.Card, g.options.CardFunc)
			if err != nil {
				g.onError(err)
				return jsonResponse(core.NewObject("error", "agent card unavailable"), 503, "retry-after", "30"), nil
			}
			var body any = core.Undefined
			if card != nil {
				body = card
			}
			return jsonResponse(body, 200, "access-control-allow-origin", "*", "cache-control", "public, max-age=300"), nil
		}
	}
	if presented(request) == nil {
		return g.challenge(""), nil
	}
	caller := g.authorizer.Authenticate(request)
	if caller == nil {
		return g.challenge("invalid_token"), nil
	}
	if request.Method != http.MethodPost {
		if g.options.OtherHTTPMethods == "allow" {
			return next(request, caller)
		}
		return jsonResponse(core.NewObject("error", "method not allowed"), 405, "allow", "POST"), nil
	}
	text, within, err := boundedBody(request, g.maxBodyBytes)
	if err != nil {
		return nil, err
	}
	if !within {
		return jsonResponse(core.NewObject("error", "request too large"), 413), nil
	}
	parsed, err := core.ParseJSONString(text)
	if err != nil {
		return rpcError(nil, -32700, "Parse error", nil, 200), nil
	}
	message, ok := plain(parsed)
	method, methodIsString := "", false
	if ok {
		method, methodIsString = message.Get("method").(string)
	}
	if !ok || !methodIsString {
		return rpcError(nil, -32600, "Invalid Request: A2A takes one JSON-RPC request per call", nil, 200), nil
	}
	id := message.Get("id")
	params, ok := plain(message.Get("params"))
	if !ok {
		params = core.NewObject()
	}
	owner := TaskOwnerOf(caller)
	// The server receives the request exactly as the gate read it (no duplicate keys a different parser could pick).
	body := []byte(core.MustStringify(parsed))
	forward := request.Clone(ctx)
	forward.Method = http.MethodPost
	forward.Header = request.Header.Clone()
	forward.Header.Del("content-length")
	if len(forward.Header.Values("content-type")) == 0 {
		forward.Header.Set("content-type", "text/plain;charset=UTF-8")
	}
	forward.Body = io.NopCloser(bytes.NewReader(body))
	forward.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	forward.ContentLength = int64(len(body))
	response, handled, err := g.serveMethod(ctx, caller, method, id, params, owner, forward, next)
	if err != nil {
		var known *core.IamError
		if errors.As(err, &known) && (known.Status == 401 || known.Code == "UNAUTHENTICATED") {
			return g.challenge("invalid_token"), nil
		}
		g.onError(err)
		return rpcError(id, -32603, "Internal error", nil, 500), nil
	}
	if handled {
		return response, nil
	}
	if g.options.OtherMethods == "allow" {
		return next(forward, caller)
	}
	return rpcError(id, -32601, "Method not found", nil, 200), nil
}

// serveMethod answers the A2A methods; handled is false for methods A2A does not define.
func (g *Gate) serveMethod(ctx context.Context, caller *Caller, method string, id any, params *core.Object, owner string,
	forward *http.Request, next Next) (*http.Response, bool, error) {
	if messageMethods[method] {
		sent, ok := plain(params.Get("message"))
		if !ok {
			sent = core.NewObject()
		}
		// Continuing a task or a conversation, or pointing at earlier tasks: only whoever started them may.
		if taskID := sent.Get("taskId"); !core.IsUndefined(taskID) {
			owns, err := g.ownsTask(ctx, caller, taskID)
			if err != nil {
				return nil, true, err
			}
			if !owns {
				return rpcError(id, -32001, "Task not found", nil, 200), true, nil
			}
		}
		if contextID := sent.Get("contextId"); !core.IsUndefined(contextID) {
			joins, err := g.mayJoin(ctx, caller, contextID)
			if err != nil {
				return nil, true, err
			}
			if !joins {
				return rpcError(id, -32602, "Invalid params: unknown context", nil, 200), true, nil
			}
		}
		if references := sent.Get("referenceTaskIds"); !core.IsUndefined(references) {
			list, isArray := references.([]any)
			if !isArray || len(list) > 100 {
				return rpcError(id, -32602, "Invalid params: referenceTaskIds", nil, 200), true, nil
			}
			for _, reference := range list {
				owns, err := g.ownsTask(ctx, caller, reference)
				if err != nil {
					return nil, true, err
				}
				if !owns {
					return rpcError(id, -32001, "Task not found", nil, 200), true, nil
				}
			}
		}
		decision, err := g.authorizer.CanSend(ctx, caller, params)
		if err != nil {
			return nil, true, err
		}
		if !decision.Allowed {
			if decision.Confirmation != nil {
				return rpcError(id, A2AConfirmationRequested,
					"The person you act for must confirm this request first. Retry after they approve it.",
					core.NewObject("reason", decision.Reason, "confirmationId", decision.Confirmation.ID, "expiresAt", decision.Confirmation.ExpiresAt),
					403), true, nil
			}
			message := "Access denied"
			switch decision.Reason {
			case "UNKNOWN_SKILL":
				message = "Unknown skill"
			case "AMBIGUOUS_SKILL":
				message = "The request names two different skills"
			}
			return rpcError(id, A2AAccessDenied, message, core.NewObject("reason", decision.Reason), 403), true, nil
		}
		response, err := next(forward, caller)
		if err == nil && response == nil {
			err = errNoResponse
		}
		if err != nil {
			return nil, true, err
		}
		observed, err := g.observe(ctx, response, owner)
		return observed, true, err
	}
	if taskMethods[method] {
		taskID := params.Get("id")
		if method == "tasks/pushNotificationConfig/set" {
			taskID = params.Get("taskId")
		}
		owns, err := g.ownsTask(ctx, caller, taskID)
		if err != nil {
			return nil, true, err
		}
		if !owns {
			return rpcError(id, -32001, "Task not found", nil, 200), true, nil
		}
		response, err := next(forward, caller)
		return response, true, err
	}
	if method == extendedCardMethod {
		if id == nil || core.IsUndefined(id) {
			id = nil
		}
		if g.options.ExtendedCard != nil || g.options.ExtendedCardFunc != nil {
			card, err := cardOf(ctx, g.options.ExtendedCard, g.options.ExtendedCardFunc)
			if err != nil {
				return nil, true, err
			}
			result := core.NewObject()
			var skills any = core.Undefined
			if card != nil {
				result = card.Spread()
				skills = card.Get("skills")
			}
			list, err := skillList(skills)
			if err != nil {
				return nil, true, err
			}
			visible, err := g.authorizer.VisibleSkills(ctx, caller, list)
			if err != nil {
				return nil, true, err
			}
			result.Set("skills", visible)
			return jsonResponse(core.NewObject("jsonrpc", "2.0", "id", id, "result", result), 200), true, nil
		}
		response, err := next(forward, caller)
		if err == nil && response == nil {
			err = errNoResponse
		}
		if err != nil {
			return nil, true, err
		}
		if !strings.Contains(contentType(response), "application/json") {
			return response, true, nil
		}
		var raw []byte
		if response.Body != nil {
			raw, err = io.ReadAll(response.Body)
			_ = response.Body.Close()
			if err != nil {
				return nil, true, err
			}
		}
		body, err := core.ParseJSONString(textDecode(raw))
		if err != nil {
			return nil, true, err
		}
		if body == nil {
			return nil, true, &core.TypeError{Message: "Cannot read properties of null (reading 'result')"}
		}
		if object, ok := plain(body); ok {
			if result, ok := plain(object.Get("result")); ok {
				if skills, isArray := result.Get("skills").([]any); isArray {
					visible, err := g.authorizer.VisibleSkills(ctx, caller, skills)
					if err != nil {
						return nil, true, err
					}
					object.Set("result", result.Spread(core.NewObject("skills", visible)))
				}
			}
		}
		return jsonResponse(body, response.StatusCode), true, nil
	}
	return nil, false, nil
}

// skillList is `card?.skills ?? []` iterated: an array, or none.
func skillList(skills any) ([]any, error) {
	switch value := skills.(type) {
	case nil, core.UndefinedType:
		return nil, nil
	case []any:
		return value, nil
	}
	return nil, &core.TypeError{Message: "card.skills is not iterable"}
}

type callerKey struct{}

// CallerOf is the caller the gate authenticated, in the context of a request Middleware passed on.
func CallerOf(ctx context.Context) (*Caller, bool) {
	caller, ok := ctx.Value(callerKey{}).(*Caller)
	return caller, ok && caller != nil
}

// Middleware puts the gate in front of an http.Handler (the A2A server); the handler reads the caller with CallerOf.
// Responses pass through as they are produced, so event streams keep streaming.
func (g *Gate) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		response, err := g.Serve(r, func(forward *http.Request, caller *Caller) (*http.Response, error) {
			return runHandler(next, forward.WithContext(context.WithValue(forward.Context(), callerKey{}, caller)))
		})
		if err != nil {
			g.onError(err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		writeResponse(w, response)
	})
}

// writeResponse sends a response, flushing as the body arrives.
func writeResponse(w http.ResponseWriter, response *http.Response) {
	header := w.Header()
	for name, values := range response.Header {
		header[name] = append([]string(nil), values...)
	}
	if response.ContentLength >= 0 {
		header.Set("content-length", strconv.FormatInt(response.ContentLength, 10))
	} else {
		header.Del("content-length")
	}
	w.WriteHeader(response.StatusCode)
	if response.Body == nil {
		return
	}
	defer response.Body.Close()
	flusher, _ := w.(http.Flusher)
	buffer := make([]byte, 32*1024)
	for {
		n, err := response.Body.Read(buffer)
		if n > 0 {
			if _, writeErr := w.Write(buffer[:n]); writeErr != nil {
				return
			}
			if flusher != nil {
				flusher.Flush()
			}
		}
		if err != nil {
			return
		}
	}
}

// pipeWriter is the http.ResponseWriter runHandler gives a handler: the response is ready once the handler commits
// its headers, and its body streams through a pipe.
type pipeWriter struct {
	header    http.Header
	pipe      *io.PipeWriter
	once      sync.Once
	committed chan *http.Response
	reader    *io.PipeReader
	length    int64
}

func (p *pipeWriter) Header() http.Header { return p.header }

func (p *pipeWriter) WriteHeader(status int) {
	if status >= 100 && status < 200 && status != http.StatusSwitchingProtocols {
		return
	}
	p.once.Do(func() {
		header := p.header.Clone()
		length := int64(-1)
		if declared := header.Get("content-length"); declared != "" {
			if parsed, err := strconv.ParseInt(declared, 10, 64); err == nil {
				length = parsed
			}
		}
		response := &http.Response{
			Status: strconv.Itoa(status) + " " + http.StatusText(status), StatusCode: status, Proto: "HTTP/1.1", ProtoMajor: 1,
			ProtoMinor: 1, Header: header, Body: p.reader, ContentLength: length,
		}
		p.committed <- response
	})
}

func (p *pipeWriter) Write(data []byte) (int, error) {
	p.WriteHeader(http.StatusOK)
	return p.pipe.Write(data)
}

func (p *pipeWriter) Flush() { p.WriteHeader(http.StatusOK) }

// runHandler runs an http.Handler as a fetch-style handler.
func runHandler(handler http.Handler, request *http.Request) (*http.Response, error) {
	reader, writer := io.Pipe()
	w := &pipeWriter{header: http.Header{}, pipe: writer, committed: make(chan *http.Response, 1), reader: reader}
	failed := make(chan error, 1)
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil {
				err := errors.New("a2a: the handler panicked")
				if asError, ok := recovered.(error); ok {
					err = errors.Join(err, asError)
				}
				failed <- err
				_ = writer.CloseWithError(err)
				return
			}
			w.WriteHeader(http.StatusOK)
			_ = writer.Close()
		}()
		handler.ServeHTTP(w, request)
	}()
	select {
	case response := <-w.committed:
		return response, nil
	case err := <-failed:
		select {
		case response := <-w.committed:
			return response, nil
		default:
			return nil, err
		}
	case <-request.Context().Done():
		return nil, request.Context().Err()
	}
}
