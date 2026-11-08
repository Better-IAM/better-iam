package server

// Port of packages/server/src/inference-gateway.ts: the inference gateway, an HTTP handler (request → response) that
// lets any Better IAM credential (a person's session, a service account or agent key, a delegated agent session) call
// AI models without ever holding a provider key. It authenticates the caller, checks `inference:invoke` on
// `model/{name}` and the covering budgets, forwards the request to the provider with the sealed key, streams the
// answer back unchanged, and meters the tokens the provider reports. Requests pass through in the provider's own wire
// format: Anthropic Messages (`POST /v1/messages`, and `POST /v1/messages/count_tokens`, checked but not metered) for
// models on an `anthropic` provider; OpenAI Chat Completions (`POST /v1/chat/completions`), Responses
// (`POST /v1/responses`) and Embeddings (`POST /v1/embeddings`) for `openai` and `openai-compatible` providers.
// `GET /v1/models` lists the models the caller may use.
//
// Responses API conversations live at the provider under the organization's key, so the gateway keeps them apart:
// `previous_response_id` must name a response the same caller created through the gateway, and the `conversation`
// parameter and `background` mode are refused (their state and usage are out of the gateway's sight).
//
// The gateway runtime (`GatewayRuntime`, api/inference.ts createInferenceRuntime) is the server-side half the gateway
// calls: its permits are `{ principal, tenantId, check, upstreamModel, provider }` objects whose `principal` member
// holds the *Principal and whose `provider` is the ProviderCredential (never expose it).

import (
	"bytes"
	"context"
	"errors"
	"io"
	"math"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// GatewayFetch is the gateway's upstream transport (InferenceGatewayOptions.fetch): it sends one request and returns
// the response headers with a streaming body. Inject one (as the `fetch` member of the gateway options) for proxies
// or tests; an injected transport replaces both the default and the SSRF guard and must enforce its own address
// rules.
type GatewayFetch func(request *http.Request) (*http.Response, error)

// GatewayRuntime is inference-gateway.ts GatewayRuntime: what the gateway needs from `iam.inference`.
type GatewayRuntime struct {
	server *ServerContext
}

// NewGatewayRuntime is the gateway runtime over a server context (api/inference.ts createInferenceRuntime's
// authorize, record, models and ownsResponse).
func NewGatewayRuntime(server *ServerContext) *GatewayRuntime {
	return &GatewayRuntime{server: server}
}

// permitPrincipal is a permit's `principal`.
func permitPrincipal(permit *core.Object) *Principal {
	principal, _ := permit.Get("principal").(*Principal)
	return principal
}

// Authorize (inference-gateway.ts GatewayRuntime.authorize, api/inference.ts createInferenceRuntime().authorize):
// Authenticates `credential`, checks `model` for it in the credential's tenant (or `tenantId`), with the
// provider-run `tools` the request asks for, and on success returns the permit with the provider's opened key; a
// refused check answers `{ denied: check }`. Throws FEATURE_DISABLED when inference is off. input is `{ model,
// tenantId?, estimatedTokens?, tools? }`.
func (s *GatewayRuntime) Authorize(ctx context.Context, credential core.CredentialInput, input *core.Object) (*core.Object, error) {
	server := s.server
	if err := AssertInference(server); err != nil {
		return nil, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return nil, err
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		tenantID := jsString(coalesce(input.Get("tenantId"), principal.Session.Get("tenantId")))
		checkInput := core.NewObject("tenantId", tenantID, "model", input.Get("model"))
		if value := input.Get("estimatedTokens"); !isUndefined(value) {
			checkInput.Set("estimatedTokens", value)
		}
		if value := input.Get("tools"); !isUndefined(value) {
			checkInput.Set("tools", value)
		}
		check, err := CheckInvocation(ctx, server, tx, principal, checkInput)
		if err != nil {
			return nil, err
		}
		if check.Get("allowed") != true {
			return core.NewObject("denied", check), nil
		}
		found, err := ResolveModel(ctx, server, tx, tenantID, jsString(member(check.Get("model"), "name")))
		if err != nil {
			return nil, err
		}
		var model, provider *core.Object
		if found != nil {
			model, provider = foundParts(found)
		}
		if provider == nil {
			return nil, core.NewIamError("NOT_FOUND", "Model provider not found", 404)
		}
		credential, err := ProviderCredential(ctx, server, tx, provider)
		if err != nil {
			return nil, err
		}
		permit := core.NewObject()
		permit.SetRaw("principal", principal)
		permit.Set("tenantId", tenantID)
		permit.Set("check", check)
		permit.Set("upstreamModel", model.Get("upstreamModel"))
		permit.Set("provider", credential)
		return permit, nil
	})
}

// Record (inference-gateway.ts GatewayRuntime.record, api/inference.ts createInferenceRuntime().record): Meters a
// call made under a permit (`{ principal, tenantId }`); usage is the InvocationRecord without `tenantId`. Answers
// the stored usage record.
func (s *GatewayRuntime) Record(ctx context.Context, permit *core.Object, usage *core.Object) (any, error) {
	server := s.server
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		return RecordInvocation(ctx, server, tx, permitPrincipal(permit), usage.Spread(core.NewObject("tenantId", permit.Get("tenantId"))))
	})
}

// Models (inference-gateway.ts GatewayRuntime.models, api/inference.ts createInferenceRuntime().models): The enabled
// models a credential may invoke in its session's tenant.
func (s *GatewayRuntime) Models(ctx context.Context, credential core.CredentialInput) ([]*core.Object, error) {
	server := s.server
	if err := AssertInference(server); err != nil {
		return nil, err
	}
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return nil, err
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) ([]*core.Object, error) {
		principal, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return nil, err
		}
		return gatewayInvocableModels(ctx, server, tx, principal, jsString(principal.Session.Get("tenantId")))
	})
}

// gatewayInvocableModels is api/inference.ts invocableModels: the enabled models visible from a tenant that a
// principal may invoke, decided with one prepared decision.
func gatewayInvocableModels(ctx context.Context, server *ServerContext, tx core.IamStore, principal *Principal, tenantID string) ([]*core.Object, error) {
	tenant, err := server.Tenant(ctx, tx, tenantID)
	if err != nil {
		return nil, err
	}
	prepared, err := server.Decisions.PrepareDecision(ctx, tx, principal, tenant, InferenceAction)
	if err != nil {
		return nil, err
	}
	// Security clearances: label every model under the scheme the prepared decision already read.
	labeling := PreparedLabeling(prepared)
	result := []*core.Object{}
	visible, err := VisibleModels(ctx, server, tx, tenantID)
	if err != nil {
		return nil, err
	}
	for _, found := range visible {
		model, provider := foundParts(found)
		view, err := PublicModel(model, provider, tenantID)
		if err != nil {
			return nil, err
		}
		if !truthy(view.Get("enabled")) {
			continue
		}
		resource, err := server.Decisions.Resolve(ctx, tx, core.ResourceRef{TenantID: tenantID, Type: InferenceResourceType,
			ID: jsString(model.Get("name"))}, false, "", labeling)
		if err != nil {
			return nil, err
		}
		decision, err := DecideOn(prepared, *resource, "")
		if err != nil {
			return nil, err
		}
		if decision.Allowed {
			result = append(result, view)
		}
	}
	return result, nil
}

// OwnsResponse (inference-gateway.ts GatewayRuntime.ownsResponse): Whether an OpenAI Responses API response id was
// created through the gateway by the same caller (the same person, through the same agent if any) at the permit's
// provider. Without it the gateway refuses `previous_response_id`.
func (s *GatewayRuntime) OwnsResponse(ctx context.Context, permit *core.Object, responseID string) (bool, error) {
	server := s.server
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (bool, error) {
		return OwnsInferenceResponse(ctx, server, tx, permitPrincipal(permit), jsString(permit.Get("tenantId")), responseID,
			jsString(member(permit.Get("provider"), "id")))
	})
}

// gatewayFormat is an error shape (and which providers serve an endpoint): Anthropic or OpenAI.
type gatewayFormat = string

// gatewayEndpoint is one passthrough route.
type gatewayEndpoint struct {
	path string
	// format is the error shape, and which providers serve it: `anthropic` providers, or `openai` /
	// `openai-compatible` ones.
	format gatewayFormat
	// usage is where usage is reported (UsageFormat); "" for calls that are checked but cost nothing (not metered).
	usage string
	// outputFields are request fields that limit output tokens (capped at the model's `maxOutputTokens`).
	outputFields []string
	// defaultOutputField is the field set to the model's cap when the request has none (by provider kind); nil to
	// leave it unset.
	defaultOutputField func(kind string) string
}

var gatewayEndpoints = map[string]*gatewayEndpoint{
	"/v1/messages": {
		path: "/v1/messages", format: "anthropic", usage: "anthropic", outputFields: []string{"max_tokens"},
		defaultOutputField: func(string) string { return "max_tokens" },
	},
	"/v1/messages/count_tokens": {path: "/v1/messages/count_tokens", format: "anthropic", outputFields: []string{}},
	"/v1/chat/completions": {
		path: "/v1/chat/completions", format: "openai", usage: "openai", outputFields: []string{"max_tokens", "max_completion_tokens"},
		// OpenAI's own API prefers max_completion_tokens; compatible servers commonly know only max_tokens.
		defaultOutputField: func(kind string) string {
			if kind == "openai" {
				return "max_completion_tokens"
			}
			return "max_tokens"
		},
	},
	"/v1/responses": {
		path: "/v1/responses", format: "openai", usage: "responses", outputFields: []string{"max_output_tokens"},
		defaultOutputField: func(string) string { return "max_output_tokens" },
	},
	"/v1/embeddings": {path: "/v1/embeddings", format: "openai", usage: "openai", outputFields: []string{}},
}

// gatewayResponseIDPattern is the shape of provider-side ids of Responses API objects: letters, digits, `_` and `-`.
var gatewayResponseIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,200}$`)

// gatewayToolLimits is how many tools and MCP servers a request may list: all of them are read, so more are refused.
const (
	gatewayMaxTools      = 256
	gatewayMaxMcpServers = 64
)

// utf16Map lowercases nothing; it replaces every UTF-16 unit of s outside keep with '_' (a regex replace without the
// u flag, where an astral character is two units) and returns at most max units.
func utf16Map(s string, keep func(c uint16) bool, max int) string {
	units := core.ToUTF16(s)
	var out strings.Builder
	for index, unit := range units {
		if index >= max {
			break
		}
		if unit < 0x80 && keep(unit) {
			out.WriteByte(byte(unit))
		} else {
			out.WriteByte('_')
		}
	}
	return out.String()
}

// mcpHost is the host of a remote MCP server URL (lowercase, without a trailing dot), or `invalid` for anything but a
// plain http(s) URL in canonical form: user info, backslashes, encoded hosts or default ports would let the host
// checked here differ from the one a provider connects to.
func mcpHost(value any) string {
	text, ok := value.(string)
	if !ok {
		return "invalid"
	}
	u, err := auth.ParseFetchURL(text)
	if err != nil {
		return "invalid"
	}
	canonical := core.JSLower(u.Href)
	given := core.JSLower(text)
	if (u.Protocol != "https:" && u.Protocol != "http:") || urlUsername(u) != "" || urlPassword(u) != "" || u.Hostname == "" ||
		(canonical != given && canonical != given+"/") {
		return "invalid"
	}
	host := strings.TrimSuffix(core.JSLower(u.Hostname), ".")
	return utf16Map(host, func(c uint16) bool {
		return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == ':' || c == '-'
	}, 200)
}

// StoredReference (inference-gateway.ts storedReference): The first reference in a request to an object stored at
// the provider under the organization's key, which the gateway cannot tie to the caller: `item_reference` inputs,
// `file_id`s and `file_ids` wherever they appear (message parts, function outputs, image masks, code-interpreter
// containers), `vector_store_ids` (file search), `file` sources (Anthropic, including inside tool results), and
// existing code-execution containers. The whole request is searched (the path is kept for callers), so a reference
// cannot hide in a shape the gateway does not know; one too large or deep to search counts as a reference. "" when
// there is none.
func StoredReference(path string, body *core.Object) string {
	budget := 50_000
	var search func(value any, depth int) string
	search = func(value any, depth int) string {
		budget--
		if budget < 0 || depth > 64 {
			return "too-complex"
		}
		if list, ok := value.([]any); ok {
			for _, item := range list {
				if found := search(item, depth+1); found != "" {
					return found
				}
			}
			return ""
		}
		object, ok := value.(*core.Object)
		if !ok || object == nil {
			return ""
		}
		if object.Get("type") == "item_reference" {
			return "item_reference"
		}
		if _, ok := object.Get("file_id").(string); ok {
			return "file_id"
		}
		if ids, ok := object.Get("file_ids").([]any); ok && len(ids) > 0 {
			return "file_id"
		}
		if ids, ok := object.Get("vector_store_ids").([]any); ok && len(ids) > 0 {
			return "vector_store"
		}
		if source, ok := object.Get("source").(*core.Object); ok && source != nil && source.Get("type") == "file" {
			return "file_id"
		}
		switch container := object.Get("container").(type) {
		case string:
			return "container"
		case *core.Object:
			if _, ok := container.Get("id").(string); ok && container != nil {
				return "container"
			}
		}
		found := ""
		object.Entries(func(key string, item any) bool {
			// Free text and numbers never hold a reference; only structure is searched.
			if _, isText := item.(string); key == "text" && isText {
				return true
			}
			found = search(item, depth+1)
			return found == ""
		})
		return found
	}
	return search(body, 0)
}

var (
	toolKindDate    = regexp.MustCompile(`_[0-9]{8}$`)
	toolKindPreview = regexp.MustCompile(`_preview(_[0-9]{4}_[0-9]{2}_[0-9]{2})?$`)
)

// toolKind is a tool kind as a policy names it: lowercase, without a version date (`web_search_20250305`) or
// `_preview`.
func toolKind(value string) string {
	kind := core.JSLower(value)
	kind = toolKindDate.ReplaceAllString(kind, "")
	kind = toolKindPreview.ReplaceAllString(kind, "")
	kind = utf16Map(kind, func(c uint16) bool {
		return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-'
	}, 64)
	if kind == "" {
		return "unknown"
	}
	return kind
}

// ProviderToolsOf (inference-gateway.ts providerToolsOf): The tools a request asks the provider to run (or that the
// provider defines for the model to drive): Anthropic server and Anthropic-defined tools (`tools[].type` other than
// `custom`) and remote MCP servers (`mcp_servers`); OpenAI Responses built-in tools (`tools[].type` other than
// `function` and `custom`, MCP servers as `mcp:{host}` or `mcp:{connector_id}`), and a stored prompt (`prompt`, which
// may bring tools of its own); Chat Completions web search (`web_search_options`). Functions the caller runs itself
// are not listed. At most 65 entries are returned (more are refused), from the first 256 tools and 64 MCP servers
// (the gateway refuses requests with more).
func ProviderToolsOf(path string, body *core.Object) []string {
	tools := newOrderedSet()
	list, _ := body.Get("tools").([]any)
	if len(list) > gatewayMaxTools {
		list = list[:gatewayMaxTools]
	}
	for _, item := range list {
		tool, ok := item.(*core.Object)
		if !ok || tool == nil {
			continue
		}
		kind, _ := tool.Get("type").(string)
		if kind == "" || kind == "function" || kind == "custom" {
			continue
		}
		if kind == "mcp" {
			if connector, ok := tool.Get("connector_id").(string); ok && isUndefined(tool.Get("server_url")) {
				tools.Add("mcp:" + toolKind(connector))
			} else {
				tools.Add("mcp:" + mcpHost(tool.Get("server_url")))
			}
		} else {
			tools.Add(toolKind(kind))
		}
	}
	if servers, ok := body.Get("mcp_servers").([]any); path == "/v1/messages" && ok {
		if len(servers) > gatewayMaxMcpServers {
			servers = servers[:gatewayMaxMcpServers]
		}
		for _, server := range servers {
			tools.Add("mcp:" + mcpHost(member(server, "url")))
		}
	}
	if prompt := body.Get("prompt"); path == "/v1/responses" && !nullish(prompt) {
		tools.Add("prompt")
	}
	if options := body.Get("web_search_options"); path == "/v1/chat/completions" && !nullish(options) {
		tools.Add("web_search")
	}
	result := tools.Values()
	if len(result) > 65 {
		result = result[:65]
	}
	if result == nil {
		result = []string{}
	}
	return result
}

var gatewayErrorTypes = map[gatewayFormat]map[int]string{
	"anthropic": {
		400: "invalid_request_error",
		401: "authentication_error",
		403: "permission_error",
		404: "not_found_error",
		413: "request_too_large",
		429: "rate_limit_error",
		500: "api_error",
		502: "api_error",
	},
	"openai": {
		400: "invalid_request_error",
		401: "invalid_request_error",
		403: "insufficient_quota",
		404: "invalid_request_error",
		413: "invalid_request_error",
		429: "rate_limit_exceeded",
		500: "server_error",
		502: "server_error",
	},
}

// gatewayResponse is `new Response(body, { status, headers })` for a text body.
func gatewayResponse(status int, headers http.Header, body string) *http.Response {
	return &http.Response{
		Status: strconv.Itoa(status) + " " + http.StatusText(status), StatusCode: status,
		Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: headers, Body: io.NopCloser(strings.NewReader(body)), ContentLength: int64(len(body)),
	}
}

// gatewayJSON is JSON.stringify of a model value.
func gatewayJSON(value any) string {
	text, _, _ := core.Stringify(value)
	return text
}

// gatewayErrorResponse is inference-gateway.ts errorResponse: an error in the API's own shape.
func gatewayErrorResponse(format gatewayFormat, status int, code, message string, extra ...string) *http.Response {
	kind, ok := gatewayErrorTypes[format][status]
	if !ok {
		kind = "server_error"
		if format == "anthropic" {
			kind = "api_error"
		}
	}
	var body *core.Object
	if format == "anthropic" {
		body = core.NewObject("type", "error", "error", core.NewObject("type", kind, "message", message, "code", code))
	} else {
		body = core.NewObject("error", core.NewObject("message", message, "type", kind, "code", code))
	}
	headers := http.Header{}
	headers.Set("content-type", "application/json")
	for index := 0; index+1 < len(extra); index += 2 {
		headers.Set(extra[index], extra[index+1])
	}
	return gatewayResponse(status, headers, gatewayJSON(body))
}

var bearerPattern = regexp.MustCompile(`(?i)^Bearer[` + jsWhitespace + `]+([^` + jsWhitespace + `]+)$`)

// credentialOf is the presented credential: `Authorization: Bearer …`, else `x-api-key` (the Anthropic SDK's
// header); ok is false when there is none.
func credentialOf(request *http.Request) (string, bool) {
	authorization, _ := headerGet(request.Header, "authorization")
	if match := bearerPattern.FindStringSubmatch(authorization); match != nil {
		return match[1], true
	}
	return headerGet(request.Header, "x-api-key")
}

// headerHas is Headers#has.
func headerHas(headers http.Header, name string) bool {
	return len(headers.Values(name)) > 0
}

// usageCount is a provider token count: a non-negative safe integer, else 0.
func usageCount(item any) float64 {
	if number, ok := item.(float64); ok && core.IsSafeInteger(number) && number >= 0 {
		return number
	}
	return 0
}

// UsageFrom (inference-gateway.ts usageFrom): Token counts from a provider's usage object (Anthropic, OpenAI Chat
// Completions / Embeddings, or OpenAI Responses: format `anthropic`, `openai` or `responses`) as `{ inputTokens,
// outputTokens, cacheReadTokens?, cacheWriteTokens? }`; nil when there is none. Cached input tokens are counted
// apart from other input.
func UsageFrom(format string, usage any) *core.Object {
	value, ok := usage.(*core.Object)
	if !ok || value == nil {
		if _, isArray := usage.([]any); !isArray {
			return nil
		}
		value = core.NewObject()
	}
	if format == "responses" {
		cached := usageCount(member(value.Get("input_tokens_details"), "cached_tokens"))
		result := core.NewObject(
			"inputTokens", math.Max(0, usageCount(value.Get("input_tokens"))-cached),
			"outputTokens", usageCount(value.Get("output_tokens")),
		)
		if cached != 0 {
			result.Set("cacheReadTokens", cached)
		}
		return result
	}
	if format == "anthropic" {
		result := core.NewObject(
			"inputTokens", usageCount(value.Get("input_tokens")),
			"outputTokens", usageCount(value.Get("output_tokens")),
		)
		if read := usageCount(value.Get("cache_read_input_tokens")); read != 0 {
			result.Set("cacheReadTokens", read)
		}
		if written := usageCount(value.Get("cache_creation_input_tokens")); written != 0 {
			result.Set("cacheWriteTokens", written)
		}
		return result
	}
	cached := usageCount(member(value.Get("prompt_tokens_details"), "cached_tokens"))
	result := core.NewObject(
		"inputTokens", math.Max(0, usageCount(value.Get("prompt_tokens"))-cached),
		"outputTokens", usageCount(value.Get("completion_tokens")),
	)
	if cached != 0 {
		result.Set("cacheReadTokens", cached)
	}
	return result
}

// errNullEvent is the TypeError reading a member of a `null` event (`data: null`), which ends the stream with an
// error as the TypeScript gateway does.
var errNullEvent = errors.New("Cannot read properties of null")

// streamUsage follows a server-sent event stream and keeps the latest token counts: Anthropic reports input (and
// cache) tokens in `message_start` and cumulative output tokens in `message_delta`; OpenAI Chat Completions reports
// everything in the final chunk when `stream_options.include_usage` is set (the gateway sets it); the Responses API
// reports it on `response.completed` (or `response.incomplete` / `response.failed`) and names the response from
// `response.created`. The final counts arrive last, so it also counts the characters of generated deltas: a stream
// the client closes early is metered from them (`metered`), never as free.
type streamUsage struct {
	format string
	// pending holds the bytes of an incomplete UTF-8 sequence at the end of the last chunk (a streaming TextDecoder).
	pending []byte
	buffer  string
	// bufferUnits is the UTF-16 length of buffer.
	bufferUnits int
	usage       *core.Object
	responseID  any
	// complete says whether the provider's final counts arrived.
	complete bool
	// outputChars counts characters of generated text, tool arguments and reasoning seen in deltas.
	outputChars int
}

func newStreamUsage(format string) *streamUsage {
	return &streamUsage{format: format, responseID: core.Undefined}
}

// metered is the usage to meter: the provider's counts once complete. Otherwise the input the provider reported so
// far (or `inputEstimate` when it reported none) and at least a token per four generated characters, so closing a
// stream before its final event does not avoid metering.
func (t *streamUsage) metered(inputEstimate float64) *core.Object {
	if t.complete && t.usage != nil {
		return t.usage
	}
	seen := t.usage
	result := core.NewObject()
	if seen != nil {
		result = seen.Spread()
	}
	input := inputEstimate
	seenOutput := 0.0
	if seen != nil {
		input = jsNumber(seen.Get("inputTokens"))
		seenOutput = numberOr(seen.Get("outputTokens"), 0)
	}
	result.Set("inputTokens", input)
	result.Set("outputTokens", math.Max(seenOutput, math.Ceil(float64(t.outputChars)/4)))
	return result
}

func (t *streamUsage) count(value any) {
	if text, ok := value.(string); ok {
		t.outputChars += utf16Len(text)
	}
}

// decode is `decoder.decode(chunk, { stream: true })`: complete sequences now, an incomplete trailing one later.
func (t *streamUsage) decode(chunk []byte) string {
	data := append(t.pending, chunk...)
	t.pending = nil
	// Hold back a lead byte (and what follows it) at the end that still needs continuation bytes.
	for back := 1; back <= 3 && back <= len(data); back++ {
		c := data[len(data)-back]
		if c < 0x80 {
			break
		}
		if c >= 0xC0 {
			need := 0
			switch {
			case c >= 0xC2 && c <= 0xDF:
				need = 2
			case c >= 0xE0 && c <= 0xEF:
				need = 3
			case c >= 0xF0 && c <= 0xF4:
				need = 4
			}
			if need > back && validPrefix(data[len(data)-back:]) {
				t.pending = append([]byte(nil), data[len(data)-back:]...)
				data = data[:len(data)-back]
			}
			break
		}
	}
	return decodeUTF8(data)
}

// validPrefix reports whether bytes (a lead byte and continuation bytes) can still become a valid UTF-8 sequence.
func validPrefix(prefix []byte) bool {
	if len(prefix) < 2 {
		return true
	}
	lower, upper := byte(0x80), byte(0xBF)
	switch prefix[0] {
	case 0xE0:
		lower = 0xA0
	case 0xED:
		upper = 0x9F
	case 0xF0:
		lower = 0x90
	case 0xF4:
		upper = 0x8F
	}
	if prefix[1] < lower || prefix[1] > upper {
		return false
	}
	for _, c := range prefix[2:] {
		if c < 0x80 || c > 0xBF {
			return false
		}
	}
	return true
}

// push reads a chunk of the stream.
func (t *streamUsage) push(chunk []byte) error {
	text := t.decode(chunk)
	t.buffer += text
	t.bufferUnits += utf16Len(text)
	for {
		newline := strings.IndexByte(t.buffer, '\n')
		if newline < 0 {
			break
		}
		line := strings.TrimSuffix(t.buffer[:newline], "\r")
		t.bufferUnits -= utf16Len(t.buffer[:newline]) + 1
		t.buffer = t.buffer[newline+1:]
		if strings.HasPrefix(line, "data:") {
			if err := t.data(core.JSTrim(line[5:])); err != nil {
				return err
			}
		}
	}
	// A line longer than 1 MiB is not an event we need; drop it rather than buffer without bound.
	if t.bufferUnits > 1<<20 {
		t.buffer = ""
		t.bufferUnits = 0
	}
	return nil
}

func (t *streamUsage) data(payload string) error {
	if payload == "" || payload == "[DONE]" {
		return nil
	}
	event, err := core.ParseJSONString(payload)
	if err != nil {
		return nil
	}
	if event == nil {
		return errNullEvent
	}
	eventType := member(event, "type")
	if t.format == "openai" {
		choices, _ := member(event, "choices").([]any)
		for _, choice := range choices {
			delta := member(choice, "delta")
			if !truthy(delta) {
				continue
			}
			t.count(member(delta, "content"))
			t.count(member(delta, "reasoning_content"))
			calls, _ := member(delta, "tool_calls").([]any)
			for _, call := range calls {
				t.count(member(member(call, "function"), "arguments"))
			}
		}
		if usage := UsageFrom("openai", member(event, "usage")); usage != nil {
			t.usage = usage
			t.complete = true
		}
		return nil
	}
	if t.format == "responses" {
		kind, isString := eventType.(string)
		if isString && strings.HasSuffix(kind, ".delta") {
			t.count(member(event, "delta"))
		}
		response := member(event, "response")
		if !truthy(response) || !isString || !strings.HasPrefix(kind, "response.") {
			return nil
		}
		if id, ok := member(response, "id").(string); ok && isUndefined(t.responseID) {
			t.responseID = id
		}
		usage := UsageFrom("responses", member(response, "usage"))
		if usage != nil {
			t.usage = usage
		}
		if usage != nil && (kind == "response.completed" || kind == "response.incomplete" || kind == "response.failed") {
			t.complete = true
		}
		return nil
	}
	switch eventType {
	case "content_block_delta":
		delta := member(event, "delta")
		t.count(member(delta, "text"))
		t.count(member(delta, "partial_json"))
		t.count(member(delta, "thinking"))
	case "message_start":
		if usage := UsageFrom("anthropic", member(member(event, "message"), "usage")); usage != nil {
			t.usage = usage
		}
	case "message_delta":
		// Output tokens are cumulative; newer responses repeat the input and cache counts here too.
		delta := member(event, "usage")
		next := UsageFrom("anthropic", delta)
		if !truthy(delta) || next == nil {
			return nil
		}
		usage := core.NewObject("inputTokens", 0.0, "outputTokens", 0.0)
		if t.usage != nil {
			usage = t.usage.Spread()
		}
		usage.Set("outputTokens", next.Get("outputTokens"))
		if _, ok := member(delta, "input_tokens").(float64); ok {
			usage.Set("inputTokens", next.Get("inputTokens"))
		}
		if read := next.Get("cacheReadTokens"); truthy(read) {
			usage.Set("cacheReadTokens", read)
		}
		if written := next.Get("cacheWriteTokens"); truthy(written) {
			usage.Set("cacheWriteTokens", written)
		}
		t.usage = usage
		// message_delta carries the final output count; message_stop follows.
		t.complete = true
	}
	return nil
}

// upstreamURL joins a provider base URL and an endpoint path. Base URLs are stored without the API version; one
// that already ends in /v1 is accepted.
func upstreamURL(baseURL, path string) string {
	if strings.HasSuffix(baseURL, "/v1") {
		return baseURL + path[3:]
	}
	return baseURL + path
}

// retryableStatuses are upstream answers after which the gateway tries a model's fallbacks: rate limits, overload and
// server errors.
var retryableStatuses = map[int]bool{429: true, 500: true, 502: true, 503: true, 504: true, 529: true}

// boundedBody is the request body as text, or ok false when it is larger than maxBytes (read no further than that).
func boundedBody(request *http.Request, maxBytes int64) (string, bool, error) {
	declared, has := headerGet(request.Header, "content-length")
	if !has && request.ContentLength > 0 {
		declared = strconv.FormatInt(request.ContentLength, 10)
	}
	if jsNumber(coalesceString(declared, has || request.ContentLength > 0, "0")) > float64(maxBytes) {
		return "", false, nil
	}
	if request.Body == nil || request.Body == http.NoBody {
		return "", true, nil
	}
	data, err := io.ReadAll(io.LimitReader(request.Body, maxBytes+1))
	if err != nil {
		return "", false, err
	}
	if int64(len(data)) > maxBytes {
		return "", false, nil
	}
	return decodeUTF8(data), true, nil
}

// coalesceString is `(present ? value : fallback)`.
func coalesceString(value string, present bool, fallback string) string {
	if present {
		return value
	}
	return fallback
}

// spreadObjectLike is `{ ...value }` for a value already known to be a truthy object (arrays spread their indexes).
func spreadObjectLike(value any) *core.Object {
	switch v := value.(type) {
	case *core.Object:
		return v.Spread()
	case []any:
		out := core.NewObject()
		for index, item := range v {
			out.SetRaw(strconv.Itoa(index), item)
		}
		return out
	}
	return core.NewObject()
}

// gatewayOptions are the InferenceGatewayOptions read from the options object.
type gatewayOptions struct {
	basePath         string
	fetch            GatewayFetch
	timeoutMs        float64
	anthropicVersion any
	maxBodyBytes     float64
	onError          func(error)
}

func readGatewayOptions(options *core.Object) gatewayOptions {
	read := gatewayOptions{timeoutMs: 600_000, maxBodyBytes: 20 * 1024 * 1024, onError: func(error) {}, anthropicVersion: core.Undefined}
	if options == nil {
		return read
	}
	if value, ok := options.Get("basePath").(string); ok {
		read.basePath = value
	}
	switch fetch := options.Get("fetch").(type) {
	case GatewayFetch:
		read.fetch = fetch
	case func(*http.Request) (*http.Response, error):
		read.fetch = fetch
	}
	if value := options.Get("timeoutMs"); !nullish(value) {
		read.timeoutMs = jsNumber(value)
	}
	if value := options.Get("anthropicVersion"); !nullish(value) {
		read.anthropicVersion = value
	}
	if value := options.Get("maxBodyBytes"); !nullish(value) {
		read.maxBodyBytes = jsNumber(value)
	}
	switch onError := options.Get("onError").(type) {
	case func(error):
		read.onError = onError
	}
	return read
}

// defaultGatewayFetch is `globalThis.fetch` with `redirect: 'error'`: a redirect fails the request.
func defaultGatewayFetch(request *http.Request) (*http.Response, error) {
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return errors.New("fetch failed: unexpected redirect")
	}}
	return client.Do(request)
}

// gatewayAttempt is one upstream call: the permit it was made under, when it started, and the response or the error
// when the provider could not be reached.
type gatewayAttempt struct {
	current  *core.Object
	started  int64
	upstream *http.Response
	err      error
}

// CreateInferenceGateway (inference-gateway.ts createInferenceGateway): Builds the gateway handler over the inference
// runtime. options (InferenceGatewayOptions, nil for none) has `basePath` (the path prefix the gateway is mounted
// under, such as `/ai`; default none, so routes start at `/v1`), `fetch` (a GatewayFetch for upstream calls; by
// default platform providers use plain HTTP and base URLs an organization chose use the SSRF guard), `timeoutMs`
// (deadline for the upstream response headers; default 10 minutes), `anthropicVersion` (sent upstream when the client
// sends none; default `2023-06-01`), `maxBodyBytes` (largest accepted request body; default 20 MiB) and `onError` (a
// func(error) called when metering after a response fails; the response itself is unaffected).
func CreateInferenceGateway(runtime *GatewayRuntime, options *core.Object) (func(context.Context, *http.Request) (*http.Response, error), error) {
	settings := readGatewayOptions(options)
	base := strings.TrimRight(settings.basePath, "/")
	transport := settings.fetch
	if transport == nil {
		transport = defaultGatewayFetch
	}
	timeout := time.Duration(settings.timeoutMs * float64(time.Millisecond))
	maxBodyBytes := int64(settings.maxBodyBytes)
	onError := settings.onError
	now := func() int64 { return runtime.server.Wall() }

	denial := func(format gatewayFormat, denied *core.Object) *http.Response {
		switch denied.Get("reason") {
		case "BUDGET_EXCEEDED":
			resetsAt := member(denied.Get("budget"), "resetsAt")
			var extra []string
			if truthy(resetsAt) {
				if retry := math.Max(1, math.Ceil((jsNumber(resetsAt)-float64(now()))/1000)); truthy(retry) {
					extra = []string{"retry-after", core.NumberString(retry)}
				}
			}
			until := "its next window"
			if truthy(resetsAt) {
				until = isoString(jsNumber(resetsAt))
			}
			name := coalesce(member(denied.Get("budget"), "name"), "inference")
			return gatewayErrorResponse(format, 429, "BUDGET_EXCEEDED", `Budget "`+jsString(name)+`" is exhausted until `+until, extra...)
		case "MODEL_DISABLED":
			return gatewayErrorResponse(format, 403, "MODEL_DISABLED", "This model is disabled")
		case "TOOL_NOT_ALLOWED":
			tool := coalesce(denied.Get("tool"), "")
			return gatewayErrorResponse(format, 403, "TOOL_NOT_ALLOWED",
				core.JSTrim("You may not use the provider tool "+jsString(tool)+" with this model"))
		}
		return gatewayErrorResponse(format, 403, "ACCESS_DENIED", "You may not use this model")
	}

	failure := func(format gatewayFormat, err error) *http.Response {
		if known, ok := asIamError(err); ok {
			status := known.Status
			if status != 401 && status != 403 && status != 404 {
				status = 400
			}
			return gatewayErrorResponse(format, status, known.Code, known.Message)
		}
		onError(err)
		return gatewayErrorResponse(format, 500, "INTERNAL", "The gateway failed to handle the request")
	}

	listModels := func(ctx context.Context, request *http.Request, credential core.CredentialInput) *http.Response {
		anthropic := headerHas(request.Header, "anthropic-version")
		format := "openai"
		if anthropic {
			format = "anthropic"
		}
		models, err := runtime.Models(ctx, credential)
		if err != nil {
			return failure(format, err)
		}
		created := math.Floor(float64(now()) / 1000)
		data := make([]any, len(models))
		var body *core.Object
		if anthropic {
			for index, model := range models {
				data[index] = core.NewObject("type", "model", "id", model.Get("name"),
					"display_name", coalesce(model.Get("displayName"), model.Get("name")), "created_at", isoString(created*1000))
			}
			var first, last any
			if len(models) > 0 {
				first = coalesce(models[0].Get("name"), nil)
				last = coalesce(models[len(models)-1].Get("name"), nil)
			}
			body = core.NewObject("data", data, "has_more", false, "first_id", first, "last_id", last)
		} else {
			for index, model := range models {
				data[index] = core.NewObject("id", model.Get("name"), "object", "model", "created", created,
					"owned_by", member(model.Get("provider"), "name"))
			}
			body = core.NewObject("object", "list", "data", data)
		}
		headers := http.Header{}
		headers.Set("content-type", "application/json")
		return gatewayResponse(200, headers, gatewayJSON(body))
	}

	invoke := func(ctx context.Context, request *http.Request, endpoint *gatewayEndpoint, credential core.CredentialInput) (*http.Response, error) {
		format := endpoint.format
		requestID := ID()
		raw, fits, err := boundedBody(request, maxBodyBytes)
		if err != nil {
			return nil, err
		}
		if !fits {
			return gatewayErrorResponse(format, 413, "TOO_LARGE", "The request body is too large"), nil
		}
		parsed, parseErr := core.ParseJSONString(raw)
		body, isObject := parsed.(*core.Object)
		if parseErr != nil || !isObject || body == nil {
			return gatewayErrorResponse(format, 400, "INVALID_INPUT", "The request body must be a JSON object"), nil
		}
		modelName, isString := body.Get("model").(string)
		if !isString {
			return gatewayErrorResponse(format, 400, "INVALID_INPUT", "model is required"), nil
		}
		previousResponseID := ""
		hasPrevious := false
		if endpoint.usage == "responses" {
			// Conversation objects and background responses keep state and usage at the provider, out of the gateway's
			// sight; a previous response must be the caller's own (checked once the caller is known).
			if !nullish(body.Get("conversation")) {
				return gatewayErrorResponse(format, 400, "UNSUPPORTED_PARAMETER",
					"The gateway does not support conversation; continue with previous_response_id"), nil
			}
			if body.Get("background") == true {
				return gatewayErrorResponse(format, 400, "UNSUPPORTED_PARAMETER", "The gateway does not support background responses"), nil
			}
			if previous := body.Get("previous_response_id"); !nullish(previous) {
				id, ok := previous.(string)
				if !ok || !gatewayResponseIDPattern.MatchString(id) {
					return gatewayErrorResponse(format, 400, "INVALID_INPUT", "previous_response_id is invalid"), nil
				}
				previousResponseID, hasPrevious = id, true
			}
		}
		maxOutput := 0.0
		for _, field := range endpoint.outputFields {
			if value, ok := body.Get(field).(float64); ok && core.IsSafeInteger(value) && value > 0 {
				maxOutput = value
				break
			}
		}
		// A rough upper bound: four bytes per input token plus the requested output.
		inputEstimate := math.Ceil(float64(utf16Len(raw)) / 4)
		estimatedTokens := inputEstimate + maxOutput
		// Every tool is read, so a request listing more than the gateway reads is refused rather than half checked.
		listedTools, _ := body.Get("tools").([]any)
		listedServers, _ := body.Get("mcp_servers").([]any)
		if len(listedTools) > gatewayMaxTools || len(listedServers) > gatewayMaxMcpServers {
			return gatewayErrorResponse(format, 400, "INVALID_INPUT",
				"A request may list at most "+strconv.Itoa(gatewayMaxTools)+" tools and "+strconv.Itoa(gatewayMaxMcpServers)+" MCP servers"), nil
		}
		// Objects stored at the provider under the organization's key cannot be tied to the caller.
		if endpoint.usage != "" {
			if reference := StoredReference(endpoint.path, body); reference != "" {
				return gatewayErrorResponse(format, 400, "UNSUPPORTED_PARAMETER",
					"The gateway does not pass on references to stored provider objects ("+reference+")"), nil
			}
		}
		// Tools the provider would run, checked by each model's `providerTools` (token counting runs none).
		var tools []string
		if endpoint.usage != "" {
			tools = ProviderToolsOf(endpoint.path, body)
		}
		checked := func(model string) *core.Object {
			input := core.NewObject("model", model, "estimatedTokens", estimatedTokens)
			if len(tools) > 0 {
				input.Set("tools", stringsOf(tools))
			}
			return input
		}
		outcome, err := runtime.Authorize(ctx, credential, checked(modelName))
		if err != nil {
			return failure(format, err), nil
		}
		if denied, ok := outcome.Get("denied").(*core.Object); ok && outcome.Has("denied") {
			return denial(format, denied), nil
		}
		permit := outcome
		permitModel := func(current *core.Object) *core.Object {
			model, _ := member(current.Get("check"), "model").(*core.Object)
			return model
		}
		providerOf := func(current *core.Object) *core.Object {
			provider, _ := current.Get("provider").(*core.Object)
			return provider
		}
		kind := jsString(providerOf(permit).Get("kind"))
		if (format == "anthropic") != (kind == "anthropic") {
			use := "POST /v1/chat/completions, /v1/responses or /v1/embeddings"
			if kind == "anthropic" {
				use = "POST /v1/messages"
			}
			return gatewayErrorResponse(format, 400, "WRONG_FORMAT",
				"Model "+jsString(permitModel(permit).Get("name"))+" is served by an "+kind+" provider; use "+use), nil
		}
		if hasPrevious {
			owned, err := runtime.OwnsResponse(ctx, permit, previousResponseID)
			if err != nil {
				return failure(format, err), nil
			}
			if !owned {
				return gatewayErrorResponse(format, 404, "RESPONSE_NOT_FOUND", "previous_response_id names no response of yours"), nil
			}
		}
		stream := body.Get("stream") == true
		path := endpoint.path

		// send sends the request to a permit's provider: the answer, or the error when the provider could not be
		// reached.
		send := func(current *core.Object) gatewayAttempt {
			provider := providerOf(current)
			kind := jsString(provider.Get("kind"))
			upstreamBody := body.Spread(core.NewObject("model", current.Get("upstreamModel")))
			// The model's `maxOutputTokens` caps every call: larger limits are lowered, and a call without one gets it.
			if limit := permitModel(current).Get("maxOutputTokens"); !isUndefined(limit) && len(endpoint.outputFields) > 0 {
				limited := false
				for _, field := range endpoint.outputFields {
					value, ok := upstreamBody.Get(field).(float64)
					if !ok {
						continue
					}
					limited = true
					if value > jsNumber(limit) {
						upstreamBody.Set(field, limit)
					}
				}
				if endpoint.defaultOutputField != nil {
					if field := endpoint.defaultOutputField(kind); !limited && field != "" {
						upstreamBody.Set(field, limit)
					}
				}
			}
			headers := http.Header{}
			headers.Set("content-type", "application/json")
			if stream {
				headers.Set("accept", "text/event-stream")
			} else {
				headers.Set("accept", "application/json")
			}
			if format == "anthropic" {
				headers.Set("x-api-key", jsString(provider.Get("apiKey")))
				version, has := headerGet(request.Header, "anthropic-version")
				if !has {
					version = jsString(coalesce(settings.anthropicVersion, "2023-06-01"))
				}
				headers.Set("anthropic-version", version)
				if beta, _ := headerGet(request.Header, "anthropic-beta"); beta != "" {
					headers.Set("anthropic-beta", beta)
				}
			} else {
				headers.Set("authorization", "Bearer "+jsString(provider.Get("apiKey")))
				if stream && endpoint.usage == "openai" {
					streamOptions := core.NewObject()
					if existing := body.Get("stream_options"); typeOf(existing) == "object" && truthy(existing) {
						streamOptions = spreadObjectLike(existing)
					}
					streamOptions.Set("include_usage", true)
					upstreamBody.Set("stream_options", streamOptions)
				}
			}
			started := now()
			attemptCtx, cancel := context.WithCancel(ctx)
			timer := time.AfterFunc(timeout, cancel)
			// A base URL an organization chose goes through the SSRF guard: the answer is streamed back to the caller.
			do := settings.fetch
			if do == nil {
				if guard, ok := provider.Get("guard").(*core.Object); ok && guard != nil {
					guarded := auth.CreateGuardedFetch(auth.GuardedFetchOptions{SafeFetchAddressOptions: auth.SafeFetchAddressOptions{
						AnyPort:                guard.Get("anyPort") == true,
						AllowInsecureLocalhost: guard.Get("allowInsecureLocalhost") == true,
						AllowPrivateNetworks:   guard.Get("allowPrivateNetworks") == true,
					}})
					do = guarded.DoRedirectError
				} else {
					do = transport
				}
			}
			outgoing, err := http.NewRequestWithContext(attemptCtx, http.MethodPost, upstreamURL(jsString(provider.Get("baseUrl")), path),
				bytes.NewReader(utf8Bytes(gatewayJSON(upstreamBody))))
			if err != nil {
				timer.Stop()
				cancel()
				return gatewayAttempt{current: current, started: started, err: err}
			}
			outgoing.Header = headers
			upstream, err := do(outgoing)
			timer.Stop()
			if err != nil {
				cancel()
				return gatewayAttempt{current: current, started: started, err: err}
			}
			if upstream.Body == nil {
				upstream.Body = http.NoBody
			}
			upstream.Body = &cancelOnClose{ReadCloser: upstream.Body, cancel: cancel}
			return gatewayAttempt{current: current, started: started, upstream: upstream}
		}
		meterCtx := context.WithoutCancel(ctx)
		meterFor := func(current *core.Object, started int64) func(usage *core.Object, status string, responseID any) {
			return func(usage *core.Object, status string, responseID any) {
				// Calls that cost nothing (token counting) are checked but not metered.
				if endpoint.usage == "" {
					return
				}
				record := core.NewObject("model", permitModel(current).Get("name"), "inputTokens", 0.0, "outputTokens", 0.0)
				if usage != nil {
					record.Set("inputTokens", numberOr(usage.Get("inputTokens"), 0))
					record.Set("outputTokens", numberOr(usage.Get("outputTokens"), 0))
					if read := usage.Get("cacheReadTokens"); truthy(read) {
						record.Set("cacheReadTokens", read)
					}
					if written := usage.Get("cacheWriteTokens"); truthy(written) {
						record.Set("cacheWriteTokens", written)
					}
				}
				record.Set("status", status)
				record.Set("requestId", requestID)
				record.Set("latencyMs", float64(now()-started))
				if id, ok := responseID.(string); ok && id != "" && gatewayResponseIDPattern.MatchString(id) {
					record.Set("responseId", id)
				}
				if _, err := runtime.Record(meterCtx, current, record); err != nil {
					onError(err)
				}
			}
		}

		// A model's fallbacks, in order, when its provider is unreachable, rate limited or failing: each only if the
		// caller may use it (access, budgets) and it speaks the same wire format.
		sent := send(permit)
		fallbacks, _ := permitModel(permit).Get("fallbacks").([]any)
		fallbacks = append([]any(nil), fallbacks...)
		tried := newOrderedSet(jsString(permitModel(permit).Get("name")))
		for (sent.upstream == nil || retryableStatuses[sent.upstream.StatusCode]) && len(fallbacks) > 0 {
			var next *core.Object
			for next == nil && len(fallbacks) > 0 {
				name := jsString(fallbacks[0])
				fallbacks = fallbacks[1:]
				if tried.Has(name) {
					continue
				}
				tried.Add(name)
				outcome, err := runtime.Authorize(ctx, credential, checked(name))
				if err != nil || outcome.Has("denied") {
					continue
				}
				if (format == "anthropic") != (providerOf(outcome).Get("kind") == "anthropic") {
					continue
				}
				// A continued response exists only at the provider whose ownership was checked.
				if hasPrevious && providerOf(outcome).Get("id") != providerOf(permit).Get("id") {
					continue
				}
				next = outcome
			}
			if next == nil {
				break
			}
			// The failed attempt is metered (no tokens) against the model that failed, then the next one is tried.
			meterFor(sent.current, sent.started)(nil, "error", core.Undefined)
			if sent.upstream != nil {
				sent.upstream.Body.Close()
			}
			sent = send(next)
		}
		chosen := sent.current
		meter := meterFor(chosen, sent.started)
		if sent.upstream == nil {
			meter(nil, "error", core.Undefined)
			onError(sent.err)
			return gatewayErrorResponse(format, 502, "UPSTREAM_UNAVAILABLE", "The model provider could not be reached"), nil
		}
		upstream := sent.upstream
		responseHeaders := http.Header{}
		contentType, hasType := headerGet(upstream.Header, "content-type")
		responseHeaders.Set("content-type", coalesceString(contentType, hasType, "application/json"))
		responseHeaders.Set("x-better-iam-request-id", requestID)
		responseHeaders.Set("x-better-iam-model", jsString(permitModel(chosen).Get("name")))
		if chosen != permit {
			responseHeaders.Set("x-better-iam-fallback-from", jsString(permitModel(permit).Get("name")))
		}
		upstreamRequestID, has := headerGet(upstream.Header, "request-id")
		if !has {
			upstreamRequestID, _ = headerGet(upstream.Header, "x-request-id")
		}
		if upstreamRequestID != "" {
			responseHeaders.Set("x-upstream-request-id", upstreamRequestID)
		}
		status := "error"
		if upstream.StatusCode >= 200 && upstream.StatusCode <= 299 {
			status = "ok"
		}
		eventStream := strings.Contains(contentType, "text/event-stream")
		if !eventStream || upstream.Body == nil {
			data, readErr := io.ReadAll(upstream.Body)
			upstream.Body.Close()
			if readErr != nil {
				return nil, readErr
			}
			text := decodeUTF8(data)
			var usage *core.Object
			var responseID any = core.Undefined
			payload := text
			if parsed, err := core.ParseJSONString(text); err == nil && parsed != nil {
				if endpoint.usage != "" {
					usage = UsageFrom(endpoint.usage, member(parsed, "usage"))
				}
				if id, ok := member(parsed, "id").(string); endpoint.usage == "responses" && ok {
					responseID = id
				}
				if object, ok := parsed.(*core.Object); ok {
					if _, isString := object.Get("model").(string); isString {
						object.Set("model", permitModel(chosen).Get("name"))
						payload = gatewayJSON(object)
					}
				}
			}
			meter(usage, status, responseID)
			return gatewayResponse(upstream.StatusCode, responseHeaders, payload), nil
		}
		responseHeaders.Set("cache-control", "no-cache")
		trackerFormat := endpoint.usage
		if trackerFormat == "" {
			trackerFormat = format
		}
		forwarded := &meteredStream{source: upstream.Body, tracker: newStreamUsage(trackerFormat)}
		forwarded.finish = func() {
			forwarded.once.Do(func() {
				// Without the provider's final counts (the client closed early, or the provider sent none), estimated.
				meter(forwarded.tracker.metered(inputEstimate), status, forwarded.tracker.responseID)
			})
		}
		return &http.Response{
			Status: strconv.Itoa(upstream.StatusCode) + " " + http.StatusText(upstream.StatusCode), StatusCode: upstream.StatusCode,
			Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1, Header: responseHeaders, Body: forwarded, ContentLength: -1,
		}, nil
	}

	return func(ctx context.Context, request *http.Request) (*http.Response, error) {
		pathname := request.URL.EscapedPath()
		if base != "" && !strings.HasPrefix(pathname, base+"/") {
			return gatewayErrorResponse("openai", 404, "NOT_FOUND", "Not found"), nil
		}
		path := pathname[len(base):]
		endpoint := gatewayEndpoints[path]
		format := "openai"
		if endpoint != nil {
			format = endpoint.format
		} else if headerHas(request.Header, "anthropic-version") {
			format = "anthropic"
		}
		token, ok := credentialOf(request)
		if !ok || token == "" {
			return gatewayErrorResponse(format, 401, "UNAUTHENTICATED", "Send a Better IAM credential as a bearer token or x-api-key"), nil
		}
		credential := core.CredentialInput{Token: token, Headers: request.Header}
		if request.Method == http.MethodGet && path == "/v1/models" {
			return listModels(ctx, request, credential), nil
		}
		if request.Method == http.MethodPost && endpoint != nil {
			return invoke(ctx, request, endpoint, credential)
		}
		return gatewayErrorResponse(format, 404, "NOT_FOUND", "Not found"), nil
	}, nil
}

// cancelOnClose releases an upstream call's context when its body is closed.
type cancelOnClose struct {
	io.ReadCloser
	cancel context.CancelFunc
}

func (c *cancelOnClose) Close() error {
	err := c.ReadCloser.Close()
	c.cancel()
	return err
}

// meteredStream forwards an upstream event stream untouched while following its usage; the call is metered once,
// when the stream ends, fails, or the client closes it.
type meteredStream struct {
	source  io.ReadCloser
	tracker *streamUsage
	once    sync.Once
	finish  func()
	failed  error
}

func (m *meteredStream) Read(p []byte) (int, error) {
	if m.failed != nil {
		return 0, m.failed
	}
	n, err := m.source.Read(p)
	if n > 0 {
		if pushErr := m.tracker.push(p[:n]); pushErr != nil {
			m.finish()
			m.failed = pushErr
			return 0, pushErr
		}
	}
	if err == io.EOF {
		m.finish()
		return n, io.EOF
	}
	if err != nil {
		m.finish()
		m.failed = err
		return n, err
	}
	return n, nil
}

func (m *meteredStream) Close() error {
	m.finish()
	return m.source.Close()
}
