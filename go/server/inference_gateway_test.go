package server

// Port of tests/inference-gateway.test.ts and the stored-reference cases of tests/security-inference.test.ts.
// Providers and models are seeded as the inference API writes them (api/inference.ts is ported separately), usage is
// read from the usage records (inference.usage groupBy: 'model'), and agents are stood in for by members with the
// same grants (agent credentials come from api/agents.ts and api/credentials.ts).

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

type upstreamCall struct {
	url     string
	headers http.Header
	body    *core.Object
}

// fakeUpstream is a fake provider: it records each request and answers from the model and `stream` flag.
type fakeUpstream struct {
	mu    sync.Mutex
	calls []upstreamCall
}

func sse(events ...[2]any) string {
	var out strings.Builder
	for _, event := range events {
		if name, ok := event[0].(string); ok && name != "" {
			out.WriteString("event: " + name + "\n")
		}
		data, isText := event[1].(string)
		if !isText {
			data = gatewayJSON(core.Normalize(event[1]))
		}
		out.WriteString("data: " + data + "\n\n")
	}
	return out.String()
}

// chunkedReader delivers a body in small pieces, splitting events across chunks.
type chunkedReader struct {
	data []byte
	size int
}

func (r *chunkedReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := r.size
	if n > len(r.data) {
		n = len(r.data)
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p, r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

func upstreamResponse(status int, contentType string, body io.Reader, extra ...string) *http.Response {
	headers := http.Header{}
	headers.Set("content-type", contentType)
	for index := 0; index+1 < len(extra); index += 2 {
		headers.Set(extra[index], extra[index+1])
	}
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(body)}
}

func upstreamJSON(status int, value any, extra ...string) *http.Response {
	return upstreamResponse(status, "application/json", strings.NewReader(gatewayJSON(core.Normalize(value))), extra...)
}

func (u *fakeUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.calls)
}

func (u *fakeUpstream) call(index int) upstreamCall {
	u.mu.Lock()
	defer u.mu.Unlock()
	if index < 0 {
		index += len(u.calls)
	}
	return u.calls[index]
}

func (u *fakeUpstream) fetch(request *http.Request) (*http.Response, error) {
	data, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, err
	}
	body := must(core.ParseJSON(data)).(*core.Object)
	url := request.URL.String()
	u.mu.Lock()
	u.calls = append(u.calls, upstreamCall{url: url, headers: request.Header.Clone(), body: body})
	calls := len(u.calls)
	u.mu.Unlock()
	if strings.HasSuffix(url, "/v1/messages/count_tokens") {
		return upstreamJSON(200, core.NewObject("input_tokens", 42.0)), nil
	}
	if strings.HasSuffix(url, "/embeddings") {
		return upstreamJSON(200, core.NewObject("object", "list", "model", body.Get("model"),
			"data", []any{core.NewObject("object", "embedding", "index", 0.0, "embedding", []any{0.1, 0.2})},
			"usage", core.NewObject("prompt_tokens", 9.0, "total_tokens", 9.0))), nil
	}
	if strings.HasSuffix(url, "/responses") {
		response := func(usage any) *core.Object {
			return core.NewObject("id", "resp_"+strconv.Itoa(calls), "object", "response", "model", body.Get("model"), "usage", usage)
		}
		used := core.NewObject("input_tokens", 30.0, "input_tokens_details", core.NewObject("cached_tokens", 10.0),
			"output_tokens", 12.0, "output_tokens_details", core.NewObject("reasoning_tokens", 4.0), "total_tokens", 42.0)
		if body.Get("stream") != true {
			return upstreamJSON(200, response(used)), nil
		}
		return upstreamResponse(200, "text/event-stream", strings.NewReader(sse(
			[2]any{"response.created", core.NewObject("type", "response.created", "response", response(nil))},
			[2]any{"response.output_text.delta", core.NewObject("type", "response.output_text.delta", "delta", "Hi")},
			[2]any{"response.completed", core.NewObject("type", "response.completed", "response", response(used))},
		))), nil
	}
	anthropic := strings.HasSuffix(url, "/v1/messages")
	if body.Get("stream") != true {
		if anthropic {
			return upstreamJSON(200, core.NewObject("id", "msg_1", "type", "message", "model", body.Get("model"),
				"content", []any{core.NewObject("type", "text", "text", "Hello")},
				"usage", core.NewObject("input_tokens", 10.0, "output_tokens", 20.0, "cache_read_input_tokens", 5.0)),
				"request-id", "req_upstream"), nil
		}
		return upstreamJSON(200, core.NewObject("id", "chatcmpl_1", "object", "chat.completion", "model", body.Get("model"),
			"choices", []any{core.NewObject("index", 0.0, "message", core.NewObject("role", "assistant", "content", "Hi"))},
			"usage", core.NewObject("prompt_tokens", 12.0, "completion_tokens", 8.0, "prompt_tokens_details", core.NewObject("cached_tokens", 2.0))),
			"request-id", "req_upstream"), nil
	}
	var text string
	if anthropic {
		text = sse(
			[2]any{"message_start", core.NewObject("type", "message_start", "message", core.NewObject("usage", core.NewObject("input_tokens", 10.0, "output_tokens", 1.0)))},
			[2]any{"content_block_delta", core.NewObject("type", "content_block_delta", "delta", core.NewObject("type", "text_delta", "text", "Hel"))},
			[2]any{"message_delta", core.NewObject("type", "message_delta", "usage", core.NewObject("output_tokens", 25.0))},
			[2]any{"message_stop", core.NewObject("type", "message_stop")},
		)
	} else {
		text = sse(
			[2]any{nil, core.NewObject("choices", []any{core.NewObject("delta", core.NewObject("content", "Hi"))}, "usage", nil)},
			[2]any{nil, core.NewObject("choices", []any{}, "usage", core.NewObject("prompt_tokens", 7.0, "completion_tokens", 3.0))},
			[2]any{nil, "[DONE]"},
		)
	}
	return upstreamResponse(200, "text/event-stream", &chunkedReader{data: []byte(text), size: 17}), nil
}

type gatewayFixture struct {
	*inferenceFixture
	upstream    *fakeUpstream
	gateway     func(context.Context, *http.Request) (*http.Response, error)
	anthropicID string
	routerID    string
}

func gatewayOptionsWith(fetch GatewayFetch) *core.Object {
	options := core.NewObject("basePath", "/ai")
	options.SetRaw("fetch", fetch)
	return options
}

func newGatewayFixture(t *testing.T) *gatewayFixture {
	f := newInferenceFixture(t, &InferenceOptions{AllowCustomBaseUrls: flag(true)})
	g := &gatewayFixture{inferenceFixture: f, upstream: &fakeUpstream{}}
	g.anthropicID = f.provider(f.tenantID, "Anthropic", "anthropic", "sk-ant-provider-key-9999", "")
	g.routerID = f.provider(f.tenantID, "Router", "openai-compatible", "sk-router-key-8888", "https://router.example/api/v1")
	f.model(f.tenantID, "sonnet", g.anthropicID, "claude-sonnet-5", "inputPricePerMTok", 3.0, "outputPricePerMTok", 15.0,
		"cachedInputPricePerMTok", 0.3)
	f.model(f.tenantID, "open-model", g.routerID, "vendor/open-model-70b", "inputPricePerMTok", 1.0, "outputPricePerMTok", 1.0)
	g.gateway = must(CreateInferenceGateway(f.runtime, gatewayOptionsWith(g.upstream.fetch)))
	return g
}

type gatewayAnswer struct {
	status  int
	headers http.Header
	text    string
}

func (a gatewayAnswer) json(t *testing.T) *core.Object {
	t.Helper()
	parsed, err := core.ParseJSONString(a.text)
	if err != nil {
		t.Fatalf("not JSON: %q", a.text)
	}
	object, _ := parsed.(*core.Object)
	return object
}

// send calls a gateway; body nil is a GET.
func sendTo(t *testing.T, gateway func(context.Context, *http.Request) (*http.Response, error), path, token string, body any, headers ...string) gatewayAnswer {
	t.Helper()
	method := http.MethodGet
	var reader io.Reader
	if body != nil {
		method = http.MethodPost
		reader = strings.NewReader(gatewayJSON(core.Normalize(body)))
	}
	request := httptest.NewRequest(method, "http://gateway.test/ai"+path, reader)
	if token != "" {
		request.Header.Set("authorization", "Bearer "+token)
	}
	request.Header.Set("content-type", "application/json")
	for index := 0; index+1 < len(headers); index += 2 {
		request.Header.Set(headers[index], headers[index+1])
	}
	response, err := gateway(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return gatewayAnswer{status: response.StatusCode, headers: response.Header, text: string(data)}
}

func (g *gatewayFixture) call(path, token string, body any, headers ...string) gatewayAnswer {
	g.t.Helper()
	return sendTo(g.t, g.gateway, path, token, body, headers...)
}

func expectUsage(t *testing.T, rows map[string]map[string]float64, model string, want map[string]float64) {
	t.Helper()
	row := rows[model]
	for key, value := range want {
		if row[key] != value {
			t.Fatalf("usage of %s: %s = %v, want %v (row %v)", model, key, row[key], value, row)
		}
	}
}

func TestInferenceGatewayPassesAnthropicMessagesThrough(t *testing.T) {
	g := newGatewayFixture(t)
	response := g.call("/v1/messages", g.owner.Token, core.NewObject("model", "sonnet", "max_tokens", 256.0,
		"messages", []any{core.NewObject("role", "user", "content", "Hello")}))
	if response.status != 200 || response.headers.Get("x-better-iam-model") != "sonnet" ||
		response.headers.Get("x-upstream-request-id") != "req_upstream" || response.headers.Get("x-better-iam-request-id") == "" {
		t.Fatalf("response: %d %v %s", response.status, response.headers, response.text)
	}
	body := response.json(t)
	infExpect(t, body, "model", "sonnet")
	if member(body.Get("content").([]any)[0], "text") != "Hello" {
		t.Fatal(response.text)
	}
	sent := g.upstream.call(0)
	if sent.url != "https://api.anthropic.com/v1/messages" || sent.headers.Get("x-api-key") != "sk-ant-provider-key-9999" ||
		sent.headers.Get("anthropic-version") != "2023-06-01" || sent.headers.Get("authorization") != "" ||
		sent.body.Get("model") != "claude-sonnet-5" {
		t.Fatalf("sent: %s %v %s", sent.url, sent.headers, gatewayJSON(sent.body))
	}
	// 10 × $3 + 5 cached × $0.30 + 20 × $15 per million = 331.5 micro-dollars.
	rows := g.usageByModel()
	if len(rows) != 1 {
		t.Fatalf("usage: %v", rows)
	}
	expectUsage(t, rows, "sonnet", map[string]float64{"inputTokens": 10, "outputTokens": 20, "cacheReadTokens": 5, "costMicros": 331.5})
}

func TestInferenceGatewayStreamsEventsAndMetersWhenTheStreamEnds(t *testing.T) {
	g := newGatewayFixture(t)
	response := g.call("/v1/messages", "", core.NewObject("model", "sonnet", "max_tokens", 64.0, "stream", true, "messages", []any{}),
		"x-api-key", g.owner.Token, "anthropic-version", "2023-06-01")
	if response.headers.Get("content-type") != "text/event-stream" || response.headers.Get("cache-control") != "no-cache" {
		t.Fatalf("headers: %v", response.headers)
	}
	if !strings.Contains(response.text, "event: message_start") || !strings.Contains(response.text, `"output_tokens":25`) {
		t.Fatal(response.text)
	}
	expectUsage(t, g.usageByModel(), "sonnet", map[string]float64{"inputTokens": 10, "outputTokens": 25, "requests": 1})
}

func TestInferenceGatewayServesOpenAIChatCompletions(t *testing.T) {
	g := newGatewayFixture(t)
	plain := g.call("/v1/chat/completions", g.owner.Token, core.NewObject("model", "open-model",
		"messages", []any{core.NewObject("role", "user", "content", "Hi")}))
	if plain.status != 200 {
		t.Fatalf("%d %s", plain.status, plain.text)
	}
	first := g.upstream.call(0)
	if first.url != "https://router.example/api/v1/chat/completions" || first.headers.Get("authorization") != "Bearer sk-router-key-8888" {
		t.Fatalf("sent: %s %v", first.url, first.headers)
	}
	streamed := g.call("/v1/chat/completions", g.owner.Token, core.NewObject("model", "open-model", "stream", true, "messages", []any{}))
	if got := gatewayJSON(g.upstream.call(1).body.Get("stream_options")); got != `{"include_usage":true}` {
		t.Fatalf("stream_options: %s", got)
	}
	if !strings.Contains(streamed.text, "[DONE]") {
		t.Fatal(streamed.text)
	}
	// 10 + 2 cached input and 8 output, then 7 input and 3 output.
	expectUsage(t, g.usageByModel(), "open-model", map[string]float64{"requests": 2, "inputTokens": 17, "outputTokens": 11, "cacheReadTokens": 2})
}

func TestInferenceGatewayRefusesInEachAPIsOwnErrorShape(t *testing.T) {
	g := newGatewayFixture(t)
	_, aliceSession := g.person(g.tenantID, "alice")

	anonymous := g.call("/v1/messages", "", core.NewObject("model", "sonnet", "messages", []any{}))
	if anonymous.status != 401 {
		t.Fatal(anonymous.status)
	}
	infExpect(t, anonymous.json(t), "type", "error")
	infExpect(t, anonymous.json(t), "error.type", "authentication_error")

	bogus := g.call("/v1/chat/completions", "not-a-real-credential-token-value-xyz", core.NewObject("model", "open-model"))
	if bogus.status != 401 {
		t.Fatalf("%d %s", bogus.status, bogus.text)
	}
	infExpect(t, bogus.json(t), "error.code", "UNAUTHENTICATED")

	denied := g.call("/v1/messages", aliceSession.Token, core.NewObject("model", "sonnet", "messages", []any{}))
	if denied.status != 403 {
		t.Fatal(denied.status)
	}
	infExpect(t, denied.json(t), "error.type", "permission_error")
	infExpect(t, denied.json(t), "error.code", "ACCESS_DENIED")

	wrongFormat := g.call("/v1/chat/completions", g.owner.Token, core.NewObject("model", "sonnet"))
	if wrongFormat.status != 400 {
		t.Fatal(wrongFormat.status)
	}
	infExpect(t, wrongFormat.json(t), "error.code", "WRONG_FORMAT")
	infExpect(t, wrongFormat.json(t), "error.message", "Model sonnet is served by an anthropic provider; use POST /v1/messages")

	unknown := g.call("/v1/messages", g.owner.Token, core.NewObject("model", "missing"))
	if unknown.status != 404 {
		t.Fatal(unknown.status)
	}
	infExpect(t, unknown.json(t), "error.type", "not_found_error")

	g.budget(g.tenantID, "Tight", "subjectType", "identity", "subjectId", g.ownerID, "period", "hour", "maxTokens", 100.0)
	tooBig := g.call("/v1/messages", g.owner.Token, core.NewObject("model", "sonnet", "max_tokens", 4096.0, "messages", []any{}))
	if tooBig.status != 429 {
		t.Fatal(tooBig.status)
	}
	if retry, _ := strconv.Atoi(tooBig.headers.Get("retry-after")); retry <= 0 {
		t.Fatalf("retry-after: %q", tooBig.headers.Get("retry-after"))
	}
	infExpect(t, tooBig.json(t), "error.type", "rate_limit_error")
	infExpect(t, tooBig.json(t), "error.code", "BUDGET_EXCEEDED")
	if !strings.HasPrefix(jsString(member(tooBig.json(t).Get("error"), "message")), `Budget "Tight" is exhausted until 20`) {
		t.Fatal(tooBig.text)
	}
	if g.upstream.count() != 0 {
		t.Fatal("refused calls reached the provider")
	}
	missing := g.call("/v2/other", g.owner.Token, nil)
	if missing.status != 404 || missing.json(t).Get("error") == nil {
		t.Fatal(missing.text)
	}
	outside := sendTo(t, g.gateway, "/../elsewhere", g.owner.Token, nil)
	if outside.status != 404 {
		t.Fatal(outside.status)
	}
	invalid := g.call("/v1/messages", g.owner.Token, []any{1.0})
	infExpect(t, invalid.json(t), "error.message", "The request body must be a JSON object")
	noModel := g.call("/v1/messages", g.owner.Token, core.NewObject("messages", []any{}))
	infExpect(t, noModel.json(t), "error.message", "model is required")
}

func TestInferenceGatewayCapsOutputTokensAndLimitsRequestsPerMinute(t *testing.T) {
	g := newGatewayFixture(t)
	g.updateModel(g.tenantID, "sonnet", "maxOutputTokens", 1000.0)
	g.updateModel(g.tenantID, "open-model", "maxOutputTokens", 500.0)
	ask := func(model string, extra ...any) int {
		t.Helper()
		path := "/v1/chat/completions"
		if model == "sonnet" {
			path = "/v1/messages"
		}
		body := core.NewObject("model", model, "messages", []any{})
		for index := 0; index+1 < len(extra); index += 2 {
			body.Set(extra[index].(string), extra[index+1])
		}
		return g.call(path, g.owner.Token, body).status
	}
	if ask("sonnet", "max_tokens", 64_000.0) != 200 || ask("sonnet", "max_tokens", 200.0) != 200 || ask("open-model") != 200 {
		t.Fatal("capped calls refused")
	}
	var limits []string
	for index := 0; index < g.upstream.count(); index++ {
		limits = append(limits, jsString(g.upstream.call(index).body.Get("max_tokens")))
	}
	if strings.Join(limits, ",") != "1000,200,500" {
		t.Fatalf("limits: %v", limits)
	}

	// A per-minute budget is a rate limit: the third request in a minute waits for the next one.
	g.budget(g.tenantID, "Two per minute", "subjectType", "identity", "subjectId", g.ownerID, "period", "minute", "maxRequests", 2.0)
	g.advance(60_000 - int64(g.now())%60_000)
	if ask("sonnet", "max_tokens", 10.0) != 200 || ask("sonnet", "max_tokens", 10.0) != 200 {
		t.Fatal("calls within the limit refused")
	}
	if status := ask("sonnet", "max_tokens", 10.0); status != 429 {
		t.Fatalf("third call: %d", status)
	}
	g.advance(60_000)
	if status := ask("sonnet", "max_tokens", 10.0); status != 200 {
		t.Fatalf("next minute: %d", status)
	}
}

func TestInferenceGatewayFallsBackWhenAProviderIsOverloaded(t *testing.T) {
	g := newGatewayFixture(t)
	g.model(g.tenantID, "haiku", g.anthropicID, "claude-haiku-4-5")
	// open-model speaks the other wire format and is skipped; haiku is next.
	g.updateModel(g.tenantID, "sonnet", "fallbacks", items("open-model", "haiku"))
	overloaded := func(request *http.Request) (*http.Response, error) {
		data, _ := io.ReadAll(request.Body)
		if strings.Contains(string(data), `"model":"claude-sonnet-5"`) {
			return upstreamJSON(529, core.NewObject("type", "error", "error", core.NewObject("type", "overloaded_error", "message", "Overloaded"))), nil
		}
		request.Body = io.NopCloser(strings.NewReader(string(data)))
		return g.upstream.fetch(request)
	}
	gateway := must(CreateInferenceGateway(g.runtime, gatewayOptionsWith(overloaded)))
	ask := func(token string) gatewayAnswer {
		return sendTo(t, gateway, "/v1/messages", token, core.NewObject("model", "sonnet", "max_tokens", 64.0, "messages", []any{}))
	}
	response := ask(g.owner.Token)
	if response.status != 200 || response.headers.Get("x-better-iam-model") != "haiku" || response.headers.Get("x-better-iam-fallback-from") != "sonnet" {
		t.Fatalf("%d %v %s", response.status, response.headers, response.text)
	}
	infExpect(t, response.json(t), "model", "haiku")
	rows := g.usageByModel()
	expectUsage(t, rows, "sonnet", map[string]float64{"requests": 1, "outputTokens": 0})
	expectUsage(t, rows, "haiku", map[string]float64{"requests": 1, "outputTokens": 20})
	failed := g.find("inferenceUsage", core.NewObject("tenantId", g.tenantID, "model", "sonnet"))
	if len(failed) != 1 || failed[0].Get("status") != "error" {
		t.Fatalf("failed attempt: %s", gatewayJSON(failed))
	}

	// A caller who may not use the fallback gets the provider's answer instead.
	only, onlyCredential := g.person(g.tenantID, "sonnet-only")
	g.grant(g.tenantID, anaID(only), allow(items("inference:invoke"), items("model/sonnet")))
	refused := ask(onlyCredential.Token)
	if refused.status != 529 || refused.headers.Get("x-better-iam-fallback-from") != "" {
		t.Fatalf("%d %v", refused.status, refused.headers)
	}
}

func TestInferenceGatewayListsTheModelsACallerMayUse(t *testing.T) {
	g := newGatewayFixture(t)
	coder, coderCredential := g.person(g.tenantID, "coder")
	g.grant(g.tenantID, anaID(coder), allow(items("inference:invoke"), items("model/open-*")))
	openai := g.call("/v1/models", coderCredential.Token, nil)
	body := openai.json(t)
	infExpect(t, body, "object", "list")
	data := body.Get("data").([]any)
	if len(data) != 1 {
		t.Fatal(openai.text)
	}
	infExpect(t, data[0], "id", "open-model")
	infExpect(t, data[0], "object", "model")
	infExpect(t, data[0], "owned_by", "Router")
	anthropic := g.call("/v1/models", g.owner.Token, nil, "anthropic-version", "2023-06-01")
	listed := anthropic.json(t)
	var ids []string
	for _, model := range listed.Get("data").([]any) {
		ids = append(ids, jsString(member(model, "id")))
		infExpect(t, model, "type", "model")
	}
	if strings.Join(ids, ",") != "open-model,sonnet" {
		t.Fatalf("ids: %v", ids)
	}
	infExpect(t, listed, "has_more", false)
	infExpect(t, listed, "first_id", "open-model")
	infExpect(t, listed, "last_id", "sonnet")
	if completion := g.call("/v1/chat/completions", coderCredential.Token, core.NewObject("model", "open-model")); completion.status != 200 {
		t.Fatal(completion.status)
	}
	usage := g.find("inferenceUsage", core.NewObject("tenantId", g.tenantID, "identityId", anaID(coder)))
	if len(usage) != 1 {
		t.Fatalf("usage: %d", len(usage))
	}
	unauthenticated := g.call("/v1/models", "not-a-real-credential-token-value-xyz", nil, "anthropic-version", "2023-06-01")
	if unauthenticated.status != 401 {
		t.Fatal(unauthenticated.status)
	}
	infExpect(t, unauthenticated.json(t), "type", "error")
}

func TestInferenceGatewayServesResponsesAndEmbeddingsAndKeepsConversationsApart(t *testing.T) {
	g := newGatewayFixture(t)
	g.updateModel(g.tenantID, "open-model", "maxOutputTokens", 500.0)
	owner := g.owner.Token
	first := g.call("/v1/responses", owner, core.NewObject("model", "open-model", "input", "Hi", "max_output_tokens", 9999.0))
	if first.status != 200 {
		t.Fatal(first.status, first.text)
	}
	created := first.json(t)
	infExpect(t, created, "id", "resp_1")
	infExpect(t, created, "object", "response")
	infExpect(t, created, "model", "open-model")
	sent := g.upstream.call(0)
	if sent.url != "https://router.example/api/v1/responses" || sent.body.Get("model") != "vendor/open-model-70b" ||
		sent.body.Get("max_output_tokens") != 500.0 {
		t.Fatalf("sent: %s %s", sent.url, gatewayJSON(sent.body))
	}

	// Streamed, with the id taken from response.created and usage from response.completed.
	streamed := g.call("/v1/responses", owner, core.NewObject("model", "open-model", "input", "More", "stream", true,
		"previous_response_id", "resp_1"))
	if streamed.status != 200 || !strings.Contains(streamed.text, "event: response.completed") {
		t.Fatal(streamed.status, streamed.text)
	}
	if g.upstream.call(1).body.Has("stream_options") {
		t.Fatal("the Responses API got stream_options")
	}
	continued := g.call("/v1/responses", owner, core.NewObject("model", "open-model", "input", "And again", "previous_response_id", "resp_2"))
	if continued.status != 200 {
		t.Fatal(continued.status, continued.text)
	}

	// Someone else, even with access to the model, cannot continue the owner's conversation.
	alice, aliceSession := g.person(g.tenantID, "alice")
	g.grant(g.tenantID, anaID(alice), allow(items("inference:invoke"), items("model/open-model")))
	before := g.upstream.count()
	stolen := g.call("/v1/responses", aliceSession.Token, core.NewObject("model", "open-model", "input", "What did they say?",
		"previous_response_id", "resp_1"))
	if stolen.status != 404 {
		t.Fatal(stolen.status)
	}
	infExpect(t, stolen.json(t), "error.code", "RESPONSE_NOT_FOUND")
	for _, refused := range []*core.Object{
		core.NewObject("previous_response_id", "../resp_1"),
		core.NewObject("conversation", "conv_123"),
		core.NewObject("background", true),
	} {
		answer := g.call("/v1/responses", aliceSession.Token, core.NewObject("model", "open-model", "input", "x").Assign(refused))
		if answer.status != 400 {
			t.Fatalf("%s: %d", gatewayJSON(refused), answer.status)
		}
	}
	if g.upstream.count() != before {
		t.Fatal("refused requests reached the provider")
	}
	if own := g.call("/v1/responses", aliceSession.Token, core.NewObject("model", "open-model", "input", "Hi")); own.status != 200 {
		t.Fatal(own.status)
	}

	// Embeddings: input tokens only, and no output limit is added.
	embedded := g.call("/v1/embeddings", owner, core.NewObject("model", "open-model", "input", "text"))
	if embedded.status != 200 {
		t.Fatal(embedded.status)
	}
	infExpect(t, embedded.json(t), "model", "open-model")
	infExpect(t, embedded.json(t), "usage.prompt_tokens", 9.0)
	embedding := g.upstream.call(-1)
	if embedding.url != "https://router.example/api/v1/embeddings" || strings.Join(embedding.body.Keys(), ",") != "model,input" {
		t.Fatalf("embedding: %s %s", embedding.url, gatewayJSON(embedding.body))
	}

	// Three owner responses and one of Alice's (20 input, 10 cached, 12 output each), plus 9 embedding tokens.
	expectUsage(t, g.usageByModel(), "open-model", map[string]float64{"requests": 5, "inputTokens": 4*20 + 9, "cacheReadTokens": 4 * 10,
		"outputTokens": 4 * 12})
}

func TestInferenceGatewayGovernsProviderTools(t *testing.T) {
	g := newGatewayFixture(t)
	g.updateModel(g.tenantID, "open-model", "providerTools", "policy")
	g.updateModel(g.tenantID, "sonnet", "providerTools", "deny")
	alice, aliceSession := g.person(g.tenantID, "alice")
	g.grant(g.tenantID, anaID(alice),
		allow(items("inference:invoke"), items("model/open-model", "model/sonnet")),
		allow(items("inference:use-tool"), items("model-tool/web_search", "model-tool/mcp:*.acme.test")))
	token := aliceSession.Token
	respond := func(tools ...any) gatewayAnswer {
		return g.call("/v1/responses", token, core.NewObject("model", "open-model", "input", "Hi", "tools", tools))
	}
	if status := respond(core.NewObject("type", "web_search_preview")).status; status != 200 {
		t.Fatalf("web search: %d", status)
	}
	if status := respond(core.NewObject("type", "mcp", "server_label", "kb", "server_url", "https://kb.acme.test/mcp")).status; status != 200 {
		t.Fatalf("mcp: %d", status)
	}
	// Functions the caller runs itself are not provider tools.
	if status := respond(core.NewObject("type", "function", "name", "lookup", "parameters", core.NewObject())).status; status != 200 {
		t.Fatalf("function: %d", status)
	}
	sent := g.upstream.count()
	interpreter := respond(core.NewObject("type", "code_interpreter", "container", core.NewObject("type", "auto")))
	if interpreter.status != 403 {
		t.Fatal(interpreter.status, interpreter.text)
	}
	infExpect(t, interpreter.json(t), "error.code", "TOOL_NOT_ALLOWED")
	infExpect(t, interpreter.json(t), "error.message", "You may not use the provider tool code_interpreter with this model")
	elsewhere := respond(core.NewObject("type", "mcp", "server_label", "x", "server_url", "https://tools.evil.example/mcp"))
	if elsewhere.status != 403 || g.upstream.count() != sent {
		t.Fatal(elsewhere.status)
	}
	if status := g.call("/v1/chat/completions", token, core.NewObject("model", "open-model", "messages", []any{},
		"web_search_options", core.NewObject())).status; status != 200 {
		t.Fatalf("chat web search: %d", status)
	}

	// A model that allows no provider tools: custom tools still pass, server tools and MCP servers do not.
	messages := func(extra ...any) gatewayAnswer {
		body := core.NewObject("model", "sonnet", "max_tokens", 16.0, "messages", []any{})
		for index := 0; index+1 < len(extra); index += 2 {
			body.Set(extra[index].(string), extra[index+1])
		}
		return g.call("/v1/messages", token, body)
	}
	if status := messages("tools", items(core.NewObject("name", "lookup", "input_schema", core.NewObject("type", "object")))).status; status != 200 {
		t.Fatalf("custom tool: %d", status)
	}
	search := messages("tools", items(core.NewObject("type", "web_search_20250305", "name", "web_search", "max_uses", 2.0)))
	if search.status != 403 {
		t.Fatal(search.status)
	}
	infExpect(t, search.json(t), "type", "error")
	infExpect(t, search.json(t), "error.type", "permission_error")
	infExpect(t, search.json(t), "error.code", "TOOL_NOT_ALLOWED")
	if status := messages("mcp_servers", items(core.NewObject("type", "url", "url", "https://kb.acme.test/mcp", "name", "kb"))).status; status != 403 {
		t.Fatalf("mcp server: %d", status)
	}
	// Counting tokens runs no tool.
	if status := g.call("/v1/messages/count_tokens", token, core.NewObject("model", "sonnet", "messages", []any{},
		"tools", items(core.NewObject("type", "web_search_20250305", "name", "web_search")))).status; status != 200 {
		t.Fatalf("count tokens: %d", status)
	}
}

func TestInferenceGatewayRefusesWhatItCannotCheck(t *testing.T) {
	g := newGatewayFixture(t)
	g.updateModel(g.tenantID, "open-model", "providerTools", "deny")
	owner := g.owner.Token
	respond := func(extra ...any) gatewayAnswer {
		body := core.NewObject("model", "open-model", "input", "Hi")
		for index := 0; index+1 < len(extra); index += 2 {
			body.Set(extra[index].(string), extra[index+1])
		}
		return g.call("/v1/responses", owner, body)
	}
	many := make([]any, 257)
	for index := range many {
		many[index] = core.NewObject("type", "function", "name", "f"+strconv.Itoa(index), "parameters", core.NewObject())
	}
	tooMany := respond("tools", many)
	if tooMany.status != 400 {
		t.Fatal(tooMany.status)
	}
	infExpect(t, tooMany.json(t), "error.message", "A request may list at most 256 tools and 64 MCP servers")
	if status := respond("prompt", core.NewObject("id", "pmpt_1")).status; status != 403 {
		t.Fatalf("prompt: %d", status)
	}
	for _, input := range []any{
		items(core.NewObject("type", "item_reference", "id", "msg_someone_elses")),
		items(core.NewObject("role", "user", "content", items(core.NewObject("type", "input_file", "file_id", "file-abc")))),
	} {
		refused := respond("input", input)
		if refused.status != 400 {
			t.Fatal(refused.status)
		}
		infExpect(t, refused.json(t), "error.code", "UNSUPPORTED_PARAMETER")
	}
	if status := g.call("/v1/messages", owner, core.NewObject("model", "sonnet", "messages", []any{}, "container", "container_1")).status; status != 400 {
		t.Fatalf("container: %d", status)
	}
	if g.upstream.count() != 0 {
		t.Fatal("refused requests reached the provider")
	}

	// A response continues only at the provider that answered it.
	other := g.provider(g.tenantID, "Echo", "openai-compatible", "sk-echo-key-7777", "https://echo.example/v1")
	g.model(g.tenantID, "echo-model", other, "echo")
	g.updateModel(g.tenantID, "open-model", "providerTools", core.Undefined)
	first := respond().json(t)
	if status := respond("previous_response_id", first.Get("id")).status; status != 200 {
		t.Fatalf("continued: %d", status)
	}
	if status := g.call("/v1/responses", owner, core.NewObject("model", "echo-model", "input", "Hi", "previous_response_id", first.Get("id"))).status; status != 404 {
		t.Fatalf("other provider: %d", status)
	}
}

// hangingBody streams the start of an answer and then blocks until closed.
type hangingBody struct {
	first  []byte
	closed chan struct{}
	once   sync.Once
}

func (b *hangingBody) Read(p []byte) (int, error) {
	if len(b.first) > 0 {
		n := copy(p, b.first)
		b.first = b.first[n:]
		return n, nil
	}
	<-b.closed
	return 0, io.ErrClosedPipe
}

func (b *hangingBody) Close() error {
	b.once.Do(func() { close(b.closed) })
	return nil
}

func TestInferenceGatewayMetersAStreamTheClientClosesEarly(t *testing.T) {
	g := newGatewayFixture(t)
	hanging := func(*http.Request) (*http.Response, error) {
		events := sse(
			[2]any{"response.created", core.NewObject("type", "response.created", "response", core.NewObject("id", "resp_h", "usage", nil))},
			[2]any{"response.output_text.delta", core.NewObject("type", "response.output_text.delta", "delta", strings.Repeat("x", 400))},
		)
		headers := http.Header{}
		headers.Set("content-type", "text/event-stream")
		return &http.Response{StatusCode: 200, Header: headers, Body: &hangingBody{first: []byte(events), closed: make(chan struct{})}}, nil
	}
	gateway := must(CreateInferenceGateway(g.runtime, gatewayOptionsWith(hanging)))
	request := httptest.NewRequest(http.MethodPost, "http://gateway.test/ai/v1/responses",
		strings.NewReader(gatewayJSON(core.NewObject("model", "open-model", "input", strings.Repeat("x", 4000), "stream", true))))
	request.Header.Set("authorization", "Bearer "+g.owner.Token)
	response, err := gateway(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]byte, 64*1024)
	if _, err := response.Body.Read(buffer); err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	rows := g.usageByModel()
	// No final counts: the request's size stands in for the input, the text streamed so far for the output.
	expectUsage(t, rows, "open-model", map[string]float64{"requests": 1, "outputTokens": 100})
	if rows["open-model"]["inputTokens"] < 1000 {
		t.Fatalf("input: %v", rows["open-model"])
	}
	recorded := g.find("inferenceResponses", core.NewObject("tenantId", g.tenantID))
	if len(recorded) != 1 || recorded[0].Get("responseId") != "resp_h" {
		t.Fatalf("responses: %s", gatewayJSON(recorded))
	}
}

func TestInferenceGatewayNamesProviderToolsTheWayPoliciesSeeThem(t *testing.T) {
	tools := func(path string, body *core.Object) string { return strings.Join(ProviderToolsOf(path, body), ",") }
	if got := tools("/v1/responses", core.NewObject("tools", items(
		core.NewObject("type", "web_search_preview_2025_03_11"),
		core.NewObject("type", "function", "name", "x"),
		core.NewObject("type", "custom", "name", "y"),
		core.NewObject("type", "mcp", "server_url", "https://KB.Acme.Test:8443/mcp"),
		core.NewObject("type", "mcp", "connector_id", "connector_googledrive"),
		core.NewObject("type", "mcp", "server_url", "not a url"),
		core.NewObject("type", "image_generation"),
	))); got != "web_search,mcp:kb.acme.test,mcp:connector_googledrive,mcp:invalid,image_generation" {
		t.Fatal(got)
	}
	if got := tools("/v1/messages", core.NewObject(
		"tools", items(
			core.NewObject("type", "code_execution_20250825", "name", "code_execution"),
			core.NewObject("name", "lookup", "input_schema", core.NewObject()),
			core.NewObject("type", "computer_20250124", "name", "computer"),
		),
		"mcp_servers", items(core.NewObject("type", "url", "url", "http://[::1]:9000/mcp")),
	)); got != "code_execution,computer,mcp:_::1_" {
		t.Fatal(got)
	}
	// Only canonical http(s) URLs name a host: tricks that parse differently elsewhere read as invalid.
	if got := tools("/v1/messages", core.NewObject("mcp_servers", items(
		core.NewObject("url", "https://kb.acme.test"),
		core.NewObject("url", "https://evil.example./mcp"),
		core.NewObject("url", `https://kb.acme.test\@evil.example/mcp`),
		core.NewObject("url", "https://user@kb.acme.test/mcp"),
		core.NewObject("url", "https://kb.acme.test:443/mcp"),
	))); got != "mcp:kb.acme.test,mcp:evil.example,mcp:invalid" {
		t.Fatal(got)
	}
	if got := tools("/v1/responses", core.NewObject("prompt", core.NewObject("id", "pmpt_1"))); got != "prompt" {
		t.Fatal(got)
	}
	if got := tools("/v1/chat/completions", core.NewObject("web_search_options", core.NewObject(), "prompt", core.NewObject())); got != "web_search" {
		t.Fatal(got)
	}
	if got := toolKind("Ünïcode Tool 😀"); got != "_n_code_tool___" {
		t.Fatalf("tool kind: %q", got)
	}
	if got := toolKind("_20250101"); got != "unknown" {
		t.Fatalf("empty kind: %q", got)
	}
}

func TestInferenceGatewayCountsAnthropicTokensWithoutMetering(t *testing.T) {
	g := newGatewayFixture(t)
	g.updateModel(g.tenantID, "sonnet", "maxOutputTokens", 1000.0)
	counted := g.call("/v1/messages/count_tokens", g.owner.Token, core.NewObject("model", "sonnet",
		"messages", items(core.NewObject("role", "user", "content", "Hello"))))
	if counted.status != 200 || counted.text != `{"input_tokens":42}` {
		t.Fatal(counted.status, counted.text)
	}
	sent := g.upstream.call(0)
	if sent.url != "https://api.anthropic.com/v1/messages/count_tokens" ||
		gatewayJSON(sent.body) != `{"model":"claude-sonnet-5","messages":[{"role":"user","content":"Hello"}]}` {
		t.Fatalf("sent: %s %s", sent.url, gatewayJSON(sent.body))
	}
	if rows := g.usageByModel(); len(rows) != 0 {
		t.Fatalf("metered: %v", rows)
	}
	_, bob := g.person(g.tenantID, "bob")
	refused := g.call("/v1/messages/count_tokens", bob.Token, core.NewObject("model", "sonnet", "messages", []any{}))
	if refused.status != 403 {
		t.Fatal(refused.status)
	}
	infExpect(t, refused.json(t), "type", "error")
	infExpect(t, refused.json(t), "error.code", "ACCESS_DENIED")
	wrongFormat := g.call("/v1/responses", g.owner.Token, core.NewObject("model", "sonnet", "input", "x"))
	if wrongFormat.status != 400 {
		t.Fatal(wrongFormat.status)
	}
	infExpect(t, wrongFormat.json(t), "error.code", "WRONG_FORMAT")
}

func TestInferenceGatewayRefusesLargeBodiesAndUnreachableProviders(t *testing.T) {
	g := newGatewayFixture(t)
	options := gatewayOptionsWith(func(*http.Request) (*http.Response, error) { return nil, io.ErrUnexpectedEOF })
	options.Set("maxBodyBytes", 64.0)
	var reported []error
	options.SetRaw("onError", func(err error) { reported = append(reported, err) })
	gateway := must(CreateInferenceGateway(g.runtime, options))
	large := sendTo(t, gateway, "/v1/messages", g.owner.Token, core.NewObject("model", "sonnet", "messages", items(strings.Repeat("x", 100))))
	if large.status != 413 {
		t.Fatal(large.status)
	}
	infExpect(t, large.json(t), "error.type", "request_too_large")
	unreachable := sendTo(t, gateway, "/v1/messages", g.owner.Token, core.NewObject("model", "sonnet"))
	if unreachable.status != 502 {
		t.Fatal(unreachable.status, unreachable.text)
	}
	infExpect(t, unreachable.json(t), "error.code", "UPSTREAM_UNAVAILABLE")
	if len(reported) != 1 || reported[0] != io.ErrUnexpectedEOF {
		t.Fatalf("reported: %v", reported)
	}
	failed := g.find("inferenceUsage", core.NewObject("tenantId", g.tenantID))
	if len(failed) != 1 || failed[0].Get("status") != "error" || failed[0].Get("outputTokens") != 0.0 {
		t.Fatalf("metered failure: %s", gatewayJSON(failed))
	}
}

func TestInferenceGatewayFindsStoredProviderReferences(t *testing.T) {
	for _, body := range []*core.Object{
		core.NewObject("tools", items(core.NewObject("type", "code_interpreter", "container", core.NewObject("type", "auto", "file_ids", items("file-x"))))),
		core.NewObject("tools", items(core.NewObject("type", "file_search", "vector_store_ids", items("vs_other_tenant")))),
		core.NewObject("tools", items(core.NewObject("type", "image_generation", "input_image_mask", core.NewObject("file_id", "file-mask")))),
		core.NewObject("input", items(core.NewObject("type", "function_call_output", "call_id", "c",
			"output", items(core.NewObject("type", "input_file", "file_id", "file-y"))))),
		core.NewObject("messages", items(core.NewObject("role", "user", "content", items(core.NewObject("type", "tool_result", "tool_use_id", "t",
			"content", items(core.NewObject("type", "document", "source", core.NewObject("type", "file", "file_id", "f")))))))),
		core.NewObject("input", items(core.NewObject("type", "item_reference", "id", "msg_1"))),
	} {
		if StoredReference("/v1/responses", body) == "" {
			t.Fatalf("missed: %s", gatewayJSON(body))
		}
	}
	if found := StoredReference("/v1/responses", core.NewObject(
		"model", "gpt",
		"input", items(core.NewObject("role", "user", "content", items(core.NewObject("type", "input_text", "text", "file_id: nothing here")))),
		"tools", items(core.NewObject("type", "function", "name", "fetch",
			"parameters", core.NewObject("type", "object", "properties", core.NewObject("file_id", core.NewObject("type", "string"))))),
	)); found != "" {
		t.Fatalf("false positive: %s", found)
	}
	deep := any("leaf")
	for index := 0; index < 70; index++ {
		deep = items(deep)
	}
	if found := StoredReference("/v1/responses", core.NewObject("input", deep)); found != "too-complex" {
		t.Fatalf("deep: %q", found)
	}
}

func TestInferenceGatewayReadsUsageAndStreams(t *testing.T) {
	if got := gatewayJSON(UsageFrom("responses", core.NewObject("input_tokens", 30.0, "input_tokens_details", core.NewObject("cached_tokens", 10.0),
		"output_tokens", 12.0))); got != `{"inputTokens":20,"outputTokens":12,"cacheReadTokens":10}` {
		t.Fatal(got)
	}
	if got := gatewayJSON(UsageFrom("anthropic", core.NewObject("input_tokens", 1.0, "output_tokens", -2.0, "cache_creation_input_tokens", 3.0))); got != `{"inputTokens":1,"outputTokens":0,"cacheWriteTokens":3}` {
		t.Fatal(got)
	}
	if got := gatewayJSON(UsageFrom("openai", core.NewObject("prompt_tokens", 1.5, "completion_tokens", 4.0))); got != `{"inputTokens":0,"outputTokens":4}` {
		t.Fatal(got)
	}
	if UsageFrom("openai", nil) != nil || UsageFrom("openai", "x") != nil {
		t.Fatal("usage from nothing")
	}
	// A multi-byte character split across chunks, and CRLF line ends.
	tracker := newStreamUsage("anthropic")
	stream := []byte("data: {\"type\":\"content_block_delta\",\"delta\":{\"text\":\"héllo \U0001F600\"}}\r\n\r\n" +
		"data: {\"type\":\"message_start\",\"message\":{\"usage\":{\"input_tokens\":7}}}\n\n")
	for index := 0; index < len(stream); index += 3 {
		end := index + 3
		if end > len(stream) {
			end = len(stream)
		}
		if err := tracker.push(stream[index:end]); err != nil {
			t.Fatal(err)
		}
	}
	if tracker.outputChars != 8 || tracker.complete {
		t.Fatalf("chars: %d complete: %v", tracker.outputChars, tracker.complete)
	}
	if got := gatewayJSON(tracker.metered(1000)); got != `{"inputTokens":7,"outputTokens":2}` {
		t.Fatal(got)
	}
	if err := newStreamUsage("openai").push([]byte("data: null\n")); err == nil {
		t.Fatal("a null event does not fail the stream")
	}
	if upstreamURL("https://router.example/api/v1", "/v1/responses") != "https://router.example/api/v1/responses" ||
		upstreamURL("https://api.anthropic.com", "/v1/messages") != "https://api.anthropic.com/v1/messages" {
		t.Fatal("upstream URL")
	}
}
