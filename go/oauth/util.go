// Package oauth is the Go port of @better-iam/oauth: OAuth 2.0 and OpenID Connect sign-in with external providers
// (createOAuthLogin), a tenant-aware OAuth 2.1 / OpenID Connect authorization server (createOAuthProvider, a native
// implementation of the oidc-provider features the TypeScript configuration enables), offline access token
// verification for resource servers (createAccessTokenVerifier, createResourceGuard) and an OpenID Shared Signals
// Framework transmitter (createSharedSignalsTransmitter).
//
// Records, sealed artifacts and audit events are byte-compatible with the TypeScript package, so TypeScript, Rust
// and Go replicas can share one database.
package oauth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"math"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// Response is a complete HTTP response a handler produced (the Fetch API Response of the TypeScript handlers).
type Response struct {
	Status int
	Header http.Header
	Body   []byte
}

// WriteTo writes the response to w.
func (r *Response) WriteTo(w http.ResponseWriter) {
	for key, values := range r.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}
	w.WriteHeader(r.Status)
	if len(r.Body) > 0 {
		_, _ = w.Write(r.Body)
	}
}

// jsonResponse is Response.json(value, { status, headers }).
func jsonResponse(status int, value any, headers map[string]string) *Response {
	header := http.Header{}
	for key, item := range headers {
		header.Set(key, item)
	}
	header.Set("content-type", "application/json")
	return &Response{Status: status, Header: header, Body: []byte(stringify(value))}
}

// stringify is JSON.stringify for model values ("" for undefined).
func stringify(value any) string {
	text, _, err := core.Stringify(value)
	if err != nil {
		return ""
	}
	return text
}

// wallNow is Date.now().
func wallNow() int64 { return time.Now().UnixMilli() }

// epoch is Math.floor(ms / 1000).
func epoch(ms int64) int64 { return int64(math.Floor(float64(ms) / 1000)) }

// hash is the SHA-256 hex digest the TypeScript package keys records with.
func hash(text string) string {
	digest := sha256.Sum256(utf8Bytes(text))
	return hex.EncodeToString(digest[:])
}

// Hash is adapter.ts `hash`: the SHA-256 hex digest of a token or identifier.
func Hash(text string) string { return hash(text) }

// sha256B64URL is crypto.hash('sha256', value, 'base64url').
func sha256B64URL(text string) string {
	digest := sha256.Sum256(utf8Bytes(text))
	return b64url(digest[:])
}

func b64url(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

// utf8Bytes is Buffer.from(value): UTF-8 with unpaired surrogates replaced by U+FFFD.
func utf8Bytes(s string) []byte {
	if !strings.Contains(s, "\xed") {
		return []byte(s)
	}
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		c := s[i]
		if c == 0xED && i+2 < len(s) && s[i+1] >= 0xA0 && s[i+1] <= 0xBF && s[i+2]&0xC0 == 0x80 {
			out = append(out, 0xEF, 0xBF, 0xBD)
			i += 3
			continue
		}
		out = append(out, c)
		i++
	}
	return out
}

// decodeUTF8 is Buffer#toString('utf8') (invalid sequences become U+FFFD).
func decodeUTF8(b []byte) string {
	if utf8.Valid(b) {
		return string(b)
	}
	return strings.ToValidUTF8(string(b), "�")
}

// nodeBase64Decode is Buffer.from(value, 'base64'): both alphabets, padding and junk skipped.
func nodeBase64Decode(s string) []byte {
	var clean strings.Builder
	for _, c := range s {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			clean.WriteRune(c)
		case c == '+' || c == '-':
			clean.WriteByte('+')
		case c == '/' || c == '_':
			clean.WriteByte('/')
		case c == '=':
			goto done
		}
	}
done:
	text := clean.String()
	if len(text)%4 == 1 {
		text = text[:len(text)-1]
	}
	out, err := base64.RawStdEncoding.DecodeString(text)
	if err != nil {
		return nil
	}
	return out
}

func isUndefined(value any) bool { return core.IsUndefined(value) }

// truthy is JavaScript truthiness.
func truthy(value any) bool {
	switch v := value.(type) {
	case nil, core.UndefinedType:
		return false
	case bool:
		return v
	case string:
		return v != ""
	case float64:
		return v != 0 && !math.IsNaN(v)
	case *core.Object:
		return v != nil
	}
	return true
}

// jsString is String(value).
func jsString(value any) string {
	switch v := value.(type) {
	case nil:
		return "null"
	case core.UndefinedType:
		return "undefined"
	case bool:
		if v {
			return "true"
		}
		return "false"
	case string:
		return v
	case float64:
		return core.NumberString(v)
	case []any:
		parts := make([]string, len(v))
		for index, item := range v {
			if item == nil || core.IsUndefined(item) {
				continue
			}
			parts[index] = jsString(item)
		}
		return strings.Join(parts, ",")
	case *core.Object:
		return "[object Object]"
	}
	return jsString(core.Normalize(value))
}

// str is a string member ("" when absent or not a string).
func str(o *core.Object, key string) string {
	if o == nil {
		return ""
	}
	value, _ := o.Get(key).(string)
	return value
}

// num is a number member.
func num(o *core.Object, key string) (float64, bool) {
	if o == nil {
		return 0, false
	}
	value, ok := o.Get(key).(float64)
	return value, ok
}

// get is a member of a possibly nil object (Undefined when absent).
func get(o *core.Object, key string) any {
	if o == nil {
		return core.Undefined
	}
	return o.Get(key)
}

// obj is an object member (nil when absent).
func obj(o *core.Object, key string) *core.Object {
	if o == nil {
		return nil
	}
	value, _ := o.Get(key).(*core.Object)
	return value
}

// strings of an array member that are strings.
func stringList(value any) []string {
	list, ok := value.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func anyList(values []string) []any {
	out := make([]any, len(values))
	for index, value := range values {
		out[index] = value
	}
	return out
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// unique is [...new Set(values)].
func unique(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

// splitFilter is value.split(' ').filter(Boolean).
func splitFilter(value string) []string {
	out := []string{}
	for _, part := range strings.Split(value, " ") {
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}

func sortedStrings(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func boolPtr(value bool) *bool { return &value }

// isSafeInteger is Number.isSafeInteger.
func isSafeInteger(value any) bool { return core.IsSafeInteger(value) }

// parsedURL is a WHATWG-parsed absolute URL.
type parsedURL = auth.FetchURL

// parseURL is `new URL(value)`.
func parseURL(value string) (*parsedURL, error) { return auth.ParseFetchURL(value) }

// canParseURL is URL.canParse.
func canParseURL(value string) bool {
	_, err := parseURL(value)
	return err == nil
}

// urlOrigin is URL#origin ("null" for non-special schemes).
func urlOrigin(u *parsedURL) string {
	switch u.Protocol {
	case "http:", "https:", "ws:", "wss:", "ftp:":
		host := u.Hostname
		if u.Port != "" {
			host += ":" + u.Port
		}
		return u.Protocol + "//" + host
	}
	return "null"
}

// urlPathname is URL#pathname.
func urlPathname(u *parsedURL) string {
	if u.Opaque != "" {
		return u.Opaque
	}
	path := u.EscapedPath()
	if path == "" {
		switch u.Protocol {
		case "http:", "https:", "ws:", "wss:", "ftp:":
			return "/"
		}
	}
	return path
}

// urlHasCredentials is whether a URL has a username or password.
func urlHasCredentials(u *parsedURL) bool {
	return u.User != nil && (u.User.Username() != "" || func() bool { _, set := u.User.Password(); return set }())
}

// urlHasHash is whether a URL has a non-empty fragment (URL#hash).
func urlHasHash(u *parsedURL) bool { return u.Fragment != "" || u.RawFragment != "" }

// urlHasSearch is whether a URL has a non-empty query (URL#search).
func urlHasSearch(u *parsedURL) bool { return u.RawQuery != "" }

// withoutSearchAndHash is the URL's href after `url.search = ”; url.hash = ”`.
func withoutSearchAndHash(u *parsedURL) string {
	copy := *u.URL
	copy.RawQuery = ""
	copy.ForceQuery = false
	copy.Fragment = ""
	copy.RawFragment = ""
	return copy.String()
}

var loopbacks = []string{"localhost", "127.0.0.1", "[::1]"}

// formEncode is URLSearchParams serialization (application/x-www-form-urlencoded) of ordered pairs.
func formEncode(pairs [][2]string) string {
	parts := make([]string, len(pairs))
	for index, pair := range pairs {
		parts[index] = formEscape(pair[0]) + "=" + formEscape(pair[1])
	}
	return strings.Join(parts, "&")
}

// formEscape is the application/x-www-form-urlencoded byte serializer.
func formEscape(s string) string {
	var b strings.Builder
	for _, c := range utf8Bytes(s) {
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '*', c == '-', c == '.', c == '_':
			b.WriteByte(c)
		case c == ' ':
			b.WriteByte('+')
		default:
			b.WriteString("%" + strings.ToUpper(strconv.FormatInt(int64(c)>>4, 16)) + strings.ToUpper(strconv.FormatInt(int64(c)&15, 16)))
		}
	}
	return b.String()
}

// encodeURIComponent is the JavaScript global.
func encodeURIComponent(s string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_.!~*'()"
	var b strings.Builder
	for _, c := range utf8Bytes(s) {
		if strings.IndexByte(unreserved, c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteString("%" + strings.ToUpper(strconv.FormatInt(int64(c)>>4, 16)) + strings.ToUpper(strconv.FormatInt(int64(c)&15, 16)))
	}
	return b.String()
}

// decodeURIComponent is the JavaScript global (ok false where it throws a URIError).
func decodeURIComponent(s string) (string, bool) {
	if !strings.Contains(s, "%") {
		return s, true
	}
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] != '%' {
			out = append(out, s[i])
			continue
		}
		if i+2 >= len(s) {
			return "", false
		}
		value, err := strconv.ParseUint(s[i+1:i+3], 16, 8)
		if err != nil {
			return "", false
		}
		out = append(out, byte(value))
		i += 2
	}
	if !utf8.Valid(out) {
		return "", false
	}
	return string(out), true
}

// queryUnescape is Node's querystring.unescape: decodeURIComponent, falling back to decoding the valid %XX
// sequences byte by byte.
func queryUnescape(s string) string {
	if decoded, ok := decodeURIComponent(s); ok {
		return decoded
	}
	var out []byte
	for i := 0; i < len(s); i++ {
		if s[i] == '%' && i+2 < len(s) {
			if value, err := strconv.ParseUint(s[i+1:i+3], 16, 8); err == nil {
				out = append(out, byte(value))
				i += 2
				continue
			}
		}
		out = append(out, s[i])
	}
	return decodeUTF8(out)
}

// queryParse is Node's querystring.parse: repeated keys become arrays, '+' is a space. Keys keep their order.
func queryParse(text string) *core.Object {
	out := core.NewObject()
	if text == "" {
		return out
	}
	for _, part := range strings.Split(text, "&") {
		if part == "" {
			continue
		}
		key, value := part, ""
		if index := strings.Index(part, "="); index >= 0 {
			key, value = part[:index], part[index+1:]
		}
		key = queryUnescape(strings.ReplaceAll(key, "+", " "))
		value = queryUnescape(strings.ReplaceAll(value, "+", " "))
		switch existing := out.Get(key).(type) {
		case string:
			out.Set(key, []any{existing, value})
		case []any:
			out.Set(key, append(existing, value))
		default:
			out.Set(key, value)
		}
	}
	return out
}

// headerValue reads a header from a plain header map.
func headerValue(headers http.Header, name string) string {
	if headers == nil {
		return ""
	}
	return headers.Get(name)
}

// jsonParse parses JSON text into the core model.
func jsonParse(text string) (any, error) { return core.ParseJSONString(text) }

// toObject converts a Go map or struct into an *core.Object.
func toObject(value any) *core.Object {
	switch v := value.(type) {
	case *core.Object:
		return v
	case nil:
		return nil
	}
	if normalized, ok := core.Normalize(value).(*core.Object); ok {
		return normalized
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	parsed, _ := core.ParseJSON(raw)
	o, _ := parsed.(*core.Object)
	return o
}

// htmlSafe is oidc-provider's html_safe.
func htmlSafe(input any) string {
	switch v := input.(type) {
	case float64:
		if math.IsInf(v, 0) || math.IsNaN(v) {
			return ""
		}
		return core.NumberString(v)
	case string:
		return strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&#39;").Replace(v)
	case bool:
		if v {
			return "true"
		}
		return "false"
	}
	return ""
}

// randomUUID is crypto.randomUUID (a version 4 UUID).
func randomUUID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b)
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}
