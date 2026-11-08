package server

import (
	"net/http"
	"strconv"
	"strings"
	"testing"
)

// Port of tests/federation-import-gaps.test.ts "protocol redirects through the host": a protocol's
// `x-better-iam-redirect` hint becomes a 303 carrying the protocol's cookies and the session cookie, and untrusted
// targets are never followed.
func TestProtocolRedirectHintBecomes303WithSessionCookie(t *testing.T) {
	const base = "http://localhost:3000"
	f := newIam(t, base, func(options *BetterIamOptions) {
		options.TrustedOrigins = []string{"https://app.example.test"}
	})
	hint, status := "/dashboard", http.StatusOK
	f.iam.UseProtocol(ProtocolService{BasePath: "/fake-saml", Handler: func(w http.ResponseWriter, r *http.Request) bool {
		if r.URL.Path != "/fake-saml/acs" {
			return false
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("x-better-iam-redirect", hint)
		w.Header().Add("Set-Cookie", "binding=; Path=/; Max-Age=0")
		w.WriteHeader(status)
		if status == http.StatusOK {
			expiresAt := strconv.FormatInt(f.iam.Context.Now()+3_600_000, 10)
			_, _ = w.Write([]byte(`{"token":"session-token","session":{"expiresAt":` + expiresAt + `}}`))
		} else {
			_, _ = w.Write([]byte(`{"error":"SAML_INVALID"}`))
		}
		return true
	}})
	acs := func() *Response { return f.fetch(http.MethodPost, base+"/fake-saml/acs", nil, "") }
	sessionCookies := func(response *Response) []string {
		var found []string
		for _, cookie := range response.Header.Values("Set-Cookie") {
			if strings.HasPrefix(cookie, "better-iam.session=") {
				found = append(found, cookie)
			}
		}
		return found
	}

	signedIn := acs()
	if signedIn.Status != http.StatusSeeOther || signedIn.Header.Get("Location") != "/dashboard" {
		t.Fatalf("redirect: %d %q", signedIn.Status, signedIn.Header.Get("Location"))
	}
	if signedIn.Header.Get("x-better-iam-redirect") != "" || len(signedIn.Body) != 0 {
		t.Fatalf("hint or body leaked: %v %q", signedIn.Header, signedIn.Body)
	}
	if signedIn.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("cache-control: %q", signedIn.Header.Get("Cache-Control"))
	}
	cookies := signedIn.Header.Values("Set-Cookie")
	if len(cookies) != 2 || cookies[0] != "binding=; Path=/; Max-Age=0" || len(sessionCookies(signedIn)) != 1 {
		t.Fatalf("cookies: %v", cookies)
	}
	if !strings.HasPrefix(sessionCookies(signedIn)[0], "better-iam.session=session-token;") {
		t.Fatalf("session cookie: %q", sessionCookies(signedIn)[0])
	}

	hint = "https://app.example.test/welcome"
	if location := acs().Header.Get("Location"); location != "https://app.example.test/welcome" {
		t.Fatalf("trusted origin: %q", location)
	}

	// Untrusted origins, scheme-relative paths, backslashes and credentials are not followed: the JSON answer stands,
	// without the hint.
	for _, target := range []string{"https://evil.example.test/", "//evil.example.test/", "/\\evil", "https://user@app.example.test/", "javascript:alert(1)", "dashboard"} {
		hint = target
		answer := acs()
		if answer.Status != http.StatusOK || answer.Header.Get("Location") != "" || answer.Header.Get("x-better-iam-redirect") != "" {
			t.Fatalf("%q followed: %d %v", target, answer.Status, answer.Header)
		}
		if jsonBody(t, answer).Get("token") != "session-token" || len(sessionCookies(answer)) != 1 {
			t.Fatalf("%q: JSON answer changed: %q %v", target, answer.Body, answer.Header)
		}
	}

	// A failure with an error page goes there, without any session cookie.
	hint, status = "/login?error=SAML_INVALID", http.StatusUnauthorized
	failed := acs()
	if failed.Status != http.StatusSeeOther || failed.Header.Get("Location") != "/login?error=SAML_INVALID" {
		t.Fatalf("failure redirect: %d %q", failed.Status, failed.Header.Get("Location"))
	}
	if len(sessionCookies(failed)) != 0 {
		t.Fatalf("failure set a session cookie: %v", failed.Header.Values("Set-Cookie"))
	}
}
