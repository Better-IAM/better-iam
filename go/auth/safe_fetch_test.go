package auth

// Port of tests/safe-fetch.test.ts, tests/safe-fetch-cancel.test.ts and the guarded-fetch part of
// tests/security-outbound.test.ts.

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
)

func strictOptions() SafeFetchOptions { return SafeFetchOptions{TimeoutMs: 1000, MaxBytes: 1024} }

func localOptions() SafeFetchOptions {
	options := strictOptions()
	options.AllowInsecureLocalhost = true
	return options
}

func reasonOf(t *testing.T, err error) string {
	t.Helper()
	var refused *SafeFetchError
	if !errors.As(err, &refused) {
		t.Fatalf("expected a SafeFetchError, got %v", err)
	}
	return refused.Reason
}

func TestIsPublicAddress(t *testing.T) {
	for _, address := range []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "100.63.255.255", "100.128.0.1", "172.32.0.1",
		"2606:4700:4700::1111", "2a00:1450:4001:830::200e", "::ffff:8.8.8.8"} {
		if !IsPublicAddress(address) {
			t.Errorf("%s should be public", address)
		}
	}
	for _, address := range []string{"0.0.0.0", "10.0.0.1", "100.64.0.1", "127.0.0.1", "127.255.0.9", "169.254.169.254", "172.16.5.4",
		"172.31.255.255", "192.0.0.8", "192.0.2.10", "192.88.99.1", "192.168.1.1", "198.18.0.1", "198.51.100.7", "203.0.113.9",
		"224.0.0.1", "240.0.0.1", "255.255.255.255", "::", "::1", "::ffff:10.0.0.1", "::ffff:127.0.0.1", "::ffff:a9fe:a9fe",
		"64:ff9b::a00:1", "64:ff9b:1::a00:1", "::127.0.0.1", "::a00:1", "::a9fe:a9fe", "100::1", "2001::1", "2001:10::1",
		"2001:db8::1", "2002:0a00::", "2002:808:808::1", "fd00::1", "fc00::1", "fe80::1", "fec0::1", "ff02::1",
		"::ffff:0:7f00:1", "::ffff:0:a9fe:a9fe"} {
		if IsPublicAddress(address) {
			t.Errorf("%s should not be public", address)
		}
	}
	for _, address := range []string{"", "example.com", "1.2.3", "01.2.3.4", "256.1.1.1", "fe80::1%eth0", "[::1]", "1.2.3.4/32"} {
		if IsPublicAddress(address) {
			t.Errorf("malformed %q should not be public", address)
		}
	}
}

func TestCheckFetchURL(t *testing.T) {
	strict := SafeFetchAddressOptions{}
	if u := must[*FetchURL](t)(CheckFetchURL("https://idp.example.com/.well-known/jwks.json", strict)); u.Href != "https://idp.example.com/.well-known/jwks.json" {
		t.Errorf("href %s", u.Href)
	}
	if u := must[*FetchURL](t)(CheckFetchURL("https://idp.example.com:443/keys?x=1", strict)); u.Port != "" {
		t.Errorf("port %q", u.Port)
	}
	if u := must[*FetchURL](t)(CheckFetchURL("https://8.8.8.8/keys", strict)); u.Hostname != "8.8.8.8" {
		t.Errorf("hostname %q", u.Hostname)
	}
	for _, item := range [][2]string{
		{"http://idp.example.com/jwks", "url"}, {"https://idp.example.com:8443/jwks", "url"},
		{"https://user:secret@idp.example.com/jwks", "url"}, {"https://idp.example.com/jwks#keys", "url"},
		{"https://idp.example.com/jwks#", "url"}, {"/jwks", "url"}, {"file:///etc/passwd", "url"},
		{"http://localhost:8080/jwks", "url"}, {"https://10.0.0.1/jwks", "address"},
		{"https://169.254.169.254/latest/meta-data", "address"}, {"https://[::1]/jwks", "address"},
		{"https://[::ffff:10.0.0.1]/jwks", "address"}, {"https://[fd00::1]/jwks", "address"},
	} {
		_, err := CheckFetchURL(item[0], strict)
		if reason := reasonOf(t, err); reason != item[1] {
			t.Errorf("%s: %s, expected %s", item[0], reason, item[1])
		}
	}
	private := SafeFetchAddressOptions{AllowPrivateNetworks: true}
	if u := must[*FetchURL](t)(CheckFetchURL("https://10.0.0.1/jwks", private)); u.Hostname != "10.0.0.1" {
		t.Error("allowPrivateNetworks")
	}
	_, err := CheckFetchURL("http://10.0.0.1/jwks", private)
	if reasonOf(t, err) != "url" {
		t.Error("http with allowPrivateNetworks")
	}
	local := SafeFetchAddressOptions{AllowInsecureLocalhost: true}
	for _, address := range []string{"http://127.0.0.1:9000/jwks", "http://localhost:9000/jwks", "http://[::1]:9000/"} {
		if u := must[*FetchURL](t)(CheckFetchURL(address, local)); u.Protocol != "http:" {
			t.Errorf("%s: protocol %s", address, u.Protocol)
		}
	}
	for _, address := range []string{"http://10.0.0.1:9000/", "ftp://127.0.0.1/"} {
		_, err := CheckFetchURL(address, local)
		if reasonOf(t, err) != "url" {
			t.Errorf("%s accepted", address)
		}
	}
}

func jsonServer(t *testing.T) string {
	t.Helper()
	write := func(status int, contentType, body string) http.HandlerFunc {
		return func(w http.ResponseWriter, _ *http.Request) {
			if contentType != "" {
				w.Header().Set("content-type", contentType)
			}
			w.WriteHeader(status)
			_, _ = io.WriteString(w, body)
		}
	}
	mux := http.NewServeMux()
	mux.Handle("/ok", write(200, "application/json; charset=utf-8", `{"keys":[{"kid":"a"}]}`))
	mux.Handle("/jwk-set", write(200, "application/jwk-set+json", `{"keys":[]}`))
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("location", "http://169.254.169.254/")
		w.WriteHeader(302)
	})
	mux.Handle("/missing", write(404, "application/json", "{}"))
	mux.Handle("/error", write(500, "application/json", "{}"))
	mux.Handle("/created", write(201, "application/json", "{}"))
	mux.Handle("/html", write(200, "text/html", "<html></html>"))
	mux.Handle("/no-type", write(200, "", "{}"))
	mux.Handle("/large-declared", write(200, "application/json", `{"padding":"`+strings.Repeat("x", 4096)+`"}`))
	mux.HandleFunc("/large-chunked", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("content-type", "application/json")
		_, _ = io.WriteString(w, `{"padding":"`)
		for {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(5 * time.Millisecond):
				if _, err := io.WriteString(w, strings.Repeat("x", 512)); err != nil {
					return
				}
				w.(http.Flusher).Flush()
			}
		}
	})
	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(2 * time.Second):
			w.Header().Set("content-type", "application/json")
			_, _ = io.WriteString(w, "{}")
		}
	})
	mux.Handle("/bad-json", write(200, "application/json", `{"keys":`))
	server := httptest.NewServer(mux)
	t.Cleanup(func() {
		server.CloseClientConnections()
		server.Close()
	})
	return server.URL
}

func TestFetchJSONSafely(t *testing.T) {
	base := jsonServer(t)
	ctx := context.Background()
	if got := must[any](t)(FetchJSONSafely(ctx, base+"/ok", localOptions())); MustJSON(got) != `{"keys":[{"kid":"a"}]}` {
		t.Errorf("ok: %s", MustJSON(got))
	}
	if got := must[any](t)(FetchJSONSafely(ctx, base+"/jwk-set", localOptions())); MustJSON(got) != `{"keys":[]}` {
		t.Errorf("jwk-set: %s", MustJSON(got))
	}
	_, port, _ := net.SplitHostPort(strings.TrimPrefix(base, "http://"))
	if got := must[any](t)(FetchJSONSafely(ctx, "http://localhost:"+port+"/ok", localOptions())); MustJSON(got) != `{"keys":[{"kid":"a"}]}` {
		t.Errorf("localhost: %s", MustJSON(got))
	}
	_, err := FetchJSONSafely(ctx, base+"/ok", strictOptions())
	if reasonOf(t, err) != "url" {
		t.Error("the loopback server was reachable without the dev option")
	}
	_, err = FetchJSONSafely(ctx, "https://localhost/ok", strictOptions())
	if reasonOf(t, err) != "address" {
		t.Error("localhost passed the guarded lookup")
	}
	for _, item := range [][2]string{
		{"/redirect", "redirect"}, {"/missing", "status"}, {"/error", "status"}, {"/created", "status"}, {"/html", "content-type"},
		{"/no-type", "content-type"}, {"/large-declared", "size"}, {"/large-chunked", "size"}, {"/bad-json", "json"},
	} {
		_, err := FetchJSONSafely(ctx, base+item[0], localOptions())
		if reason := reasonOf(t, err); reason != item[1] {
			t.Errorf("%s: %s, expected %s", item[0], reason, item[1])
		}
	}
	slow := localOptions()
	slow.TimeoutMs = 200
	started := time.Now()
	_, err = FetchJSONSafely(ctx, base+"/slow", slow)
	if reasonOf(t, err) != "timeout" || time.Since(started) > 1500*time.Millisecond {
		t.Errorf("deadline: %v after %v", err, time.Since(started))
	}
	listener, _ := net.Listen("tcp", "127.0.0.1:0")
	address := listener.Addr().String()
	_ = listener.Close()
	_, err = FetchJSONSafely(ctx, "http://"+address+"/ok", localOptions())
	if reasonOf(t, err) != "network" {
		t.Error("a refused connection is not a network failure")
	}
}

// MustJSON stringifies a model value.
func MustJSON(value any) string {
	text, _, _ := core.Stringify(value)
	return text
}

func refusalReason(t *testing.T, err error) string {
	t.Helper()
	var failed *FetchFailedError
	if !errors.As(err, &failed) {
		t.Fatalf("expected fetch failed, got %v", err)
	}
	return reasonOf(t, failed.Cause)
}

func TestGuardedFetchRefusesPrivateTargetsBeforeConnecting(t *testing.T) {
	guarded := CreateGuardedFetch(GuardedFetchOptions{SafeFetchAddressOptions: SafeFetchAddressOptions{AnyPort: true}})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	var connections atomic.Int32
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connections.Add(1)
			_ = conn.Close()
		}
	}()
	_, port, _ := net.SplitHostPort(listener.Addr().String())
	post := func(address string) error {
		request, err := http.NewRequest(http.MethodPost, address, strings.NewReader("{}"))
		if err != nil {
			return err
		}
		_, err = guarded.Do(request)
		return err
	}
	for _, address := range []string{"https://10.0.0.5:8443/hook", "https://169.254.169.254/latest/meta-data", "https://[::1]:6443/",
		"https://[::ffff:0:7f00:1]/", "https://127.0.0.1:" + port + "/", "https://localhost:" + port + "/"} {
		if reason := refusalReason(t, post(address)); reason != "address" {
			t.Errorf("%s: %s", address, reason)
		}
	}
	if connections.Load() != 0 {
		t.Error("a refused target was connected to")
	}
	for _, address := range []string{"http://example.com/", "file:///etc/passwd"} {
		if reason := refusalReason(t, post(address)); reason != "url" {
			t.Errorf("%s: %s", address, reason)
		}
	}
	request, _ := http.NewRequest(http.MethodGet, "https://example.com:8443/", nil)
	_, err = CreateGuardedFetch(GuardedFetchOptions{}).Do(request)
	if refusalReason(t, err) != "url" {
		t.Error("non-443 port without anyPort")
	}
}

func TestGuardedFetchWorksLikeFetch(t *testing.T) {
	var method, contentType, received string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		data, _ := io.ReadAll(r.Body)
		method, contentType, received = r.Method, r.Header.Get("content-type"), string(data)
		if r.URL.Path == "/r" {
			w.Header().Set("location", "http://169.254.169.254/")
			w.WriteHeader(302)
			return
		}
		w.Header().Set("content-type", "application/json")
		w.Header().Set("x-reply", "yes")
		w.WriteHeader(201)
		_, _ = io.WriteString(w, `{"ok":true}`)
	}))
	defer server.Close()
	guarded := CreateGuardedFetch(GuardedFetchOptions{SafeFetchAddressOptions: SafeFetchAddressOptions{AllowInsecureLocalhost: true}})
	request, _ := http.NewRequest(http.MethodPost, server.URL+"/in", strings.NewReader(`{"hello":"world"}`))
	request.Header.Set("content-type", "application/json")
	response := must[*http.Response](t)(guarded.Do(request))
	data, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 201 || response.Header.Get("x-reply") != "yes" || string(data) != `{"ok":true}` {
		t.Errorf("response %d %s", response.StatusCode, data)
	}
	if method != "POST" || contentType != "application/json" || received != `{"hello":"world"}` {
		t.Errorf("request %s %s %s", method, contentType, received)
	}
	manual, _ := http.NewRequest(http.MethodGet, server.URL+"/r", nil)
	redirected := must[*http.Response](t)(guarded.Do(manual))
	redirected.Body.Close()
	if redirected.StatusCode != 302 {
		t.Errorf("redirect followed: %d", redirected.StatusCode)
	}
	manual, _ = http.NewRequest(http.MethodGet, server.URL+"/r", nil)
	_, err := guarded.DoRedirectError(manual)
	if refusalReason(t, err) != "redirect" {
		t.Error("redirect: 'error'")
	}
}

func TestGuardedFetchBoundsBodiesAndHonoursCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/slow":
			select {
			case <-r.Context().Done():
			case <-time.After(2 * time.Second):
			}
		case "/small":
			_, _ = io.WriteString(w, `{"ok":true}`)
		case "/exact":
			_, _ = io.WriteString(w, strings.Repeat("z", 1024))
		case "/error":
			w.WriteHeader(500)
			_, _ = io.WriteString(w, `{"error":"`+strings.Repeat("x", 200)+`"}`)
		default:
			_, _ = io.WriteString(w, strings.Repeat("x", 64*1024))
		}
	}))
	defer server.Close()
	limit := int64(1024)
	guarded := CreateGuardedFetch(GuardedFetchOptions{SafeFetchAddressOptions: SafeFetchAddressOptions{AllowInsecureLocalhost: true, AnyPort: true}, MaxBytes: &limit})
	get := func(path string) ([]byte, error) {
		request, _ := http.NewRequest(http.MethodGet, server.URL+path, nil)
		response, err := guarded.Do(request)
		if err != nil {
			return nil, err
		}
		defer response.Body.Close()
		return io.ReadAll(response.Body)
	}
	if data, err := get("/small"); err != nil || string(data) != `{"ok":true}` {
		t.Errorf("small: %s %v", data, err)
	}
	if _, err := get("/big"); err == nil {
		t.Error("an oversized body was read")
	}
	if data, err := get("/exact"); err != nil || len(data) != 1024 {
		t.Errorf("exact: %d %v", len(data), err)
	}
	// Closing a body early (the SSF transmitter cancels every response) is harmless.
	for _, bound := range []*int64{nil, &limit} {
		fetch := CreateGuardedFetch(GuardedFetchOptions{SafeFetchAddressOptions: SafeFetchAddressOptions{AllowInsecureLocalhost: true, AnyPort: true}, MaxBytes: bound})
		for attempt := 0; attempt < 10; attempt++ {
			request, _ := http.NewRequest(http.MethodPost, server.URL+"/error", strings.NewReader("{}"))
			response := must[*http.Response](t)(fetch.DoRedirectError(request))
			_ = response.Body.Close()
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/slow", nil)
	if _, err := guarded.Do(request); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("abort: %v", err)
	}
}
