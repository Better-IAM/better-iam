package main

import (
	"bytes"
	"os"
	"testing"
)

// client_gen.go must be what the generator writes from the current operation table (run go generate in go/client).
func TestClientGenIsCurrent(t *testing.T) {
	source, err := os.ReadFile("../../../apitypes/operations_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	want, err := generate(source)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile("../../client_gen.go")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.ReplaceAll(got, []byte("\r\n"), []byte("\n")), want) {
		t.Fatal("go/client/client_gen.go is stale: run go generate in go/client")
	}
}

func TestPascalMatchesTheTypeGenerator(t *testing.T) {
	for input, want := range map[string]string{
		"accessPaths": "AccessPaths", "oidcProviders": "OidcProviders", "getCallerIdentity": "GetCallerIdentity",
		"listIPRanges": "ListIPRanges", "apiKeys": "APIKeys", "jwks": "Jwks", "SCIMTokens": "ScimTokens",
	} {
		if got := pascal(input); got != want {
			t.Errorf("pascal(%q) = %q, want %q", input, got, want)
		}
	}
}
