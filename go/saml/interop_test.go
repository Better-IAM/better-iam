package saml

// Interoperability with the TypeScript dependencies: testdata/interop.json holds responses that xml-crypto signed
// (and xml-encryption encrypted), with the canonical XML node-saml's getVerifiedXml returned for them and the outcome
// of node-saml's validatePostResponseAsync (profile, assertion XML, error message, cache left behind). The Go port
// must reproduce each one exactly.

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

type memoryCache struct{ saved map[string]string }

func (c *memoryCache) SaveAsync(_ context.Context, key, value string) error {
	c.saved[key] = value
	return nil
}

func (c *memoryCache) GetAsync(_ context.Context, key string) (string, bool, error) {
	value, ok := c.saved[key]
	return value, ok && value != "", nil
}

func (c *memoryCache) RemoveAsync(_ context.Context, key string) (string, bool, error) {
	value, ok := c.saved[key]
	delete(c.saved, key)
	return value, ok, nil
}

type interopCase struct {
	Name        string          `json:"name"`
	XML         string          `json:"xml"`
	Unsolicited bool            `json:"unsolicited"`
	Canon       *string         `json:"canon"`
	Outcome     json.RawMessage `json:"outcome"`
	CacheAfter  []string        `json:"cacheAfter"`
}

func TestInteropWithNodeSaml(t *testing.T) {
	data, err := os.ReadFile("testdata/interop.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		At    int64         `json:"at"`
		Cert  string        `json:"cert"`
		Cases []interopCase `json:"cases"`
	}
	if err := json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	key, err := os.ReadFile("testdata/key.pem")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range fixtures.Cases {
		t.Run(c.Name, func(t *testing.T) {
			doc := must(ParseXML(c.XML))
			canon, err := getVerifiedXml(c.XML, doc.DocumentElement(), []string{fixtures.Cert})
			switch {
			case c.Canon == nil:
				if err != nil || canon != "" {
					t.Fatalf("expected no verified XML, got %q %v", canon, err)
				}
			case len(*c.Canon) > 7 && (*c.Canon)[:7] == "error: ":
				if err == nil || err.Error() != (*c.Canon)[7:] {
					t.Fatalf("expected error %q, got %v", (*c.Canon)[7:], err)
				}
			default:
				if err != nil || canon != *c.Canon {
					t.Fatalf("canonical XML differs:\n go: %s\nnode: %s\n(%v)", canon, *c.Canon, err)
				}
			}
			cache := &memoryCache{saved: map[string]string{"_fixture": isoString(fixtures.At)}}
			s := &nodeSaml{options: samlOptions{
				entryPoint: "https://idp.test/login", issuer: "https://iam.test/saml/acme/metadata", idpIssuer: "https://idp.test",
				callbackURL: "https://iam.test/saml/acme/acs", audience: "https://iam.test/saml/acme/metadata",
				idpCert: []string{fixtures.Cert}, privateKey: string(key), publicCert: fixtures.Cert, decryptionPvk: string(key),
				validateAlways: !c.Unsolicited, cache: cache, generateUniqueID: func() string { return "_x" },
				now: func() int64 { return fixtures.At },
			}}
			result, err := s.validatePostResponse(context.Background(), b64(c.XML))
			var got *core.Object
			if err != nil {
				got = core.NewObject("error", err.Error())
			} else {
				var profile any = nil
				if result.profile != nil {
					profile = result.profile
				}
				var assertion any = nil
				if result.profile != nil {
					assertion = result.assertion
				}
				got = core.NewObject("profile", profile, "loggedOut", result.loggedOut, "assertion", assertion)
			}
			want, err := core.ParseJSON(c.Outcome)
			if err != nil {
				t.Fatal(err)
			}
			if core.MustStringify(got) != core.MustStringify(want) {
				t.Fatalf("outcome differs:\n go: %s\nnode: %s", core.MustStringify(got), core.MustStringify(want))
			}
			keys := make([]string, 0, len(cache.saved))
			for key := range cache.saved {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			sort.Strings(c.CacheAfter)
			if core.MustStringify(stringsOf(keys)) != core.MustStringify(stringsOf(c.CacheAfter)) {
				t.Fatalf("cache after: go %v, node %v", keys, c.CacheAfter)
			}
		})
	}
}

func stringsOf(values []string) []any {
	out := make([]any, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
}
