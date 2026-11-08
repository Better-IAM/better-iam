package ldap

// testdata/vectors.json was written by the compiled TypeScript package (encoders, DN and filter results, directory
// entries); the port must reproduce every vector exactly.

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

type vectors struct {
	Encodings []struct {
		Name string `json:"name"`
		Hex  string `json:"hex"`
	} `json:"encodings"`
	Dns []struct {
		Dn         string          `json:"dn"`
		Normalized *string         `json:"normalized"`
		Parsed     json.RawMessage `json:"parsed"`
		Error      *string         `json:"error"`
	} `json:"dns"`
	Escapes []struct {
		Value   string `json:"value"`
		Escaped string `json:"escaped"`
	} `json:"escapes"`
	Filters []struct {
		Text    string  `json:"text"`
		Match   *bool   `json:"match"`
		Encoded *string `json:"encoded"`
		Error   *string `json:"error"`
	} `json:"filters"`
	Data    json.RawMessage `json:"data"`
	Entries json.RawMessage `json:"entries"`
	Select  []struct {
		Requested  []string        `json:"requested"`
		Attributes json.RawMessage `json:"attributes"`
	} `json:"select"`
}

func mustFilter(t *testing.T, text string) *Filter {
	filter, err := ParseFilter(text)
	if err != nil {
		t.Fatal(err)
	}
	return filter
}

func attributesJSON(list []AttributeValues) []any {
	out := make([]any, len(list))
	for i, attribute := range list {
		values := make([]any, len(attribute.Values))
		for j, value := range attribute.Values {
			values[j] = value
		}
		out[i] = []any{attribute.Name, values}
	}
	return out
}

func TestLdapMatchesTheTypeScriptVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var v vectors
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	rule := "2.5.13.2"
	encodings := map[string][]byte{
		"bind":   EncodeBind(1, "uid=alice,ou=people,dc=acme,dc=test", "pässword"),
		"unbind": EncodeUnbind(7),
		"search": EncodeSearch(300, SearchOptions{Base: "dc=acme,dc=test", Scope: "one",
			Filter:     mustFilter(t, `(&(objectClass=person)(|(uid=al\2aice)(mail=*@acme.test))(!(cn>=m))(cn~=x)(sn<=z))`),
			Attributes: []string{"mail", "+"}, SizeLimit: 5, TypesOnly: true}, PagedResultsRequest(2, []byte("4"))),
		"extended":              EncodeExtended(70000, OIDWhoAmI, nil),
		"extendedValue":         EncodeExtended(2, "1.2.3", []byte("v")),
		"compare":               EncodeCompare(3, "uid=a,dc=x", "mail", "a@x"),
		"paged":                 PagedResultsRequest(1000, []byte{}),
		"bindResponse":          BindResponse(5, 49, "Invalid credentials"),
		"searchDone":            SearchDone(6, 0, "", "", PagedResultsControl(3, []byte("2"))),
		"searchDoneMatched":     SearchDone(6, 32, "No such object", "dc=acme,dc=test", nil),
		"compareResponse":       CompareResponse(8, 6, ""),
		"generic":               GenericResponse(9, 0x6b, 53, "This directory is read-only"),
		"extendedResponse":      ExtendedResponse(10, 0, "", "", []byte("dn:uid=a")),
		"extendedResponseEmpty": ExtendedResponse(10, 0, "", "", []byte{}),
		"notice":                NoticeOfDisconnection(52, "Idle timeout"),
		"entry":                 SearchEntry(11, "uid=a,dc=x", []AttributeValues{{"objectClass", []string{"top", "person"}}, {"mail", []string{"a@x"}}, {"empty", []string{}}}, false),
		"entryTypes":            SearchEntry(11, "uid=a,dc=x", []AttributeValues{{"objectClass", []string{"top", "person"}}}, true),
		"negative": EncodeSearch(271, SearchOptions{Base: "", Filter: &Filter{Type: "extensible", Attribute: "cn", HasAttribute: true,
			Rule: rule, HasRule: true, Value: "x", DnAttributes: true}}, nil),
	}
	for _, encoding := range v.Encodings {
		got, ok := encodings[encoding.Name]
		if !ok {
			t.Fatalf("no Go encoding for %s", encoding.Name)
		}
		if hex.EncodeToString(got) != encoding.Hex {
			t.Fatalf("%s:\n go %x\nnode %s", encoding.Name, got, encoding.Hex)
		}
		// Every encoded message decodes again.
		element, err := ReadElement(got, 0, len(got))
		if err != nil || element == nil {
			t.Fatalf("%s: %v", encoding.Name, err)
		}
	}
	for _, c := range v.Dns {
		normalized, err := NormalizeDn(c.Dn)
		if c.Error != nil {
			if _, parseErr := ParseDn(c.Dn); parseErr == nil || parseErr.Error() != *c.Error {
				t.Fatalf("%q: expected error %q, got %v", c.Dn, *c.Error, parseErr)
			}
			continue
		}
		if err != nil || normalized != *c.Normalized {
			t.Fatalf("%q: normalized %q (%v), want %q", c.Dn, normalized, err, *c.Normalized)
		}
		parsed, _ := ParseDn(c.Dn)
		if parsed == nil {
			parsed = [][]Rdn{}
		}
		got, _ := json.Marshal(parsed)
		want, _ := core.ParseJSON(c.Parsed)
		if core.MustStringify(must(core.ParseJSON(got))) != core.MustStringify(want) {
			t.Fatalf("%q: parsed %s, want %s", c.Dn, got, c.Parsed)
		}
	}
	for _, c := range v.Escapes {
		if got := EscapeDnValue(c.Value); got != c.Escaped {
			t.Fatalf("escape %q: %q, want %q", c.Value, got, c.Escaped)
		}
	}
	entry := EntryAttributes{"objectclass": {"top", "inetOrgPerson"}, "mail": {"alice@acme.test"}, "cn": {"Alice  Liddell"}, "uid": {"alice"}}
	for _, c := range v.Filters {
		filter, err := ParseFilter(c.Text)
		if c.Error != nil {
			if err == nil || err.Error() != *c.Error {
				t.Fatalf("%q: expected error %q, got %v", c.Text, *c.Error, err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%q: %v", c.Text, err)
		}
		if MatchFilter(filter, entry) != *c.Match {
			t.Fatalf("%q: match %v", c.Text, !*c.Match)
		}
		if got := hex.EncodeToString(EncodeFilter(filter)); got != *c.Encoded {
			t.Fatalf("%q: encoded %s, want %s", c.Text, got, *c.Encoded)
		}
	}
	model, err := core.ParseJSON(v.Data)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := BuildEntries(DirectoryDataFrom(model))
	if err != nil {
		t.Fatal(err)
	}
	var built []any
	for _, e := range entries {
		var index []any
		for _, name := range indexOrder(e) {
			values := make([]any, len(e.Index[name]))
			for i, value := range e.Index[name] {
				values[i] = value
			}
			index = append(index, []any{name, values})
		}
		built = append(built, core.NewObject("dn", e.Dn, "normalizedDn", e.NormalizedDn, "attributes", attributesJSON(e.Attributes),
			"operational", attributesJSON(e.Operational), "index", index))
	}
	want, _ := core.ParseJSON(v.Entries)
	if core.MustStringify(built) != core.MustStringify(want) {
		t.Fatalf("entries:\n go %s\nnode %s", core.MustStringify(built), core.MustStringify(want))
	}
	for _, c := range v.Select {
		got := attributesJSON(SelectAttributes(entries[3], c.Requested))
		want, _ := core.ParseJSON(c.Attributes)
		if core.MustStringify(got) != core.MustStringify(want) {
			t.Fatalf("select %v: %s, want %s", c.Requested, core.MustStringify(got), c.Attributes)
		}
	}
}

// indexOrder is the order the TypeScript Map was filled in: kept user attributes, then operational ones.
func indexOrder(e DirectoryEntry) []string {
	var names []string
	seen := map[string]int{}
	for _, attribute := range append(append([]AttributeValues(nil), e.Attributes...), e.Operational...) {
		name := core.JSLower(attribute.Name)
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = len(names)
		names = append(names, name)
	}
	return names
}

func must(value any, err error) any {
	if err != nil {
		panic(err)
	}
	return value
}
