package scim

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/adapters/sqlite"
	"github.com/Better-IAM/better-iam/go/core"
)

var bg = context.Background()

func newStore(t *testing.T) core.IamStore {
	t.Helper()
	store, err := sqlite.New(sqlite.Options{Filename: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(bg); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(bg) })
	return store
}

func must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}

func ok(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func insert(t *testing.T, store core.IamStore, collection string, records ...*core.Object) {
	t.Helper()
	ok(t, store.Transaction(bg, func(ctx context.Context, tx core.IamStore) error {
		for _, record := range records {
			if _, err := tx.Insert(ctx, collection, record); err != nil {
				return err
			}
		}
		return nil
	}))
}

func put(t *testing.T, store core.IamStore, collection string, record *core.Object) {
	t.Helper()
	ok(t, store.Transaction(bg, func(ctx context.Context, tx core.IamStore) error {
		_, err := tx.Put(ctx, collection, record)
		return err
	}))
}

func get(t *testing.T, store core.IamStore, collection, id string) *core.Object {
	t.Helper()
	return must(store.Get(bg, collection, id))
}

func find(t *testing.T, store core.IamStore, collection string, filter *core.Object) []*core.Object {
	t.Helper()
	return must(store.Find(bg, collection, filter, nil))
}

// answer is a decoded SCIM response.
type answer struct {
	status int
	header http.Header
	body   any
}

func (a answer) object() *core.Object {
	o, _ := a.body.(*core.Object)
	if o == nil {
		return core.NewObject()
	}
	return o
}

func (a answer) get(path ...string) any {
	var value any = a.object()
	for _, key := range path {
		value = member(value, key)
	}
	return value
}

func decode(t *testing.T, response *Response) answer {
	t.Helper()
	if response == nil {
		t.Fatal("the service did not answer")
	}
	result := answer{status: response.Status, header: response.Header}
	if len(response.Body) > 0 {
		result.body = must(core.ParseJSON(response.Body))
	}
	return result
}

// jsonBody serializes a request body: a string as it is, anything else as JSON.
func jsonBody(body any) io.Reader {
	if body == nil {
		return nil
	}
	if text, isText := body.(string); isText {
		return strings.NewReader(text)
	}
	return strings.NewReader(core.MustStringify(core.Normalize(body)))
}

// connectionCredential is what a test holds for a connection: its path and token.
type connectionCredential struct {
	path  string
	token string
	id    string
}

func credentialOf(created *core.Object) connectionCredential {
	return connectionCredential{path: created.Get("path").(string), token: created.Get("token").(string), id: created.Get("id").(string)}
}

// scimCall sends an IdP request to the service.
func scimCall(t *testing.T, service *Service, origin string, connection connectionCredential, resource, method string, body any, headers map[string]string) answer {
	t.Helper()
	if method == "" {
		method = "GET"
	}
	request := httptest.NewRequest(method, origin+connection.path+"/"+resource, jsonBody(body))
	request.Header.Set("authorization", "Bearer "+connection.token)
	request.Header.Set("content-type", "application/scim+json")
	for key, value := range headers {
		request.Header.Set(key, value)
	}
	return decode(t, service.Handle(request))
}

func expectCode(t *testing.T, err error, code string, status int) {
	t.Helper()
	known, isKnown := err.(*core.IamError)
	if !isKnown {
		t.Fatalf("expected IamError %s, got %v", code, err)
	}
	if known.Code != code || (status != 0 && known.Status != status) {
		t.Fatalf("expected %s (%d), got %s (%d): %s", code, status, known.Code, known.Status, known.Message)
	}
}

func patchOp(operations ...*core.Object) *core.Object {
	list := make([]any, len(operations))
	for index, operation := range operations {
		list[index] = operation
	}
	return core.NewObject("schemas", []any{PatchSchema}, "Operations", list)
}

func list(items ...any) []any { return items }

func obj(pairs ...any) *core.Object { return core.NewObject(pairs...) }

func show(value any) string {
	text, ok, err := core.Stringify(value)
	if err != nil || !ok {
		return "<unserializable>"
	}
	return text
}

func sameJSON(t *testing.T, got, want any) {
	t.Helper()
	if show(core.Normalize(got)) != show(core.Normalize(want)) {
		t.Fatalf("expected %s\n     got %s", show(core.Normalize(want)), show(core.Normalize(got)))
	}
}
