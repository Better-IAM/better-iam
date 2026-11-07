package core

import (
	"context"
	"errors"
	"fmt"
	"math"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ConformanceCase is one behavioral check every IamStore adapter must pass. Give every case a freshly created and
// migrated store, then close it afterwards (a case may close the store itself; Close must be idempotent). This is
// the Go port of @better-iam/core adapterConformanceCases(), case for case. Checks that JavaScript can express but
// Go's types cannot (sparse arrays, arrays with extra properties, symbol keys, a fractional limit, a non-string
// cursor) are left out of the Go cases; everything else is identical.
type ConformanceCase struct {
	Name string
	Run  func(ctx context.Context, store IamStore) error
}

// ConformanceFailure is a failed conformance check.
type ConformanceFailure struct{ Message string }

func (e *ConformanceFailure) Error() string { return e.Message }

type conformanceAbort struct{ err error }

func check(condition bool, message string) {
	if !condition {
		panic(conformanceAbort{&ConformanceFailure{message}})
	}
}

func must[T any](value T, err error) T {
	if err != nil {
		panic(conformanceAbort{err})
	}
	return value
}

func mustDo(err error) {
	if err != nil {
		panic(conformanceAbort{err})
	}
}

// conformanceCanonical is the suite's own canonical rendering (sorted keys, JSON.stringify scalars).
func conformanceCanonical(value any) string {
	switch v := value.(type) {
	case *Object:
		if v == nil {
			return "null"
		}
		keys := sortedUTF16(v.keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			parts = append(parts, QuoteJSON(key)+":"+conformanceCanonical(v.values[key]))
		}
		return "{" + strings.Join(parts, ",") + "}"
	case []any:
		parts := make([]string, len(v))
		for index, item := range v {
			parts[index] = conformanceCanonical(item)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case []string:
		parts := make([]string, len(v))
		for index, item := range v {
			parts[index] = QuoteJSON(item)
		}
		return "[" + strings.Join(parts, ",") + "]"
	case int:
		return strconv.Itoa(v)
	}
	text, ok, err := Stringify(value)
	if err != nil || !ok {
		return "undefined"
	}
	return text
}

func same(actual, expected any, message string) {
	left := conformanceCanonical(actual)
	right := conformanceCanonical(expected)
	check(left == right, message+": expected "+right+", received "+left)
}

func rejects(operation func() error, code, message string) *IamError {
	failure := operation()
	check(failure != nil, message+": expected "+code+", but the operation succeeded")
	var iamError *IamError
	received := failure.Error()
	if errors.As(failure, &iamError) {
		received = iamError.Code
	}
	check(received == code, message+": expected "+code+", received "+received)
	return iamError
}

func idsOf(records []*Object) []string {
	out := make([]string, len(records))
	for index, record := range records {
		out[index] = recordID(record)
	}
	return out
}

func seed(ctx context.Context, store IamStore, collection string, records []*Object) {
	mustDo(store.Transaction(ctx, func(ctx context.Context, tx IamStore) error {
		for _, record := range records {
			if _, err := tx.Insert(ctx, collection, record); err != nil {
				return err
			}
		}
		return nil
	}))
}

func rec(pairs ...any) *Object { return NewObject(pairs...) }

func insertTx(ctx context.Context, store IamStore, collection string, record *Object) func() error {
	return func() error {
		return store.Transaction(ctx, func(ctx context.Context, tx IamStore) error {
			_, err := tx.Insert(ctx, collection, record)
			return err
		})
	}
}

func putTx(ctx context.Context, store IamStore, collection string, record *Object) func() error {
	return func() error {
		return store.Transaction(ctx, func(ctx context.Context, tx IamStore) error {
			_, err := tx.Put(ctx, collection, record)
			return err
		})
	}
}

func sortedByIDs(ids []string) []string {
	out := append([]string(nil), ids...)
	sort.SliceStable(out, func(i, j int) bool { return CompareIDs(out[i], out[j]) < 0 })
	return out
}

func sliceIDs(ids []string, start, end int) []string {
	if start > len(ids) {
		return []string{}
	}
	if end > len(ids) {
		end = len(ids)
	}
	return ids[start:end]
}

func find(ctx context.Context, store IamStore, collection string, filter *Object, options *FindOptions) []string {
	return idsOf(must(store.Find(ctx, collection, filter, options)))
}

var conformanceCases = []ConformanceCase{
	{
		Name: "round-trips JSON records and returns detached copies",
		Run: func(ctx context.Context, store IamStore) error {
			record := rec("id", "r1", "tenantId", "t1", "name", "Ada",
				"nested", rec("list", []any{1.0, "two", true, nil, rec("deep", "é 😀 中文")}),
				"sum", pointOne+pointTwo, "large", math.Pow(2, 53)+2, "small", 5e-324, "exponent", 1e21)
			seed(ctx, store, "items", []*Object{record})
			read := must(store.Get(ctx, "items", "r1"))
			reparsed := must(ParseJSONString(MustStringify(record)))
			same(read, reparsed, "get returns the stored record")
			check(read != nil, "inserted records can be read")
			read.Set("name", "changed")
			again := must(store.Get(ctx, "items", "r1"))
			check(again != nil && again.Get("name") == "Ada", "records are detached copies")
			check(must(store.Get(ctx, "items", "missing")) == nil, "missing ids read as undefined")
			check(must(store.Get(ctx, "other", "r1")) == nil, "collections are separate")
			return nil
		},
	},
	{
		Name: "enforces identifier and tenant-scoped natural-key uniqueness",
		Run: func(ctx context.Context, store IamStore) error {
			seed(ctx, store, "users", []*Object{
				rec("id", "one", "tenantId", "a", "uniqueKey", "same@example.com"),
				rec("id", "two", "tenantId", "b", "uniqueKey", "same@example.com"),
				rec("id", "three", "tenantId", "a"),
			})
			seed(ctx, store, "groups", []*Object{rec("id", "one", "tenantId", "a")})
			rejects(insertTx(ctx, store, "users", rec("id", "one", "tenantId", "c")), "CONFLICT", "ids are unique per collection across tenants")
			rejects(insertTx(ctx, store, "users", rec("id", "four", "tenantId", "a", "uniqueKey", "same@example.com")), "CONFLICT", "natural keys are unique within a tenant")
			rejects(putTx(ctx, store, "users", rec("id", "three", "tenantId", "a", "uniqueKey", "same@example.com")), "CONFLICT", "put cannot take another record’s natural key")
			rejects(func() error {
				return store.Transaction(ctx, func(ctx context.Context, tx IamStore) error {
					if _, err := tx.Insert(ctx, "users", rec("id", "five", "tenantId", "a")); err != nil {
						return err
					}
					// A caught storage failure still dooms the transaction.
					_, _ = tx.Insert(ctx, "users", rec("id", "one", "tenantId", "a"))
					return nil
				})
			}, "TRANSACTION_ABORTED", "a failed statement aborts the enclosing transaction")
			check(must(store.Get(ctx, "users", "five")) == nil, "aborted writes are rolled back")
			return nil
		},
	},
	{
		Name: "replaces whole records on put without upserting or moving tenants",
		Run: func(ctx context.Context, store IamStore) error {
			seed(ctx, store, "items", []*Object{rec("id", "x", "tenantId", "t1", "uniqueKey", "key-x", "label", "first", "extra", true)})
			rejects(putTx(ctx, store, "items", rec("id", "missing", "tenantId", "t1")), "NOT_FOUND", "put does not insert")
			rejects(putTx(ctx, store, "items", rec("id", "x", "tenantId", "t2")), "CONFLICT", "tenant ownership is immutable")
			mustDo(putTx(ctx, store, "items", rec("id", "x", "tenantId", "t1", "label", "second"))())
			same(must(store.Get(ctx, "items", "x")), rec("id", "x", "tenantId", "t1", "label", "second"), "put replaces the record")
			check(len(must(store.Find(ctx, "items", rec("extra", true), nil))) == 0, "removed fields stop matching")
			seed(ctx, store, "items", []*Object{rec("id", "y", "tenantId", "t1", "uniqueKey", "key-x")})
			found := must(store.Find(ctx, "items", rec("uniqueKey", "key-x"), nil))
			check(len(found) > 0 && recordID(found[0]) == "y", "freed keys can be reused")
			return nil
		},
	},
	{
		Name: "deletes records and ignores missing ids",
		Run: func(ctx context.Context, store IamStore) error {
			seed(ctx, store, "items", []*Object{rec("id", "x", "tenantId", "t1", "tokenHash", "abc")})
			mustDo(store.Transaction(ctx, func(ctx context.Context, tx IamStore) error {
				if err := tx.Delete(ctx, "items", "x"); err != nil {
					return err
				}
				return tx.Delete(ctx, "items", "never-existed")
			}))
			check(must(store.Get(ctx, "items", "x")) == nil, "deleted records are gone")
			check(len(must(store.Find(ctx, "items", rec("tokenHash", "abc"), nil))) == 0, "deleted records stop matching")
			return nil
		},
	},
	{
		Name: "requires a transaction for every write",
		Run: func(ctx context.Context, store IamStore) error {
			rejects(func() error { _, err := store.Insert(ctx, "items", rec("id", "x", "tenantId", "t")); return err }, "TRANSACTION_REQUIRED", "insert")
			seed(ctx, store, "items", []*Object{rec("id", "y", "tenantId", "t")})
			rejects(func() error { _, err := store.Put(ctx, "items", rec("id", "y", "tenantId", "t", "v", 1)); return err }, "TRANSACTION_REQUIRED", "put")
			rejects(func() error { return store.Delete(ctx, "items", "y") }, "TRANSACTION_REQUIRED", "delete")
			read := must(store.Get(ctx, "items", "y"))
			check(read != nil && IsUndefined(read.Get("v")), "rejected writes change nothing")
			return nil
		},
	},
	{
		Name: "rolls back failed transactions and joins nested ones",
		Run: func(ctx context.Context, store IamStore) error {
			failure := errors.New("application failure")
			thrown := store.Transaction(ctx, func(ctx context.Context, tx IamStore) error {
				if _, err := tx.Insert(ctx, "items", rec("id", "a", "tenantId", "t")); err != nil {
					return err
				}
				return failure
			})
			check(thrown == failure, "the callback’s error propagates unchanged")
			check(must(store.Get(ctx, "items", "a")) == nil, "a throwing callback rolls back")
			mustDo(store.Transaction(ctx, func(ctx context.Context, tx IamStore) error {
				if _, err := tx.Insert(ctx, "items", rec("id", "b", "tenantId", "t")); err != nil {
					return err
				}
				if err := store.Transaction(ctx, func(ctx context.Context, inner IamStore) error {
					read, err := inner.Get(ctx, "items", "b")
					if err != nil {
						return err
					}
					check(read != nil, "nested transactions see outer writes")
					_, err = inner.Insert(ctx, "items", rec("id", "c", "tenantId", "t"))
					return err
				}); err != nil {
					return err
				}
				return tx.Transaction(ctx, func(ctx context.Context, inner IamStore) error {
					_, err := inner.Insert(ctx, "items", rec("id", "d", "tenantId", "t"))
					return err
				})
			}))
			same(find(ctx, store, "items", nil, nil), []string{"b", "c", "d"}, "nested writes commit with the outer transaction")
			rejects(func() error {
				return store.Transaction(ctx, func(ctx context.Context, tx IamStore) error {
					if _, err := tx.Insert(ctx, "items", rec("id", "e", "tenantId", "t")); err != nil {
						return err
					}
					// The outer transaction must still roll back.
					_ = tx.Transaction(ctx, func(context.Context, IamStore) error { return errors.New("inner failure") })
					return nil
				})
			}, "TRANSACTION_ABORTED", "a failed nested transaction aborts the outer one")
			check(must(store.Get(ctx, "items", "e")) == nil, "nested failures roll back outer writes")
			return nil
		},
	},
	{
		Name: "rejects transaction handles after completion",
		Run: func(ctx context.Context, store IamStore) error {
			var leaked IamStore
			mustDo(store.Transaction(ctx, func(ctx context.Context, tx IamStore) error {
				leaked = tx
				_, err := tx.Insert(ctx, "items", rec("id", "a", "tenantId", "t"))
				return err
			}))
			rejects(func() error { _, err := leaked.Get(ctx, "items", "a"); return err }, "TRANSACTION_CLOSED", "reads through a leaked handle")
			rejects(func() error { _, err := leaked.Insert(ctx, "items", rec("id", "b", "tenantId", "t")); return err }, "TRANSACTION_CLOSED", "writes through a leaked handle")
			return nil
		},
	},
	{
		Name: "serializes concurrent read-modify-write transactions",
		Run: func(ctx context.Context, store IamStore) error {
			seed(ctx, store, "counters", []*Object{rec("id", "c", "tenantId", "t", "value", 0)})
			var wait sync.WaitGroup
			failures := make([]error, 8)
			for index := 0; index < 8; index++ {
				wait.Add(1)
				go func(index int) {
					defer wait.Done()
					failures[index] = store.Transaction(ctx, func(ctx context.Context, tx IamStore) error {
						current, err := tx.Get(ctx, "counters", "c")
						if err != nil {
							return err
						}
						time.Sleep(time.Duration(index%3) * time.Millisecond)
						value, _ := current.Number("value")
						_, err = tx.Put(ctx, "counters", current.Spread(rec("value", value+1)))
						return err
					})
				}(index)
			}
			wait.Wait()
			for _, failure := range failures {
				mustDo(failure)
			}
			counter := must(store.Get(ctx, "counters", "c"))
			check(counter != nil && counter.Get("value") == 8.0, "no update is lost")
			return nil
		},
	},
	{
		Name: "matches filters with strict, typed JSON equality",
		Run: func(ctx context.Context, store IamStore) error {
			values := rec("a", 1, "b", "1", "c", true, "d", "true", "e", nil, "g", rec("x", 1, "y", []any{1.0, 2.0}),
				"h", []any{1.0, 2.0}, "i", []any{2.0, 1.0}, "j", rec("x", 1), "k", 0, "l", "Abc", "m", "abc", "n", "é",
				"o", "é", "p", 1.5, "q", "", "r", " abc", "s", []any{}, "t", rec(), "u", false, "w", []any{nil, 1.0})
			var records []*Object
			for _, key := range values.Keys() {
				records = append(records, rec("id", key, "tenantId", "t", "v", values.Get(key)))
			}
			records = append(records, rec("id", "f", "tenantId", "t"))
			seed(ctx, store, "values", records)
			expectations := []struct {
				value    any
				expected []string
			}{
				{1.0, []string{"a"}}, {"1", []string{"b"}}, {true, []string{"c"}}, {false, []string{"u"}},
				{"true", []string{"d"}}, {nil, []string{"e"}}, {Undefined, []string{"f"}},
				{rec("y", []any{1.0, 2.0}, "x", 1), []string{"g"}}, {[]any{1.0, 2.0}, []string{"h"}},
				{[]any{2.0, 1.0}, []string{"i"}}, {rec("x", 1), []string{"j"}}, {[]any{nil, 1.0}, []string{"w"}},
				{0.0, []string{"k"}}, {math.Copysign(0, -1), []string{"k"}}, {"abc", []string{"m"}}, {"Abc", []string{"l"}},
				{"é", []string{"o"}}, {"é", []string{"n"}}, {1.5, []string{"p"}}, {"", []string{"q"}},
				{[]any{}, []string{"s"}}, {rec(), []string{"t"}},
			}
			for _, expectation := range expectations {
				same(find(ctx, store, "values", rec("v", expectation.value), nil), expectation.expected, "filter v = "+conformanceCanonical(expectation.value))
			}
			same(find(ctx, store, "values", rec("missing", "x"), nil), []string{}, "filters on absent fields")
			same(find(ctx, store, "values", rec("v", 1, "tenantId", "t"), nil), []string{"a"}, "conditions combine with AND")
			same(find(ctx, store, "values", rec("v", 1, "tenantId", "other"), nil), []string{}, "tenant narrows results")
			same(find(ctx, store, "values", rec("v", false, "absent\u0000key", Undefined), nil), []string{"u"}, "absence of a key no database can name")
			wide := rec("v", 1.5)
			for index := 0; index < 40; index++ {
				wide.Set("missing"+strconv.Itoa(index), Undefined)
			}
			same(find(ctx, store, "values", wide, nil), []string{"p"}, "forty conditions")
			wide.Set("missing39", "present")
			same(find(ctx, store, "values", wide, nil), []string{}, "forty conditions, one failing")
			return nil
		},
	},
	{
		Name: "filters by id, tenant, and natural-key columns",
		Run: func(ctx context.Context, store IamStore) error {
			seed(ctx, store, "keys", []*Object{
				rec("id", "a", "tenantId", "t1", "uniqueKey", "k1"),
				rec("id", "b", "tenantId", "t2", "uniqueKey", "k1"),
				rec("id", "c", "tenantId", "t1"),
			})
			same(find(ctx, store, "keys", rec("id", "a"), nil), []string{"a"}, "id filter")
			same(find(ctx, store, "keys", rec("id", 5), nil), []string{}, "non-string id filter")
			same(find(ctx, store, "keys", rec("tenantId", "t1"), nil), []string{"a", "c"}, "tenant filter")
			same(find(ctx, store, "keys", rec("tenantId", Undefined), nil), []string{}, "absent tenant filter")
			same(find(ctx, store, "keys", rec("uniqueKey", "k1"), nil), []string{"a", "b"}, "natural key across tenants")
			same(find(ctx, store, "keys", rec("uniqueKey", Undefined), nil), []string{"c"}, "records without a natural key")
			same(find(ctx, store, "keys", rec("uniqueKey", nil), nil), []string{}, "natural keys are never null")
			same(find(ctx, store, "keys", rec("tenantId", "t1", "uniqueKey", "k1", "id", "a"), nil), []string{"a"}, "combined columns")
			return nil
		},
	},
	{
		Name: "filters on field names that cannot appear in SQL",
		Run: func(ctx context.Context, store IamStore) error {
			names := []string{"dotted.key", "with space", `quote"key`, "apostrophe'key", "$dollar", "123start", "unicodé", ""}
			var records []*Object
			for index, name := range names {
				records = append(records, rec("id", "n"+strconv.Itoa(index), "tenantId", "t", name, "match"))
			}
			seed(ctx, store, "names", records)
			for index, name := range names {
				same(find(ctx, store, "names", rec(name, "match"), nil), []string{"n" + strconv.Itoa(index)}, "field "+QuoteJSON(name))
			}
			return nil
		},
	},
	{
		Name: "stores and finds strings with U+0000, unpaired surrogates, and reserved keys",
		Run: func(ctx context.Context, store IamStore) error {
			escapeKey := JSONBEscapeKey
			high := FromUTF16([]uint16{0xd800})
			low := FromUTF16([]uint16{0xdc00})
			highEmoji := FromUTF16([]uint16{0xd83d})
			records := []*Object{
				rec("id", "a", "tenantId", "t", "kind", "odd", "v", "a\u0000b"),
				rec("id", "b", "tenantId", "t", "kind", "odd", "v", high),
				rec("id", "c", "tenantId", "t", "kind", "odd", "v", "x"+low+"y"),
				rec("id", "d", "tenantId", "t", "kind", "odd", "k\u0000", 1, "v", "plain"),
				rec("id", "e", "tenantId", "t", "kind", "odd", "v", rec("list", []any{"\u0000", highEmoji}, escapeKey, "x")),
				rec("id", "f", "tenantId", "t", "kind", "odd", "v", rec(escapeKey, "deadbeef")),
				rec("id", "g", "tenantId", "t", "kind", "plain", "v", "�"),
				rec("id", "h", "tenantId", "t", "kind", "plain", "v", "😀"),
			}
			seed(ctx, store, "strings", records)
			for _, record := range records {
				same(must(store.Get(ctx, "strings", recordID(record))), record, "round trip of "+recordID(record))
			}
			byValue := []struct {
				value    any
				expected []string
			}{
				{"a\u0000b", []string{"a"}}, {high, []string{"b"}}, {"x" + low + "y", []string{"c"}},
				{"plain", []string{"d"}}, {rec("list", []any{"\u0000", highEmoji}, escapeKey, "x"), []string{"e"}},
				{rec(escapeKey, "deadbeef"), []string{"f"}}, {"�", []string{"g"}}, {"😀", []string{"h"}},
				{"a", []string{}},
			}
			for _, item := range byValue {
				same(find(ctx, store, "strings", rec("v", item.value), nil), item.expected, "filter v = "+conformanceCanonical(item.value))
			}
			same(find(ctx, store, "strings", rec("kind", "odd"), nil), []string{"a", "b", "c", "d", "e", "f"}, "sibling fields")
			same(find(ctx, store, "strings", rec("k\u0000", 1), nil), []string{"d"}, "a key with U+0000")
			same(find(ctx, store, "strings", rec("kind", "odd"), &FindOptions{Offset: Ptr(4), Limit: Ptr(5)}), []string{"e", "f"}, "paged")
			// Identifiers must survive UTF-8 unchanged: an unpaired surrogate would alias U+FFFD.
			rejects(insertTx(ctx, store, "strings", rec("id", "x"+high, "tenantId", "t")), "INVALID_RECORD", "an id with an unpaired surrogate")
			seed(ctx, store, "strings", []*Object{rec("id", "x�", "tenantId", "t�")})
			check(must(store.Get(ctx, "strings", "x"+high)) == nil, "no alias through get")
			same(find(ctx, store, "strings", rec("id", "x"+high), nil), []string{}, "no alias through find")
			same(find(ctx, store, "strings", rec("tenantId", "t"+low), nil), []string{}, "no tenant alias")
			mustDo(store.Transaction(ctx, func(ctx context.Context, tx IamStore) error { return tx.Delete(ctx, "strings", "x"+high) }))
			check(must(store.Get(ctx, "strings", "x�")) != nil, "no alias through delete")
			return nil
		},
	},
	{
		Name: "orders by id in code-point order and paginates deterministically",
		Run: func(ctx context.Context, store IamStore) error {
			order := []string{"b", "B", "a", "A", "0", "~", "_", "é", "z", "￿", "😀", "", "aa", "a-"}
			var records []*Object
			for index, id := range order {
				records = append(records, rec("id", id, "tenantId", "t", "kind", "x", "odd key", index%2))
			}
			seed(ctx, store, "ordered", records)
			expected := sortedByIDs(order)
			same(find(ctx, store, "ordered", nil, nil), expected, "unfiltered order")
			same(find(ctx, store, "ordered", rec("kind", "x"), nil), expected, "filtered order")
			for _, page := range [][2]int{{0, 3}, {3, 3}, {12, 5}, {14, 2}, {20, 1}} {
				offset, limit := page[0], page[1]
				want := sliceIDs(expected, offset, offset+limit)
				label := strconv.Itoa(offset) + "+" + strconv.Itoa(limit)
				same(find(ctx, store, "ordered", nil, &FindOptions{Offset: Ptr(offset), Limit: Ptr(limit)}), want, "page "+label)
				same(find(ctx, store, "ordered", rec("kind", "x"), &FindOptions{Offset: Ptr(offset), Limit: Ptr(limit)}), want, "filtered page "+label)
			}
			same(find(ctx, store, "ordered", nil, &FindOptions{Limit: Ptr(0)}), []string{}, "limit 0")
			same(find(ctx, store, "ordered", rec("kind", "x"), &FindOptions{Offset: Ptr(5)}), expected[5:], "offset without limit")
			var odd []string
			for _, id := range expected {
				for index, item := range order {
					if item == id && index%2 == 1 {
						odd = append(odd, id)
					}
				}
			}
			same(find(ctx, store, "ordered", rec("odd key", 1), &FindOptions{Offset: Ptr(1), Limit: Ptr(3)}), sliceIDs(odd, 1, 4), "in-memory filter page")
			rejects(func() error {
				_, err := store.Find(ctx, "ordered", nil, &FindOptions{Offset: Ptr(-1)})
				return err
			}, "INVALID_FILTER", "negative offset")
			return nil
		},
	},
	{
		Name: "pages with an id cursor in code-point order",
		Run: func(ctx context.Context, store IamStore) error {
			order := []string{"b", "B", "a", "A", "0", "~", "_", "é", "z", "￿", "😀", "", "aa", "a-", "u1"}
			byID := map[string]*Object{}
			var records []*Object
			for index, id := range order {
				tenant := "t"
				if id == "u1" {
					tenant = "u"
				}
				kind := "y"
				if index%3 == 0 {
					kind = "x"
				}
				record := rec("id", id, "tenantId", tenant, "kind", kind, "odd key", index%2)
				records = append(records, record)
				byID[id] = record
			}
			seed(ctx, store, "cursor", records)
			expected := sortedByIDs(order)
			after := func(cursor string, keep func(id string) bool) []string {
				out := []string{}
				for _, id := range expected {
					if CompareIDs(id, cursor) > 0 && (keep == nil || keep(id)) {
						out = append(out, id)
					}
				}
				return out
			}
			for _, size := range []int{1, 4} {
				var walked []string
				var cursor *string
				for guard := 0; guard <= len(order); guard++ {
					options := &FindOptions{Limit: Ptr(size)}
					if cursor != nil {
						options.After = cursor
					}
					page := must(store.Find(ctx, "cursor", nil, options))
					walked = append(walked, idsOf(page)...)
					if len(page) < size {
						break
					}
					last := recordID(page[len(page)-1])
					cursor = &last
				}
				same(walked, expected, "walk in pages of "+strconv.Itoa(size))
			}
			kind := func(value string) func(string) bool {
				return func(id string) bool { return byID[id].Get("kind") == value }
			}
			same(find(ctx, store, "cursor", nil, &FindOptions{After: Ptr("a")}), after("a", nil), "cursor between ids")
			same(find(ctx, store, "cursor", nil, &FindOptions{After: Ptr("")}), expected, "empty cursor")
			same(find(ctx, store, "cursor", nil, &FindOptions{After: Ptr("\U0010FFFF")}), []string{}, "past the last id")
			lone := FromUTF16([]uint16{0xd83d})
			same(find(ctx, store, "cursor", nil, &FindOptions{After: Ptr(lone)}), after(lone, nil), "cursor with an unpaired surrogate")
			same(find(ctx, store, "cursor", rec("kind", "x"), &FindOptions{After: Ptr("B"), Limit: Ptr(2)}), sliceIDs(after("B", kind("x")), 0, 2), "filtered cursor page")
			same(find(ctx, store, "cursor", nil, &FindOptions{After: Ptr("a"), Offset: Ptr(1), Limit: Ptr(1)}), sliceIDs(after("a", nil), 1, 2), "cursor with offset")
			same(find(ctx, store, "cursor", rec("kind", "y"), &FindOptions{After: Ptr("B"), Offset: Ptr(1), Limit: Ptr(2)}), sliceIDs(after("B", kind("y")), 1, 3), "filtered cursor with offset")
			same(find(ctx, store, "cursor", rec("tenantId", "t"), &FindOptions{After: Ptr("_")}), after("_", func(id string) bool { return byID[id].Get("tenantId") == "t" }), "tenant cursor")
			same(find(ctx, store, "cursor", rec("odd key", 1), &FindOptions{After: Ptr("B"), Offset: Ptr(1), Limit: Ptr(2)}),
				sliceIDs(after("B", func(id string) bool { return byID[id].Get("odd key") == 1.0 }), 1, 3), "in-memory filter with cursor and offset")
			return nil
		},
	},
	{
		Name: "finds numbers by value across the whole double range",
		Run: func(ctx context.Context, store IamStore) error {
			numbers := []float64{0, 1, -1, pointOne + pointTwo, math.Pow(2, 53) - 1, math.Pow(2, 53) + 2, math.Pow(2, 60), -math.Pow(2, 60),
				4611686018427389000, 9223372036854775000, math.Pow(2, 64), 1e16, 1e17, 1e21, 1e-7, 1e-300, 5e-324,
				1.7125808327557952e177, -7.491602062452078e303, 2.2093402303347207e-113, math.MaxFloat64}
			var records []*Object
			for index, n := range numbers {
				id := "n" + strconv.Itoa(index)
				records = append(records, rec("id", id, "tenantId", "t", "n", n), rec("id", id+"-copy", "tenantId", "t", "n", n))
			}
			seed(ctx, store, "numbers", records)
			for index, n := range numbers {
				id := "n" + strconv.Itoa(index)
				same(find(ctx, store, "numbers", rec("n", n), nil), []string{id, id + "-copy"}, "n = "+NumberString(n))
				same(find(ctx, store, "numbers", rec("n", n), &FindOptions{Offset: Ptr(1), Limit: Ptr(1)}), []string{id + "-copy"}, "paged n = "+NumberString(n))
				read := must(store.Get(ctx, "numbers", id))
				var value any = Undefined
				if read != nil {
					value = read.Get("n")
				}
				same(value, n, "round trip of "+NumberString(n))
			}
			return nil
		},
	},
	{
		Name: "pages selectively filtered results across many rows",
		Run: func(ctx context.Context, store IamStore) error {
			var records []*Object
			for index := 0; index < 300; index++ {
				tenant := "even"
				if index%2 == 1 {
					tenant = "odd"
				}
				records = append(records, rec("id", fmt.Sprintf("r%03d", index), "tenantId", tenant, "third", index%3 == 0,
					"group", "g"+strconv.Itoa(index%7), "in memory", index%5))
			}
			seed(ctx, store, "rows", records)
			same(len(must(store.Find(ctx, "rows", nil, nil))), 300, "no silent truncation")
			var expected, mixed []string
			for _, record := range records {
				if record.Get("third") == true && record.Get("tenantId") == "even" {
					expected = append(expected, recordID(record))
				}
				if record.Get("group") == "g3" && record.Get("in memory") == 2.0 {
					mixed = append(mixed, recordID(record))
				}
			}
			same(find(ctx, store, "rows", rec("third", true, "tenantId", "even"), nil), expected, "filtered")
			for _, page := range [][2]int{{0, 7}, {7, 7}, {45, 10}, {49, 3}} {
				offset, limit := page[0], page[1]
				same(find(ctx, store, "rows", rec("third", true, "tenantId", "even"), &FindOptions{Offset: Ptr(offset), Limit: Ptr(limit)}),
					sliceIDs(expected, offset, offset+limit), "page "+strconv.Itoa(offset)+"+"+strconv.Itoa(limit))
			}
			same(find(ctx, store, "rows", rec("group", "g3", "in memory", 2), &FindOptions{Offset: Ptr(1), Limit: Ptr(4)}), sliceIDs(mixed, 1, 5), "page of a partly in-memory filter")
			return nil
		},
	},
	{
		Name: "finds uncommitted writes inside the writing transaction",
		Run: func(ctx context.Context, store IamStore) error {
			seed(ctx, store, "drafts", []*Object{rec("id", "a", "tenantId", "t", "state", "old", "kind", "x")})
			rejects(func() error {
				return store.Transaction(ctx, func(ctx context.Context, tx IamStore) error {
					must(tx.Insert(ctx, "drafts", rec("id", "b", "tenantId", "t", "state", "new", "kind", "x")))
					must(tx.Put(ctx, "drafts", rec("id", "a", "tenantId", "t", "state", "new", "kind", "x")))
					same(find(ctx, tx, "drafts", rec("state", "new"), nil), []string{"a", "b"}, "exact filter")
					same(find(ctx, tx, "drafts", rec("state", "new"), &FindOptions{Limit: Ptr(1)}), []string{"a"}, "exact page")
					same(find(ctx, tx, "drafts", rec("state", "old"), nil), []string{}, "replaced value")
					same(find(ctx, store, "drafts", rec("kind", "x", "x y", Undefined), nil), []string{"a", "b"}, "joined read")
					mustDo(tx.Delete(ctx, "drafts", "a"))
					same(find(ctx, tx, "drafts", rec("kind", "x"), nil), []string{"b"}, "deleted inside")
					return NewIamError("ROLLBACK", "discard")
				})
			}, "ROLLBACK", "the draft transaction")
			same(find(ctx, store, "drafts", rec("state", "old"), nil), []string{"a"}, "rolled back")
			return nil
		},
	},
	{
		Name: "orders, bounds, and pages by a numeric field",
		Run: func(ctx context.Context, store IamStore) error {
			stamps := []any{5.0, 3.0, 5.0, -1.0, math.Pow(2, 60), 0.5, 7.0, "6", nil, Undefined, 5.0, 1e21, 3.0}
			var records []*Object
			for index := 0; index < 300; index++ {
				tenant := "t"
				if index%3 == 0 {
					tenant = "other"
				}
				kind := "y"
				if index%4 == 0 {
					kind = "x"
				}
				record := rec("id", fmt.Sprintf("e%03d", (index*37)%300), "tenantId", tenant, "kind", kind)
				if stamp := stamps[index%len(stamps)]; !IsUndefined(stamp) {
					record.Set("timestamp", stamp)
				}
				records = append(records, record)
			}
			seed(ctx, store, "events", records)
			reference := func(filter func(*Object) bool, desc bool) []string {
				var kept []*Object
				for _, record := range records {
					if _, ok := record.Get("timestamp").(float64); ok && filter(record) {
						kept = append(kept, record)
					}
				}
				direction := "asc"
				if desc {
					direction = "desc"
				}
				return idsOf(orderRecords(kept, "timestamp", direction))
			}
			tenant := func(record *Object) bool { return record.Get("tenantId") == "t" }
			ordered := func(store IamStore, filter *Object, order OrderOptions, where func(*Object) bool) []string {
				return idsOf(must(FindOrdered(ctx, store, "events", filter, order, where)))
			}
			for _, direction := range []string{"asc", "desc"} {
				all := reference(tenant, direction == "desc")
				same(ordered(store, rec("tenantId", "t"), OrderOptions{Field: "timestamp", Direction: direction}, nil), all, direction+" order")
				for _, page := range [][2]int{{0, 10}, {15, 20}, {len(all) - 3, 10}} {
					offset, limit := page[0], page[1]
					same(ordered(store, rec("tenantId", "t"), OrderOptions{Field: "timestamp", Direction: direction, Offset: Ptr(offset), Limit: Ptr(limit)}, nil),
						sliceIDs(all, offset, offset+limit), direction+" page "+strconv.Itoa(offset)+"+"+strconv.Itoa(limit))
				}
			}
			bounded := reference(func(record *Object) bool {
				value, _ := record.Get("timestamp").(float64)
				return tenant(record) && value >= 0.5 && value <= 5
			}, false)
			same(ordered(store, rec("tenantId", "t"), OrderOptions{Field: "timestamp", From: Ptr(0.5), To: Ptr(5.0)}, nil), bounded, "bounded range")
			big := math.Pow(2, 60)
			same(ordered(store, rec("tenantId", "t"), OrderOptions{Field: "timestamp", From: &big, To: &big}, nil),
				reference(func(record *Object) bool { return tenant(record) && record.Get("timestamp") == big }, false), "a bound above 2^53")
			xs := reference(func(record *Object) bool { return tenant(record) && record.Get("kind") == "x" }, true)
			same(ordered(store, rec("tenantId", "t", "kind", "x"), OrderOptions{Field: "timestamp", Direction: "desc", Offset: Ptr(2), Limit: Ptr(7)}, nil),
				sliceIDs(xs, 2, 9), "filtered page")
			same(ordered(store, rec("tenantId", "t"), OrderOptions{Field: "timestamp", Direction: "desc", Offset: Ptr(3), Limit: Ptr(5)},
				func(record *Object) bool { return record.Get("kind") == "x" }), sliceIDs(xs, 3, 8), "in-memory predicate page")
			rejects(func() error {
				_, err := FindOrdered(ctx, store, "events", nil, OrderOptions{Field: "not a field"}, nil)
				return err
			}, "INVALID_FILTER", "an order field that is not an identifier")
			rejects(func() error {
				_, err := FindOrdered(ctx, store, "events", nil, OrderOptions{Field: "timestamp", From: Ptr(math.NaN())}, nil)
				return err
			}, "INVALID_FILTER", "a NaN bound")
			rejects(func() error {
				return store.Transaction(ctx, func(ctx context.Context, tx IamStore) error {
					must(tx.Insert(ctx, "events", rec("id", "z-new", "tenantId", "t", "timestamp", 1e22)))
					same(ordered(tx, rec("tenantId", "t"), OrderOptions{Field: "timestamp", Direction: "desc", Limit: Ptr(1)}, nil), []string{"z-new"}, "uncommitted write in order")
					return NewIamError("ROLLBACK", "discard")
				})
			}, "ROLLBACK", "the ordered draft")
			return nil
		},
	},
	{
		Name: "validates records before writing",
		Run: func(ctx context.Context, store IamStore) error {
			circular := rec("id", "x", "tenantId", "t")
			circular.SetRaw("self", circular)
			proto := must(ParseJSONString(`{"id":"x","tenantId":"t","__proto__":1}`)).(*Object)
			invalid := []struct {
				label  string
				record *Object
			}{
				{"a Date", rec("id", "x", "tenantId", "t").SetRaw("at", time.Unix(0, 0))},
				{"NaN", rec("id", "x", "tenantId", "t", "v", math.NaN())},
				{"Infinity", rec("id", "x", "tenantId", "t", "v", math.Inf(1))},
				{"a Map", rec("id", "x", "tenantId", "t").SetRaw("v", map[string]any{})},
				{"a function", rec("id", "x", "tenantId", "t").SetRaw("v", func() int { return 1 })},
				{"a circular reference", circular},
				{"a __proto__ key", proto},
				{"an undefined array item", rec("id", "x", "tenantId", "t").SetRaw("v", []any{Undefined})},
				{"an empty id", rec("id", "", "tenantId", "t")},
				{"an oversized id", rec("id", strings.Repeat("é", 257), "tenantId", "t")},
				{"a control character in tenantId", rec("id", "x", "tenantId", "t\n")},
				{"a null natural key", rec("id", "x", "tenantId", "t", "uniqueKey", nil)},
				{"an oversized record", rec("id", "x", "tenantId", "t", "v", strings.Repeat("a", 1_048_577))},
			}
			for _, item := range invalid {
				rejects(insertTx(ctx, store, "invalid", item.record), "INVALID_RECORD", item.label)
			}
			check(len(must(store.Find(ctx, "invalid", nil, nil))) == 0, "no invalid record was written")
			return nil
		},
	},
	{
		Name: "keeps lookups consistent through updates and deletes",
		Run: func(ctx context.Context, store IamStore) error {
			seed(ctx, store, "sessions", []*Object{
				rec("id", "s1", "tenantId", "t1", "tokenHash", "h1", "identityId", "i1"),
				rec("id", "s2", "tenantId", "t2", "tokenHash", "h2", "identityId", "i1"),
				rec("id", "s3", "tenantId", "t1", "tokenHash", "h3", "identityId", "i2"),
			})
			same(find(ctx, store, "sessions", rec("tokenHash", "h2"), nil), []string{"s2"}, "lookup across tenants")
			same(find(ctx, store, "sessions", rec("identityId", "i1"), nil), []string{"s1", "s2"}, "secondary lookup")
			same(find(ctx, store, "sessions", rec("identityId", "i1", "tenantId", "t1"), nil), []string{"s1"}, "tenant-scoped lookup")
			mustDo(putTx(ctx, store, "sessions", rec("id", "s2", "tenantId", "t2", "tokenHash", "h4", "identityId", "i1"))())
			same(find(ctx, store, "sessions", rec("tokenHash", "h2"), nil), []string{}, "old value no longer matches")
			same(find(ctx, store, "sessions", rec("tokenHash", "h4"), nil), []string{"s2"}, "new value matches")
			mustDo(store.Transaction(ctx, func(ctx context.Context, tx IamStore) error { return tx.Delete(ctx, "sessions", "s1") }))
			same(find(ctx, store, "sessions", rec("identityId", "i1"), nil), []string{"s2"}, "deleted records disappear")
			same(find(ctx, store, "sessions", rec("tokenHash", 1), nil), []string{}, "typed lookups never coerce")
			return nil
		},
	},
	{
		Name: "migrates idempotently without touching data",
		Run: func(ctx context.Context, store IamStore) error {
			seed(ctx, store, "items", []*Object{rec("id", "kept", "tenantId", "t", "tokenHash", "h")})
			mustDo(store.Migrate(ctx))
			mustDo(store.Migrate(ctx))
			same(find(ctx, store, "items", rec("tokenHash", "h"), nil), []string{"kept"}, "data survives migration")
			return nil
		},
	},
	{
		Name: "reports storage conflicts without leaking SQL or record data",
		Run: func(ctx context.Context, store IamStore) error {
			seed(ctx, store, "items", []*Object{rec("id", "x", "tenantId", "t", "uniqueKey", "key-do-not-leak", "secret", "do-not-leak")})
			conflicts := []*IamError{
				rejects(insertTx(ctx, store, "items", rec("id", "x", "tenantId", "t", "secret", "do-not-leak")), "CONFLICT", "duplicate id"),
				rejects(insertTx(ctx, store, "items", rec("id", "y", "tenantId", "t", "uniqueKey", "key-do-not-leak", "secret", "do-not-leak")), "CONFLICT", "duplicate natural key"),
			}
			leak := regexp.MustCompile(`(?i)insert|select|iam_records|do-not-leak`)
			for _, failure := range conflicts {
				exposed := []string{failure.Message, failure.Error(), fmt.Sprintf("%+v", failure), fmt.Sprintf("%#v", *failure)}
				for cause := errors.Unwrap(error(failure)); cause != nil; cause = errors.Unwrap(cause) {
					exposed = append(exposed, cause.Error())
				}
				check(!leak.MatchString(strings.Join(exposed, "\n")), "errors carry no SQL, table names, or record data")
			}
			return nil
		},
	},
	{
		Name: "closes idempotently and rejects later use",
		Run: func(ctx context.Context, store IamStore) error {
			mustDo(store.Close(ctx))
			mustDo(store.Close(ctx))
			rejects(func() error { _, err := store.Get(ctx, "items", "x"); return err }, "STORE_CLOSED", "reads after close")
			rejects(func() error { return store.Transaction(ctx, func(context.Context, IamStore) error { return nil }) }, "STORE_CLOSED", "transactions after close")
			return nil
		},
	},
}

// AdapterConformanceCases returns a fresh copy of every conformance case, in a stable order.
func AdapterConformanceCases() []ConformanceCase {
	out := make([]ConformanceCase, len(conformanceCases))
	for index, item := range conformanceCases {
		test := item
		out[index] = ConformanceCase{Name: test.Name, Run: func(ctx context.Context, store IamStore) (err error) {
			defer func() {
				if recovered := recover(); recovered != nil {
					if abort, ok := recovered.(conformanceAbort); ok {
						err = abort.err
						return
					}
					panic(recovered)
				}
			}()
			return test.Run(ctx, store)
		}}
	}
	return out
}

// ConformanceResult lists the passed and failed cases of RunAdapterConformance.
type ConformanceResult struct {
	Passed []string
	Failed []struct {
		Name string
		Err  error
	}
}

// RunAdapterConformance runs every case against fresh stores and collects failures instead of stopping at the first.
func RunAdapterConformance(ctx context.Context, createStore func() (IamStore, error)) ConformanceResult {
	var result ConformanceResult
	for _, test := range AdapterConformanceCases() {
		store, err := createStore()
		if err == nil {
			err = store.Migrate(ctx)
			if err == nil {
				err = test.Run(ctx, store)
			}
			_ = store.Close(ctx)
		}
		if err != nil {
			result.Failed = append(result.Failed, struct {
				Name string
				Err  error
			}{test.Name, err})
		} else {
			result.Passed = append(result.Passed, test.Name)
		}
	}
	return result
}

// pointOne and pointTwo are variables so that their sum is computed in float64 (0.30000000000000004), as JavaScript
// computes 0.1 + 0.2; a Go constant expression would be exactly 0.3.
var pointOne, pointTwo = 0.1, 0.2
