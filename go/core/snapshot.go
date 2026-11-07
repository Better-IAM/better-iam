package core

import (
	"context"
	"errors"
	"iter"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Portable store snapshots: every record of every collection as JSON Lines, independent of the adapter, for backups,
// moving from SQLite to PostgreSQL, and test fixtures. Records are copied verbatim, so audit hash chains, token hashes,
// and encrypted secrets stay valid. A snapshot holds credential hashes and encrypted secrets: protect it like the
// database itself.
//
// Format: a header line { format, version, createdAt, collections }, one { c, r } line per record (collection,
// record), and a trailer { end: true, records, collections } with counts, so a truncated file is detected before
// anything is committed.

// SnapshotFormat is the header's format.
const SnapshotFormat = "better-iam-store"

// SnapshotVersion is the header's version.
const SnapshotVersion = 1

// SnapshotSummary counts the records of a snapshot.
type SnapshotSummary struct {
	Records int `json:"records"`
	// Collections counts records per collection (an *Object of numbers, in JavaScript key order).
	Collections *Object `json:"collections"`
}

// ToValue is the summary as a model value.
func (s SnapshotSummary) ToValue() *Object {
	return NewObject("records", s.Records).SetRaw("collections", s.Collections)
}

// SnapshotOptions configure ExportStore and CopyStore.
type SnapshotOptions struct {
	// Collections to include; nil means every collection the store lists (Collections).
	Collections []string
	// PageSize is the records read per query while exporting (nil: 1000).
	PageSize *int
	// Clock gives createdAt (nil: time.Now).
	Clock func() time.Time
}

// listCollections returns the store's collections, or nil when it cannot list them (no method, or UNSUPPORTED).
func listCollections(ctx context.Context, store IamStore) ([]string, error) {
	lister, ok := store.(CollectionLister)
	if !ok {
		return nil, nil
	}
	names, err := lister.Collections(ctx)
	if err != nil {
		var iamError *IamError
		if errors.As(err, &iamError) && iamError.Code == "UNSUPPORTED" {
			return nil, nil
		}
		return nil, err
	}
	if names == nil {
		names = []string{}
	}
	return names, nil
}

func collectionsOf(ctx context.Context, store IamStore, options SnapshotOptions) ([]string, error) {
	if options.Collections != nil {
		seen := map[string]bool{}
		var out []string
		for _, name := range options.Collections {
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}
		sort.SliceStable(out, func(i, j int) bool { return compareUTF16(out[i], out[j]) < 0 })
		if out == nil {
			out = []string{}
		}
		return out, nil
	}
	listed, err := listCollections(ctx, store)
	if err != nil {
		return nil, err
	}
	if listed == nil {
		return nil, NewIamError("UNSUPPORTED", "This store cannot list its collections; pass the collections to copy explicitly", 501)
	}
	return listed, nil
}

func pageSizeOf(options SnapshotOptions) (int, error) {
	size := 1000
	if options.PageSize != nil {
		size = *options.PageSize
	}
	if size < 1 || size > 100_000 {
		return 0, NewIamError("INVALID_INPUT", "pageSize must be between 1 and 100000")
	}
	return size, nil
}

// eachRecord reads every record of the listed collections, a page at a time, in id order. Pages follow an id cursor
// (after); a store that ignores the cursor is detected and paged by offset instead.
func eachRecord(ctx context.Context, tx IamStore, collections []string, pageSize int, visit func(collection string, record *Object) error) (SnapshotSummary, error) {
	summary := SnapshotSummary{Collections: NewObject()}
	for _, collection := range collections {
		count := 0
		var cursor *string
		keyset := true
		for {
			after := cursor
			options := &FindOptions{Limit: Ptr(pageSize)}
			if after != nil {
				if keyset {
					options.After = after
				} else {
					options.Offset = Ptr(count)
				}
			}
			page, err := tx.Find(ctx, collection, nil, options)
			if err != nil {
				return SnapshotSummary{}, err
			}
			if keyset && after != nil {
				ignored := false
				for _, record := range page {
					if CompareIDs(recordID(record), *after) <= 0 {
						ignored = true
						break
					}
				}
				if ignored {
					keyset = false
					page, err = tx.Find(ctx, collection, nil, &FindOptions{Offset: Ptr(count), Limit: Ptr(pageSize)})
					if err != nil {
						return SnapshotSummary{}, err
					}
				}
			}
			cursor = nil
			if len(page) > 0 {
				id := recordID(page[len(page)-1])
				cursor = &id
			}
			for _, record := range page {
				if err := visit(collection, record); err != nil {
					return SnapshotSummary{}, err
				}
				count++
			}
			if len(page) < pageSize {
				break
			}
		}
		summary.Collections.Set(collection, count)
		summary.Records += count
	}
	return summary, nil
}

// isoTime is Date.prototype.toISOString.
func isoTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

// ExportStore writes a snapshot through write, one line at a time (without newlines). It runs in one store
// transaction, so the snapshot is consistent; that also holds the store's write lock until done.
func ExportStore(ctx context.Context, store IamStore, write func(line string) error, options SnapshotOptions) (SnapshotSummary, error) {
	pageSize, err := pageSizeOf(options)
	if err != nil {
		return SnapshotSummary{}, err
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	return Transact(ctx, store, func(ctx context.Context, tx IamStore) (SnapshotSummary, error) {
		collections, err := collectionsOf(ctx, tx, options)
		if err != nil {
			return SnapshotSummary{}, err
		}
		names := make([]any, len(collections))
		for index, name := range collections {
			names[index] = name
		}
		header := NewObject("format", SnapshotFormat, "version", SnapshotVersion, "createdAt", isoTime(clock())).SetRaw("collections", names)
		if err := write(MustStringify(header)); err != nil {
			return SnapshotSummary{}, err
		}
		summary, err := eachRecord(ctx, tx, collections, pageSize, func(collection string, record *Object) error {
			return write(MustStringify(NewObject("c", collection).SetRaw("r", record)))
		})
		if err != nil {
			return SnapshotSummary{}, err
		}
		trailer := NewObject("end", true).Assign(summary.ToValue())
		if err := write(MustStringify(trailer)); err != nil {
			return SnapshotSummary{}, err
		}
		return summary, nil
	})
}

func assertEmpty(ctx context.Context, tx IamStore, collections []string, declared bool) error {
	existing, err := listCollections(ctx, tx)
	if err != nil {
		return err
	}
	if len(existing) > 0 {
		shown := existing
		if len(shown) > 5 {
			shown = shown[:5]
		}
		return NewIamError("STORE_NOT_EMPTY", "The target store already holds records ("+strings.Join(shown, ", ")+"); import into an empty, migrated database", 409)
	}
	if existing == nil {
		if !declared {
			collections = []string{"tenants", "identities"}
		}
		for _, collection := range collections {
			found, err := tx.Find(ctx, collection, nil, &FindOptions{Limit: Ptr(1)})
			if err != nil {
				return err
			}
			if len(found) > 0 {
				return NewIamError("STORE_NOT_EMPTY", "The target store already holds records", 409)
			}
		}
	}
	return nil
}

// ImportStore loads a snapshot into an empty, migrated store in one transaction: a malformed line, a record the store
// refuses, or a missing or mismatched trailer rolls everything back.
func ImportStore(ctx context.Context, store IamStore, lines []string) (SnapshotSummary, error) {
	return ImportStoreFrom(ctx, store, func(yield func(string, error) bool) {
		for _, line := range lines {
			if !yield(line, nil) {
				return
			}
		}
	})
}

// ImportStoreFrom is ImportStore over a stream of lines (for example a file read line by line); an error from the
// stream aborts the import.
func ImportStoreFrom(ctx context.Context, store IamStore, lines iter.Seq2[string, error]) (SnapshotSummary, error) {
	return Transact(ctx, store, func(ctx context.Context, tx IamStore) (SnapshotSummary, error) {
		summary := SnapshotSummary{Collections: NewObject()}
		var header *Object
		var trailerRecords float64
		var trailerCollections *Object
		hasTrailer := false
		index := 0
		for raw, err := range lines {
			if err != nil {
				return SnapshotSummary{}, err
			}
			index++
			lineNumber := strconv.Itoa(index)
			line := JSTrim(raw)
			if line == "" {
				continue
			}
			if hasTrailer {
				return SnapshotSummary{}, NewIamError("SNAPSHOT_INVALID", "Content after the trailer on line "+lineNumber)
			}
			parsed, err := ParseJSONString(line)
			if err != nil {
				return SnapshotSummary{}, NewIamError("SNAPSHOT_INVALID", "Line "+lineNumber+" is not JSON")
			}
			entry, ok := parsed.(*Object)
			if !ok || entry == nil {
				return SnapshotSummary{}, NewIamError("SNAPSHOT_INVALID", "Line "+lineNumber+" is not an object")
			}
			if header == nil {
				if entry.Get("format") != SnapshotFormat || entry.Get("version") != float64(SnapshotVersion) {
					return SnapshotSummary{}, NewIamError("SNAPSHOT_INVALID", "Not a "+SnapshotFormat+" version "+strconv.Itoa(SnapshotVersion)+" snapshot")
				}
				header = entry
				var declared []string
				list, isList := entry.Get("collections").([]any)
				if isList {
					declared = []string{}
					for _, item := range list {
						if name, ok := item.(string); ok {
							declared = append(declared, name)
						}
					}
				}
				if err := assertEmpty(ctx, tx, declared, isList); err != nil {
					return SnapshotSummary{}, err
				}
				continue
			}
			if entry.Get("end") == true {
				listed, ok := entry.Get("collections").(*Object)
				if !ok || listed == nil {
					return SnapshotSummary{}, NewIamError("SNAPSHOT_INVALID", "The trailer on line "+lineNumber+" has no counts")
				}
				trailerRecords = jsNumber(entry.Get("records"))
				trailerCollections = listed
				hasTrailer = true
				continue
			}
			collection, isString := entry.Get("c").(string)
			record, isObject := entry.Get("r").(*Object)
			_, isArray := entry.Get("r").([]any)
			if !isString || !(isObject && record != nil || isArray) {
				return SnapshotSummary{}, NewIamError("SNAPSHOT_INVALID", "Line "+lineNumber+" is not a record entry")
			}
			// An array passes as an object here, and the store refuses it as not a record (record stays nil).
			if _, err := tx.Insert(ctx, collection, record); err != nil {
				return SnapshotSummary{}, err
			}
			current, _ := summary.Collections.Get(collection).(float64)
			summary.Collections.Set(collection, current+1)
			summary.Records++
		}
		if header == nil {
			return SnapshotSummary{}, NewIamError("SNAPSHOT_INVALID", "The snapshot is empty")
		}
		if !hasTrailer {
			return SnapshotSummary{}, NewIamError("SNAPSHOT_TRUNCATED", "The snapshot has no trailer; nothing was imported")
		}
		var expected []string
		for _, name := range trailerCollections.keys {
			if count := trailerCollections.values[name]; !strictEquals(count, 0.0) {
				expected = append(expected, name)
			}
		}
		mismatch := trailerRecords != float64(summary.Records) || len(expected) != summary.Collections.Len()
		for _, name := range expected {
			if mismatch {
				break
			}
			if !summary.Collections.Has(name) || !strictEquals(summary.Collections.Get(name), trailerCollections.Get(name)) {
				mismatch = true
			}
		}
		if mismatch {
			return SnapshotSummary{}, NewIamError("SNAPSHOT_TRUNCATED", "Record counts do not match the snapshot trailer; nothing was imported")
		}
		return summary, nil
	})
}

// jsNumber is Number(value) for model values.
func jsNumber(value any) float64 {
	switch v := value.(type) {
	case float64:
		return v
	case bool:
		if v {
			return 1
		}
		return 0
	case nil:
		return 0
	case string:
		trimmed := JSTrim(v)
		if trimmed == "" {
			return 0
		}
		f, err := strconv.ParseFloat(trimmed, 64)
		if err != nil {
			return nan()
		}
		return f
	}
	return nan()
}

func nan() float64 {
	var zero float64
	return zero / zero
}

// CopyStore copies every record from source into an empty, migrated target (for example SQLite to PostgreSQL). It
// reads in one source transaction and writes in one target transaction, so the copy is consistent and all-or-nothing.
func CopyStore(ctx context.Context, source, target IamStore, options SnapshotOptions) (SnapshotSummary, error) {
	pageSize, err := pageSizeOf(options)
	if err != nil {
		return SnapshotSummary{}, err
	}
	summary, err := Transact(ctx, source, func(ctx context.Context, from IamStore) (SnapshotSummary, error) {
		collections, err := collectionsOf(ctx, from, options)
		if err != nil {
			return SnapshotSummary{}, err
		}
		return Transact(ctx, target, func(ctx context.Context, to IamStore) (SnapshotSummary, error) {
			if err := assertEmpty(ctx, to, collections, true); err != nil {
				return SnapshotSummary{}, err
			}
			return eachRecord(ctx, from, collections, pageSize, func(collection string, record *Object) error {
				_, err := to.Insert(ctx, collection, record)
				return err
			})
		})
	})
	if err != nil {
		// SQLite and libSQL refuse a second instance's transaction on a file the caller already holds.
		var iamError *IamError
		if errors.As(err, &iamError) && iamError.Code == "DATABASE_IN_USE" {
			return SnapshotSummary{}, NewIamError("SAME_DATABASE", "The source and target are the same database", 409)
		}
		return SnapshotSummary{}, err
	}
	return summary, nil
}
