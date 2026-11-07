package core

import (
	"context"
	"sort"
	"time"
)

// StoreCallPage is the pagination of an observed find.
type StoreCallPage struct {
	Offset *int `json:"offset,omitempty"`
	Limit  *int `json:"limit,omitempty"`
	// Keyset reports a keyset cursor (never its id).
	Keyset bool `json:"keyset,omitempty"`
}

// StoreCall is one storage call observed by InstrumentStore. It never carries record data or filter values.
type StoreCall struct {
	// Method is get, find, findOrdered, insert, put, delete, collections or describe.
	Method string `json:"method"`
	// Collection is the collection, or * for whole-store calls.
	Collection string `json:"collection"`
	// FilterKeys are the filter keys of a find, sorted.
	FilterKeys []string `json:"filterKeys,omitempty"`
	// Page is the pagination of a find, when given.
	Page *StoreCallPage `json:"page,omitempty"`
	// Records returned (find, get) or written (insert, put, delete: 1); collections listed or described.
	Records    int     `json:"records"`
	DurationMs float64 `json:"durationMs"`
	// InTransaction: the call was made through the handle a Transaction callback received.
	InTransaction bool `json:"inTransaction"`
	// Failed: the call failed; Records is 0.
	Failed bool `json:"failed"`
}

type instrumented struct {
	target        IamStore
	inTransaction bool
	report        func(StoreCall)
	now           func() float64
	wrap          func(target IamStore, inTransaction bool) IamStore
}

func timed[T any](s *instrumented, method, collection string, extra StoreCall, run func() (T, error), count func(T) int) (T, error) {
	started := s.now()
	value, err := run()
	call := extra
	call.Method = method
	call.Collection = collection
	call.DurationMs = s.now() - started
	call.InTransaction = s.inTransaction
	if err != nil {
		call.Records = 0
		call.Failed = true
	} else {
		call.Records = count(value)
	}
	s.report(call)
	return value, err
}

func filterKeys(filter *Object) []string {
	keys := filter.Keys()
	if keys == nil {
		keys = []string{}
	}
	sort.Slice(keys, func(i, j int) bool { return compareUTF16(keys[i], keys[j]) < 0 })
	return keys
}

func (s *instrumented) Get(ctx context.Context, collection, id string) (*Object, error) {
	return timed(s, "get", collection, StoreCall{}, func() (*Object, error) { return s.target.Get(ctx, collection, id) },
		func(value *Object) int {
			if value != nil {
				return 1
			}
			return 0
		})
}

func (s *instrumented) Find(ctx context.Context, collection string, filter *Object, options *FindOptions) ([]*Object, error) {
	extra := StoreCall{FilterKeys: filterKeys(filter)}
	if options != nil && (options.Limit != nil || options.Offset != nil || options.After != nil) {
		extra.Page = &StoreCallPage{Offset: options.Offset, Limit: options.Limit, Keyset: options.After != nil}
	}
	return timed(s, "find", collection, extra, func() ([]*Object, error) { return s.target.Find(ctx, collection, filter, options) },
		func(value []*Object) int { return len(value) })
}

func (s *instrumented) Insert(ctx context.Context, collection string, record *Object) (*Object, error) {
	return timed(s, "insert", collection, StoreCall{}, func() (*Object, error) { return s.target.Insert(ctx, collection, record) },
		func(*Object) int { return 1 })
}

func (s *instrumented) Put(ctx context.Context, collection string, record *Object) (*Object, error) {
	return timed(s, "put", collection, StoreCall{}, func() (*Object, error) { return s.target.Put(ctx, collection, record) },
		func(*Object) int { return 1 })
}

func (s *instrumented) Delete(ctx context.Context, collection, id string) error {
	_, err := timed(s, "delete", collection, StoreCall{}, func() (struct{}, error) { return struct{}{}, s.target.Delete(ctx, collection, id) },
		func(struct{}) int { return 1 })
	return err
}

func (s *instrumented) Transaction(ctx context.Context, fn TxFunc) error {
	return s.target.Transaction(ctx, func(ctx context.Context, tx IamStore) error {
		return fn(ctx, s.wrap(tx, true))
	})
}

func (s *instrumented) Migrate(ctx context.Context) error { return s.target.Migrate(ctx) }
func (s *instrumented) Close(ctx context.Context) error   { return s.target.Close(ctx) }

type orderedPart struct{ s *instrumented }

func (p orderedPart) FindOrdered(ctx context.Context, collection string, filter *Object, order OrderOptions) ([]*Object, error) {
	extra := StoreCall{FilterKeys: filterKeys(filter), Page: &StoreCallPage{Offset: order.Offset, Limit: order.Limit}}
	return timed(p.s, "findOrdered", collection, extra, func() ([]*Object, error) {
		return p.s.target.(OrderedFinder).FindOrdered(ctx, collection, filter, order)
	}, func(value []*Object) int { return len(value) })
}

type listerPart struct{ s *instrumented }

func (p listerPart) Collections(ctx context.Context) ([]string, error) {
	return timed(p.s, "collections", "*", StoreCall{}, func() ([]string, error) {
		return p.s.target.(CollectionLister).Collections(ctx)
	}, func(names []string) int { return len(names) })
}

type describerPart struct{ s *instrumented }

func (p describerPart) Describe(ctx context.Context) (*StoreDescription, error) {
	return timed(p.s, "describe", "*", StoreCall{}, func() (*StoreDescription, error) {
		return p.s.target.(Describer).Describe(ctx)
	}, func(description *StoreDescription) int {
		if description == nil {
			return 0
		}
		return len(description.Collections)
	})
}

// InstrumentStore wraps a store so every data call is reported to onCall (reads, writes, collections, and describe;
// transaction, migrate, and close pass straight through). The wrapper adds no behavior: results, errors, and
// transactions are the underlying store's, and it has exactly the optional methods (FindOrdered, Collections,
// Describe) the store has. onCall runs synchronously after each call; panics it raises are ignored. now (nil: a
// monotonic clock in milliseconds) times the calls.
func InstrumentStore(store IamStore, onCall func(StoreCall), now func() float64) IamStore {
	report := func(call StoreCall) {
		defer func() { _ = recover() }() // Observability must never change the outcome of a storage call.
		onCall(call)
	}
	if now == nil {
		start := time.Now()
		now = func() float64 { return float64(time.Since(start).Nanoseconds()) / 1e6 }
	}
	var wrap func(target IamStore, inTransaction bool) IamStore
	wrap = func(target IamStore, inTransaction bool) IamStore {
		s := &instrumented{target: target, inTransaction: inTransaction, report: report, now: now, wrap: wrap}
		_, ordered := target.(OrderedFinder)
		_, lister := target.(CollectionLister)
		_, describer := target.(Describer)
		switch {
		case ordered && lister && describer:
			return struct {
				*instrumented
				orderedPart
				listerPart
				describerPart
			}{s, orderedPart{s}, listerPart{s}, describerPart{s}}
		case ordered && lister:
			return struct {
				*instrumented
				orderedPart
				listerPart
			}{s, orderedPart{s}, listerPart{s}}
		case ordered && describer:
			return struct {
				*instrumented
				orderedPart
				describerPart
			}{s, orderedPart{s}, describerPart{s}}
		case lister && describer:
			return struct {
				*instrumented
				listerPart
				describerPart
			}{s, listerPart{s}, describerPart{s}}
		case ordered:
			return struct {
				*instrumented
				orderedPart
			}{s, orderedPart{s}}
		case lister:
			return struct {
				*instrumented
				listerPart
			}{s, listerPart{s}}
		case describer:
			return struct {
				*instrumented
				describerPart
			}{s, describerPart{s}}
		}
		return s
	}
	return wrap(store, false)
}

// StoreCallTotals are the totals of one method and collection.
type StoreCallTotals struct {
	Calls      int     `json:"calls"`
	Records    int     `json:"records"`
	DurationMs float64 `json:"durationMs"`
}

// SummarizeStoreCalls totals a list of calls grouped by method and collection ("find:sessions"), keyed in first-seen
// order (keys lists the order).
func SummarizeStoreCalls(calls []StoreCall) (summary map[string]*StoreCallTotals, keys []string) {
	summary = map[string]*StoreCallTotals{}
	for _, call := range calls {
		key := call.Method + ":" + call.Collection
		entry, ok := summary[key]
		if !ok {
			entry = &StoreCallTotals{}
			summary[key] = entry
			keys = append(keys, key)
		}
		entry.Calls++
		entry.Records += call.Records
		entry.DurationMs += call.DurationMs
	}
	return summary, keys
}
