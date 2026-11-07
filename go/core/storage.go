package core

import (
	"context"
	"errors"
	"math"
	"regexp"
	"sort"
	"strings"
)

// StorageRow is one row of iam_records: the low-level adapter building block.
type StorageRow struct {
	Collection string
	ID         string
	TenantID   string
	// UniqueKey is nil for SQL NULL.
	UniqueKey *string
	Data      string
}

// FieldCondition is a typed equality test on one top-level JSON field. Kind is "string" (Value string), "number"
// (Value float64), "boolean" (Value bool), "null" (present and JSON null), "absent" (not present) or "json" (deep
// JSON equality with an object or array; Value is its JSON text).
type FieldCondition struct {
	Field string
	Kind  string
	Value any
}

// MarshalJSON writes the condition as TypeScript does ({ field, kind, value? }).
func (c FieldCondition) MarshalJSON() ([]byte, error) {
	o := NewObject("field", c.Field, "kind", c.Kind)
	if c.Kind != "null" && c.Kind != "absent" {
		o.Set("value", c.Value)
	}
	return o.MarshalJSON()
}

// QueryOrder is RecordQuery.order.
type QueryOrder struct {
	Field     string   `json:"field"`
	Direction string   `json:"direction"`
	From      *float64 `json:"from,omitempty"`
	To        *float64 `json:"to,omitempty"`
}

// QueryPage is RecordQuery.page.
type QueryPage struct {
	Offset int  `json:"offset"`
	Limit  *int `json:"limit,omitempty"`
}

// RecordQuery is a filtered read a driver may evaluate in SQL.
type RecordQuery struct {
	Collection string
	ID         *string
	TenantID   *string
	UniqueKey  *string
	Conditions []FieldCondition
	// After keeps only rows whose id sorts after this id in code-point order (`id > after`); never with Order.
	After *string
	// Order orders by a numeric top-level field instead of id (ties by id, ascending), keeping only rows whose field
	// is a JSON number within [from, to]. Requires QueryCapabilities.Order.
	Order *QueryOrder
	// Page is present only when the query expresses the caller's complete filter.
	Page *QueryPage
}

// MarshalJSON writes the query with TypeScript's member names.
func (q RecordQuery) MarshalJSON() ([]byte, error) {
	o := NewObject("collection", q.Collection)
	if q.ID != nil {
		o.Set("id", *q.ID)
	}
	if q.TenantID != nil {
		o.Set("tenantId", *q.TenantID)
	}
	if q.UniqueKey != nil {
		o.Set("uniqueKey", *q.UniqueKey)
	}
	conditions := []any{}
	for _, condition := range q.Conditions {
		item := NewObject("field", condition.Field, "kind", condition.Kind)
		if condition.Kind != "null" && condition.Kind != "absent" {
			item.Set("value", condition.Value)
		}
		conditions = append(conditions, item)
	}
	o.Set("conditions", conditions)
	if q.After != nil {
		o.Set("after", *q.After)
	}
	if q.Order != nil {
		order := NewObject("field", q.Order.Field, "direction", q.Order.Direction)
		if q.Order.From != nil {
			order.Set("from", *q.Order.From)
		}
		if q.Order.To != nil {
			order.Set("to", *q.Order.To)
		}
		o.Set("order", order)
	}
	if q.Page != nil {
		page := NewObject("offset", q.Page.Offset)
		if q.Page.Limit != nil {
			page.Set("limit", *q.Page.Limit)
		}
		o.Set("page", page)
	}
	return o.MarshalJSON()
}

// QueryCapabilities says which optional conditions a driver evaluates.
type QueryCapabilities struct {
	// JSON: the driver evaluates json (object and array) conditions. Scalar kinds are always required.
	JSON bool
	// Order: the driver evaluates RecordQuery.Order.
	Order bool
}

// OrderedFields are the numeric fields SQL adapters index for findOrdered within a tenant (audit time and sequence).
var OrderedFields = []string{"timestamp", "sequence"}

// ExpiryFields are the numeric fields SQL adapters index for findOrdered across a whole collection.
var ExpiryFields = []string{"expiresAt", "deliveredAt", "failedAt"}

// RecordDriver is the minimal row access a RecordStore needs.
type RecordDriver interface {
	Select(ctx context.Context, collection string, id, tenantID *string) ([]StorageRow, error)
	Insert(ctx context.Context, row StorageRow) error
	Update(ctx context.Context, row StorageRow) (bool, error)
	Delete(ctx context.Context, collection, id string) error
}

// QueryDriver is the optional filtered read of a RecordDriver: exactly the rows of the collection matching every
// column and field condition, ordered by id in code-point order (or by Order), applying Page when present.
type QueryDriver interface {
	Query(ctx context.Context, query RecordQuery) ([]StorageRow, error)
	QueryCapabilities() QueryCapabilities
}

// CollectionsDriver is the optional distinct collection names in the table, sorted.
type CollectionsDriver interface {
	Collections(ctx context.Context) ([]string, error)
}

// QueryableField matches the field names a driver may inline into SQL paths. Other names are filtered in memory.
var QueryableField = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,127}$`)

// LookupIndexSteps are the lookup fields each schema step indexes (SQLite and libSQL), in step order.
var LookupIndexSteps = []struct {
	Step   string
	Fields []string
}{
	{"0002_query_indexes", []string{
		"tokenHash", "identityId", "email", "parentId", "subjectId", "groupId", "roleId", "credentialId",
		"originalIdentityId", "impersonatorSessionId", "accountId", "clientId", "uidHash", "userCodeHash",
		"grantIdHash", "connectionId", "targetId", "streamId", "jti",
	}},
	// Session cascades: role and temporary sessions by their source session, and by trust.
	{"0005_lookup_indexes", []string{"sourceSessionId", "trustId"}},
	// Data protection: deterministic token lookups and erasure by value (keyed value fingerprints).
	{"0006_protection_indexes", []string{"fingerprint"}},
}

func lookupIndexStep(step string) []string {
	for _, entry := range LookupIndexSteps {
		if entry.Step == step {
			return entry.Fields
		}
	}
	return nil
}

// IndexedFields are the high-cardinality string fields SQL adapters may index; they only affect performance.
var IndexedFields = func() []string {
	var out []string
	for _, entry := range LookupIndexSteps {
		out = append(out, entry.Fields...)
	}
	return out
}()

// JSONBEscapeKey is the reserved object key of the PostgreSQL value encoding (EncodeJSONBDocument).
const JSONBEscapeKey = "\u0001better-iam"

// MaxQueryConditions is the most typed conditions PlanQuery hands to a driver; further keys are filtered in memory.
const MaxQueryConditions = 24

func validIdentifier(value string, name string) error {
	// Keep composite natural-key indexes below PostgreSQL's B-tree tuple limit, including multibyte UTF-8 input.
	// Apply the same limit in every adapter.
	return validIdentifierValue(value, name)
}

// utf8Length is `new TextEncoder().encode(value).byteLength`: unpaired surrogates encode as U+FFFD (3 bytes).
func utf8Length(value string) int {
	n := 0
	for i := 0; i < len(value); {
		r, size := decodeUnit(value, i)
		i += size
		switch {
		case r >= 0xD800 && r <= 0xDFFF:
			n += 3
		case r < 0x80:
			n++
		case r < 0x800:
			n += 2
		case r < 0x10000:
			n += 3
		default:
			n += 4
		}
	}
	return n
}

func hasControl(value string) bool {
	for i := 0; i < len(value); i++ {
		if value[i] < 0x20 {
			return true
		}
	}
	return false
}

func validIdentifierValue(value any, name string) error {
	text, ok := value.(string)
	if !ok {
		return NewIamError("INVALID_RECORD", name+" must be a nonempty string of at most 512 UTF-8 bytes")
	}
	length := UTF16Len(text)
	if length == 0 || length > 512 || utf8Length(text) > 512 || hasControl(text) {
		return NewIamError("INVALID_RECORD", name+" must be a nonempty string of at most 512 UTF-8 bytes")
	}
	return nil
}

// storableIdentifier refuses identifiers (collection, id, tenant, natural key) a database column cannot hold
// unchanged: UTF-8 drivers turn an unpaired surrogate into U+FFFD, so two different ids would share one row.
func storableIdentifier(value any, name string) error {
	if err := validIdentifierValue(value, name); err != nil {
		return err
	}
	if !StorableString(value.(string)) {
		return NewIamError("INVALID_RECORD", name+" cannot contain unpaired surrogates")
	}
	return nil
}

// StorableString reports whether the string has no U+0000 and no unpaired surrogate. Such strings can be stored as
// record values, but database text comparisons cannot represent them, so Find evaluates filters holding them in
// memory. Identifiers must satisfy it.
func StorableString(value string) bool {
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == 0 {
			return false
		}
		if c == 0xED && i+1 < len(value) && value[i+1] >= 0xA0 && value[i+1] <= 0xBF {
			return false
		}
	}
	return true
}

func jsonValue(value any, ancestors map[*Object]bool, depth int) error {
	if depth > 64 {
		return NewIamError("INVALID_RECORD", "Record nesting exceeds 64 levels")
	}
	switch v := value.(type) {
	case nil, UndefinedType, string, bool:
		return nil
	case float64:
		if math.IsNaN(v) || math.IsInf(v, 0) {
			return NewIamError("INVALID_RECORD", "Records must contain JSON data only")
		}
		return nil
	case []any:
		for _, item := range v {
			if IsUndefined(item) {
				return NewIamError("INVALID_RECORD", "Undefined array items are not JSON values")
			}
			if err := jsonValue(item, ancestors, depth+1); err != nil {
				return err
			}
		}
		return nil
	case *Object:
		if v == nil {
			return nil
		}
		if ancestors[v] {
			return NewIamError("INVALID_RECORD", "Circular records are not supported")
		}
		ancestors[v] = true
		defer delete(ancestors, v)
		for _, key := range v.keys {
			if key == "__proto__" || key == "constructor" || key == "prototype" {
				return NewIamError("INVALID_RECORD", "Unsafe JSON property")
			}
			if err := jsonValue(v.values[key], ancestors, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	return NewIamError("INVALID_RECORD", "Records must contain JSON data only")
}

// pushableJSON reports whether a filter value is one a database can compare exactly.
func pushableJSON(value any) bool {
	switch v := value.(type) {
	case nil, bool:
		return true
	case float64:
		return !math.IsNaN(v) && !math.IsInf(v, 0)
	case string:
		return StorableString(v)
	case []any:
		for _, item := range v {
			if IsUndefined(item) || !pushableJSON(item) {
				return false
			}
		}
		return true
	case *Object:
		ok := true
		v.Entries(func(key string, item any) bool {
			if key == JSONBEscapeKey || !StorableString(key) || IsUndefined(item) || !pushableJSON(item) {
				ok = false
				return false
			}
			return true
		})
		return ok
	}
	return false
}

// RowFor validates a record and builds its row (rowFor).
func RowFor(collection string, record *Object) (StorageRow, error) {
	if err := storableIdentifier(collection, "collection"); err != nil {
		return StorageRow{}, err
	}
	if record == nil {
		return StorageRow{}, NewIamError("INVALID_RECORD", "Record must be an object")
	}
	id := record.Get("id")
	if err := storableIdentifier(id, "id"); err != nil {
		return StorageRow{}, err
	}
	tenantID := record.Get("tenantId")
	if err := storableIdentifier(tenantID, "tenantId"); err != nil {
		return StorageRow{}, err
	}
	var uniqueKey *string
	if key := record.Get("uniqueKey"); !IsUndefined(key) {
		if err := storableIdentifier(key, "uniqueKey"); err != nil {
			return StorageRow{}, err
		}
		text := key.(string)
		uniqueKey = &text
	}
	if err := jsonValue(record, map[*Object]bool{}, 0); err != nil {
		return StorageRow{}, err
	}
	data, _, err := Stringify(record)
	if err != nil {
		return StorageRow{}, NewIamError("INVALID_RECORD", "Records must contain JSON data only")
	}
	if UTF16Len(data) > 1_048_576 {
		return StorageRow{}, NewIamError("INVALID_RECORD", "Record exceeds one million characters")
	}
	return StorageRow{Collection: collection, ID: id.(string), TenantID: tenantID.(string), UniqueKey: uniqueKey, Data: data}, nil
}

// DecodeRow parses a stored row and checks its metadata (decode).
func DecodeRow(row StorageRow) (*Object, error) {
	value, err := ParseJSONString(row.Data)
	if err != nil {
		return nil, NewIamError("STORAGE_CORRUPT", "Invalid stored JSON", 500)
	}
	record, ok := value.(*Object)
	if !ok || record == nil {
		return nil, NewIamError("STORAGE_CORRUPT", "Record metadata mismatch", 500)
	}
	id, idOK := record.Get("id").(string)
	tenantID, tenantOK := record.Get("tenantId").(string)
	if !idOK || id != row.ID || !tenantOK || tenantID != row.TenantID {
		return nil, NewIamError("STORAGE_CORRUPT", "Record metadata mismatch", 500)
	}
	switch key := record.Get("uniqueKey").(type) {
	case UndefinedType:
		if row.UniqueKey != nil {
			return nil, NewIamError("STORAGE_CORRUPT", "Record metadata mismatch", 500)
		}
	case nil:
		// `(record.uniqueKey ?? null) !== row.unique_key`: a JSON null natural key matches a NULL column.
		if row.UniqueKey != nil {
			return nil, NewIamError("STORAGE_CORRUPT", "Record metadata mismatch", 500)
		}
	case string:
		if row.UniqueKey == nil || *row.UniqueKey != key {
			return nil, NewIamError("STORAGE_CORRUPT", "Record metadata mismatch", 500)
		}
	default:
		return nil, NewIamError("STORAGE_CORRUPT", "Record metadata mismatch", 500)
	}
	return record, nil
}

// DeepEqual is the storage equality: strict for scalars, structural for objects (key order ignored) and arrays
// (order kept).
func DeepEqual(actual, expected any) bool {
	if strictEquals(actual, expected) {
		return true
	}
	switch a := actual.(type) {
	case *Object:
		b, ok := expected.(*Object)
		if !ok || a == nil || b == nil {
			return false
		}
		if a.Len() != b.Len() {
			return false
		}
		for _, key := range a.keys {
			other, has := b.values[key]
			if !has || !DeepEqual(a.values[key], other) {
				return false
			}
		}
		return true
	case []any:
		b, ok := expected.([]any)
		if !ok || len(a) != len(b) {
			return false
		}
		for index := range a {
			if !DeepEqual(a[index], b[index]) {
				return false
			}
		}
		return true
	}
	return false
}

// MatchesFilter is the in-memory definition of filter semantics. Drivers' SQL must agree with it.
func MatchesFilter(record *Object, filter *Object) bool {
	ok := true
	filter.Entries(func(key string, value any) bool {
		if !DeepEqual(record.Get(key), value) {
			ok = false
			return false
		}
		return true
	})
	return ok
}

// CompareIDs is code-point (UTF-8 byte) order, the order of SQLite's BINARY and PostgreSQL's "C" collation,
// computed over UTF-16 code units as TypeScript does (so unpaired surrogates order identically).
func CompareIDs(left, right string) int {
	if StorableString(left) && StorableString(right) {
		// Valid UTF-8 byte order is code-point order.
		return strings.Compare(left, right)
	}
	a, b := ToUTF16(left), ToUTF16(right)
	length := min(len(a), len(b))
	for index := 0; index < length; index++ {
		x, y := int(a[index]), int(b[index])
		if x == y {
			continue
		}
		if x >= 0xD800 {
			if x >= 0xE000 {
				x -= 0x800
			} else {
				x += 0x2000
			}
		}
		if y >= 0xD800 {
			if y >= 0xE000 {
				y -= 0x800
			} else {
				y += 0x2000
			}
		}
		return x - y
	}
	return len(a) - len(b)
}

// FindPlan is the result of PlanQuery.
type FindPlan struct {
	Query RecordQuery
	// Exact: every filter key became part of the query, so the driver's rows need no further filtering.
	Exact bool
	// Empty: a column filter no stored record can satisfy (an identifier no column can hold).
	Empty bool
}

// MarshalJSON writes the plan with TypeScript's member names.
func (p FindPlan) MarshalJSON() ([]byte, error) {
	query, err := p.Query.MarshalJSON()
	if err != nil {
		return nil, err
	}
	return NewObject("query", jsonRaw(query), "exact", p.Exact, "empty", p.Empty).MarshalJSON()
}

func jsonRaw(text []byte) any {
	value, err := ParseJSON(text)
	if err != nil {
		panic(err)
	}
	return value
}

// PlanQuery splits a validated filter into driver conditions and keys left to the in-memory filter.
func PlanQuery(collection string, filter *Object, capabilities QueryCapabilities) FindPlan {
	query := RecordQuery{Collection: collection, Conditions: []FieldCondition{}}
	exact, empty := true, false
	filter.Entries(func(field string, value any) bool {
		if text, ok := value.(string); ok && (field == "id" || field == "tenantId" || field == "uniqueKey") {
			// decode() guarantees these JSON fields equal their columns; writes refuse unstorable ones.
			switch {
			case !StorableString(text):
				empty = true
			case field == "id":
				query.ID = &text
			case field == "tenantId":
				query.TenantID = &text
			default:
				query.UniqueKey = &text
			}
			return true
		}
		if !QueryableField.MatchString(field) || len(query.Conditions) >= MaxQueryConditions {
			exact = false
			return true
		}
		switch v := value.(type) {
		case string:
			if StorableString(v) {
				query.Conditions = append(query.Conditions, FieldCondition{Field: field, Kind: "string", Value: v})
			} else {
				exact = false
			}
		case float64:
			query.Conditions = append(query.Conditions, FieldCondition{Field: field, Kind: "number", Value: v})
		case bool:
			query.Conditions = append(query.Conditions, FieldCondition{Field: field, Kind: "boolean", Value: v})
		case nil:
			query.Conditions = append(query.Conditions, FieldCondition{Field: field, Kind: "null"})
		case UndefinedType:
			query.Conditions = append(query.Conditions, FieldCondition{Field: field, Kind: "absent"})
		default:
			if _, isObject := value.(*Object); capabilities.JSON && (isObject || isArray(value)) && pushableJSON(value) {
				query.Conditions = append(query.Conditions, FieldCondition{Field: field, Kind: "json", Value: MustStringify(value)})
			} else {
				exact = false
			}
		}
		return true
	})
	return FindPlan{Query: query, Exact: exact, Empty: empty}
}

func isArray(value any) bool {
	_, ok := value.([]any)
	return ok
}

// RecordBackend is what an adapter supplies to RecordStore: how reads and writes reach a driver (inside the caller's
// transaction when ctx carries one). Errors from op are mapped by the backend (StorageError).
type RecordBackend interface {
	Read(ctx context.Context, op func(ctx context.Context, driver RecordDriver) error) error
	Write(ctx context.Context, op func(ctx context.Context, driver RecordDriver) error) error
}

// RecordStore implements the shared strict JSON behavior that keeps SQLite, libSQL, and PostgreSQL semantically
// identical. Adapters embed it and add Transaction, Migrate, Close (and Describe).
type RecordStore struct {
	Backend RecordBackend
}

// Get reads one record; nil when missing.
func (s *RecordStore) Get(ctx context.Context, collection, id string) (*Object, error) {
	if err := validIdentifier(collection, "collection"); err != nil {
		return nil, err
	}
	if err := validIdentifier(id, "id"); err != nil {
		return nil, err
	}
	var record *Object
	err := s.Backend.Read(ctx, func(ctx context.Context, driver RecordDriver) error {
		// Writes refuse such identifiers; querying would match the row of the U+FFFD spelling.
		if !StorableString(collection) || !StorableString(id) {
			return nil
		}
		rows, err := driver.Select(ctx, collection, &id, nil)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return nil
		}
		record, err = DecodeRow(rows[0])
		return err
	})
	if err != nil {
		return nil, err
	}
	return record, nil
}

func validFilter(filter *Object) error {
	if err := jsonValue(filter, map[*Object]bool{}, 0); err != nil {
		return err
	}
	return nil
}

func validPage(offset int, limit *int) error {
	const maxSafe = 9007199254740991
	if offset < 0 || offset > maxSafe || (limit != nil && (*limit < 0 || *limit > maxSafe)) {
		return NewIamError("INVALID_FILTER", "Pagination must use nonnegative safe integers")
	}
	return nil
}

func pageSlice(records []*Object, offset int, limit *int) []*Object {
	if offset >= len(records) {
		return []*Object{}
	}
	end := len(records)
	if limit != nil && offset+*limit < end {
		end = offset + *limit
	}
	return records[offset:end]
}

func decodeRows(rows []StorageRow) ([]*Object, error) {
	out := make([]*Object, 0, len(rows))
	for _, row := range rows {
		record, err := DecodeRow(row)
		if err != nil {
			return nil, err
		}
		out = append(out, record)
	}
	return out, nil
}

func recordID(record *Object) string {
	id, _ := record.Get("id").(string)
	return id
}

// Find returns the records matching the filter, ordered by id in code-point order.
func (s *RecordStore) Find(ctx context.Context, collection string, filter *Object, options *FindOptions) ([]*Object, error) {
	if err := validIdentifier(collection, "collection"); err != nil {
		return nil, err
	}
	if filter == nil {
		filter = NewObject()
	}
	if err := validFilter(filter); err != nil {
		return nil, err
	}
	if options == nil {
		options = &FindOptions{}
	}
	offset := 0
	if options.Offset != nil {
		offset = *options.Offset
	}
	limit, after := options.Limit, options.After
	if err := validPage(offset, limit); err != nil {
		return nil, err
	}
	var result []*Object
	err := s.Backend.Read(ctx, func(ctx context.Context, driver RecordDriver) error {
		records, err := findWith(ctx, driver, collection, filter, offset, limit, after)
		result = records
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func findWith(ctx context.Context, driver RecordDriver, collection string, filter *Object, offset int, limit *int, after *string) ([]*Object, error) {
	wanted := func(record *Object) bool {
		return MatchesFilter(record, filter) && (after == nil || CompareIDs(recordID(record), *after) > 0)
	}
	filterAll := func(records []*Object) []*Object {
		out := make([]*Object, 0, len(records))
		for _, record := range records {
			if wanted(record) {
				out = append(out, record)
			}
		}
		return out
	}
	if (limit != nil && *limit == 0) || !StorableString(collection) {
		return []*Object{}, nil
	}
	if querier, ok := driver.(QueryDriver); ok {
		plan := PlanQuery(collection, filter, querier.QueryCapabilities())
		if plan.Empty {
			return []*Object{}, nil
		}
		// A cursor the database cannot hold exactly (an unpaired surrogate) is applied in memory.
		query := plan.Query
		if after != nil && StorableString(*after) {
			query.After = after
		}
		if plan.Exact && (query.After != nil) == (after != nil) {
			// With a cursor, read from it and skip `offset` here: a driver that ignores the cursor then returns a row at
			// or before it whenever that would change the page, which fails the check below instead of silently
			// shifting the page.
			window := QueryPage{Offset: offset, Limit: limit}
			if after != nil {
				window = QueryPage{Offset: 0}
				if limit != nil {
					end := offset + *limit
					window.Limit = &end
				}
			}
			paged := query
			paged.Page = &window
			rows, err := querier.Query(ctx, paged)
			if err != nil {
				return nil, err
			}
			records, err := decodeRows(rows)
			if err != nil {
				return nil, err
			}
			all := true
			for _, record := range records {
				if !wanted(record) {
					all = false
					break
				}
			}
			if all {
				if after == nil {
					return records, nil
				}
				return pageSlice(records, offset, nil), nil
			}
			// A driver that disagrees with the reference semantics (or ignores the cursor) must not shift pages: redo
			// the query without paging and filter in memory.
		}
		rows, err := querier.Query(ctx, query)
		if err != nil {
			return nil, err
		}
		records, err := decodeRows(rows)
		if err != nil {
			return nil, err
		}
		return pageSlice(filterAll(records), offset, limit), nil
	}
	var id, tenantID *string
	for _, column := range []string{"id", "tenantId"} {
		if text, ok := filter.Get(column).(string); ok {
			if !StorableString(text) {
				return []*Object{}, nil
			}
			value := text
			if column == "id" {
				id = &value
			} else {
				tenantID = &value
			}
		}
	}
	rows, err := driver.Select(ctx, collection, id, tenantID)
	if err != nil {
		return nil, err
	}
	records, err := decodeRows(rows)
	if err != nil {
		return nil, err
	}
	records = filterAll(records)
	// Do not inherit installation-dependent collation from a third-party driver.
	sort.SliceStable(records, func(i, j int) bool { return CompareIDs(recordID(records[i]), recordID(records[j])) < 0 })
	return pageSlice(records, offset, limit), nil
}

// FindOrdered is the store's ordered, bounded, paged find (IamStore.findOrdered).
func (s *RecordStore) FindOrdered(ctx context.Context, collection string, filter *Object, order OrderOptions) ([]*Object, error) {
	if err := validIdentifier(collection, "collection"); err != nil {
		return nil, err
	}
	if filter == nil {
		filter = NewObject()
	}
	if err := validFilter(filter); err != nil {
		return nil, err
	}
	options, err := orderOptions(order)
	if err != nil {
		return nil, err
	}
	var result []*Object
	err = s.Backend.Read(ctx, func(ctx context.Context, driver RecordDriver) error {
		if (options.limit != nil && *options.limit == 0) || !StorableString(collection) {
			result = []*Object{}
			return nil
		}
		matching := func(record *Object) bool { return MatchesFilter(record, filter) && inRange(record, options) }
		inOrder := func(records []*Object) []*Object {
			kept := make([]*Object, 0, len(records))
			for _, record := range records {
				if matching(record) {
					kept = append(kept, record)
				}
			}
			return pageSlice(orderRecords(kept, options.field, options.direction), options.offset, options.limit)
		}
		querier, ok := driver.(QueryDriver)
		if ok && querier.QueryCapabilities().Order {
			plan := PlanQuery(collection, filter, querier.QueryCapabilities())
			if plan.Empty {
				result = []*Object{}
				return nil
			}
			query := plan.Query
			query.Order = &QueryOrder{Field: options.field, Direction: options.direction, From: options.from, To: options.to}
			if plan.Exact {
				paged := query
				paged.Page = &QueryPage{Offset: options.offset, Limit: options.limit}
				rows, err := querier.Query(ctx, paged)
				if err != nil {
					return err
				}
				records, err := decodeRows(rows)
				if err != nil {
					return err
				}
				all := true
				for _, record := range records {
					if !matching(record) {
						all = false
						break
					}
				}
				if all {
					result = records
					return nil
				}
			}
			rows, err := querier.Query(ctx, query)
			if err != nil {
				return err
			}
			records, err := decodeRows(rows)
			if err != nil {
				return err
			}
			result = inOrder(records)
			return nil
		}
		// Stores without ordered queries: read the matching records and order them here.
		records, err := findWith(ctx, driver, collection, filter, 0, nil, nil)
		if err != nil {
			return err
		}
		result = inOrder(records)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

// Collections lists the collections holding records, sorted by code point. A driver without CollectionsDriver makes
// it fail with UNSUPPORTED, raised after the read so probing it inside a transaction does not roll it back.
func (s *RecordStore) Collections(ctx context.Context) ([]string, error) {
	var listed []string
	supported := false
	err := s.Backend.Read(ctx, func(ctx context.Context, driver RecordDriver) error {
		lister, ok := driver.(CollectionsDriver)
		if !ok {
			return nil
		}
		supported = true
		names, err := lister.Collections(ctx)
		listed = names
		return err
	})
	if err != nil {
		return nil, err
	}
	if !supported || listed == nil {
		if !supported {
			return nil, NewIamError("UNSUPPORTED", "This adapter cannot list its collections", 501)
		}
		listed = []string{}
	}
	sort.SliceStable(listed, func(i, j int) bool { return CompareIDs(listed[i], listed[j]) < 0 })
	return listed, nil
}

// Insert writes a new record (inside a transaction).
func (s *RecordStore) Insert(ctx context.Context, collection string, record *Object) (*Object, error) {
	row, err := RowFor(collection, record)
	if err != nil {
		return nil, err
	}
	var out *Object
	err = s.Backend.Write(ctx, func(ctx context.Context, driver RecordDriver) error {
		if err := driver.Insert(ctx, row); err != nil {
			return err
		}
		out, err = DecodeRow(row)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Put replaces an existing record (inside a transaction); it never inserts or moves a record between tenants.
func (s *RecordStore) Put(ctx context.Context, collection string, record *Object) (*Object, error) {
	row, err := RowFor(collection, record)
	if err != nil {
		return nil, err
	}
	var out *Object
	err = s.Backend.Write(ctx, func(ctx context.Context, driver RecordDriver) error {
		rows, err := driver.Select(ctx, collection, &row.ID, nil)
		if err != nil {
			return err
		}
		if len(rows) == 0 {
			return NewIamError("NOT_FOUND", "Cannot update a missing record", 404)
		}
		if rows[0].TenantID != row.TenantID {
			return NewIamError("CONFLICT", "Record tenant cannot be changed", 409)
		}
		updated, err := driver.Update(ctx, row)
		if err != nil {
			return err
		}
		if !updated {
			return NewIamError("NOT_FOUND", "Cannot update a missing record", 404)
		}
		out, err = DecodeRow(row)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// Delete removes a record (inside a transaction); missing ids are ignored.
func (s *RecordStore) Delete(ctx context.Context, collection, id string) error {
	if err := validIdentifier(collection, "collection"); err != nil {
		return err
	}
	if err := validIdentifier(id, "id"); err != nil {
		return err
	}
	return s.Backend.Write(ctx, func(ctx context.Context, driver RecordDriver) error {
		// No stored record can have such an identifier (see Get).
		if StorableString(collection) && StorableString(id) {
			return driver.Delete(ctx, collection, id)
		}
		return nil
	})
}

type validatedOrder struct {
	field     string
	direction string
	from, to  *float64
	offset    int
	limit     *int
}

// orderOptions validates OrderOptions and applies defaults.
func orderOptions(order OrderOptions) (validatedOrder, error) {
	direction := order.Direction
	if direction == "" {
		direction = "asc"
	}
	if !QueryableField.MatchString(order.Field) {
		return validatedOrder{}, NewIamError("INVALID_FILTER", "The order field must be a top-level identifier")
	}
	if direction != "asc" && direction != "desc" {
		return validatedOrder{}, NewIamError("INVALID_FILTER", "Order direction must be asc or desc")
	}
	for _, bound := range []*float64{order.From, order.To} {
		if bound != nil && (math.IsNaN(*bound) || math.IsInf(*bound, 0)) {
			return validatedOrder{}, NewIamError("INVALID_FILTER", "Range bounds must be finite numbers")
		}
	}
	offset := 0
	if order.Offset != nil {
		offset = *order.Offset
	}
	if err := validPage(offset, order.Limit); err != nil {
		return validatedOrder{}, err
	}
	return validatedOrder{field: order.Field, direction: direction, from: order.From, to: order.To, offset: offset, limit: order.Limit}, nil
}

func inRange(record *Object, order validatedOrder) bool {
	value, ok := record.Get(order.field).(float64)
	return ok && (order.from == nil || value >= *order.from) && (order.to == nil || value <= *order.to)
}

func orderRecords(records []*Object, field, direction string) []*Object {
	sign := 1.0
	if direction == "desc" {
		sign = -1
	}
	sort.SliceStable(records, func(i, j int) bool {
		left, _ := records[i].Get(field).(float64)
		right, _ := records[j].Get(field).(float64)
		difference := sign * (left - right)
		if difference != 0 && !math.IsNaN(difference) {
			return difference < 0
		}
		return CompareIDs(recordID(records[i]), recordID(records[j])) < 0
	})
	return records
}

// FindOrdered returns the records matching filter whose numeric order.Field lies in [From, To], ordered by that field
// (ties by id, ascending) and paged. It uses the store's FindOrdered when it has one and otherwise orders a plain Find
// in memory. where adds an in-memory predicate (nil for none); the store is then read in ordered chunks until the page
// is full, so it never loads everything.
func FindOrdered(ctx context.Context, store IamStore, collection string, filter *Object, order OrderOptions, where func(*Object) bool) ([]*Object, error) {
	options, err := orderOptions(order)
	if err != nil {
		return nil, err
	}
	ordered, ok := store.(OrderedFinder)
	if !ok {
		records, err := store.Find(ctx, collection, filter, nil)
		if err != nil {
			return nil, err
		}
		kept := make([]*Object, 0, len(records))
		for _, record := range records {
			if inRange(record, options) && (where == nil || where(record)) {
				kept = append(kept, record)
			}
		}
		return pageSlice(orderRecords(kept, options.field, options.direction), options.offset, options.limit), nil
	}
	if where == nil {
		return ordered.FindOrdered(ctx, collection, filter, order)
	}
	wanted := math.MaxInt
	if options.limit != nil {
		wanted = options.offset + *options.limit
	}
	chunk := 500
	if wanted != math.MaxInt {
		chunk = wanted * 2
	}
	chunk = min(max(chunk, 100), 2000)
	var matches []*Object
	for read := 0; len(matches) < wanted; read += chunk {
		page := order
		offset, limit := read, chunk
		page.Offset, page.Limit = &offset, &limit
		batch, err := ordered.FindOrdered(ctx, collection, filter, page)
		if err != nil {
			return nil, err
		}
		for _, record := range batch {
			if where(record) {
				matches = append(matches, record)
			}
		}
		if len(batch) < chunk {
			break
		}
	}
	return pageSlice(matches, options.offset, options.limit), nil
}

// SchemaMigration is a named, idempotent schema step. The ledger iam_migrations records which ones ran.
type SchemaMigration struct {
	Name       string
	Statements []string
}

// DriverError carries a database driver's error code (a PostgreSQL SQLSTATE such as 23505, or an SQLite extended
// result code name such as SQLITE_CONSTRAINT_UNIQUE) so StorageError can map it.
type DriverError struct {
	Code string
	Err  error
}

func (e *DriverError) Error() string { return "database driver error " + e.Code }
func (e *DriverError) Unwrap() error { return e.Err }

// StorageError maps database failures without leaking SQL or credential-bearing record data.
func StorageError(err error) *IamError {
	var iamError *IamError
	if errors.As(err, &iamError) {
		return iamError
	}
	code := ""
	var driverError *DriverError
	var sqlState interface{ SQLState() string }
	switch {
	case errors.As(err, &driverError):
		code = driverError.Code
	case errors.As(err, &sqlState):
		code = sqlState.SQLState()
	}
	switch code {
	case "23505", "SQLITE_CONSTRAINT_UNIQUE", "SQLITE_CONSTRAINT_PRIMARYKEY":
		return NewIamError("CONFLICT", "A record with this identifier or tenant key already exists", 409)
	case "40001", "40P01", "55P03", "57014", "SQLITE_BUSY", "SQLITE_BUSY_SNAPSHOT", "SQLITE_LOCKED":
		return NewIamError("STORAGE_BUSY", "Database is busy; retry the complete operation", 503)
	}
	return NewIamError("STORAGE_ERROR", "Database operation failed", 500)
}

// Ptr returns a pointer to v (for FindOptions and OrderOptions fields).
func Ptr[T any](v T) *T { return &v }
