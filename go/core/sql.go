package core

import (
	"context"
	"embed"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// SQL shared by the reference adapters. Everything here is plain string building: adapters pass the text and values
// to their own driver. Field names are validated against QueryableField before they appear in SQL; every value is a
// bound parameter.

// SqlStatement is SQL text with its bound values (strings, float64 or int).
type SqlStatement struct {
	Text   string `json:"text"`
	Values []any  `json:"values"`
}

// SqlDialect is "sqlite" (SQLite and libSQL) or "postgres".
type SqlDialect = string

// SqlRow is one result row keyed by column name.
type SqlRow = map[string]any

// SqlExecutor runs one statement with bound values and returns its rows.
type SqlExecutor func(ctx context.Context, text string, values ...any) ([]SqlRow, error)

const recordColumns = "collection, id, tenant_id, unique_key, data"

func sqlField(field string) (string, error) {
	if !QueryableField.MatchString(field) {
		return "", NewIamError("INVALID_FILTER", "Field names in SQL conditions must be identifiers")
	}
	return field, nil
}

func sqlDirection(order *QueryOrder) string {
	if order.Direction == "desc" {
		return "DESC"
	}
	return "ASC"
}

// sqlitePath is the SQLite path literal. Identical text in the query and the index lets the planner use the index.
func sqlitePath(name string) string { return `'$."` + name + `"'` }

func jsonText(value any) string {
	text, ok, _ := Stringify(value)
	if !ok {
		return "null"
	}
	return text
}

// SqliteSelect is the SELECT for SQLite and libSQL (JSON1). json conditions are not supported.
func SqliteSelect(query RecordQuery) (SqlStatement, error) {
	where := []string{"collection = ?"}
	values := []any{query.Collection}
	for _, column := range []struct {
		name  string
		value *string
	}{{"id", query.ID}, {"tenant_id", query.TenantID}, {"unique_key", query.UniqueKey}} {
		if column.value == nil {
			continue
		}
		where = append(where, column.name+" = ?")
		values = append(values, *column.value)
	}
	// BINARY collation compares UTF-8 bytes, which is code-point order (CompareIDs).
	if query.After != nil {
		where = append(where, "id > ?")
		values = append(values, *query.After)
	}
	for _, condition := range query.Conditions {
		name, err := sqlField(condition.Field)
		if err != nil {
			return SqlStatement{}, err
		}
		path := sqlitePath(name)
		typ := "json_type(data, " + path + ")"
		value := "json_extract(data, " + path + ")"
		switch condition.Kind {
		case "string":
			where = append(where, typ+" = 'text' AND "+value+" = ?")
			values = append(values, condition.Value)
		case "number":
			// Compare the literal's text, not a parsed double. SQLite reads integer literals above 2^53 as exact 64-bit
			// integers and some builds parse large exponents inexactly, while every stored number and every bound value
			// is JSON.stringify output of a double.
			where = append(where, typ+" IN ('integer', 'real') AND (data -> "+path+") = ?")
			values = append(values, jsonText(condition.Value))
		case "boolean":
			literal := "false"
			if condition.Value == true {
				literal = "true"
			}
			where = append(where, typ+" = '"+literal+"'")
		case "null":
			where = append(where, typ+" = 'null'")
		case "absent":
			where = append(where, typ+" IS NULL")
		default:
			return SqlStatement{}, NewIamError("INVALID_FILTER", "SQLite adapters do not evaluate JSON conditions")
		}
	}
	orderBy := "id"
	if query.Order != nil {
		name, err := sqlField(query.Order.Field)
		if err != nil {
			return SqlStatement{}, err
		}
		path := sqlitePath(name)
		value := "json_extract(data, " + path + ")"
		// `IS NOT NULL` repeats the partial index predicate so the ordered indexes qualify.
		where = append(where, value+" IS NOT NULL AND json_type(data, "+path+") IN ('integer', 'real')")
		// Bounds are parsed from JSON text like stored values, so large integers compare consistently.
		for _, bound := range []struct {
			operator string
			value    *float64
		}{{">=", query.Order.From}, {"<=", query.Order.To}} {
			if bound.value == nil {
				continue
			}
			where = append(where, value+" "+bound.operator+" json_extract(?, '$')")
			values = append(values, jsonText(*bound.value))
		}
		orderBy = value + " " + sqlDirection(query.Order) + ", id"
	}
	text := "SELECT " + recordColumns + " FROM iam_records WHERE " + strings.Join(where, " AND ") + " ORDER BY " + orderBy
	if query.Page != nil {
		text += " LIMIT ? OFFSET ?"
		limit := -1
		if query.Page.Limit != nil {
			limit = *query.Page.Limit
		}
		values = append(values, limit, query.Page.Offset)
	}
	return SqlStatement{Text: text, Values: values}, nil
}

var postgresTypes = map[string]string{"string": "string", "number": "number", "boolean": "boolean", "null": "null"}

// PostgresSelect is the SELECT for PostgreSQL. Scalar tests share one jsonb containment test, served by a GIN index.
func PostgresSelect(query RecordQuery) (SqlStatement, error) {
	var values []any
	bind := func(value any) string {
		values = append(values, value)
		return "$" + strconv.Itoa(len(values))
	}
	where := []string{"collection = " + bind(query.Collection)}
	if query.ID != nil {
		where = append(where, "id = "+bind(*query.ID))
	}
	if query.TenantID != nil {
		where = append(where, "tenant_id = "+bind(*query.TenantID))
	}
	if query.UniqueKey != nil {
		where = append(where, "unique_key = "+bind(*query.UniqueKey))
	}
	// The id column uses the "C" collation: byte order, which is code-point order.
	if query.After != nil {
		where = append(where, "id > "+bind(*query.After))
	}
	contains := NewObject()
	for _, condition := range query.Conditions {
		name, err := sqlField(condition.Field)
		if err != nil {
			return SqlStatement{}, err
		}
		member := "((data::jsonb) -> " + bind(name) + "::text)"
		switch condition.Kind {
		case "string", "number", "boolean", "null":
			// Containment finds candidates through the index; the type test makes it exact equality.
			if condition.Kind == "null" {
				contains.Set(name, nil)
			} else {
				contains.Set(name, condition.Value)
			}
			where = append(where, "jsonb_typeof"+member+" = '"+postgresTypes[condition.Kind]+"'")
		case "absent":
			where = append(where, member+" IS NULL")
		case "json":
			where = append(where, member+" = "+bind(condition.Value)+"::jsonb")
		}
	}
	if contains.Len() > 0 {
		where = append(where, "(data::jsonb) @> "+bind(jsonText(contains))+"::jsonb")
	}
	orderBy := "id"
	if query.Order != nil {
		name, err := sqlField(query.Order.Field)
		if err != nil {
			return SqlStatement{}, err
		}
		// The validated field name is inlined so the expression matches the ordered indexes.
		member := "((data::jsonb) -> '" + name + "')"
		where = append(where, "jsonb_typeof"+member+" = 'number'")
		if query.Order.From != nil {
			where = append(where, member+" >= "+bind(jsonText(*query.Order.From))+"::jsonb")
		}
		if query.Order.To != nil {
			where = append(where, member+" <= "+bind(jsonText(*query.Order.To))+"::jsonb")
		}
		orderBy = member + " " + sqlDirection(query.Order) + ", id"
	}
	text := "SELECT " + recordColumns + " FROM iam_records WHERE " + strings.Join(where, " AND ") + " ORDER BY " + orderBy
	if query.Page != nil {
		limit := "ALL"
		if query.Page.Limit != nil {
			limit = bind(*query.Page.Limit)
		}
		text += " LIMIT " + limit + " OFFSET " + bind(query.Page.Offset)
	}
	if values == nil {
		values = []any{}
	}
	return SqlStatement{Text: text, Values: values}, nil
}

//go:embed migrations/sqlite/*.sql migrations/postgres/*.sql
var migrationFiles embed.FS

// MigrationNames are the schema steps in order (spec/storage/migrations/index.json).
var MigrationNames = []string{
	"0001_records",
	"0002_query_indexes",
	"0003_ordered_indexes",
	"0004_expiry_indexes",
	"0005_lookup_indexes",
	"0006_protection_indexes",
}

func migrationDir(dialect SqlDialect) string {
	if dialect == "postgres" {
		return "migrations/postgres"
	}
	return "migrations/sqlite"
}

// MigrationStatements reads one embedded spec migration file: one statement per line, `;`-terminated.
func MigrationStatements(dialect SqlDialect, name string) []string {
	data, err := migrationFiles.ReadFile(migrationDir(dialect) + "/" + name + ".sql")
	if err != nil {
		panic(fmt.Sprintf("core: missing embedded migration %s/%s: %v", dialect, name, err))
	}
	var statements []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(strings.TrimRight(line, "\r"), ";")
		if line != "" {
			statements = append(statements, line)
		}
	}
	return statements
}

// SchemaMigrations are the ordered, append-only schema steps: exactly the statements of
// spec/storage/migrations/{dialect}/ (embedded from go/core/migrations, which a test keeps identical to spec/).
// Secondary indexes end in `id` so one index both finds rows and yields them in `ORDER BY id` order.
func SchemaMigrations(dialect SqlDialect) []SchemaMigration {
	out := make([]SchemaMigration, 0, len(MigrationNames))
	for _, name := range MigrationNames {
		out = append(out, SchemaMigration{Name: name, Statements: MigrationStatements(dialect, name)})
	}
	return out
}

// MigrationOptions tune ApplyMigrations.
type MigrationOptions struct {
	// Now is the applied_at clock (epoch milliseconds); zero means the current time.
	Now int64
	// Before runs before a migration's statements, in the same transaction (for data rewrites).
	Before func(ctx context.Context, name string, execute SqlExecutor) error
}

func toNumber(value any) (float64, bool) {
	switch v := value.(type) {
	case int64:
		return float64(v), true
	case int:
		return float64(v), true
	case int32:
		return float64(v), true
	case float64:
		return v, true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return f, err == nil
	case []byte:
		f, err := strconv.ParseFloat(strings.TrimSpace(string(v)), 64)
		return f, err == nil
	}
	return 0, false
}

func toText(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	case nil:
		return "null"
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return NumberString(v)
	}
	return fmt.Sprint(value)
}

// ApplyMigrations creates the schema and applies missing named migrations, recording each in iam_migrations. Run it
// inside the adapter's serialized write transaction. Returns the names applied now.
func ApplyMigrations(ctx context.Context, execute SqlExecutor, dialect SqlDialect, options MigrationOptions) ([]string, error) {
	now := options.Now
	if now == 0 {
		now = NowMillis()
	}
	if _, err := execute(ctx, "CREATE TABLE IF NOT EXISTS iam_schema_version (id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL)"); err != nil {
		return nil, err
	}
	rows, err := execute(ctx, "SELECT version FROM iam_schema_version WHERE id = 1")
	if err != nil {
		return nil, err
	}
	if len(rows) > 0 {
		if version, ok := toNumber(rows[0]["version"]); !ok || version != 1 {
			return nil, NewIamError("SCHEMA_VERSION", "Unsupported database schema version", 500)
		}
	}
	if _, err := execute(ctx, "CREATE TABLE IF NOT EXISTS iam_migrations (name TEXT PRIMARY KEY, applied_at BIGINT NOT NULL)"); err != nil {
		return nil, err
	}
	rows, err = execute(ctx, "SELECT name FROM iam_migrations")
	if err != nil {
		return nil, err
	}
	applied := map[string]bool{}
	for _, row := range rows {
		applied[toText(row["name"])] = true
	}
	ran := []string{}
	insert := "INSERT INTO iam_migrations (name, applied_at) VALUES (?, ?)"
	if dialect == "postgres" {
		insert = "INSERT INTO iam_migrations (name, applied_at) VALUES ($1, $2)"
	}
	for _, migration := range SchemaMigrations(dialect) {
		if applied[migration.Name] {
			continue
		}
		if options.Before != nil {
			if err := options.Before(ctx, migration.Name, execute); err != nil {
				return nil, err
			}
		}
		for _, statement := range migration.Statements {
			if _, err := execute(ctx, statement); err != nil {
				return nil, err
			}
		}
		if _, err := execute(ctx, insert, migration.Name, now); err != nil {
			return nil, err
		}
		ran = append(ran, migration.Name)
	}
	if _, err := execute(ctx, "INSERT INTO iam_schema_version (id, version) VALUES (1, 1) ON CONFLICT (id) DO NOTHING"); err != nil {
		return nil, err
	}
	return ran, nil
}

var noSuchTable = regexp.MustCompile(`(?i)no such table`)

// IsMissingTable reports whether a query failed because a table does not exist (PostgreSQL 42P01, SQLite "no such
// table").
func IsMissingTable(err error) bool {
	if err == nil {
		return false
	}
	var driverError *DriverError
	if errors.As(err, &driverError) && driverError.Code == "42P01" {
		return true
	}
	var sqlState interface{ SQLState() string }
	if errors.As(err, &sqlState) && sqlState.SQLState() == "42P01" {
		return true
	}
	for cause := err; cause != nil; cause = errors.Unwrap(cause) {
		if noSuchTable.MatchString(cause.Error()) {
			return true
		}
	}
	return false
}

// CollectionsSQL lists the distinct collection names in the records table.
const CollectionsSQL = "SELECT DISTINCT collection FROM iam_records ORDER BY collection"

// DescribeRecords is the adapter-independent part of IamStore.Describe: schema version, applied migrations, and
// record counts per collection. Missing tables read as empty, so an unmigrated database reports empty lists; any
// other failure is returned. Run it outside a transaction on PostgreSQL (a failed statement aborts the transaction).
func DescribeRecords(ctx context.Context, execute SqlExecutor, adapter string, settings *Object) (*StoreDescription, error) {
	// Only a table that does not exist yet reads as empty; a database that cannot be reached must fail rather than
	// look like a fresh, unmigrated one.
	attempt := func(text string) ([]SqlRow, error) {
		rows, err := execute(ctx, text)
		if err != nil {
			if IsMissingTable(err) {
				return nil, nil
			}
			return nil, err
		}
		return rows, nil
	}
	versionRows, err := attempt("SELECT version FROM iam_schema_version WHERE id = 1")
	if err != nil {
		return nil, err
	}
	migrationRows, err := attempt("SELECT name, applied_at FROM iam_migrations ORDER BY name")
	if err != nil {
		return nil, err
	}
	collectionRows, err := attempt("SELECT collection, COUNT(*) AS records FROM iam_records GROUP BY collection ORDER BY collection")
	if err != nil {
		return nil, err
	}
	description := &StoreDescription{Adapter: adapter, Migrations: []MigrationInfo{}, Collections: []CollectionInfo{}, Settings: settings}
	if len(versionRows) > 0 {
		version, _ := toNumber(versionRows[0]["version"])
		v := int64(version)
		description.SchemaVersion = &v
	}
	for _, row := range migrationRows {
		at, _ := toNumber(row["applied_at"])
		description.Migrations = append(description.Migrations, MigrationInfo{Name: toText(row["name"]), AppliedAt: int64(at)})
	}
	for _, row := range collectionRows {
		count, _ := toNumber(row["records"])
		description.Collections = append(description.Collections, CollectionInfo{Name: toText(row["collection"]), Records: int64(count)})
	}
	if description.Settings == nil {
		description.Settings = NewObject()
	}
	return description, nil
}

// --- PostgreSQL value encoding -------------------------------------------------------------------------------------
//
// PostgreSQL's jsonb rejects U+0000 and unpaired surrogates, and the PostgreSQL adapter indexes `data::jsonb`. Record
// values may still hold such strings, so that adapter stores them encoded: a string becomes
// `{ [JSONBEscapeKey]: "<UTF-16 code units as hex>" }`, and an object's keys that are unstorable (or equal to the
// escape key itself) move into `[JSONBEscapeKey]: [[hex key, value], ...]`. Decoding restores the original record;
// only the order of escaped keys within their object can change.

var escapedJSON = regexp.MustCompile(`(?i)\\u0000|\\ud[89a-f][0-9a-f]{2}|\\u0001better-iam`)
var hexUnits = regexp.MustCompile(`^(?:[0-9a-f]{4})*$`)

func hexString(value string) string {
	var b strings.Builder
	for _, unit := range ToUTF16(value) {
		fmt.Fprintf(&b, "%04x", unit)
	}
	return b.String()
}

func fromHex(value any) (string, error) {
	text, ok := value.(string)
	if !ok || !hexUnits.MatchString(text) {
		return "", NewIamError("STORAGE_CORRUPT", "Invalid escaped value", 500)
	}
	units := make([]uint16, 0, len(text)/4)
	for index := 0; index < len(text); index += 4 {
		n, _ := strconv.ParseUint(text[index:index+4], 16, 16)
		units = append(units, uint16(n))
	}
	return FromUTF16(units), nil
}

func encodeValue(value any) any {
	switch v := value.(type) {
	case string:
		if StorableString(v) {
			return v
		}
		return NewObject(JSONBEscapeKey, hexString(v))
	case []any:
		out := make([]any, len(v))
		for index, item := range v {
			out[index] = encodeValue(item)
		}
		return out
	case *Object:
		if v == nil {
			return v
		}
		out := NewObject()
		var escaped []any
		v.Entries(func(key string, item any) bool {
			if IsUndefined(item) {
				return true
			}
			if key == JSONBEscapeKey || !StorableString(key) {
				escaped = append(escaped, []any{hexString(key), encodeValue(item)})
			} else {
				out.SetRaw(key, encodeValue(item))
			}
			return true
		})
		if len(escaped) > 0 {
			out.SetRaw(JSONBEscapeKey, escaped)
		}
		return out
	}
	return value
}

func decodeValue(value any) (any, error) {
	switch v := value.(type) {
	case []any:
		out := make([]any, len(v))
		for index, item := range v {
			decoded, err := decodeValue(item)
			if err != nil {
				return nil, err
			}
			out[index] = decoded
		}
		return out, nil
	case *Object:
		if v == nil {
			return v, nil
		}
		marker := v.Get(JSONBEscapeKey)
		if _, ok := marker.(string); ok && v.Len() == 1 {
			return fromHex(marker)
		}
		out := NewObject()
		var failure error
		v.Entries(func(key string, item any) bool {
			if key == JSONBEscapeKey {
				return true
			}
			decoded, err := decodeValue(item)
			if err != nil {
				failure = err
				return false
			}
			out.SetRaw(key, decoded)
			return true
		})
		if failure != nil {
			return nil, failure
		}
		if !IsUndefined(marker) {
			pairs, ok := marker.([]any)
			if !ok {
				return nil, NewIamError("STORAGE_CORRUPT", "Invalid escaped keys", 500)
			}
			for _, pair := range pairs {
				entry, ok := pair.([]any)
				if !ok || len(entry) != 2 {
					return nil, NewIamError("STORAGE_CORRUPT", "Invalid escaped keys", 500)
				}
				key, err := fromHex(entry[0])
				if err != nil {
					return nil, err
				}
				decoded, err := decodeValue(entry[1])
				if err != nil {
					return nil, err
				}
				out.SetRaw(key, decoded)
			}
		}
		return out, nil
	}
	return value, nil
}

// EncodeJSONBDocument is record JSON as the PostgreSQL adapter stores it: valid jsonb, reversible by
// DecodeJSONBDocument.
func EncodeJSONBDocument(data string) (string, error) {
	// Only JSON text containing one of the escapes can need a rewrite (false positives re-encode to the same text);
	// JSON.stringify never writes these characters unescaped.
	if !escapedJSON.MatchString(data) {
		return data, nil
	}
	value, err := ParseJSONString(data)
	if err != nil {
		return "", err
	}
	return MustStringify(encodeValue(value)), nil
}

// DecodeJSONBDocument is the original record JSON of a document written by EncodeJSONBDocument.
func DecodeJSONBDocument(data string) (string, error) {
	if !strings.Contains(data, `\u0001better-iam`) {
		return data, nil
	}
	value, err := ParseJSONString(data)
	if err != nil {
		return "", err
	}
	decoded, err := decodeValue(value)
	if err != nil {
		return "", err
	}
	return MustStringify(decoded), nil
}

// EncodeLegacyPostgresRows is the PostgreSQL migration hook that rewrites rows written before the value encoding
// existed, whose text jsonb would reject, so the jsonb index of 0002_query_indexes can be built.
func EncodeLegacyPostgresRows(ctx context.Context, name string, execute SqlExecutor) error {
	if name != "0002_query_indexes" {
		return nil
	}
	rows, err := execute(ctx, `SELECT collection, id, data FROM iam_records WHERE strpos(data, '\u0000') > 0 OR data ~* '\\ud[89a-f]'`)
	if err != nil {
		return err
	}
	for _, row := range rows {
		data := toText(row["data"])
		encoded, err := EncodeJSONBDocument(data)
		if err != nil {
			return err
		}
		if encoded != data {
			if _, err := execute(ctx, "UPDATE iam_records SET data = $1 WHERE collection = $2 AND id = $3", encoded, row["collection"], row["id"]); err != nil {
				return err
			}
		}
	}
	return nil
}
