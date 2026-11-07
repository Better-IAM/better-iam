// Package sqlite is the SQLite adapter (the Go port of @better-iam/adapter-sqlite), built on the pure-Go
// modernc.org/sqlite driver. It runs the same schema migrations and the same SQL as the TypeScript adapter, so the
// two can share one database file.
//
// SQLite serializes operations per canonical filename in this process; SQLite's own BEGIN IMMEDIATE lock coordinates
// other processes with a bounded wait. Use PostgreSQL when sustained concurrent writes or large datasets are expected.
package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"sync/atomic"

	"github.com/Better-IAM/better-iam/go/adapters/internal/serial"
	"github.com/Better-IAM/better-iam/go/adapters/internal/sqlrows"
	"github.com/Better-IAM/better-iam/go/core"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver
)

// Options configure the SQLite adapter.
type Options struct {
	// Filename is a database file path or ":memory:". URI filenames (file:...) are unsupported.
	Filename string
	// BusyTimeoutMs is how long an operation waits for another connection's lock (nil: 5000; 0 to 60000).
	BusyTimeoutMs *int
	// JournalMode of a database file: "wal" (default) or "delete". Ignored for :memory:.
	JournalMode string
	// Durability: "full" (default) flushes every commit to disk; "normal" in WAL mode can lose the last commits on
	// power loss or an OS crash (never the database) in exchange for much cheaper writes.
	Durability string
}

var synchronousModes = []string{"off", "normal", "full", "extra"}

var registry = serial.NewRegistry()

// trace observes every statement (tests only).
var trace sqlrows.Trace

// sqliteCodes are the extended result codes the shared error mapper knows by name.
var sqliteCodes = map[int]string{
	2067: "SQLITE_CONSTRAINT_UNIQUE",
	1555: "SQLITE_CONSTRAINT_PRIMARYKEY",
	5:    "SQLITE_BUSY",
	517:  "SQLITE_BUSY_SNAPSHOT",
	6:    "SQLITE_LOCKED",
}

// driverError attaches the SQLite result code name to a driver error so core.StorageError can map it.
func driverError(err error) error {
	if err == nil {
		return nil
	}
	var iamError *core.IamError
	if errors.As(err, &iamError) {
		return err
	}
	var coded interface{ Code() int }
	if errors.As(err, &coded) {
		name, ok := sqliteCodes[coded.Code()]
		if !ok {
			name = "SQLITE_" + itoa(coded.Code())
		}
		return &core.DriverError{Code: name, Err: err}
	}
	return err
}

func itoa(n int) string { return core.NumberString(float64(n)) }

type txContext struct {
	store        *Store
	active       atomic.Bool
	rollbackOnly atomic.Bool
}

type shared struct {
	db       *sql.DB
	conn     *sql.Conn
	mutex    *serial.Mutex
	scope    *int
	inMemory bool
}

// Store is a SQLite IamStore. The root store (from New) and the handles transactions pass to their callbacks are both
// Stores.
type Store struct {
	core.RecordStore
	shared  *shared
	context *txContext
	closed  atomic.Bool
}

var _ core.IamStore = (*Store)(nil)
var _ core.OrderedFinder = (*Store)(nil)
var _ core.CollectionLister = (*Store)(nil)
var _ core.Describer = (*Store)(nil)

func newStore(s *shared, context *txContext) *Store {
	store := &Store{shared: s, context: context}
	store.RecordStore.Backend = store
	return store
}

// New opens a SQLite database (sqliteAdapter).
func New(options Options) (*Store, error) {
	if options.Filename == "" || strings.HasPrefix(options.Filename, "file:") {
		return nil, core.NewIamError("INVALID_CONFIG", "SQLite requires a filename or :memory:; URI filenames are unsupported")
	}
	timeout := 5000
	if options.BusyTimeoutMs != nil {
		timeout = *options.BusyTimeoutMs
	}
	if timeout < 0 || timeout > 60_000 {
		return nil, core.NewIamError("INVALID_CONFIG", "busyTimeoutMs must be between 0 and 60000")
	}
	if options.JournalMode != "" && options.JournalMode != "wal" && options.JournalMode != "delete" {
		return nil, core.NewIamError("INVALID_CONFIG", "journalMode must be wal or delete")
	}
	if options.Durability != "" && options.Durability != "full" && options.Durability != "normal" {
		return nil, core.NewIamError("INVALID_CONFIG", "durability must be full or normal")
	}
	inMemory := options.Filename == ":memory:"
	mutex := registry.New()
	if !inMemory {
		mutex = registry.For(serial.CanonicalPath(options.Filename))
	}
	db, err := sql.Open("sqlite", options.Filename)
	if err != nil {
		return nil, core.StorageError(driverError(err))
	}
	// One connection, like better-sqlite3: an in-memory database lives in it, and transactions keep it across
	// awaited application code.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err == nil {
		pragmas := []string{"PRAGMA busy_timeout = " + itoa(timeout), "PRAGMA foreign_keys = ON"}
		if !inMemory {
			mode := "WAL"
			if options.JournalMode == "delete" {
				mode = "DELETE"
			}
			pragmas = append(pragmas, "PRAGMA journal_mode = "+mode)
		}
		synchronous := "FULL"
		if options.Durability == "normal" {
			synchronous = "NORMAL"
		}
		pragmas = append(pragmas, "PRAGMA synchronous = "+synchronous)
		for _, pragma := range pragmas {
			if _, err = sqlrows.Rows(ctx, conn, trace, driverError, pragma); err != nil {
				break
			}
		}
	}
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		_ = db.Close()
		return nil, core.StorageError(driverError(err))
	}
	return newStore(&shared{db: db, conn: conn, mutex: mutex, scope: new(int), inMemory: inMemory}, nil), nil
}

func (s *Store) active(ctx context.Context) (*txContext, error) {
	if s.closed.Load() {
		return nil, core.NewIamError("STORE_CLOSED", "Database adapter is closed", 500)
	}
	current := s.context
	if current == nil {
		current, _ = ctx.Value(s.shared.scope).(*txContext)
	}
	if current != nil && !current.active.Load() {
		return nil, core.NewIamError("TRANSACTION_CLOSED", "Transaction has already completed", 500)
	}
	return current, nil
}

// Read implements core.RecordBackend.
func (s *Store) Read(ctx context.Context, operation func(ctx context.Context, driver core.RecordDriver) error) error {
	current, err := s.active(ctx)
	if err != nil {
		return err
	}
	if current != nil {
		if err := operation(ctx, &driver{conn: s.shared.conn}); err != nil {
			current.rollbackOnly.Store(true)
			return core.StorageError(err)
		}
		return nil
	}
	return s.shared.mutex.Run(ctx, func(ctx context.Context) error {
		if _, err := s.active(ctx); err != nil {
			return err
		}
		if err := operation(ctx, &driver{conn: s.shared.conn}); err != nil {
			return core.StorageError(err)
		}
		return nil
	})
}

// Write implements core.RecordBackend: writes require a transaction.
func (s *Store) Write(ctx context.Context, operation func(ctx context.Context, driver core.RecordDriver) error) error {
	current, err := s.active(ctx)
	if err != nil {
		return err
	}
	if current == nil {
		return core.NewIamError("TRANSACTION_REQUIRED", "Database writes require transaction()", 500)
	}
	return s.Read(ctx, operation)
}

// Transaction runs fn holding the SQLite writer lock (BEGIN IMMEDIATE) on the adapter's one connection; nested calls
// join the outer transaction.
func (s *Store) Transaction(ctx context.Context, fn core.TxFunc) error {
	current, err := s.active(ctx)
	if err != nil {
		return err
	}
	if current != nil {
		return joined(ctx, current, fn)
	}
	return s.shared.mutex.Run(ctx, func(ctx context.Context) error {
		if _, err := s.active(ctx); err != nil {
			return err
		}
		conn := s.shared.conn
		// Acquire the SQLite writer lock before any reads, and keep one connection across application code. A
		// deferred transaction is not sufficient.
		if _, err := sqlrows.Exec(ctx, conn, trace, driverError, "BEGIN IMMEDIATE"); err != nil {
			return core.StorageError(err)
		}
		context := &txContext{}
		context.active.Store(true)
		tx := newStore(s.shared, context)
		context.store = tx
		committed := false
		defer func() {
			if !committed {
				// Preserve the original failure (or panic).
				_, _ = sqlrows.Exec(withoutCancel(ctx), conn, trace, driverError, "ROLLBACK")
			}
			context.active.Store(false)
		}()
		err := fn(withScope(ctx, s.shared.scope, context), tx)
		if err == nil && context.rollbackOnly.Load() {
			err = core.NewIamError("TRANSACTION_ABORTED", "A nested database operation failed; transaction rolled back", 409)
		}
		if err != nil {
			return err
		}
		if _, err := sqlrows.Exec(ctx, conn, trace, driverError, "COMMIT"); err != nil {
			return core.StorageError(err)
		}
		committed = true
		return nil
	})
}

func joined(ctx context.Context, current *txContext, fn core.TxFunc) (err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			current.rollbackOnly.Store(true)
			panic(recovered)
		}
	}()
	if err = fn(ctx, current.store); err != nil {
		current.rollbackOnly.Store(true)
	}
	return err
}

func withScope(ctx context.Context, key *int, current *txContext) context.Context {
	return context.WithValue(ctx, key, current)
}

func withoutCancel(ctx context.Context) context.Context { return context.WithoutCancel(ctx) }

func (s *Store) executor() core.SqlExecutor {
	conn := s.shared.conn
	return func(ctx context.Context, text string, values ...any) ([]core.SqlRow, error) {
		return sqlrows.Rows(ctx, conn, trace, driverError, text, values...)
	}
}

// Migrate creates the schema and applies missing migrations (spec/storage/migrations/sqlite).
func (s *Store) Migrate(ctx context.Context) error {
	return s.migrate(ctx, core.MigrationOptions{})
}

func (s *Store) migrate(ctx context.Context, options core.MigrationOptions) error {
	return s.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		if _, err := core.ApplyMigrations(ctx, tx.(*Store).executor(), "sqlite", options); err != nil {
			return core.StorageError(err)
		}
		return nil
	})
}

// Describe reports the schema version, applied migrations, record counts and SQLite settings.
func (s *Store) Describe(ctx context.Context) (*core.StoreDescription, error) {
	run := func(ctx context.Context) (*core.StoreDescription, error) {
		execute := s.executor()
		pragma := func(name string) (any, error) {
			rows, err := execute(ctx, "PRAGMA "+name)
			if err != nil || len(rows) == 0 {
				return nil, err
			}
			for _, value := range rows[0] {
				return value, nil
			}
			return nil, nil
		}
		number := func(name string) (float64, error) {
			value, err := pragma(name)
			if err != nil {
				return 0, err
			}
			switch v := value.(type) {
			case int64:
				return float64(v), nil
			case float64:
				return v, nil
			}
			return 0, nil
		}
		pageSize, err := number("page_size")
		if err != nil {
			return nil, core.StorageError(err)
		}
		journal, err := pragma("journal_mode")
		if err != nil {
			return nil, core.StorageError(err)
		}
		synchronousIndex, err := number("synchronous")
		if err != nil {
			return nil, core.StorageError(err)
		}
		var synchronous any
		if index := int(synchronousIndex); index >= 0 && index < len(synchronousModes) {
			synchronous = synchronousModes[index]
		}
		pages, err := number("page_count")
		if err != nil {
			return nil, core.StorageError(err)
		}
		free, err := number("freelist_count")
		if err != nil {
			return nil, core.StorageError(err)
		}
		settings := core.NewObject("journalMode", sqlrows.Text(journal), "synchronous", synchronous,
			"sizeBytes", pages*pageSize, "freeBytes", free*pageSize, "inMemory", s.shared.inMemory)
		description, err := core.DescribeRecords(ctx, execute, "sqlite", settings)
		if err != nil {
			return nil, core.StorageError(err)
		}
		return description, nil
	}
	current, err := s.active(ctx)
	if err != nil {
		return nil, err
	}
	if current != nil {
		return run(ctx)
	}
	var description *core.StoreDescription
	err = s.shared.mutex.Run(ctx, func(ctx context.Context) error {
		if _, err := s.active(ctx); err != nil {
			return err
		}
		var err error
		description, err = run(ctx)
		return err
	})
	return description, err
}

// Close closes the database; it is idempotent and refused inside a transaction.
func (s *Store) Close(ctx context.Context) error {
	if s.closed.Load() {
		return nil
	}
	current, err := s.active(ctx)
	if err != nil {
		return err
	}
	if current != nil {
		return core.NewIamError("TRANSACTION_ACTIVE", "Cannot close an adapter inside a transaction", 500)
	}
	return s.shared.mutex.Run(ctx, func(ctx context.Context) error {
		if !s.closed.Load() {
			s.closed.Store(true)
			_ = s.shared.conn.Close()
			_ = s.shared.db.Close()
		}
		return nil
	})
}

// driver runs the record statements of the TypeScript adapter (the SQL Kysely generates for it, and core's
// SqliteSelect).
type driver struct {
	conn *sql.Conn
}

func (d *driver) rows(ctx context.Context, text string, values ...any) ([]core.SqlRow, error) {
	return sqlrows.Rows(ctx, d.conn, trace, driverError, text, values...)
}

func (d *driver) Select(ctx context.Context, collection string, id, tenantID *string) ([]core.StorageRow, error) {
	text := `select * from "iam_records" where "collection" = ?`
	values := []any{collection}
	if id != nil {
		text += ` and "id" = ?`
		values = append(values, *id)
	}
	if tenantID != nil {
		text += ` and "tenant_id" = ?`
		values = append(values, *tenantID)
	}
	rows, err := d.rows(ctx, text+` order by "id" asc`, values...)
	if err != nil {
		return nil, err
	}
	return sqlrows.StorageRows(rows), nil
}

func nullable(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func (d *driver) Insert(ctx context.Context, row core.StorageRow) error {
	_, err := sqlrows.Exec(ctx, d.conn, trace, driverError,
		`insert into "iam_records" ("collection", "id", "tenant_id", "unique_key", "data") values (?, ?, ?, ?, ?)`,
		row.Collection, row.ID, row.TenantID, nullable(row.UniqueKey), row.Data)
	return err
}

func (d *driver) Update(ctx context.Context, row core.StorageRow) (bool, error) {
	affected, err := sqlrows.Exec(ctx, d.conn, trace, driverError,
		`update "iam_records" set "data" = ?, "unique_key" = ? where "collection" = ? and "id" = ? and "tenant_id" = ?`,
		row.Data, nullable(row.UniqueKey), row.Collection, row.ID, row.TenantID)
	return affected == 1, err
}

func (d *driver) Delete(ctx context.Context, collection, id string) error {
	_, err := sqlrows.Exec(ctx, d.conn, trace, driverError, `delete from "iam_records" where "collection" = ? and "id" = ?`, collection, id)
	return err
}

func (d *driver) QueryCapabilities() core.QueryCapabilities {
	return core.QueryCapabilities{Order: true}
}

func (d *driver) Query(ctx context.Context, query core.RecordQuery) ([]core.StorageRow, error) {
	statement, err := core.SqliteSelect(query)
	if err != nil {
		return nil, err
	}
	rows, err := d.rows(ctx, statement.Text, statement.Values...)
	if err != nil {
		return nil, err
	}
	return sqlrows.StorageRows(rows), nil
}

func (d *driver) Collections(ctx context.Context) ([]string, error) {
	rows, err := d.rows(ctx, core.CollectionsSQL)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		names = append(names, sqlrows.Text(row["collection"]))
	}
	return names, nil
}
