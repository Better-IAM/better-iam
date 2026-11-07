// Package libsql is the libSQL adapter (the Go port of @better-iam/adapter-libsql): local files and in-memory
// databases through the pure-Go modernc.org/sqlite driver (a libSQL file is an SQLite file), and remote Turso or sqld
// databases (libsql:, https:, http:, wss:, ws:) through github.com/tursodatabase/libsql-client-go. It runs the same
// schema migrations and SQL text as the TypeScript adapter.
//
// Transactions serialize per database in this process and take the writer lock (BEGIN IMMEDIATE) before any read;
// remote servers queue write transactions themselves.
package libsql

import (
	"context"
	"database/sql"
	"errors"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/Better-IAM/better-iam/go/adapters/internal/serial"
	"github.com/Better-IAM/better-iam/go/adapters/internal/sqlrows"
	"github.com/Better-IAM/better-iam/go/core"
	libsqlclient "github.com/tursodatabase/libsql-client-go/libsql"

	_ "modernc.org/sqlite" // registers the "sqlite" database/sql driver for local files
)

// Options configure the libSQL adapter.
type Options struct {
	// URL is ":memory:", "file:./iam.db", a plain path, or a remote libsql:, https:, wss: URL (Turso, sqld).
	URL string
	// AuthToken is the bearer token for remote databases.
	AuthToken string
	// EncryptionKey encrypts local files. Not available in the Go port (needs libSQL's native library): NOT_IMPLEMENTED.
	EncryptionKey string
	// SyncURL makes the local file an embedded replica of this remote URL. Not available in the Go port: NOT_IMPLEMENTED.
	SyncURL string
	// SyncInterval is the sync interval in seconds for embedded replicas.
	SyncInterval *float64
	// BusyTimeoutMs is how long local file operations wait for another connection's lock (nil: 5000; 0 to 60000).
	BusyTimeoutMs *int
}

var registry = serial.NewRegistry()

// trace observes every statement (tests only).
var trace sqlrows.Trace

func memory(url string) bool { return url == ":memory:" || strings.HasPrefix(url, "file::memory:") }

// scheme is a URL scheme of two or more characters; a single letter followed by a colon is a Windows drive.
var scheme = regexp.MustCompile(`(?i)^[a-z][a-z0-9+.-]+:`)
var supportedScheme = regexp.MustCompile(`^(file|libsql|https?|wss?):`)

var sqliteCodes = map[int]string{
	2067: "SQLITE_CONSTRAINT_UNIQUE",
	1555: "SQLITE_CONSTRAINT_PRIMARYKEY",
	5:    "SQLITE_BUSY",
	517:  "SQLITE_BUSY_SNAPSHOT",
	6:    "SQLITE_LOCKED",
}

var remoteCode = regexp.MustCompile(`SQLITE_[A-Z_]+`)

// mapError reports SQLite's extended result code to the shared mapper (libSQL reports it separately).
func mapError(err error) error {
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
			name = "SQLITE_" + core.NumberString(float64(coded.Code()))
		}
		return &core.DriverError{Code: name, Err: err}
	}
	// Remote (hrana) errors carry the code in their text.
	if code := remoteCode.FindString(err.Error()); code != "" {
		return &core.DriverError{Code: code, Err: err}
	}
	return err
}

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
	location string
}

// Store is a libSQL IamStore.
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

// localPath is the file a file: URL or plain path names (as the TypeScript adapter's lock canonicalizes it).
func localPath(target string) string {
	path, _, _ := strings.Cut(target, "?")
	if strings.HasPrefix(path, "file://") {
		if parsed, err := url.Parse(path); err == nil {
			p := parsed.Path
			if len(p) >= 3 && p[0] == '/' && p[2] == ':' {
				p = p[1:] // file:///C:/x.db
			}
			return filepath.FromSlash(p)
		}
		return strings.TrimPrefix(path, "file://")
	}
	return strings.TrimPrefix(path, "file:")
}

// New opens a libSQL database (libsqlAdapter).
func New(options Options) (*Store, error) {
	if options.URL == "" {
		return nil, core.NewIamError("INVALID_CONFIG", "libSQL requires a url: :memory:, file:, libsql:, https:, or wss:")
	}
	if !memory(options.URL) && !supportedScheme.MatchString(options.URL) && scheme.MatchString(options.URL) {
		return nil, core.NewIamError("INVALID_CONFIG", "Unsupported libSQL URL scheme")
	}
	timeout := 5000
	if options.BusyTimeoutMs != nil {
		timeout = *options.BusyTimeoutMs
	}
	if timeout < 0 || timeout > 60_000 {
		return nil, core.NewIamError("INVALID_CONFIG", "busyTimeoutMs must be between 0 and 60000")
	}
	target := options.URL
	if !memory(target) && !scheme.MatchString(target) {
		target = "file:" + target
	}
	if options.EncryptionKey != "" {
		return nil, core.NewIamError("NOT_IMPLEMENTED", "Encrypted libSQL files need libSQL's native library, which the Go port does not use", 501)
	}
	if options.SyncURL != "" {
		return nil, core.NewIamError("NOT_IMPLEMENTED", "Embedded libSQL replicas need libSQL's native library, which the Go port does not use", 501)
	}
	location := "remote"
	switch {
	case memory(target):
		location = "memory"
	case strings.HasPrefix(target, "file:"):
		location = "file"
	}
	var mutex *serial.Mutex
	switch location {
	case "memory":
		mutex = registry.New()
	case "file":
		mutex = registry.For("file:" + serial.CanonicalPath(localPath(target)))
	default:
		mutex = registry.For(target)
	}
	var db *sql.DB
	var err error
	switch location {
	case "memory":
		db, err = sql.Open("sqlite", ":memory:")
	case "file":
		db, err = sql.Open("sqlite", localPath(target))
	default:
		c, connectorErr := libsqlclient.NewConnector(target, libsqlclient.WithAuthToken(options.AuthToken))
		if connectorErr != nil {
			return nil, core.StorageError(mapError(connectorErr))
		}
		db = sql.OpenDB(c)
	}
	if err != nil {
		return nil, core.StorageError(mapError(err))
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)
	db.SetConnMaxIdleTime(0)
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err == nil && location != "remote" {
		_, err = sqlrows.Rows(ctx, conn, trace, mapError, "PRAGMA busy_timeout = "+core.NumberString(float64(timeout)))
	}
	if err == nil {
		// The libSQL client checks that the database can be opened at all.
		_, err = sqlrows.Rows(ctx, conn, trace, mapError, "SELECT 1 AS checkThatTheDatabaseCanBeOpened")
	}
	if err != nil {
		if conn != nil {
			_ = conn.Close()
		}
		_ = db.Close()
		return nil, core.StorageError(mapError(err))
	}
	return newStore(&shared{db: db, conn: conn, mutex: mutex, scope: new(int), location: location}, nil), nil
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

// Read implements core.RecordBackend. Root reads wait for the current transaction.
func (s *Store) Read(ctx context.Context, operation func(ctx context.Context, driver core.RecordDriver) error) error {
	current, err := s.active(ctx)
	if err != nil {
		return err
	}
	if current != nil {
		if err := operation(ctx, &driver{conn: s.shared.conn}); err != nil {
			current.rollbackOnly.Store(true)
			return core.StorageError(mapError(err))
		}
		return nil
	}
	return s.shared.mutex.Run(ctx, func(ctx context.Context) error {
		if _, err := s.active(ctx); err != nil {
			return err
		}
		if err := operation(ctx, &driver{conn: s.shared.conn}); err != nil {
			return core.StorageError(mapError(err))
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

// Transaction runs fn in a write transaction (BEGIN IMMEDIATE, as the libSQL client's transaction('write')); nested
// calls join the outer transaction.
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
		if _, err := sqlrows.Exec(ctx, conn, trace, mapError, "BEGIN IMMEDIATE"); err != nil {
			return core.StorageError(err)
		}
		context := &txContext{}
		context.active.Store(true)
		tx := newStore(s.shared, context)
		context.store = tx
		committed := false
		defer func() {
			if !committed {
				_, _ = sqlrows.Exec(contextWithoutCancel(ctx), conn, trace, mapError, "ROLLBACK")
			}
			context.active.Store(false)
		}()
		err := fn(contextWithScope(ctx, s.shared.scope, context), tx)
		if err == nil && context.rollbackOnly.Load() {
			err = core.NewIamError("TRANSACTION_ABORTED", "A nested database operation failed; transaction rolled back", 409)
		}
		if err != nil {
			return err
		}
		if _, err := sqlrows.Exec(ctx, conn, trace, mapError, "COMMIT"); err != nil {
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

func contextWithScope(ctx context.Context, key *int, current *txContext) context.Context {
	return context.WithValue(ctx, key, current)
}

func contextWithoutCancel(ctx context.Context) context.Context { return context.WithoutCancel(ctx) }

func (s *Store) executor() core.SqlExecutor {
	conn := s.shared.conn
	return func(ctx context.Context, text string, values ...any) ([]core.SqlRow, error) {
		return sqlrows.Rows(ctx, conn, trace, mapError, text, values...)
	}
}

// Migrate creates the schema and applies missing migrations (spec/storage/migrations/libsql).
func (s *Store) Migrate(ctx context.Context) error {
	return s.migrate(ctx, core.MigrationOptions{})
}

func (s *Store) migrate(ctx context.Context, options core.MigrationOptions) error {
	return s.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		if _, err := core.ApplyMigrations(ctx, tx.(*Store).executor(), "sqlite", options); err != nil {
			return core.StorageError(mapError(err))
		}
		return nil
	})
}

// Describe reports the schema version, applied migrations, record counts and the database's location and journal.
func (s *Store) Describe(ctx context.Context) (*core.StoreDescription, error) {
	run := func(ctx context.Context) (*core.StoreDescription, error) {
		execute := s.executor()
		var journalMode any
		// Remote servers may refuse PRAGMA statements; the queries below still surface outages.
		if rows, err := execute(ctx, "PRAGMA journal_mode"); err == nil && len(rows) > 0 {
			for _, value := range rows[0] {
				journalMode = sqlrows.Text(value)
			}
		}
		settings := core.NewObject("location", s.shared.location, "inMemory", s.shared.location == "memory", "journalMode", journalMode)
		description, err := core.DescribeRecords(ctx, execute, "libsql", settings)
		if err != nil {
			return nil, core.StorageError(mapError(err))
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

// Close closes the client; it is idempotent and refused inside a transaction.
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

// driver runs the TypeScript libSQL adapter's statements, text for text.
type driver struct {
	conn *sql.Conn
}

func (d *driver) rows(ctx context.Context, text string, values ...any) ([]core.SqlRow, error) {
	return sqlrows.Rows(ctx, d.conn, trace, mapError, text, values...)
}

func (d *driver) Select(ctx context.Context, collection string, id, tenantID *string) ([]core.StorageRow, error) {
	text := "SELECT collection, id, tenant_id, unique_key, data FROM iam_records WHERE collection = ?"
	values := []any{collection}
	if id != nil {
		text += " AND id = ?"
		values = append(values, *id)
	}
	if tenantID != nil {
		text += " AND tenant_id = ?"
		values = append(values, *tenantID)
	}
	rows, err := d.rows(ctx, text+" ORDER BY id ASC", values...)
	if err != nil {
		return nil, err
	}
	return sqlrows.StorageRows(rows), nil
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

func nullable(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func (d *driver) Insert(ctx context.Context, row core.StorageRow) error {
	_, err := sqlrows.Exec(ctx, d.conn, trace, mapError,
		"INSERT INTO iam_records (collection, id, tenant_id, unique_key, data) VALUES (?, ?, ?, ?, ?)",
		row.Collection, row.ID, row.TenantID, nullable(row.UniqueKey), row.Data)
	return err
}

func (d *driver) Update(ctx context.Context, row core.StorageRow) (bool, error) {
	affected, err := sqlrows.Exec(ctx, d.conn, trace, mapError,
		"UPDATE iam_records SET data = ?, unique_key = ? WHERE collection = ? AND id = ? AND tenant_id = ?",
		row.Data, nullable(row.UniqueKey), row.Collection, row.ID, row.TenantID)
	return affected == 1, err
}

func (d *driver) Delete(ctx context.Context, collection, id string) error {
	_, err := sqlrows.Exec(ctx, d.conn, trace, mapError, "DELETE FROM iam_records WHERE collection = ? AND id = ?", collection, id)
	return err
}
