// Package postgres is the PostgreSQL adapter (the Go port of @better-iam/adapter-postgres), built on
// github.com/jackc/pgx/v5. It runs the same schema migrations and SQL as the TypeScript adapter (documents stored
// jsonb-compatible by core.EncodeJSONBDocument), so both can serve one database.
//
// Transactions serialize through a database advisory lock, including other adapter instances and the TypeScript
// adapter.
package postgres

import (
	"context"
	"regexp"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Options configure the PostgreSQL adapter.
type Options struct {
	// ConnectionString is a postgres:// or postgresql:// URL.
	ConnectionString string
	// PoolSize is the most connections (nil: 10; 1 to 100).
	PoolSize *int
	// LockTimeoutMs bounds waits for the transaction lock and for a pool connection (nil: 5000; 1 to 60000).
	LockTimeoutMs *int
}

// migrationLockTimeoutMs is how long a migration waits for other instances' transactions, including another
// migration.
const migrationLockTimeoutMs = 10 * 60_000

// trace observes every statement (tests only).
var trace func(text string, values []any)

var connectionPattern = regexp.MustCompile(`^postgres(?:ql)?://`)

type querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

type txContext struct {
	store        *Store
	conn         *pgxpool.Conn
	lock         sync.Mutex // a pgx connection serves one statement at a time
	active       atomic.Bool
	rollbackOnly atomic.Bool
}

type shared struct {
	pool    *pgxpool.Pool
	scope   *int
	timeout int
}

// Store is a PostgreSQL IamStore.
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

// New creates the adapter and its connection pool (postgresAdapter). Connections open lazily.
func New(options Options) (*Store, error) {
	if !connectionPattern.MatchString(options.ConnectionString) {
		return nil, core.NewIamError("INVALID_CONFIG", "A PostgreSQL connection string is required")
	}
	timeout := 5000
	if options.LockTimeoutMs != nil {
		timeout = *options.LockTimeoutMs
	}
	size := 10
	if options.PoolSize != nil {
		size = *options.PoolSize
	}
	if timeout < 1 || timeout > 60_000 || size < 1 || size > 100 {
		return nil, core.NewIamError("INVALID_CONFIG", "Invalid PostgreSQL pool size or lock timeout")
	}
	config, err := pgxpool.ParseConfig(options.ConnectionString)
	if err != nil {
		return nil, core.NewIamError("INVALID_CONFIG", "A PostgreSQL connection string is required")
	}
	config.MaxConns = int32(size)
	config.MinConns = 0
	config.ConnConfig.ConnectTimeout = time.Duration(timeout) * time.Millisecond
	// Untyped text parameters, as node-postgres sends them: the server infers each parameter's type from the SQL.
	config.ConnConfig.DefaultQueryExecMode = pgx.QueryExecModeExec
	pool, err := pgxpool.NewWithConfig(context.Background(), config)
	if err != nil {
		return nil, core.StorageError(err)
	}
	return newStore(&shared{pool: pool, scope: new(int), timeout: timeout}, nil), nil
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

// poolQuerier runs each statement on a pool connection acquired within the connection timeout.
type poolQuerier struct {
	pool    *pgxpool.Pool
	timeout int
}

func (p poolQuerier) acquire(ctx context.Context) (*pgxpool.Conn, error) {
	acquireCtx, cancel := context.WithTimeout(ctx, time.Duration(p.timeout)*time.Millisecond)
	defer cancel()
	return p.pool.Acquire(acquireCtx)
}

type releasingRows struct {
	pgx.Rows
	conn *pgxpool.Conn
}

func (r *releasingRows) Close() {
	r.Rows.Close()
	if r.conn != nil {
		r.conn.Release()
		r.conn = nil
	}
}

func (p poolQuerier) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	conn, err := p.acquire(ctx)
	if err != nil {
		return nil, err
	}
	rows, err := conn.Query(ctx, sql, args...)
	if err != nil {
		conn.Release()
		return nil, err
	}
	return &releasingRows{Rows: rows, conn: conn}, nil
}

func (p poolQuerier) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	conn, err := p.acquire(ctx)
	if err != nil {
		return pgconn.CommandTag{}, err
	}
	defer conn.Release()
	return conn.Exec(ctx, sql, args...)
}

// lockedQuerier serializes statements on a transaction's connection.
type lockedQuerier struct{ tx *txContext }

func (l lockedQuerier) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	l.tx.lock.Lock()
	rows, err := l.tx.conn.Query(ctx, sql, args...)
	if err != nil {
		l.tx.lock.Unlock()
		return nil, err
	}
	return &unlockingRows{Rows: rows, unlock: l.tx.lock.Unlock}, nil
}

func (l lockedQuerier) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	l.tx.lock.Lock()
	defer l.tx.lock.Unlock()
	return l.tx.conn.Exec(ctx, sql, args...)
}

type unlockingRows struct {
	pgx.Rows
	unlock func()
}

func (r *unlockingRows) Close() {
	r.Rows.Close()
	if r.unlock != nil {
		r.unlock()
		r.unlock = nil
	}
}

func rowsOf(ctx context.Context, q querier, text string, values ...any) ([]core.SqlRow, error) {
	if trace != nil {
		trace(text, values)
	}
	rows, err := q.Query(ctx, text, values...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	fields := rows.FieldDescriptions()
	var out []core.SqlRow
	for rows.Next() {
		cells, err := rows.Values()
		if err != nil {
			return nil, err
		}
		row := core.SqlRow{}
		for index, field := range fields {
			row[field.Name] = cells[index]
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func execOf(ctx context.Context, q querier, text string, values ...any) (int64, error) {
	if trace != nil {
		trace(text, values)
	}
	tag, err := q.Exec(ctx, text, values...)
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}

func (s *Store) querierFor(current *txContext) querier {
	if current != nil {
		return lockedQuerier{current}
	}
	return poolQuerier{pool: s.shared.pool, timeout: s.shared.timeout}
}

// Read implements core.RecordBackend.
func (s *Store) Read(ctx context.Context, operation func(ctx context.Context, driver core.RecordDriver) error) error {
	current, err := s.active(ctx)
	if err != nil {
		return err
	}
	if err := operation(ctx, &driver{q: s.querierFor(current)}); err != nil {
		if current != nil {
			current.rollbackOnly.Store(true)
		}
		return core.StorageError(err)
	}
	return nil
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

// Transaction runs fn in a READ COMMITTED transaction that first takes the shared advisory lock; nested calls join.
func (s *Store) Transaction(ctx context.Context, fn core.TxFunc) error {
	return s.serialized(ctx, fn, s.shared.timeout)
}

type callbackFailure struct{ err error }

func (s *Store) serialized(ctx context.Context, fn core.TxFunc, lockTimeoutMs int) error {
	current, err := s.active(ctx)
	if err != nil {
		return err
	}
	if current != nil {
		return joined(ctx, current, fn)
	}
	pool := poolQuerier{pool: s.shared.pool, timeout: s.shared.timeout}
	conn, err := pool.acquire(ctx)
	if err != nil {
		return core.StorageError(err)
	}
	defer conn.Release()
	failure, err := s.run(ctx, conn, fn, lockTimeoutMs)
	if failure != nil {
		return failure.err
	}
	if err != nil {
		return core.StorageError(err)
	}
	return nil
}

// run is the transaction body; a callbackFailure is the application's own error, returned unchanged.
func (s *Store) run(ctx context.Context, conn *pgxpool.Conn, fn core.TxFunc, lockTimeoutMs int) (*callbackFailure, error) {
	if _, err := execOf(ctx, conn, "start transaction isolation level read committed"); err != nil {
		return nil, err
	}
	committed := false
	defer func() {
		if !committed {
			_, _ = execOf(context.WithoutCancel(ctx), conn, "rollback")
		}
	}()
	// All application transactions take the same database advisory lock before reading. READ COMMITTED takes its
	// data snapshot after this wait; SERIALIZABLE would pin a stale snapshot while waiting for the lock.
	if _, err := rowsOf(ctx, conn, "SELECT set_config('lock_timeout', $1, true)", strconv.Itoa(lockTimeoutMs)+"ms"); err != nil {
		return nil, err
	}
	if _, err := rowsOf(ctx, conn, "SELECT pg_advisory_xact_lock(1647206759, 1)"); err != nil {
		return nil, err
	}
	context := &txContext{conn: conn}
	context.active.Store(true)
	tx := newStore(s.shared, context)
	context.store = tx
	err := func() error {
		defer context.active.Store(false)
		err := fn(withScope(ctx, s.shared.scope, context), tx)
		if err == nil && context.rollbackOnly.Load() {
			err = core.NewIamError("TRANSACTION_ABORTED", "A nested database operation failed; transaction rolled back", 409)
		}
		return err
	}()
	if err != nil {
		return &callbackFailure{err}, nil
	}
	if _, err := execOf(ctx, conn, "commit"); err != nil {
		return nil, err
	}
	committed = true
	return nil, nil
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

// Migrate creates the schema and applies missing migrations (spec/storage/migrations/postgres). Index builds on a
// large table can take minutes; other instances migrating at the same time wait for the lock.
func (s *Store) Migrate(ctx context.Context) error {
	return s.migrate(ctx, core.MigrationOptions{Before: core.EncodeLegacyPostgresRows})
}

func (s *Store) migrate(ctx context.Context, options core.MigrationOptions) error {
	return s.serialized(ctx, func(ctx context.Context, tx core.IamStore) error {
		store := tx.(*Store)
		execute := func(ctx context.Context, text string, values ...any) ([]core.SqlRow, error) {
			return rowsOf(ctx, lockedQuerier{store.context}, text, values...)
		}
		if _, err := core.ApplyMigrations(ctx, execute, "postgres", options); err != nil {
			return core.StorageError(err)
		}
		return nil
	}, migrationLockTimeoutMs)
}

// Describe always runs on the pool, never on a caller's transaction: a probe of a table that does not exist yet
// would abort that transaction. Inside a transaction it therefore reports committed data and needs a free pool
// connection.
func (s *Store) Describe(ctx context.Context) (*core.StoreDescription, error) {
	if _, err := s.active(ctx); err != nil {
		return nil, err
	}
	pool := poolQuerier{pool: s.shared.pool, timeout: s.shared.timeout}
	execute := func(ctx context.Context, text string, values ...any) ([]core.SqlRow, error) {
		return rowsOf(ctx, pool, text, values...)
	}
	single := func(text string) (any, error) {
		rows, err := execute(ctx, text)
		if err != nil {
			if core.IsMissingTable(err) {
				return nil, nil
			}
			return nil, err
		}
		if len(rows) == 0 {
			return nil, nil
		}
		for _, value := range rows[0] {
			return value, nil
		}
		return nil, nil
	}
	size, err := single("SELECT pg_total_relation_size('iam_records') AS size")
	if err != nil {
		return nil, core.StorageError(err)
	}
	version, err := single("SHOW server_version")
	if err != nil {
		return nil, core.StorageError(err)
	}
	synchronousCommit, err := single("SHOW synchronous_commit")
	if err != nil {
		return nil, core.StorageError(err)
	}
	text := func(value any) any {
		if value == nil {
			return nil
		}
		if s, ok := value.(string); ok {
			return s
		}
		return core.MustStringify(core.Normalize(value))
	}
	var sizeBytes any
	if size != nil {
		sizeBytes = core.Normalize(size)
	}
	settings := core.NewObject("serverVersion", text(version), "synchronousCommit", text(synchronousCommit), "sizeBytes", sizeBytes, "lockTimeoutMs", s.shared.timeout)
	description, err := core.DescribeRecords(ctx, execute, "postgres", settings)
	if err != nil {
		return nil, core.StorageError(err)
	}
	return description, nil
}

// Close closes the pool; it is idempotent and refused inside a transaction.
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
	s.closed.Store(true)
	s.shared.pool.Close()
	return nil
}

// driver runs the TypeScript adapter's statements (the SQL Kysely generates for it, and core's PostgresSelect) and
// stores documents jsonb-compatible.
type driver struct{ q querier }

func storageRows(rows []core.SqlRow) ([]core.StorageRow, error) {
	out := make([]core.StorageRow, 0, len(rows))
	for _, row := range rows {
		data, _ := row["data"].(string)
		decoded, err := core.DecodeJSONBDocument(data)
		if err != nil {
			return nil, err
		}
		storage := core.StorageRow{Data: decoded}
		storage.Collection, _ = row["collection"].(string)
		storage.ID, _ = row["id"].(string)
		storage.TenantID, _ = row["tenant_id"].(string)
		if key, ok := row["unique_key"].(string); ok {
			storage.UniqueKey = &key
		}
		out = append(out, storage)
	}
	return out, nil
}

func (d *driver) Select(ctx context.Context, collection string, id, tenantID *string) ([]core.StorageRow, error) {
	text := `select * from "iam_records" where "collection" = $1`
	values := []any{collection}
	if id != nil {
		values = append(values, *id)
		text += ` and "id" = $` + strconv.Itoa(len(values))
	}
	if tenantID != nil {
		values = append(values, *tenantID)
		text += ` and "tenant_id" = $` + strconv.Itoa(len(values))
	}
	rows, err := rowsOf(ctx, d.q, text+` order by "id" asc`, values...)
	if err != nil {
		return nil, err
	}
	return storageRows(rows)
}

func nullable(value *string) any {
	if value == nil {
		return nil
	}
	return *value
}

func (d *driver) Insert(ctx context.Context, row core.StorageRow) error {
	data, err := core.EncodeJSONBDocument(row.Data)
	if err != nil {
		return err
	}
	_, err = execOf(ctx, d.q, `insert into "iam_records" ("collection", "id", "tenant_id", "unique_key", "data") values ($1, $2, $3, $4, $5)`,
		row.Collection, row.ID, row.TenantID, nullable(row.UniqueKey), data)
	return err
}

func (d *driver) Update(ctx context.Context, row core.StorageRow) (bool, error) {
	data, err := core.EncodeJSONBDocument(row.Data)
	if err != nil {
		return false, err
	}
	affected, err := execOf(ctx, d.q, `update "iam_records" set "data" = $1, "unique_key" = $2 where "collection" = $3 and "id" = $4 and "tenant_id" = $5`,
		data, nullable(row.UniqueKey), row.Collection, row.ID, row.TenantID)
	return affected == 1, err
}

func (d *driver) Delete(ctx context.Context, collection, id string) error {
	_, err := execOf(ctx, d.q, `delete from "iam_records" where "collection" = $1 and "id" = $2`, collection, id)
	return err
}

func (d *driver) QueryCapabilities() core.QueryCapabilities {
	return core.QueryCapabilities{JSON: true, Order: true}
}

func (d *driver) Query(ctx context.Context, query core.RecordQuery) ([]core.StorageRow, error) {
	statement, err := core.PostgresSelect(query)
	if err != nil {
		return nil, err
	}
	rows, err := rowsOf(ctx, d.q, statement.Text, statement.Values...)
	if err != nil {
		return nil, err
	}
	return storageRows(rows)
}

func (d *driver) Collections(ctx context.Context) ([]string, error) {
	rows, err := rowsOf(ctx, d.q, core.CollectionsSQL)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(rows))
	for _, row := range rows {
		name, _ := row["collection"].(string)
		names = append(names, name)
	}
	return names, nil
}
