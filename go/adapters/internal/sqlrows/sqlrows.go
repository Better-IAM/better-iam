// Package sqlrows runs statements on a database/sql connection and reads rows the way the adapters need them.
package sqlrows

import (
	"context"
	"database/sql"

	"github.com/Better-IAM/better-iam/go/core"
)

// Querier is a *sql.Conn, *sql.DB or *sql.Tx.
type Querier interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// Trace, when set (tests only), observes every statement an adapter sends.
type Trace func(text string, values []any)

// Rows runs a statement and returns every row keyed by column name. mapError wraps driver errors.
func Rows(ctx context.Context, q Querier, trace Trace, mapError func(error) error, text string, values ...any) ([]core.SqlRow, error) {
	if trace != nil {
		trace(text, values)
	}
	rows, err := q.QueryContext(ctx, text, values...)
	if err != nil {
		return nil, mapError(err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return nil, mapError(err)
	}
	var out []core.SqlRow
	for rows.Next() {
		cells := make([]any, len(columns))
		pointers := make([]any, len(columns))
		for index := range cells {
			pointers[index] = &cells[index]
		}
		if err := rows.Scan(pointers...); err != nil {
			return nil, mapError(err)
		}
		row := core.SqlRow{}
		for index, column := range columns {
			if bytes, ok := cells[index].([]byte); ok {
				row[column] = string(bytes)
			} else {
				row[column] = cells[index]
			}
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, mapError(err)
	}
	return out, nil
}

// Exec runs a statement and returns the number of rows it changed.
func Exec(ctx context.Context, q Querier, trace Trace, mapError func(error) error, text string, values ...any) (int64, error) {
	if trace != nil {
		trace(text, values)
	}
	result, err := q.ExecContext(ctx, text, values...)
	if err != nil {
		return 0, mapError(err)
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return 0, mapError(err)
	}
	return affected, nil
}

// StorageRows converts rows of (collection, id, tenant_id, unique_key, data) into StorageRows.
func StorageRows(rows []core.SqlRow) []core.StorageRow {
	out := make([]core.StorageRow, 0, len(rows))
	for _, row := range rows {
		storage := core.StorageRow{
			Collection: text(row["collection"]),
			ID:         text(row["id"]),
			TenantID:   text(row["tenant_id"]),
			Data:       text(row["data"]),
		}
		if key := row["unique_key"]; key != nil {
			value := text(key)
			storage.UniqueKey = &value
		}
		out = append(out, storage)
	}
	return out
}

func text(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	case nil:
		return ""
	}
	return core.MustStringify(core.Normalize(value))
}

// Text is String(value) for a cell.
func Text(value any) string { return text(value) }
