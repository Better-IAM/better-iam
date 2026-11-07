package libsql

import (
	"context"
	"testing"

	"github.com/Better-IAM/better-iam/go/adapters/internal/fleettest"
	"github.com/Better-IAM/better-iam/go/core"
)

// TestMixedFleet shares one database file with the TypeScript adapter (see
// scripts/conformance/fleet/go-fleet.mjs): TypeScript writes, Go reads and writes, TypeScript reads and writes,
// Go reads again; snapshots, data columns and audit chains must agree byte for byte. Needs BETTER_IAM_NODE (or node
// on PATH) able to load the built workspace and the libSQL client; skipped otherwise.
func TestMixedFleet(t *testing.T) {
	fleettest.Run(t, "libsql", func(path string) core.IamStore {
		store, err := New(Options{URL: "file:" + path})
		if err != nil {
			t.Fatal(err)
		}
		return store
	}, func(store core.IamStore, collection, id string) string {
		var data string
		row := store.(*Store).shared.conn.QueryRowContext(context.Background(), "SELECT data FROM iam_records WHERE collection = ? AND id = ?", collection, id)
		if err := row.Scan(&data); err != nil {
			t.Fatal(err)
		}
		return data
	})
}
