package cli

// Port of packages/cli/src/commands/storage.ts: snapshot commands, deployment operations straight on storage, like
// migrate (no credential).

import (
	"bufio"
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

var storageCommands = []*CommandSpec{
	DefineCommand(CommandSpec{
		Name:             "store-export",
		Group:            "Storage",
		Summary:          "Write every record of the database as a JSON Lines snapshot",
		Description:      "store-export writes every record of the database as a JSON Lines snapshot (one consistent transaction; the file holds credential hashes and encrypted secrets, so protect it like the database). It never overwrites a file.",
		Target:           "config",
		NoConfigDefaults: true,
		Flags: []FlagSpec{
			{Name: "output", Type: "string", Value: "PATH", Required: true, Description: "The snapshot file to create (mode 0600; it must not exist)"},
		},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			output := c.Path(c.Flags.String("output"))
			iam, err := c.Iam(ctx)
			if err != nil {
				return nil, err
			}
			file, err := os.OpenFile(output, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
			if err != nil {
				return nil, systemError(err)
			}
			summary, err := func() (core.SnapshotSummary, error) {
				var buffered strings.Builder
				summary, err := core.ExportStore(ctx, iam.Store, func(line string) error {
					buffered.WriteString(line)
					buffered.WriteByte('\n')
					if buffered.Len() >= 1<<20 {
						if _, err := file.WriteString(buffered.String()); err != nil {
							return err
						}
						buffered.Reset()
					}
					return nil
				}, core.SnapshotOptions{})
				if err != nil {
					return summary, err
				}
				if buffered.Len() > 0 {
					if _, err := file.WriteString(buffered.String()); err != nil {
						return summary, err
					}
				}
				if err := file.Sync(); err != nil {
					return summary, err
				}
				return summary, file.Close()
			}()
			if err != nil {
				_ = file.Close()
				_ = os.Remove(output)
				return nil, systemError(err)
			}
			return core.NewObject("output", output).Assign(summary.ToValue()), nil
		},
	}),
	DefineCommand(CommandSpec{
		Name:             "store-import",
		Group:            "Storage",
		Summary:          "Load a snapshot into an empty database",
		Description:      "store-import loads a snapshot into an empty database in one transaction; it migrates the target first and changes nothing on failure. Run migrate afterwards to apply plugin migrations.",
		Target:           "config",
		NoConfigDefaults: true,
		Flags: []FlagSpec{
			{Name: "input", Type: "string", Value: "PATH", Required: true, Description: "The snapshot to load"},
		},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			// Open the file before touching a database, so a wrong path changes nothing.
			inputPath := c.Path(c.Flags.String("input"))
			input, err := os.Open(inputPath)
			if err != nil {
				return nil, systemError(err)
			}
			defer input.Close()
			iam, err := c.Iam(ctx)
			if err != nil {
				return nil, err
			}
			// Schema only: Initialize would write records, and the target must stay empty until the import.
			if err := iam.Store.Migrate(ctx); err != nil {
				return nil, err
			}
			summary, err := core.ImportStoreFrom(ctx, iam.Store, readLines(input))
			if err != nil {
				return nil, err
			}
			return core.NewObject("input", inputPath).Assign(summary.ToValue()).Set("next", "Run migrate to apply plugin migrations."), nil
		},
	}),
	DefineCommand(CommandSpec{
		Name:             "store-copy",
		Group:            "Storage",
		Summary:          "Copy the database into the empty database of another configuration",
		Description:      "store-copy copies the configured database into the empty database of --target-config (for example SQLite to PostgreSQL); it migrates the target first and changes nothing on failure.",
		Target:           "config",
		NoConfigDefaults: true,
		Flags: []FlagSpec{
			{Name: "target-config", Type: "string", Value: "PATH", Required: true, Description: "Configuration of the empty target database"},
		},
		Examples: []string{"better-iam store-copy --config sqlite.json --target-config postgres.json"},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			targetPath := c.Path(c.Flags.String("target-config"))
			where, err := c.ConfigPath(ctx)
			if err != nil {
				return nil, err
			}
			if where != nil && where.Path == targetPath {
				return nil, UsageError("--target-config must name a different configuration")
			}
			source, err := c.Iam(ctx)
			if err != nil {
				return nil, err
			}
			target, err := c.Open(ctx, targetPath)
			if err != nil {
				return nil, err
			}
			if err := target.Store.Migrate(ctx); err != nil {
				return nil, err
			}
			summary, err := core.CopyStore(ctx, source.Store, target.Store, core.SnapshotOptions{})
			if err != nil {
				return nil, err
			}
			return core.NewObject("target", targetPath).Assign(summary.ToValue()).Set("next", "Run migrate with the target configuration."), nil
		},
	}),
}

// readLines yields the lines of a file without their line endings (\n or \r\n), like readline.
func readLines(file io.Reader) func(yield func(string, error) bool) {
	return func(yield func(string, error) bool) {
		reader := bufio.NewReaderSize(file, 1<<16)
		for {
			line, err := reader.ReadString('\n')
			if len(line) > 0 || err == nil {
				line = strings.TrimSuffix(strings.TrimSuffix(line, "\n"), "\r")
				if !yield(line, nil) {
					return
				}
			}
			if err != nil {
				if !errors.Is(err, io.EOF) {
					yield("", systemError(err))
				}
				return
			}
		}
	}
}
