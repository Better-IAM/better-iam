package cli

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/text/collate"
	"golang.org/x/text/language"
)

var (
	collatorMu sync.Mutex
	collator   = collate.New(language.Und)
)

// localeCompare is String.prototype.localeCompare without locales (ICU root collation).
func localeCompare(a, b string) int {
	collatorMu.Lock()
	defer collatorMu.Unlock()
	return collator.CompareString(a, b)
}

// resolvePath is path.resolve(cwd, value): an absolute, cleaned path.
func resolvePath(cwd, value string) string {
	if filepath.IsAbs(value) {
		return filepath.Clean(value)
	}
	if cwd == "" {
		cwd, _ = os.Getwd()
	}
	if !filepath.IsAbs(cwd) {
		if absolute, err := filepath.Abs(cwd); err == nil {
			cwd = absolute
		}
	}
	return filepath.Join(cwd, value)
}

// processEnv is process.env as a map.
func processEnv() map[string]string {
	env := map[string]string{}
	for _, entry := range os.Environ() {
		if name, value, ok := strings.Cut(entry, "="); ok && name != "" {
			env[name] = value
		}
	}
	return env
}

// nowMillis is Date.now().
func nowMillis() float64 { return float64(time.Now().UnixMilli()) }

// isoString is Date.prototype.toISOString of epoch milliseconds.
func isoString(ms float64) string {
	return time.UnixMilli(int64(ms)).UTC().Format("2006-01-02T15:04:05.000Z")
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
