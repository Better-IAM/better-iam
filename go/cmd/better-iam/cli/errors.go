package cli

// Port of packages/cli/src/errors.ts.

import (
	"errors"
	"io/fs"
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/Better-IAM/better-iam/go/client"
	"github.com/Better-IAM/better-iam/go/core"
)

// CliError is a command-line failure: an IamError (same Code contract; errors.As finds the *core.IamError) that may
// carry a hint, printed on its own line by the better-iam binary, telling the person what to run or set next.
type CliError struct {
	*core.IamError
	// Hint is one sentence saying what to do next, such as the command or flag that fixes the problem.
	Hint string
	// ExitStatus is set when a command run by vault-run failed: the binary exits with it, as the command would have.
	ExitStatus int
}

// NewCliError builds a CliError (status 400, like the IamError constructor).
func NewCliError(code, message string, hint ...string) *CliError {
	e := &CliError{IamError: core.NewIamError(code, message)}
	if len(hint) > 0 {
		e.Hint = hint[0]
	}
	return e
}

func (e *CliError) Error() string { return e.Message }

// Unwrap exposes the IamError, so errors.As(err, &iamError) matches a CliError.
func (e *CliError) Unwrap() error { return e.IamError }

// Name is the JavaScript error name ("CliError").
func (e *CliError) Name() string { return "CliError" }

// UsageError is a usage mistake (unknown flag, missing value, bad number): the binary exits with status 2 for these.
func UsageError(message string, hint ...string) *CliError {
	return NewCliError("INVALID_ARGUMENT", message, hint...)
}

// usageCodes are codes that mean the command line itself was wrong, so the binary exits 2 (like most Unix tools).
var usageCodes = map[string]bool{"INVALID_ARGUMENT": true, "INVALID_COMMAND": true}

// SystemError is a file-system failure in the form Node.js reports it (code ENOENT, EEXIST, ...), so the binary
// prints it like the TypeScript CLI does.
type SystemError struct {
	Code    string
	Message string
	Err     error
}

func (e *SystemError) Error() string { return e.Message }
func (e *SystemError) Unwrap() error { return e.Err }

var errnoNames = map[string]string{
	"ENOENT": "no such file or directory", "EEXIST": "file already exists", "EACCES": "permission denied",
	"EISDIR": "illegal operation on a directory", "ENOTDIR": "not a directory", "ENOTEMPTY": "directory not empty",
	"EPERM": "operation not permitted",
}

// systemError turns a Go file-system error into the Node.js form (`ENOENT: no such file or directory, open 'x'`);
// other errors are returned unchanged.
func systemError(err error) error {
	if err == nil {
		return nil
	}
	var already *SystemError
	if errors.As(err, &already) {
		return err
	}
	var path *fs.PathError
	if !errors.As(err, &path) {
		return err
	}
	code := ""
	switch {
	case errors.Is(err, fs.ErrNotExist):
		code = "ENOENT"
	case errors.Is(err, fs.ErrExist):
		code = "EEXIST"
	case errors.Is(err, fs.ErrPermission):
		code = "EACCES"
	case errors.Is(err, syscall.EISDIR):
		code = "EISDIR"
	case errors.Is(err, syscall.ENOTDIR):
		code = "ENOTDIR"
	case errors.Is(err, syscall.ENOTEMPTY):
		code = "ENOTEMPTY"
	default:
		return err
	}
	return &SystemError{Code: code, Message: code + ": " + errnoNames[code] + ", " + path.Op + " '" + path.Path + "'", Err: err}
}

// errorCode is the code of an IamError, a CliError, an IamClientError from a remote call, or a system error.
func errorCode(err error) (string, bool) {
	if err == nil {
		return "", false
	}
	var system *SystemError
	if errors.As(err, &system) {
		return system.Code, true
	}
	var remote *client.IamClientError
	if errors.As(err, &remote) {
		return remote.Code, true
	}
	var known *core.IamError
	if errors.As(err, &known) {
		return known.Code, true
	}
	converted := systemError(err)
	if errors.As(converted, &system) {
		return system.Code, true
	}
	return "", false
}

// distance is the Levenshtein distance, for "did you mean" suggestions on commands and flags (UTF-16 units, as in
// JavaScript).
func distance(a, b string) int {
	left, right := core.ToUTF16(a), core.ToUTF16(b)
	row := make([]int, len(right)+1)
	for index := range row {
		row[index] = index
	}
	for i := 1; i <= len(left); i++ {
		previous := row[0]
		row[0] = i
		for j := 1; j <= len(right); j++ {
			current := row[j]
			cost := 1
			if left[i-1] == right[j-1] {
				cost = 0
			}
			row[j] = min(row[j]+1, row[j-1]+1, previous+cost)
			previous = current
		}
	}
	return row[len(right)]
}

// suggest returns the closest candidates to a mistyped name: prefix matches first, then anything within two edits.
func suggest(input string, candidates []string, limit int) []string {
	needle := core.JSLower(input)
	type scoredName struct {
		name  string
		score int
	}
	var scored []scoredName
	seen := map[string]bool{}
	for _, name := range candidates {
		if seen[name] {
			continue
		}
		seen[name] = true
		lower := core.JSLower(name)
		if lower == needle {
			continue
		}
		score := 0
		if !strings.HasPrefix(lower, needle) && !strings.HasPrefix(needle, lower) {
			score = distance(needle, lower)
		}
		if score <= max(2, core.UTF16Len(needle)/4) {
			scored = append(scored, scoredName{name, score})
		}
	}
	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].score != scored[j].score {
			return scored[i].score < scored[j].score
		}
		return localeCompare(scored[i].name, scored[j].name) < 0
	})
	if len(scored) > limit {
		scored = scored[:limit]
	}
	names := make([]string, len(scored))
	for index, entry := range scored {
		names[index] = entry.name
	}
	return names
}

// didYouMean is " Did you mean X or Y?" or an empty string.
func didYouMean(input string, candidates []string, prefix string) string {
	matches := suggest(input, candidates, 3)
	if len(matches) == 0 {
		return ""
	}
	for index := range matches {
		matches[index] = prefix + matches[index]
	}
	if len(matches) == 1 {
		return " Did you mean " + matches[0] + "?"
	}
	return " Did you mean " + strings.Join(matches[:len(matches)-1], ", ") + " or " + matches[len(matches)-1] + "?"
}

var systemCodePattern = regexp.MustCompile(`^(E[A-Z]+|ERR_[A-Z_]+)$`)
