// Package cli is the better-iam command line (port of packages/cli, @better-iam/cli): migrations, bootstrap,
// scheduled jobs, audit and storage operations, diagnostics, configuration as code, the API caller, saved sessions
// and shell completion, with the same commands, flags, help and exit codes as the TypeScript CLI. The
// github.com/Better-IAM/better-iam/go/cmd/better-iam command is the binary; this package lets a program run commands
// (RunCli), ship its own CLI with project commands (CreateCli, DefineCommand), or read the manifest (Manifest).
//
// The TypeScript CLI loads a JavaScript configuration module; the Go CLI reads better-iam.json, the standalone JSON
// configuration of spec/conformance/CONFIG.md (see config.go), and programs can supply configuration modules from Go
// code (CreateCliOptions.LoadModule).
package cli

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"regexp"
	"slices"
	"strings"
	"sync"

	iamversion "github.com/Better-IAM/better-iam/go"
	"github.com/Better-IAM/better-iam/go/client"
	"github.com/Better-IAM/better-iam/go/core"
)

// version is the release this CLI belongs to (package.json's version in TypeScript).
var version = iamversion.Version

// builtinCommands are every built-in command, in help order.
var builtinCommands = slices.Concat(
	setupCommands,
	operationCommands,
	billingCommands,
	auditCommands,
	storageCommands,
	accessCommands,
	sshCommands,
	vcCommands,
	complianceCommands,
	vaultCommands,
	apiCommands,
	sessionCommands,
	shellCommands,
)

// BuiltinCommands returns the built-in commands, in help order.
func BuiltinCommands() []*CommandSpec { return slices.Clone(builtinCommands) }

var (
	stdinMu     sync.Mutex
	stdinReader *bufio.Reader
)

// sharedStdin is one buffered reader over standard input for every prompt of a run.
func sharedStdin() *bufio.Reader {
	stdinMu.Lock()
	defer stdinMu.Unlock()
	if stdinReader == nil {
		stdinReader = bufio.NewReader(os.Stdin)
	}
	return stdinReader
}

// readAnswer reads one line of standard input (Enter or end of input finishes it); Ctrl+C cancels.
func readAnswer() (string, error) {
	type answer struct {
		text string
		err  error
	}
	done := make(chan answer, 1)
	go func() {
		line, err := sharedStdin().ReadString('\n')
		if errors.Is(err, io.EOF) {
			err = nil
		}
		done <- answer{strings.TrimRight(line, "\r\n"), err}
	}()
	interrupts := make(chan os.Signal, 1)
	signal.Notify(interrupts, os.Interrupt)
	defer signal.Stop(interrupts)
	select {
	case result := <-done:
		return result.text, result.err
	case <-interrupts:
		return "", NewCliError("CANCELLED", "Cancelled")
	}
}

func hiddenPrompt(question string) (string, error) {
	_, _ = os.Stderr.WriteString(question)
	restore, err := withoutEcho(os.Stdin.Fd())
	if err != nil {
		return "", err
	}
	answer, err := readAnswer()
	restore()
	_, _ = os.Stderr.WriteString("\n")
	return answer, err
}

func visiblePrompt(question string) (string, error) {
	_, _ = os.Stderr.WriteString(question)
	return readAnswer()
}

// ProcessIO is the process's own IO: stdout, stderr, the process environment, and prompts when both stdin and
// stderr are terminals.
func ProcessIO() *CliIO {
	cwd, _ := os.Getwd()
	processIO := &CliIO{
		Out: func(message string) { fmt.Fprintln(os.Stdout, message) },
		Err: func(message string) { fmt.Fprintln(os.Stderr, message) },
		Env: processEnv(),
		Cwd: cwd,
		Stdin: func() (string, error) {
			data, err := io.ReadAll(sharedStdin())
			return string(data), err
		},
	}
	if isTerminal(os.Stdin.Fd()) && isTerminal(os.Stderr.Fd()) {
		processIO.Prompt = func(question string, hidden bool) (string, error) {
			if hidden {
				return hiddenPrompt(question)
			}
			return visiblePrompt(question)
		}
	}
	return processIO
}

// CreateCli creates a better-iam-style program from code: the built-in commands plus your own (DefineCommand), with
// the same parsing, help, configuration loading, and output. Use it to ship a project CLI, or to run commands in
// tests.
func CreateCli(options CreateCliOptions) *Cli {
	var commands []*CommandSpec
	if !options.NoBuiltins {
		commands = slices.Clone(builtinCommands)
	}
	commands = append(commands, options.Commands...)
	cliVersion := options.Version
	if cliVersion == "" {
		cliVersion = version
	}
	return &Cli{Commands: commands, version: cliVersion, loader: options.LoadModule, defaultIO: ProcessIO}
}

var defaultCli = CreateCli(CreateCliOptions{})

// RunCli runs one better-iam command line (without the program name) and returns when it finishes; failures return
// an IamError (or CliError) whose code says what went wrong. A nil io uses the process's.
func RunCli(ctx context.Context, argv []string, io *CliIO) error {
	return defaultCli.Run(ctx, argv, io)
}

// Manifest is the machine-readable description of every built-in command (what `better-iam help --json` prints),
// for docs and tools (TypeScript: cliManifest).
func Manifest() CliManifest { return manifestOf(builtinCommands, version) }

var controlRun = regexp.MustCompile(`[\x00-\x1f\x7f-\x{9f}]+`)

// Main runs the CLI like the better-iam binary: it prints `CODE: message` (and a hint) on stderr on failure and
// returns the exit status, 0 on success, 2 for a usage mistake, 1 otherwise. For wrappers that ship their own binary;
// a nil cli is the default program.
func Main(argv []string, cli *Cli) int {
	if cli == nil {
		cli = defaultCli
	}
	err := cli.Run(context.Background(), argv, nil)
	if err == nil {
		return 0
	}
	code, hasCode := errorCode(err)
	// Messages can come from a remote server: control characters (terminal escapes) are dropped before printing.
	printable := func(text string) string { return controlRun.ReplaceAllString(text, " ") }
	message := printable(systemError(err).Error())
	// IAM errors (local or remote) and system errors (ENOENT, EEXIST) say what went wrong; anything else may carry
	// driver details such as connection strings, so it stays generic unless BETTER_IAM_DEBUG is set.
	var iamError *core.IamError
	var remote *client.IamClientError
	known := hasCode && (errors.As(err, &iamError) || errors.As(err, &remote) || systemCodePattern.MatchString(code))
	if known {
		fmt.Fprintln(os.Stderr, printable(code)+": "+message)
	} else {
		fmt.Fprintln(os.Stderr, "Better IAM command failed. Check configuration and database connectivity (set BETTER_IAM_DEBUG=1 for details).")
	}
	var cliError *CliError
	if errors.As(err, &cliError) && cliError.Hint != "" {
		fmt.Fprintln(os.Stderr, "Hint: "+cliError.Hint)
	}
	if os.Getenv("BETTER_IAM_DEBUG") != "" {
		fmt.Fprintf(os.Stderr, "%+v\n", err)
	}
	// A command run by vault-run failed: exit with its status, as the command itself would have.
	if cliError != nil && cliError.ExitStatus > 0 && cliError.ExitStatus < 256 {
		return cliError.ExitStatus
	}
	if hasCode && usageCodes[code] {
		return 2
	}
	return 1
}

// RunBinary is what the better-iam binary does: it runs Main on the process arguments and exits with its status.
// For packages that ship the CLI under their own binary; a nil cli is the default program.
func RunBinary(cli *Cli) {
	os.Exit(Main(os.Args[1:], cli))
}
