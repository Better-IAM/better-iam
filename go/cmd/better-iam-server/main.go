// Command better-iam-server is the standalone Go better-iam server, started from a JSON configuration
// (spec/conformance/CONFIG.md):
//
//	better-iam-server --config better-iam.json --port 4100 [--host 127.0.0.1] [--conformance]
//
// It builds the instance from the file, runs Initialize (migrations) and serves the HTTP surface. With --conformance
// it also answers the test-control endpoints under /__conformance/ (spec/conformance/CONTROL.md): ready, clock,
// outbox, events, script, reset, call, store and shutdown, puts both server clocks under control, and makes the
// `capture` delivery transport and scripted callbacks available. Never use --conformance in production.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Better-IAM/better-iam/go/adapters/libsql"
	"github.com/Better-IAM/better-iam/go/adapters/postgres"
	"github.com/Better-IAM/better-iam/go/adapters/sqlite"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

const usage = "Usage: better-iam-server --config <better-iam.json> --port <port> [--host 127.0.0.1] [--conformance]"

type arguments struct {
	config      string
	port        int
	host        string
	conformance bool
	help        bool
}

func parseArguments(argv []string) (arguments, error) {
	args := arguments{host: "127.0.0.1", port: -1}
	for index := 0; index < len(argv); index++ {
		arg := argv[index]
		value := func() (string, error) {
			index++
			if index >= len(argv) {
				return "", fmt.Errorf("%s needs a value", arg)
			}
			return argv[index], nil
		}
		var err error
		switch arg {
		case "--config":
			args.config, err = value()
		case "--port":
			var text string
			if text, err = value(); err == nil {
				port, convErr := strconv.Atoi(text)
				if convErr != nil {
					port = -1
				}
				args.port = port
			}
		case "--host":
			args.host, err = value()
		case "--conformance":
			args.conformance = true
		case "--help", "-h":
			args.help = true
		default:
			err = fmt.Errorf("Unknown argument %s", arg)
		}
		if err != nil {
			return args, err
		}
	}
	return args, nil
}

// clocks are the two server clocks (CONTROL.md "Clock"): the injected clock (authentication.now), frozen once set,
// and the wall clock (Date.now()), which keeps moving in real time from the value it was set to.
type clocks struct {
	mu         sync.Mutex
	frozen     *int64
	wallOffset int64
	wallSet    bool
}

func realNow() int64 { return time.Now().UnixMilli() }

func (c *clocks) wall() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return realNow() + c.wallOffset
}

func (c *clocks) now() int64 {
	c.mu.Lock()
	frozen := c.frozen
	c.mu.Unlock()
	if frozen != nil {
		return *frozen
	}
	return c.wall()
}

func (c *clocks) setWall(value int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	offset := value - realNow()
	if c.wallSet && c.wallOffset > offset {
		offset = c.wallOffset
	}
	c.wallOffset, c.wallSet = offset, true
}

func (c *clocks) setNow(value int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.frozen = &value
}

func (c *clocks) real() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.frozen, c.wallOffset, c.wallSet = nil, 0, false
}

// state is the conformance state: captured deliveries, events, script answers and calls.
type state struct {
	mu          sync.Mutex
	outbox      []any
	dispatching *[]any
	events      []any
	script      []*answer
	calls       []any
}

type answer struct {
	id       any
	callback string
	args     any
	result   any
	failure  any
	hasError bool
	async    bool
	used     bool
}

type instance struct {
	iam   *server.BetterIam
	store core.IamStore
}

type app struct {
	args       arguments
	configText []byte
	clock      *clocks
	state      *state
	resetting  sync.RWMutex
	current    *instance
	listener   net.Listener
	httpServer *http.Server
}

func main() {
	args, err := parseArguments(os.Args[1:])
	if err != nil {
		fmt.Fprintln(os.Stderr, err.Error()+"\n"+usage)
		os.Exit(2)
	}
	if args.help {
		fmt.Println(usage)
		return
	}
	if args.config == "" || args.port < 0 || args.port > 65535 {
		fmt.Fprintln(os.Stderr, usage)
		os.Exit(2)
	}
	text, err := os.ReadFile(args.config)
	if err != nil {
		fmt.Fprintln(os.Stderr, server.ConfigErrorLine(err))
		os.Exit(1)
	}
	application := &app{args: args, configText: text, clock: &clocks{}, state: &state{}}
	current, err := application.start(text, true)
	if err != nil {
		// One JSON line, so a conformance runner can compare why construction failed (CONTROL.md "Startup"), and for
		// the file `better-iam init` writes a hint line after it.
		fmt.Fprintln(os.Stderr, startupError(err))
		os.Exit(1)
	}
	application.current = current
	listener, err := net.Listen("tcp", net.JoinHostPort(args.host, strconv.Itoa(args.port)))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	application.listener = listener
	application.httpServer = &http.Server{Handler: application, ReadHeaderTimeout: 30 * time.Second}
	mode := ""
	if args.conformance {
		mode = " (conformance mode)"
	}
	fmt.Printf("better-iam (go) listening on http://%s:%d%s\n", args.host, listener.Addr().(*net.TCPAddr).Port, mode)
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-signals
		application.shutdown(0)
	}()
	if err := application.httpServer.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	select {}
}

// adapters open the databases a configuration names.
var adapters = server.ConfigAdapters{
	SQLite: func(store server.StoreConfig) (core.IamStore, error) {
		path := store.Path
		if path == "" {
			path = ":memory:"
		}
		return sqlite.New(sqlite.Options{Filename: path, BusyTimeoutMs: store.BusyTimeoutMs, JournalMode: store.JournalMode, Durability: store.Durability})
	},
	Postgres: func(store server.StoreConfig) (core.IamStore, error) {
		return postgres.New(postgres.Options{ConnectionString: store.URL, PoolSize: store.PoolSize, LockTimeoutMs: store.LockTimeoutMs})
	},
	LibSQL: func(store server.StoreConfig) (core.IamStore, error) {
		return libsql.New(libsql.Options{URL: store.URL, AuthToken: store.AuthToken, EncryptionKey: store.EncryptionKey, SyncURL: store.SyncURL, SyncInterval: store.SyncInterval})
	},
}

func (a *app) start(text []byte, initialize bool) (*instance, error) {
	runtime := server.ConfigRuntime{Adapters: adapters}
	if a.args.conformance {
		runtime.Now = a.clock.now
		runtime.Wall = a.clock.wall
		runtime.Deliver = a.deliver
		runtime.Scripted = a.scripted
	}
	options, err := server.LoadStandaloneConfig(text, runtime)
	if err != nil {
		return nil, err
	}
	iam, err := server.New(options)
	if err != nil {
		if options.Database != nil {
			_ = options.Database.Close(context.Background())
		}
		return nil, err
	}
	if initialize {
		if err := iam.Initialize(context.Background()); err != nil {
			iam.Close()
			_ = options.Database.Close(context.Background())
			return nil, err
		}
	}
	return &instance{iam: iam, store: options.Database}, nil
}

func (a *app) stop() {
	current := a.current
	a.current = nil
	if current == nil {
		return
	}
	// Buffered usage of a discarded instance does not matter.
	_, _ = current.iam.FlushAccessUsage(context.Background())
	current.iam.Close()
	_ = current.store.Close(context.Background())
}

func (a *app) shutdown(code int) {
	go func() {
		_ = a.httpServer.Close()
		a.resetting.Lock()
		a.stop()
		a.resetting.Unlock()
		os.Exit(code)
	}()
}

// deliver keeps `capture` deliveries (and events) for the control endpoints.
func (a *app) deliver(ctx context.Context, kind string, message any) error {
	encoded := encodeValue(message)
	a.state.mu.Lock()
	defer a.state.mu.Unlock()
	if kind == "events" {
		a.state.events = append(a.state.events, encoded)
		return nil
	}
	captured := core.NewObject("kind", kind)
	if object, ok := encoded.(*core.Object); ok {
		captured.Assign(object)
	}
	a.state.outbox = append(a.state.outbox, captured)
	if a.state.dispatching != nil {
		*a.state.dispatching = append(*a.state.dispatching, captured)
	}
	return nil
}

func (a *app) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pathname := r.URL.Path
	if a.args.conformance && strings.HasPrefix(pathname, "/__conformance/") {
		a.control(w, r, strings.TrimPrefix(pathname, "/__conformance/"))
		return
	}
	a.resetting.RLock()
	current := a.current
	a.resetting.RUnlock()
	if current == nil {
		http.Error(w, "server is resetting", http.StatusServiceUnavailable)
		return
	}
	current.iam.ServeHTTP(w, r)
}

func send(w http.ResponseWriter, status int, value any) {
	text, ok, err := core.Stringify(value)
	if err != nil || !ok {
		text = "null"
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, text)
}

type controlError struct{ err error }

func (a *app) control(w http.ResponseWriter, r *http.Request, path string) {
	var body any = core.Undefined
	if r.Method == http.MethodPost {
		data, err := io.ReadAll(r.Body)
		if err == nil && len(strings.TrimSpace(string(data))) > 0 {
			parsed, parseErr := core.ParseJSON(data)
			if parseErr != nil {
				send(w, 400, core.NewObject("error", errorShape(parseErr)))
				return
			}
			body = parsed
		}
	}
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		failure := core.NewIamError("METHOD_NOT_ALLOWED", "Use GET or POST", 405)
		send(w, 405, core.NewObject("error", errorShape(failure)))
		return
	}
	var result any
	var err error
	if path == "reset" {
		a.resetting.Lock()
		result, err = a.handle(path, body, true)
		a.resetting.Unlock()
	} else {
		a.resetting.RLock()
		result, err = a.handle(path, body, false)
		a.resetting.RUnlock()
	}
	if err != nil {
		shape := errorShape(err)
		status := int(core.Normalize(shape.Get("status")).(float64))
		send(w, status, core.NewObject("error", shape))
		return
	}
	send(w, 200, result)
}

func bodyMember(body any, key string) any {
	if object, ok := body.(*core.Object); ok && object != nil {
		return object.Get(key)
	}
	return core.Undefined
}

func (a *app) handle(path string, body any, exclusive bool) (any, error) {
	ctx := context.Background()
	current := a.current
	switch path {
	case "ready":
		return core.NewObject("ready", true, "implementation", "go", "conformance", 1.0), nil
	case "clock":
		if _, isObject := body.(*core.Object); isObject {
			for _, key := range []string{"set", "advance", "wall"} {
				if value := bodyMember(body, key); !core.IsUndefined(value) {
					if number, ok := value.(float64); !ok || number != number || number > 1e300 || number < -1e300 {
						return nil, core.NewIamError("INVALID_INPUT", key+" must be a number", 400)
					}
				}
			}
			if bodyMember(body, "real") == true {
				a.clock.real()
			}
			set, hasSet := bodyMember(body, "set").(float64)
			advance, hasAdvance := bodyMember(body, "advance").(float64)
			if hasSet {
				a.clock.setNow(int64(set))
			} else if hasAdvance {
				a.clock.setNow(a.clock.now() + int64(advance))
			}
			// Without its own value the wall clock moves with the injected clock.
			if wall, hasWall := bodyMember(body, "wall").(float64); hasWall {
				a.clock.setWall(int64(wall))
			} else if hasSet || hasAdvance {
				a.clock.setWall(a.clock.now())
			}
		}
		a.clock.mu.Lock()
		frozen := a.clock.frozen != nil
		a.clock.mu.Unlock()
		return core.NewObject("now", float64(a.clock.now()), "wall", float64(a.clock.wall()), "frozen", frozen), nil
	case "outbox":
		a.state.mu.Lock()
		defer a.state.mu.Unlock()
		return core.NewObject("messages", append([]any{}, a.state.outbox...)), nil
	case "outbox/clear":
		a.state.mu.Lock()
		defer a.state.mu.Unlock()
		cleared := len(a.state.outbox)
		a.state.outbox = nil
		return core.NewObject("cleared", float64(cleared)), nil
	case "events":
		a.state.mu.Lock()
		defer a.state.mu.Unlock()
		return core.NewObject("events", append([]any{}, a.state.events...)), nil
	case "events/clear":
		a.state.mu.Lock()
		defer a.state.mu.Unlock()
		cleared := len(a.state.events)
		a.state.events = nil
		return core.NewObject("cleared", float64(cleared)), nil
	case "outbox/dispatch":
		a.state.mu.Lock()
		if a.state.dispatching != nil {
			a.state.mu.Unlock()
			return nil, core.NewIamError("CONFLICT", "A dispatch is already running", 409)
		}
		messages := []any{}
		a.state.dispatching = &messages
		a.state.mu.Unlock()
		limit := 0
		if value, ok := bodyMember(body, "limit").(float64); ok {
			limit = int(value)
		}
		result, err := current.iam.Auth.DispatchOutbox(ctx, limit)
		a.state.mu.Lock()
		captured := *a.state.dispatching
		a.state.dispatching = nil
		a.state.mu.Unlock()
		if err != nil {
			return core.NewObject("error", errorShape(err), "messages", captured), nil
		}
		return core.NewObject("result", encodeValue(result), "messages", captured), nil
	case "script":
		return a.scriptControl(body)
	case "reset":
		a.stop()
		a.state.mu.Lock()
		a.state.outbox, a.state.events, a.state.script, a.state.calls = nil, nil, nil, nil
		a.state.mu.Unlock()
		a.clock.real()
		if config := bodyMember(body, "config"); !core.IsUndefined(config) {
			a.configText = []byte(core.MustStringify(config))
		}
		next, err := a.start(a.configText, bodyMember(body, "initialize") != false)
		if err != nil {
			return nil, err
		}
		a.current = next
		return core.NewObject("reset", true), nil
	case "call":
		method := bodyMember(body, "method")
		fn, err := resolveMethod(current.iam, method)
		if err != nil {
			return nil, err
		}
		args, _ := decodeValue(bodyMember(body, "args")).([]any)
		result, callErr := invokeMember(ctx, fn, method, args, nil)
		if callErr != nil {
			return core.NewObject("error", errorShape(callErr)), nil
		}
		return core.NewObject("data", encodeValue(result)), nil
	case "store":
		return a.storeControl(ctx, current, body)
	case "shutdown":
		go func() {
			time.Sleep(20 * time.Millisecond)
			a.shutdown(0)
		}()
		return core.NewObject("shutdown", true), nil
	}
	return nil, core.NewIamError("NOT_FOUND", "Unknown control endpoint", 404)
}

// cliMemberRefusal is the refusal of a configuration that has the better-iam CLI's "cli" member (TypeScript's
// message, unchanged).
const cliMemberRefusal = `Invalid better-iam.json: unknown member "cli"`

// cliMemberHint follows the error line when the configuration has the "cli" member: the Go CLI keeps its flag
// defaults there (better-iam init writes it), and no standalone server reads it, the TypeScript one included.
const cliMemberHint = `better-iam-server: "cli" holds the better-iam CLI's flag defaults (better-iam init writes it); ` +
	`the standalone server does not read it, so give better-iam-server a copy of the file without "cli".`

// startupError is what the server writes to stderr when it cannot start: the error line (ConfigErrorLine), plus
// cliMemberHint on a second line for the "cli" member's refusal.
func startupError(err error) string {
	line := server.ConfigErrorLine(err)
	var known *core.IamError
	if errors.As(err, &known) && known.Code == "INVALID_CONFIG" && known.Message == cliMemberRefusal {
		return line + "\n" + cliMemberHint
	}
	return line
}
