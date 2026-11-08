package cli

// Port of packages/cli/src/commands/api.ts.

import (
	"context"
	"os"
	"regexp"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

func isRecord(value any) bool {
	object, ok := value.(*core.Object)
	return ok && object != nil
}

// assign sets a.b.c (and list[] to append) on an object, refusing prototype keys.
func assign(target *core.Object, key string, value any) error {
	parts := strings.Split(key, ".")
	for _, part := range parts {
		if part == "" || unsafeKeys[strings.TrimSuffix(part, "[]")] {
			return UsageError(key + " is not a usable field name")
		}
	}
	current := target
	for index, raw := range parts {
		appendTo := strings.HasSuffix(raw, "[]")
		part := strings.TrimSuffix(raw, "[]")
		if index == len(parts)-1 {
			if appendTo {
				existing := current.Get(part)
				var list []any
				if !core.IsUndefined(existing) {
					items, ok := existing.([]any)
					if !ok {
						return UsageError(part + " is already set to a non-list value")
					}
					list = append(list, items...)
				}
				current.Set(part, append(list, value))
			} else {
				current.Set(part, value)
			}
			return nil
		}
		if appendTo {
			return UsageError(key + ": [] may only end a field name")
		}
		next := current.Get(part)
		if core.IsUndefined(next) {
			current.Set(part, core.NewObject())
		} else if !isRecord(next) {
			return UsageError(part + " is already set to a non-object value")
		}
		current = current.Get(part).(*core.Object)
	}
	return nil
}

func readJSON(text, source string) (any, error) {
	parsed, err := core.ParseJSONString(text)
	if err != nil {
		return nil, UsageError(source + " is not valid JSON")
	}
	return parsed, nil
}

// withoutUnsafeKeys drops __proto__, constructor and prototype members at any depth (the JSON.parse reviver).
func withoutUnsafeKeys(value any) any {
	switch typed := value.(type) {
	case *core.Object:
		out := core.NewObject()
		for _, key := range typed.Keys() {
			if !unsafeKeys[key] {
				out.Set(key, withoutUnsafeKeys(typed.Get(key)))
			}
		}
		return out
	case []any:
		out := make([]any, len(typed))
		for index, item := range typed {
			out[index] = withoutUnsafeKeys(item)
		}
		return out
	}
	return value
}

var bodyItem = regexp.MustCompile(`(?s)^([^=:]+)(:=|=)(.*)$`)

func readText(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", systemError(err)
	}
	return string(data), nil
}

// RequestBody builds the request body from --data (JSON, @file.json, or - for stdin) and key=value items, like
// HTTPie: name=Admin (string), limit:=10 / actions:='["a"]' (JSON), document:=@policy.json (JSON file),
// content=@terms.md (file text), resource.type=project (nested), actions[]=a (append). A value that must start with
// @ without reading a file is escaped as key=\@text; scripts passing values they do not control should always escape
// a leading @. resolve maps relative file names to paths.
func RequestBody(io *CliIO, resolve func(string) string, data *string, items []string) (*core.Object, error) {
	body := core.NewObject()
	if data != nil {
		var parsed any
		var err error
		switch {
		case *data == "-":
			if io.Stdin == nil {
				return nil, UsageError("--data - needs standard input")
			}
			text, readErr := io.Stdin()
			if readErr != nil {
				return nil, readErr
			}
			parsed, err = readJSON(text, "Standard input")
		case strings.HasPrefix(*data, "@"):
			text, readErr := readText(resolve((*data)[1:]))
			if readErr != nil {
				return nil, readErr
			}
			parsed, err = readJSON(text, (*data)[1:])
		default:
			parsed, err = readJSON(*data, "--data")
		}
		if err != nil {
			return nil, err
		}
		if !isRecord(parsed) {
			return nil, UsageError("--data must be a JSON object")
		}
		body = withoutUnsafeKeys(parsed).(*core.Object)
	}
	for _, item := range items {
		match := bodyItem.FindStringSubmatch(item)
		if match == nil {
			return nil, UsageError(item+" is not key=value or key:=json", "Quote values with spaces; see better-iam help api.")
		}
		key, operator, raw := match[1], match[2], match[3]
		var value any
		if operator == ":=" {
			text := raw
			source := key + ":="
			if strings.HasPrefix(raw, "@") {
				var err error
				if text, err = readText(resolve(raw[1:])); err != nil {
					return nil, err
				}
				source = raw[1:]
			}
			parsed, err := readJSON(text, source)
			if err != nil {
				return nil, err
			}
			value = parsed
		} else {
			switch {
			case strings.HasPrefix(raw, `\@`):
				// key=\@text sends the literal "@text" (as in httpie), for values that must never read a file.
				value = raw[1:]
			case strings.HasPrefix(raw, "@") && len(raw) > 1:
				text, err := readText(resolve(raw[1:]))
				if err != nil {
					return nil, err
				}
				value = text
			default:
				value = raw
			}
		}
		if err := assign(body, core.JSTrim(key), value); err != nil {
			return nil, err
		}
	}
	converted, _ := jsonValue(body).(*core.Object)
	if converted == nil {
		converted = core.NewObject()
	}
	return converted, nil
}

var groupSuffix = regexp.MustCompile(`[./].*$`)

var apiCommands = []*CommandSpec{
	DefineCommand(CommandSpec{
		Name:        "api",
		Group:       "API",
		Summary:     "Call any IAM API method as the current token",
		Description: `api calls any method of the HTTP API (the same routes and permission checks as POST {basePath}/{group}/{method}) as BETTER_IAM_TOKEN or the session saved by login, in process through the configuration or against --url, and prints the result. Build the input with --data (JSON, @file.json, or - for standard input) and key=value items: name=Admin sets a string, limit:=10 or actions:='["a","b"]' sets JSON, document:=@policy.json reads a JSON file, content=@terms.md reads a text file, resource.type=project nests, and actions[]=a appends. --tenant (or BETTER_IAM_TENANT, or the saved profile) fills tenantId when the input has none. api --list [GROUP] lists every route with whether it needs a credential.`,
		Usage:       "better-iam api GROUP.METHOD [key=value ...] [--data JSON|@FILE|-] [--tenant TENANT_ID] [--list] [--url URL] [--profile NAME]",
		Target:      "token",
		Args: []ArgSpec{
			{Name: "route", Description: "group.method (roles.create, auth.getSession) or authorize"},
			{Name: "fields", Description: `key=value, key:=json, key:=@file.json, key=@file.txt (key=\@text sends a literal @text)`, Variadic: true},
		},
		Flags: []FlagSpec{
			{Name: "data", Type: "string", Value: "JSON|@FILE|-", Description: "Request body as JSON, a JSON file, or standard input"},
			{Name: "tenant", Type: "string", Value: "TENANT_ID", Env: "BETTER_IAM_TENANT", Profile: "tenantId", Description: "tenantId for inputs that do not set one"},
			{Name: "list", Type: "boolean", Description: "List routes (optionally of one group) instead of calling one"},
		},
		Examples: []string{
			"better-iam api --list roles",
			`better-iam api roles.create name=Reader permissions:='["documents:read"]'`,
			"better-iam api policies.create name=Deny-deletes document:=@deny.json --tenant ten_123",
			`better-iam api identities.list limit:=5 --query "[].email"`,
			`echo '{"slug":"acme"}' | better-iam api tenants.lookup --data -`,
		},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			route := ""
			var items []string
			if len(c.Args) > 0 {
				route, items = c.Args[0], c.Args[1:]
			}
			if c.Flags.Bool("list") || route == "" {
				if len(items) > 0 {
					return nil, UsageError("api --list takes at most a group name")
				}
				// The instance whose routes api --list shows: the configuration's (for its base path); the route table is
				// the same for every deployment of this version. Plugin endpoints are not listed; call them as
				// plugins/{pluginId}/{path}.
				basePath := "/api/iam"
				where, err := c.ConfigPath(ctx)
				if err != nil {
					return nil, err
				}
				if !c.Flags.Has("url") && (where != nil || c.Env["BETTER_IAM_DATABASE_URL"] != "") {
					iam, err := c.Iam(ctx)
					if err != nil {
						return nil, err
					}
					basePath = iam.Endpoint.BasePath
				} else if c.Flags.Has("url") {
					parsed, err := parseEndpoint(c.Flags.String("url"))
					if err != nil {
						return nil, err
					}
					basePath = parsed.basePath
				}
				group := groupSuffix.ReplaceAllString(route, "")
				rows := []any{}
				for _, entry := range ListRoutes() {
					if group != "" && strings.SplitN(entry.Route, "/", 2)[0] != group {
						continue
					}
					rows = append(rows, core.NewObject("method", strings.Replace(entry.Route, "/", ".", 1), "access", entry.Access,
						"http", "POST "+basePath+"/"+entry.Route))
				}
				if group != "" && len(rows) == 0 {
					return nil, NewCliError("NOT_FOUND", "No API group named "+group, "Run better-iam api --list for all groups.")
				}
				// A table by default: this is for reading; --format json gives tools the same rows.
				format := c.Flags.String("format")
				if format == "" {
					format = "table"
				}
				text, err := FormatResult(rows, format, c.Flags.String("query"), c.Flags.Has("query"))
				if err != nil {
					return nil, err
				}
				c.IO.Out(text)
				return nil, nil
			}
			path, err := routePath(route)
			if err != nil {
				return nil, err
			}
			var data *string
			if c.Flags.Has("data") {
				value := c.Flags.String("data")
				data = &value
			}
			body, err := RequestBody(c.IO, c.Path, data, items)
			if err != nil {
				return nil, err
			}
			if tenant := c.Flags.String("tenant"); tenant != "" && core.IsUndefined(body.Get("tenantId")) {
				body.Set("tenantId", tenant)
			}
			// MFA enrollment is public for a sign-in challenge but uses the caller's own session without one.
			nested, _ := body.Get("credential").(*core.Object)
			_, challenge := body.Get("challenge").(string)
			nestedChallenge := false
			if nested != nil {
				_, nestedChallenge = nested.Get("challenge").(string)
			}
			ownSession := (path == "auth/beginMfa" && !challenge) || (path == "auth/confirmMfa" && !nestedChallenge)
			transport, err := c.Api(ctx, ApiOptions{Anonymous: !(ownSession || !isPublicRoute(path))})
			if err != nil {
				return nil, err
			}
			answer, err := transport.Call(ctx, path, body)
			if err != nil {
				return nil, err
			}
			if answer == nil {
				// null is printed, as the TypeScript CLI prints a null result.
				return Null, nil
			}
			return answer, nil
		},
	}),
}
