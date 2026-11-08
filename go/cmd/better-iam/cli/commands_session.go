package cli

// Port of packages/cli/src/commands/session.ts.

import (
	"context"
	"regexp"
	"slices"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

var questionSuffix = regexp.MustCompile(`[:?]\s*$`)

func ask(c *CommandContext, question string, hidden bool, missing string) (string, error) {
	if c.IO.Prompt == nil {
		return "", NewCliError("MISSING_ENV", missing, "Run it in a terminal, or set the variable.")
	}
	answer, err := c.IO.Prompt(question, hidden)
	if err != nil {
		return "", err
	}
	answer = core.JSTrim(answer)
	if answer == "" {
		return "", UsageError(questionSuffix.ReplaceAllString(question, "") + " is required")
	}
	return answer, nil
}

// profileTransport is the deployment a saved profile belongs to, as a transport carrying its token (never any
// other deployment).
func profileTransport(ctx context.Context, c *CommandContext, profile *StoredProfile) (ApiTransport, error) {
	switch {
	case profile.URL != "":
		return RemoteTransport(profile.URL, profile.Token, c.IO.Fetch)
	case profile.Config != "":
		iam, err := c.Open(ctx, profile.Config)
		if err != nil {
			return nil, err
		}
		return LocalTransport(iam, profile.Config, profile.Token), nil
	case profile.EnvConfig:
		iam, err := c.OpenEnv(ctx)
		if err != nil {
			return nil, err
		}
		return LocalTransport(iam, "BETTER_IAM_DATABASE_URL", profile.Token), nil
	}
	return nil, nil
}

// profileTarget is where a command's calls go, in the form a profile records it.
type profileTarget struct {
	url       string
	config    string
	envConfig bool
}

func (t profileTarget) model() *core.Object {
	switch {
	case t.url != "":
		return core.NewObject("url", t.url)
	case t.config != "":
		return core.NewObject("config", t.config)
	}
	return core.NewObject("envConfig", true)
}

func targetOf(ctx context.Context, c *CommandContext, transport ApiTransport) (profileTarget, error) {
	if transport.Mode() == "remote" {
		return profileTarget{url: transport.Target()}, nil
	}
	where, err := c.ConfigPath(ctx)
	if err != nil {
		return profileTarget{}, err
	}
	if where != nil {
		return profileTarget{config: where.Path}, nil
	}
	return profileTarget{envConfig: true}, nil
}

func sameTarget(profile *StoredProfile, target profileTarget) bool {
	if target.url != "" {
		return profile.URL != "" && sameEndpoint(profile.URL, target.url)
	}
	if target.config != "" {
		return profile.Config == target.config
	}
	return profile.EnvConfig && profile.URL == "" && profile.Config == ""
}

func stringAt(value any, key string) (string, bool) {
	text, ok := pathOf(value, key).(string)
	return text, ok
}

var sessionCommands = []*CommandSpec{
	DefineCommand(CommandSpec{
		Name:        "login",
		Group:       "Session",
		Summary:     "Sign in once and save the session for later commands",
		Description: `login signs in with an email and password (and an authenticator or emailed code when MFA is required) and saves the session in the credentials file as a profile (--profile, default the current profile or "default"; a profile that holds a session for another deployment is only replaced when named with --profile), so later token commands need no BETTER_IAM_TOKEN. The password comes from BETTER_IAM_PASSWORD or a hidden prompt and the code from BETTER_IAM_MFA_CODE or a prompt, never from flags. --with-token saves a token read from standard input instead (an API key for CI, or a session from elsewhere) after checking it. The profile remembers the server (--url) or configuration it was created with, and --tenant/--org sets the default tenant of later commands.`,
		Usage:       "better-iam login [--config better-iam.json | --url URL] [--tenant TENANT_ID | --org SLUG] [--email EMAIL] [--email-code] [--with-token] [--profile NAME]",
		Target:      "token",
		Flags: []FlagSpec{
			{Name: "tenant", Type: "string", Value: "TENANT_ID", Env: "BETTER_IAM_TENANT", Description: "Organization to sign in to"},
			{Name: "org", Type: "string", Value: "SLUG", Description: "Organization to sign in to, by its slug"},
			{Name: "email", Type: "string", Value: "EMAIL", Env: "BETTER_IAM_EMAIL", Description: "Account email (prompted when absent)"},
			{Name: "email-code", Type: "boolean", Description: "Email a one-time code for MFA instead of using an authenticator"},
			{Name: "with-token", Type: "boolean", Description: "Save a token read from standard input instead of signing in"},
		},
		Examples: []string{
			"better-iam login --url https://iam.example.com --org acme --email me@acme.test",
			`echo "$API_KEY" | better-iam login --with-token --url https://iam.example.com --profile ci`,
		},
		// Only flags typed on the command line conflict; BETTER_IAM_TENANT / BETTER_IAM_EMAIL are defaults that yield.
		Validate: func(flags Flags, args []string, explicit map[string]bool) error {
			if explicit["tenant"] && explicit["org"] {
				return UsageError("Give --tenant or --org, not both")
			}
			if explicit["with-token"] && slices.ContainsFunc([]string{"tenant", "org", "email", "email-code"}, func(name string) bool { return explicit[name] }) {
				return UsageError("--with-token takes no sign-in flags (the token names its tenant)")
			}
			return nil
		},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			anonymous, err := c.Api(ctx, ApiOptions{Anonymous: true})
			if err != nil {
				return nil, err
			}
			// Refuse before signing in, so a new session never silently replaces one saved for another deployment.
			where, err := targetOf(ctx, c, anonymous)
			if err != nil {
				return nil, err
			}
			name, err := c.Profiles.CurrentName(c.Flags.String("profile"))
			if err != nil {
				return nil, err
			}
			existing, err := c.Profiles.Get(name)
			if err != nil {
				return nil, err
			}
			if existing != nil && c.Flags.String("profile") == "" && !sameTarget(existing, where) {
				return nil, NewCliError("PROFILE_IN_USE", "Profile "+name+" holds a session for "+DescribeProfileTarget(existing),
					"Pass --profile NAME to save this session under another name, or run better-iam logout first.")
			}
			var token, signedInEmail string
			if c.Flags.Bool("with-token") {
				if c.IO.Stdin == nil {
					return nil, UsageError("--with-token reads the token from standard input")
				}
				text, err := c.IO.Stdin()
				if err != nil {
					return nil, err
				}
				token = core.JSTrim(text)
				if token == "" {
					return nil, UsageError("Standard input held no token")
				}
			} else {
				// --org is always typed on the command line, so it wins over a BETTER_IAM_TENANT default.
				tenantID := ""
				if c.Flags.String("org") == "" {
					tenantID = c.Flags.String("tenant")
				}
				if tenantID == "" {
					slug := c.Flags.String("org")
					if slug == "" {
						if slug, err = ask(c, "Organization (slug): ", false, "Pass --tenant ID or --org SLUG"); err != nil {
							return nil, err
						}
					}
					found, err := anonymous.Call(ctx, "tenants/lookup", core.NewObject("slug", slug))
					if err != nil {
						return nil, err
					}
					tenantID, _ = stringAt(found, "tenantId")
				}
				email := c.Flags.String("email")
				if email == "" {
					if email, err = ask(c, "Email: ", false, "Pass --email or set BETTER_IAM_EMAIL"); err != nil {
						return nil, err
					}
				}
				signedInEmail = email
				password := c.Env["BETTER_IAM_PASSWORD"]
				if password == "" {
					if password, err = ask(c, "Password: ", true, "Set BETTER_IAM_PASSWORD (passwords are never flags)"); err != nil {
						return nil, err
					}
				}
				signedIn, err := anonymous.Call(ctx, "auth/signIn", core.NewObject("tenantId", tenantID, "email", email, "password", password))
				if err != nil {
					return nil, err
				}
				if pathOf(signedIn, "mfaRequired") == true {
					challenge, _ := stringAt(signedIn, "challenge")
					emailCode := c.Flags.Bool("email-code")
					if emailCode {
						if pathOf(signedIn, "emailCodeAvailable") != true {
							return nil, NewCliError("MFA_EMAIL_UNAVAILABLE", "This organization does not offer emailed codes")
						}
						if _, err := anonymous.Call(ctx, "auth/requestMfaCode", core.NewObject("tenantId", tenantID, "challenge", challenge)); err != nil {
							return nil, err
						}
						c.Note("A one-time code was sent to " + email + ".")
					} else if pathOf(signedIn, "enrollmentRequired") == true {
						hint := "Enroll one in the console first."
						if pathOf(signedIn, "emailCodeAvailable") == true {
							hint = "Enroll one in the console, or pass --email-code to receive a one-time code."
						}
						return nil, NewCliError("MFA_ENROLLMENT_REQUIRED", "This account must enroll an authenticator before it can sign in", hint)
					}
					code := c.Env["BETTER_IAM_MFA_CODE"]
					if code == "" {
						question := "Authenticator code: "
						if emailCode {
							question = "Emailed code: "
						}
						if code, err = ask(c, question, false, "Set BETTER_IAM_MFA_CODE"); err != nil {
							return nil, err
						}
					}
					if signedIn, err = anonymous.Call(ctx, "auth/verifyMfa", core.NewObject("tenantId", tenantID, "challenge", challenge, "code", code)); err != nil {
						return nil, err
					}
				}
				issued, _ := stringAt(signedIn, "token")
				if issued == "" {
					return nil, NewCliError("SIGN_IN_INCOMPLETE", "Sign-in did not return a session")
				}
				token = issued
			}
			transport, err := c.Api(ctx, ApiOptions{Token: token})
			if err != nil {
				return nil, err
			}
			caller, err := transport.Call(ctx, "sts/getCallerIdentity", nil)
			if err != nil {
				return nil, err
			}
			tenantID, _ := stringAt(caller, "tenantId")
			identity, _ := stringAt(caller, "identityId")
			profile := &StoredProfile{URL: where.url, Config: where.config, EnvConfig: where.envConfig, Token: token,
				TenantID: tenantID, IdentityID: identity, Email: signedInEmail, SavedAt: nowMillis()}
			if kind, ok := stringAt(caller, "sessionKind"); ok {
				profile.Kind = kind
			}
			if expiresAt, ok := pathOf(caller, "expiresAt").(float64); ok {
				profile.ExpiresAt = &expiresAt
			}
			if err := c.Profiles.Save(name, profile, true); err != nil {
				return nil, err
			}
			out := core.NewObject("profile", name).Assign(where.model())
			out.Set("tenantId", pathOf(caller, "tenantId"))
			out.Set("identityId", pathOf(caller, "identityId"))
			if profile.ExpiresAt != nil {
				out.Set("expiresAt", isoString(*profile.ExpiresAt))
			}
			if c.Profiles.Path != "" {
				out.Set("credentials", c.Profiles.Path)
			}
			return out, nil
		},
	}),
	DefineCommand(CommandSpec{
		Name:        "logout",
		Group:       "Session",
		Summary:     "Sign out and forget a saved session",
		Description: "logout signs a saved user session out on the server (best effort; API keys and other machine credentials saved with --with-token are only forgotten, never revoked) and removes the profile from the credentials file.",
		Target:      "token",
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			name, err := c.Profiles.CurrentName(c.Flags.String("profile"))
			if err != nil {
				return nil, err
			}
			saved, err := c.Profiles.Get(name)
			if err != nil {
				return nil, err
			}
			if saved == nil {
				return nil, NewCliError("NOT_FOUND", "No saved session named "+name, "Run better-iam profiles to list them.")
			}
			revoked := false
			if saved.Kind == "" || saved.Kind == "user" {
				// An expired or already revoked session is gone either way.
				if transport, err := profileTransport(ctx, c, saved); err == nil && transport != nil {
					if _, err := transport.Call(ctx, "auth/signOut", nil); err == nil {
						revoked = true
					}
				}
			}
			if _, err := c.Profiles.Remove(name); err != nil {
				return nil, err
			}
			return core.NewObject("profile", name, "revoked", revoked, "forgotten", true), nil
		},
	}),
	DefineCommand(CommandSpec{
		Name:        "profiles",
		Group:       "Session",
		Summary:     "List saved sessions, or choose or remove one",
		Description: "profiles lists the sessions saved by login (never their tokens) and marks the current one; profiles use NAME makes NAME current, and profiles remove NAME forgets one without signing it out.",
		Usage:       "better-iam profiles [use NAME | remove NAME]",
		Args: []ArgSpec{
			{Name: "action", Description: "use or remove"},
			{Name: "name", Description: "The profile"},
		},
		Flags: []FlagSpec{
			{Name: "profile", Type: "string", Value: "NAME", Env: "BETTER_IAM_PROFILE", Hidden: true, Description: "Treat NAME as current"},
		},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			action, name := "", ""
			if len(c.Args) > 0 {
				action = c.Args[0]
			}
			if len(c.Args) > 1 {
				name = c.Args[1]
			}
			if action == "" {
				listed, err := c.Profiles.List(c.Flags.String("profile"))
				if err != nil {
					return nil, err
				}
				rows := make([]any, len(listed))
				for index, entry := range listed {
					row := entry.Model()
					if expiresAt, ok := row.Get("expiresAt").(float64); ok && expiresAt != 0 {
						row.Set("expiresAt", isoString(expiresAt))
					}
					savedAt, _ := row.Get("savedAt").(float64)
					row.Set("savedAt", isoString(savedAt))
					rows[index] = row
				}
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
			if name == "" || (action != "use" && action != "remove") {
				return nil, UsageError("Use: better-iam profiles, profiles use NAME, or profiles remove NAME")
			}
			if action == "use" {
				if err := c.Profiles.Use(name); err != nil {
					return nil, err
				}
				return core.NewObject("current", name), nil
			}
			removed, err := c.Profiles.Remove(name)
			if err != nil {
				return nil, err
			}
			if !removed {
				return nil, NewCliError("NOT_FOUND", "No saved profile named "+name)
			}
			return core.NewObject("removed", name), nil
		},
	}),
	DefineCommand(CommandSpec{
		Name:        "token",
		Group:       "Session",
		Summary:     "Print the token commands act as, for scripts",
		Description: "token prints the bearer token token commands would use (BETTER_IAM_TOKEN, else the saved profile's), for scripts and other tools: export BETTER_IAM_TOKEN=$(better-iam token). It is a secret; do not log it.",
		Target:      "token",
		Output:      "text",
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			token, err := c.Token(ctx)
			if err != nil {
				return nil, err
			}
			return token, nil
		},
	}),
}

var _ = strings.TrimSpace
