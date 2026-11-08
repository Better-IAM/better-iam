package cli

// Port of packages/cli/src/commands/ssh.ts: SSH certificates. People get one for what policies allow; hosts enroll
// and check in; the sweep job.

import (
	"context"
	"encoding/base64"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

func commaList(value string) []any {
	items := []any{}
	for _, item := range strings.Split(value, ",") {
		if trimmed := core.JSTrim(item); trimmed != "" {
			items = append(items, trimmed)
		}
	}
	return items
}

const renewalTokenPath = "/etc/ssh/better-iam/renewal-token"

// posixNormalize is path.posix.normalize: the cleaned path, keeping a trailing slash.
func posixNormalize(value string) string {
	if value == "" {
		return "."
	}
	normal := path.Clean(value)
	if strings.HasSuffix(value, "/") && normal != "/" {
		normal += "/"
	}
	return normal
}

// hostFilePath maps a path the server names to the file under root: only files under /etc/ssh, never outside it.
// The host trusts the server, but not blindly with paths.
func hostFilePath(root, name string) (string, error) {
	normal := posixNormalize(name)
	if !strings.HasPrefix(normal, "/etc/ssh/") || strings.Contains(normal, "..") || normal != name {
		return "", NewCliError("UNEXPECTED_RESPONSE", "The server named a file outside /etc/ssh: "+sliceUnits(name, 80))
	}
	var parts []string
	for _, part := range strings.Split(normal, "/") {
		if part != "" {
			parts = append(parts, part)
		}
	}
	return filepath.Join(append([]string{root}, parts...)...), nil
}

type hostFile struct {
	path     string
	content  string
	mode     string
	encoding string
}

func hostFilesOf(setup any) []hostFile {
	list, _ := pathOf(setup, "files").([]any)
	files := make([]hostFile, 0, len(list))
	for _, item := range list {
		file := hostFile{}
		file.path, _ = pathOf(item, "path").(string)
		file.content, _ = pathOf(item, "content").(string)
		file.mode, _ = pathOf(item, "mode").(string)
		file.encoding, _ = pathOf(item, "encoding").(string)
		files = append(files, file)
	}
	return files
}

// parseOctal is Number.parseInt(value, 8) for file modes.
func parseOctal(value string) os.FileMode {
	digits := regexp.MustCompile(`^\s*[+]?[0-7]+`).FindString(value)
	mode, err := strconv.ParseUint(strings.TrimLeft(strings.TrimSpace(digits), "+"), 8, 32)
	if err != nil {
		return 0
	}
	return os.FileMode(mode)
}

func writeHostFiles(c *CommandContext, root string, setup any, dryRun bool) ([]any, error) {
	written := []any{}
	files := hostFilesOf(setup)
	if token, ok := pathOf(setup, "renewalToken").(string); ok && token != "" {
		files = append(files, hostFile{path: renewalTokenPath, content: token + "\n", mode: "0600"})
	}
	for _, file := range files {
		target, err := hostFilePath(root, file.path)
		if err != nil {
			return nil, err
		}
		written = append(written, file.path)
		if dryRun {
			continue
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o777); err != nil {
			return nil, systemError(err)
		}
		data := []byte(file.content)
		if file.encoding == "base64" {
			if data, err = base64.StdEncoding.DecodeString(file.content); err != nil {
				data, _ = base64.RawStdEncoding.DecodeString(strings.TrimRight(file.content, "="))
			}
		}
		mode := parseOctal(file.mode)
		if err := os.WriteFile(target, data, mode); err != nil {
			return nil, systemError(err)
		}
		// Also tighten an existing file (WriteFile's mode applies to new files only); a no-op on Windows.
		_ = os.Chmod(target, mode)
	}
	// A login removed from the host must stop working here too: its principals file goes.
	directories, _ := pathOf(setup, "managedDirectories").([]any)
	for _, item := range directories {
		directory, _ := item.(string)
		folder, err := hostFilePath(root, strings.TrimSuffix(directory, "/")+"/")
		if err != nil {
			return nil, err
		}
		listed := map[string]bool{}
		for _, file := range files {
			target, err := hostFilePath(root, file.path)
			if err != nil {
				return nil, err
			}
			listed[target] = true
		}
		entries, err := os.ReadDir(folder)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			target := filepath.Join(folder, entry.Name())
			if listed[target] {
				continue
			}
			written = append(written, "-"+path.Join(directory, entry.Name()))
			if !dryRun {
				if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
					return nil, systemError(err)
				}
			}
		}
	}
	if !dryRun {
		c.Note("Wrote the SSH files; reload sshd to apply them (systemctl reload ssh).")
	}
	return written, nil
}

var rootFlag = FlagSpec{Name: "root", Type: "string", Value: "DIR", Default: "/", Description: "Write under this directory instead of / (for images and tests)"}

func homeFile(parts ...string) string {
	home, _ := os.UserHomeDir()
	return filepath.Join(append([]string{home}, parts...)...)
}

func isoAt(value any, key string) string {
	ms, _ := pathOf(value, key).(float64)
	return isoString(ms)
}

func stringFlag(flags Flags, name, fallback string) string {
	if value := flags.String(name); value != "" {
		return value
	}
	return fallback
}

var sshCommands = []*CommandSpec{
	DefineCommand(CommandSpec{
		Name:        "ssh-cert",
		Group:       "Access",
		Summary:     "Get a short-lived SSH certificate for your key",
		Description: "ssh-cert sends your public key (--key, default ~/.ssh/id_ed25519.pub) to the organization's SSH certificate authority as BETTER_IAM_TOKEN or the session saved by login, and saves the certificate it returns next to the key (id_ed25519-cert.pub), where ssh picks it up. The certificate names every enrolled host and login policies allow you (ssh:login on ssh-login/{host}/{login}), or only --hosts and --logins. It also writes the organization's host authority to --known-hosts (default ~/.ssh/better-iam_known_hosts): add that file to UserKnownHostsFile in ~/.ssh/config so hosts are verified by certificate, and the host revocation list written beside it (better-iam_revoked_hosts) to RevokedHostKeys.",
		Target:      "token",
		Flags: []FlagSpec{
			tenantFlag,
			{Name: "key", Type: "string", Value: "PATH", Description: "Your OpenSSH public key (default ~/.ssh/id_ed25519.pub)"},
			{Name: "hosts", Type: "string", Value: "HOST,...", Description: "Only these hosts"},
			{Name: "logins", Type: "string", Value: "LOGIN,...", Description: "Only these logins"},
			boundedInteger("ttl-minutes", "Lifetime (default and maximum from the organization's settings)", 1, 10080, nil),
			{Name: "reason", Type: "string", Value: "TEXT", Description: "Why you need access (audited)"},
			{Name: "known-hosts", Type: "string", Value: "PATH", Description: "Where to write the known_hosts lines (default ~/.ssh/better-iam_known_hosts)"},
			{Name: "no-write", Type: "boolean", Description: "Print the certificate instead of saving files"},
		},
		Examples: []string{
			"better-iam ssh-cert --tenant ten_123",
			`better-iam ssh-cert --hosts web-01 --logins deploy --ttl-minutes 30 --reason "hotfix 42"`,
		},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			keyPath := c.Path(stringFlag(c.Flags, "key", homeFile(".ssh", "id_ed25519.pub")))
			if !strings.HasSuffix(keyPath, ".pub") {
				return nil, UsageError("--key must name the .pub public key file")
			}
			raw, err := os.ReadFile(keyPath)
			if err != nil {
				return nil, NewCliError("NOT_FOUND", "No public key at "+keyPath, "Create one with ssh-keygen -t ed25519.")
			}
			publicKey := core.JSTrim(string(raw))
			transport, err := c.Api(ctx, ApiOptions{})
			if err != nil {
				return nil, err
			}
			input := core.NewObject("tenantId", c.Flags.String("tenant"), "publicKey", publicKey)
			if hosts := c.Flags.String("hosts"); hosts != "" {
				input.Set("hosts", commaList(hosts))
			}
			if logins := c.Flags.String("logins"); logins != "" {
				input.Set("logins", commaList(logins))
			}
			if minutes, ok := c.Flags.Int("ttl-minutes"); ok {
				input.Set("ttlMs", float64(minutes)*60_000)
			}
			if reason := c.Flags.String("reason"); reason != "" {
				input.Set("reason", reason)
			}
			issued, err := transport.Call(ctx, "ssh/issueCertificate", input)
			if err != nil {
				return nil, err
			}
			summary := core.NewObject("id", pathOf(issued, "id"), "principals", pathOf(issued, "principals"),
				"validBefore", isoAt(issued, "validBefore"), "hosts", pathOf(issued, "hosts"))
			certificate, _ := pathOf(issued, "certificate").(string)
			knownHosts, _ := pathOf(issued, "knownHosts").(string)
			if c.Flags.Bool("no-write") {
				return summary.Set("certificate", certificate).Set("knownHosts", knownHosts), nil
			}
			certificatePath := strings.TrimSuffix(keyPath, ".pub") + "-cert.pub"
			knownHostsPath := c.Path(stringFlag(c.Flags, "known-hosts", homeFile(".ssh", "better-iam_known_hosts")))
			if err := os.WriteFile(certificatePath, []byte(certificate+"\n"), 0o644); err != nil {
				return nil, systemError(err)
			}
			if err := os.MkdirAll(filepath.Dir(knownHostsPath), 0o777); err != nil {
				return nil, systemError(err)
			}
			if err := os.WriteFile(knownHostsPath, []byte(knownHosts), 0o644); err != nil {
				return nil, systemError(err)
			}
			// Revoked host keys and certificates, for RevokedHostKeys in ~/.ssh/config.
			revokedHostsPath := strings.TrimSuffix(knownHostsPath, "_known_hosts") + "_revoked_hosts"
			revoked, _ := pathOf(issued, "revokedHostKeys").(string)
			decoded, err := base64.StdEncoding.DecodeString(revoked)
			if err != nil {
				decoded, _ = base64.RawStdEncoding.DecodeString(strings.TrimRight(revoked, "="))
			}
			if err := os.WriteFile(revokedHostsPath, decoded, 0o644); err != nil {
				return nil, systemError(err)
			}
			return summary.Set("certificatePath", certificatePath).Set("knownHostsPath", knownHostsPath).Set("revokedHostsPath", revokedHostsPath), nil
		},
	}),
	DefineCommand(CommandSpec{
		Name:        "ssh-host-enroll",
		Group:       "Setup",
		Summary:     "Enroll this server with the SSH certificate authority",
		Description: "ssh-host-enroll runs on a server: it sends the server's public host key (--host-key, default /etc/ssh/ssh_host_ed25519_key.pub) with the one-time join token from ssh.createHost, and writes what sshd needs under /etc/ssh: the host certificate, the trusted user authority, one principals file per login, the key revocation list, an sshd_config.d drop-in, and the renewal token (root-only) that ssh-host-sync uses from then on. Needs no session; point it at the server with --url.",
		Target:      "token",
		Flags: []FlagSpec{
			{Name: "join-token", Type: "string", Value: "TOKEN", Required: true, Env: "BETTER_IAM_SSH_JOIN_TOKEN", Description: "The one-time join token from ssh.createHost or ssh.resetJoinToken"},
			{Name: "host-key", Type: "string", Value: "PATH", Default: "/etc/ssh/ssh_host_ed25519_key.pub", Description: "The server's public host key"},
			rootFlag,
			{Name: "dry-run", Type: "boolean", Description: "List the files without writing them"},
		},
		Examples: []string{"BETTER_IAM_SSH_JOIN_TOKEN=biam_sshj.... better-iam ssh-host-enroll --url https://iam.example.com"},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			raw, err := os.ReadFile(c.Path(stringFlag(c.Flags, "host-key", "/etc/ssh/ssh_host_ed25519_key.pub")))
			if err != nil {
				return nil, systemError(err)
			}
			transport, err := c.Api(ctx, ApiOptions{Anonymous: true})
			if err != nil {
				return nil, err
			}
			setup, err := transport.Call(ctx, "ssh/enrollHost", core.NewObject("joinToken", c.Flags.String("join-token"), "publicKey", core.JSTrim(string(raw))))
			if err != nil {
				return nil, err
			}
			files, err := writeHostFiles(c, c.Path(stringFlag(c.Flags, "root", "/")), setup, c.Flags.Bool("dry-run"))
			if err != nil {
				return nil, err
			}
			return core.NewObject("host", pathOf(setup, "host", "name"), "hostId", pathOf(setup, "host", "id"),
				"certificateExpiresAt", isoAt(setup, "certificateExpiresAt"), "files", files,
				"next", "Schedule better-iam ssh-host-sync every 5 minutes, then reload sshd."), nil
		},
	}),
	DefineCommand(CommandSpec{
		Name:        "ssh-host-sync",
		Group:       "Operations",
		Summary:     "Refresh this server's SSH trust, principals, revocations and certificate",
		Description: "ssh-host-sync runs on an enrolled server (every few minutes, from cron or a systemd timer): with the renewal token ssh-host-enroll saved, it fetches the current trusted user authorities, principals files and key revocation list, and a new host certificate when the current one nears its end or the host's addresses changed, and rewrites the files. Reload sshd when the certificate or trust changed; revocations and principals apply to the next login without a reload.",
		Target:      "token",
		Flags: []FlagSpec{
			{Name: "renewal-token-file", Type: "string", Value: "PATH", Default: renewalTokenPath, Description: "Where ssh-host-enroll saved the renewal token"},
			{Name: "renew", Type: "boolean", Description: "Issue a new host certificate now"},
			rootFlag,
			{Name: "dry-run", Type: "boolean", Description: "List the files without writing them"},
		},
		Run: func(ctx context.Context, c *CommandContext) (any, error) {
			root := c.Path(stringFlag(c.Flags, "root", "/"))
			tokenFile := ""
			if name := c.Flags.String("renewal-token-file"); name != "" {
				tokenFile = c.Path(name)
			} else {
				var err error
				if tokenFile, err = hostFilePath(root, renewalTokenPath); err != nil {
					return nil, err
				}
			}
			raw, err := os.ReadFile(tokenFile)
			if err != nil {
				return nil, NewCliError("NOT_FOUND", "No renewal token at "+tokenFile, "Enroll the host with ssh-host-enroll first.")
			}
			transport, err := c.Api(ctx, ApiOptions{Anonymous: true})
			if err != nil {
				return nil, err
			}
			input := core.NewObject("renewalToken", core.JSTrim(string(raw)))
			if c.Flags.Bool("renew") {
				input.Set("renew", true)
			}
			setup, err := transport.Call(ctx, "ssh/syncHost", input)
			if err != nil {
				return nil, err
			}
			files, err := writeHostFiles(c, root, setup, c.Flags.Bool("dry-run"))
			if err != nil {
				return nil, err
			}
			return core.NewObject("host", pathOf(setup, "host", "name"), "certificateRenewed", pathOf(setup, "certificateRenewed"),
				"certificateExpiresAt", isoAt(setup, "certificateExpiresAt"), "revocationVersion", pathOf(setup, "revocationVersion"),
				"files", files), nil
		},
	}),
	DefineCommand(CommandSpec{
		Name:        "ssh-sweep",
		Group:       "Operations",
		Summary:     "Revoke SSH certificates whose holder or access went away",
		Description: "ssh-sweep re-checks every live SSH user certificate (or one --tenant's): certificates of people and machines who are no longer active, whose temporary session ended, or whose hosts and logins policies no longer allow are revoked and published in the revocation list hosts fetch with ssh-host-sync. A deployment operation; run it every few minutes.",
		Target:      "config",
		Flags:       []FlagSpec{{Name: "tenant", Type: "string", Value: "TENANT_ID", Description: "Only this tenant"}},
		Run: withIam(func(ctx context.Context, c *CommandContext, iam *server.BetterIam) (any, error) {
			return result(iam.Ssh.Sweep(ctx, tenantOnly(c.Flags)))
		}),
	}),
}
