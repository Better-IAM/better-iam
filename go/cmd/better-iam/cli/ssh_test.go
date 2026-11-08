package cli

// Port of tests/ssh-cli.test.ts.

import (
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
	"golang.org/x/crypto/ssh"
)

func sshPublicKey(t *testing.T, comment string) string {
	t.Helper()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))) + " " + comment
}

func TestHostFilePaths(t *testing.T) {
	root := t.TempDir()
	for _, path := range []string{"/etc/passwd", "/etc/ssh/../passwd", "/etc/ssh//x", "etc/ssh/x", "/etc/sshd/x"} {
		if _, err := hostFilePath(root, path); codeOf(err) != "UNEXPECTED_RESPONSE" {
			t.Fatalf("%s: %v", path, err)
		}
	}
	got, err := hostFilePath(root, "/etc/ssh/better-iam/principals/")
	if err != nil || got != filepath.Join(root, "etc", "ssh", "better-iam", "principals") {
		t.Fatalf("%s %v", got, err)
	}
}

func TestSshHostsAndCertificates(t *testing.T) {
	f := newOrganization(t, func(options *server.BetterIamOptions) { options.Ssh = server.On[server.SshOptions]() })
	folder := t.TempDir()
	r := newRecorder(folder)
	io := func(env map[string]string) *CliIO {
		return r.io(env, func(io *CliIO) { io.Fetch = f.fetch(nil) })
	}
	callRoute(t, f.iam, f.owner, "ssh/setup", core.NewObject("tenantId", f.tenantID))
	created := callRoute(t, f.iam, f.owner, "ssh/createHost", core.NewObject("tenantId", f.tenantID, "name", "web-01", "logins", []any{"deploy"}))
	if err := os.WriteFile(filepath.Join(folder, "host_key.pub"), []byte(sshPublicKey(t, "root@web-01")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustRun(t, []string{"ssh-host-enroll", "--url", testURL, "--host-key", "host_key.pub", "--root", "root"},
		io(map[string]string{"BETTER_IAM_SSH_JOIN_TOKEN": at(created, "joinToken").(string)}))
	if at(r.last(t), "host") != "web-01" || at(r.last(t), "hostId") != at(created, "host", "id") {
		t.Fatalf("enroll %s", r.lastLine(t))
	}
	etc := filepath.Join(folder, "root", "etc", "ssh")
	read := func(parts ...string) string {
		data, err := os.ReadFile(filepath.Join(append([]string{etc}, parts...)...))
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	certificate, err := server.ParseSshCertificate(read("ssh_host_ed25519_key-cert.pub"))
	if err != nil {
		t.Fatal(err)
	}
	if core.MustStringify(certificate.Get("principals")) != `["web-01"]` {
		t.Fatalf("host principals %s", core.MustStringify(certificate.Get("principals")))
	}
	if read("better-iam", "principals", "deploy") != "deploy@web-01\n" {
		t.Fatal("principals file")
	}
	if !strings.HasPrefix(read("better-iam", "revoked.krl"), "SSHKRL") {
		t.Fatal("revocation list")
	}
	expectContains(t, read("sshd_config.d", "00-better-iam.conf"), "TrustedUserCAKeys")
	if !regexp.MustCompile(`^biam_sshr\.`).MatchString(read("better-iam", "renewal-token")) {
		t.Fatal("renewal token")
	}

	mustRun(t, []string{"ssh-host-sync", "--url", testURL, "--root", "root"}, io(nil))
	if at(r.last(t), "host") != "web-01" || at(r.last(t), "certificateRenewed") != false {
		t.Fatalf("sync %s", r.lastLine(t))
	}
	// A forced renewal is honoured hourly; it rotates the renewal token, which the CLI saves for the next sync.
	firstToken := read("better-iam", "renewal-token")
	f.advance(2 * 3_600_000)
	mustRun(t, []string{"ssh-host-sync", "--url", testURL, "--root", "root", "--renew"}, io(nil))
	if at(r.last(t), "certificateRenewed") != true {
		t.Fatalf("renew %s", r.lastLine(t))
	}
	if read("better-iam", "renewal-token") == firstToken {
		t.Fatal("the renewal token was not rotated")
	}
	mustRun(t, []string{"ssh-host-sync", "--url", testURL, "--root", "root"}, io(nil))
	if at(r.last(t), "certificateRenewed") != false {
		t.Fatalf("sync %s", r.lastLine(t))
	}

	// A person gets a certificate next to their key and the known_hosts lines for the host authority.
	if err := os.WriteFile(filepath.Join(folder, "id_ed25519.pub"), []byte(sshPublicKey(t, "owner@laptop")+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustRun(t, []string{"ssh-cert", "--url", testURL, "--tenant", f.tenantID, "--key", "id_ed25519.pub", "--known-hosts", "known_hosts", "--ttl-minutes", "30"},
		io(map[string]string{"BETTER_IAM_TOKEN": f.owner}))
	if core.MustStringify(at(r.last(t), "principals")) != `["deploy@web-01"]` || at(r.last(t), "hosts", "0", "name") != "web-01" {
		t.Fatalf("cert %s", r.lastLine(t))
	}
	userCert, err := os.ReadFile(filepath.Join(folder, "id_ed25519-cert.pub"))
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := server.ParseSshCertificate(string(userCert))
	if err != nil {
		t.Fatal(err)
	}
	if core.MustStringify(parsed.Get("principals")) != `["deploy@web-01"]` {
		t.Fatal("user principals")
	}
	if parsed.Get("validBefore").(float64)-parsed.Get("validAfter").(float64) != 35*60 {
		t.Fatalf("validity %v", parsed.Get("validBefore").(float64)-parsed.Get("validAfter").(float64))
	}
	knownHosts, _ := os.ReadFile(filepath.Join(folder, "known_hosts"))
	if !regexp.MustCompile(`^@cert-authority web-01 ssh-ed25519 `).Match(knownHosts) {
		t.Fatalf("known hosts %s", knownHosts)
	}
	// The host revocation list for RevokedHostKeys, beside the known_hosts file.
	revoked, _ := os.ReadFile(filepath.Join(folder, "known_hosts_revoked_hosts"))
	if !strings.HasPrefix(string(revoked), "SSHKRL") {
		t.Fatal("host revocation list")
	}

	// A login removed from the host: the next sync deletes its principals file.
	callRoute(t, f.iam, f.owner, "ssh/updateHost", core.NewObject("tenantId", f.tenantID, "hostId", at(created, "host", "id"), "logins", []any{"ops"}))
	mustRun(t, []string{"ssh-host-sync", "--url", testURL, "--root", "root"}, io(nil))
	files := at(r.last(t), "files").([]any)
	if !slices.Contains(files, any("-/etc/ssh/better-iam/principals/deploy")) {
		t.Fatalf("files %s", core.MustStringify(files))
	}
	entries, _ := os.ReadDir(filepath.Join(etc, "better-iam", "principals"))
	if len(entries) != 1 || entries[0].Name() != "ops" {
		t.Fatalf("principals %v", entries)
	}
}
