package server

// Tests of ssh.go (packages/server/src/ssh.ts), after tests/ssh.test.ts. The SSH API group (api/ssh.ts) is a separate
// unit, so the scenarios of that test drive the module functions it builds on directly: options and the catalog,
// settings, host names and patterns, authorities, resource resolution, trust bundles, revocation lists, and the
// continuous-authorization sweep. Certificates are signed with the authorities and recorded the way issueCertificate
// records them.

import (
	"context"
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

const sshTestHour = 3_600_000.0

type sshFixture struct {
	*directoryFixture
	server   *ServerContext
	tenantID string
	owner    *core.Object
	web, db  *core.Object
	roleID   string
	alice    *core.Object
	lines    map[string]string
}

// newSshFixture is the TypeScript setup(): Acme with a verified domain (acme.test), the SSH CA set up, two enrolled
// hosts (web-01 staging, db-01 production), and alice allowed `deploy` on staging hosts with port forwarding
// everywhere.
func newSshFixture(t *testing.T, mutate func(options *BetterIamOptions)) *sshFixture {
	t.Helper()
	f := &sshFixture{directoryFixture: newDirectoryFixture(t, func(options *BetterIamOptions) {
		options.Ssh = On[SshOptions]()
		if mutate != nil {
			mutate(options)
		}
	})}
	f.server = f.iam.Context
	f.lines = map[string]string{}
	f.tenantID, _ = f.organization("Acme", "owner@acme.test")
	f.owner = f.find("identities", core.NewObject("tenantId", f.tenantID, "owner", true))[0]
	f.seed("tenantDomains", core.NewObject("id", ID(), "tenantId", f.tenantID, "domain", "Acme.test", "status", "verified"))
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		_, err := EnsureAuthorities(ctx, f.server, tx, f.tenantID, jsString(f.owner.Get("id")))
		return err
	})
	f.web = f.host("web-01", []any{"web-01.acme.test", "10.0.0.5"}, []any{"deploy", "root"}, "staging", sshTestPublicKey(t, "ed25519", "root@web-01"))
	f.db = f.host("db-01", []any{}, []any{"postgres", "root"}, "production", sshTestPublicKey(t, "ecdsa", "root@db-01"))
	f.alice, _ = f.person(f.tenantID, "alice")
	f.roleID = f.role(f.tenantID, "Staging deploy",
		allow(items("ssh:login"), items("ssh-login/*/deploy"), "conditions",
			core.NewObject("StringEquals", core.NewObject("resource.environment", "staging"))),
		allow(items("ssh:port-forward"), items("ssh-host/*")),
	)
	f.bind(f.tenantID, f.roleID, "identity", jsString(f.alice.Get("id")))
	return f
}

// host seeds an enrolled host the way createHost and enrollHost leave it.
func (f *sshFixture) host(name string, addresses, logins []any, environment, hostKey string) *core.Object {
	f.t.Helper()
	key := sshTestParse(f.t, hostKey)
	host := core.NewObject(
		"id", ID(), "tenantId", f.tenantID, "uniqueKey", name, "name", name, "addresses", addresses, "logins", logins,
		"labels", core.NewObject("environment", environment), "status", "enrolled",
		"hostKey", must(SshKeyLine(key.Get("blob").([]byte), "")), "hostKeyFingerprint", key.Get("fingerprint"),
		"enrolledAt", f.now(), "createdAt", f.now(), "createdBy", f.owner.Get("id"), "updatedAt", f.now(),
	)
	f.seed("sshHosts", host)
	return host
}

// sessionOf is the identity's newest session.
func (f *sshFixture) sessionOf(identity *core.Object) *core.Object {
	f.t.Helper()
	sessions := f.find("sessions", core.NewObject("identityId", identity.Get("id")))
	if len(sessions) == 0 {
		f.t.Fatalf("no session for %v", identity.Get("id"))
	}
	return sessions[len(sessions)-1]
}

// certificate signs a user certificate for identity's session and records it as issueCertificate does.
func (f *sshFixture) certificate(identity, session *core.Object, access []any, extensions []any) (*core.Object, *core.Object) {
	f.t.Helper()
	var record, parsed *core.Object
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		authority, err := ActiveAuthority(ctx, tx, f.tenantID, "user")
		if err != nil {
			return err
		}
		signing, err := OpenAuthority(f.server, authority)
		if err != nil {
			return err
		}
		key := sshTestParse(f.t, sshTestPublicKey(f.t, "ed25519", ""))
		serial := must(SshSerial()).(uint64)
		principal := &Principal{Identity: identity, Session: session}
		keyID, err := CertificateKeyID(principal)
		if err != nil {
			return err
		}
		var principals []any
		for _, item := range access {
			for _, login := range sshStrings(member(item, "logins")) {
				principals = append(principals, must(SshLoginPrincipal(login, jsString(member(item, "host")))))
			}
		}
		now := f.now()
		validBefore := now + sshTestHour
		signed, err := SignSshCertificate(signing, sshRaw(
			"key", key, "serial", serial, "kind", float64(SshCertUser), "keyId", keyID, "principals", principals,
			"validAfter", float64(int64(now)/1000), "validBefore", float64(int64(validBefore)/1000), "extensions", extensions,
		), "")
		if err != nil {
			return err
		}
		if parsed, err = ParseSshCertificate(signed.Get("line").(string)); err != nil {
			return err
		}
		record, err = tx.Insert(ctx, "sshCertificates", core.NewObject(
			"id", ID(), "tenantId", f.tenantID, "uniqueKey", jsString(authority.Get("id"))+":"+strconv.FormatUint(serial, 10),
			"kind", "user", "serial", strconv.FormatUint(serial, 10), "keyId", keyID, "authorityId", authority.Get("id"),
			"identityId", identity.Get("id"), "sessionId", session.Get("id"), "sessionKind", session.Get("kind"),
			"mfa", session.Get("mfa"), "principals", principals, "access", access, "extensions", extensions,
			"keyType", key.Get("type"), "publicKeyFingerprint", key.Get("fingerprint"), "validAfter", now,
			"validBefore", validBefore, "issuedAt", now, "expiresAt", validBefore+90*sshDay,
		))
		if err == nil {
			f.lines[jsString(record.Get("id"))] = signed.Get("line").(string)
		}
		return err
	})
	return record, parsed
}

// staging is the access alice's grant allows: deploy on web-01, with port forwarding.
func (f *sshFixture) staging(identity *core.Object) (*core.Object, *core.Object) {
	return f.certificate(identity, f.sessionOf(identity),
		items(core.NewObject("host", "web-01", "logins", items("deploy"))),
		items("permit-port-forwarding", "permit-pty", "permit-user-rc"))
}

func (f *sshFixture) revocationList(kind string) *core.Object {
	f.t.Helper()
	tenant := f.record("tenants", f.tenantID)
	return must(RevocationList(f.ctx, f.server, f.iam.Store, tenant, kind))
}

func (f *sshFixture) trust(audience string) *core.Object {
	f.t.Helper()
	return must(TrustBundle(f.ctx, f.server, f.iam.Store, f.record("tenants", f.tenantID), audience))
}

func (f *sshFixture) sweep(input *core.Object) *core.Object {
	f.t.Helper()
	return must(SweepSshCertificates(f.ctx, f.server, input))
}

// krlSerials decodes the serials a KRL revokes.
func krlSerials(t *testing.T, encoded string) []uint64 {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reader := NewSshReader(data)
	// Magic, format version, KRL version, generated at, flags, reserved, comment.
	if must(reader.U64()) != krlMagic || must(reader.U32()) != 1 {
		t.Fatal("not a KRL")
	}
	must(reader.U64())
	must(reader.U64())
	must(reader.U64())
	must(reader.String())
	must(reader.String())
	var serials []uint64
	for !reader.Done() {
		sectionType := must(reader.Byte())
		section := must(reader.String())
		if sectionType != krlSectionCertificates {
			continue
		}
		body := NewSshReader(section)
		must(body.String())
		must(body.String())
		for !body.Done() {
			kind := must(body.Byte())
			list := NewSshReader(must(body.String()))
			for kind == krlSectionCertSerialList && !list.Done() {
				serials = append(serials, must(list.U64()))
			}
		}
	}
	return serials
}

func sshExpectObject(t *testing.T, got *core.Object, want string) {
	t.Helper()
	if text, _, _ := core.Stringify(got); text != want {
		t.Fatalf("got %s\nwant %s", text, want)
	}
}

func TestSshIsOffUnlessTheOptionIsSetAndValidatesIt(t *testing.T) {
	k := newKernel(t, nil)
	_, err := AssertSsh(k.server)
	expectError(t, err, "FEATURE_DISABLED", "The SSH certificate authority is not enabled on this deployment")
	if iamError(t, err).Status != 403 {
		t.Fatal("status")
	}
	if plugins := must(SshPlugins(k.options)); plugins != nil {
		t.Fatal("plugins while off")
	}
	if resolved, err := ResolveSshResource(k.ctx, k.server, k.store, core.ResourceRef{TenantID: "t", Type: SshLoginResourceType, ID: "web-01/deploy"}); resolved != nil || err != nil {
		t.Fatalf("resolved while off: %v %v", resolved, err)
	}
	_, err = LoadSshSettings(k.ctx, k.server, k.store, "t")
	expectError(t, err, "FEATURE_DISABLED", "The SSH certificate authority is not enabled on this deployment")

	sshExpectObject(t, must(ResolveSshOptions(On[SshOptions]())),
		`{"maxUserCertificateMs":86400000,"hostCertificateMs":7776000000,"clockSkewMs":300000,"maxHostsPerCertificate":64,"recordRetentionMs":7776000000,"joinTokenMs":86400000,"issuanceLimit":60}`)
	sshExpectObject(t, must(ResolveSshOptions(With(SshOptions{RecordRetentionDays: float(1), ClockSkewMs: float(0)}))),
		`{"maxUserCertificateMs":86400000,"hostCertificateMs":7776000000,"clockSkewMs":0,"maxHostsPerCertificate":64,"recordRetentionMs":86400000,"joinTokenMs":86400000,"issuanceLimit":60}`)
	for _, testCase := range []struct {
		options SshOptions
		message string
	}{
		{SshOptions{MaxUserCertificateMs: float(1000)}, "ssh.maxUserCertificateMs must be an integer between 300000 and 604800000"},
		{SshOptions{HostCertificateMs: float(400 * sshDay)}, "ssh.hostCertificateMs must be an integer between 86400000 and 31536000000"},
		{SshOptions{ClockSkewMs: float(1.5)}, "ssh.clockSkewMs must be an integer between 0 and 3600000"},
		{SshOptions{MaxHostsPerCertificate: float(0)}, "ssh.maxHostsPerCertificate must be an integer between 1 and 256"},
		{SshOptions{RecordRetentionDays: float(0)}, "ssh.recordRetentionDays must be an integer between 1 and 3650"},
		{SshOptions{JoinTokenMs: float(31 * sshDay)}, "ssh.joinTokenMs must be an integer between 300000 and 2592000000"},
		{SshOptions{IssuanceLimit: float(100_001)}, "ssh.issuanceLimit must be an integer between 1 and 100000"},
		// The first invalid option in declaration order is reported.
		{SshOptions{IssuanceLimit: float(0), MaxUserCertificateMs: float(1)}, "ssh.maxUserCertificateMs must be an integer between 300000 and 604800000"},
	} {
		_, err := ResolveSshOptions(With(testCase.options))
		expectError(t, err, "INVALID_CONFIG", testCase.message)
	}
	// Composition refuses an invalid option.
	_, err = New(&BetterIamOptions{Database: newStore(t), Secret: testSecret, BaseURL: "http://localhost:3000",
		Ssh: With(SshOptions{IssuanceLimit: float(0)})})
	expectError(t, err, "INVALID_CONFIG", "ssh.issuanceLimit must be an integer between 1 and 100000")

	plugins := must(SshPlugins(&BetterIamOptions{Ssh: On[SshOptions]()}))
	if len(plugins) != 1 || plugins[0].ID != "better-iam:ssh" || len(plugins[0].ResourceTypes) != 2 {
		t.Fatalf("plugins %+v", plugins)
	}
	login, host := plugins[0].ResourceTypes[0], plugins[0].ResourceTypes[1]
	if login.Name != "ssh-login" || !reflect.DeepEqual(login.Definition.Actions, []string{"ssh:login"}) ||
		!reflect.DeepEqual(login.Definition.Attributes, []core.NamedAttribute{{Name: "host", Type: "string"}, {Name: "login", Type: "string"}}) {
		t.Fatalf("ssh-login %+v", login)
	}
	if host.Name != "ssh-host" || !reflect.DeepEqual(host.Definition.Actions, []string{"ssh:port-forward", "ssh:agent-forward", "ssh:x11-forward"}) {
		t.Fatalf("ssh-host %+v", host)
	}
}

func TestSshSettingsDefaultsCapsAndRevocationVersion(t *testing.T) {
	k := newKernel(t, func(options *BetterIamOptions) {
		options.Ssh = With(SshOptions{MaxUserCertificateMs: float(4 * sshTestHour)})
	})
	settings := must(LoadSshSettings(k.ctx, k.server, k.store, "acme"))
	sshExpectObject(t, settings, `{"id":"acme","tenantId":"acme","requireMfa":false,"requireSecurityKey":false,"requireUserVerification":false,"bindSourceAddress":false,"defaultCertificateMs":14400000,"maxCertificateMs":14400000,"hostPatterns":[],"revocationVersion":0}`)
	// A deployment that lowered its maximum caps what tenants stored earlier.
	k.insert("sshSettings", core.NewObject("id", "acme", "tenantId", "acme", "requireMfa", true, "defaultCertificateMs", 8*sshTestHour,
		"maxCertificateMs", 16*sshTestHour, "hostPatterns", items("*.acme.test"), "revocationVersion", 3.0, "updatedBy", "owner"))
	settings = must(LoadSshSettings(k.ctx, k.server, k.store, "acme"))
	sshExpectObject(t, settings, `{"id":"acme","tenantId":"acme","requireMfa":true,"requireSecurityKey":false,"requireUserVerification":false,"bindSourceAddress":false,"defaultCertificateMs":14400000,"maxCertificateMs":14400000,"hostPatterns":["*.acme.test"],"revocationVersion":3,"updatedBy":"owner"}`)
	// A record of another tenant under this ID is ignored.
	k.insert("sshSettings", core.NewObject("id", "other", "tenantId", "acme", "requireMfa", true))
	if must(LoadSshSettings(k.ctx, k.server, k.store, "other")).Get("requireMfa") != false {
		t.Fatal("foreign settings record used")
	}
	if err := k.tx(func(ctx context.Context, tx core.IamStore) error {
		if err := BumpRevocationVersion(ctx, k.server, tx, "acme"); err != nil {
			return err
		}
		return BumpRevocationVersion(ctx, k.server, tx, "fresh")
	}); err != nil {
		t.Fatal(err)
	}
	if must(k.store.Get(k.ctx, "sshSettings", "acme")).Get("revocationVersion") != 4.0 {
		t.Fatal("revocation version not bumped")
	}
	// Saving creates the record the first time.
	if must(k.store.Get(k.ctx, "sshSettings", "fresh")).Get("revocationVersion") != 1.0 {
		t.Fatal("first revocation not stored")
	}
}

func TestSshKeepsTheHostAuthorityToNamesTheOrganizationOwns(t *testing.T) {
	domains := []string{"acme.test"}
	// `*` and names outside the verified domains are refused as patterns.
	for _, patterns := range [][]any{{"*"}, {"*.github.com"}, {"localhost"}, {"*.8.8"}} {
		_, err := HostPatternList(patterns, domains)
		if iamError(t, err).Code != "HOST_OUTSIDE_PATTERNS" || iamError(t, err).Status != 400 {
			t.Fatalf("%v: %v", patterns, err)
		}
	}
	_, err := HostPatternList([]any{"*.github.com"}, domains)
	expectError(t, err, "HOST_OUTSIDE_PATTERNS", "Pattern *.github.com must end in a verified domain of this organization or fix an address prefix")
	patterns := must(HostPatternList([]any{"*.ACME.test", "web-*", "db-*", "10.0.0.*", "!bastion.acme.test", "*.acme.test", "fd00:1:*", "10.0.0.5"}, domains))
	if !reflect.DeepEqual(patterns, []string{"*.acme.test", "web-*", "db-*", "10.0.0.*", "!bastion.acme.test", "fd00:1:*", "10.0.0.5"}) {
		t.Fatalf("patterns %v", patterns)
	}
	if len(must(HostPatternList([]any{}, domains))) != 0 {
		t.Fatal("empty patterns")
	}
	_, err = HostPatternList(make([]any, 17), domains)
	expectError(t, err, "INVALID_INPUT", "hostPatterns must list at most 16 known_hosts patterns")
	_, err = HostPatternList("*.acme.test", domains)
	expectError(t, err, "INVALID_INPUT", "hostPatterns must list at most 16 known_hosts patterns")
	_, err = HostPatternList([]any{"a b"}, domains)
	expectError(t, err, "INVALID_INPUT", "hostPatterns hold known_hosts patterns such as *.corp.example.com")
	_, err = HostPatternList([]any{"!web-01"}, domains)
	expectError(t, err, "INVALID_INPUT", "hostPatterns needs at least one pattern that is not negated")

	// Without patterns: single labels, private addresses, and names under the verified domains.
	plain := core.NewObject("hostPatterns", []any{})
	if err := AssertVouchable(plain, domains, []string{"web-01", "web-01.acme.test", "acme.test", "10.0.0.5", "192.168.1.1", "fd00::1", "fe80::1"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"8.8.8.8", "localhost", "evil.test", "acme.test.evil", "2001:db8::1"} {
		err := AssertVouchable(plain, domains, []string{name})
		expectError(t, err, "HOST_OUTSIDE_PATTERNS", name+" is outside the names this organization can vouch for (verify its domain or set hostPatterns)")
	}
	err = AssertVouchable(plain, domains, []string{"a.evil", "b.evil", "c.evil", "d.evil", "e.evil", "f.evil"})
	expectError(t, err, "HOST_OUTSIDE_PATTERNS", "a.evil, b.evil, c.evil, d.evil, e.evil is outside the names this organization can vouch for (verify its domain or set hostPatterns)")

	// With patterns: every name must match them, and patterns only narrow.
	narrowed := core.NewObject("hostPatterns", items("*.acme.test", "web-*", "db-*", "10.0.0.*", "!bastion.acme.test"))
	if err := AssertVouchable(narrowed, domains, []string{"web-01", "web-01.acme.test", "10.0.0.5", "db-01"}); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"github.com", "bastion.acme.test", "evil.example.com", "10.1.0.5", "mail-01"} {
		if err := AssertVouchable(narrowed, domains, []string{name}); iamError(t, err).Code != "HOST_OUTSIDE_PATTERNS" {
			t.Fatalf("%s vouched", name)
		}
	}
	// A public address inside an address pattern is vouched for by that pattern.
	public := core.NewObject("hostPatterns", items("203.0.113.*"))
	if err := AssertVouchable(public, domains, []string{"203.0.113.7"}); err != nil {
		t.Fatal(err)
	}
	// `*.acme.test` alone does not cover the single-label host web-01.
	if err := AssertVouchable(core.NewObject("hostPatterns", items("*.acme.test")), domains, []string{"web-01"}); err == nil {
		t.Fatal("web-01 vouched by *.acme.test")
	}
	// A short-name pattern such as `*m` is a valid pattern, but it must still cover every host (updateSettings).
	short := must(HostPatternList([]any{"*m"}, domains))
	if err := AssertVouchable(core.NewObject("hostPatterns", stringsOf(short)), domains, []string{"web-01"}); err == nil {
		t.Fatal("web-01 vouched by *m")
	}
}

func TestSshHostNamesKeysAndLabels(t *testing.T) {
	f := newSshFixture(t, nil)
	if domains := must(VerifiedDomains(f.ctx, f.iam.Store, f.tenantID)); !reflect.DeepEqual(domains, []string{"acme.test"}) {
		t.Fatalf("domains %v", domains)
	}
	// Another host's names are taken; a host's own names are not.
	webID := jsString(f.web.Get("id"))
	err := AssertNamesFree(f.ctx, f.iam.Store, f.tenantID, []string{"web-02", "web-01.acme.test"}, "")
	expectError(t, err, "HOST_NAME_TAKEN", "Host web-01 already uses web-01.acme.test")
	if iamError(t, err).Status != 409 {
		t.Fatal("status")
	}
	if err := AssertNamesFree(f.ctx, f.iam.Store, f.tenantID, []string{"web-01", "10.0.0.5"}, webID); err != nil {
		t.Fatal(err)
	}
	// An authority key or another host's key is never accepted as a host key.
	authority := must(ActiveAuthority(f.ctx, f.iam.Store, f.tenantID, "user"))
	err = AssertHostKeyFree(f.ctx, f.iam.Store, f.tenantID, "spare", sshTestParse(t, authority.Get("publicKey").(string)))
	expectError(t, err, "INVALID_INPUT", "An authority key cannot be a host key")
	webKey := must(StoredHostKey(f.web))
	err = AssertHostKeyFree(f.ctx, f.iam.Store, f.tenantID, "spare", webKey)
	expectError(t, err, "HOST_KEY_IN_USE", "Host web-01 already uses this key")
	if err := AssertHostKeyFree(f.ctx, f.iam.Store, f.tenantID, webID, webKey); err != nil {
		t.Fatal(err)
	}
	err = AssertHostKeyFree(f.ctx, f.iam.Store, f.tenantID, "spare", sshTestParse(t, sshTestPublicKey(t, "sk-ed25519", "")))
	expectError(t, err, "INVALID_INPUT", "Host keys cannot be security keys")
	_, err = StoredHostKey(core.NewObject("name", "x"))
	expectError(t, err, "INVALID_INPUT", `Enter an OpenSSH public key such as "ssh-ed25519 AAAA..."`)

	sshExpectObject(t, must(PrincipalFiles(f.web)), `{"deploy":"deploy@web-01\n","root":"root@web-01\n"}`)
	if must(HostByName(f.ctx, f.iam.Store, f.tenantID, "db-01")).Get("id") != f.db.Get("id") {
		t.Fatal("host by name")
	}
	if host := must(HostByName(f.ctx, f.iam.Store, f.tenantID, "nope")); host != nil {
		t.Fatal("unknown host found")
	}

	for input, want := range map[string]string{" Web-01.Acme.Test ": "web-01.acme.test", "a": "a", "db-01": "db-01", "x.y1": "x.y1"} {
		if got := must(SshHostName(input)); got != want {
			t.Fatalf("SshHostName(%q) = %q", input, got)
		}
	}
	for _, bad := range []any{"-web", "web-", "a..b", "127.1", "web_01", "web/01", "*.acme.test", "", strings.Repeat("a", 129), 3.0} {
		_, err := SshHostName(bad)
		if _, ok := bad.(string); !ok {
			expectError(t, err, "INVALID_INPUT", "Invalid host name")
			continue
		}
		expectError(t, err, "INVALID_INPUT", `Host names use 1-128 lowercase letters, digits, "." or "-"`)
	}

	if labels := must(SshLabels(core.Undefined)); labels.Len() != 0 {
		t.Fatal("undefined labels")
	}
	sshExpectObject(t, must(SshLabels(core.NewObject("environment", "staging", "team_1", ""))), `{"environment":"staging","team_1":""}`)
	for _, testCase := range []struct {
		value   any
		message string
	}{
		{nil, "labels must be an object of strings"},
		{[]any{}, "labels must be an object of strings"},
		{"x", "labels must be an object of strings"},
		{core.NewObject("host", "x"), "Invalid or reserved label name host"},
		{core.NewObject("1abc", "x"), "Invalid or reserved label name 1abc"},
		{core.NewObject("env", 1.0), "Label env must be a string of at most 256 characters"},
		{core.NewObject("env", strings.Repeat("x", 257)), "Label env must be a string of at most 256 characters"},
		{core.NewObject("env", "a\nb"), "Label env must be a string of at most 256 characters"},
	} {
		_, err := SshLabels(testCase.value)
		expectError(t, err, "INVALID_INPUT", testCase.message)
	}
	many := core.NewObject()
	for index := range 33 {
		many.Set("label"+strconv.Itoa(index), "x")
	}
	_, err = SshLabels(many)
	expectError(t, err, "INVALID_INPUT", "A host has at most 32 labels")
}

func TestSshSetsUpAuthoritiesAndOpensThem(t *testing.T) {
	f := newSshFixture(t, nil)
	authorities := must(TenantAuthorities(f.ctx, f.iam.Store, f.tenantID, ""))
	if len(authorities) != 2 || authorities[0].Get("kind") != "user" || authorities[1].Get("kind") != "host" {
		t.Fatalf("authorities %v", authorities)
	}
	for _, authority := range authorities {
		if authority.Get("status") != "active" || authority.Get("algorithm") != "ssh-ed25519" ||
			!strings.HasSuffix(authority.Get("publicKey").(string), " better-iam-"+authority.Get("kind").(string)+"-ca") ||
			authority.Get("activatedAt") != authority.Get("createdAt") {
			t.Fatalf("authority %v", authority)
		}
		// Authority keys are sealed at rest.
		if sealed := authority.Get("keySealed").(string); strings.Contains(sealed, "MC4C") || len(strings.Split(sealed, ".")) != 3 {
			t.Fatalf("sealed key %s", sealed)
		}
		if must(SshFingerprint(sshPublicBlobOf(authority))) != authority.Get("fingerprint") {
			t.Fatal("fingerprint")
		}
	}
	// Setup is idempotent.
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		ensured, err := EnsureAuthorities(ctx, f.server, tx, f.tenantID, "owner")
		if err != nil {
			return err
		}
		if created := ensured.Get("created").([]any); len(created) != 0 {
			t.Fatalf("created %v", created)
		}
		if ensured.Get("user").(*core.Object).Get("id") != authorities[0].Get("id") {
			t.Fatal("user authority")
		}
		return nil
	})
	// A pending authority is listed after the older one of its kind, and users before hosts.
	f.advance(1000)
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		pending, err := CreateAuthority(ctx, f.server, tx, f.tenantID, "user", "pending", "owner")
		if err != nil {
			return err
		}
		if !isUndefined(pending.Get("activatedAt")) {
			t.Fatal("pending authority activated")
		}
		return nil
	})
	authorities = must(TenantAuthorities(f.ctx, f.iam.Store, f.tenantID, ""))
	var order []string
	for _, item := range authorities {
		order = append(order, jsString(item.Get("kind"))+":"+jsString(item.Get("status")))
	}
	if !reflect.DeepEqual(order, []string{"user:active", "user:pending", "host:active"}) {
		t.Fatalf("order %v", order)
	}
	if len(must(TenantAuthorities(f.ctx, f.iam.Store, f.tenantID, "host"))) != 1 {
		t.Fatal("kind filter")
	}
	_, err := ActiveAuthority(f.ctx, f.iam.Store, "elsewhere", "user")
	expectError(t, err, "SSH_NOT_CONFIGURED", "Set up the SSH certificate authority first (ssh.setup)")

	// The opened key signs certificates that verify against the authority.
	_, parsed := f.staging(f.alice)
	if parsed.Get("signatureValid") != true || parsed.Get("signatureKeyFingerprint") != authorities[0].Get("fingerprint") {
		t.Fatalf("certificate %v", parsed)
	}
	if parsed.Get("keyId") != "alice@acme.test ("+jsString(f.alice.Get("id"))+")" {
		t.Fatalf("key ID %v", parsed.Get("keyId"))
	}
	// A key sealed for one authority does not open as another.
	forged := authorities[2].Spread(core.NewObject("keySealed", authorities[0].Get("keySealed")))
	_, err = OpenAuthority(f.server, forged)
	expectError(t, err, "INVALID_SEALED_VALUE", "Invalid sealed value")
}

func TestSshResolvesLoginsAndHostsForTheDecisionEngine(t *testing.T) {
	f := newSshFixture(t, nil)
	resolve := func(resourceType, id string) (*ResolvedResource, error) {
		return ResolveSshResource(f.ctx, f.server, f.iam.Store, core.ResourceRef{TenantID: f.tenantID, Type: resourceType, ID: id})
	}
	login := must(resolve(SshLoginResourceType, "web-01/deploy"))
	if login.Type != "ssh-login" || login.ID != "web-01/deploy" || login.TenantID != f.tenantID {
		t.Fatalf("login %+v", login)
	}
	sshExpectObject(t, login.Attributes, `{"environment":"staging","host":"web-01","login":"deploy"}`)
	host := must(resolve(SshHostResourceType, "db-01"))
	sshExpectObject(t, host.Attributes, `{"environment":"production","host":"db-01"}`)
	for _, testCase := range []struct{ resourceType, id, message string }{
		{SshLoginResourceType, "nope/deploy", "Unknown SSH host"},
		{SshLoginResourceType, "web-01", "Unknown SSH host"},
		{SshLoginResourceType, "/deploy", "Unknown SSH host"},
		{SshHostResourceType, "", "Unknown SSH host"},
		{SshLoginResourceType, "web-01/postgres", "Unknown login on this host"},
		{SshLoginResourceType, "web-01/", "Unknown login on this host"},
	} {
		_, err := resolve(testCase.resourceType, testCase.id)
		expectError(t, err, "NOT_FOUND", testCase.message)
	}
	if other := must(resolve("document", "x")); other != nil {
		t.Fatal("other types resolved")
	}
	// Policies decide on them: alice may log in as deploy on staging hosts only, and forward ports everywhere.
	session := f.sessionOf(f.alice)
	tenant := f.record("tenants", f.tenantID)
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		principal, err := f.server.Principals.CurrentPrincipal(ctx, tx, &Principal{Identity: f.alice, Session: session})
		if err != nil {
			return err
		}
		prepared, err := f.server.Decisions.PrepareDecision(ctx, tx, principal, tenant, SshLoginAction)
		if err != nil {
			return err
		}
		for _, testCase := range []struct {
			resource ResolvedResource
			action   string
			allowed  bool
		}{
			{must(LoginResource(f.web, "deploy")), SshLoginAction, true},
			{must(LoginResource(f.web, "root")), SshLoginAction, false},
			{must(LoginResource(f.db, "postgres")), SshLoginAction, false},
			{must(HostResource(f.db)), "ssh:port-forward", true},
			{must(HostResource(f.db)), "ssh:agent-forward", false},
		} {
			decision, err := DecideOn(prepared, testCase.resource, testCase.action)
			if err != nil {
				return err
			}
			if decision.Allowed != testCase.allowed {
				t.Fatalf("%s %s: %+v", testCase.action, testCase.resource.ID, decision)
			}
		}
		return nil
	})
}

func TestSshTrustBundles(t *testing.T) {
	f := newSshFixture(t, nil)
	authorities := must(TenantAuthorities(f.ctx, f.iam.Store, f.tenantID, ""))
	head := func(authority *core.Object) string { return sshKeyHead(authority.Get("publicKey").(string)) }
	// The public trust lists no names; members' clients trust the host authority for exactly the enrolled names.
	public := f.trust("public")
	if public.Get("knownHosts") != "" || len(public.Get("userAuthorities").([]any)) != 1 || len(public.Get("hostAuthorities").([]any)) != 1 {
		t.Fatalf("public %v", public)
	}
	if text, _, _ := core.Stringify(public); strings.Contains(text, "web-01") || strings.Contains(text, "keySealed") {
		t.Fatalf("public trust leaks %s", text)
	}
	if public.Get("trustedUserCaKeys") != authorities[0].Get("publicKey").(string)+"\n" {
		t.Fatalf("trusted user CA keys %v", public.Get("trustedUserCaKeys"))
	}
	sshExpectObject(t, public.Get("userAuthorities").([]any)[0].(*core.Object),
		`{"id":"`+jsString(authorities[0].Get("id"))+`","status":"active","publicKey":"`+jsString(authorities[0].Get("publicKey"))+`","fingerprint":"`+jsString(authorities[0].Get("fingerprint"))+`"}`)
	member := f.trust("member")
	want := "@cert-authority 10.0.0.5,db-01,web-01,web-01.acme.test " + head(authorities[1]) + " better-iam:" + f.tenantID + "\n"
	if member.Get("knownHosts") != want {
		t.Fatalf("member known hosts %q, want %q", member.Get("knownHosts"), want)
	}
	// A disabled host's key is published as @revoked to members, and its names leave the trusted list.
	f.patch("sshHosts", jsString(f.db.Get("id")), core.NewObject("status", "disabled"))
	member = f.trust("member")
	wantKnown := "@cert-authority 10.0.0.5,web-01,web-01.acme.test " + head(authorities[1]) + " better-iam:" + f.tenantID + "\n" +
		"@revoked * " + sshKeyHead(f.db.Get("hostKey").(string)) + " better-iam:revoked\n"
	if member.Get("knownHosts") != wantKnown {
		t.Fatalf("member known hosts %q, want %q", member.Get("knownHosts"), wantKnown)
	}
	// Configured patterns replace the enrolled names, for everyone.
	f.seed("sshSettings", DefaultSshSettings(f.tenantID, must(AssertSsh(f.server))).Spread(core.NewObject("hostPatterns", items("*.acme.test", "web-*"))))
	public = f.trust("public")
	if public.Get("knownHosts") != "@cert-authority *.acme.test,web-* "+head(authorities[1])+" better-iam:"+f.tenantID+"\n" {
		t.Fatalf("patterned known hosts %q", public.Get("knownHosts"))
	}
	// Pending authorities are trusted ahead of a rotation; retired ones nowhere.
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		_, err := CreateAuthority(ctx, f.server, tx, f.tenantID, "user", "pending", "owner")
		return err
	})
	f.patch("sshAuthorities", jsString(authorities[0].Get("id")), core.NewObject("status", "retired"))
	public = f.trust("public")
	if users := public.Get("userAuthorities").([]any); len(users) != 1 || users[0].(*core.Object).Get("status") != "pending" {
		t.Fatalf("user authorities %v", users)
	}
}

func TestSshRevokesCertificatesAndPublishesThemInTheRevocationLists(t *testing.T) {
	f := newSshFixture(t, nil)
	first, _ := f.staging(f.alice)
	second, _ := f.staging(f.alice)
	empty := f.revocationList("")
	if empty.Get("kind") != "user" || empty.Get("revokedCertificates") != 0.0 || empty.Get("tenantActive") != true || empty.Get("version") != 0.0 {
		t.Fatalf("empty %v", empty)
	}
	if data, _ := base64.StdEncoding.DecodeString(empty.Get("krl").(string)); string(data[:8]) != "SSHKRL\n\x00" {
		t.Fatal("KRL magic")
	}
	if live := must(LiveCertificates(f.ctx, f.server, f.iam.Store, core.NewObject("tenantId", f.tenantID))); len(live) != 2 {
		t.Fatalf("live %d", len(live))
	}
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		revoked, err := MarkRevoked(ctx, f.server, tx, first, "revoked", "alice")
		if err != nil {
			return err
		}
		if revoked.Get("revokedAt") != f.now() || revoked.Get("revocationReason") != "revoked" || revoked.Get("revokedBy") != "alice" {
			t.Fatalf("revoked %v", revoked)
		}
		// Idempotent: a revoked record stays as it was.
		again, err := MarkRevoked(ctx, f.server, tx, revoked, "superseded", "someone")
		if err != nil {
			return err
		}
		if again.Get("revocationReason") != "revoked" {
			t.Fatal("revocation overwritten")
		}
		return BumpRevocationVersion(ctx, f.server, tx, f.tenantID)
	})
	list := f.revocationList("user")
	if list.Get("revokedCertificates") != 1.0 || list.Get("version") != 1.0 {
		t.Fatalf("list %v", list)
	}
	if serials := krlSerials(t, list.Get("krl").(string)); len(serials) != 1 || strconv.FormatUint(serials[0], 10) != first.Get("serial") {
		t.Fatalf("serials %v, want %v", serials, first.Get("serial"))
	}
	if live := must(LiveCertificates(f.ctx, f.server, f.iam.Store, core.NewObject("tenantId", f.tenantID, "kind", "user"))); len(live) != 1 || live[0].Get("id") != second.Get("id") {
		t.Fatal("live certificates include a revoked one")
	}
	// Ended sessions take their certificates along before the sweep runs.
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		return tx.Delete(ctx, "sessions", jsString(second.Get("sessionId")))
	})
	if f.revocationList("user").Get("revokedCertificates") != 2.0 {
		t.Fatal("certificate of an ended session not listed")
	}

	// A revoked host certificate and a disabled host's key go to the host list only.
	hostAuthority := must(ActiveAuthority(f.ctx, f.iam.Store, f.tenantID, "host"))
	dbKey := must(StoredHostKey(f.db))
	f.seed("sshCertificates", core.NewObject(
		"id", ID(), "tenantId", f.tenantID, "kind", "host", "serial", "77", "keyId", "host:db-01", "authorityId", hostAuthority.Get("id"),
		"hostId", f.db.Get("id"), "principals", items("db-01"), "extensions", items(), "keyType", dbKey.Get("type"),
		"publicKeyFingerprint", dbKey.Get("fingerprint"), "publicKey", f.db.Get("hostKey"), "validAfter", f.now(),
		"validBefore", f.now()+90*sshDay, "issuedAt", f.now(), "revokedAt", f.now(), "revokedBy", "owner",
		"revocationReason", "host-disabled", "expiresAt", f.now()+180*sshDay,
	))
	f.patch("sshHosts", jsString(f.db.Get("id")), core.NewObject("status", "disabled"))
	users := f.revocationList("user")
	if users.Get("revokedCertificates") != 2.0 || users.Get("revokedHostKeys") != 0.0 {
		t.Fatalf("users %v", users)
	}
	hosts := f.revocationList("host")
	if hosts.Get("kind") != "host" || hosts.Get("revokedCertificates") != 1.0 || hosts.Get("revokedHostKeys") != 1.0 {
		t.Fatalf("hosts %v", hosts)
	}
	if serials := krlSerials(t, hosts.Get("krl").(string)); !reflect.DeepEqual(serials, []uint64{77}) {
		t.Fatalf("host serials %v", serials)
	}
	if !strings.Contains(f.trust("member").Get("knownHosts").(string), "@revoked * ecdsa-sha2-nistp256 ") {
		t.Fatal("revoked host key not published")
	}

	// ssh-keygen refuses exactly the revoked certificates.
	keygen := sshTestKeygen()
	if keygen == "" {
		return
	}
	f.issue(f.alice, false)
	third, _ := f.staging(f.alice)
	directory := t.TempDir()
	krl, _ := base64.StdEncoding.DecodeString(f.revocationList("user").Get("krl").(string))
	files := map[string][]byte{"revoked.krl": krl}
	for name, record := range map[string]*core.Object{"first.pub": first, "second.pub": second, "third.pub": third} {
		files[name] = []byte(f.lines[jsString(record.Get("id"))] + "\n")
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(directory, name), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, revoked := range map[string]bool{"first.pub": true, "second.pub": true, "third.pub": false} {
		status, output := sshTestRunKeygen(keygen, "-Q", "-f", filepath.Join(directory, "revoked.krl"), filepath.Join(directory, name))
		if strings.Contains(output, "REVOKED") != revoked || (!revoked && status != 0) {
			t.Fatalf("%s: %d %s", name, status, output)
		}
	}
}

func TestSshRevokesEveryUserCertificateWhileTheOrganizationIsSuspended(t *testing.T) {
	f := newSshFixture(t, nil)
	f.staging(f.alice)
	f.patch("tenants", f.tenantID, core.NewObject("status", "suspended"))
	list := f.revocationList("")
	if list.Get("tenantActive") != false || list.Get("revokedCertificates") != 1.0 {
		t.Fatalf("list %v", list)
	}
	if active := must(TenantActive(f.ctx, f.server, f.iam.Store, f.record("tenants", f.tenantID))); active {
		t.Fatal("suspended tenant active")
	}
	// The sweep leaves them alone: they return with the organization.
	swept := f.sweep(core.NewObject("tenantId", f.tenantID))
	sshExpectObject(t, swept, `{"examined":1,"revoked":0,"byReason":{}}`)
	f.patch("tenants", f.tenantID, core.NewObject("status", "active"))
	if f.revocationList("").Get("revokedCertificates") != 0.0 {
		t.Fatal("certificates did not return with the organization")
	}
}

func TestSshEndsCertificatesWithTheSessionThatRequestedThem(t *testing.T) {
	f := newSshFixture(t, nil)
	cert, _ := f.staging(f.alice)
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		return tx.Delete(ctx, "sessions", jsString(cert.Get("sessionId")))
	})
	if f.revocationList("").Get("revokedCertificates") != 1.0 {
		t.Fatal("hosts must refuse it before the sweep runs")
	}
	sshExpectObject(t, f.sweep(core.NewObject("tenantId", f.tenantID)), `{"examined":1,"revoked":1,"byReason":{"session-ended":1}}`)
	record := f.record("sshCertificates", jsString(cert.Get("id")))
	if record.Get("revocationReason") != "session-ended" || record.Get("revokedBy") != "deployment-operator" {
		t.Fatalf("record %v", record)
	}
	if must(f.iam.Store.Get(f.ctx, "sshSettings", f.tenantID)).Get("revocationVersion") != 1.0 {
		t.Fatal("revocation version not bumped")
	}
	events := f.find("audit", core.NewObject("tenantId", f.tenantID, "action", "ssh:certificate:revoke"))
	if len(events) != 1 {
		t.Fatalf("audit events %d", len(events))
	}
	sshExpectObject(t, events[0].Get("metadata").(*core.Object),
		`{"reason":"session-ended","serial":"`+jsString(cert.Get("serial"))+`","identityId":"`+jsString(f.alice.Get("id"))+`"}`)
	if events[0].Get("actorId") != "deployment-operator" || events[0].Get("outcome") != "allow" ||
		events[0].Get("resourceId") != "ssh/certificates/"+jsString(cert.Get("id")) {
		t.Fatalf("event %v", events[0])
	}
	// Nothing left to sweep.
	sshExpectObject(t, f.sweep(nil), `{"examined":0,"revoked":0,"byReason":{}}`)
}

func TestSshSweepsCertificatesWhoseHolderLoginOrAccessWentAway(t *testing.T) {
	f := newSshFixture(t, nil)
	bob, _ := f.person(f.tenantID, "bob")
	carol, _ := f.person(f.tenantID, "carol")
	bobBinding := f.bind(f.tenantID, f.roleID, "identity", jsString(bob.Get("id")))
	f.bind(f.tenantID, f.roleID, "identity", jsString(carol.Get("id")))
	aliceCert, _ := f.staging(f.alice)
	bobCert, _ := f.staging(bob)
	sshExpectObject(t, f.sweep(nil), `{"examined":2,"revoked":0,"byReason":{}}`)

	// Alice's account is disabled: the revocation list refuses her certificate even before the sweep runs.
	f.patch("identities", jsString(f.alice.Get("id")), core.NewObject("status", "disabled"))
	if f.revocationList("").Get("revokedCertificates") != 1.0 {
		t.Fatal("disabled holder's certificate not listed")
	}
	// Bob loses the grant: his certificate no longer matches policy.
	f.transact(func(ctx context.Context, tx core.IamStore) error { return tx.Delete(ctx, "bindings", bobBinding) })
	// byReason follows the store's record order (random IDs here), so its members are checked one by one.
	swept := f.sweep(core.NewObject("tenantId", f.tenantID))
	byReason := swept.Get("byReason").(*core.Object)
	if swept.Get("examined") != 2.0 || swept.Get("revoked") != 2.0 || byReason.Len() != 2 ||
		byReason.Get("identity-inactive") != 1.0 || byReason.Get("access-changed") != 1.0 {
		t.Fatalf("swept %v", swept)
	}
	if f.record("sshCertificates", jsString(aliceCert.Get("id"))).Get("revocationReason") != "identity-inactive" ||
		f.record("sshCertificates", jsString(bobCert.Get("id"))).Get("revocationReason") != "access-changed" {
		t.Fatal("revocation reasons")
	}

	// A login removed from the host takes the certificates naming it.
	carolCert, _ := f.staging(carol)
	f.patch("sshHosts", jsString(f.web.Get("id")), core.NewObject("logins", items("root")))
	sshExpectObject(t, f.sweep(core.NewObject("tenantId", f.tenantID)), `{"examined":1,"revoked":1,"byReason":{"access-changed":1}}`)
	if f.record("sshCertificates", jsString(carolCert.Get("id"))).Get("revokedAt") != f.now() {
		t.Fatal("carol's certificate not revoked")
	}

	// Forwarding a certificate carries must stay allowed on every host it names.
	f.patch("sshHosts", jsString(f.web.Get("id")), core.NewObject("logins", items("deploy", "root")))
	agentCert, _ := f.certificate(carol, f.sessionOf(carol), items(core.NewObject("host", "web-01", "logins", items("deploy"))),
		items("permit-agent-forwarding", "permit-pty"))
	portCert, _ := f.staging(carol)
	sshExpectObject(t, f.sweep(nil), `{"examined":2,"revoked":1,"byReason":{"access-changed":1}}`)
	if f.record("sshCertificates", jsString(agentCert.Get("id"))).Get("revocationReason") != "access-changed" ||
		!isUndefined(f.record("sshCertificates", jsString(portCert.Get("id"))).Get("revokedAt")) {
		t.Fatal("forwarding sweep")
	}
	// A deleted host takes nothing away.
	f.transact(func(ctx context.Context, tx core.IamStore) error {
		return tx.Delete(ctx, "sshHosts", jsString(f.web.Get("id")))
	})
	sshExpectObject(t, f.sweep(nil), `{"examined":1,"revoked":0,"byReason":{}}`)
	if version := must(f.iam.Store.Get(f.ctx, "sshSettings", f.tenantID)).Get("revocationVersion"); version != 3.0 {
		t.Fatalf("revocation version %v", version)
	}
}

func TestSshSweepNeverLetsThePlatformRootOverrideKeepAnOrganizationLogin(t *testing.T) {
	f := newSshFixture(t, nil)
	root := f.record("identities", jsString(member(f.root.Get("identity"), "id")))
	cert, _ := f.staging(root)
	sshExpectObject(t, f.sweep(core.NewObject("tenantId", f.tenantID)), `{"examined":1,"revoked":1,"byReason":{"access-changed":1}}`)
	if f.record("sshCertificates", jsString(cert.Get("id"))).Get("revocationReason") != "access-changed" {
		t.Fatal("root override certificate kept")
	}
}

func TestSshCertificateKeyIDs(t *testing.T) {
	for _, testCase := range []struct {
		identity, session *core.Object
		want              string
	}{
		{core.NewObject("id", "i1", "email", "alice@acme.test", "name", "Alice"), core.NewObject(), "alice@acme.test (i1)"},
		{core.NewObject("id", "i1", "email", nil, "name", "Alice"), core.NewObject(), "Alice (i1)"},
		{core.NewObject("id", "i1"), core.NewObject("agentId", "a1", "originalIdentityId", "i0"), "i1 (i1) via agent a1"},
		{core.NewObject("id", "i1"), core.NewObject("originalIdentityId", "i0"), "i1 (i1) via i0"},
		{core.NewObject("id", "i1", "name", "Zoë \"Z\" 😀"), core.NewObject("agentId", 5.0), "Zo_ _Z_ __ (i1)"},
		{core.NewObject("id", "i1", "name", strings.Repeat("x", 300)), core.NewObject(), strings.Repeat("x", 256)},
	} {
		got := must(CertificateKeyID(&Principal{Identity: testCase.identity, Session: testCase.session}))
		if got != testCase.want {
			t.Fatalf("CertificateKeyID = %q, want %q", got, testCase.want)
		}
	}
}

func TestSshPrivateAddressesAndKnownHostsPatterns(t *testing.T) {
	for address, want := range map[string]bool{
		"10.1.2.3": true, "127.0.0.1": true, "172.16.0.1": true, "172.32.0.1": false, "192.168.0.1": true, "169.254.1.1": true,
		"100.64.0.1": true, "100.128.0.1": false, "8.8.8.8": false, "::1": true, "fd00::1": true, "FC12::1": true,
		"fe80::1": true, "febf::1": true, "fec0::1": false, "2001:db8::1": false, "web-01": false,
	} {
		if got := sshPrivateAddress(address); got != want {
			t.Fatalf("sshPrivateAddress(%q) = %v", address, got)
		}
	}
	patterns := []string{"*.Acme.test", "!bastion.acme.test", "10.0.0.?"}
	for name, want := range map[string]bool{"WEB.acme.test": true, "bastion.acme.test": false, "10.0.0.5": true, "10.0.0.50": false, "acme.test": false} {
		if got := sshKnownHostsMatch(patterns, name); got != want {
			t.Fatalf("sshKnownHostsMatch(%q) = %v", name, got)
		}
	}
	if sshKnownHostsMatch(nil, "x") {
		t.Fatal("empty patterns match")
	}
	if !reflect.DeepEqual(SshCollections, []string{"sshSettings", "sshAuthorities", "sshHosts", "sshCertificates"}) {
		t.Fatal("collections")
	}
}
