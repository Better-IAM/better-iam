package server

// Port of tests/ssh.test.ts: the `ssh` API group (SSH certificate authority) end to end, on the directory fixture
// (api_directory_support_test.go) with the in-process key helpers of ssh_ca_test.go.

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// sshIn is a request body for an API call.
func sshIn[T any](pairs ...any) In[T] { return Input[T](core.NewObject(pairs...)) }

// sshScenario is setup(): Acme with a verified domain (acme.test), the SSH CA set up, two enrolled hosts (web-01
// staging, db-01 production), and alice allowed `deploy` on staging hosts with port forwarding everywhere.
type sshScenario struct {
	*directoryFixture
	tenantID     string
	owner        core.CredentialInput
	setupResult  *core.Object
	web          *core.Object
	db           *core.Object
	webSetup     *core.Object
	dbSetup      *core.Object
	webHostKey   string
	alice        *core.Object
	aliceSession core.CredentialInput
	roleID       string
}

func newSshAPIFixture(t *testing.T, ssh *Toggle[SshOptions]) (*directoryFixture, string, core.CredentialInput) {
	t.Helper()
	f := newDirectoryFixture(t, func(options *BetterIamOptions) { options.Ssh = ssh })
	tenantID, owner := f.organization("Acme", "owner@acme.test")
	return f, tenantID, owner
}

func newSshScenario(t *testing.T) *sshScenario {
	t.Helper()
	f, tenantID, owner := newSshAPIFixture(t, On[SshOptions]())
	s := &sshScenario{directoryFixture: f, tenantID: tenantID, owner: owner}
	api := f.iam.API
	claim := answerObject(api.Domains.Add(f.ctx, owner, sshIn[apitypes.DomainsAddInput]("tenantId", tenantID, "domain", "acme.test")))
	record := claim.Get("dnsRecord").(*core.Object)
	f.setDNS(jsString(record.Get("name")), []string{jsString(record.Get("value"))})
	answer(api.Domains.Verify(f.ctx, owner, sshIn[apitypes.DomainsVerifyInput]("tenantId", tenantID, "domainId", claim.Get("id"))))
	s.setupResult = answerObject(api.Ssh.Setup(f.ctx, owner, sshIn[apitypes.SshSetupInput]("tenantId", tenantID)))
	s.web = answerObject(api.Ssh.CreateHost(f.ctx, owner, sshIn[apitypes.SshCreateHostInput](
		"tenantId", tenantID, "name", "web-01", "addresses", items("web-01.acme.test", "10.0.0.5"),
		"logins", items("deploy", "root"), "labels", core.NewObject("environment", "staging"))))
	s.db = answerObject(api.Ssh.CreateHost(f.ctx, owner, sshIn[apitypes.SshCreateHostInput](
		"tenantId", tenantID, "name", "db-01", "logins", items("postgres", "root"),
		"labels", core.NewObject("environment", "production"))))
	s.webHostKey = sshTestPublicKey(t, "ed25519", "root@web-01")
	s.webSetup = answerObject(api.Ssh.EnrollHost(f.ctx, sshIn[apitypes.SshEnrollHostInput]("joinToken", s.web.Get("joinToken"), "publicKey", s.webHostKey)))
	s.dbSetup = answerObject(api.Ssh.EnrollHost(f.ctx, sshIn[apitypes.SshEnrollHostInput]("joinToken", s.db.Get("joinToken"),
		"publicKey", sshTestPublicKey(t, "ecdsa", "root@db-01"))))
	s.alice, s.aliceSession = f.person(tenantID, "alice")
	s.roleID = s.createRole("Staging deploy", obj(t, `{"version":1,"statements":[
		{"effect":"allow","actions":["ssh:login"],"resources":["ssh-login/*/deploy"],"conditions":{"StringEquals":{"resource.environment":"staging"}}},
		{"effect":"allow","actions":["ssh:port-forward"],"resources":["ssh-host/*"]}]}`))
	s.bindRole(s.roleID, jsString(s.alice.Get("id")))
	return s
}

func (s *sshScenario) createRole(name string, document *core.Object) string {
	s.t.Helper()
	role := answerObject(s.iam.API.Roles.Create(s.ctx, s.owner, sshIn[apitypes.RolesCreateInput]("tenantId", s.tenantID, "name", name, "document", document)))
	return jsString(role.Get("id"))
}

func (s *sshScenario) bindRole(roleID, identityID string, extra ...any) {
	s.t.Helper()
	pairs := append([]any{"tenantId", s.tenantID, "roleId", roleID, "subjectType", "identity", "subjectId", identityID}, extra...)
	answer(s.iam.API.Bindings.Create(s.ctx, s.owner, sshIn[apitypes.BindingsCreateInput](pairs...)))
}

func (s *sshScenario) issue(credential core.CredentialInput, pairs ...any) (*core.Object, error) {
	out, err := s.iam.API.Ssh.IssueCertificate(s.ctx, credential, sshIn[apitypes.SshIssueCertificateInput](append([]any{"tenantId", s.tenantID}, pairs...)...))
	if err != nil {
		return nil, err
	}
	return out.Value.(*core.Object), nil
}

func (s *sshScenario) mustIssue(credential core.CredentialInput, pairs ...any) *core.Object {
	s.t.Helper()
	issued, err := s.issue(credential, pairs...)
	if err != nil {
		s.t.Fatalf("issueCertificate: %v", err)
	}
	return issued
}

func (s *sshScenario) revocationList(kind string) *core.Object {
	s.t.Helper()
	pairs := []any{"tenantId", s.tenantID}
	if kind != "" {
		pairs = append(pairs, "kind", kind)
	}
	return answerObject(s.iam.API.Ssh.RevocationList(s.ctx, sshIn[apitypes.SshRevocationListInput](pairs...)))
}

func (s *sshScenario) sync(pairs ...any) (*core.Object, error) {
	out, err := s.iam.API.Ssh.SyncHost(s.ctx, sshIn[apitypes.SshSyncHostInput](pairs...))
	if err != nil {
		return nil, err
	}
	return out.Value.(*core.Object), nil
}

func (s *sshScenario) mustSync(pairs ...any) *core.Object {
	s.t.Helper()
	synced, err := s.sync(pairs...)
	if err != nil {
		s.t.Fatalf("syncHost: %v", err)
	}
	return synced
}

func (s *sshScenario) sweep(input *core.Object) string {
	s.t.Helper()
	return stringify(must(s.iam.Ssh.Sweep(s.ctx, input)))
}

func (s *sshScenario) listCertificates(pairs ...any) *core.Object {
	s.t.Helper()
	return answerObject(s.iam.API.Ssh.ListCertificates(s.ctx, s.owner, sshIn[apitypes.SshListCertificatesInput](append([]any{"tenantId", s.tenantID}, pairs...)...)))
}

// auditOf is the tenant's audit events (as the owner lists them).
func (s *sshScenario) auditOf() []*core.Object {
	s.t.Helper()
	value := answer(s.iam.API.Audit.List(s.ctx, s.owner, sshIn[apitypes.AuditListInput]("tenantId", s.tenantID, "limit", 500.0)))
	if object, ok := value.(*core.Object); ok {
		value = object.Get("events")
	}
	list, _ := value.([]any)
	events := make([]*core.Object, len(list))
	for index, item := range list {
		events[index], _ = item.(*core.Object)
	}
	return events
}

func sshCert(t *testing.T, line any) *core.Object {
	t.Helper()
	parsed, err := ParseSshCertificate(jsString(line))
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return parsed
}

func sshFingerprintOf(t *testing.T, line string) any {
	return sshTestParse(t, line).Get("fingerprint")
}

func expectSshStrings(t *testing.T, value any, want ...string) {
	t.Helper()
	got := sshStrings(value)
	if got == nil {
		got = []string{}
	}
	if want == nil {
		want = []string{}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func expectSshJSON(t *testing.T, value any, want string) {
	t.Helper()
	if got := stringify(value); got != want {
		t.Fatalf("expected %s, got %s", want, got)
	}
}

func TestSshIsOffUnlessTheOptionIsSet(t *testing.T) {
	f, tenantID, owner := newSshAPIFixture(t, nil)
	_, err := f.iam.API.Ssh.Setup(f.ctx, owner, sshIn[apitypes.SshSetupInput]("tenantId", tenantID))
	expectError(t, err, "FEATURE_DISABLED", "The SSH certificate authority is not enabled on this deployment")
	// The ssh-login type and ssh:login are not in the catalog either.
	_, err = f.iam.API.Roles.Create(f.ctx, owner, sshIn[apitypes.RolesCreateInput]("tenantId", tenantID, "name", "x",
		"document", obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["ssh:login"],"resources":["*"]}]}`)))
	if iamError(t, err).Code != "INVALID_ACTION" {
		t.Fatalf("expected INVALID_ACTION, got %v", err)
	}
}

func TestSshSetsUpAuthoritiesEnrollsHostsAndHandsThemWhatSshdNeeds(t *testing.T) {
	s := newSshScenario(t)
	expectSshStrings(t, s.setupResult.Get("created"), "user", "host")
	authorities := s.setupResult.Get("authorities").([]any)
	var kinds []string
	for _, item := range authorities {
		kinds = append(kinds, jsString(member(item, "kind"))+":"+jsString(member(item, "status")))
	}
	if !reflect.DeepEqual(kinds, []string{"user:active", "host:active"}) {
		t.Fatalf("authorities %v", kinds)
	}
	// Setup is idempotent.
	again := answerObject(s.iam.API.Ssh.Setup(s.ctx, s.owner, sshIn[apitypes.SshSetupInput]("tenantId", s.tenantID)))
	expectSshStrings(t, again.Get("created"))
	// Authority keys are sealed at rest and never leave in views.
	for _, row := range s.find("sshAuthorities", core.NewObject("tenantId", s.tenantID)) {
		sealed, ok := row.Get("keySealed").(string)
		if !ok || strings.Contains(sealed, "MC4C") {
			t.Fatalf("keySealed %v", row.Get("keySealed"))
		}
	}
	if strings.Contains(stringify(s.setupResult), "keySealed") {
		t.Fatal("setup leaks keySealed")
	}

	cert := sshCert(t, s.webSetup.Get("certificate"))
	if cert.Get("kind") != float64(SshCertHost) || cert.Get("keyId") != "host:web-01" || cert.Get("signatureValid") != true ||
		cert.Get("publicKeyFingerprint") != sshFingerprintOf(t, s.webHostKey) {
		t.Fatalf("host certificate %s", stringify(cert))
	}
	expectSshStrings(t, cert.Get("principals"), "web-01", "web-01.acme.test", "10.0.0.5")
	hostAuthority := authorities[1].(*core.Object)
	if cert.Get("signatureKeyFingerprint") != hostAuthority.Get("fingerprint") {
		t.Fatal("host certificate not signed by the host authority")
	}
	expectSshJSON(t, s.webSetup.Get("principals"), `{"deploy":"deploy@web-01\n","root":"root@web-01\n"}`)
	userKey := strings.Split(jsString(member(authorities[0], "publicKey")), " ")[1]
	if !strings.Contains(jsString(s.webSetup.Get("trustedUserCaKeys")), userKey) {
		t.Fatal("trustedUserCaKeys misses the user authority")
	}
	sshdConfig := jsString(s.webSetup.Get("sshdConfig"))
	for _, line := range []string{"AuthorizedPrincipalsFile /etc/ssh/better-iam/principals/%u", "HostCertificate /etc/ssh/ssh_host_ed25519_key-cert.pub"} {
		if !strings.Contains(sshdConfig, line) {
			t.Fatalf("sshdConfig misses %q:\n%s", line, sshdConfig)
		}
	}
	var paths []string
	for _, file := range s.webSetup.Get("files").([]any) {
		paths = append(paths, jsString(member(file, "path")))
	}
	for _, path := range []string{"/etc/ssh/better-iam/revoked.krl", "/etc/ssh/sshd_config.d/00-better-iam.conf"} {
		if !containsString(paths, path) {
			t.Fatalf("files miss %s: %v", path, paths)
		}
	}
	expectSshStrings(t, s.webSetup.Get("managedDirectories"), "/etc/ssh/better-iam/principals")
	renewalToken := jsString(s.webSetup.Get("renewalToken"))
	if !strings.HasPrefix(renewalToken, "biam_sshr.") {
		t.Fatalf("renewal token %q", renewalToken)
	}
	if s.webSetup.Get("host").(*core.Object).Has("renewalTokenHash") {
		t.Fatal("host view leaks renewalTokenHash")
	}

	// The join token works once.
	_, err := s.iam.API.Ssh.EnrollHost(s.ctx, sshIn[apitypes.SshEnrollHostInput]("joinToken", s.web.Get("joinToken"), "publicKey", s.webHostKey))
	expectError(t, err, "INVALID_TOKEN", "Invalid or expired host token")
	// Syncing with the renewal token reuses a fresh certificate and hands out the same setup.
	sync := s.mustSync("renewalToken", renewalToken)
	if sync.Get("certificateRenewed") != false || sync.Get("certificate") != s.webSetup.Get("certificate") || sync.Has("renewalToken") {
		t.Fatalf("sync %s", stringify(sync))
	}
	_, err = s.sync("renewalToken", renewalToken+"x")
	expectError(t, err, "INVALID_TOKEN", "Invalid or expired host token")

	// Members' clients trust the host authority for exactly the enrolled names; the public trust lists no names.
	client := answerObject(s.iam.API.Ssh.ClientTrust(s.ctx, s.owner, sshIn[apitypes.SshClientTrustInput]("tenantId", s.tenantID)))
	if !regexp.MustCompile(`^@cert-authority 10\.0\.0\.5,db-01,web-01,web-01\.acme\.test ssh-ed25519 \S+ better-iam:`).MatchString(jsString(client.Get("knownHosts"))) {
		t.Fatalf("knownHosts %q", client.Get("knownHosts"))
	}
	trust := answerObject(s.iam.API.Ssh.Trust(s.ctx, sshIn[apitypes.SshTrustInput]("tenantId", s.tenantID)))
	if len(trust.Get("userAuthorities").([]any)) != 1 || trust.Get("knownHosts") != "" || strings.Contains(stringify(trust), "web-01") {
		t.Fatalf("public trust %s", stringify(trust))
	}
}

func TestSshIssuesCertificatesForExactlyTheHostsAndLoginsPoliciesAllow(t *testing.T) {
	s := newSshScenario(t)
	publicKey := sshTestPublicKey(t, "ed25519", "alice@laptop")
	access := answerObject(s.iam.API.Ssh.MyAccess(s.ctx, s.aliceSession, sshIn[apitypes.SshMyAccessInput]("tenantId", s.tenantID)))
	expectSshJSON(t, access.Get("hosts"), `[{"name":"web-01","addresses":["web-01.acme.test","10.0.0.5"],"labels":{"environment":"staging"},"logins":["deploy"],"forwarding":{"port":true,"agent":false,"x11":false}}]`)

	issued := s.mustIssue(s.aliceSession, "publicKey", publicKey, "ttlMs", sshTestHour, "reason", "deploy release 42")
	expectSshStrings(t, issued.Get("principals"), "deploy@web-01")
	expectSshJSON(t, issued.Get("hosts"), `[{"name":"web-01","addresses":["web-01.acme.test","10.0.0.5"],"logins":["deploy"]}]`)
	if jsNumber(issued.Get("validBefore"))-s.now() != sshTestHour {
		t.Fatalf("validBefore %v", issued.Get("validBefore"))
	}
	cert := sshCert(t, issued.Get("certificate"))
	if cert.Get("kind") != float64(SshCertUser) || cert.Get("signatureValid") != true || cert.Get("publicKeyFingerprint") != sshFingerprintOf(t, publicKey) {
		t.Fatalf("user certificate %s", stringify(cert))
	}
	expectSshStrings(t, cert.Get("principals"), "deploy@web-01")
	expectSshStrings(t, cert.Get("extensions"), "permit-port-forwarding", "permit-pty", "permit-user-rc")
	if cert.Get("keyId") != "alice@acme.test ("+jsString(s.alice.Get("id"))+")" {
		t.Fatalf("keyId %v", cert.Get("keyId"))
	}
	if jsNumber(cert.Get("validBefore")) != float64(int64(jsNumber(issued.Get("validBefore"))/1000)) {
		t.Fatalf("certificate validBefore %v", cert.Get("validBefore"))
	}
	if !strings.Contains(jsString(issued.Get("knownHosts")), "@cert-authority") {
		t.Fatal("knownHosts misses @cert-authority")
	}
	krl, _ := base64.StdEncoding.DecodeString(jsString(issued.Get("revokedHostKeys")))
	if len(krl) < 6 || string(krl[:6]) != "SSHKRL" {
		t.Fatalf("revokedHostKeys %q", issued.Get("revokedHostKeys"))
	}

	// Asking for a host or login outside the grant is refused and audited.
	_, err := s.issue(s.aliceSession, "publicKey", publicKey, "hosts", items("db-01"))
	expectError(t, err, "ACCESS_DENIED", "Access denied")
	_, err = s.issue(s.aliceSession, "publicKey", publicKey, "logins", items("root"))
	expectError(t, err, "ACCESS_DENIED", "Access denied")
	_, err = s.issue(s.aliceSession, "publicKey", publicKey, "hosts", items("nope"))
	expectError(t, err, "NOT_FOUND", "No enrolled host is named nope")
	denied, allowed := false, false
	for _, event := range s.auditOf() {
		if event.Get("action") == "ssh:login" && event.Get("outcome") == "deny" {
			denied = true
		}
		if event.Get("action") == "ssh:certificate:issue" && event.Get("outcome") == "allow" && member(event.Get("metadata"), "reason") == "deploy release 42" {
			allowed = true
		}
	}
	if !denied || !allowed {
		t.Fatalf("audit: denied %v, issued %v", denied, allowed)
	}

	// The owner (every grant) gets every login on every host; lifetimes are capped by the tenant maximum.
	owner := s.mustIssue(s.owner, "publicKey", sshTestPublicKey(t, "rsa", ""), "ttlMs", 20*sshTestHour)
	expectSshStrings(t, owner.Get("principals"), "postgres@db-01", "root@db-01", "deploy@web-01", "root@web-01")
	if jsNumber(owner.Get("validBefore"))-s.now() != 16*sshTestHour {
		t.Fatalf("owner validBefore %v", owner.Get("validBefore"))
	}
	expectSshStrings(t, owner.Get("extensions"), "permit-X11-forwarding", "permit-agent-forwarding", "permit-port-forwarding", "permit-pty", "permit-user-rc")

	// The generic decision API and access reviews see the same resources.
	decision, err := s.iam.Authorize(s.ctx, AuthorizationRequest{Credential: s.aliceSession, TenantID: s.tenantID, Action: "ssh:login",
		Resource: ResourceTarget{Type: "ssh-login", ID: "web-01/deploy"}})
	if err != nil || !decision.Allowed {
		t.Fatalf("authorize: %v %v", decision, err)
	}
	hosts := answer(s.iam.API.Ssh.ListHosts(s.ctx, s.owner, sshIn[apitypes.SshListHostsInput]("tenantId", s.tenantID))).([]any)
	var webID any
	for _, host := range hosts {
		if member(host, "name") == "web-01" {
			webID = member(host, "id")
		}
	}
	who := answerObject(s.iam.API.Ssh.WhoCanLogin(s.ctx, s.owner, sshIn[apitypes.SshWhoCanLoginInput]("tenantId", s.tenantID, "hostId", webID)))
	entries := map[string]string{}
	for _, entry := range who.Get("identities").([]any) {
		entries[jsString(member(entry, "email"))] = stringify(member(entry, "logins"))
	}
	if entries["alice@acme.test"] != `["deploy"]` || entries["owner@acme.test"] != `["deploy","root"]` {
		t.Fatalf("whoCanLogin %s", stringify(who))
	}

	mine := answer(s.iam.API.Ssh.MyCertificates(s.ctx, s.aliceSession, sshIn[apitypes.SshMyCertificatesInput]("tenantId", s.tenantID))).([]any)
	if len(mine) != 1 || member(mine[0], "id") != issued.Get("id") || member(mine[0], "status") != "active" {
		t.Fatalf("myCertificates %s", stringify(mine))
	}
	if mine[0].(*core.Object).Has("sessionId") {
		t.Fatal("certificate view leaks sessionId")
	}
}

func TestSshEnforcesTenantSettings(t *testing.T) {
	s := newSshScenario(t)
	update := func(credential core.CredentialInput, pairs ...any) error {
		_, err := s.iam.API.Ssh.UpdateSettings(s.ctx, credential, sshIn[apitypes.SshUpdateSettingsInput](append([]any{"tenantId", s.tenantID}, pairs...)...))
		return err
	}
	if err := update(s.owner, "requireMfa", true); err != nil {
		t.Fatal(err)
	}
	_, err := s.issue(s.aliceSession, "publicKey", sshTestPublicKey(t, "", ""))
	expectError(t, err, "MFA_REQUIRED", "Sign in with multi-factor authentication to get an SSH certificate")
	if err := update(s.owner, "requireMfa", false, "requireSecurityKey", true, "requireUserVerification", true, "defaultCertificateMs", 600_000.0); err != nil {
		t.Fatal(err)
	}
	_, err = s.issue(s.aliceSession, "publicKey", sshTestPublicKey(t, "", ""))
	expectError(t, err, "SECURITY_KEY_REQUIRED", "This organization certifies only hardware security keys (ed25519-sk or ecdsa-sk)")
	sk := s.mustIssue(s.aliceSession, "publicKey", sshTestPublicKey(t, "sk-ed25519", ""))
	if jsNumber(sk.Get("validBefore"))-s.now() != 600_000 {
		t.Fatalf("validBefore %v", sk.Get("validBefore"))
	}
	parsed := sshCert(t, sk.Get("certificate"))
	if parsed.Get("type") != "sk-ssh-ed25519-cert-v01@openssh.com" {
		t.Fatalf("type %v", parsed.Get("type"))
	}
	expectSshJSON(t, parsed.Get("criticalOptions"), `{"verify-required":""}`)

	if err := update(s.owner, "requireSecurityKey", false, "bindSourceAddress", true); err != nil {
		t.Fatal(err)
	}
	// No client address is known in-process: refused rather than issued unbound.
	_, err = s.issue(s.aliceSession, "publicKey", sshTestPublicKey(t, "", ""))
	expectError(t, err, "SOURCE_ADDRESS_UNKNOWN", "This organization binds certificates to your address, which could not be determined")
	expectError(t, update(s.owner, "defaultCertificateMs", 20*sshTestHour), "INVALID_INPUT", "defaultCertificateMs cannot exceed maxCertificateMs")
	expectError(t, update(s.owner, "hostPatterns", items("bad pattern")), "INVALID_INPUT", "hostPatterns hold known_hosts patterns such as *.corp.example.com")
	// Members without iam:ssh:manage cannot change settings or enroll hosts.
	expectError(t, update(s.aliceSession, "requireMfa", false), "ACCESS_DENIED", "Access denied")
	_, err = s.iam.API.Ssh.CreateHost(s.ctx, s.aliceSession, sshIn[apitypes.SshCreateHostInput]("tenantId", s.tenantID, "name", "x", "logins", items("a")))
	expectError(t, err, "ACCESS_DENIED", "Access denied")
}

func TestSshAPIRevokesCertificatesAndPublishesThemInTheRevocationLists(t *testing.T) {
	s := newSshScenario(t)
	publicKey := sshTestPublicKey(t, "", "")
	first := s.mustIssue(s.aliceSession, "publicKey", publicKey)
	second := s.mustIssue(s.aliceSession, "publicKey", publicKey)
	empty := s.revocationList("")
	if empty.Get("revokedCertificates") != 0.0 {
		t.Fatalf("empty list %s", stringify(empty))
	}

	// A person may revoke their own certificate without any permission.
	revoked := answerObject(s.iam.API.Ssh.RevokeCertificate(s.ctx, s.aliceSession, sshIn[apitypes.SshRevokeCertificateInput]("tenantId", s.tenantID, "certificateId", first.Get("id"))))
	if revoked.Get("status") != "revoked" || revoked.Get("revocationReason") != "revoked" || revoked.Get("revokedBy") != s.alice.Get("id") {
		t.Fatalf("revoked %s", stringify(revoked))
	}
	list := s.revocationList("")
	if list.Get("revokedCertificates") != 1.0 || jsNumber(list.Get("version")) != jsNumber(empty.Get("version"))+1 {
		t.Fatalf("list %s", stringify(list))
	}

	// Disabling the database host revokes its certificate and publishes its key to clients (never in the user list).
	answer(s.iam.API.Ssh.DisableHost(s.ctx, s.owner, sshIn[apitypes.SshDisableHostInput]("tenantId", s.tenantID, "hostId", member(s.db.Get("host"), "id"))))
	users := s.revocationList("")
	if users.Get("kind") != "user" || users.Get("revokedCertificates") != 1.0 || users.Get("revokedHostKeys") != 0.0 {
		t.Fatalf("user list %s", stringify(users))
	}
	hosts := s.revocationList("host")
	if hosts.Get("kind") != "host" || hosts.Get("revokedCertificates") != 1.0 || hosts.Get("revokedHostKeys") != 1.0 {
		t.Fatalf("host list %s", stringify(hosts))
	}
	client := answerObject(s.iam.API.Ssh.ClientTrust(s.ctx, s.aliceSession, sshIn[apitypes.SshClientTrustInput]("tenantId", s.tenantID)))
	if !regexp.MustCompile(`@revoked \* ecdsa-sha2-nistp256 \S+ better-iam:revoked`).MatchString(jsString(client.Get("knownHosts"))) {
		t.Fatalf("knownHosts %q", client.Get("knownHosts"))
	}
	_, err := s.sync("renewalToken", s.dbSetup.Get("renewalToken"))
	expectError(t, err, "INVALID_TOKEN", "Invalid or expired host token")

	if keygen := sshTestKeygen(); keygen != "" {
		dir := t.TempDir()
		write := func(name string, data []byte) string {
			path := filepath.Join(dir, name)
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			return path
		}
		krl, _ := base64.StdEncoding.DecodeString(jsString(users.Get("krl")))
		krlPath := write("revoked.krl", krl)
		firstPath := write("first-cert.pub", []byte(jsString(first.Get("certificate"))+"\n"))
		secondPath := write("second-cert.pub", []byte(jsString(second.Get("certificate"))+"\n"))
		if _, output := sshTestRunKeygen(keygen, "-Q", "-f", krlPath, firstPath); !strings.Contains(output, "REVOKED") {
			t.Fatalf("ssh-keygen -Q first: %s", output)
		}
		if status, output := sshTestRunKeygen(keygen, "-Q", "-f", krlPath, secondPath); status != 0 {
			t.Fatalf("ssh-keygen -Q second: %d %s", status, output)
		}
	}

	// Incident response: everything alice holds, at once.
	expectSshJSON(t, answer(s.iam.API.Ssh.RevokeIdentity(s.ctx, s.owner, sshIn[apitypes.SshRevokeIdentityInput]("tenantId", s.tenantID, "identityId", s.alice.Get("id")))), `{"revoked":1}`)
	// Someone else's certificate needs iam:ssh:manage.
	owners := s.mustIssue(s.owner, "publicKey", publicKey)
	_, err = s.iam.API.Ssh.RevokeCertificate(s.ctx, s.aliceSession, sshIn[apitypes.SshRevokeCertificateInput]("tenantId", s.tenantID, "certificateId", owners.Get("id")))
	expectError(t, err, "ACCESS_DENIED", "Access denied")
	all := s.listCertificates("kind", "user", "status", "revoked")
	if all.Get("total") != 2.0 {
		t.Fatalf("revoked certificates %s", stringify(all))
	}
}

func TestSshEndsCertificatesWithTheSessionOrAPIKeyThatRequestedThem(t *testing.T) {
	s := newSshScenario(t)
	api := s.iam.API
	cert := s.mustIssue(s.aliceSession, "publicKey", sshTestPublicKey(t, "", ""))
	answer(api.Identities.RevokeSessions(s.ctx, s.owner, sshIn[apitypes.IdentitiesRevokeSessionsInput]("tenantId", s.tenantID, "identityId", s.alice.Get("id"))))
	// Hosts refuse it from their next revocation list, before the sweep even runs.
	if count := s.revocationList("").Get("revokedCertificates"); count != 1.0 {
		t.Fatalf("revokedCertificates %v", count)
	}

	robot := answerObject(api.ServiceAccounts.Create(s.ctx, s.owner, sshIn[apitypes.ServiceAccountsCreateInput]("tenantId", s.tenantID, "name", "deployer")))
	s.bindRole(s.roleID, jsString(robot.Get("id")))
	key := answerObject(api.Credentials.Create(s.ctx, s.owner, sshIn[apitypes.CredentialsCreateInput]("tenantId", s.tenantID, "identityId", robot.Get("id"))))
	robotCert := s.mustIssue(core.CredentialInput{Token: jsString(key.Get("token"))}, "publicKey", sshTestPublicKey(t, "", ""))
	expectSshStrings(t, robotCert.Get("principals"), "deploy@web-01")
	answer(api.Credentials.Revoke(s.ctx, s.owner, sshIn[apitypes.CredentialsRevokeInput]("tenantId", s.tenantID, "credentialId", key.Get("credentialId"))))

	if got := s.sweep(core.NewObject("tenantId", s.tenantID)); got != `{"examined":2,"revoked":2,"byReason":{"session-ended":2}}` {
		t.Fatalf("sweep %s", got)
	}
	records := s.listCertificates("kind", "user").Get("certificates").([]any)
	ids := map[any]bool{}
	for _, record := range records {
		ids[member(record, "id")] = true
		if member(record, "revocationReason") != "session-ended" {
			t.Fatalf("record %s", stringify(record))
		}
	}
	if len(records) != 2 || !ids[cert.Get("id")] || !ids[robotCert.Get("id")] {
		t.Fatalf("records %s", stringify(records))
	}
}

func TestSshAPISweepsCertificatesWhoseHolderLoginOrAccessWentAway(t *testing.T) {
	s := newSshScenario(t)
	api := s.iam.API
	bob, bobSession := s.person(s.tenantID, "bob")
	carol, carolSession := s.person(s.tenantID, "carol")
	for _, person := range []*core.Object{bob, carol} {
		s.bindRole(s.roleID, jsString(person.Get("id")))
	}
	aliceCert := s.mustIssue(s.aliceSession, "publicKey", sshTestPublicKey(t, "", ""))
	bobCert := s.mustIssue(bobSession, "publicKey", sshTestPublicKey(t, "", ""))
	if got := s.sweep(nil); got != `{"examined":2,"revoked":0,"byReason":{}}` {
		t.Fatalf("sweep %s", got)
	}

	// Alice's account is disabled: the revocation list refuses her certificate even before the sweep runs.
	answer(api.Identities.SetStatus(s.ctx, s.owner, sshIn[apitypes.IdentitiesSetStatusInput]("tenantId", s.tenantID, "identityId", s.alice.Get("id"), "status", "disabled")))
	if count := s.revocationList("").Get("revokedCertificates"); count != 1.0 {
		t.Fatalf("revokedCertificates %v", count)
	}
	// Bob loses the grant: his certificate no longer matches policy.
	bindings := answer(api.Bindings.List(s.ctx, s.owner, sshIn[apitypes.BindingsListInput]("tenantId", s.tenantID, "subjectId", bob.Get("id"))))
	if object, ok := bindings.(*core.Object); ok {
		bindings = coalesce(object.Get("bindings"), object.Get("items"))
	}
	var bindingID any
	for _, item := range bindings.([]any) {
		if member(item, "roleId") == s.roleID {
			bindingID = member(item, "id")
		}
	}
	answer(api.Bindings.Delete(s.ctx, s.owner, sshIn[apitypes.BindingsDeleteInput]("tenantId", s.tenantID, "bindingId", bindingID)))

	swept := must(s.iam.Ssh.Sweep(s.ctx, core.NewObject("tenantId", s.tenantID)))
	byReason, _ := swept.Get("byReason").(*core.Object)
	if swept.Get("examined") != 2.0 || swept.Get("revoked") != 2.0 || byReason == nil || byReason.Len() != 2 ||
		byReason.Get("identity-inactive") != 1.0 || byReason.Get("access-changed") != 1.0 {
		t.Fatalf("sweep %s", stringify(swept))
	}
	reasons := map[any]any{}
	for _, record := range s.listCertificates("kind", "user").Get("certificates").([]any) {
		reasons[member(record, "id")] = member(record, "revocationReason")
	}
	if len(reasons) != 2 || reasons[aliceCert.Get("id")] != "identity-inactive" || reasons[bobCert.Get("id")] != "access-changed" {
		t.Fatalf("reasons %v", reasons)
	}
	krl := must(s.iam.Ssh.RevocationList(s.ctx, s.tenantID, ""))
	if bytes, _ := krl.Get("bytes").([]byte); len(bytes) < 8 || string(bytes[:8]) != "SSHKRL\n\x00" {
		t.Fatalf("krl bytes %v", krl.Get("bytes"))
	}

	// A login removed from the host takes the certificates naming it (the host deletes its principals file too).
	carolCert := s.mustIssue(carolSession, "publicKey", sshTestPublicKey(t, "", ""))
	answer(api.Ssh.UpdateHost(s.ctx, s.owner, sshIn[apitypes.SshUpdateHostInput]("tenantId", s.tenantID, "hostId", member(s.web.Get("host"), "id"), "logins", items("root"))))
	if got := stringify(must(s.iam.Ssh.Sweep(s.ctx, core.NewObject("tenantId", s.tenantID))).Get("byReason")); got != `{"access-changed":1}` {
		t.Fatalf("byReason %s", got)
	}
	carolRecord := answerObject(api.Ssh.GetCertificate(s.ctx, s.owner, sshIn[apitypes.SshGetCertificateInput]("tenantId", s.tenantID, "certificateId", carolCert.Get("id"))))
	if carolRecord.Get("status") != "revoked" {
		t.Fatalf("carol %s", stringify(carolRecord))
	}
}

func TestSshCapsCertificatesAtTheTimeLimitedGrantsThatAllowThem(t *testing.T) {
	s := newSshScenario(t)
	dave, daveSession := s.person(s.tenantID, "dave")
	roleID := s.createRole("Database on call", obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["ssh:login"],"resources":["ssh-login/db-01/postgres"]}]}`))
	s.bindRole(roleID, jsString(dave.Get("id")), "expiresAt", s.now()+2*sshTestHour)
	cert := s.mustIssue(daveSession, "publicKey", sshTestPublicKey(t, "", ""))
	expectSshStrings(t, cert.Get("principals"), "postgres@db-01")
	if cert.Get("validBefore") != s.now()+2*sshTestHour {
		t.Fatalf("validBefore %v", cert.Get("validBefore"))
	}
	// A standing grant sets no such limit.
	standing := s.mustIssue(s.aliceSession, "publicKey", sshTestPublicKey(t, "", ""))
	if jsNumber(standing.Get("validBefore"))-s.now() != 8*sshTestHour {
		t.Fatalf("standing validBefore %v", standing.Get("validBefore"))
	}
}

func TestSshAPIKeepsTheHostAuthorityToNamesTheOrganizationOwns(t *testing.T) {
	s := newSshScenario(t)
	api := s.iam.API
	update := func(patterns ...any) error {
		_, err := api.Ssh.UpdateSettings(s.ctx, s.owner, sshIn[apitypes.SshUpdateSettingsInput]("tenantId", s.tenantID, "hostPatterns", patterns))
		return err
	}
	// `*` and names outside the verified domains are refused as patterns; patterns must cover every host.
	for _, patterns := range [][]any{items("*"), items("*.github.com"), items("*m")} {
		if err := update(patterns...); err == nil || iamError(t, err).Code != "HOST_OUTSIDE_PATTERNS" {
			t.Fatalf("patterns %v: %v", patterns, err)
		}
	}
	if err := update("*.acme.test"); err == nil || iamError(t, err).Code != "HOST_OUTSIDE_PATTERNS" {
		t.Fatalf("*.acme.test: %v", err)
	}
	if err := update("*.acme.test", "web-*", "db-*", "10.0.0.*", "!bastion.acme.test"); err != nil {
		t.Fatal(err)
	}
	// A name outside them (github.com, a negated name) can never enter a host certificate.
	for _, input := range [][]any{
		{"name", "web-02", "addresses", items("github.com"), "logins", items("deploy")},
		{"name", "bastion.acme.test", "logins", items("ops")},
	} {
		_, err := api.Ssh.CreateHost(s.ctx, s.owner, sshIn[apitypes.SshCreateHostInput](append([]any{"tenantId", s.tenantID}, input...)...))
		if err == nil || iamError(t, err).Code != "HOST_OUTSIDE_PATTERNS" {
			t.Fatalf("createHost %v: %v", input, err)
		}
	}
	_, err := api.Ssh.UpdateHost(s.ctx, s.owner, sshIn[apitypes.SshUpdateHostInput]("tenantId", s.tenantID, "hostId", member(s.web.Get("host"), "id"), "addresses", items("evil.example.com")))
	if err == nil || iamError(t, err).Code != "HOST_OUTSIDE_PATTERNS" {
		t.Fatalf("updateHost: %v", err)
	}
	// Another host's names are taken.
	_, err = api.Ssh.CreateHost(s.ctx, s.owner, sshIn[apitypes.SshCreateHostInput]("tenantId", s.tenantID, "name", "web-02", "addresses", items("web-01.acme.test"), "logins", items("deploy")))
	expectError(t, err, "HOST_NAME_TAKEN", "Host web-01 already uses web-01.acme.test")
	trust := answerObject(api.Ssh.Trust(s.ctx, sshIn[apitypes.SshTrustInput]("tenantId", s.tenantID)))
	if !regexp.MustCompile(`^@cert-authority \*\.acme\.test,web-\*,db-\*,10\.0\.0\.\*,!bastion\.acme\.test `).MatchString(jsString(trust.Get("knownHosts"))) {
		t.Fatalf("knownHosts %q", trust.Get("knownHosts"))
	}
	// An authority key or another host's key is never accepted as a host key.
	spare := answerObject(api.Ssh.CreateHost(s.ctx, s.owner, sshIn[apitypes.SshCreateHostInput]("tenantId", s.tenantID, "name", "web-03", "logins", items("deploy"))))
	authorityKey := member(s.setupResult.Get("authorities").([]any)[0], "publicKey")
	_, err = api.Ssh.EnrollHost(s.ctx, sshIn[apitypes.SshEnrollHostInput]("joinToken", spare.Get("joinToken"), "publicKey", authorityKey))
	expectError(t, err, "INVALID_INPUT", "An authority key cannot be a host key")
	_, err = api.Ssh.EnrollHost(s.ctx, sshIn[apitypes.SshEnrollHostInput]("joinToken", spare.Get("joinToken"), "publicKey", member(s.webSetup.Get("host"), "hostKey")))
	expectError(t, err, "HOST_KEY_IN_USE", "Host web-01 already uses this key")
	var reasons []string
	for _, event := range s.auditOf() {
		if event.Get("action") == "iam:ssh:manage" && event.Get("outcome") == "deny" {
			reasons = append(reasons, jsString(member(event.Get("metadata"), "reason")))
		}
	}
	if !containsString(reasons, "HOST_OUTSIDE_PATTERNS") || !containsString(reasons, "HOST_NAME_TAKEN") {
		t.Fatalf("audited refusals %v", reasons)
	}
}

func TestSshScopesHostAdministrationToTheNamesAnAdministratorManages(t *testing.T) {
	s := newSshScenario(t)
	bob, bobSession := s.person(s.tenantID, "bob")
	roleID := s.createRole("Team A hosts", obj(t, `{"version":1,"statements":[{"effect":"allow","actions":["iam:ssh:manage"],"resources":["iam/ssh/hosts/team-a-*"]}]}`))
	s.bindRole(roleID, jsString(bob.Get("id")))
	create := func(addresses ...any) (Out[apitypes.SshCreateHostOutput], error) {
		return s.iam.API.Ssh.CreateHost(s.ctx, bobSession, sshIn[apitypes.SshCreateHostInput]("tenantId", s.tenantID, "name", "team-a-box", "addresses", addresses, "logins", items("deploy")))
	}
	_, err := create("web-01.acme.test")
	expectError(t, err, "HOST_NAME_TAKEN", "Host web-01 already uses web-01.acme.test")
	_, err = create("payroll.acme.test")
	expectError(t, err, "ACCESS_DENIED", "You may not manage the host name payroll.acme.test")
	created := answerObject(create("team-a-box.acme.test"))
	expectSshStrings(t, member(created.Get("host"), "addresses"), "team-a-box.acme.test")
}

func TestSshRebuildsHostsSupersedesCertificatesRotatesRenewalTokensRefusesKeySwaps(t *testing.T) {
	s := newSshScenario(t)
	api := s.iam.API
	renewalToken := s.webSetup.Get("renewalToken")
	// A renewal token cannot move the host to another key; the attempt is audited.
	_, err := s.sync("renewalToken", renewalToken, "publicKey", sshTestPublicKey(t, "", ""))
	expectError(t, err, "HOST_KEY_CHANGED", "This host key differs from the enrolled one; re-enroll the host with a new join token")
	audited := false
	for _, event := range s.auditOf() {
		if event.Get("action") == "ssh:host:sync" && event.Get("outcome") == "deny" && member(event.Get("metadata"), "reason") == "HOST_KEY_CHANGED" {
			audited = true
		}
	}
	if !audited {
		t.Fatal("the key swap was not audited")
	}
	// A forced renewal is honoured at most hourly, and rotates the renewal token (the old one works until the new is used).
	if s.mustSync("renewalToken", renewalToken, "renew", true).Get("certificateRenewed") != false {
		t.Fatal("renewed within the hour")
	}
	s.advance(int64(2 * sshTestHour))
	renewed := s.mustSync("renewalToken", renewalToken, "renew", true)
	if renewed.Get("certificateRenewed") != true || !strings.HasPrefix(jsString(renewed.Get("renewalToken")), "biam_sshr.") {
		t.Fatalf("renewed %s", stringify(renewed))
	}
	if s.mustSync("renewalToken", renewalToken).Get("certificateRenewed") != false {
		t.Fatal("the old token renewed again")
	}
	s.mustSync("renewalToken", renewed.Get("renewalToken"))
	_, err = s.sync("renewalToken", renewalToken)
	expectError(t, err, "INVALID_TOKEN", "Invalid or expired host token")
	// Re-enrolling a rebuilt host takes a fresh join token; every earlier certificate is superseded and the old key
	// is published to clients as revoked.
	webID := member(s.web.Get("host"), "id")
	reset := answerObject(api.Ssh.ResetJoinToken(s.ctx, s.owner, sshIn[apitypes.SshResetJoinTokenInput]("tenantId", s.tenantID, "hostId", webID)))
	rebuilt := answerObject(api.Ssh.EnrollHost(s.ctx, sshIn[apitypes.SshEnrollHostInput]("joinToken", reset.Get("joinToken"), "publicKey", sshTestPublicKey(t, "", ""))))
	_, err = s.sync("renewalToken", renewed.Get("renewalToken"))
	expectError(t, err, "INVALID_TOKEN", "Invalid or expired host token")
	if s.mustSync("renewalToken", rebuilt.Get("renewalToken")).Get("certificateRenewed") != false {
		t.Fatal("a fresh certificate was renewed")
	}
	hostCerts := s.listCertificates("kind", "host", "hostId", webID).Get("certificates").([]any)
	active := 0
	var reasons []string
	for _, record := range hostCerts {
		switch member(record, "status") {
		case "active":
			active++
		case "revoked":
			reasons = append(reasons, jsString(member(record, "revocationReason")))
		}
	}
	if active != 1 || !reflect.DeepEqual(reasons, []string{"superseded", "superseded"}) {
		t.Fatalf("host certificates %s", stringify(hostCerts))
	}
	client := answerObject(api.Ssh.ClientTrust(s.ctx, s.owner, sshIn[apitypes.SshClientTrustInput]("tenantId", s.tenantID)))
	knownHosts := jsString(client.Get("knownHosts"))
	oldKey := strings.Split(jsString(member(s.webSetup.Get("host"), "hostKey")), " ")
	if !strings.Contains(knownHosts, "@revoked * "+oldKey[0]+" "+oldKey[1]) {
		t.Fatalf("knownHosts misses the old key: %s", knownHosts)
	}
	if strings.Contains(knownHosts, strings.Split(jsString(member(rebuilt.Get("host"), "hostKey")), " ")[1]) {
		t.Fatalf("knownHosts names the new key: %s", knownHosts)
	}
}

func TestSshAPIRevokesEveryUserCertificateWhileTheOrganizationIsSuspended(t *testing.T) {
	s := newSshScenario(t)
	s.mustIssue(s.aliceSession, "publicKey", sshTestPublicKey(t, "", ""))
	answer(s.iam.API.Tenants.SetStatus(s.ctx, s.rootCred, sshIn[apitypes.TenantsSetStatusInput]("tenantId", s.tenantID, "status", "suspended")))
	list := s.revocationList("")
	if list.Get("tenantActive") != false || list.Get("revokedCertificates") != 1.0 {
		t.Fatalf("list %s", stringify(list))
	}
	// Hosts still sync (and fetch that list), without new certificates.
	sync := s.mustSync("renewalToken", s.webSetup.Get("renewalToken"), "renew", true)
	if sync.Get("certificateRenewed") != false || sync.Get("revocationList") != list.Get("krl") {
		t.Fatalf("sync %s", stringify(sync))
	}
}

func TestSshRotatesAuthoritiesWithoutBreakingCertificatesAlreadyIssued(t *testing.T) {
	s := newSshScenario(t)
	api := s.iam.API
	before := s.mustIssue(s.aliceSession, "publicKey", sshTestPublicKey(t, "", ""))
	rotate := func(credential core.CredentialInput, pairs ...any) (*core.Object, error) {
		out, err := api.Ssh.RotateAuthority(s.ctx, credential, sshIn[apitypes.SshRotateAuthorityInput](append([]any{"tenantId", s.tenantID}, pairs...)...))
		if err != nil {
			return nil, err
		}
		return out.Value.(*core.Object), nil
	}
	pending := must(rotate(s.owner, "kind", "user"))
	if pending.Get("status") != "pending" {
		t.Fatalf("pending %s", stringify(pending))
	}
	// Published ahead of signing: hosts trust both keys from their next sync.
	sync := s.mustSync("renewalToken", s.webSetup.Get("renewalToken"))
	if lines := strings.Split(core.JSTrim(jsString(sync.Get("trustedUserCaKeys"))), "\n"); len(lines) != 2 {
		t.Fatalf("trustedUserCaKeys %q", sync.Get("trustedUserCaKeys"))
	}
	_, err := rotate(s.owner, "kind", "user")
	expectError(t, err, "CONFLICT", "A rotation is already pending; activate or retire it first")
	answer(api.Ssh.ActivateAuthority(s.ctx, s.owner, sshIn[apitypes.SshActivateAuthorityInput]("tenantId", s.tenantID, "authorityId", pending.Get("id"))))
	after := s.mustIssue(s.aliceSession, "publicKey", sshTestPublicKey(t, "", ""))
	if sshCert(t, after.Get("certificate")).Get("signatureKeyFingerprint") != pending.Get("fingerprint") {
		t.Fatal("the new authority does not sign")
	}
	old := s.setupResult.Get("authorities").([]any)[0].(*core.Object)
	if sshCert(t, before.Get("certificate")).Get("signatureKeyFingerprint") != old.Get("fingerprint") {
		t.Fatal("the earlier certificate is not the old authority's")
	}
	// The previous key stays trusted while its certificates live; retiring it early needs force.
	_, err = api.Ssh.RetireAuthority(s.ctx, s.owner, sshIn[apitypes.SshRetireAuthorityInput]("tenantId", s.tenantID, "authorityId", old.Get("id")))
	expectError(t, err, "RESOURCE_IN_USE", "1 certificates signed by this authority are still valid")
	s.advance(int64(17 * sshTestHour))
	owner := s.ownerSignIn(s.tenantID)
	retired := answerObject(api.Ssh.RetireAuthority(s.ctx, owner, sshIn[apitypes.SshRetireAuthorityInput]("tenantId", s.tenantID, "authorityId", old.Get("id"))))
	if retired.Get("status") != "retired" {
		t.Fatalf("retired %s", stringify(retired))
	}
	trust := answerObject(api.Ssh.Trust(s.ctx, sshIn[apitypes.SshTrustInput]("tenantId", s.tenantID)))
	userAuthorities := trust.Get("userAuthorities").([]any)
	if len(userAuthorities) != 1 || member(userAuthorities[0], "id") != pending.Get("id") {
		t.Fatalf("userAuthorities %s", stringify(userAuthorities))
	}

	// A host rotation re-issues host certificates at the next sync.
	hostPending := must(rotate(owner, "kind", "host", "activate", true))
	renewed := s.mustSync("renewalToken", s.webSetup.Get("renewalToken"))
	if renewed.Get("certificateRenewed") != true || sshCert(t, renewed.Get("certificate")).Get("signatureKeyFingerprint") != hostPending.Get("fingerprint") {
		t.Fatalf("renewed %s", stringify(renewed))
	}
}

func TestSshNeverLetsThePlatformRootOverrideOpenAnOrganizationHost(t *testing.T) {
	s := newSshScenario(t)
	_, err := s.issue(s.rootCred, "publicKey", sshTestPublicKey(t, "", ""))
	expectError(t, err, "ROOT_SSH_RESTRICTED", "Platform administrators need a role in this organization to open its hosts")
	access := answerObject(s.iam.API.Ssh.MyAccess(s.ctx, s.rootCred, sshIn[apitypes.SshMyAccessInput]("tenantId", s.tenantID)))
	expectSshJSON(t, access.Get("hosts"), `[]`)
	// Root still administers the authority (audited as a root override).
	status := answerObject(s.iam.API.Ssh.Status(s.ctx, s.rootCred, sshIn[apitypes.SshStatusInput]("tenantId", s.tenantID)))
	if member(status.Get("hosts"), "enrolled") != 2.0 {
		t.Fatalf("status %s", stringify(status))
	}
}

func TestSshServesHostsOverHTTPWithoutASessionAndMembersWithABearerToken(t *testing.T) {
	s := newSshScenario(t)
	call := func(path string, payload *core.Object, token string) *Response {
		headers := map[string]string{}
		if token != "" {
			headers["authorization"] = "Bearer " + token
		}
		return s.post(directoryOrigin, "ssh/"+path, stringify(payload), headers)
	}
	host := answerObject(s.iam.API.Ssh.CreateHost(s.ctx, s.owner, sshIn[apitypes.SshCreateHostInput]("tenantId", s.tenantID, "name", "ci-runner", "logins", items("ci"))))
	// A host enrolls with plain JSON (curl with the usual X-Better-IAM header), the join token its only credential.
	enrolled := call("enrollHost", body("joinToken", host.Get("joinToken"), "publicKey", sshTestPublicKey(t, "", "")), "")
	if enrolled.Status != 200 {
		t.Fatalf("enrollHost %d %s", enrolled.Status, enrolled.Body)
	}
	setup := jsonBody(t, enrolled).Get("data").(*core.Object)
	if !strings.HasPrefix(jsString(setup.Get("certificate")), "ssh-ed25519-cert-v01@openssh.com ") {
		t.Fatalf("certificate %v", setup.Get("certificate"))
	}
	if synced := call("syncHost", body("renewalToken", setup.Get("renewalToken")), ""); synced.Status != 200 {
		t.Fatalf("syncHost %d %s", synced.Status, synced.Body)
	}
	krl := call("revocationList", body("tenantId", s.tenantID), "")
	if !strings.HasPrefix(jsString(member(jsonBody(t, krl).Get("data"), "krl")), "U1NIS1JM") {
		t.Fatalf("revocationList %s", krl.Body)
	}
	// Members call issueCertificate with their credential; without one it is refused.
	issued := call("issueCertificate", body("tenantId", s.tenantID, "publicKey", sshTestPublicKey(t, "", ""), "hosts", items("web-01")), s.aliceSession.Token)
	if issued.Status != 200 {
		t.Fatalf("issueCertificate %d %s", issued.Status, issued.Body)
	}
	expectSshStrings(t, member(jsonBody(t, issued).Get("data"), "principals"), "deploy@web-01")
	if anonymous := call("issueCertificate", body("tenantId", s.tenantID, "publicKey", sshTestPublicKey(t, "", "")), ""); anonymous.Status != 401 {
		t.Fatalf("anonymous %d", anonymous.Status)
	}
	if badToken := call("syncHost", body("renewalToken", "biam_sshr.x.y"), ""); badToken.Status != 401 {
		t.Fatalf("bad token %d", badToken.Status)
	}
}

func TestSshProducesAUserCertificateSshKeygenReads(t *testing.T) {
	keygen := sshTestKeygen()
	if keygen == "" {
		t.Skip("ssh-keygen is not installed")
	}
	s := newSshScenario(t)
	issued := s.mustIssue(s.aliceSession, "publicKey", sshTestPublicKey(t, "ecdsa", ""))
	path := filepath.Join(t.TempDir(), "id-cert.pub")
	if err := os.WriteFile(path, []byte(jsString(issued.Get("certificate"))+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	status, output := sshTestRunKeygen(keygen, "-L", "-f", path)
	if status != 0 {
		t.Fatalf("ssh-keygen -L: %d %s", status, output)
	}
	for _, fragment := range []string{"user certificate", "deploy@web-01", "permit-port-forwarding"} {
		if !strings.Contains(output, fragment) {
			t.Fatalf("ssh-keygen -L misses %q:\n%s", fragment, output)
		}
	}
	if strings.Contains(output, "permit-agent-forwarding") {
		t.Fatalf("ssh-keygen -L lists agent forwarding:\n%s", output)
	}
}
