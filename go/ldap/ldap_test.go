package ldap

// Port of tests/ldap.test.ts: LDAP primitives and the directory gateway over a composed server.

import (
	"context"
	"errors"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/adapters/sqlite"
	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

const base = "dc=acme,dc=test"

// done are the final answers: bind, search done, modify, add, delete, modify DN, compare, extended.
var done = map[int]bool{0x61: true, 0x65: true, 0x67: true, 0x69: true, 0x6b: true, 0x6d: true, 0x6f: true, 0x78: true}

type answer struct {
	*LdapResponse
	entries []*LdapResponse
}

// ldapClient is a minimal LDAP client over TCP: one call at a time, answers collected by message ID.
type ldapClient struct {
	t        *testing.T
	conn     net.Conn
	mu       sync.Mutex
	received []*LdapResponse
	closed   bool
	signal   chan struct{}
	next     int64
}

func dial(t *testing.T, port int) *ldapClient {
	t.Helper()
	conn, err := net.Dial("tcp", "127.0.0.1:"+strconv.Itoa(port))
	if err != nil {
		t.Fatal(err)
	}
	c := &ldapClient{t: t, conn: conn, signal: make(chan struct{}, 1), next: 1}
	go func() {
		var buffer []byte
		chunk := make([]byte, 65536)
		for {
			n, err := conn.Read(chunk)
			buffer = append(buffer, chunk[:n]...)
			for {
				item, _ := ReadElement(buffer, 0, 1<<24)
				if item == nil {
					break
				}
				buffer = buffer[item.Size:]
				if response, err := DecodeResponse(item); err == nil {
					c.mu.Lock()
					c.received = append(c.received, response)
					c.mu.Unlock()
				}
			}
			if err != nil {
				c.mu.Lock()
				c.closed = true
				c.mu.Unlock()
			}
			select {
			case c.signal <- struct{}{}:
			default:
			}
			if err != nil {
				return
			}
		}
	}()
	return c
}

func (c *ldapClient) call(encode func(id int64) []byte) answer {
	c.t.Helper()
	id := c.next
	c.next++
	if _, err := c.conn.Write(encode(id)); err != nil {
		c.t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		c.mu.Lock()
		var final *LdapResponse
		var entries []*LdapResponse
		for _, response := range c.received {
			if response.ID == id && response.Tag == 0x64 {
				entries = append(entries, response)
			}
			if response.ID == id && done[response.Tag] && final == nil {
				final = response
			}
		}
		closed := c.closed
		var notice string
		for _, response := range c.received {
			if response.ID == 0 {
				notice = response.Message
			}
		}
		c.mu.Unlock()
		if final != nil {
			return answer{final, entries}
		}
		if closed {
			c.t.Fatalf("connection closed: %s", notice)
		}
		if time.Now().After(deadline) {
			c.t.Fatalf("no answer to request %d", id)
		}
		select {
		case <-c.signal:
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (c *ldapClient) bind(name, password string) answer {
	return c.call(func(id int64) []byte { return EncodeBind(id, name, password) })
}

func (c *ldapClient) search(base, filter string, scope SearchScope, attributes []string, controls []byte) answer {
	c.t.Helper()
	parsed, err := ParseFilter(filter)
	if err != nil {
		c.t.Fatal(err)
	}
	return c.call(func(id int64) []byte {
		return EncodeSearch(id, SearchOptions{Base: base, Scope: scope, Filter: parsed, Attributes: attributes}, controls)
	})
}

func (c *ldapClient) compare(entry, attribute, value string) answer {
	return c.call(func(id int64) []byte { return EncodeCompare(id, entry, attribute, value) })
}

func (c *ldapClient) whoAmI() answer {
	return c.call(func(id int64) []byte { return EncodeExtended(id, OIDWhoAmI, nil) })
}

// remove sends a delete request (`[APPLICATION 10]`), which a read-only directory refuses.
func (c *ldapClient) remove(dn string) answer {
	return c.call(func(id int64) []byte {
		body := append([]byte{0x02, 0x01, byte(id), 0x4a, byte(len(dn))}, dn...)
		return append([]byte{0x30, byte(len(body))}, body...)
	})
}

func (c *ldapClient) close() { _ = c.conn.Close() }

// --- the organization fixture (tests/support/organization.ts) ------------------------------------------------------

type orgFixture struct {
	t        *testing.T
	ctx      context.Context
	iam      *server.BetterIam
	clock    *atomic.Int64
	tenantID string
	owner    core.CredentialInput
}

func member(value any, key string) any {
	if object, ok := value.(*core.Object); ok && object != nil {
		return object.Get(key)
	}
	return core.Undefined
}

func str(value any) string {
	text, _ := value.(string)
	return text
}

func newOrgFixture(t *testing.T) *orgFixture {
	t.Helper()
	store, err := sqlite.New(sqlite.Options{Filename: ":memory:"})
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Migrate(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close(context.Background()) })
	clock := &atomic.Int64{}
	clock.Store(time.Now().UnixMilli())
	week := int64(7 * 86_400_000)
	now := func() int64 { return clock.Load() }
	iam, err := server.New(&server.BetterIamOptions{
		Database: store, Secret: "organization-fixture-secret-with-32-characters", BaseURL: "http://localhost:3000",
		Permissions:    &core.PermissionsConfig{Actions: []string{"documents:read", "documents:write"}},
		WallClock:      now,
		Authentication: &auth.Options{Now: now, SessionLifetimeMs: &week, SessionIdleTimeoutMs: &week},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(iam.Close)
	f := &orgFixture{t: t, ctx: context.Background(), iam: iam, clock: clock}
	if err := iam.Initialize(f.ctx); err != nil {
		t.Fatal(err)
	}
	root, err := iam.Bootstrap(f.ctx, core.NewObject("email", "root@example.test", "name", "Root", "password", "a strong root test password"))
	if err != nil {
		t.Fatal(err)
	}
	rootTenantID := str(member(root.Get("tenant"), "id"))
	rootID := str(member(root.Get("identity"), "id"))
	err = iam.Store.Transaction(f.ctx, func(ctx context.Context, tx core.IamStore) error {
		authorities, err := tx.Find(ctx, "grantAuthorities", core.NewObject("tenantId", rootTenantID, "identityId", rootID), nil)
		if err != nil {
			return err
		}
		if len(authorities) == 0 {
			return errors.New("root has no grant authority")
		}
		f.tenantID = server.ID()
		realm := core.NewObject("id", f.tenantID, "tenantId", f.tenantID, "name", "Acme", "type", "organization",
			"parentId", rootTenantID, "status", "active", "createdAt", float64(now()))
		if _, err := tx.Insert(ctx, "tenants", realm); err != nil {
			return err
		}
		authority, err := tx.Insert(ctx, "grantAuthorities", core.NewObject("id", server.ID(), "tenantId", f.tenantID,
			"identityId", "pending", "parentAuthorityId", authorities[0].Get("id"), "ceiling", server.All(), "revoked", false))
		if err != nil {
			return err
		}
		owner, err := iam.Auth.CreateIdentity(ctx, tx, auth.CreateIdentityInput{TenantID: f.tenantID, Email: "owner@acme.test",
			Name: "Owner", Password: "a strong tenant owner password", HasPassword: true, Owner: true, EmailVerified: true})
		if err != nil {
			return err
		}
		return iam.Context.OwnerSetup(ctx, tx, realm, owner, authority)
	})
	if err != nil {
		t.Fatal(err)
	}
	f.owner = f.signInAs("owner@acme.test", "a strong tenant owner password")
	return f
}

func (f *orgFixture) signInAs(email, password string) core.CredentialInput {
	f.t.Helper()
	out, err := f.iam.API.Auth.SignIn(f.ctx, server.Input[apitypes.AuthSignInInput](core.NewObject("tenantId", f.tenantID,
		"email", email, "password", password)))
	if err != nil {
		f.t.Fatal(err)
	}
	token, ok := member(out.Value, "token").(string)
	if !ok {
		f.t.Fatalf("unexpected sign-in answer %v", core.MustStringify(out.Value))
	}
	return core.CredentialInput{Token: token}
}

func ok[T any](t *testing.T) func(server.Out[T], error) any {
	return func(out server.Out[T], err error) any {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		model, err := server.ToModel(out.Value)
		if err != nil {
			t.Fatal(err)
		}
		return model
	}
}

func (f *orgFixture) member(name string) any {
	return ok[apitypes.IdentitiesCreateOutput](f.t)(f.iam.API.Identities.Create(f.ctx, f.owner, server.Input[apitypes.IdentitiesCreateInput](core.NewObject(
		"tenantId", f.tenantID, "email", name+"@acme.test", "name", name, "password", "a strong "+name+" password"))))
}

type gatewaySetup struct {
	f        *orgFixture
	key      string
	settings any
	port     int
}

// setup is Acme publishing its directory under dc=acme,dc=test, with a directory reader service account and a
// gateway.
func setup(t *testing.T) *gatewaySetup {
	f := newOrgFixture(t)
	alice := f.member("alice")
	f.member("bob")
	engineering := ok[apitypes.GroupsCreateOutput](t)(f.iam.API.Groups.Create(f.ctx, f.owner, server.Input[apitypes.GroupsCreateInput](
		core.NewObject("tenantId", f.tenantID, "name", "Engineering"))))
	ok[apitypes.GroupsAddMembersOutput](t)(f.iam.API.Groups.AddMembers(f.ctx, f.owner, server.Input[apitypes.GroupsAddMembersInput](
		core.NewObject("tenantId", f.tenantID, "groupId", member(engineering, "id"), "identityIds", []any{member(alice, "id")}))))
	reader := ok[apitypes.ServiceAccountsCreateOutput](t)(f.iam.API.ServiceAccounts.Create(f.ctx, f.owner, server.Input[apitypes.ServiceAccountsCreateInput](
		core.NewObject("tenantId", f.tenantID, "name", "vpn"))))
	role := ok[apitypes.RolesCreateOutput](t)(f.iam.API.Roles.Create(f.ctx, f.owner, server.Input[apitypes.RolesCreateInput](
		core.NewObject("tenantId", f.tenantID, "name", "Directory readers", "document", core.NewObject("version", 1.0,
			"statements", []any{core.NewObject("effect", "allow", "actions", []any{"iam:ldap:read"}, "resources", []any{"*"})})))))
	ok[apitypes.BindingsCreateOutput](t)(f.iam.API.Bindings.Create(f.ctx, f.owner, server.Input[apitypes.BindingsCreateInput](
		core.NewObject("tenantId", f.tenantID, "roleId", member(role, "id"), "subjectType", "identity", "subjectId", member(reader, "id")))))
	key := ok[apitypes.CredentialsCreateOutput](t)(f.iam.API.Credentials.Create(f.ctx, f.owner, server.Input[apitypes.CredentialsCreateInput](
		core.NewObject("tenantId", f.tenantID, "identityId", member(reader, "id")))))
	settings := ok[apitypes.LdapUpdateSettingsOutput](t)(f.iam.API.Ldap.UpdateSettings(f.ctx, f.owner, server.Input[apitypes.LdapUpdateSettingsInput](
		core.NewObject("tenantId", f.tenantID, "enabled", true, "baseDn", "dc=acme, dc=test", "includeServiceAccounts", true))))
	cacheMs := int64(0)
	gateway := CreateLdapServer(LdapServerOptions{Iam: FromBetterIam(f.iam), CacheMs: &cacheMs})
	t.Cleanup(func() { _ = gateway.Close() })
	address, err := gateway.Listen(0, "")
	if err != nil {
		t.Fatal(err)
	}
	return &gatewaySetup{f: f, key: str(member(key, "token")), settings: settings, port: address.Port}
}

func TestLdapPrimitivesNormalizeAndEscapeDNsAndMatchFilters(t *testing.T) {
	if normalized, _ := NormalizeDn("UID=Alice,  OU=People , DC=Acme,DC=Test"); normalized != "uid=alice,ou=people,dc=acme,dc=test" {
		t.Fatalf("normalized %q", normalized)
	}
	if escaped := EscapeDnValue("Smith, John+1"); escaped != `Smith\, John\+1` {
		t.Fatalf("escaped %q", escaped)
	}
	if under, _ := IsUnder("uid=a,ou=people,dc=acme,dc=test", "dc=acme,dc=test"); !under {
		t.Fatal("uid=a should be under dc=acme,dc=test")
	}
	if under, _ := IsUnder("dc=acme,dc=test", "ou=people,dc=acme,dc=test"); under {
		t.Fatal("the base is not under its child")
	}
	entry := EntryAttributes{"objectclass": {"top", "inetOrgPerson"}, "mail": {"alice@acme.test"}, "cn": {"Alice Liddell"}}
	match := func(text string) bool {
		filter, err := ParseFilter(text)
		if err != nil {
			t.Fatal(err)
		}
		return MatchFilter(filter, entry)
	}
	if !match("(&(objectClass=inetOrgPerson)(mail=ALICE@acme.test))") || match("(|(cn=Bob*)(!(mail=*)))") ||
		!match("(cn=*Lid*)") || match("(title=*)") {
		t.Fatal("filter evaluation differs")
	}
	if _, err := ParseFilter("(cn=unbalanced"); err == nil {
		t.Fatal("unbalanced filter parsed")
	}
	// A DN escape that hides a separator stays inside the value.
	if under, _ := IsUnder(`cn=a\,ou=people,dc=x`, "ou=people,dc=x"); under {
		t.Fatal("an escaped comma is not a separator")
	}
	// BER round trip of a filter.
	filter, _ := ParseFilter(`(&(objectClass=person)(|(uid=al\2aice)(mail=*@acme.test))(!(cn>=m)))`)
	encoded := EncodeFilter(filter)
	element, err := ReadElement(encoded, 0, len(encoded))
	if err != nil || element == nil {
		t.Fatal(err)
	}
	decoded, err := DecodeFilter(element)
	if err != nil || string(EncodeFilter(decoded)) != string(encoded) || decoded.Filters[1].Filters[0].Value != "al*ice" {
		t.Fatalf("filter round trip: %v", err)
	}
}

func TestLdapGatewayLetsPeopleAndServiceAccountsBindAndServesTheDirectoryEachMayRead(t *testing.T) {
	s := setup(t)
	f := s.f
	if member(s.settings, "enabled") != true || member(s.settings, "baseDn") != base || member(s.settings, "uid") != "email" ||
		core.MustStringify(member(s.settings, "attributes")) != "[]" {
		t.Fatalf("settings %v", core.MustStringify(s.settings))
	}
	client := dial(t, s.port)
	defer client.close()

	// Before a bind: the root DSE only.
	dse := client.search("", "(objectClass=*)", "base", nil, nil)
	if len(dse.entries) != 1 || strings.Join(dse.entries[0].Attributes["supportedLDAPVersion"], ",") != "3" {
		t.Fatalf("root DSE %+v", dse.entries)
	}
	if code := client.search(base, "(objectClass=*)", "", nil, nil).Code; code != ResultInsufficientAccessRights {
		t.Fatalf("unbound search %d", code)
	}

	// People bind with their password, under the uid the organization chose.
	alice := "uid=alice@acme.test,ou=people," + base
	if code := client.bind(alice, "wrong password").Code; code != ResultInvalidCredentials {
		t.Fatalf("wrong password %d", code)
	}
	if code := client.bind(alice, "").Code; code != ResultUnwillingToPerform {
		t.Fatalf("empty password %d", code)
	}
	if code := client.bind("uid=nobody@acme.test,ou=people,"+base, "x").Code; code != ResultInvalidCredentials {
		t.Fatalf("nobody %d", code)
	}
	// DNs compare without regard to case.
	if response := client.bind(strings.ToUpper(alice), "a strong alice password"); response.Code != ResultSuccess {
		t.Fatalf("alice bind %d %s", response.Code, response.Message)
	}
	if value := string(client.whoAmI().ResponseValue); value != "dn:"+strings.ToUpper(alice) {
		t.Fatalf("whoAmI %q", value)
	}

	// Without iam:ldap:read a person sees only their own entry, and their groups with only them in it.
	own := client.search(base, "(|(objectClass=inetOrgPerson)(objectClass=groupOfNames))", "", nil, nil)
	if own.Code != ResultSuccess {
		t.Fatalf("own search %d %s", own.Code, own.Message)
	}
	var dns []string
	for _, entry := range own.entries {
		dns = append(dns, entry.Dn)
	}
	sort.Strings(dns)
	want := []string{"cn=Engineering,ou=groups," + base, alice}
	sort.Strings(want)
	if strings.Join(dns, "|") != strings.Join(want, "|") {
		t.Fatalf("own entries %v", dns)
	}
	for _, entry := range own.entries {
		if entry.Dn == alice {
			if strings.Join(entry.Attributes["mail"], ",") != "alice@acme.test" || strings.Join(entry.Attributes["memberOf"], ",") != "cn=Engineering,ou=groups,"+base {
				t.Fatalf("alice %v", entry.Attributes)
			}
		}
	}
	if code := client.compare(alice, "mail", "alice@acme.test").Code; code != ResultCompareTrue {
		t.Fatalf("compare true %d", code)
	}
	if code := client.compare(alice, "mail", "bob@acme.test").Code; code != ResultCompareFalse {
		t.Fatalf("compare false %d", code)
	}
	// The directory is read-only, and other trees do not exist for this binding.
	if code := client.remove(alice).Code; code != ResultUnwillingToPerform {
		t.Fatalf("delete %d", code)
	}
	if code := client.search("dc=other,dc=test", "(objectClass=*)", "", nil, nil).Code; code != ResultNoSuchObject {
		t.Fatalf("other tree %d", code)
	}

	// A service account binds with an API key; with iam:ldap:read it reads the whole published directory.
	if response := client.bind("cn=vpn,ou=services,"+base, s.key); response.Code != ResultSuccess {
		t.Fatalf("service bind %d %s", response.Code, response.Message)
	}
	people := client.search("ou=people,"+base, "(objectClass=inetOrgPerson)", "one", []string{"mail", "memberOf"}, nil)
	var mails []string
	for _, entry := range people.entries {
		mails = append(mails, entry.Attributes["mail"][0])
	}
	sort.Strings(mails)
	if strings.Join(mails, ",") != "alice@acme.test,bob@acme.test,owner@acme.test" {
		t.Fatalf("people %v", mails)
	}
	group := client.search("cn=Engineering,ou=groups,"+base, "(objectClass=*)", "base", nil, nil)
	if len(group.entries) != 1 || strings.Join(group.entries[0].Attributes["member"], ",") != alice {
		t.Fatalf("group %+v", group.entries)
	}
	if services := client.search("ou=services,"+base, "(cn=vpn)", "one", nil, nil); len(services.entries) != 1 {
		t.Fatalf("services %d", len(services.entries))
	}

	// Paged results (RFC 2696) walk the people one page at a time.
	var seen []string
	cookie := []byte{}
	for {
		page := client.search("ou=people,"+base, "(objectClass=inetOrgPerson)", "one", nil, PagedResultsRequest(2, cookie))
		for _, entry := range page.entries {
			seen = append(seen, entry.Dn)
		}
		var control *LdapControl
		for index := range page.Controls {
			if page.Controls[index].Type == OIDPagedResults {
				control = &page.Controls[index]
			}
		}
		if control == nil {
			t.Fatal("no paged results control")
		}
		paged, err := ReadPagedResults(control.Value, true)
		if err != nil {
			t.Fatal(err)
		}
		cookie = paged.Cookie
		if len(cookie) == 0 {
			break
		}
	}
	if len(seen) != 3 {
		t.Fatalf("paged %v", seen)
	}

	reads := ok[apitypes.AuditListOutput](t)(f.iam.API.Audit.List(f.ctx, f.owner, server.Input[apitypes.AuditListInput](
		core.NewObject("tenantId", f.tenantID, "action", "ldap:directory:read"))))
	events, isList := reads.([]any)
	if !isList {
		events, _ = member(reads, "events").([]any)
	}
	if len(events) == 0 {
		t.Fatal("no ldap:directory:read audit events")
	}
}

func TestLdapGatewayTakesTheOneTimeCodeAfterThePasswordAndStopsWhenTurnedOff(t *testing.T) {
	s := setup(t)
	f := s.f
	first := f.signInAs("bob@acme.test", "a strong bob password")
	enrollment := ok[apitypes.AuthBeginMfaOutput](t)(f.iam.API.Auth.BeginMfa(f.ctx, auth.MfaCredential{Credentials: &first}))
	secret := str(member(enrollment, "secret"))
	code, err := auth.GenerateTotp(secret, f.clock.Load())
	if err != nil {
		t.Fatal(err)
	}
	ok[apitypes.AuthConfirmMfaOutput](t)(f.iam.API.Auth.ConfirmMfa(f.ctx, auth.ConfirmMfaInput{Credential: auth.MfaCredential{Credentials: &first}, Code: code}))
	f.clock.Add(30_000)
	client := dial(t, s.port)
	defer client.close()
	bob := "uid=bob@acme.test,ou=people," + base
	if response := client.bind(bob, "a strong bob password"); response.Code != ResultInvalidCredentials {
		t.Fatalf("password alone %d", response.Code)
	}
	code, _ = auth.GenerateTotp(secret, f.clock.Load())
	if response := client.bind(bob, "a strong bob password"+code); response.Code != ResultSuccess {
		t.Fatalf("password and code %d %s", response.Code, response.Message)
	}

	// Only declared identity attributes can be published.
	_, err = f.iam.API.Ldap.UpdateSettings(f.ctx, f.owner, server.Input[apitypes.LdapUpdateSettingsInput](
		core.NewObject("tenantId", f.tenantID, "attributes", []any{"salary"})))
	var known *core.IamError
	if !errors.As(err, &known) || known.Code != "INVALID_INPUT" {
		t.Fatalf("salary: %v", err)
	}

	ok[apitypes.LdapUpdateSettingsOutput](t)(f.iam.API.Ldap.UpdateSettings(f.ctx, f.owner, server.Input[apitypes.LdapUpdateSettingsInput](
		core.NewObject("tenantId", f.tenantID, "enabled", false))))
	if response := client.bind("uid=alice@acme.test,ou=people,"+base, "a strong alice password"); response.Code != ResultInvalidCredentials {
		t.Fatalf("after disabling %d", response.Code)
	}
}

func TestLdapGatewayClosesMalformedConnectionsWithANotice(t *testing.T) {
	s := setup(t)
	client := dial(t, s.port)
	defer client.close()
	// An indefinite length is refused with a notice of disconnection.
	if _, err := client.conn.Write([]byte{0x30, 0x80, 0x00, 0x00}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		client.mu.Lock()
		closed := client.closed
		var notice *LdapResponse
		for _, response := range client.received {
			if response.ID == 0 {
				notice = response
			}
		}
		client.mu.Unlock()
		if closed && notice != nil {
			if notice.ResponseName != OIDNoticeOfDisconnection || notice.Code != ResultProtocolError || notice.Message != "Indefinite lengths are not allowed" {
				t.Fatalf("notice %+v", notice)
			}
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("connection not closed")
}
