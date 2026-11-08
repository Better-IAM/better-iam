package ldap

// Port of packages/ldap/src/server.ts: a read-only LDAPv3 gateway over Better IAM. Applications bind as a person
// (`uid={uid},ou=people,{base}` with the password, plus the current one-time code appended when the organization
// requires MFA) or as a service account (`cn={name},ou=services,{base}` with an API key as the password), then
// search people, groups and service accounts of the organization whose base DN they use. Binds go through Better IAM
// sign-in, so rate limits, lockouts, allowed methods, IP rules and sign-in alerts apply; searches are authorized as
// the bound account (`iam:ldap:read` for the whole directory, otherwise only its own entry). Writes are refused.

import (
	"context"
	"crypto/tls"
	"errors"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
)

// LdapIam is what the gateway needs from a Better IAM server (FromBetterIam adapts a composed server).
type LdapIam interface {
	// SignIn is api.auth.signIn({ tenantId, email, password }).
	SignIn(ctx context.Context, tenantID, email, password string) (any, error)
	// VerifyMfa is api.auth.verifyMfa({ tenantId, challenge, code }).
	VerifyMfa(ctx context.Context, tenantID, challenge, code string) (any, error)
	// SignOut is api.auth.signOut(credential).
	SignOut(ctx context.Context, credential core.CredentialInput) error
	// Directory is api.ldap.directory(credential, { tenantId }).
	Directory(ctx context.Context, credential core.CredentialInput, tenantID string) (any, error)
	// Authenticate is iam.authenticate(credential): the identity and session records.
	Authenticate(ctx context.Context, credential core.CredentialInput) (identity, session *core.Object, err error)
	// WithClient is auth.withClient: a context whose sign-ins record this client.
	WithClient(ctx context.Context, client *core.SessionClientInfo) context.Context
	// TenantForBase is ldap.tenantForBase(normalizedBaseDn) (nil when no organization publishes it).
	TenantForBase(ctx context.Context, normalizedBaseDn string) (*core.Object, error)
	// ResolveBindName is ldap.resolveBindName(tenantId, kind, value) (nil when nobody matches).
	ResolveBindName(ctx context.Context, tenantID, kind, value string) (*core.Object, error)
}

// LdapServerOptions configure CreateLdapServer. Numeric options left nil take their defaults.
type LdapServerOptions struct {
	Iam LdapIam
	// TLS serves LDAPS (TLS from the first byte); without it, plain LDAP.
	TLS *tls.Config
	// MaxResults is the most entries one search returns, and the largest page (default 1000).
	MaxResults *int
	// IdleTimeoutMs closes connections idle this long (default 5 minutes).
	IdleTimeoutMs *int64
	// MaxRequestBytes is the largest request accepted (default 64 KiB).
	MaxRequestBytes *int
	// CacheMs is how long a connection reuses a directory snapshot between searches (default 5 seconds).
	CacheMs *int64
	// MaxConnections is the most simultaneous connections (default 1000).
	MaxConnections *int
	// OnError is called with errors the gateway could not answer (logging).
	OnError func(err error)
	// Now is Date.now() (Go-only; default the system clock).
	Now func() int64
}

// binding is a bound connection: the tenant, the bound DN, and the credential searches use.
type binding struct {
	tenantID         string
	baseDn           string
	normalizedBaseDn string
	dn               string
	credential       core.CredentialInput
	// owned: the gateway created the session (a person's bind) and signs it out when the binding ends.
	owned bool
}

type directoryCache struct {
	at       int64
	tenantID string
	entries  []DirectoryEntry
	scope    string
}

type connection struct {
	conn     net.Conn
	secure   bool
	mu       sync.Mutex
	binding  *binding
	cache    *directoryCache
	closed   bool
	messages chan *LdapMessage
	idle     *time.Timer
}

// LdapServer is the gateway CreateLdapServer returns.
type LdapServer struct {
	iam             LdapIam
	options         LdapServerOptions
	maxResults      int
	idleTimeout     time.Duration
	maxRequestBytes int
	cacheMs         int64
	maxConnections  int
	now             func() int64

	mu          sync.Mutex
	connections map[*connection]bool
	listener    net.Listener
	done        chan struct{}
}

func loopback(address string) bool {
	return address == "" || address == "::1" || strings.HasPrefix(address, "127.") || address == "::ffff:127.0.0.1"
}

func credentialOf(value any) (core.CredentialInput, bool) {
	object, ok := value.(*core.Object)
	if !ok || object == nil {
		return core.CredentialInput{}, false
	}
	token, ok := object.Get("token").(string)
	return core.CredentialInput{Token: token}, ok
}

// CreateLdapServer is createLdapServer(options).
func CreateLdapServer(options LdapServerOptions) *LdapServer {
	s := &LdapServer{iam: options.Iam, options: options, maxResults: 1000, idleTimeout: 5 * time.Minute,
		maxRequestBytes: 65536, cacheMs: 5000, maxConnections: 1000, connections: map[*connection]bool{}, done: make(chan struct{})}
	if options.MaxResults != nil {
		s.maxResults = *options.MaxResults
	}
	if options.IdleTimeoutMs != nil {
		s.idleTimeout = time.Duration(*options.IdleTimeoutMs) * time.Millisecond
	}
	if options.MaxRequestBytes != nil {
		s.maxRequestBytes = *options.MaxRequestBytes
	}
	if options.CacheMs != nil {
		s.cacheMs = *options.CacheMs
	}
	if options.MaxConnections != nil {
		s.maxConnections = *options.MaxConnections
	}
	s.now = options.Now
	if s.now == nil {
		s.now = func() int64 { return time.Now().UnixMilli() }
	}
	return s
}

func (s *LdapServer) write(c *connection, chunks ...[]byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return
	}
	var data []byte
	for _, chunk := range chunks {
		data = append(data, chunk...)
	}
	if _, err := c.conn.Write(data); err == nil {
		s.touch(c)
	}
}

func (s *LdapServer) touch(c *connection) {
	if c.idle != nil {
		c.idle.Reset(s.idleTimeout)
	}
}

func (s *LdapServer) release(ctx context.Context, b *binding) {
	if b != nil && b.owned {
		_ = s.iam.SignOut(ctx, b.credential)
	}
}

func (s *LdapServer) close(c *connection, notice []byte) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return
	}
	if notice != nil {
		_, _ = c.conn.Write(notice)
	}
	c.closed = true
	b := c.binding
	c.binding = nil
	if c.idle != nil {
		c.idle.Stop()
	}
	c.mu.Unlock()
	s.mu.Lock()
	delete(s.connections, c)
	s.mu.Unlock()
	if tcp, ok := c.conn.(interface{ CloseWrite() error }); ok {
		_ = tcp.CloseWrite()
	}
	_ = c.conn.Close()
	s.release(context.Background(), b)
}

type target struct {
	tenant   *core.Object
	relative [][]Rdn
}

// tenantOf is the tenant whose base DN dn lies under: the longest matching suffix.
func (s *LdapServer) tenantOf(ctx context.Context, dn string) (*target, error) {
	rdns, err := ParseDn(dn)
	if err != nil {
		return nil, err
	}
	for start := 0; start < len(rdns); start++ {
		suffix, err := NormalizeDn(FormatDn(rdns[start:]))
		if err != nil {
			return nil, err
		}
		found, err := s.iam.TenantForBase(ctx, suffix)
		if err != nil {
			return nil, err
		}
		if found != nil {
			return &target{tenant: found, relative: rdns[:start]}, nil
		}
	}
	return nil, nil
}

func remoteIP(c *connection) string {
	if address, ok := c.conn.RemoteAddr().(*net.TCPAddr); ok {
		return address.IP.String()
	}
	host, _, _ := net.SplitHostPort(c.conn.RemoteAddr().String())
	return host
}

func isTrue(object *core.Object, key string) bool {
	value, _ := object.Get(key).(bool)
	return value
}

func (s *LdapServer) bind(ctx context.Context, c *connection, id int64, request *LdapRequest) {
	c.mu.Lock()
	previous := c.binding
	c.binding = nil
	c.cache = nil
	c.mu.Unlock()
	s.release(ctx, previous)
	if request.Version != 3 {
		s.write(c, BindResponse(id, ResultProtocolError, "Only LDAPv3 is supported"))
		return
	}
	if request.Sasl != "" {
		s.write(c, BindResponse(id, ResultAuthMethodNotSupported, "Use a simple bind"))
		return
	}
	password := utf8Text(request.Password)
	if request.Name == "" && password == "" {
		s.write(c, BindResponse(id, ResultSuccess, ""))
		return
	}
	// RFC 4513 5.1.2: a name with an empty password is an unauthenticated bind; never treat it as signed in.
	if password == "" {
		s.write(c, BindResponse(id, ResultUnwillingToPerform, "Unauthenticated binds are not allowed"))
		return
	}
	invalid := func() { s.write(c, BindResponse(id, ResultInvalidCredentials, "Invalid credentials")) }
	found, err := s.tenantOf(ctx, request.Name)
	if err != nil {
		s.write(c, BindResponse(id, ResultInvalidDNSyntax, "Invalid DN"))
		return
	}
	if found == nil || len(found.relative) != 2 {
		invalid()
		return
	}
	tenant := found.tenant
	tenantID, _ := tenant.Get("tenantId").(string)
	if isTrue(tenant, "requireTls") && !c.secure && !loopback(remoteIP(c)) {
		s.write(c, BindResponse(id, ResultConfidentialityRequired, "Bind over TLS (LDAPS)"))
		return
	}
	leaf, container := found.relative[0], found.relative[1]
	ou := ""
	if len(container) == 1 && core.JSLower(container[0].Type) == "ou" {
		ou = core.JSLower(container[0].Value)
	}
	var rdn *Rdn
	if len(leaf) == 1 {
		rdn = &leaf[0]
	}
	client := &core.SessionClientInfo{IP: remoteIP(c), UserAgent: "better-iam-ldap"}
	bound := func(credential core.CredentialInput, owned bool) {
		baseDn, _ := tenant.Get("baseDn").(string)
		normalized, _ := tenant.Get("normalizedBaseDn").(string)
		c.mu.Lock()
		c.binding = &binding{tenantID: tenantID, baseDn: baseDn, normalizedBaseDn: normalized, dn: request.Name,
			credential: credential, owned: owned}
		c.mu.Unlock()
		s.write(c, BindResponse(id, ResultSuccess, ""))
	}
	err = func() error {
		if ou == "people" && rdn != nil && core.JSLower(rdn.Type) == "uid" && isTrue(tenant, "peopleBind") {
			person, err := s.iam.ResolveBindName(ctx, tenantID, "person", rdn.Value)
			if err != nil {
				return err
			}
			email, _ := person.Get("email").(string)
			if person == nil || email == "" {
				invalid()
				return nil
			}
			mfa, _ := person.Get("mfa").(string)
			suffix, _ := tenant.Get("mfaSuffix").(string)
			credential, ok, err := s.signInPerson(ctx, tenantID, email, mfa, password, suffix, client)
			if err != nil {
				return err
			}
			if !ok {
				invalid()
				return nil
			}
			bound(credential, true)
			return nil
		}
		if ou == "services" && rdn != nil && core.JSLower(rdn.Type) == "cn" && isTrue(tenant, "serviceBind") {
			service, err := s.iam.ResolveBindName(ctx, tenantID, "service", rdn.Value)
			if err != nil {
				return err
			}
			if service == nil {
				invalid()
				return nil
			}
			identity, session, err := s.iam.Authenticate(s.iam.WithClient(ctx, client), core.CredentialInput{Token: password})
			if err != nil {
				return err
			}
			if identity.Get("id") != service.Get("identityId") || session.Get("tenantId") != tenantID || session.Get("kind") != "api-key" {
				invalid()
				return nil
			}
			bound(core.CredentialInput{Token: password}, false)
			return nil
		}
		invalid()
		return nil
	}()
	if err != nil {
		var known *core.IamError
		if errors.As(err, &known) && known.Code == "RATE_LIMITED" {
			s.write(c, BindResponse(id, ResultUnwillingToPerform, "Too many attempts; try again later"))
			return
		}
		invalid()
	}
}

var codeSuffix = regexp.MustCompile(`(?s)^.+[0-9]{6}$`)

// signInPerson signs a person in: with the password, or, when they must use MFA and mfaSuffix allows it, with the
// password followed by the current six-digit authenticator code. Exactly one sign-in attempt per bind, so a person's
// own binds never count as failed sign-ins.
func (s *LdapServer) signInPerson(ctx context.Context, tenantID, email, mfa, password, mfaSuffix string, client *core.SessionClientInfo) (core.CredentialInput, bool, error) {
	signIn := func(secret string) (any, error) {
		return s.iam.SignIn(s.iam.WithClient(ctx, client), tenantID, email, secret)
	}
	if mfa == "" {
		mfa = "none"
	}
	if mfa == "unavailable" {
		return core.CredentialInput{}, false, nil
	}
	if mfa == "none" {
		result, err := signIn(password)
		if err != nil {
			return core.CredentialInput{}, false, err
		}
		credential, ok := credentialOf(result)
		return credential, ok, nil
	}
	units := core.ToUTF16(password)
	if mfaSuffix != "auto" || !codeSuffix.MatchString(password) || len(units) < 6 {
		return core.CredentialInput{}, false, nil
	}
	secret := core.FromUTF16(units[:len(units)-6])
	code := core.FromUTF16(units[len(units)-6:])
	result, err := signIn(secret)
	if err != nil {
		return core.CredentialInput{}, false, err
	}
	// MFA stopped being required in the meantime: the digits were not part of the password.
	if direct, ok := credentialOf(result); ok {
		_ = s.iam.SignOut(ctx, direct)
		return core.CredentialInput{}, false, nil
	}
	object, _ := result.(*core.Object)
	challenge, _ := object.Get("challenge").(string)
	if object == nil || object.Get("mfaRequired") != true || challenge == "" {
		return core.CredentialInput{}, false, nil
	}
	verified, err := s.iam.VerifyMfa(s.iam.WithClient(ctx, client), tenantID, challenge, code)
	if err != nil {
		return core.CredentialInput{}, false, err
	}
	credential, ok := credentialOf(verified)
	return credential, ok, nil
}

func (s *LdapServer) entriesFor(ctx context.Context, c *connection) (*directoryCache, error) {
	c.mu.Lock()
	b := c.binding
	cache := c.cache
	c.mu.Unlock()
	now := s.now()
	if cache != nil && cache.tenantID == b.tenantID && now-cache.at < s.cacheMs {
		return cache, nil
	}
	value, err := s.iam.Directory(ctx, b.credential, b.tenantID)
	if err != nil {
		return nil, err
	}
	data := DirectoryDataFrom(value)
	entries, err := BuildEntries(data)
	if err != nil {
		return nil, err
	}
	cache = &directoryCache{at: now, tenantID: b.tenantID, entries: entries, scope: data.Scope}
	c.mu.Lock()
	c.cache = cache
	c.mu.Unlock()
	return cache, nil
}

func rootDse() []AttributeValues {
	return []AttributeValues{
		{"objectClass", []string{"top", "extensibleObject"}},
		{"supportedLDAPVersion", []string{"3"}},
		{"supportedExtension", []string{OIDWhoAmI}},
		{"supportedControl", []string{OIDPagedResults}},
		{"supportedSASLMechanisms", []string{}},
		{"vendorName", []string{"Better IAM"}},
	}
}

func (s *LdapServer) currentBinding(c *connection) *binding {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.binding
}

// jsParseInt10 is Number.parseInt(value, 10) (NaN: ok false).
func jsParseInt10(value string) (float64, bool) {
	value = strings.TrimLeftFunc(value, isJSSpace)
	sign := 1.0
	if strings.HasPrefix(value, "-") || strings.HasPrefix(value, "+") {
		if value[0] == '-' {
			sign = -1
		}
		value = value[1:]
	}
	end := 0
	for end < len(value) && value[end] >= '0' && value[end] <= '9' {
		end++
	}
	if end == 0 {
		return math.NaN(), false
	}
	parsed, _ := strconv.ParseFloat(value[:end], 64)
	return sign * parsed, true
}

func (s *LdapServer) search(ctx context.Context, c *connection, message *LdapMessage, request *LdapRequest) error {
	id := message.ID
	b := s.currentBinding(c)
	if request.Base == "" && request.Scope == "base" {
		attributes := rootDse()
		if b != nil {
			attributes = append(attributes, AttributeValues{"namingContexts", []string{b.baseDn}})
		}
		var shown []AttributeValues
		for _, attribute := range attributes {
			if len(attribute.Values) > 0 {
				shown = append(shown, attribute)
			}
		}
		s.write(c, SearchEntry(id, "", shown, request.TypesOnly))
		s.write(c, SearchDone(id, ResultSuccess, "", "", nil))
		return nil
	}
	if b == nil {
		s.write(c, SearchDone(id, ResultInsufficientAccessRights, "Bind first", "", nil))
		return nil
	}
	base, err := NormalizeDn(request.Base)
	if err != nil {
		s.write(c, SearchDone(id, ResultInvalidDNSyntax, "Invalid base DN", "", nil))
		return nil
	}
	// Another organization's tree does not exist for this binding.
	under, err := IsUnder(base, b.normalizedBaseDn)
	if err != nil {
		return err
	}
	if !under {
		s.write(c, SearchDone(id, ResultNoSuchObject, "No such object", "", nil))
		return nil
	}
	cache, err := s.entriesFor(ctx, c)
	if err != nil {
		s.write(c, SearchDone(id, ResultInsufficientAccessRights, "Access denied", "", nil))
		return nil
	}
	entries := cache.entries
	exists := false
	for _, item := range entries {
		if item.NormalizedDn == base {
			exists = true
			break
		}
	}
	if !exists {
		s.write(c, SearchDone(id, ResultNoSuchObject, "No such object", b.normalizedBaseDn, nil))
		return nil
	}
	var matches []DirectoryEntry
	for _, item := range entries {
		depth, err := DepthBelow(item.NormalizedDn, base)
		if err != nil {
			return err
		}
		inScope := depth >= 0
		switch request.Scope {
		case "base":
			inScope = depth == 0
		case "one":
			inScope = depth == 1
		}
		if inScope && MatchFilter(request.Filter, item.Index) {
			matches = append(matches, item)
		}
	}
	for _, control := range message.Controls {
		if control.Type != OIDPagedResults {
			continue
		}
		page, err := ReadPagedResults(control.Value, control.HasValue)
		if err != nil {
			return err
		}
		size := int64(s.maxResults)
		if page != nil {
			size = page.Size
		}
		size = min(max(size, 1), int64(s.maxResults))
		offset := 0.0
		if page != nil && len(page.Cookie) > 0 {
			parsed, ok := jsParseInt10(utf8Text(page.Cookie))
			if !ok || parsed != math.Trunc(parsed) || math.Abs(parsed) > 9007199254740991 || parsed < 0 {
				s.write(c, SearchDone(id, ResultProtocolError, "Invalid paging cookie", "", nil))
				return nil
			}
			offset = parsed
		}
		start := int(min(offset, float64(len(matches))))
		end := int(min(offset+float64(size), float64(len(matches))))
		for _, item := range matches[start:end] {
			s.write(c, SearchEntry(id, item.Dn, SelectAttributes(item, request.Attributes), request.TypesOnly))
		}
		next := []byte{}
		if offset+float64(size) < float64(len(matches)) {
			next = []byte(strconv.FormatInt(int64(offset)+size, 10))
		}
		s.write(c, SearchDone(id, ResultSuccess, "", "", PagedResultsControl(int64(len(matches)), next)))
		return nil
	}
	limit := int64(s.maxResults)
	if request.SizeLimit > 0 {
		limit = request.SizeLimit
	}
	limit = min(limit, int64(s.maxResults))
	for index, item := range matches {
		if int64(index) >= limit {
			break
		}
		s.write(c, SearchEntry(id, item.Dn, SelectAttributes(item, request.Attributes), request.TypesOnly))
	}
	if int64(len(matches)) > limit {
		s.write(c, SearchDone(id, ResultSizeLimitExceeded, "More than "+strconv.FormatInt(limit, 10)+" entries match", "", nil))
	} else {
		s.write(c, SearchDone(id, ResultSuccess, "", "", nil))
	}
	return nil
}

func (s *LdapServer) compare(ctx context.Context, c *connection, id int64, request *LdapRequest) error {
	b := s.currentBinding(c)
	if b == nil {
		s.write(c, CompareResponse(id, ResultInsufficientAccessRights, "Bind first"))
		return nil
	}
	target, err := NormalizeDn(request.Entry)
	if err != nil {
		s.write(c, CompareResponse(id, ResultInvalidDNSyntax, "Invalid DN"))
		return nil
	}
	under, err := IsUnder(target, b.normalizedBaseDn)
	if err != nil {
		return err
	}
	var found *DirectoryEntry
	if under {
		cache, err := s.entriesFor(ctx, c)
		if err != nil {
			return err
		}
		for index := range cache.entries {
			if cache.entries[index].NormalizedDn == target {
				found = &cache.entries[index]
				break
			}
		}
	}
	if found == nil {
		s.write(c, CompareResponse(id, ResultNoSuchObject, "No such object"))
		return nil
	}
	matched := MatchFilter(&Filter{Type: "equal", Attribute: request.Attribute, Value: request.Value}, found.Index)
	code := ResultCompareFalse
	if matched {
		code = ResultCompareTrue
	}
	s.write(c, CompareResponse(id, code, ""))
	return nil
}

func (s *LdapServer) handle(ctx context.Context, c *connection, message *LdapMessage) error {
	id, request := message.ID, message.Request
	switch request.Op {
	case "bind":
		s.bind(ctx, c, id, request)
	case "unbind":
		s.close(c, nil)
	case "search":
		return s.search(ctx, c, message, request)
	case "compare":
		return s.compare(ctx, c, id, request)
	case "extended":
		if request.Name == OIDWhoAmI {
			value := []byte{}
			if b := s.currentBinding(c); b != nil {
				value = []byte("dn:" + b.dn)
			}
			s.write(c, ExtendedResponse(id, ResultSuccess, "", "", value))
			return nil
		}
		name := request.Name
		if units := core.ToUTF16(name); len(units) > 64 {
			name = core.FromUTF16(units[:64])
		}
		s.write(c, ExtendedResponse(id, ResultProtocolError, "Unsupported extended operation "+name, "", nil))
	case "abandon":
	case "unsupported":
		s.write(c, GenericResponse(id, request.ResponseTag, ResultUnwillingToPerform, "This directory is read-only"))
	}
	return nil
}

func (s *LdapServer) isClosed(c *connection) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func (s *LdapServer) accept(conn net.Conn, secure bool) {
	s.mu.Lock()
	if len(s.connections) >= s.maxConnections {
		s.mu.Unlock()
		_, _ = conn.Write(NoticeOfDisconnection(ResultBusy, "Too many connections"))
		_ = conn.Close()
		return
	}
	c := &connection{conn: conn, secure: secure, messages: make(chan *LdapMessage, 64)}
	s.connections[c] = true
	s.mu.Unlock()
	c.idle = time.AfterFunc(s.idleTimeout, func() {
		s.close(c, NoticeOfDisconnection(ResultUnavailable, "Idle timeout"))
	})
	// One request at a time per connection, in order.
	go func() {
		ctx := context.Background()
		for message := range c.messages {
			if s.isClosed(c) {
				continue
			}
			if err := s.handle(ctx, c, message); err != nil {
				if s.options.OnError != nil {
					s.options.OnError(err)
				}
				s.close(c, NoticeOfDisconnection(ResultOther, "Internal error"))
			}
		}
	}()
	go func() {
		defer close(c.messages)
		var buffer []byte
		chunk := make([]byte, 16384)
		for {
			n, err := conn.Read(chunk)
			if n > 0 {
				if s.isClosed(c) {
					return
				}
				c.mu.Lock()
				s.touch(c)
				c.mu.Unlock()
				buffer = append(buffer, chunk[:n]...)
				for {
					item, readErr := ReadElement(buffer, 0, s.maxRequestBytes)
					if readErr != nil {
						s.close(c, NoticeOfDisconnection(ResultProtocolError, readErr.Error()))
						return
					}
					if item == nil {
						if len(buffer) > s.maxRequestBytes+8 {
							s.close(c, NoticeOfDisconnection(ResultProtocolError, "Request too large"))
							return
						}
						break
					}
					raw := append([]byte(nil), buffer[:item.Size]...)
					buffer = append([]byte(nil), buffer[item.Size:]...)
					parsed, _ := ReadElement(raw, 0, len(raw))
					message, decodeErr := DecodeMessage(parsed)
					if decodeErr != nil {
						s.close(c, NoticeOfDisconnection(ResultProtocolError, decodeErr.Error()))
						return
					}
					c.messages <- message
				}
			}
			if err != nil {
				s.close(c, nil)
				return
			}
		}
	}()
}

// Listen starts listening (port 0 picks a free one; port -1 is the default, 636 with TLS and 389 without; host ""
// is 127.0.0.1) and returns the bound address.
func (s *LdapServer) Listen(port int, host string) (*net.TCPAddr, error) {
	if port < 0 {
		port = 389
		if s.options.TLS != nil {
			port = 636
		}
	}
	if host == "" {
		host = "127.0.0.1"
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	var listener net.Listener
	var err error
	if s.options.TLS != nil {
		listener, err = tls.Listen("tcp", address, s.options.TLS)
	} else {
		listener, err = net.Listen("tcp", address)
	}
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.listener = listener
	s.mu.Unlock()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			s.accept(conn, s.options.TLS != nil)
		}
	}()
	return listener.Addr().(*net.TCPAddr), nil
}

// Close stops accepting connections, tells connected clients, and signs out the sessions it created.
func (s *LdapServer) Close() error {
	s.mu.Lock()
	listener := s.listener
	open := make([]*connection, 0, len(s.connections))
	for c := range s.connections {
		open = append(open, c)
	}
	s.mu.Unlock()
	var wg sync.WaitGroup
	for _, c := range open {
		wg.Add(1)
		go func(c *connection) {
			defer wg.Done()
			s.close(c, NoticeOfDisconnection(ResultUnavailable, "Server shutting down"))
		}(c)
	}
	wg.Wait()
	if listener != nil {
		return listener.Close()
	}
	return nil
}

// Connections is the number of live connections (for metrics).
func (s *LdapServer) Connections() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.connections)
}
