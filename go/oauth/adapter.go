package oauth

// Port of packages/oauth/src/adapter.ts: provider persistence with encrypted payloads and hashed token identifiers.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"sync"

	"github.com/Better-IAM/better-iam/go/core"
)

// ProtocolTenant is the sentinel tenant for artifacts that exist before any client or account is known (for
// example interactions).
const ProtocolTenant = "__protocol__"

// Cipher is AES-256-GCM sealing for provider artifacts; the key is separate from signing and cookie keys.
type Cipher struct {
	aead cipher.AEAD
}

// NewCipher is adapter.ts `cipher(key)`.
func NewCipher(key []byte) (*Cipher, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &Cipher{aead: aead}, nil
}

// Seal encrypts JSON.stringify(value): base64(iv || ciphertext || tag).
func (c *Cipher) Seal(value any) string {
	iv := make([]byte, 12)
	_, _ = rand.Read(iv)
	return c.sealWithIV(value, iv)
}

func (c *Cipher) sealWithIV(value any, iv []byte) string {
	sealed := c.aead.Seal(nil, iv, utf8Bytes(stringify(value)), nil)
	return base64.StdEncoding.EncodeToString(append(append([]byte{}, iv...), sealed...))
}

// Open decrypts a sealed value and parses its JSON.
func (c *Cipher) Open(value string) (any, error) {
	buffer := nodeBase64Decode(value)
	if len(buffer) < 28 {
		return nil, errors.New("Unsupported state or unable to authenticate data")
	}
	plain, err := c.aead.Open(nil, buffer[:12], buffer[12:], nil)
	if err != nil {
		return nil, errors.New("Unsupported state or unable to authenticate data")
	}
	return core.ParseJSONString(decodeUTF8(plain))
}

// openObject opens a sealed object (an empty object when the sealed value is not one).
func (c *Cipher) openObject(value string) (*core.Object, error) {
	opened, err := c.Open(value)
	if err != nil {
		return nil, err
	}
	o, ok := opened.(*core.Object)
	if !ok || o == nil {
		return core.NewObject(), nil
	}
	return o, nil
}

// EncryptionKey is adapter.ts `encryptionKey`: the base64 key must encode exactly 32 bytes.
func EncryptionKey(encoded string) ([]byte, error) {
	key := nodeBase64Decode(encoded)
	if len(key) != 32 {
		return nil, core.NewIamError("configuration", "OAuth encryptionKey must encode exactly 32 bytes.")
	}
	return key, nil
}

// ValidateSessionFunc is the host's session validation (custom idle limits, email verification, MFA policy).
type ValidateSessionFunc func(ctx context.Context, sessionID string) error

// RegisterClientFunc stores a client created by dynamic registration.
type RegisterClientFunc func(ctx context.Context, clientID string, payload *core.Object) error

// ProviderAdapter is createProviderAdapter's result: every artifact is bound to the tenant of its client and
// account, and every user grant is re-validated against its IAM session on each use.
type ProviderAdapter struct {
	store           core.IamStore
	crypt           *Cipher
	validateSession ValidateSessionFunc
	registerClient  RegisterClientFunc
	now             func() int64

	mu                 sync.Mutex
	pendingRevocations map[string]*revocationFlight
}

type revocationFlight struct {
	done chan struct{}
	err  error
}

// CreateProviderAdapter is adapter.ts `createProviderAdapter`.
func CreateProviderAdapter(store core.IamStore, encodedKey string, validateSession ValidateSessionFunc, registerClient RegisterClientFunc) (*ProviderAdapter, error) {
	key, err := EncryptionKey(encodedKey)
	if err != nil {
		return nil, err
	}
	crypt, err := NewCipher(key)
	if err != nil {
		return nil, err
	}
	return &ProviderAdapter{store: store, crypt: crypt, validateSession: validateSession, registerClient: registerClient,
		now: wallNow, pendingRevocations: map[string]*revocationFlight{}}, nil
}

// Model is `new Adapter(model)`.
func (a *ProviderAdapter) Model(name string) *ModelAdapter {
	return &ModelAdapter{adapter: a, model: name}
}

func (a *ProviderAdapter) client(ctx context.Context, id string) (*core.Object, error) {
	row, err := a.store.Get(ctx, "oauthClients", hash(id))
	if err != nil || row == nil {
		return nil, err
	}
	if revoked, _ := row.Get("revoked").(bool); revoked {
		return nil, nil
	}
	active, err := core.TenantTreeActive(ctx, a.store, str(row, "tenantId"))
	if err != nil || !active {
		return nil, err
	}
	if serviceID, ok := row.Get("serviceAccountId").(string); ok && serviceID != "" {
		service, err := a.store.Get(ctx, "identities", serviceID)
		if err != nil {
			return nil, err
		}
		if service == nil || str(service, "kind") != "service" || str(service, "status") != "active" ||
			str(service, "tenantId") != str(row, "tenantId") {
			return nil, nil
		}
	} else if truthy(row.Get("serviceAccountId")) {
		return nil, nil
	}
	return row, nil
}

func (a *ProviderAdapter) validGrantSession(ctx context.Context, grantID string, accountID string) error {
	revoked, err := a.store.Get(ctx, "oauthRevokedGrants", hash(grantID))
	if err != nil {
		return err
	}
	if revoked != nil {
		return errInvalidGrant("Grant is revoked.")
	}
	binding, err := a.store.Get(ctx, "oauthGrantSessions", hash(grantID))
	if err != nil {
		return err
	}
	if binding == nil || (accountID != "" && str(binding, "identityId") != accountID) {
		return errInvalidGrant("Grant has no valid IAM session binding.")
	}
	session, err := a.store.Get(ctx, "sessions", str(binding, "sessionId"))
	if err != nil {
		return err
	}
	identity, err := a.store.Get(ctx, "identities", str(binding, "identityId"))
	if err != nil {
		return err
	}
	mfa, err := a.store.Get(ctx, "authMfa", str(binding, "identityId"))
	if err != nil {
		return err
	}
	now := float64(a.now())
	usable := session != nil && identity != nil &&
		str(session, "kind") == "user" &&
		jsEq(session.Get("identityId"), binding.Get("identityId")) &&
		jsEq(session.Get("tenantId"), binding.Get("tenantId")) &&
		jsEq(identity.Get("tenantId"), binding.Get("tenantId")) &&
		str(identity, "status") == "active"
	if usable {
		expiresAt, _ := num(session, "expiresAt")
		usable = expiresAt > now
	}
	if usable && a.validateSession == nil {
		lastSeen, _ := num(session, "lastSeenAt")
		usable = now-lastSeen < 86400_000
	}
	if usable && (truthy(identity.Get("rootAdmin")) || (mfa != nil && truthy(mfa.Get("enabled")))) && !truthy(session.Get("mfa")) {
		usable = false
	}
	if usable {
		active, err := core.TenantTreeActive(ctx, a.store, str(binding, "tenantId"))
		if err != nil {
			return err
		}
		usable = active
	}
	if !usable {
		return errInvalidGrant("IAM session is unavailable.")
	}
	if a.validateSession != nil {
		return a.validateSession(ctx, str(session, "id"))
	}
	return nil
}

// jsEq is === for model values.
func jsEq(a, b any) bool { return core.StrictEquals(a, b) }

// scope is the tenant an artifact belongs to, derived from its client and account, which must agree.
func (a *ProviderAdapter) scope(ctx context.Context, payload *core.Object) (string, error) {
	tenantID := ""
	clientID, _ := payload.Get("clientId").(string)
	if isUndefined(payload.Get("clientId")) || payload.Get("clientId") == nil {
		if params := obj(payload, "params"); params != nil {
			clientID, _ = params.Get("client_id").(string)
		}
	}
	if clientID != "" {
		row, err := a.client(ctx, clientID)
		if err != nil {
			return "", err
		}
		if row == nil {
			return "", errInvalidClient("Client is unavailable.")
		}
		tenantID = str(row, "tenantId")
	}
	if accountID := payload.Get("accountId"); truthy(accountID) {
		identity, err := a.store.Get(ctx, "identities", jsString(accountID))
		if err != nil {
			return "", err
		}
		active := false
		if identity != nil && str(identity, "status") == "active" {
			if active, err = core.TenantTreeActive(ctx, a.store, str(identity, "tenantId")); err != nil {
				return "", err
			}
		}
		if !active {
			return "", errInvalidGrant("Account is unavailable.")
		}
		if tenantID != "" && str(identity, "tenantId") != tenantID {
			return "", errInvalidGrant("Account and client belong to different tenants.")
		}
		tenantID = str(identity, "tenantId")
	}
	if grantID := payload.Get("grantId"); truthy(grantID) {
		revoked, err := a.store.Get(ctx, "oauthRevokedGrants", hash(jsString(grantID)))
		if err != nil {
			return "", err
		}
		if revoked != nil {
			return "", errInvalidGrant("Grant is revoked.")
		}
		if err := a.validGrantSession(ctx, jsString(grantID), accountString(payload)); err != nil {
			return "", err
		}
	}
	if tenantID == "" {
		return ProtocolTenant, nil
	}
	return tenantID, nil
}

func accountString(payload *core.Object) string {
	if value := payload.Get("accountId"); truthy(value) {
		return jsString(value)
	}
	return ""
}

// ModelAdapter persists one oidc-provider model (Grant, Session, AccessToken, ...).
type ModelAdapter struct {
	adapter *ProviderAdapter
	model   string
}

func (m *ModelAdapter) recordID(id string) string { return hash(m.model + ":" + id) }

// Upsert stores an artifact for expiresIn seconds (86400 when 0).
func (m *ModelAdapter) Upsert(ctx context.Context, id string, payload *core.Object, expiresIn int64) error {
	a := m.adapter
	if m.model == "Client" {
		if a.registerClient == nil {
			return core.NewIamError("PROTECTED_OPERATION", "Use authenticated registerClient().", 403)
		}
		return a.registerClient(ctx, id, payload)
	}
	if expiresIn == 0 {
		expiresIn = 86400
	}
	return a.store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		tenantID, err := a.scope(ctx, payload)
		if err != nil {
			return err
		}
		recordID := m.recordID(id)
		previous, err := tx.Get(ctx, "oauthArtifacts", recordID)
		if err != nil {
			return err
		}
		if previous != nil && str(previous, "boundTenantId") != ProtocolTenant && str(previous, "boundTenantId") != tenantID {
			return errInvalidGrant("Immutable tenant binding changed.")
		}
		recordTenant := any(tenantID)
		if previous != nil && previous.Get("tenantId") != nil && !isUndefined(previous.Get("tenantId")) {
			recordTenant = previous.Get("tenantId")
		}
		record := core.NewObject(
			"id", recordID,
			"tenantId", recordTenant,
			"boundTenantId", tenantID,
			"model", m.model,
			"encrypted", a.crypt.Seal(payload),
			"expiresAt", a.now()+expiresIn*1000,
			"clientId", payload.Get("clientId"),
			"accountId", payload.Get("accountId"),
		)
		record.Set("uidHash", hashedMember(payload, "uid"))
		record.Set("userCodeHash", hashedMember(payload, "userCode"))
		record.Set("grantIdHash", hashedMember(payload, "grantId"))
		if previous != nil {
			_, err = tx.Put(ctx, "oauthArtifacts", record)
		} else {
			_, err = tx.Insert(ctx, "oauthArtifacts", record)
		}
		return err
	})
}

func hashedMember(payload *core.Object, key string) any {
	if value := payload.Get(key); truthy(value) {
		return hash(jsString(value))
	}
	return core.Undefined
}

func (m *ModelAdapter) unpack(ctx context.Context, row *core.Object) (*core.Object, error) {
	a := m.adapter
	if row == nil {
		return nil, nil
	}
	if expiresAt, _ := num(row, "expiresAt"); expiresAt <= float64(a.now()) {
		return nil, nil
	}
	payload, err := a.crypt.openObject(str(row, "encrypted"))
	if err != nil {
		return nil, err
	}
	bound, err := a.scope(ctx, payload)
	if err != nil || str(row, "boundTenantId") != bound {
		return nil, nil
	}
	if m.model == "Grant" && truthy(payload.Get("jti")) {
		if a.validGrantSession(ctx, jsString(payload.Get("jti")), accountString(payload)) != nil {
			return nil, nil
		}
	}
	if m.model == "Session" && truthy(payload.Get("accountId")) {
		var grants []string
		if authorizations := obj(payload, "authorizations"); authorizations != nil {
			authorizations.Entries(func(_ string, value any) bool {
				if entry, ok := value.(*core.Object); ok && truthy(entry.Get("grantId")) {
					grants = append(grants, jsString(entry.Get("grantId")))
				}
				return true
			})
		}
		if len(grants) == 0 {
			return nil, nil
		}
		valid := false
		for _, grant := range grants {
			if a.validGrantSession(ctx, grant, accountString(payload)) == nil {
				valid = true
			}
		}
		if !valid {
			return nil, nil
		}
	}
	if grantHash, ok := row.Get("grantIdHash").(string); ok && grantHash != "" {
		revoked, err := a.store.Get(ctx, "oauthRevokedGrants", grantHash)
		if err != nil {
			return nil, err
		}
		if revoked != nil {
			return nil, nil
		}
	}
	return payload, nil
}

// Find reads an artifact by its identifier (nil when missing, expired or no longer valid).
func (m *ModelAdapter) Find(ctx context.Context, id string) (*core.Object, error) {
	a := m.adapter
	if m.model == "Client" {
		row, err := a.client(ctx, id)
		if err != nil || row == nil {
			return nil, err
		}
		return a.crypt.openObject(str(row, "encrypted"))
	}
	row, err := a.store.Get(ctx, "oauthArtifacts", m.recordID(id))
	if err != nil {
		return nil, err
	}
	return m.unpack(ctx, row)
}

// FindByUID reads a Session by its uid.
func (m *ModelAdapter) FindByUID(ctx context.Context, uid string) (*core.Object, error) {
	rows, err := m.adapter.store.Find(ctx, "oauthArtifacts", core.NewObject("model", m.model, "uidHash", hash(uid)), nil)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return m.unpack(ctx, rows[0])
}

// FindByUserCode reads a DeviceCode by its user code.
func (m *ModelAdapter) FindByUserCode(ctx context.Context, userCode string) (*core.Object, error) {
	rows, err := m.adapter.store.Find(ctx, "oauthArtifacts", core.NewObject("model", m.model, "userCodeHash", hash(userCode)), nil)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return m.unpack(ctx, rows[0])
}

// Destroy deletes an artifact.
func (m *ModelAdapter) Destroy(ctx context.Context, id string) error {
	return m.adapter.store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		return tx.Delete(ctx, "oauthArtifacts", m.recordID(id))
	})
}

// Consume marks a single-use artifact consumed: a second consumption revokes the whole grant family, including
// tokens issued by a racing request.
func (m *ModelAdapter) Consume(ctx context.Context, id string) error {
	a := m.adapter
	invalid, grantID := false, ""
	err := a.store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		invalid, grantID = false, ""
		row, err := tx.Get(ctx, "oauthArtifacts", m.recordID(id))
		if err != nil {
			return err
		}
		if row == nil {
			invalid = true
			return nil
		}
		if expiresAt, _ := num(row, "expiresAt"); expiresAt <= float64(a.now()) {
			invalid = true
			return nil
		}
		payload, err := a.crypt.openObject(str(row, "encrypted"))
		if err != nil {
			return err
		}
		if truthy(payload.Get("consumed")) {
			invalid = true
			if truthy(payload.Get("grantId")) {
				grantID = jsString(payload.Get("grantId"))
			}
			return nil
		}
		payload.Set("consumed", epoch(a.now()))
		next := row.Clone()
		next.Set("encrypted", a.crypt.Seal(payload))
		_, err = tx.Put(ctx, "oauthArtifacts", next)
		return err
	})
	if err != nil {
		return err
	}
	// Commit family revocation before throwing. Rejected requests cannot roll it back.
	if invalid {
		if grantID != "" {
			if err := m.RevokeByGrantID(ctx, grantID); err != nil {
				return err
			}
		}
		return errInvalidGrant("Credential is unavailable or has already been consumed.")
	}
	return nil
}

// RevokeByGrantID revokes a grant and deletes every artifact issued under it.
func (m *ModelAdapter) RevokeByGrantID(ctx context.Context, grantID string) error {
	a := m.adapter
	grantHash := hash(grantID)
	a.mu.Lock()
	if pending, ok := a.pendingRevocations[grantHash]; ok {
		a.mu.Unlock()
		<-pending.done
		return pending.err
	}
	flight := &revocationFlight{done: make(chan struct{})}
	a.pendingRevocations[grantHash] = flight
	a.mu.Unlock()
	flight.err = a.store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
		existing, err := tx.Get(ctx, "oauthRevokedGrants", grantHash)
		if err != nil {
			return err
		}
		if existing == nil {
			if _, err := tx.Insert(ctx, "oauthRevokedGrants", core.NewObject("id", grantHash, "tenantId", ProtocolTenant, "revokedAt", a.now())); err != nil {
				return err
			}
		}
		rows, err := tx.Find(ctx, "oauthArtifacts", core.NewObject("grantIdHash", grantHash), nil)
		if err != nil {
			return err
		}
		for _, row := range rows {
			if err := tx.Delete(ctx, "oauthArtifacts", str(row, "id")); err != nil {
				return err
			}
		}
		return tx.Delete(ctx, "oauthArtifacts", hash("Grant:"+grantID))
	})
	a.mu.Lock()
	delete(a.pendingRevocations, grantHash)
	a.mu.Unlock()
	close(flight.done)
	return flight.err
}
