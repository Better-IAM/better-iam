package server

// Port of packages/server/src/ssh-ca.ts: OpenSSH certificate authority primitives: the SSH wire encoding (RFC 4251),
// public key parsing, certificates as specified in OpenSSH's PROTOCOL.certkeys, and key revocation lists
// (PROTOCOL.krl). Authorities are Ed25519 keys; the keys they certify may be Ed25519, ECDSA (P-256/384/521), RSA
// (2048 bits or more), or FIDO security keys (`sk-*`). Nothing here touches storage; `api_ssh.go` seals authority
// keys and records what was issued.
//
// Values that TypeScript keeps as Buffers are []byte members of the returned objects, and bigints (serials, the KRL
// version) are uint64. Those members are stored with SetRaw: core.NewObject / Set would normalize them (a []byte
// becomes a base64 string and a uint64 a float64), so callers building a spec should use SetRaw as well. The
// readers below still accept a base64 string for a byte member and a decimal string for a serial.

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"math"
	"math/big"
	"math/bits"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// SshKeyTypes are the public key algorithms accepted in certificates, with their certificate type names, in the
// TypeScript declaration order (ssh-ca.ts sshKeyTypes).
var SshKeyTypes = []struct{ Key, Certificate string }{
	{"ssh-ed25519", "ssh-ed25519-cert-v01@openssh.com"},
	{"ecdsa-sha2-nistp256", "ecdsa-sha2-nistp256-cert-v01@openssh.com"},
	{"ecdsa-sha2-nistp384", "ecdsa-sha2-nistp384-cert-v01@openssh.com"},
	{"ecdsa-sha2-nistp521", "ecdsa-sha2-nistp521-cert-v01@openssh.com"},
	{"ssh-rsa", "ssh-rsa-cert-v01@openssh.com"},
	{"sk-ssh-ed25519@openssh.com", "sk-ssh-ed25519-cert-v01@openssh.com"},
	{"sk-ecdsa-sha2-nistp256@openssh.com", "sk-ecdsa-sha2-nistp256-cert-v01@openssh.com"},
}

// sshCertificateType is sshKeyTypes[type] ("" for an unknown type).
func sshCertificateType(keyType string) string {
	for _, entry := range SshKeyTypes {
		if entry.Key == keyType {
			return entry.Certificate
		}
	}
	return ""
}

// SshExtensions are the extensions a user certificate may carry; `permit-pty` and `permit-user-rc` are granted to
// every login (ssh-ca.ts sshExtensions).
var SshExtensions = []string{
	"permit-X11-forwarding",
	"permit-agent-forwarding",
	"permit-port-forwarding",
	"permit-pty",
	"permit-user-rc",
	"no-touch-required",
}

type sshCurve struct {
	name  string
	curve ecdh.Curve
	size  int
}

var sshCurves = map[string]sshCurve{
	"ecdsa-sha2-nistp256":                {"nistp256", ecdh.P256(), 32},
	"ecdsa-sha2-nistp384":                {"nistp384", ecdh.P384(), 48},
	"ecdsa-sha2-nistp521":                {"nistp521", ecdh.P521(), 66},
	"sk-ecdsa-sha2-nistp256@openssh.com": {"nistp256", ecdh.P256(), 32},
}

const sshDefaultKeyMessage = `Enter an OpenSSH public key such as "ssh-ed25519 AAAA..."`

// sshInvalidKey is invalidKey(message): INVALID_INPUT.
func sshInvalidKey(message string) *core.IamError {
	if message == "" {
		message = sshDefaultKeyMessage
	}
	return core.NewIamError("INVALID_INPUT", message)
}

// SshWriter builds SSH wire-format data: bytes, uint32/uint64 big-endian, length-prefixed strings.
type SshWriter struct {
	buffer bytes.Buffer
}

// Byte appends one byte.
func (w *SshWriter) Byte(value byte) *SshWriter {
	w.buffer.WriteByte(value)
	return w
}

// U32 appends a big-endian uint32.
func (w *SshWriter) U32(value uint32) *SshWriter {
	var buffer [4]byte
	binary.BigEndian.PutUint32(buffer[:], value)
	w.buffer.Write(buffer[:])
	return w
}

// U64 appends a big-endian uint64.
func (w *SshWriter) U64(value uint64) *SshWriter {
	var buffer [8]byte
	binary.BigEndian.PutUint64(buffer[:], value)
	w.buffer.Write(buffer[:])
	return w
}

// String appends a length-prefixed byte string.
func (w *SshWriter) String(data []byte) *SshWriter {
	w.U32(uint32(len(data)))
	w.buffer.Write(data)
	return w
}

// Text appends a length-prefixed UTF-8 string (Buffer.from(value, 'utf8')).
func (w *SshWriter) Text(value string) *SshWriter {
	return w.String(utf8Bytes(value))
}

// Raw appends bytes as they are.
func (w *SshWriter) Raw(data []byte) *SshWriter {
	w.buffer.Write(data)
	return w
}

// Bytes is the data written so far (toBuffer).
func (w *SshWriter) Bytes() []byte {
	return append([]byte(nil), w.buffer.Bytes()...)
}

// SshReader reads SSH wire-format data; every read is bounds-checked and a short buffer is an invalid key.
type SshReader struct {
	buffer []byte
	offset int
}

// NewSshReader reads buffer from its start.
func NewSshReader(buffer []byte) *SshReader {
	return &SshReader{buffer: buffer}
}

func (r *SshReader) take(length int) ([]byte, error) {
	if length < 0 || r.offset+length > len(r.buffer) {
		return nil, sshInvalidKey("Truncated data")
	}
	slice := r.buffer[r.offset : r.offset+length]
	r.offset += length
	return slice, nil
}

// Byte reads one byte.
func (r *SshReader) Byte() (byte, error) {
	data, err := r.take(1)
	if err != nil {
		return 0, err
	}
	return data[0], nil
}

// U32 reads a big-endian uint32.
func (r *SshReader) U32() (uint32, error) {
	data, err := r.take(4)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(data), nil
}

// U64 reads a big-endian uint64.
func (r *SshReader) U64() (uint64, error) {
	data, err := r.take(8)
	if err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint64(data), nil
}

// String reads a length-prefixed byte string.
func (r *SshReader) String() ([]byte, error) {
	length, err := r.U32()
	if err != nil {
		return nil, err
	}
	if uint64(length) > uint64(len(r.buffer)) {
		return nil, sshInvalidKey("Truncated data")
	}
	return r.take(int(length))
}

// Text reads a length-prefixed string as UTF-8 (toString('utf8')).
func (r *SshReader) Text() (string, error) {
	data, err := r.String()
	if err != nil {
		return "", err
	}
	return decodeUTF8(data), nil
}

// Position is the read offset.
func (r *SshReader) Position() int { return r.offset }

// Done reports whether everything was read.
func (r *SshReader) Done() bool { return r.offset == len(r.buffer) }

// sshRaw builds an object whose values are stored as they are (Buffers as []byte, bigints as uint64).
func sshRaw(pairs ...any) *core.Object {
	object := core.NewObject()
	for index := 0; index+1 < len(pairs); index += 2 {
		object.SetRaw(pairs[index].(string), pairs[index+1])
	}
	return object
}

// sshBytes reads a Buffer member: []byte (or a named byte slice such as an ed25519 key), or a base64 string (what
// core.Object.Set makes of a []byte).
func sshBytes(value any) []byte {
	switch v := value.(type) {
	case []byte:
		return v
	case ed25519.PublicKey:
		return v
	case ed25519.PrivateKey:
		return v
	case string:
		return nodeBase64Decode(v)
	}
	return nil
}

// sshStrings reads a string array member ([]string or []any).
func sshStrings(value any) []string {
	switch v := value.(type) {
	case []string:
		return v
	case []any:
		out := make([]string, len(v))
		for index, item := range v {
			out[index] = jsString(item)
		}
		return out
	}
	return nil
}

// sshBigUint is BigInt(value) for a uint64 field: uint64 and other Go integers, an integral number, a decimal
// string, or a *big.Int. It fails (as BigInt and writeBigUInt64BE throw) for anything else or out of range.
func sshBigUint(value any) (uint64, error) {
	switch v := value.(type) {
	case uint64:
		return v, nil
	case uint32:
		return uint64(v), nil
	case uint:
		return uint64(v), nil
	case int:
		if v >= 0 {
			return uint64(v), nil
		}
	case int64:
		if v >= 0 {
			return uint64(v), nil
		}
	case float64:
		if v >= 0 && v == math.Trunc(v) && v < 18446744073709551616 {
			return uint64(v), nil
		}
	case string:
		text := core.JSTrim(v)
		if text == "" {
			return 0, nil
		}
		if parsed, err := strconv.ParseUint(text, 10, 64); err == nil {
			return parsed, nil
		}
		if parsed, ok := new(big.Int).SetString(text, 0); ok && parsed.Sign() >= 0 && parsed.IsUint64() {
			return parsed.Uint64(), nil
		}
	case *big.Int:
		if v != nil && v.Sign() >= 0 && v.IsUint64() {
			return v.Uint64(), nil
		}
	}
	return 0, core.NewIamError("INVALID_INPUT", "The value "+jsString(value)+" is not a valid unsigned 64-bit integer")
}

// SshFingerprint (ssh-ca.ts sshFingerprint): `SHA256:` plus the unpadded base64 SHA-256 of a key blob.
func SshFingerprint(blob []byte) (result string, err error) {
	return sshFingerprint(blob), nil
}

func sshFingerprint(blob []byte) string {
	sum := sha256.Sum256(blob)
	return "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
}

// SshKeyLine (ssh-ca.ts sshKeyLine): An `authorized_keys`-style line for a key blob ("" comment: none).
func SshKeyLine(blob []byte, comment string) (result string, err error) {
	keyType, err := NewSshReader(blob).Text()
	if err != nil {
		return "", err
	}
	line := keyType + " " + base64.StdEncoding.EncodeToString(blob)
	if comment != "" {
		line += " " + comment
	}
	return line, nil
}

// sshMpintBits is the bit length of an mpint (leading zero bytes ignored).
func sshMpintBits(value []byte) int {
	start := 0
	for start < len(value) && value[start] == 0 {
		start++
	}
	if start == len(value) {
		return 0
	}
	return (len(value)-start-1)*8 + bits.Len8(value[start])
}

func sshCheckEcPoint(keyType, curveName string, point []byte) error {
	curve := sshCurves[keyType]
	if curveName != curve.name {
		return sshInvalidKey("The ECDSA curve does not match the key type")
	}
	if len(point) != 1+2*curve.size || point[0] != 4 {
		return sshInvalidKey("ECDSA keys must be uncompressed points")
	}
	if _, err := curve.curve.NewPublicKey(point); err != nil {
		return sshInvalidKey("The ECDSA point is not on its curve")
	}
	return nil
}

var sshBase64Data = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)

// sshFields is `line.trim().split(/\s+/)`.
func sshFields(line string) []string {
	return strings.FieldsFunc(core.JSTrim(line), jsSpace)
}

// ParseSshPublicKey (ssh-ca.ts parseSshPublicKey): Parses and validates one public key line (`type base64
// [comment]`). Certificates, DSA keys, RSA keys under 2048 bits, malformed points and trailing data are refused.
// options may hold minRsaBits (nil: none). The result has type, blob ([]byte), fields ([]byte: the blob after its
// type string), fingerprint, securityKey, and bits (RSA) and comment when there are any.
func ParseSshPublicKey(line any, options *core.Object) (result *core.Object, err error) {
	text, ok := line.(string)
	if !ok || utf16Len(text) > 16384 {
		return nil, sshInvalidKey("")
	}
	parts := sshFields(text)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		return nil, sshInvalidKey("")
	}
	typeName, data, rest := parts[0], parts[1], parts[2:]
	if sshCertificateType(typeName) == "" {
		if strings.Contains(typeName, "-cert-v01@") {
			return nil, sshInvalidKey("Send the public key, not a certificate")
		}
		return nil, sshInvalidKey("Unsupported key type " + jsSlice(typeName, 64))
	}
	keyType := typeName
	if !sshBase64Data.MatchString(data) {
		return nil, sshInvalidKey("")
	}
	blob := nodeBase64Decode(data)
	reader := NewSshReader(blob)
	embedded, err := reader.Text()
	if err != nil {
		return nil, err
	}
	if embedded != keyType {
		return nil, sshInvalidKey("The key data does not match its type")
	}
	fieldsStart := 4 + len(keyType)
	var keyBits *float64
	switch keyType {
	case "ssh-ed25519", "sk-ssh-ed25519@openssh.com":
		raw, err := reader.String()
		if err != nil {
			return nil, err
		}
		if len(raw) != 32 {
			return nil, sshInvalidKey("Ed25519 keys are 32 bytes")
		}
	case "ssh-rsa":
		e, err := reader.String()
		if err != nil {
			return nil, err
		}
		n, err := reader.String()
		if err != nil {
			return nil, err
		}
		// Canonical mpints only: a padded encoding would fingerprint differently from the key sshd logs.
		for _, part := range [][]byte{e, n} {
			if len(part) == 0 || part[0]&0x80 != 0 || (part[0] == 0 && (len(part) == 1 || part[1]&0x80 == 0)) {
				return nil, sshInvalidKey("The RSA key is not canonically encoded")
			}
		}
		size := float64(sshMpintBits(n))
		keyBits = &size
		minimum := 2048.0
		if options != nil {
			if value := options.Get("minRsaBits"); !nullish(value) {
				minimum = jsNumber(value)
			}
		}
		if size < minimum {
			return nil, sshInvalidKey("RSA keys must have at least " + jsString(minimum) + " bits")
		}
		if size > 16384 {
			return nil, sshInvalidKey("RSA keys may have at most 16384 bits")
		}
		// createPublicKey({ kty: 'RSA', n, e }) accepts any positive modulus and exponent, which the canonical
		// encoding above already guarantees: 'Invalid RSA key' is never reached.
	default:
		curveName, err := reader.Text()
		if err != nil {
			return nil, err
		}
		point, err := reader.String()
		if err != nil {
			return nil, err
		}
		if err := sshCheckEcPoint(keyType, curveName, point); err != nil {
			return nil, err
		}
	}
	securityKey := strings.HasPrefix(keyType, "sk-")
	if securityKey {
		application, err := reader.Text()
		if err != nil {
			return nil, err
		}
		if !strings.HasPrefix(application, "ssh:") {
			return nil, sshInvalidKey("Security keys need an ssh: application")
		}
	}
	if !reader.Done() {
		return nil, sshInvalidKey("Unexpected data after the key")
	}
	comment := jsSlice(strings.Join(rest, " "), 256)
	result = sshRaw(
		"type", keyType,
		"blob", blob,
		"fields", blob[fieldsStart:],
		"fingerprint", sshFingerprint(blob),
		"securityKey", securityKey,
	)
	if keyBits != nil {
		result.SetRaw("bits", *keyBits)
	}
	if comment != "" {
		result.SetRaw("comment", comment)
	}
	return result, nil
}

// GenerateSshAuthorityKey (ssh-ca.ts generateSshAuthorityKey): A new Ed25519 authority key, with the private key as
// base64 PKCS#8 DER (the caller seals it): { publicBlob []byte, privatePkcs8 string }.
func GenerateSshAuthorityKey() (result *core.Object, err error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	der, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, err
	}
	return sshRaw(
		"publicBlob", new(SshWriter).Text("ssh-ed25519").String(publicKey).Bytes(),
		"privatePkcs8", base64.StdEncoding.EncodeToString(der),
	), nil
}

// SshSigningKey (ssh-ca.ts sshSigningKey): Opens a stored authority key: { publicBlob []byte, privateKey
// ed25519.PrivateKey }.
func SshSigningKey(publicBlob []byte, privatePkcs8 string) (result *core.Object, err error) {
	parsed, err := x509.ParsePKCS8PrivateKey(nodeBase64Decode(privatePkcs8))
	if err != nil {
		return nil, err
	}
	privateKey, ok := parsed.(ed25519.PrivateKey)
	if !ok {
		return nil, core.NewIamError("INVALID_INPUT", "SSH authority keys are Ed25519 keys")
	}
	return sshRaw("publicBlob", publicBlob, "privateKey", privateKey), nil
}

// sshPrivateKey reads a signing key's privateKey member.
func sshPrivateKey(key *core.Object) (ed25519.PrivateKey, error) {
	raw := sshBytes(key.Get("privateKey"))
	switch len(raw) {
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(raw), nil
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(raw), nil
	}
	return nil, core.NewIamError("INVALID_INPUT", "SSH authority keys are Ed25519 keys")
}

// SshSerial (ssh-ca.ts sshSerial): A random non-zero 63-bit serial (KRLs cannot revoke serial 0), as a uint64.
func SshSerial() (result any, err error) {
	for {
		var buffer [8]byte
		if _, err := rand.Read(buffer[:]); err != nil {
			return nil, err
		}
		value := binary.BigEndian.Uint64(buffer[:]) & 0x7fffffffffffffff
		if value != 0 {
			return value, nil
		}
	}
}

// sshByBytes compares strings by their UTF-8 bytes (Buffer.compare(Buffer.from(a), Buffer.from(b))).
func sshByBytes(a, b string) int {
	return bytes.Compare(utf8Bytes(a), utf8Bytes(b))
}

type sshOption struct {
	name  string
	value string
}

// sshPackOptions packs name/data pairs in lexical order; an option's data is itself a string (empty: no data).
func sshPackOptions(entries []sshOption) []byte {
	sorted := append([]sshOption(nil), entries...)
	sort.SliceStable(sorted, func(i, j int) bool { return sshByBytes(sorted[i].name, sorted[j].name) < 0 })
	writer := new(SshWriter)
	for _, entry := range sorted {
		writer.Text(entry.name)
		if entry.value == "" {
			writer.String(nil)
		} else {
			writer.String(new(SshWriter).Text(entry.value).Bytes())
		}
	}
	return writer.Bytes()
}

// sshSign signs data with an Ed25519 authority: an `ssh-ed25519` signature blob.
func sshSign(key *core.Object, data []byte) ([]byte, error) {
	privateKey, err := sshPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return new(SshWriter).Text("ssh-ed25519").String(ed25519.Sign(privateKey, data)).Bytes(), nil
}

// sshSeconds is BigInt(seconds) for a validity bound.
func sshSeconds(value any) (uint64, error) {
	return sshBigUint(jsNumber(value))
}

// SignSshCertificate (ssh-ca.ts signSshCertificate): Issues an OpenSSH certificate; returns { blob []byte, line }
// (the `*-cert.pub` line). spec holds key (a ParseSshPublicKey result), serial (uint64), kind (SshCertUser or
// SshCertHost), keyId, principals, validAfter and validBefore (seconds since the epoch), and optionally
// criticalOptions (an object of strings; the value may be empty) and extensions.
func SignSshCertificate(authority *core.Object, spec *core.Object, comment string) (result *core.Object, err error) {
	key, _ := spec.Get("key").(*core.Object)
	if key == nil {
		return nil, core.NewIamError("INVALID_INPUT", "A certificate needs a public key")
	}
	certificateType := sshCertificateType(jsString(key.Get("type")))
	principals := new(SshWriter)
	for _, principal := range sshStrings(spec.Get("principals")) {
		principals.Text(principal)
	}
	serial, err := sshBigUint(spec.Get("serial"))
	if err != nil {
		return nil, err
	}
	validAfter, err := sshSeconds(spec.Get("validAfter"))
	if err != nil {
		return nil, err
	}
	validBefore, err := sshSeconds(spec.Get("validBefore"))
	if err != nil {
		return nil, err
	}
	var critical []sshOption
	if options, ok := spec.Get("criticalOptions").(*core.Object); ok {
		options.Entries(func(name string, value any) bool {
			text := ""
			if !isUndefined(value) {
				text = jsString(value)
			}
			critical = append(critical, sshOption{name, text})
			return true
		})
	}
	var extensions []sshOption
	for _, name := range sshStrings(spec.Get("extensions")) {
		extensions = append(extensions, sshOption{name, ""})
	}
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	authorityBlob := sshBytes(authority.Get("publicBlob"))
	body := new(SshWriter).
		Text(certificateType).
		String(nonce).
		Raw(sshBytes(key.Get("fields"))).
		U64(serial).
		U32(uint32(jsNumber(spec.Get("kind")))).
		Text(jsString(spec.Get("keyId"))).
		String(principals.Bytes()).
		U64(validAfter).
		U64(validBefore).
		String(sshPackOptions(critical)).
		String(sshPackOptions(extensions)).
		String(nil).
		String(authorityBlob).
		Bytes()
	signature, err := sshSign(authority, body)
	if err != nil {
		return nil, err
	}
	blob := append(body, new(SshWriter).String(signature).Bytes()...)
	line := certificateType + " " + base64.StdEncoding.EncodeToString(blob)
	if comment != "" {
		line += " " + comment
	}
	return sshRaw("blob", blob, "line", line), nil
}

// sshUnpackOptions reads name/data pairs (with their string values, or names only).
func sshUnpackOptions(data []byte, withValues bool) ([]sshOption, error) {
	reader := NewSshReader(data)
	var result []sshOption
	for !reader.Done() {
		name, err := reader.Text()
		if err != nil {
			return nil, err
		}
		value, err := reader.String()
		if err != nil {
			return nil, err
		}
		text := ""
		if withValues && len(value) > 0 {
			if text, err = NewSshReader(value).Text(); err != nil {
				return nil, err
			}
		}
		result = append(result, sshOption{name, text})
	}
	return result, nil
}

// ParseSshCertificate (ssh-ca.ts parseSshCertificate): Decodes a certificate line (`*-cert-v01@openssh.com base64
// [comment]`) into the fields PROTOCOL.certkeys defines, with its signature checked (only Ed25519 authorities
// verify): type, keyType, publicKeyFingerprint, serial (uint64), kind, keyId, principals, validAfter, validBefore,
// criticalOptions, extensions, signatureKey ([]byte), signatureKeyFingerprint, signatureValid.
func ParseSshCertificate(line string) (*core.Object, error) {
	parts := sshFields(line)
	typeName, data := "", ""
	if len(parts) > 0 {
		typeName = parts[0]
	}
	if len(parts) > 1 {
		data = parts[1]
	}
	keyType := ""
	for _, entry := range SshKeyTypes {
		if entry.Certificate == typeName {
			keyType = entry.Key
			break
		}
	}
	if keyType == "" || data == "" {
		return nil, sshInvalidKey("Not an OpenSSH certificate")
	}
	blob := nodeBase64Decode(data)
	cert := NewSshReader(blob)
	embedded, err := cert.Text()
	if err != nil {
		return nil, err
	}
	if embedded != typeName {
		return nil, sshInvalidKey("The certificate data does not match its type")
	}
	if _, err := cert.String(); err != nil { // nonce
		return nil, err
	}
	// The embedded public key fields, by type (ed25519: pk; sk-ed25519: pk, application; rsa: e, n;
	// ecdsa: curve, point; sk-ecdsa: curve, point, application), rebuild the plain key blob.
	keyStart := cert.Position()
	fieldCount := 2
	if keyType == "ssh-ed25519" {
		fieldCount = 1
	} else if keyType == "sk-ecdsa-sha2-nistp256@openssh.com" {
		fieldCount = 3
	}
	for index := 0; index < fieldCount; index++ {
		if _, err := cert.String(); err != nil {
			return nil, err
		}
	}
	keyBlob := append(new(SshWriter).Text(keyType).Bytes(), blob[keyStart:cert.Position()]...)
	serial, err := cert.U64()
	if err != nil {
		return nil, err
	}
	kind, err := cert.U32()
	if err != nil {
		return nil, err
	}
	keyID, err := cert.Text()
	if err != nil {
		return nil, err
	}
	principalData, err := cert.String()
	if err != nil {
		return nil, err
	}
	principalReader := NewSshReader(principalData)
	principals := []any{}
	for !principalReader.Done() {
		principal, err := principalReader.Text()
		if err != nil {
			return nil, err
		}
		principals = append(principals, principal)
	}
	validAfter, err := cert.U64()
	if err != nil {
		return nil, err
	}
	validBefore, err := cert.U64()
	if err != nil {
		return nil, err
	}
	criticalData, err := cert.String()
	if err != nil {
		return nil, err
	}
	critical, err := sshUnpackOptions(criticalData, true)
	if err != nil {
		return nil, err
	}
	criticalOptions := core.NewObject()
	for _, option := range critical {
		criticalOptions.SetRaw(option.name, option.value)
	}
	extensionData, err := cert.String()
	if err != nil {
		return nil, err
	}
	unpacked, err := sshUnpackOptions(extensionData, false)
	if err != nil {
		return nil, err
	}
	extensions := make([]any, len(unpacked))
	for index, option := range unpacked {
		extensions[index] = option.name
	}
	if _, err := cert.String(); err != nil { // reserved
		return nil, err
	}
	signatureKey, err := cert.String()
	if err != nil {
		return nil, err
	}
	bodyLength := cert.Position()
	signatureData, err := cert.String()
	if err != nil {
		return nil, err
	}
	if !cert.Done() {
		return nil, sshInvalidKey("Unexpected data after the certificate")
	}
	signature := NewSshReader(signatureData)
	algorithm, err := signature.Text()
	if err != nil {
		return nil, err
	}
	value, err := signature.String()
	if err != nil {
		return nil, err
	}
	signatureValid := false
	caReader := NewSshReader(signatureKey)
	if algorithm == "ssh-ed25519" {
		caType, err := caReader.Text()
		if err != nil {
			return nil, err
		}
		if caType == "ssh-ed25519" {
			raw, err := caReader.String()
			if err != nil {
				return nil, err
			}
			if len(raw) == ed25519.PublicKeySize {
				signatureValid = ed25519.Verify(ed25519.PublicKey(raw), blob[:bodyLength], value)
			}
		}
	}
	// "Forever" (2^64-1) does not fit a safe integer; it is never issued here.
	const maxSafeInteger = 1<<53 - 1
	before := float64(validBefore)
	if validBefore > maxSafeInteger {
		before = maxSafeInteger
	}
	return sshRaw(
		"type", typeName,
		"keyType", keyType,
		"publicKeyFingerprint", sshFingerprint(keyBlob),
		"serial", serial,
		"kind", float64(kind),
		"keyId", keyID,
		"principals", principals,
		"validAfter", float64(validAfter),
		"validBefore", before,
		"criticalOptions", criticalOptions,
		"extensions", extensions,
		"signatureKey", signatureKey,
		"signatureKeyFingerprint", sshFingerprint(signatureKey),
		"signatureValid", signatureValid,
	), nil
}

const (
	krlMagic                 = 0x5353484b524c0a00
	krlSectionCertificates   = 1
	krlSectionExplicitKey    = 2
	krlSectionCertSerialList = 0x20
	krlSectionCertKeyID      = 0x23
	sshMillisecondsPerSecond = 1000
)

// BuildSshKrl (ssh-ca.ts buildSshKrl): A binary OpenSSH key revocation list (PROTOCOL.krl) for sshd `RevokedKeys`
// and ssh `RevokedHostKeys`: certificate serials and key IDs per authority, plus plain keys revoked outright (such
// as a disabled host's key). input holds version (uint64), generatedAt (epoch milliseconds), comment, authorities
// (objects with authority []byte, serials and keyIds) and keys ([]byte blobs).
func BuildSshKrl(input *core.Object) (result []byte, err error) {
	version, err := sshBigUint(input.Get("version"))
	if err != nil {
		return nil, err
	}
	generatedAt, err := sshBigUint(math.Floor(jsNumber(input.Get("generatedAt")) / sshMillisecondsPerSecond))
	if err != nil {
		return nil, err
	}
	comment := ""
	if value := input.Get("comment"); !nullish(value) {
		comment = jsString(value)
	}
	writer := new(SshWriter).
		U64(krlMagic).
		U32(1).
		U64(version).
		U64(generatedAt).
		U64(0).
		String(nil).
		Text(comment)
	for _, item := range sshList(input.Get("authorities")) {
		section, _ := item.(*core.Object)
		if section == nil {
			continue
		}
		seen := map[uint64]bool{}
		var serials []uint64
		for _, value := range sshList(section.Get("serials")) {
			serial, err := sshBigUint(value)
			if err != nil {
				return nil, err
			}
			if !seen[serial] {
				seen[serial] = true
				if serial > 0 {
					serials = append(serials, serial)
				}
			}
		}
		sort.Slice(serials, func(i, j int) bool { return serials[i] < serials[j] })
		keyIDs := unique(sshStrings(section.Get("keyIds")))
		sort.SliceStable(keyIDs, func(i, j int) bool { return sshByBytes(keyIDs[i], keyIDs[j]) < 0 })
		if len(serials) == 0 && len(keyIDs) == 0 {
			continue
		}
		body := new(SshWriter).String(sshBytes(section.Get("authority"))).String(nil)
		if len(serials) > 0 {
			list := new(SshWriter)
			for _, serial := range serials {
				list.U64(serial)
			}
			body.Byte(krlSectionCertSerialList).String(list.Bytes())
		}
		if len(keyIDs) > 0 {
			list := new(SshWriter)
			for _, keyID := range keyIDs {
				list.Text(keyID)
			}
			body.Byte(krlSectionCertKeyID).String(list.Bytes())
		}
		writer.Byte(krlSectionCertificates).String(body.Bytes())
	}
	seenKeys := map[string]bool{}
	var keys [][]byte
	for _, value := range sshList(input.Get("keys")) {
		key := sshBytes(value)
		encoded := base64.StdEncoding.EncodeToString(key)
		if !seenKeys[encoded] {
			seenKeys[encoded] = true
			keys = append(keys, key)
		}
	}
	if len(keys) > 0 {
		sort.SliceStable(keys, func(i, j int) bool { return bytes.Compare(keys[i], keys[j]) < 0 })
		list := new(SshWriter)
		for _, key := range keys {
			list.String(key)
		}
		writer.Byte(krlSectionExplicitKey).String(list.Bytes())
	}
	return writer.Bytes(), nil
}

// sshList reads an array member of any slice type as []any.
func sshList(value any) []any {
	switch v := value.(type) {
	case []any:
		return v
	case []string:
		return stringsOf(v)
	case [][]byte:
		out := make([]any, len(v))
		for index, item := range v {
			out[index] = item
		}
		return out
	case []uint64:
		out := make([]any, len(v))
		for index, item := range v {
			out[index] = item
		}
		return out
	case []*core.Object:
		out := make([]any, len(v))
		for index, item := range v {
			out[index] = item
		}
		return out
	}
	return nil
}

// Node's net.isIP (lib/internal/net.js): 4, 6, or 0.
var (
	nodeIPv4Seg = `(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9][0-9]|[0-9])`
	nodeIPv4Str = `(?:` + nodeIPv4Seg + `\.){3}` + nodeIPv4Seg
	nodeIPv6Seg = `(?:[0-9a-fA-F]{1,4})`
	nodeIPv4    = regexp.MustCompile(`^` + nodeIPv4Str + `$`)
	nodeIPv6    = regexp.MustCompile(`^(?:` +
		`(?:` + nodeIPv6Seg + `:){7}(?:` + nodeIPv6Seg + `|:)|` +
		`(?:` + nodeIPv6Seg + `:){6}(?:` + nodeIPv4Str + `|:` + nodeIPv6Seg + `|:)|` +
		`(?:` + nodeIPv6Seg + `:){5}(?::` + nodeIPv4Str + `|(?::` + nodeIPv6Seg + `){1,2}|:)|` +
		`(?:` + nodeIPv6Seg + `:){4}(?:(?::` + nodeIPv6Seg + `){0,1}:` + nodeIPv4Str + `|(?::` + nodeIPv6Seg + `){1,3}|:)|` +
		`(?:` + nodeIPv6Seg + `:){3}(?:(?::` + nodeIPv6Seg + `){0,2}:` + nodeIPv4Str + `|(?::` + nodeIPv6Seg + `){1,4}|:)|` +
		`(?:` + nodeIPv6Seg + `:){2}(?:(?::` + nodeIPv6Seg + `){0,3}:` + nodeIPv4Str + `|(?::` + nodeIPv6Seg + `){1,5}|:)|` +
		`(?:` + nodeIPv6Seg + `:){1}(?:(?::` + nodeIPv6Seg + `){0,4}:` + nodeIPv4Str + `|(?::` + nodeIPv6Seg + `){1,6}|:)|` +
		`(?::(?:(?::` + nodeIPv6Seg + `){0,5}:` + nodeIPv4Str + `|(?::` + nodeIPv6Seg + `){1,7}|:))` +
		`)(?:%[0-9a-zA-Z-.:]{1,})?$`)
)

// nodeIsIP is net.isIP: 4 for an IPv4 address, 6 for an IPv6 address (zone IDs included), 0 otherwise.
func nodeIsIP(value string) int {
	if nodeIPv4.MatchString(value) {
		return 4
	}
	if nodeIPv6.MatchString(value) {
		return 6
	}
	return 0
}

// sshHostLabel is /^(?!-)[a-z0-9-]{1,63}(?<!-)$/i.
func sshHostLabel(label string) bool {
	if len(label) < 1 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
		return false
	}
	for index := 0; index < len(label); index++ {
		c := label[index]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

var sshNumericLabel = regexp.MustCompile(`^(?:[0-9]+|0x[0-9a-f]+)$`)

// SshHostAddress (ssh-ca.ts sshHostAddress): A host certificate principal: a DNS name (a leading `*.` is refused),
// or an IPv4/IPv6 address.
func SshHostAddress(value any) (result string, err error) {
	text, ok := value.(string)
	if !ok {
		return "", invalidInput("Invalid host address")
	}
	address := strings.TrimSuffix(core.JSLower(core.JSTrim(text)), ".")
	// No IPv6 zone IDs (`fe80::1%eth0`): they name an interface, not a host.
	if nodeIsIP(address) != 0 && !strings.Contains(address, "%") {
		return address, nil
	}
	labels := strings.Split(address, ".")
	valid := true
	for _, label := range labels {
		if !sshHostLabel(label) {
			valid = false
			break
		}
	}
	if utf16Len(address) > 253 ||
		strings.Contains(address, "%") ||
		!valid ||
		// A dotted name ending in digits (`127.1`, `10.0x1`) reads as an address to some resolvers.
		(len(labels) > 1 && sshNumericLabel.MatchString(labels[len(labels)-1])) {
		return "", invalidInput("Invalid host address " + jsSlice(address, 64))
	}
	return address, nil
}

var sshLoginPattern = regexp.MustCompile(`^[a-zA-Z_][a-zA-Z0-9_.-]{0,31}$`)

// SshLogin (ssh-ca.ts sshLogin): A Unix login name, as certificate principals carry them: portable user names only.
func SshLogin(value any) (result string, err error) {
	text, ok := value.(string)
	if !ok || !sshLoginPattern.MatchString(text) || strings.HasSuffix(text, ".") {
		return "", invalidInput(`Logins are 1-32 letters, digits, "_", "." or "-" and start with a letter or "_"`)
	}
	return text, nil
}

// SshLoginPrincipal (ssh-ca.ts sshLoginPrincipal): The principal a host accepts for a login: `{login}@{host}`, so a
// certificate names the hosts it opens.
func SshLoginPrincipal(login string, host string) (result string, err error) {
	return login + "@" + host, nil
}

// SshCertHost is ssh-ca.ts SSH_CERT_HOST.
const SshCertHost = 2

// SshCertUser is ssh-ca.ts SSH_CERT_USER.
const SshCertUser = 1
