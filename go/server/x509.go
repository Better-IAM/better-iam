package server

// Port of packages/server/src/x509.ts: the X.509 layer of the private certificate authority (pki.go): a DER encoder
// and a bounds-checked DER reader, PKCS#10 certification requests (built for clients and tests, parsed and verified for
// issuance), certificates, and certificate revocation lists (RFC 5280). The TypeScript reads what it writes with
// Node's crypto.X509Certificate (OpenSSL); this port reads certificates with its own DER reader (x509Certificate
// below) so that what is accepted does not depend on Go's stricter certificate parser.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math"
	"math/big"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/Better-IAM/better-iam/go/auth"
	"github.com/Better-IAM/better-iam/go/core"
)

// ---------------------------------------------------------------------------------------------------------------
// DER encoding

func derLength(size int) []byte {
	if size < 0x80 {
		return []byte{byte(size)}
	}
	var bytes []byte
	for rest := size; rest > 0; rest /= 256 {
		bytes = append([]byte{byte(rest & 0xff)}, bytes...)
	}
	return append([]byte{0x80 | byte(len(bytes))}, bytes...)
}

// derTLV is x509.ts tlv.
func derTLV(tag byte, contents []byte) []byte {
	out := append([]byte{tag}, derLength(len(contents))...)
	return append(out, contents...)
}

func derConcat(items ...[]byte) []byte {
	var out []byte
	for _, item := range items {
		out = append(out, item...)
	}
	if out == nil {
		out = []byte{}
	}
	return out
}

func derSequence(items ...[]byte) []byte { return derTLV(0x30, derConcat(items...)) }
func derSet(items ...[]byte) []byte      { return derTLV(0x31, derConcat(items...)) }
func derNull() []byte                    { return []byte{0x05, 0x00} }
func derBoolean(value bool) []byte {
	if value {
		return derTLV(0x01, []byte{0xff})
	}
	return derTLV(0x01, []byte{0x00})
}
func derOctetString(value []byte) []byte     { return derTLV(0x04, value) }
func derUTF8String(value string) []byte      { return derTLV(0x0c, utf8Bytes(value)) }
func derPrintableString(value string) []byte { return derTLV(0x13, asciiBytes(value)) }

// derExplicit is `[n] EXPLICIT`: a constructed context-specific wrapper.
func derExplicit(tag byte, value []byte) []byte { return derTLV(0xa0|tag, value) }

// asciiBytes is Buffer.from(value, 'ascii'): one byte per UTF-16 unit (its low byte).
func asciiBytes(value string) []byte {
	units := utf16.Encode([]rune(value))
	out := make([]byte, len(units))
	for index, unit := range units {
		out[index] = byte(unit)
	}
	return out
}

// derInteger is x509.ts integer for a Buffer: a non-negative INTEGER in minimal two's complement form.
func derInteger(bytes []byte) []byte {
	start := 0
	for start < len(bytes)-1 && bytes[start] == 0 && bytes[start+1]&0x80 == 0 {
		start++
	}
	bytes = bytes[start:]
	if len(bytes) == 0 {
		bytes = []byte{0}
	}
	if bytes[0]&0x80 != 0 {
		bytes = append([]byte{0}, bytes...)
	}
	return derTLV(0x02, bytes)
}

// derIntegerNumber is x509.ts integer for a number.
func derIntegerNumber(value float64) []byte {
	text := new(big.Int).SetInt64(int64(value)).Text(16)
	if len(text)%2 == 1 {
		text = "0" + text
	}
	bytes, _ := hex.DecodeString(text)
	return derInteger(bytes)
}

// derOID is x509.ts oid.
func derOID(dotted string) []byte {
	parts := strings.Split(dotted, ".")
	numbers := make([]*big.Int, len(parts))
	for index, part := range parts {
		number, ok := new(big.Int).SetString(part, 10)
		if !ok {
			panic("Invalid OID " + dotted)
		}
		numbers[index] = number
	}
	if len(numbers) < 2 {
		panic("Invalid OID " + dotted)
	}
	first := new(big.Int).Mul(numbers[0], big.NewInt(40))
	first.Add(first, numbers[1])
	bytes := []byte{byte(first.Int64())}
	for _, part := range numbers[2:] {
		var chunk []byte
		rest := new(big.Int).Set(part)
		for {
			chunk = append([]byte{byte(new(big.Int).And(rest, big.NewInt(0x7f)).Int64())}, chunk...)
			rest.Rsh(rest, 7)
			if rest.Sign() <= 0 {
				break
			}
		}
		for index := 0; index < len(chunk)-1; index++ {
			chunk[index] |= 0x80
		}
		bytes = append(bytes, chunk...)
	}
	return derTLV(0x06, bytes)
}

// derBitString is a BIT STRING of whole bytes (no unused bits).
func derBitString(value []byte) []byte { return derTLV(0x03, append([]byte{0}, value...)) }

// derNamedBits is a named-bit BIT STRING (key usage): bits numbered from the most significant bit, trailing zeros
// removed.
func derNamedBits(bits []int) []byte {
	highest := bits[0]
	for _, bit := range bits {
		if bit > highest {
			highest = bit
		}
	}
	bytes := make([]byte, highest/8+1)
	for _, bit := range bits {
		bytes[bit/8] |= 0x80 >> (bit % 8)
	}
	last := bytes[len(bytes)-1]
	unused := 0
	for unused < 7 && last&(1<<unused) == 0 {
		unused++
	}
	return derTLV(0x03, append([]byte{byte(unused)}, bytes...))
}

// derTime is UTCTime through 2049, GeneralizedTime from 2050 (RFC 5280 4.1.2.5).
func derTime(at float64) []byte {
	date := time.UnixMilli(int64(math.Floor(at/1000)) * 1000).UTC()
	year := date.Year()
	pad := func(value, size int) string {
		text := strconv.Itoa(value)
		for len(text) < size {
			text = "0" + text
		}
		return text
	}
	rest := pad(int(date.Month()), 2) + pad(date.Day(), 2) + pad(date.Hour(), 2) + pad(date.Minute(), 2) + pad(date.Second(), 2) + "Z"
	if year >= 1950 && year < 2050 {
		return derTLV(0x17, []byte(pad(year%100, 2)+rest))
	}
	return derTLV(0x18, []byte(pad(year, 4)+rest))
}

// ---------------------------------------------------------------------------------------------------------------
// DER reading

// derNode is x509.ts DerNode.
type derNode struct {
	tag byte
	// start is the offset of the tag byte.
	start int
	// contentStart is the offset of the first content byte.
	contentStart int
	// end is the offset just past the node.
	end int
}

func malformedCsr() *core.IamError {
	return core.NewIamError("INVALID_CSR", "The certificate request is not valid DER", 400)
}

// readDerNode is x509.ts readNode (limit < 0 is buffer.length).
func readDerNode(buffer []byte, offset int, limit int) (derNode, error) {
	if limit < 0 {
		limit = len(buffer)
	}
	if offset+2 > limit {
		return derNode{}, malformedCsr()
	}
	tag := buffer[offset]
	if tag&0x1f == 0x1f {
		return derNode{}, malformedCsr()
	}
	size := int(buffer[offset+1])
	contentStart := offset + 2
	if size&0x80 != 0 {
		count := size & 0x7f
		if count == 0 || count > 4 || contentStart+count > limit {
			return derNode{}, malformedCsr()
		}
		size = 0
		for index := 0; index < count; index++ {
			size = size*256 + int(buffer[contentStart+index])
		}
		contentStart += count
		if size < 0x80 {
			return derNode{}, malformedCsr()
		}
	}
	end := contentStart + size
	if end > limit {
		return derNode{}, malformedCsr()
	}
	return derNode{tag: tag, start: offset, contentStart: contentStart, end: end}, nil
}

// derChildren is x509.ts childrenOf.
func derChildren(buffer []byte, node derNode) ([]derNode, error) {
	children := []derNode{}
	for offset := node.contentStart; offset < node.end; {
		child, err := readDerNode(buffer, offset, node.end)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
		offset = child.end
		if len(children) > 1000 {
			return nil, malformedCsr()
		}
	}
	return children, nil
}

func derContents(buffer []byte, node derNode) []byte { return buffer[node.contentStart:node.end] }
func derWhole(buffer []byte, node derNode) []byte    { return buffer[node.start:node.end] }

// childAt is `children[index]` (nil past the end).
func childAt(children []derNode, index int) *derNode {
	if index < 0 || index >= len(children) {
		return nil
	}
	return &children[index]
}

// decodeOID is x509.ts decodeOid.
func decodeOID(bytes []byte) (string, error) {
	if len(bytes) == 0 {
		return "", malformedCsr()
	}
	first := int(bytes[0])
	var parts []string
	if first < 80 {
		parts = []string{strconv.Itoa(first / 40), strconv.Itoa(first % 40)}
	} else {
		parts = []string{"2", strconv.Itoa(first - 80)}
	}
	var value uint64
	for _, b := range bytes[1:] {
		value = value*128 + uint64(b&0x7f)
		if value > 9007199254740991 {
			return "", malformedCsr()
		}
		if b&0x80 == 0 {
			parts = append(parts, strconv.FormatUint(value, 10))
			value = 0
		}
	}
	return strings.Join(parts, "."), nil
}

// ---------------------------------------------------------------------------------------------------------------
// Names and algorithms

// x509OIDs is x509.ts OIDS.
var x509OIDs = struct {
	CommonName, Country, Locality, State, Organization, OrganizationalUnit                 string
	SubjectKeyIdentifier, KeyUsage, SubjectAltName, BasicConstraints, CrlNumber, CrlReason string
	NameConstraints, CrlDistributionPoints, AuthorityKeyIdentifier, ExtKeyUsage            string
	ServerAuth, ClientAuth, ExtensionRequest                                               string
	EcdsaSha256, EcdsaSha384, EcdsaSha512, RsaSha256, RsaSha384, RsaSha512, Ed25519        string
}{
	CommonName: "2.5.4.3", Country: "2.5.4.6", Locality: "2.5.4.7", State: "2.5.4.8", Organization: "2.5.4.10",
	OrganizationalUnit: "2.5.4.11", SubjectKeyIdentifier: "2.5.29.14", KeyUsage: "2.5.29.15", SubjectAltName: "2.5.29.17",
	BasicConstraints: "2.5.29.19", CrlNumber: "2.5.29.20", CrlReason: "2.5.29.21", NameConstraints: "2.5.29.30",
	CrlDistributionPoints: "2.5.29.31", AuthorityKeyIdentifier: "2.5.29.35", ExtKeyUsage: "2.5.29.37",
	ServerAuth: "1.3.6.1.5.5.7.3.1", ClientAuth: "1.3.6.1.5.5.7.3.2", ExtensionRequest: "1.2.840.113549.1.9.14",
	EcdsaSha256: "1.2.840.10045.4.3.2", EcdsaSha384: "1.2.840.10045.4.3.3", EcdsaSha512: "1.2.840.10045.4.3.4",
	RsaSha256: "1.2.840.113549.1.1.11", RsaSha384: "1.2.840.113549.1.1.12", RsaSha512: "1.2.840.113549.1.1.13",
	Ed25519: "1.3.101.112",
}

// EncodeName (x509.ts encodeName): Encodes a name in the conventional order (C, ST, L, O, OU, CN), one attribute per
// RDN.
func EncodeName(name *core.Object) (result []byte, err error) {
	rdn := func(kind string, value []byte) []byte { return derSet(derSequence(derOID(kind), value)) }
	parts := [][]byte{}
	part := func(key string) (string, bool) {
		value := name.Get(key)
		if !truthy(value) {
			return "", false
		}
		return jsString(value), true
	}
	if value, ok := part("country"); ok {
		parts = append(parts, rdn(x509OIDs.Country, derPrintableString(value)))
	}
	if value, ok := part("state"); ok {
		parts = append(parts, rdn(x509OIDs.State, derUTF8String(value)))
	}
	if value, ok := part("locality"); ok {
		parts = append(parts, rdn(x509OIDs.Locality, derUTF8String(value)))
	}
	if value, ok := part("organization"); ok {
		parts = append(parts, rdn(x509OIDs.Organization, derUTF8String(value)))
	}
	if value, ok := part("organizationalUnit"); ok {
		parts = append(parts, rdn(x509OIDs.OrganizationalUnit, derUTF8String(value)))
	}
	if value, ok := part("commonName"); ok {
		parts = append(parts, rdn(x509OIDs.CommonName, derUTF8String(value)))
	}
	return derSequence(parts...), nil
}

func algorithmOID(algorithm string) string {
	switch algorithm {
	case "ES256":
		return x509OIDs.EcdsaSha256
	case "ES384":
		return x509OIDs.EcdsaSha384
	case "EdDSA":
		return x509OIDs.Ed25519
	case "RS256":
		return x509OIDs.RsaSha256
	case "RS384":
		return x509OIDs.RsaSha384
	case "RS512":
		return x509OIDs.RsaSha512
	}
	return ""
}

// algorithmIdentifier is x509.ts algorithmIdentifier.
func algorithmIdentifier(algorithm string) ([]byte, error) {
	oid := algorithmOID(algorithm)
	if oid == "" {
		// algorithmOids[algorithm] is undefined and oid(undefined) throws.
		return nil, errors.New("Cannot read properties of undefined (reading 'split')")
	}
	if strings.HasPrefix(algorithm, "RS") {
		return derSequence(derOID(oid), derNull()), nil
	}
	return derSequence(derOID(oid)), nil
}

// hashForOID is x509.ts hashForOid: the hash for a signature OID (0 for Ed25519), known false for anything else
// (RSA-PSS included).
func hashForOID(value string) (hash crypto.Hash, known bool) {
	switch value {
	case x509OIDs.EcdsaSha256, x509OIDs.RsaSha256:
		return crypto.SHA256, true
	case x509OIDs.EcdsaSha384, x509OIDs.RsaSha384:
		return crypto.SHA384, true
	case x509OIDs.EcdsaSha512, x509OIDs.RsaSha512:
		return crypto.SHA512, true
	case x509OIDs.Ed25519:
		return 0, true
	}
	return 0, false
}

// algorithmForKey is x509.ts algorithmForKey: the signature algorithm a private key signs certificates and requests
// with.
func algorithmForKey(key crypto.Signer) (string, error) {
	switch typed := key.Public().(type) {
	case ed25519.PublicKey:
		return "EdDSA", nil
	case *ecdsa.PublicKey:
		if typed.Curve == elliptic.P384() {
			return "ES384", nil
		}
		return "ES256", nil
	case *rsa.PublicKey:
		return "RS256", nil
	}
	return "", invalidInput("Keys must be ECDSA P-256/P-384, Ed25519 or RSA")
}

// pkiPublicKey is a subject public key as Node's KeyObject describes it.
type pkiPublicKey struct {
	// kind is asymmetricKeyType: ed25519, ec, rsa, or another type Node reads but certificates never carry.
	kind string
	// curve is asymmetricKeyDetails.namedCurve (prime256v1, secp384r1, or another curve).
	curve string
	// bits and exponent are asymmetricKeyDetails.modulusLength and publicExponent of RSA keys.
	bits     int
	exponent *big.Int
	ec       *ecdsa.PublicKey
	ed       ed25519.PublicKey
	rsa      *big.Int
}

var errUnreadableKey = errors.New("unreadable public key")

// Algorithm OIDs of keys OpenSSL reads that certificates here never carry.
var otherKeyOIDs = map[string]bool{
	"1.3.101.110": true, "1.3.101.111": true, "1.3.101.113": true, // X25519, X448, Ed448
	"1.2.840.10040.4.1": true, "1.2.840.113549.1.3.1": true, "1.2.840.10046.2.1": true, // DSA, DH, X9.42 DH
	"1.2.840.113549.1.1.10": true, // RSA-PSS
}

// Named curves OpenSSL reads besides P-256 and P-384.
var otherCurveOIDs = map[string]bool{
	"1.3.132.0.35": true, "1.3.132.0.33": true, "1.3.132.0.10": true, // P-521, P-224, secp256k1
	"1.2.840.10045.3.1.1":  true,                                                               // P-192
	"1.3.36.3.3.2.8.1.1.7": true, "1.3.36.3.3.2.8.1.1.11": true, "1.3.36.3.3.2.8.1.1.13": true, // brainpool
}

// parsePublicKey is createPublicKey({ key: spki, format: 'der', type: 'spki' }): errUnreadableKey when OpenSSL could
// not read it.
func parsePublicKey(spki []byte) (*pkiPublicKey, error) {
	root, err := readDerNode(spki, 0, -1)
	if err != nil || root.tag != 0x30 || root.end != len(spki) {
		return nil, errUnreadableKey
	}
	parts, err := derChildren(spki, root)
	if err != nil || len(parts) != 2 || parts[0].tag != 0x30 || parts[1].tag != 0x03 {
		return nil, errUnreadableKey
	}
	algorithm, err := derChildren(spki, parts[0])
	if err != nil || len(algorithm) == 0 || algorithm[0].tag != 0x06 {
		return nil, errUnreadableKey
	}
	oid, err := decodeOID(derContents(spki, algorithm[0]))
	if err != nil {
		return nil, errUnreadableKey
	}
	bitString := derContents(spki, parts[1])
	if len(bitString) == 0 || bitString[0] > 7 {
		return nil, errUnreadableKey
	}
	bits := bitString[1:]
	switch oid {
	case "1.2.840.113549.1.1.1":
		if len(algorithm) > 1 && algorithm[1].tag != 0x05 {
			return nil, errUnreadableKey
		}
		keyRoot, err := readDerNode(bits, 0, -1)
		if err != nil || keyRoot.tag != 0x30 || keyRoot.end != len(bits) {
			return nil, errUnreadableKey
		}
		numbers, err := derChildren(bits, keyRoot)
		if err != nil || len(numbers) != 2 || numbers[0].tag != 0x02 || numbers[1].tag != 0x02 {
			return nil, errUnreadableKey
		}
		modulus := derContents(bits, numbers[0])
		exponent := derContents(bits, numbers[1])
		if len(modulus) == 0 || len(exponent) == 0 || modulus[0]&0x80 != 0 || exponent[0]&0x80 != 0 {
			return nil, errUnreadableKey
		}
		n := new(big.Int).SetBytes(modulus)
		e := new(big.Int).SetBytes(exponent)
		if n.Sign() == 0 || e.Sign() == 0 {
			return nil, errUnreadableKey
		}
		return &pkiPublicKey{kind: "rsa", bits: n.BitLen(), exponent: e, rsa: n}, nil
	case "1.2.840.10045.2.1":
		if len(algorithm) < 2 {
			return nil, errUnreadableKey
		}
		if algorithm[1].tag != 0x06 {
			// Explicit curve parameters: read, but never one of the named curves certificates here use.
			return &pkiPublicKey{kind: "ec"}, nil
		}
		curveOID, err := decodeOID(derContents(spki, algorithm[1]))
		if err != nil {
			return nil, errUnreadableKey
		}
		var curve elliptic.Curve
		var name string
		switch curveOID {
		case "1.2.840.10045.3.1.7":
			curve, name = elliptic.P256(), "prime256v1"
		case "1.3.132.0.34":
			curve, name = elliptic.P384(), "secp384r1"
		default:
			if otherCurveOIDs[curveOID] {
				return &pkiPublicKey{kind: "ec", curve: curveOID}, nil
			}
			return nil, errUnreadableKey
		}
		x, y := decodePoint(curve, bits)
		if x == nil {
			return nil, errUnreadableKey
		}
		return &pkiPublicKey{kind: "ec", curve: name, ec: &ecdsa.PublicKey{Curve: curve, X: x, Y: y}}, nil
	case x509OIDs.Ed25519:
		if len(algorithm) > 1 || len(bits) != ed25519.PublicKeySize {
			return nil, errUnreadableKey
		}
		return &pkiPublicKey{kind: "ed25519", ed: ed25519.PublicKey(append([]byte{}, bits...))}, nil
	}
	if otherKeyOIDs[oid] {
		return &pkiPublicKey{kind: oid}, nil
	}
	return nil, errUnreadableKey
}

// decodePoint reads an uncompressed, compressed or hybrid EC point (as OpenSSL does); nil when it is not on the curve.
func decodePoint(curve elliptic.Curve, point []byte) (*big.Int, *big.Int) {
	size := (curve.Params().BitSize + 7) / 8
	if len(point) == 0 {
		return nil, nil
	}
	switch point[0] {
	case 0x04:
		//nolint:staticcheck // elliptic.Unmarshal validates the point, which is what is needed here.
		return elliptic.Unmarshal(curve, point)
	case 0x02, 0x03:
		if len(point) != 1+size {
			return nil, nil
		}
		return elliptic.UnmarshalCompressed(curve, point)
	case 0x06, 0x07:
		if len(point) != 1+2*size {
			return nil, nil
		}
		uncompressed := append([]byte{0x04}, point[1:]...)
		//nolint:staticcheck // see above
		x, y := elliptic.Unmarshal(curve, uncompressed)
		if x == nil || byte(y.Bit(0)) != point[0]&1 {
			return nil, nil
		}
		return x, y
	}
	return nil, nil
}

// acceptablePublicKey is x509.ts acceptablePublicKey: ECDSA P-256/P-384, Ed25519, or RSA of 2048 to 8192 bits.
func acceptablePublicKey(key *pkiPublicKey) (string, error) {
	switch key.kind {
	case "ed25519":
		return "ed25519", nil
	case "ec":
		if key.curve == "prime256v1" {
			return "ecc-p256", nil
		}
		if key.curve == "secp384r1" {
			return "ecc-p384", nil
		}
	case "rsa":
		// A huge public exponent makes every verification slow; real keys use 65537 (or 3).
		if key.bits >= 2048 && key.bits <= 8192 && key.exponent.Cmp(big.NewInt(3)) >= 0 && key.exponent.Cmp(big.NewInt(65537)) <= 0 {
			return "rsa-" + strconv.Itoa(key.bits), nil
		}
	}
	return "", core.NewIamError("INVALID_CSR", "The requested key must be ECDSA P-256 or P-384, Ed25519, or RSA of 2048 to 8192 bits", 400)
}

func hashData(hash crypto.Hash, data []byte) []byte {
	switch hash {
	case crypto.SHA384:
		sum := sha512.Sum384(data)
		return sum[:]
	case crypto.SHA512:
		sum := sha512.Sum512(data)
		return sum[:]
	}
	sum := sha256.Sum256(data)
	return sum[:]
}

// verifyWithKey is crypto.verify(hash, data, key, signature) (PKCS#1 v1.5 for RSA, DER signatures for ECDSA): false
// when it does not verify or cannot be checked.
func verifyWithKey(key *pkiPublicKey, hash crypto.Hash, data, signature []byte) bool {
	switch key.kind {
	case "ed25519":
		if hash != 0 || key.ed == nil {
			return false
		}
		return ed25519.Verify(key.ed, data, signature)
	case "ec":
		if hash == 0 || key.ec == nil {
			return false
		}
		return ecdsa.VerifyASN1(key.ec, hashData(hash, data), signature)
	case "rsa":
		if hash == 0 || key.rsa == nil || !key.exponent.IsInt64() || key.exponent.Int64() > math.MaxInt32 {
			return false
		}
		public := &rsa.PublicKey{N: key.rsa, E: int(key.exponent.Int64())}
		return rsa.VerifyPKCS1v15(public, hash, hashData(hash, data), signature) == nil
	}
	return false
}

// signWith is x509.ts signWith.
func signWith(key crypto.Signer, algorithm string, data []byte) ([]byte, error) {
	if algorithm == "EdDSA" {
		return key.Sign(rand.Reader, data, crypto.Hash(0))
	}
	hash := crypto.SHA256
	if strings.HasSuffix(algorithm, "384") {
		hash = crypto.SHA384
	} else if strings.HasSuffix(algorithm, "512") {
		hash = crypto.SHA512
	}
	return key.Sign(rand.Reader, hashData(hash, data), hash)
}

// ---------------------------------------------------------------------------------------------------------------
// Subject alternative names

// sanSet is x509.ts SubjectAltNames.
type sanSet struct {
	dnsNames    []string
	uris        []string
	ipAddresses []string
	emails      []string
}

func (names sanSet) total() int {
	return len(names.dnsNames) + len(names.uris) + len(names.ipAddresses) + len(names.emails)
}

// object is the record form ({ dnsNames, uris, ipAddresses, emails }).
func (names sanSet) object() *core.Object {
	list := func(values []string) []any {
		if values == nil {
			return []any{}
		}
		return stringsOf(values)
	}
	return core.NewObject("dnsNames", list(names.dnsNames), "uris", list(names.uris), "ipAddresses", list(names.ipAddresses), "emails", list(names.emails))
}

// sanSetOf reads a names record (members that are not lists of strings read as empty).
func sanSetOf(value any) sanSet {
	object, _ := value.(*core.Object)
	list := func(key string) []string {
		items, _ := object.Get(key).([]any)
		out := []string{}
		for _, item := range items {
			out = append(out, jsString(item))
		}
		return out
	}
	return sanSet{dnsNames: list("dnsNames"), uris: list("uris"), ipAddresses: list("ipAddresses"), emails: list("emails")}
}

// emailAddress is printable ASCII only: IA5String names are encoded byte for byte, so what is decided is what is
// signed.
var emailAddress = regexp.MustCompile("^[A-Za-z0-9!#$%&'*+/=?^_`{|}~.-]+@[a-z0-9-]+(?:\\.[a-z0-9-]+)+$")

// spiffeID is the SPIFFE ID grammar: a lowercase trust domain and path segments of letters, digits, dots, dashes,
// underscores.
var spiffeID = regexp.MustCompile(`^spiffe://[a-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$`)

var printableASCII = regexp.MustCompile(`^[\x21-\x7e]+$`)

// dotSegment is a path segment the URL parser resolves (`.`, `..` and their percent-encoded forms).
var dotSegment = regexp.MustCompile(`(?i)^(?:\.|%2e){1,2}$`)

// canonicalURI is x509.ts canonicalUri.
func canonicalURI(value string) (string, error) {
	invalid := func() error { return invalidInput("Invalid URI " + value) }
	if utf16Len(value) > 2048 || !printableASCII.MatchString(value) || strings.Contains(value, `\`) {
		return "", invalid()
	}
	if strings.HasPrefix(core.JSLower(value), "spiffe:") {
		dots := false
		for _, segment := range strings.Split(value, "/") {
			if segment == "." || segment == ".." {
				dots = true
			}
		}
		if !spiffeID.MatchString(value) || dots {
			return "", invalidInput("Invalid SPIFFE ID " + value + ": spiffe://{trust domain}/{path}, with no dot segments, query or fragment")
		}
		return value, nil
	}
	// Only a URI already in canonical form is accepted, so policies decide on the exact string that is encoded
	// (dot segments, percent-encoded dots, host case and default ports are all resolved by the parser).
	if !uriCanonical(value) {
		return "", invalid()
	}
	return value, nil
}

// uriCanonical is `new URL(value).href === value` with no username or password, for printable ASCII without
// backslashes.
func uriCanonical(value string) bool {
	parsed, err := auth.ParseFetchURL(value)
	if err != nil || parsed.Href != value || parsed.User != nil {
		return false
	}
	special := parsed.Protocol == "http:" || parsed.Protocol == "https:" || parsed.Protocol == "ws:" || parsed.Protocol == "wss:" || parsed.Protocol == "ftp:" || parsed.Protocol == "file:"
	rest := value[len(parsed.Protocol):]
	fragment := ""
	if at := strings.Index(rest, "#"); at >= 0 {
		rest, fragment = rest[:at], rest[at+1:]
	}
	query := ""
	hasQuery := false
	if at := strings.Index(rest, "?"); at >= 0 {
		rest, query, hasQuery = rest[:at], rest[at+1:], true
	}
	path := rest
	if strings.HasPrefix(rest, "//") {
		authority := rest[2:]
		if at := strings.Index(authority, "/"); at >= 0 {
			path = authority[at:]
		} else {
			path = ""
		}
	}
	// The parser resolves dot segments in hierarchical paths and percent-encodes what its encode sets name.
	if strings.HasPrefix(path, "/") || special {
		for _, segment := range strings.Split(path, "/") {
			if dotSegment.MatchString(segment) {
				return false
			}
		}
		if strings.ContainsAny(path, "\"<>`{}") {
			return false
		}
	}
	if hasQuery && (strings.ContainsAny(query, "\"<>") || special && strings.Contains(query, "'")) {
		return false
	}
	if strings.ContainsAny(fragment, "\"<>`") {
		return false
	}
	return true
}

// canonicalIP is x509.ts canonicalIp: an IP address in canonical text: dotted IPv4 (IPv4-mapped IPv6 included), RFC
// 5952 compressed IPv6.
func canonicalIP(value string) (string, error) {
	if strings.Contains(value, "%") || net.ParseIP(value) == nil {
		return "", invalidInput("Invalid IP address " + value)
	}
	bytes := ipBytes(value)
	mapped := len(bytes) == 16
	if mapped {
		for _, b := range bytes[:10] {
			if b != 0 {
				mapped = false
			}
		}
		mapped = mapped && bytes[10] == 0xff && bytes[11] == 0xff
	}
	if mapped {
		return ipText(bytes[12:]), nil
	}
	return ipText(bytes), nil
}

// ipBytes is x509.ts ipBytes: 4 bytes for dotted IPv4, 16 for IPv6.
func ipBytes(value string) []byte {
	ip := net.ParseIP(value)
	if ip == nil {
		return nil
	}
	if !strings.Contains(value, ":") {
		return []byte(ip.To4())
	}
	return []byte(ip.To16())
}

// ipText is x509.ts ipText: dotted IPv4, or IPv6 in RFC 5952 form (lowercase, the longest run of two or more zero
// groups as `::`).
func ipText(bytes []byte) string {
	if len(bytes) == 4 {
		return strconv.Itoa(int(bytes[0])) + "." + strconv.Itoa(int(bytes[1])) + "." + strconv.Itoa(int(bytes[2])) + "." + strconv.Itoa(int(bytes[3]))
	}
	groups := make([]int, 8)
	for index := 0; index < 16; index += 2 {
		groups[index/2] = int(bytes[index])<<8 | int(bytes[index+1])
	}
	bestStart, bestLength := -1, 0
	for start := 0; start < 8; {
		if groups[start] != 0 {
			start++
			continue
		}
		end := start
		for end < 8 && groups[end] == 0 {
			end++
		}
		if end-start > bestLength {
			bestStart, bestLength = start, end-start
		}
		start = end
	}
	text := make([]string, 8)
	for index, group := range groups {
		text[index] = strconv.FormatInt(int64(group), 16)
	}
	if bestLength < 2 {
		return strings.Join(text, ":")
	}
	return strings.Join(text[:bestStart], ":") + "::" + strings.Join(text[bestStart+bestLength:], ":")
}

// subjectAltNames is x509.ts subjectAltNames over a model input.
func subjectAltNames(input *core.Object) (sanSet, error) {
	list := func(value any, name string) ([]string, error) {
		if isUndefined(value) {
			return []string{}, nil
		}
		items, ok := value.([]any)
		if !ok {
			return nil, invalidInput(name + " must be a list of strings")
		}
		out := make([]string, len(items))
		for index, item := range items {
			text, ok := item.(string)
			if !ok {
				return nil, invalidInput(name + " must be a list of strings")
			}
			out[index] = text
		}
		return out, nil
	}
	mapped := func(key string, fn func(string) (string, error)) ([]string, error) {
		values, err := list(input.Get(key), key)
		if err != nil {
			return nil, err
		}
		out := make([]string, len(values))
		for index, value := range values {
			if out[index], err = fn(value); err != nil {
				return nil, err
			}
		}
		return unique(out), nil
	}
	lower := func(value string) (string, error) { return core.JSLower(value), nil }
	dnsNames, err := mapped("dnsNames", lower)
	if err != nil {
		return sanSet{}, err
	}
	for _, value := range dnsNames {
		if utf16Len(value) > 253 || !DnsName.MatchString(value) {
			return sanSet{}, invalidInput("Invalid DNS name " + value)
		}
	}
	emails, err := mapped("emails", lower)
	if err != nil {
		return sanSet{}, err
	}
	for _, value := range emails {
		if utf16Len(value) > 254 || !emailAddress.MatchString(value) {
			return sanSet{}, invalidInput("Invalid email address " + value)
		}
	}
	uris, err := mapped("uris", canonicalURI)
	if err != nil {
		return sanSet{}, err
	}
	ipAddresses, err := mapped("ipAddresses", canonicalIP)
	if err != nil {
		return sanSet{}, err
	}
	names := sanSet{dnsNames: dnsNames, uris: uris, ipAddresses: ipAddresses, emails: emails}
	if names.total() > 100 {
		return sanSet{}, invalidInput("At most 100 subject alternative names")
	}
	return names, nil
}

// SubjectAltNames (x509.ts subjectAltNames): Validates and canonicalizes requested names, at most 100 in total:
// lowercase DNS names and email addresses (ASCII only), URIs in canonical form (SPIFFE IDs by the SPIFFE grammar),
// and IP addresses in canonical text.
func SubjectAltNames(input *core.Object) (result *core.Object, err error) {
	names, err := subjectAltNames(input)
	if err != nil {
		return nil, err
	}
	return names.object(), nil
}

// encodeGeneralNames is x509.ts encodeGeneralNames.
func encodeGeneralNames(names sanSet) []byte {
	items := [][]byte{}
	for _, value := range names.emails {
		items = append(items, derTLV(0x81, asciiBytes(value)))
	}
	for _, value := range names.dnsNames {
		items = append(items, derTLV(0x82, asciiBytes(value)))
	}
	for _, value := range names.uris {
		items = append(items, derTLV(0x86, asciiBytes(value)))
	}
	for _, value := range names.ipAddresses {
		items = append(items, derTLV(0x87, ipBytes(value)))
	}
	return derSequence(items...)
}

// latin1 is Buffer#toString('ascii'|'latin1'): one character per byte (Node's ascii decoding is latin1).
func latin1(bytes []byte) string {
	runes := make([]rune, len(bytes))
	for index, b := range bytes {
		runes[index] = rune(b)
	}
	return string(runes)
}

// decodeGeneralNames is x509.ts decodeGeneralNames.
func decodeGeneralNames(buffer []byte, node derNode) (sanSet, error) {
	names := sanSet{dnsNames: []string{}, uris: []string{}, ipAddresses: []string{}, emails: []string{}}
	children, err := derChildren(buffer, node)
	if err != nil {
		return sanSet{}, err
	}
	for _, child := range children {
		value := derContents(buffer, child)
		switch {
		case child.tag == 0x82:
			names.dnsNames = append(names.dnsNames, latin1(value))
		case child.tag == 0x86:
			names.uris = append(names.uris, latin1(value))
		case child.tag == 0x81:
			names.emails = append(names.emails, latin1(value))
		case child.tag == 0x87 && (len(value) == 4 || len(value) == 16):
			names.ipAddresses = append(names.ipAddresses, ipText(value))
		default:
			return sanSet{}, core.NewIamError("INVALID_CSR", "The request names an unsupported kind of name", 400)
		}
	}
	return names, nil
}

// ---------------------------------------------------------------------------------------------------------------
// Extensions

// derExtension is x509.ts extension.
func derExtension(kind string, critical bool, value []byte) []byte {
	if critical {
		return derSequence(derOID(kind), derBoolean(true), derOctetString(value))
	}
	return derSequence(derOID(kind), derOctetString(value))
}

// KeyIdentifier (x509.ts keyIdentifier): RFC 5280 key identifier (method 1): SHA-1 of the subject public key bits.
func KeyIdentifier(spki []byte) (result []byte, err error) {
	root, err := readDerNode(spki, 0, -1)
	if err != nil {
		return nil, err
	}
	children, err := derChildren(spki, root)
	if err != nil {
		return nil, err
	}
	bits := childAt(children, 1)
	if bits == nil || bits.tag != 0x03 {
		return nil, malformedCsr()
	}
	content := derContents(spki, *bits)
	if len(content) > 0 {
		content = content[1:]
	}
	sum := sha1.Sum(content)
	return sum[:], nil
}

// ---------------------------------------------------------------------------------------------------------------
// PKCS#10 certification requests

// CreateCertificateRequest (x509.ts createCertificateRequest): Builds a PEM PKCS#10 certification request for
// `privateKey` (a crypto.Signer, or PKCS#8 PEM text) with a `subject` and subject alternative names (`dnsNames`,
// `uris`, `ipAddresses`, `emails`), signed with the key (proof of possession). Clients call it to request
// certificates without OpenSSL.
func CreateCertificateRequest(input *core.Object) (string, error) {
	var key crypto.Signer
	switch typed := input.Get("privateKey").(type) {
	case crypto.Signer:
		key = typed
	case string:
		block, _ := pem.Decode([]byte(typed))
		if block == nil {
			return "", errors.New("Invalid private key")
		}
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return "", err
		}
		signer, ok := parsed.(crypto.Signer)
		if !ok {
			return "", errors.New("Invalid private key")
		}
		key = signer
	default:
		return "", errors.New("Invalid private key")
	}
	algorithm, err := algorithmForKey(key)
	if err != nil {
		return "", err
	}
	spki, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		return "", err
	}
	names, err := subjectAltNames(input)
	if err != nil {
		return "", err
	}
	hasNames := names.total() > 0
	var attributes []byte
	if hasNames {
		attributes = derSet(derSequence(
			derOID(x509OIDs.ExtensionRequest),
			derSet(derSequence(derExtension(x509OIDs.SubjectAltName, false, encodeGeneralNames(names)))),
		))
	}
	subject, _ := input.Get("subject").(*core.Object)
	if subject == nil {
		subject = core.NewObject()
	}
	encodedSubject, err := EncodeName(subject)
	if err != nil {
		return "", err
	}
	attributeContents := []byte{}
	if hasNames {
		node, err := readDerNode(attributes, 0, -1)
		if err != nil {
			return "", err
		}
		attributeContents = derContents(attributes, node)
	}
	// attributes [0] IMPLICIT SET OF Attribute
	info := derSequence(derIntegerNumber(0), encodedSubject, spki, derTLV(0xa0, attributeContents))
	signature, err := signWith(key, algorithm, info)
	if err != nil {
		return "", err
	}
	identifier, err := algorithmIdentifier(algorithm)
	if err != nil {
		return "", err
	}
	return Pem("CERTIFICATE REQUEST", derSequence(info, identifier, derBitString(signature)))
}

// nameValue is x509.ts nameValue: the text of a directory string (UTF8, Printable, IA5, Teletex or BMP), "", false
// for other types.
func nameValue(buffer []byte, node derNode) (string, bool, error) {
	switch node.tag {
	case 0x0c, 0x13, 0x16, 0x14:
		return decodeUTF8(derContents(buffer, node)), true, nil
	case 0x1e:
		// BMPString: UTF-16BE, so an even length.
		value := derContents(buffer, node)
		if len(value)%2 == 1 {
			return "", false, malformedCsr()
		}
		units := make([]uint16, len(value)/2)
		for index := range units {
			units[index] = uint16(value[2*index])<<8 | uint16(value[2*index+1])
		}
		return string(utf16.Decode(units)), true, nil
	}
	return "", false, nil
}

// algorithmFits is x509.ts algorithmFits: which key types each signature algorithm belongs to.
func algorithmFits(oidValue string, keyType string) bool {
	if oidValue == x509OIDs.Ed25519 {
		return keyType == "ed25519"
	}
	if oidValue == x509OIDs.EcdsaSha256 || oidValue == x509OIDs.EcdsaSha384 || oidValue == x509OIDs.EcdsaSha512 {
		return strings.HasPrefix(keyType, "ecc-")
	}
	return strings.HasPrefix(keyType, "rsa-")
}

var (
	csrBegin    = regexp.MustCompile(`-----BEGIN (NEW )?CERTIFICATE REQUEST-----`)
	csrEnd      = regexp.MustCompile(`-----END (NEW )?CERTIFICATE REQUEST-----`)
	jsSpaces    = regexp.MustCompile(`[` + jsWhitespace + `]+`)
	csrBase64   = regexp.MustCompile(`^[A-Za-z0-9+/]+={0,2}$`)
	controlChar = regexp.MustCompile(`[\x00-\x1f\x7f]`)
)

// replaceFirst is String#replace with a regular expression without the g flag.
func replaceFirst(pattern *regexp.Regexp, value, replacement string) string {
	location := pattern.FindStringIndex(value)
	if location == nil {
		return value
	}
	return value[:location[0]] + replacement + value[location[1]:]
}

// ParseCertificateRequest (x509.ts parseCertificateRequest): Parses and verifies a PEM (or base64 DER) PKCS#10
// request: the signature must verify with the request's own key (proof of possession), and the key must be of an
// accepted kind. Returns the key (`spki` DER, `keyType`), the subject `commonName` and the requested `names`.
func ParseCertificateRequest(value any) (result *core.Object, err error) {
	text, ok := value.(string)
	if !ok || utf16Len(text) > 65536 {
		return nil, core.NewIamError("INVALID_CSR", "csr must be a PEM certificate request", 400)
	}
	body := jsSpaces.ReplaceAllString(replaceFirst(csrEnd, replaceFirst(csrBegin, text, ""), ""), "")
	if !csrBase64.MatchString(body) {
		return nil, core.NewIamError("INVALID_CSR", "csr must be a PEM certificate request", 400)
	}
	der := nodeBase64Decode(body)
	root, err := readDerNode(der, 0, -1)
	if err != nil {
		return nil, err
	}
	if root.tag != 0x30 || root.end != len(der) {
		return nil, malformedCsr()
	}
	top, err := derChildren(der, root)
	if err != nil {
		return nil, err
	}
	info, algorithm, signature := childAt(top, 0), childAt(top, 1), childAt(top, 2)
	if info == nil || algorithm == nil || signature == nil || info.tag != 0x30 || signature.tag != 0x03 {
		return nil, malformedCsr()
	}
	fields, err := derChildren(der, *info)
	if err != nil {
		return nil, err
	}
	version, subject, spkiNode, attributes := childAt(fields, 0), childAt(fields, 1), childAt(fields, 2), childAt(fields, 3)
	if version == nil || subject == nil || spkiNode == nil || version.tag != 0x02 || subject.tag != 0x30 {
		return nil, malformedCsr()
	}
	// PKCS#10 version 1 is encoded as 0.
	if versionBytes := derContents(der, *version); len(versionBytes) != 1 || versionBytes[0] != 0 {
		return nil, malformedCsr()
	}
	spki := append([]byte{}, derWhole(der, *spkiNode)...)
	publicKey, err := parsePublicKey(spki)
	if err != nil {
		return nil, core.NewIamError("INVALID_CSR", "The request carries an unreadable public key", 400)
	}
	keyType, err := acceptablePublicKey(publicKey)
	if err != nil {
		return nil, err
	}
	algorithmParts, err := derChildren(der, *algorithm)
	if err != nil {
		return nil, err
	}
	algorithmOIDNode := childAt(algorithmParts, 0)
	if algorithmOIDNode == nil || algorithmOIDNode.tag != 0x06 {
		return nil, malformedCsr()
	}
	algorithmValue, err := decodeOID(derContents(der, *algorithmOIDNode))
	if err != nil {
		return nil, err
	}
	hash, known := hashForOID(algorithmValue)
	if !known || !algorithmFits(algorithmValue, keyType) {
		return nil, core.NewIamError("INVALID_CSR", "The request is signed with an unsupported algorithm", 400)
	}
	bits := derContents(der, *signature)
	if len(bits) == 0 || bits[0] != 0 {
		return nil, malformedCsr()
	}
	if !verifyWithKey(publicKey, hash, derWhole(der, *info), bits[1:]) {
		return nil, core.NewIamError("INVALID_CSR", "The request signature does not verify with its key", 400)
	}
	commonName, hasCommonName := "", false
	rdns, err := derChildren(der, *subject)
	if err != nil {
		return nil, err
	}
	for _, rdn := range rdns {
		attributeNodes, err := derChildren(der, rdn)
		if err != nil {
			return nil, err
		}
		for _, attribute := range attributeNodes {
			pair, err := derChildren(der, attribute)
			if err != nil {
				return nil, err
			}
			kind, item := childAt(pair, 0), childAt(pair, 1)
			if kind != nil && kind.tag == 0x06 && item != nil {
				decoded, err := decodeOID(derContents(der, *kind))
				if err != nil {
					return nil, err
				}
				if decoded == x509OIDs.CommonName {
					if commonName, hasCommonName, err = nameValue(der, *item); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	// The request's common name follows the same rules as one given explicitly: never truncated or cleaned up.
	if hasCommonName && (core.JSTrim(commonName) == "" || utf16Len(commonName) > 64 || controlChar.MatchString(commonName)) {
		return nil, core.NewIamError("INVALID_CSR", "The request has an invalid common name", 400)
	}
	names := sanSet{dnsNames: []string{}, uris: []string{}, ipAddresses: []string{}, emails: []string{}}
	if attributes != nil && attributes.tag == 0xa0 {
		attributeNodes, err := derChildren(der, *attributes)
		if err != nil {
			return nil, err
		}
		for _, attribute := range attributeNodes {
			pair, err := derChildren(der, attribute)
			if err != nil {
				return nil, err
			}
			kind, values := childAt(pair, 0), childAt(pair, 1)
			if kind == nil || kind.tag != 0x06 {
				continue
			}
			decoded, err := decodeOID(derContents(der, *kind))
			if err != nil {
				return nil, err
			}
			if decoded != x509OIDs.ExtensionRequest || values == nil {
				continue
			}
			extensionSets, err := derChildren(der, *values)
			if err != nil {
				return nil, err
			}
			for _, extensions := range extensionSets {
				items, err := derChildren(der, extensions)
				if err != nil {
					return nil, err
				}
				for _, item := range items {
					parts, err := derChildren(der, item)
					if err != nil {
						return nil, err
					}
					id, valueNode := childAt(parts, 0), childAt(parts, len(parts)-1)
					if id == nil || id.tag != 0x06 || valueNode == nil || valueNode.tag != 0x04 {
						continue
					}
					decoded, err := decodeOID(derContents(der, *id))
					if err != nil {
						return nil, err
					}
					if decoded != x509OIDs.SubjectAltName {
						continue
					}
					inner := derContents(der, *valueNode)
					innerRoot, err := readDerNode(inner, 0, -1)
					if err != nil {
						return nil, err
					}
					if names, err = decodeGeneralNames(inner, innerRoot); err != nil {
						return nil, err
					}
				}
			}
		}
	}
	canonical, err := subjectAltNames(names.object())
	if err != nil {
		return nil, err
	}
	result = core.NewObject()
	result.SetRaw("spki", spki)
	result.SetRaw("publicKey", publicKey)
	result.Set("keyType", keyType)
	if hasCommonName && commonName != "" {
		result.Set("commonName", commonName)
	}
	result.Set("names", canonical.object())
	return result, nil
}

// ---------------------------------------------------------------------------------------------------------------
// Certificates and CRLs

// Pem (x509.ts pem): the PEM text of DER bytes, 64 base64 characters per line.
func Pem(label string, der []byte) (result string, err error) {
	encoded := base64.StdEncoding.EncodeToString(der)
	var body strings.Builder
	for index := 0; index < len(encoded); index += 64 {
		end := index + 64
		if end > len(encoded) {
			end = len(encoded)
		}
		if index > 0 {
			body.WriteString("\n")
		}
		body.WriteString(encoded[index:end])
	}
	return "-----BEGIN " + label + "-----\n" + body.String() + "\n-----END " + label + "-----\n", nil
}

// RandomSerial (x509.ts randomSerial): A positive random serial number (about 123 random bits), as lowercase hex
// whose first digit is never `0`, so it reads the same with or without leading-zero stripping (Node's
// `X509Certificate.serialNumber` strips them).
func RandomSerial() (result string, err error) {
	bytes := make([]byte, 16)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	bytes[0] = bytes[0]&0x7f | 0x10
	return hex.EncodeToString(bytes), nil
}

// nodeHexDecode is Buffer.from(value, 'hex'): pairs of hex digits up to the first one that is not.
func nodeHexDecode(value string) []byte {
	out := []byte{}
	for index := 0; index+1 < len(value); index += 2 {
		b, err := hex.DecodeString(value[index : index+2])
		if err != nil {
			break
		}
		out = append(out, b[0])
	}
	return out
}

// bytesOf reads a byte member of a spec.
func bytesOf(value any) []byte {
	switch typed := value.(type) {
	case []byte:
		return typed
	case string:
		return []byte(typed)
	}
	return nil
}

// spkiIsRSA is `createPublicKey(spki).asymmetricKeyType === 'rsa'`.
func spkiIsRSA(spki []byte) (bool, error) {
	key, err := parsePublicKey(spki)
	if err != nil {
		return false, errors.New("Failed to read the subject public key")
	}
	return key.kind == "rsa", nil
}

// TbsCertificate (x509.ts tbsCertificate): The TBSCertificate DER for a spec, signed by the caller with the issuer's
// key. The spec holds serialNumber (hex), issuer (DER), subject, spki (DER), notBefore, notAfter, names, ca
// ({ pathLength? }), usage, authorityKeyId, crlUrl and permitted, as in x509.ts CertificateSpec.
func TbsCertificate(spec *core.Object, algorithm string) (result []byte, err error) {
	spki := bytesOf(spec.Get("spki"))
	subjectKeyID, err := KeyIdentifier(spki)
	if err != nil {
		return nil, err
	}
	extensions := [][]byte{}
	if ca, ok := spec.Get("ca").(*core.Object); ok && ca != nil {
		constraints := [][]byte{derBoolean(true)}
		if pathLength := ca.Get("pathLength"); !isUndefined(pathLength) {
			constraints = append(constraints, derIntegerNumber(jsNumber(pathLength)))
		}
		extensions = append(extensions,
			derExtension(x509OIDs.BasicConstraints, true, derSequence(constraints...)),
			derExtension(x509OIDs.KeyUsage, true, derNamedBits([]int{0, 5, 6})),
		)
		if permitted, ok := spec.Get("permitted").(*core.Object); ok && permitted != nil {
			dnsNames, _ := permitted.Get("dnsNames").([]any)
			uriHosts, _ := permitted.Get("uriHosts").([]any)
			if len(dnsNames) > 0 || len(uriHosts) > 0 {
				subtree := func(tag byte, value string) []byte { return derSequence(derTLV(tag, asciiBytes(value))) }
				subtrees := [][]byte{}
				for _, value := range dnsNames {
					subtrees = append(subtrees, subtree(0x82, jsString(value)))
				}
				// RFC 5280: a URI host constraint matches that host exactly, `.host` its subdomains; both, to mean what
				// the authority enforces at issuance (the host and everything below it).
				for _, value := range uriHosts {
					subtrees = append(subtrees, subtree(0x86, jsString(value)), subtree(0x86, "."+jsString(value)))
				}
				extensions = append(extensions, derExtension(x509OIDs.NameConstraints, true, derSequence(derTLV(0xa0, derConcat(subtrees...)))))
			}
		}
	} else {
		rsaKey, err := spkiIsRSA(spki)
		if err != nil {
			return nil, err
		}
		usageBits := []int{0}
		if rsaKey {
			usageBits = []int{0, 2}
		}
		usage := spec.Get("usage")
		purposes := [][]byte{}
		if usage != "client" {
			purposes = append(purposes, derOID(x509OIDs.ServerAuth))
		}
		if usage != "server" {
			purposes = append(purposes, derOID(x509OIDs.ClientAuth))
		}
		extensions = append(extensions,
			derExtension(x509OIDs.BasicConstraints, true, derSequence()),
			derExtension(x509OIDs.KeyUsage, true, derNamedBits(usageBits)),
			derExtension(x509OIDs.ExtKeyUsage, false, derSequence(purposes...)),
		)
	}
	extensions = append(extensions, derExtension(x509OIDs.SubjectKeyIdentifier, false, derOctetString(subjectKeyID)))
	if authorityKeyID := spec.Get("authorityKeyId"); !nullish(authorityKeyID) {
		extensions = append(extensions, derExtension(x509OIDs.AuthorityKeyIdentifier, false, derSequence(derTLV(0x80, bytesOf(authorityKeyID)))))
	}
	subject, _ := spec.Get("subject").(*core.Object)
	if subject == nil {
		subject = core.NewObject()
	}
	if namesValue, ok := spec.Get("names").(*core.Object); ok && namesValue != nil {
		names := sanSetOf(namesValue)
		if names.total() > 0 {
			emptySubject := true
			subject.Entries(func(key string, value any) bool {
				if truthy(value) {
					emptySubject = false
				}
				return true
			})
			// An empty subject makes the alternative names critical (RFC 5280 4.2.1.6), as in SPIFFE SVIDs.
			extensions = append(extensions, derExtension(x509OIDs.SubjectAltName, emptySubject, encodeGeneralNames(names)))
		}
	}
	if crlURL := spec.Get("crlUrl"); truthy(crlURL) {
		extensions = append(extensions, derExtension(x509OIDs.CrlDistributionPoints, false,
			derSequence(derSequence(derExplicit(0, derTLV(0xa0, derTLV(0x86, asciiBytes(jsString(crlURL)))))))))
	}
	identifier, err := algorithmIdentifier(algorithm)
	if err != nil {
		return nil, err
	}
	encodedSubject, err := EncodeName(subject)
	if err != nil {
		return nil, err
	}
	return derSequence(
		derExplicit(0, derIntegerNumber(2)),
		derInteger(nodeHexDecode(jsString(spec.Get("serialNumber")))),
		identifier,
		bytesOf(spec.Get("issuer")),
		derSequence(derTime(jsNumber(spec.Get("notBefore"))), derTime(jsNumber(spec.Get("notAfter")))),
		encodedSubject,
		spki,
		derExplicit(3, derSequence(extensions...)),
	), nil
}

// SignedStructure (x509.ts signedStructure): Wraps a signed TBS structure (certificate or CRL).
func SignedStructure(tbs []byte, algorithm string, signature []byte) (result []byte, err error) {
	identifier, err := algorithmIdentifier(algorithm)
	if err != nil {
		return nil, err
	}
	return derSequence(tbs, identifier, derBitString(signature)), nil
}

// revocationReasonCode is `revocationReasons[reason]` (a property lookup: the reason as a property key).
func revocationReasonCode(reason any) (float64, bool) {
	switch jsString(reason) {
	case "unspecified":
		return RevocationReasons.Unspecified, true
	case "keyCompromise":
		return RevocationReasons.KeyCompromise, true
	case "caCompromise":
		return RevocationReasons.CaCompromise, true
	case "affiliationChanged":
		return RevocationReasons.AffiliationChanged, true
	case "superseded":
		return RevocationReasons.Superseded, true
	case "cessationOfOperation":
		return RevocationReasons.CessationOfOperation, true
	case "certificateHold":
		return RevocationReasons.CertificateHold, true
	case "privilegeWithdrawn":
		return RevocationReasons.PrivilegeWithdrawn, true
	}
	return 0, false
}

// TbsCertList (x509.ts tbsCertList): A TBSCertList (RFC 5280 5.1) with a CRL number and the issuer's key identifier.
// The spec holds issuer (DER), thisUpdate, nextUpdate, crlNumber, authorityKeyId and revoked (a list of
// { serialNumber, revokedAt, reason? }).
func TbsCertList(spec *core.Object, algorithm string) (result []byte, err error) {
	revoked, _ := spec.Get("revoked").([]any)
	entries := [][]byte{}
	for _, item := range revoked {
		entry, _ := item.(*core.Object)
		fields := [][]byte{
			derInteger(nodeHexDecode(jsString(entry.Get("serialNumber")))),
			derTime(jsNumber(entry.Get("revokedAt"))),
		}
		if reason := entry.Get("reason"); truthy(reason) && reason != "unspecified" {
			code, _ := revocationReasonCode(reason)
			fields = append(fields, derSequence(derExtension(x509OIDs.CrlReason, false, derTLV(0x0a, []byte{byte(code)}))))
		}
		entries = append(entries, derSequence(fields...))
	}
	identifier, err := algorithmIdentifier(algorithm)
	if err != nil {
		return nil, err
	}
	parts := [][]byte{
		derIntegerNumber(1),
		identifier,
		bytesOf(spec.Get("issuer")),
		derTime(jsNumber(spec.Get("thisUpdate"))),
		derTime(jsNumber(spec.Get("nextUpdate"))),
	}
	if len(entries) > 0 {
		parts = append(parts, derSequence(entries...))
	}
	parts = append(parts, derExplicit(0, derSequence(
		derExtension(x509OIDs.AuthorityKeyIdentifier, false, derSequence(derTLV(0x80, bytesOf(spec.Get("authorityKeyId"))))),
		derExtension(x509OIDs.CrlNumber, false, derIntegerNumber(jsNumber(spec.Get("crlNumber")))),
	)))
	return derSequence(parts...), nil
}

// Sha256Fingerprint (x509.ts sha256Fingerprint): the lowercase hex SHA-256 of DER bytes.
func Sha256Fingerprint(der []byte) (result string, err error) {
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

var (
	certificateBegin = regexp.MustCompile(`-----BEGIN CERTIFICATE-----`)
	certificateEnd   = regexp.MustCompile(`-----END CERTIFICATE-----`)
)

// CertificateDer (x509.ts certificateDer): The DER bytes of a PEM certificate.
func CertificateDer(pemText string) (result []byte, err error) {
	body := jsSpaces.ReplaceAllString(replaceFirst(certificateEnd, replaceFirst(certificateBegin, pemText, ""), ""), "")
	return nodeBase64Decode(body), nil
}

// DnsName is x509.ts dnsName.
var DnsName = regexp.MustCompile("^(?:\\*\\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\\.)*[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")

// RevocationReasons is x509.ts revocationReasons.
var RevocationReasons = struct {
	Unspecified          float64
	KeyCompromise        float64
	CaCompromise         float64
	AffiliationChanged   float64
	Superseded           float64
	CessationOfOperation float64
	CertificateHold      float64
	PrivilegeWithdrawn   float64
}{0, 1, 2, 3, 4, 5, 6, 9}

// ---------------------------------------------------------------------------------------------------------------
// Reading certificates (what pki.ts asks of Node's crypto.X509Certificate)

// x509Extension is one certificate extension.
type x509Extension struct {
	oid      string
	critical bool
	value    []byte
}

// x509Certificate is a parsed certificate: the parts X509Certificate exposes (raw, serialNumber, validFrom, validTo,
// subject, subjectAltName, publicKey, ca) and what checkIssued and verify look at.
type x509Certificate struct {
	raw             []byte
	tbs             []byte
	innerAlgorithm  []byte
	outerAlgorithm  []byte
	signatureOID    string
	signature       []byte
	signatureUnused byte
	serial          []byte
	issuer          []byte
	subject         []byte
	notBefore       float64
	notAfter        float64
	spki            []byte
	extensions      []x509Extension
}

var errCertificateUnreadable = errors.New("The certificate cannot be read")

// parseCertificatePem is `new X509Certificate(pemText)` for one PEM certificate.
func parseCertificatePem(pemText string) (*x509Certificate, error) {
	start := strings.Index(pemText, "-----BEGIN CERTIFICATE-----")
	end := strings.Index(pemText, "-----END CERTIFICATE-----")
	if start < 0 || end < start {
		return nil, errCertificateUnreadable
	}
	body := jsSpaces.ReplaceAllString(pemText[start+len("-----BEGIN CERTIFICATE-----"):end], "")
	der, err := base64.StdEncoding.DecodeString(body)
	if err != nil {
		return nil, errCertificateUnreadable
	}
	return parseCertificateDer(der)
}

// parseX509Time reads a UTCTime or GeneralizedTime (UTC) as milliseconds.
func parseX509Time(node derNode, buffer []byte) (float64, error) {
	text := string(derContents(buffer, node))
	var layout string
	switch node.tag {
	case 0x17:
		layout = "060102150405Z"
	case 0x18:
		layout = "20060102150405Z"
		if dot := strings.Index(text, "."); dot >= 0 && strings.HasSuffix(text, "Z") {
			layout = "20060102150405." + strings.Repeat("0", len(text)-dot-2) + "Z"
		}
	default:
		return 0, errCertificateUnreadable
	}
	parsed, err := time.Parse(layout, text)
	if err != nil {
		return 0, errCertificateUnreadable
	}
	if node.tag == 0x17 && parsed.Year() >= 2050 {
		parsed = parsed.AddDate(-100, 0, 0)
	}
	return float64(parsed.UnixMilli()), nil
}

// parseCertificateDer reads a DER certificate (trailing bytes after it are ignored, as d2i_X509 does).
func parseCertificateDer(der []byte) (cert *x509Certificate, err error) {
	fail := func() (*x509Certificate, error) { return nil, errCertificateUnreadable }
	root, err := readDerNode(der, 0, -1)
	if err != nil || root.tag != 0x30 {
		return fail()
	}
	top, err := derChildren(der, root)
	if err != nil || len(top) != 3 || top[0].tag != 0x30 || top[1].tag != 0x30 || top[2].tag != 0x03 {
		return fail()
	}
	cert = &x509Certificate{raw: der[:root.end], tbs: derWhole(der, top[0]), outerAlgorithm: derWhole(der, top[1])}
	outer, err := derChildren(der, top[1])
	if err != nil || len(outer) == 0 || outer[0].tag != 0x06 {
		return fail()
	}
	if cert.signatureOID, err = decodeOID(derContents(der, outer[0])); err != nil {
		return fail()
	}
	bits := derContents(der, top[2])
	if len(bits) == 0 {
		return fail()
	}
	cert.signatureUnused, cert.signature = bits[0], bits[1:]
	fields, err := derChildren(der, top[0])
	if err != nil {
		return fail()
	}
	index := 0
	if len(fields) > 0 && fields[0].tag == 0xa0 {
		index++
	}
	if len(fields) < index+6 {
		return fail()
	}
	serial, algorithm, issuer, validity, subject, spki := fields[index], fields[index+1], fields[index+2], fields[index+3], fields[index+4], fields[index+5]
	if serial.tag != 0x02 || algorithm.tag != 0x30 || issuer.tag != 0x30 || validity.tag != 0x30 || subject.tag != 0x30 || spki.tag != 0x30 {
		return fail()
	}
	cert.serial = derContents(der, serial)
	if len(cert.serial) == 0 {
		return fail()
	}
	cert.innerAlgorithm = derWhole(der, algorithm)
	cert.issuer = derWhole(der, issuer)
	cert.subject = derWhole(der, subject)
	cert.spki = derWhole(der, spki)
	times, err := derChildren(der, validity)
	if err != nil || len(times) != 2 {
		return fail()
	}
	if cert.notBefore, err = parseX509Time(times[0], der); err != nil {
		return fail()
	}
	if cert.notAfter, err = parseX509Time(times[1], der); err != nil {
		return fail()
	}
	for _, field := range fields[index+6:] {
		if field.tag != 0xa3 {
			continue
		}
		wrapper, err := derChildren(der, field)
		if err != nil || len(wrapper) != 1 || wrapper[0].tag != 0x30 {
			return fail()
		}
		items, err := derChildren(der, wrapper[0])
		if err != nil {
			return fail()
		}
		for _, item := range items {
			parts, err := derChildren(der, item)
			if err != nil || len(parts) < 2 || parts[0].tag != 0x06 || parts[len(parts)-1].tag != 0x04 {
				return fail()
			}
			oid, err := decodeOID(derContents(der, parts[0]))
			if err != nil {
				return fail()
			}
			critical := len(parts) == 3 && parts[1].tag == 0x01 && len(derContents(der, parts[1])) == 1 && derContents(der, parts[1])[0] != 0
			cert.extensions = append(cert.extensions, x509Extension{oid: oid, critical: critical, value: derContents(der, parts[len(parts)-1])})
		}
	}
	return cert, nil
}

func (c *x509Certificate) extension(oid string) *x509Extension {
	for index := range c.extensions {
		if c.extensions[index].oid == oid {
			return &c.extensions[index]
		}
	}
	return nil
}

// serialNumber is X509Certificate#serialNumber: uppercase hex of the serial (a minus sign for a negative one).
func (c *x509Certificate) serialNumber() string {
	value := new(big.Int).SetBytes(c.serial)
	sign := ""
	if c.serial[0]&0x80 != 0 {
		value.Sub(value, new(big.Int).Lsh(big.NewInt(1), uint(8*len(c.serial))))
		value.Neg(value)
		sign = "-"
	}
	text := strings.ToUpper(value.Text(16))
	if len(text)%2 == 1 {
		text = "0" + text
	}
	return sign + text
}

// keyUsage is the key usage bits (first two bytes), present false without the extension.
func (c *x509Certificate) keyUsage() (bits int, present bool) {
	extension := c.extension(x509OIDs.KeyUsage)
	if extension == nil {
		return 0, false
	}
	node, err := readDerNode(extension.value, 0, -1)
	if err != nil || node.tag != 0x03 {
		return 0, true
	}
	content := derContents(extension.value, node)
	if len(content) > 1 {
		bits = int(content[1]) << 8
	}
	if len(content) > 2 {
		bits |= int(content[2])
	}
	return bits, true
}

// keyCertSign is key usage bit 5.
const keyCertSign = 0x0400

// ca is X509Certificate#ca (X509_check_ca === 1): basic constraints with cA set, and certificate signing in the key
// usage when there is one.
func (c *x509Certificate) ca() bool {
	if bits, present := c.keyUsage(); present && bits&keyCertSign == 0 {
		return false
	}
	extension := c.extension(x509OIDs.BasicConstraints)
	if extension == nil {
		return false
	}
	node, err := readDerNode(extension.value, 0, -1)
	if err != nil || node.tag != 0x30 {
		return false
	}
	children, err := derChildren(extension.value, node)
	if err != nil || len(children) == 0 || children[0].tag != 0x01 {
		return false
	}
	flag := derContents(extension.value, children[0])
	return len(flag) == 1 && flag[0] != 0
}

// subjectKeyID is the subject key identifier extension's value, nil without it.
func (c *x509Certificate) subjectKeyID() []byte {
	extension := c.extension(x509OIDs.SubjectKeyIdentifier)
	if extension == nil {
		return nil
	}
	node, err := readDerNode(extension.value, 0, -1)
	if err != nil || node.tag != 0x04 {
		return nil
	}
	return derContents(extension.value, node)
}

// authorityKeyID is the key identifier of the authority key identifier extension, nil without one.
func (c *x509Certificate) authorityKeyID() []byte {
	extension := c.extension(x509OIDs.AuthorityKeyIdentifier)
	if extension == nil {
		return nil
	}
	node, err := readDerNode(extension.value, 0, -1)
	if err != nil || node.tag != 0x30 {
		return nil
	}
	children, err := derChildren(extension.value, node)
	if err != nil {
		return nil
	}
	for _, child := range children {
		if child.tag == 0x80 {
			return derContents(extension.value, child)
		}
	}
	return nil
}

// publicKey is X509Certificate#publicKey.
func (c *x509Certificate) publicKey() (*pkiPublicKey, error) {
	key, err := parsePublicKey(c.spki)
	if err != nil {
		return nil, errors.New("Failed to read the certificate's public key")
	}
	return key, nil
}

// signatureFits is OpenSSL's check that a signature algorithm belongs to a key's type.
func signatureFits(oid string, key *pkiPublicKey) bool {
	switch oid {
	case x509OIDs.Ed25519:
		return key.kind == "ed25519"
	case x509OIDs.EcdsaSha256, x509OIDs.EcdsaSha384, x509OIDs.EcdsaSha512:
		return key.kind == "ec"
	case x509OIDs.RsaSha256, x509OIDs.RsaSha384, x509OIDs.RsaSha512:
		return key.kind == "rsa"
	}
	return false
}

// verify is X509Certificate#verify(publicKey): the signature verifies with the key.
func (c *x509Certificate) verify(key *pkiPublicKey) bool {
	if string(c.outerAlgorithm) != string(c.innerAlgorithm) || c.signatureUnused != 0 || !signatureFits(c.signatureOID, key) {
		return false
	}
	hash, known := hashForOID(c.signatureOID)
	if !known {
		return false
	}
	return verifyWithKey(key, hash, c.tbs, c.signature)
}

// checkIssued is X509Certificate#checkIssued(issuer): the issuer's subject names this certificate's issuer, the key
// identifiers agree, the issuer's key type fits the signature algorithm, and the issuer may sign certificates.
func (c *x509Certificate) checkIssued(issuer *x509Certificate) bool {
	if string(c.issuer) != string(issuer.subject) {
		return false
	}
	if keyID, subjectKeyID := c.authorityKeyID(), issuer.subjectKeyID(); keyID != nil && subjectKeyID != nil && string(keyID) != string(subjectKeyID) {
		return false
	}
	key, err := issuer.publicKey()
	if err != nil || !signatureFits(c.signatureOID, key) {
		return false
	}
	if bits, present := issuer.keyUsage(); present && bits&keyCertSign == 0 {
		return false
	}
	return true
}

// x509ShortNames are OpenSSL's short names of the attribute types names commonly carry.
var x509ShortNames = map[string]string{
	"2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU",
	"2.5.4.5": "serialNumber", "2.5.4.4": "SN", "2.5.4.42": "GN", "2.5.4.12": "title", "2.5.4.9": "street",
	"2.5.4.17": "postalCode", "1.2.840.113549.1.9.1": "emailAddress", "0.9.2342.19200300.100.1.25": "DC",
	"0.9.2342.19200300.100.1.1": "UID",
}

// escapeNameValue applies RFC 2253 and control-character escaping as OpenSSL prints names for Node.
func escapeNameValue(value string) string {
	var out strings.Builder
	runes := []rune(value)
	for index, r := range runes {
		switch {
		case strings.ContainsRune(`,+"\<>;`, r):
			out.WriteRune('\\')
			out.WriteRune(r)
		case (r == '#' || r == ' ') && index == 0, r == ' ' && index == len(runes)-1:
			out.WriteRune('\\')
			out.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			out.WriteString("\\" + strings.ToUpper(hex.EncodeToString([]byte{byte(r)})))
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}

// subjectText is X509Certificate#subject: one `type=value` line per attribute, "" for an empty name.
func (c *x509Certificate) subjectText() string {
	root, err := readDerNode(c.subject, 0, -1)
	if err != nil {
		return ""
	}
	rdns, err := derChildren(c.subject, root)
	if err != nil {
		return ""
	}
	lines := []string{}
	for _, rdn := range rdns {
		attributes, err := derChildren(c.subject, rdn)
		if err != nil {
			continue
		}
		parts := []string{}
		for _, attribute := range attributes {
			pair, err := derChildren(c.subject, attribute)
			if err != nil || len(pair) < 2 || pair[0].tag != 0x06 {
				continue
			}
			oid, err := decodeOID(derContents(c.subject, pair[0]))
			if err != nil {
				continue
			}
			name, known := x509ShortNames[oid]
			if !known {
				name = oid
			}
			text, isText, err := nameValue(c.subject, pair[1])
			if err != nil || !isText {
				text = "#" + strings.ToUpper(hex.EncodeToString(derWhole(c.subject, pair[1])))
			} else {
				text = escapeNameValue(text)
			}
			parts = append(parts, name+"="+text)
		}
		if len(parts) > 0 {
			lines = append(lines, strings.Join(parts, " + "))
		}
	}
	return strings.Join(lines, "\n")
}

// altNameText is how Node prints an IA5String alternative name: as is when safe, otherwise as a quoted string.
func altNameText(value []byte) string {
	safe := true
	for _, c := range value {
		if c == '"' || c == '\\' || c == ',' || c == '\'' || c < ' ' || c > '~' {
			safe = false
			break
		}
	}
	if safe {
		return string(value)
	}
	var out strings.Builder
	out.WriteByte('"')
	for _, c := range value {
		switch {
		case c == '"' || c == '\\':
			out.WriteByte('\\')
			out.WriteByte(c)
		case c < ' ' || c > '~':
			out.WriteString("\\u00" + hex.EncodeToString([]byte{c}))
		default:
			out.WriteByte(c)
		}
	}
	out.WriteByte('"')
	return out.String()
}

// subjectAltNameText is X509Certificate#subjectAltName ("" without the extension).
func (c *x509Certificate) subjectAltNameText() string {
	extension := c.extension(x509OIDs.SubjectAltName)
	if extension == nil {
		return ""
	}
	node, err := readDerNode(extension.value, 0, -1)
	if err != nil {
		return ""
	}
	children, err := derChildren(extension.value, node)
	if err != nil {
		return ""
	}
	entries := []string{}
	for _, child := range children {
		value := derContents(extension.value, child)
		switch child.tag {
		case 0x81:
			entries = append(entries, "email:"+altNameText(value))
		case 0x82:
			entries = append(entries, "DNS:"+altNameText(value))
		case 0x86:
			entries = append(entries, "URI:"+altNameText(value))
		case 0x87:
			if len(value) == 4 || len(value) == 16 {
				entries = append(entries, "IP Address:"+ipText(value))
			} else {
				entries = append(entries, "IP Address:<invalid>")
			}
		default:
			entries = append(entries, "othername:<unsupported>")
		}
	}
	return strings.Join(entries, ", ")
}
