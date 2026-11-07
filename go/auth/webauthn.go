package auth

// The WebAuthn ceremonies the passkey service relies on, ported from @simplewebauthn/server 13.3:
// generateRegistrationOptions, generateAuthenticationOptions, verifyRegistrationResponse (none, packed, fido-u2f,
// android-key, android-safetynet, tpm and apple attestation; see webauthn_attestation.go) and
// verifyAuthenticationResponse, with the same checks in the same order: client data type, challenge and origin,
// token binding, RP ID hash, user presence and verification, accepted algorithms, the signature counter, and the
// backup flags. Credential public keys are stored as the library stores them (the COSE key re-encoded by its CBOR
// codec), so passkeys registered by either implementation sign in on the other.

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/Better-IAM/better-iam/go/core"
)

// COSE algorithm identifiers.
const (
	coseES256  = -7
	coseEdDSA  = -8
	coseES384  = -35
	coseES512  = -36
	cosePS256  = -37
	cosePS384  = -38
	cosePS512  = -39
	coseES256K = -47
	coseRS256  = -257
	coseRS384  = -258
	coseRS512  = -259
	coseRS1    = -65535
)

var coseAlgorithms = []float64{coseES256, coseEdDSA, coseES384, coseES512, cosePS256, cosePS384, cosePS512, coseES256K, coseRS256, coseRS384, coseRS512, coseRS1}

// supportedCOSEAlgorithms are the algorithms verifyRegistrationResponse accepts by default.
var supportedCOSEAlgorithms = []float64{-8, -7, -36, -37, -38, -39, -257, -258, -259, -65535}

func isCOSEAlg(value any) bool {
	n, ok := value.(float64)
	if !ok {
		return false
	}
	for _, alg := range coseAlgorithms {
		if alg == n {
			return true
		}
	}
	return false
}

func containsNumber(list []float64, value float64) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

// hexagonDecode is @hexagon/base64's toArrayBuffer (isoBase64URL.toBuffer): groups of four characters, characters
// outside the alphabet read as zero, and the length is floor(length * 3/4) less the padding.
func hexagonDecode(s string, urlMode bool) []byte {
	units := core.ToUTF16(s)
	length := float64(len(units)) * 0.75
	if len(units) > 0 && units[len(units)-1] == '=' {
		length--
		if len(units) > 1 && units[len(units)-2] == '=' {
			length--
		}
	}
	size := int(length)
	if size < 0 {
		size = 0
	}
	alphabet := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	if urlMode {
		alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	}
	lookup := func(i int) int {
		if i >= len(units) || units[i] > 255 {
			return 0
		}
		index := strings.IndexByte(alphabet, byte(units[i]))
		if index < 0 {
			return 0
		}
		return index
	}
	out := make([]byte, size)
	p := 0
	put := func(b int) {
		if p < size {
			out[p] = byte(b)
		}
		p++
	}
	for i := 0; i < len(units); i += 4 {
		e1, e2, e3, e4 := lookup(i), lookup(i+1), lookup(i+2), lookup(i+3)
		put(e1<<2 | e2>>4)
		put((e2&15)<<4 | e3>>2)
		put((e3&3)<<6 | e4&63)
	}
	return out
}

// isBase64URL is isoBase64URL.isBase64URL: padding removed, only [-A-Za-z0-9_].
func isBase64URL(value any) bool {
	s, ok := value.(string)
	if !ok {
		return false
	}
	s = strings.ReplaceAll(s, "=", "")
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// generateChallenge is 32 random bytes as base64url.
func generateChallenge() string { return base64url(randomBytes(32)) }

// WebAuthnCredentialDescriptor is an allow/exclude list entry: a base64url credential ID and its transports
// (nil: not recorded).
type WebAuthnCredentialDescriptor struct {
	ID         string
	Transports any
}

func descriptors(list []WebAuthnCredentialDescriptor) ([]any, error) {
	out := make([]any, 0, len(list))
	for _, item := range list {
		if !isBase64URL(item.ID) {
			return nil, fmt.Errorf("credential id %q is not a valid base64url string", item.ID)
		}
		entry := core.NewObject("id", strings.ReplaceAll(item.ID, "=", ""))
		if item.Transports != nil && !core.IsUndefined(item.Transports) {
			entry.Set("transports", item.Transports)
		}
		entry.Set("type", "public-key")
		// generateAuthenticationOptions spreads the descriptor, then overwrites id: the key order stays id, transports.
		reordered := core.NewObject("id", entry.Get("id"))
		if entry.Has("transports") {
			reordered.Set("transports", entry.Get("transports"))
		}
		reordered.Set("type", "public-key")
		out = append(out, reordered)
	}
	return out, nil
}

// RegistrationOptionsInput is what the passkey service passes to generateRegistrationOptions.
type RegistrationOptionsInput struct {
	RPName          string
	RPID            string
	UserName        string
	UserID          []byte
	UserDisplayName string
	Exclude         []WebAuthnCredentialDescriptor
}

// GenerateRegistrationOptions returns PublicKeyCredentialCreationOptionsJSON with attestation 'none' and
// authenticatorSelection { residentKey: 'required', userVerification: 'required' }, as the TypeScript service asks.
func GenerateRegistrationOptions(input RegistrationOptionsInput) (*core.Object, error) {
	exclude, err := descriptors(input.Exclude)
	if err != nil {
		return nil, err
	}
	params := []any{}
	for _, alg := range []float64{-8, -7, -257} {
		params = append(params, core.NewObject("alg", alg, "type", "public-key"))
	}
	return core.NewObject(
		"challenge", generateChallenge(),
		"rp", core.NewObject("name", input.RPName, "id", input.RPID),
		"user", core.NewObject("id", base64url(input.UserID), "name", input.UserName, "displayName", input.UserDisplayName),
		"pubKeyCredParams", params,
		"timeout", 60000.0,
		"attestation", "none",
		"excludeCredentials", exclude,
		"authenticatorSelection", core.NewObject("residentKey", "required", "userVerification", "required", "requireResidentKey", true),
		"extensions", core.NewObject("credProps", true),
		"hints", []any{},
	), nil
}

// GenerateAuthenticationOptions returns PublicKeyCredentialRequestOptionsJSON with userVerification 'required';
// allow nil leaves allowCredentials out (discoverable credentials).
func GenerateAuthenticationOptions(rpID string, allow []WebAuthnCredentialDescriptor) (*core.Object, error) {
	options := core.NewObject("rpId", rpID, "challenge", generateChallenge())
	if allow != nil {
		list, err := descriptors(allow)
		if err != nil {
			return nil, err
		}
		options.Set("allowCredentials", list)
	}
	options.Set("timeout", 60000.0)
	options.Set("userVerification", "required")
	return options, nil
}

// --- authenticator data ------------------------------------------------------------------------------------------

type authenticatorFlags struct {
	up, uv, be, bs, at, ed bool
}

type authenticatorData struct {
	rpIDHash            []byte
	flags               authenticatorFlags
	counter             uint32
	aaguid              []byte
	credentialID        []byte
	credentialPublicKey []byte
	extensions          *cborMap
}

var badEdDSACBOR, _ = hex.DecodeString("a301634f4b500327206745643235353139")

func parseAuthenticatorData(authData []byte) (*authenticatorData, error) {
	if len(authData) < 37 {
		return nil, fmt.Errorf("Authenticator data was %d bytes, expected at least 37 bytes", len(authData))
	}
	data := append([]byte(nil), authData...)
	parsed := &authenticatorData{rpIDHash: data[:32]}
	flags := data[32]
	parsed.flags = authenticatorFlags{
		up: flags&1 != 0, uv: flags&4 != 0, be: flags&8 != 0, bs: flags&16 != 0, at: flags&64 != 0, ed: flags&128 != 0,
	}
	parsed.counter = binary.BigEndian.Uint32(data[33:37])
	pointer := 37
	slice := func(n int) []byte {
		start, end := min(pointer, len(data)), min(pointer+n, len(data))
		pointer += n
		return append([]byte(nil), data[start:end]...)
	}
	if parsed.flags.at {
		parsed.aaguid = slice(16)
		if pointer+2 > len(data) {
			return nil, errors.New("Offset is outside the bounds of the DataView")
		}
		length := int(binary.BigEndian.Uint16(data[pointer:]))
		pointer += 2
		parsed.credentialID = slice(length)
		rest := []byte{}
		if pointer < len(data) {
			rest = append(rest, data[pointer:]...)
		}
		// Some authenticators wrote an Ed25519 key without its x member in a three-entry map; the library reads it as
		// a four-entry map so the key is recognized.
		if len(rest) >= len(badEdDSACBOR) && string(rest[:len(badEdDSACBOR)]) == string(badEdDSACBOR) {
			rest[0] = 0xa4
		}
		decoded, err := cborDecodeFirst(rest)
		if err != nil {
			return nil, err
		}
		encoded, err := cborEncode(decoded)
		if err != nil {
			return nil, err
		}
		parsed.credentialPublicKey = encoded
		pointer += len(encoded)
	}
	if parsed.flags.ed {
		rest := []byte{}
		if pointer < len(data) {
			rest = data[pointer:]
		}
		decoded, err := cborDecodeFirst(rest)
		if err != nil {
			return nil, err
		}
		encoded, err := cborEncode(decoded)
		if err != nil {
			return nil, err
		}
		extensions, ok := decoded.(*cborMap)
		if !ok {
			return nil, errors.New("Error decoding authenticator extensions")
		}
		parsed.extensions = extensions
		pointer += len(encoded)
	}
	if len(data) > pointer {
		return nil, errors.New("Leftover bytes detected while parsing authenticator data")
	}
	return parsed, nil
}

func parseBackupFlags(flags authenticatorFlags) (string, bool, error) {
	deviceType := "singleDevice"
	if flags.be {
		deviceType = "multiDevice"
	}
	if deviceType == "singleDevice" && flags.bs {
		return "", false, errors.New("Single-device credential indicated that it was backed up, which should be impossible.")
	}
	return deviceType, flags.bs, nil
}

// fromASCIIString is isoUint8Array.fromASCIIString: each UTF-16 code unit truncated to a byte.
func fromASCIIString(value string) []byte {
	units := core.ToUTF16(value)
	out := make([]byte, len(units))
	for index, unit := range units {
		out[index] = byte(unit)
	}
	return out
}

func matchExpectedRPID(rpIDHash []byte, expected []string) (string, error) {
	for _, candidate := range expected {
		digest := sha256.Sum256(fromASCIIString(candidate))
		if string(digest[:]) == string(rpIDHash) {
			return candidate, nil
		}
	}
	return "", errors.New("Unexpected RP ID hash")
}

// --- client data --------------------------------------------------------------------------------------------------

func decodeClientData(value any) (*core.Object, error) {
	text, ok := value.(string)
	if !ok {
		return nil, errors.New("clientDataJSON is not a string")
	}
	parsed, err := core.ParseJSONString(decodeUTF8(hexagonDecode(text, true)))
	if err != nil {
		return nil, err
	}
	object, ok := parsed.(*core.Object)
	if !ok {
		// Destructuring a primitive reads undefined members; null throws.
		if parsed == nil {
			return nil, errors.New("Cannot destructure clientDataJSON")
		}
		return core.NewObject(), nil
	}
	return object, nil
}

func checkClientData(clientData *core.Object, expectedType, expectedChallenge string, expectedOrigins []string, tokenStatuses []string) error {
	if typ, ok := clientData.Get("type").(string); !ok || typ != expectedType {
		return fmt.Errorf("Unexpected response type: %v", clientData.Get("type"))
	}
	if challenge, ok := clientData.Get("challenge").(string); !ok || challenge != expectedChallenge {
		return errors.New("Unexpected response challenge")
	}
	origin, ok := clientData.Get("origin").(string)
	matched := false
	for _, expected := range expectedOrigins {
		if ok && origin == expected {
			matched = true
		}
	}
	if !matched {
		return errors.New("Unexpected response origin")
	}
	if binding := clientData.Get("tokenBinding"); truthy(binding) {
		object, isObject := binding.(*core.Object)
		if !isObject {
			if _, isArray := binding.([]any); !isArray {
				return errors.New("Unexpected value for TokenBinding")
			}
		}
		status := any(core.Undefined)
		if isObject {
			status = object.Get("status")
		}
		found := false
		for _, allowed := range tokenStatuses {
			if core.StrictEquals(status, allowed) {
				found = true
			}
		}
		if !found {
			return errors.New("Unexpected tokenBinding.status value")
		}
	}
	return nil
}

// --- COSE keys and signatures -------------------------------------------------------------------------------------

// webCryptoHash is mapCoseAlgToWebCryptoAlg: the digest a COSE algorithm signs with (ES384 is not mapped there).
func webCryptoHash(alg any) (crypto.Hash, error) {
	if n, ok := alg.(float64); ok {
		switch n {
		case coseRS1:
			return crypto.SHA1, nil
		case coseES256, cosePS256, coseRS256:
			return crypto.SHA256, nil
		case cosePS384, coseRS384:
			return crypto.SHA384, nil
		case coseES512, cosePS512, coseRS512, coseEdDSA:
			return crypto.SHA512, nil
		}
	}
	return 0, fmt.Errorf("Could not map COSE alg value of %v to a WebCrypto alg", alg)
}

func isNumber(value any) bool {
	_, ok := value.(float64)
	return ok
}

func digest(hash crypto.Hash, data []byte) []byte {
	switch hash {
	case crypto.SHA1:
		sum := sha1.Sum(data)
		return sum[:]
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

// toHash is the library's toHash(data, alg = ES256).
func toHash(data []byte, alg any) ([]byte, error) {
	hash, err := webCryptoHash(alg)
	if err != nil {
		return nil, err
	}
	return digest(hash, data), nil
}

func bytesMember(m *cborMap, key any) []byte {
	value, _ := m.get(key)
	b, _ := value.([]byte)
	return b
}

func memberTruthy(m *cborMap, key any) bool {
	value, ok := m.get(key)
	if !ok {
		return false
	}
	switch value.(type) {
	case []byte:
		return true
	case *cborMap, []any, *cborTag:
		return true
	case cborUndefined:
		return false
	}
	return truthy(value)
}

// componentLength is the size of r and s for a COSE curve.
func componentLength(crv any) (int, error) {
	switch crv {
	case 1.0:
		return 32, nil
	case 2.0:
		return 48, nil
	case 3.0:
		return 66, nil
	}
	return 0, fmt.Errorf("Unexpected COSE crv value of %v (EC2)", crv)
}

// unwrapEC2Signature reads a DER ECDSA-Sig-Value into r and s, normalized as the library does.
func unwrapEC2Signature(signature []byte, crv any) (*big.Int, *big.Int, error) {
	input := cryptobyte.String(signature)
	var sequence, rBytes, sBytes cryptobyte.String
	if !input.ReadASN1(&sequence, cbasn1.SEQUENCE) || !sequence.ReadASN1(&rBytes, cbasn1.INTEGER) || !sequence.ReadASN1(&sBytes, cbasn1.INTEGER) {
		return nil, nil, errors.New("Invalid ECDSA signature")
	}
	size, err := componentLength(crv)
	if err != nil {
		return nil, nil, err
	}
	normalize := func(b []byte) ([]byte, error) {
		switch {
		case len(b) < size:
			out := make([]byte, size)
			copy(out[size-len(b):], b)
			return out, nil
		case len(b) == size:
			return b, nil
		case len(b) == size+1 && b[0] == 0 && b[1]&0x80 == 0x80:
			return b[1:], nil
		}
		return nil, fmt.Errorf("Invalid signature component length %d, expected %d", len(b), size)
	}
	r, err := normalize(rBytes)
	if err != nil {
		return nil, nil, err
	}
	s, err := normalize(sBytes)
	if err != nil {
		return nil, nil, err
	}
	return new(big.Int).SetBytes(r), new(big.Int).SetBytes(s), nil
}

func ecCurve(crv any) (elliptic.Curve, int, error) {
	switch crv {
	case 1.0:
		return elliptic.P256(), 32, nil
	case 2.0:
		return elliptic.P384(), 48, nil
	case 3.0:
		return elliptic.P521(), 66, nil
	}
	return nil, 0, fmt.Errorf("Unexpected COSE crv value of %v (EC2)", crv)
}

// verifyCOSE is isoCrypto.verify: the signature over data under a COSE public key; hashOverride (the attestation
// statement's alg) replaces the key's algorithm for the digest. A malformed key or EC signature is an error; a
// signature that does not verify is false.
func verifyCOSE(key *cborMap, signature, data []byte, hashOverride any) (bool, error) {
	kty, _ := key.get(1.0)
	alg, _ := key.get(3.0)
	switch kty {
	case 2.0:
		crv, _ := key.get(-1.0)
		if crv != 1.0 && crv != 2.0 && crv != 3.0 && crv != 6.0 && crv != 8.0 {
			return false, fmt.Errorf("unknown COSE curve %v", crv)
		}
		r, s, err := unwrapEC2Signature(signature, crv)
		if err != nil {
			return false, err
		}
		x, y := bytesMember(key, -2.0), bytesMember(key, -3.0)
		if !memberTruthy(key, 3.0) {
			return false, errors.New("Public key was missing alg (EC2)")
		}
		if x == nil {
			return false, errors.New("Public key was missing x (EC2)")
		}
		if y == nil {
			return false, errors.New("Public key was missing y (EC2)")
		}
		curve, size, err := ecCurve(crv)
		if err != nil {
			return false, err
		}
		if len(x) != size || len(y) != size {
			return false, errors.New("Invalid EC key coordinates")
		}
		point := append(append([]byte{4}, x...), y...)
		px, py := elliptic.Unmarshal(curve, point)
		if px == nil {
			return false, errors.New("EC point is not on the curve")
		}
		hash, err := webCryptoHash(alg)
		if err != nil {
			return false, err
		}
		if hashOverride != nil {
			if hash, err = webCryptoHash(hashOverride); err != nil {
				return false, err
			}
		}
		return ecdsa.Verify(&ecdsa.PublicKey{Curve: curve, X: px, Y: py}, digest(hash, data), r, s), nil
	case 3.0:
		n, e := bytesMember(key, -1.0), bytesMember(key, -2.0)
		if !memberTruthy(key, 3.0) {
			return false, errors.New("Public key was missing alg (RSA)")
		}
		if !isCOSEAlg(alg) {
			return false, fmt.Errorf("Public key had invalid alg %v (RSA)", alg)
		}
		if n == nil {
			return false, errors.New("Public key was missing n (RSA)")
		}
		if e == nil {
			return false, errors.New("Public key was missing e (RSA)")
		}
		algorithm := alg.(float64)
		pss := algorithm == cosePS256 || algorithm == cosePS384 || algorithm == cosePS512
		pkcs := algorithm == coseRS256 || algorithm == coseRS384 || algorithm == coseRS512 || algorithm == coseRS1
		if !pss && !pkcs {
			return false, fmt.Errorf("Could not map COSE alg value of %v to a WebCrypto key alg name", alg)
		}
		hash, err := webCryptoHash(alg)
		if err != nil {
			return false, err
		}
		if hashOverride != nil {
			if hash, err = webCryptoHash(hashOverride); err != nil {
				return false, err
			}
		}
		exponent := new(big.Int).SetBytes(e)
		if !exponent.IsInt64() || exponent.Int64() < 2 || exponent.Int64() > 1<<31-1 {
			return false, errors.New("Invalid RSA exponent")
		}
		public := &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(exponent.Int64())}
		hashed := digest(hash, data)
		if pss {
			return rsa.VerifyPSS(public, hash, hashed, signature, &rsa.PSSOptions{SaltLength: hash.Size()}) == nil, nil
		}
		return rsa.VerifyPKCS1v15(public, hash, hashed, signature) == nil, nil
	case 1.0:
		crv, _ := key.get(-1.0)
		x := bytesMember(key, -2.0)
		if !memberTruthy(key, 3.0) {
			return false, errors.New("Public key was missing alg (OKP)")
		}
		if !isCOSEAlg(alg) {
			return false, fmt.Errorf("Public key had invalid alg %v (OKP)", alg)
		}
		if !memberTruthy(key, -1.0) {
			return false, errors.New("Public key was missing crv (OKP)")
		}
		if x == nil {
			return false, errors.New("Public key was missing x (OKP)")
		}
		if crv != 6.0 {
			return false, fmt.Errorf("Unexpected COSE crv value of %v (OKP)", crv)
		}
		if len(x) != ed25519.PublicKeySize {
			return false, errors.New("Invalid Ed25519 key")
		}
		return ed25519.Verify(ed25519.PublicKey(x), data, signature), nil
	}
	return false, fmt.Errorf("Signature verification with public key of kty %v is not supported by this method", kty)
}

// --- registration --------------------------------------------------------------------------------------------------

// RegistrationInfo is what a verified registration yields.
type RegistrationInfo struct {
	Fmt                  string
	AAGUID               string
	CredentialID         string
	CredentialPublicKey  []byte
	Counter              uint32
	Transports           any
	UserVerified         bool
	CredentialDeviceType string
	CredentialBackedUp   bool
	Origin               string
	RPID                 string
}

// VerifyRegistrationOptions are verifyRegistrationResponse's options as the passkey service passes them.
type VerifyRegistrationOptions struct {
	ExpectedChallenge       string
	ExpectedOrigins         []string
	ExpectedRPID            string
	RequireUserVerification bool
}

func objectMember(value any, key string) (any, error) {
	object, ok := value.(*core.Object)
	if !ok {
		if value == nil || core.IsUndefined(value) {
			return nil, fmt.Errorf("Cannot read properties of %s (reading '%s')", jsString(value), key)
		}
		return core.Undefined, nil
	}
	return object.Get(key), nil
}

// VerifyRegistrationResponse verifies a RegistrationResponseJSON. An error is a refused response (the library
// throws); verified false is an attestation statement whose signature does not verify.
func VerifyRegistrationResponse(response any, options VerifyRegistrationOptions) (bool, *RegistrationInfo, error) {
	id, err := objectMember(response, "id")
	if err != nil {
		return false, nil, err
	}
	rawID, _ := objectMember(response, "rawId")
	credentialType, _ := objectMember(response, "type")
	attestationResponse, _ := objectMember(response, "response")
	if !truthy(id) {
		return false, nil, errors.New("Missing credential ID")
	}
	if !core.StrictEquals(id, rawID) {
		return false, nil, errors.New("Credential ID was not base64url-encoded")
	}
	if credentialType != "public-key" {
		return false, nil, errors.New("Unexpected credential type")
	}
	clientDataJSON, err := objectMember(attestationResponse, "clientDataJSON")
	if err != nil {
		return false, nil, err
	}
	clientData, err := decodeClientData(clientDataJSON)
	if err != nil {
		return false, nil, err
	}
	if err := checkClientData(clientData, "webauthn.create", options.ExpectedChallenge, options.ExpectedOrigins,
		[]string{"present", "supported", "not-supported"}); err != nil {
		return false, nil, err
	}
	attestationText, _ := objectMember(attestationResponse, "attestationObject")
	attestationString, ok := attestationText.(string)
	if !ok {
		return false, nil, errors.New("attestationObject is not a string")
	}
	decodedAttestation, err := cborDecodeFirst(hexagonDecode(attestationString, true))
	if err != nil {
		return false, nil, err
	}
	attestation, ok := decodedAttestation.(*cborMap)
	if !ok {
		return false, nil, errors.New("Attestation object is not a map")
	}
	fmtValue, _ := attestation.get("fmt")
	authDataValue, _ := attestation.get("authData")
	attStmtValue, _ := attestation.get("attStmt")
	authData, ok := authDataValue.([]byte)
	if !ok {
		return false, nil, errors.New("authData is not a byte string")
	}
	parsed, err := parseAuthenticatorData(authData)
	if err != nil {
		return false, nil, err
	}
	matchedRPID, err := matchExpectedRPID(parsed.rpIDHash, []string{options.ExpectedRPID})
	if err != nil {
		return false, nil, err
	}
	if !parsed.flags.up {
		return false, nil, errors.New("User presence was required, but user was not present")
	}
	if options.RequireUserVerification && !parsed.flags.uv {
		return false, nil, errors.New("User verification was required, but user could not be verified")
	}
	if parsed.credentialID == nil {
		return false, nil, errors.New("No credential ID was provided by authenticator")
	}
	if parsed.credentialPublicKey == nil {
		return false, nil, errors.New("No public key was provided by authenticator")
	}
	if parsed.aaguid == nil {
		return false, nil, errors.New("No AAGUID was present during registration")
	}
	decodedKey, err := cborDecodeFirst(parsed.credentialPublicKey)
	if err != nil {
		return false, nil, err
	}
	coseKey, ok := decodedKey.(*cborMap)
	if !ok {
		return false, nil, errors.New("Credential public key is not a map")
	}
	alg, _ := coseKey.get(3.0)
	algorithm, ok := alg.(float64)
	if !ok {
		return false, nil, errors.New("Credential public key was missing numeric alg")
	}
	if !containsNumber(supportedCOSEAlgorithms, algorithm) {
		return false, nil, fmt.Errorf("Unexpected public key alg \"%v\"", alg)
	}
	clientDataDigest := sha256.Sum256(hexagonDecode(clientDataJSON.(string), true))
	format, _ := fmtValue.(string)
	attStmt, _ := attStmtValue.(*cborMap)
	if attStmt == nil {
		return false, nil, errors.New("Cannot read properties of attStmt")
	}
	verifier := attestationInput{
		aaguid:              parsed.aaguid,
		attStmt:             attStmt,
		authData:            authData,
		clientDataHash:      clientDataDigest[:],
		credentialID:        parsed.credentialID,
		credentialPublicKey: parsed.credentialPublicKey,
		rpIDHash:            parsed.rpIDHash,
	}
	var verified bool
	switch fmtValue {
	case "fido-u2f":
		verified, err = verifyAttestationFIDOU2F(verifier)
	case "packed":
		verified, err = verifyAttestationPacked(verifier)
	case "android-safetynet":
		verifier.rootCertificates = androidSafetyNetRootPEMs
		verified, err = verifyAttestationAndroidSafetyNet(verifier)
	case "android-key":
		verifier.rootCertificates = androidKeyRootPEMs
		verified, err = verifyAttestationAndroidKey(verifier)
	case "tpm":
		verified, err = verifyAttestationTPM(verifier)
	case "apple":
		verifier.rootCertificates = appleRootPEMs
		verified, err = verifyAttestationApple(verifier)
	case "none":
		if attStmt.size() > 0 {
			return false, nil, errors.New("None attestation had unexpected attestation statement")
		}
		verified = true
	default:
		return false, nil, fmt.Errorf("Unsupported Attestation Format: %v", fmtValue)
	}
	if err != nil {
		return false, nil, err
	}
	if !verified {
		return false, nil, nil
	}
	deviceType, backedUp, err := parseBackupFlags(parsed.flags)
	if err != nil {
		return false, nil, err
	}
	transports, _ := objectMember(attestationResponse, "transports")
	origin, _ := clientData.Get("origin").(string)
	return true, &RegistrationInfo{
		Fmt:                  format,
		AAGUID:               aaguidString(parsed.aaguid),
		CredentialID:         base64url(parsed.credentialID),
		CredentialPublicKey:  parsed.credentialPublicKey,
		Counter:              parsed.counter,
		Transports:           transports,
		UserVerified:         parsed.flags.uv,
		CredentialDeviceType: deviceType,
		CredentialBackedUp:   backedUp,
		Origin:               origin,
		RPID:                 matchedRPID,
	}, nil
}

// aaguidString is convertAAGUIDToString: 8-4-4-4-12 lowercase hex.
func aaguidString(aaguid []byte) string {
	h := hex.EncodeToString(aaguid)
	part := func(start, end int) string {
		if start > len(h) {
			return ""
		}
		return h[start:min(end, len(h))]
	}
	return part(0, 8) + "-" + part(8, 12) + "-" + part(12, 16) + "-" + part(16, 20) + "-" + part(20, 32)
}

// --- authentication ------------------------------------------------------------------------------------------------

// WebAuthnCredential is a stored credential as verifyAuthenticationResponse needs it.
type WebAuthnCredential struct {
	ID        string
	PublicKey []byte
	Counter   float64
}

// AuthenticationInfo is what a verified assertion yields.
type AuthenticationInfo struct {
	NewCounter           uint32
	CredentialID         string
	UserVerified         bool
	CredentialDeviceType string
	CredentialBackedUp   bool
	Origin               string
	RPID                 string
}

// VerifyAuthenticationOptions are verifyAuthenticationResponse's options as the passkey service passes them.
type VerifyAuthenticationOptions struct {
	ExpectedChallenge       string
	ExpectedOrigins         []string
	ExpectedRPID            string
	Credential              WebAuthnCredential
	RequireUserVerification bool
}

// VerifyAuthenticationResponse verifies an AuthenticationResponseJSON. An error is a refused response (the
// library throws); verified false is a signature that does not verify.
func VerifyAuthenticationResponse(response any, options VerifyAuthenticationOptions) (bool, *AuthenticationInfo, error) {
	id, err := objectMember(response, "id")
	if err != nil {
		return false, nil, err
	}
	rawID, _ := objectMember(response, "rawId")
	credentialType, _ := objectMember(response, "type")
	assertion, _ := objectMember(response, "response")
	if !truthy(id) {
		return false, nil, errors.New("Missing credential ID")
	}
	if !core.StrictEquals(id, rawID) {
		return false, nil, errors.New("Credential ID was not base64url-encoded")
	}
	if credentialType != "public-key" {
		return false, nil, errors.New("Unexpected credential type")
	}
	clientDataJSON, _ := objectMember(assertion, "clientDataJSON")
	if _, ok := clientDataJSON.(string); !ok {
		return false, nil, errors.New("Credential response clientDataJSON was not a string")
	}
	clientData, err := decodeClientData(clientDataJSON)
	if err != nil {
		return false, nil, err
	}
	if err := checkClientData(clientData, "webauthn.get", options.ExpectedChallenge, options.ExpectedOrigins,
		[]string{"present", "supported", "notSupported"}); err != nil {
		return false, nil, err
	}
	authenticatorText, _ := objectMember(assertion, "authenticatorData")
	signatureText, _ := objectMember(assertion, "signature")
	if !isBase64URL(authenticatorText) {
		return false, nil, errors.New("Credential response authenticatorData was not a base64url string")
	}
	if !isBase64URL(signatureText) {
		return false, nil, errors.New("Credential response signature was not a base64url string")
	}
	if userHandle, _ := objectMember(assertion, "userHandle"); truthy(userHandle) {
		if _, ok := userHandle.(string); !ok {
			return false, nil, errors.New("Credential response userHandle was not a string")
		}
	}
	authData := hexagonDecode(authenticatorText.(string), true)
	parsed, err := parseAuthenticatorData(authData)
	if err != nil {
		return false, nil, err
	}
	matchedRPID, err := matchExpectedRPID(parsed.rpIDHash, []string{options.ExpectedRPID})
	if err != nil {
		return false, nil, err
	}
	if !parsed.flags.up {
		return false, nil, errors.New("User not present during authentication")
	}
	if options.RequireUserVerification && !parsed.flags.uv {
		return false, nil, errors.New("User verification required, but user could not be verified")
	}
	clientDataDigest := sha256.Sum256(hexagonDecode(clientDataJSON.(string), true))
	signatureBase := append(append([]byte(nil), authData...), clientDataDigest[:]...)
	signature := hexagonDecode(signatureText.(string), true)
	counter := float64(parsed.counter)
	if (counter > 0 || options.Credential.Counter > 0) && counter <= options.Credential.Counter {
		return false, nil, fmt.Errorf("Response counter value %d was lower than expected %v", parsed.counter, options.Credential.Counter)
	}
	deviceType, backedUp, err := parseBackupFlags(parsed.flags)
	if err != nil {
		return false, nil, err
	}
	decodedKey, err := cborDecodeFirst(options.Credential.PublicKey)
	if err != nil {
		return false, nil, err
	}
	coseKey, ok := decodedKey.(*cborMap)
	if !ok {
		return false, nil, errors.New("Credential public key is not a map")
	}
	verified, err := verifyCOSE(coseKey, signature, signatureBase, nil)
	if err != nil {
		return false, nil, err
	}
	origin, _ := clientData.Get("origin").(string)
	return verified, &AuthenticationInfo{
		NewCounter:           parsed.counter,
		CredentialID:         options.Credential.ID,
		UserVerified:         parsed.flags.uv,
		CredentialDeviceType: deviceType,
		CredentialBackedUp:   backedUp,
		Origin:               origin,
		RPID:                 matchedRPID,
	}, nil
}

// certificatePublicKeyToCOSE is convertX509PublicKeyToCOSE: the certificate's EC (P-256, P-384) or RSA key as a COSE
// key whose alg follows the certificate's own signature algorithm.
func certificatePublicKeyToCOSE(certificate *x509.Certificate) (*cborMap, error) {
	var alg float64
	switch certificate.SignatureAlgorithm {
	case x509.ECDSAWithSHA256:
		alg = coseES256
	case x509.ECDSAWithSHA384:
		alg = coseES384
	case x509.ECDSAWithSHA512:
		alg = coseES512
	case x509.SHA256WithRSA:
		alg = coseRS256
	case x509.SHA384WithRSA:
		alg = coseRS384
	case x509.SHA512WithRSA:
		alg = coseRS512
	case x509.SHA1WithRSA:
		alg = coseRS1
	default:
		return nil, fmt.Errorf("Unable to map X.509 signature algorithm %v to a COSE algorithm", certificate.SignatureAlgorithm)
	}
	key := newCBORMap()
	switch public := certificate.PublicKey.(type) {
	case *ecdsa.PublicKey:
		var crv float64
		switch public.Curve {
		case elliptic.P256():
			crv = 1
		case elliptic.P384():
			crv = 2
		default:
			return nil, errors.New("Certificate public key contained unexpected namedCurve (EC2)")
		}
		raw := subjectPublicKeyBits(certificate)
		if len(raw) == 0 || raw[0] != 0x04 {
			return nil, errors.New(`TODO: Figure out how to handle public keys in "compressed form"`)
		}
		half := (len(raw) - 1) / 2
		key.set(1.0, 2.0)
		key.set(3.0, alg)
		key.set(-1.0, crv)
		key.set(-2.0, raw[1:1+half])
		key.set(-3.0, raw[1+half:])
	case *rsa.PublicKey:
		key.set(1.0, 3.0)
		key.set(3.0, alg)
		key.set(-1.0, public.N.Bytes())
		key.set(-2.0, big.NewInt(int64(public.E)).Bytes())
	default:
		return nil, errors.New("Certificate public key contained unexpected algorithm ID")
	}
	return key, nil
}

// verifyWithCertificate is verifySignature with an x509Certificate.
func verifyWithCertificate(der []byte, signature, data []byte, hashAlgorithm any) (bool, error) {
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return false, err
	}
	key, err := certificatePublicKeyToCOSE(certificate)
	if err != nil {
		return false, err
	}
	return verifyCOSE(key, signature, data, hashAlgorithm)
}
