package auth

// Attestation statement formats of @simplewebauthn/server 13.3 (registration/verifications/*): packed (self and
// full), fido-u2f, apple, android-key, android-safetynet and tpm, plus the certificate helpers they share
// (getCertificateInfo, validateExtFIDOGenCEAAGUID, validateCertificatePath with its CRL revocation check, and the
// @peculiar/x509 chain builder). The metadata service is not configured in better-iam, so no format consults it.

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"

	"github.com/Better-IAM/better-iam/go/core"
)

type attestationInput struct {
	aaguid              []byte
	attStmt             *cborMap
	authData            []byte
	clientDataHash      []byte
	credentialID        []byte
	credentialPublicKey []byte
	rpIDHash            []byte
	rootCertificates    []string
}

func concatBytes(parts ...[]byte) []byte {
	var out []byte
	for _, part := range parts {
		out = append(out, part...)
	}
	return out
}

// x5cOf reads attStmt.x5c: false when absent (or falsy); an error when it is not an array of byte strings.
func x5cOf(statement *cborMap) ([][]byte, bool, error) {
	if !memberTruthy(statement, "x5c") {
		return nil, false, nil
	}
	value, _ := statement.get("x5c")
	list, ok := value.([]any)
	if !ok {
		return nil, true, errors.New("x5c is not an array")
	}
	out := make([][]byte, len(list))
	for index, item := range list {
		der, ok := item.([]byte)
		if !ok {
			return nil, true, errors.New("x5c entry is not a byte string")
		}
		out[index] = der
	}
	return out, true, nil
}

// coseToPKCS is convertCOSEtoPKCS: 0x04 || x || y (or 0x04 || x).
func coseToPKCS(credentialPublicKey []byte) ([]byte, error) {
	decoded, err := cborDecodeFirst(credentialPublicKey)
	if err != nil {
		return nil, err
	}
	key, ok := decoded.(*cborMap)
	if !ok {
		return nil, errors.New("COSE public key is not a map")
	}
	x, y := bytesMember(key, -2.0), bytesMember(key, -3.0)
	if x == nil {
		return nil, errors.New("COSE public key was missing x")
	}
	if y != nil {
		return concatBytes([]byte{4}, x, y), nil
	}
	return concatBytes([]byte{4}, x), nil
}

// subjectPublicKeyBits is tbsCertificate.subjectPublicKeyInfo.subjectPublicKey: the BIT STRING's bytes.
func subjectPublicKeyBits(certificate *x509.Certificate) []byte {
	input := cryptobyte.String(certificate.RawSubjectPublicKeyInfo)
	var spki, algorithm cryptobyte.String
	if !input.ReadASN1(&spki, cbasn1.SEQUENCE) || !spki.ReadASN1(&algorithm, cbasn1.SEQUENCE) {
		return nil
	}
	var raw cryptobyte.String
	if !spki.ReadASN1(&raw, cbasn1.BIT_STRING) || len(raw) == 0 {
		return nil
	}
	return []byte(raw[1:])
}

// certificateInfo is getCertificateInfo.
type certificateInfo struct {
	subject             map[string]string
	combined            string
	version             int // ASN.1 value: 2 for v3
	basicConstraintsCA  bool
	notBefore, notAfter time.Time
	certificate         *x509.Certificate
}

var subjectKeys = map[string]string{"2.5.4.6": "C", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.3": "CN"}

// attributeString is AttributeValue#toString for the string types.
func attributeString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case []byte:
		return string(v)
	}
	return fmt.Sprint(value)
}

func nameAttributes(raw []byte) (map[string]string, error) {
	var sequence pkix.RDNSequence
	if rest, err := asn1.Unmarshal(raw, &sequence); err != nil || len(rest) > 0 {
		return nil, errors.New("invalid name")
	}
	out := map[string]string{}
	for _, rdn := range sequence {
		if len(rdn) == 0 {
			continue
		}
		// Only the first attribute of each relative distinguished name is read.
		if key, ok := subjectKeys[rdn[0].Type.String()]; ok {
			out[key] = attributeString(rdn[0].Value)
		}
	}
	return out, nil
}

func getCertificateInfo(der []byte) (*certificateInfo, error) {
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	subject, err := nameAttributes(certificate.RawSubject)
	if err != nil {
		return nil, err
	}
	var parts []string
	for _, key := range []string{"C", "O", "OU", "CN"} {
		if subject[key] != "" {
			parts = append(parts, subject[key])
		}
	}
	return &certificateInfo{
		subject:            subject,
		combined:           strings.Join(parts, " : "),
		version:            certificate.Version - 1,
		basicConstraintsCA: certificate.BasicConstraintsValid && certificate.IsCA,
		notBefore:          certificate.NotBefore,
		notAfter:           certificate.NotAfter,
		certificate:        certificate,
	}, nil
}

func extensionValue(certificate *x509.Certificate, oid string) ([]byte, bool) {
	for _, extension := range certificate.Extensions {
		if extension.Id.String() == oid {
			return extension.Value, true
		}
	}
	return nil, false
}

// validateExtFIDOGenCEAAGUID compares the id-fido-gen-ce-aaguid extension, when present, with the AAGUID.
func validateExtFIDOGenCEAAGUID(certificate *x509.Certificate, aaguid []byte) error {
	value, ok := extensionValue(certificate, "1.3.6.1.4.1.45724.1.1.4")
	if !ok {
		return nil
	}
	var inner []byte
	if _, err := asn1.Unmarshal(value, &inner); err != nil {
		return err
	}
	if !bytes.Equal(inner, aaguid) {
		return fmt.Errorf("Certificate extension id-fido-gen-ce-aaguid value of %q was present but not equal to attestation statement AAGUID value of %q",
			hex.EncodeToString(inner), hex.EncodeToString(aaguid))
	}
	return nil
}

func withinValidity(certificate *x509.Certificate) bool {
	now := time.Now()
	return !certificate.NotBefore.After(now) && !certificate.NotAfter.Before(now)
}

// --- revocation ----------------------------------------------------------------------------------------------------

type revocationEntry struct {
	serials    []*big.Int
	nextUpdate time.Time
}

var revocationCache = struct {
	sync.Mutex
	entries map[string]revocationEntry
}{entries: map[string]revocationEntry{}}

// crlClient fetches CRLs for the revocation check (the library uses the global fetch).
var crlClient = &http.Client{Timeout: 30 * time.Second}

func crlURL(certificate *x509.Certificate) string {
	value, ok := extensionValue(certificate, "2.5.29.31")
	if !ok {
		return ""
	}
	// CRLDistributionPoints ::= SEQUENCE OF DistributionPoint; the first point's first fullName URI.
	input := cryptobyte.String(value)
	var points, point cryptobyte.String
	if !input.ReadASN1(&points, cbasn1.SEQUENCE) || !points.ReadASN1(&point, cbasn1.SEQUENCE) {
		return ""
	}
	var name cryptobyte.String
	var present bool
	if !point.ReadOptionalASN1(&name, &present, cbasn1.Tag(0).ContextSpecific().Constructed()) || !present {
		return ""
	}
	var fullName cryptobyte.String
	if !name.ReadOptionalASN1(&fullName, &present, cbasn1.Tag(0).ContextSpecific().Constructed()) || !present {
		return ""
	}
	var uri cryptobyte.String
	if !fullName.ReadOptionalASN1(&uri, &present, cbasn1.Tag(6).ContextSpecific()) || !present {
		return ""
	}
	return string(uri)
}

// isCertRevoked downloads (and caches until nextUpdate) the CRL a certificate names; any failure reads as not
// revoked, as in the library.
func isCertRevoked(certificate *x509.Certificate) bool {
	if len(certificate.Extensions) == 0 {
		return false
	}
	keyIdentifier := ""
	if len(certificate.AuthorityKeyId) > 0 {
		keyIdentifier = hex.EncodeToString(certificate.AuthorityKeyId)
	} else if len(certificate.SubjectKeyId) > 0 {
		keyIdentifier = hex.EncodeToString(certificate.SubjectKeyId)
	}
	contains := func(entry revocationEntry) bool {
		for _, serial := range entry.serials {
			if serial.Cmp(certificate.SerialNumber) == 0 {
				return true
			}
		}
		return false
	}
	if keyIdentifier != "" {
		revocationCache.Lock()
		cached, ok := revocationCache.entries[keyIdentifier]
		revocationCache.Unlock()
		if ok && (cached.nextUpdate.IsZero() || cached.nextUpdate.After(time.Now())) {
			return contains(cached)
		}
	}
	address := crlURL(certificate)
	if address == "" {
		return false
	}
	response, err := crlClient.Get(address)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 32<<20))
	if err != nil {
		return false
	}
	if block, _ := pem.Decode(body); block != nil {
		body = block.Bytes
	}
	list, err := x509.ParseRevocationList(body)
	if err != nil {
		return false
	}
	entry := revocationEntry{nextUpdate: list.NextUpdate}
	for _, revoked := range list.RevokedCertificateEntries {
		entry.serials = append(entry.serials, revoked.SerialNumber)
	}
	if keyIdentifier != "" {
		revocationCache.Lock()
		revocationCache.entries[keyIdentifier] = entry
		revocationCache.Unlock()
	}
	return contains(entry)
}

// --- certificate paths ---------------------------------------------------------------------------------------------

// pemOf is convertCertBufferToPEM.
func pemOf(der []byte) string {
	b64 := base64.StdEncoding.EncodeToString(der)
	var out strings.Builder
	out.WriteString("-----BEGIN CERTIFICATE-----\n")
	for start := 0; start < len(b64); start += 64 {
		out.WriteString(b64[start:min(len(b64), start+64)] + "\n")
	}
	out.WriteString("-----END CERTIFICATE-----\n")
	return out.String()
}

func parsePEMCertificate(text string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(text))
	if block == nil {
		return nil, errors.New("Could not parse trust anchor certificate")
	}
	return x509.ParseCertificate(block.Bytes)
}

// checkCertificateSignature verifies child's signature with parent's key (signature only, no CA constraints), as
// the chain builder does.
func checkCertificateSignature(child, parent *x509.Certificate) bool {
	algorithm := child.SignatureAlgorithm
	hash := crypto.SHA256
	switch algorithm {
	case x509.SHA1WithRSA, x509.ECDSAWithSHA1:
		hash = crypto.SHA1
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384, x509.SHA384WithRSAPSS:
		hash = crypto.SHA384
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512, x509.SHA512WithRSAPSS:
		hash = crypto.SHA512
	}
	switch key := parent.PublicKey.(type) {
	case *rsa.PublicKey:
		hashed := digest(hash, child.RawTBSCertificate)
		switch algorithm {
		case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
			return rsa.VerifyPSS(key, hash, hashed, child.Signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}) == nil
		case x509.SHA1WithRSA, x509.SHA256WithRSA, x509.SHA384WithRSA, x509.SHA512WithRSA:
			return rsa.VerifyPKCS1v15(key, hash, hashed, child.Signature) == nil
		}
	case *ecdsa.PublicKey:
		switch algorithm {
		case x509.ECDSAWithSHA1, x509.ECDSAWithSHA256, x509.ECDSAWithSHA384, x509.ECDSAWithSHA512:
			return ecdsa.VerifyASN1(key, digest(hash, child.RawTBSCertificate), child.Signature)
		}
	case ed25519.PublicKey:
		return algorithm == x509.PureEd25519 && ed25519.Verify(key, child.RawTBSCertificate, child.Signature)
	}
	return false
}

func selfSigned(certificate *x509.Certificate) bool {
	return bytes.Equal(certificate.RawSubject, certificate.RawIssuer) && checkCertificateSignature(certificate, certificate)
}

// buildChain is @peculiar/x509's X509ChainBuilder#build: from the leaf, repeatedly the first pool certificate whose
// subject is the current issuer, whose key identifier agrees with the authority key identifier, and whose key
// verifies the current signature, until a self-signed certificate or a repeat.
func buildChain(leaf *x509.Certificate, pool []*x509.Certificate) []*x509.Certificate {
	chain := []*x509.Certificate{leaf}
	current := leaf
	for {
		if selfSigned(current) {
			return chain
		}
		var issuer *x509.Certificate
		for _, candidate := range pool {
			if !bytes.Equal(candidate.RawSubject, current.RawIssuer) {
				continue
			}
			if len(current.AuthorityKeyId) > 0 && len(candidate.SubjectKeyId) > 0 && !bytes.Equal(candidate.SubjectKeyId, current.AuthorityKeyId) {
				continue
			}
			if !checkCertificateSignature(current, candidate) {
				continue
			}
			issuer = candidate
			break
		}
		if issuer == nil {
			return chain
		}
		for _, seen := range chain {
			if bytes.Equal(seen.Raw, issuer.Raw) {
				return chain
			}
		}
		chain = append(chain, issuer)
		current = issuer
	}
}

// validateCertificatePath chains x5c to one of the trust anchors (PEM). With no anchors there is nothing to chain
// to, and the path is accepted.
func validateCertificatePath(x5c [][]byte, anchorsPEM []string) error {
	if len(anchorsPEM) == 0 {
		return nil
	}
	certificates := make([]*x509.Certificate, len(x5c))
	for index, der := range x5c {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		certificates[index] = certificate
	}
	for _, certificate := range certificates {
		if isCertRevoked(certificate) {
			return errors.New("Found revoked certificate in x5c")
		}
		if !withinValidity(certificate) {
			return errors.New("Found certificate out of validity period in x5c")
		}
	}
	var anchors []*x509.Certificate
	for _, text := range anchorsPEM {
		anchor, err := parsePEMCertificate(text)
		if err != nil {
			return errors.New("Could not parse trust anchor certificate")
		}
		if isCertRevoked(anchor) || !withinValidity(anchor) {
			continue
		}
		anchors = append(anchors, anchor)
	}
	if len(anchors) == 0 {
		return errors.New("No specified trust anchor was valid for verifying x5c")
	}
	for _, anchor := range anchors {
		all := append(append([]*x509.Certificate(nil), certificates...), anchor)
		unique := map[string]bool{}
		for _, certificate := range all {
			unique[string(certificate.Raw)] = true
		}
		if len(unique) != len(all) {
			return errors.New("Unexpected error while validating certificate path")
		}
		if len(certificates) == 0 {
			return errors.New("Unexpected error while validating certificate path")
		}
		chain := buildChain(certificates[0], append(append([]*x509.Certificate(nil), certificates[1:]...), anchor))
		if len(chain) < len(unique) {
			continue
		}
		if !bytes.Equal(chain[len(chain)-1].RawSubject, anchor.RawSubject) {
			continue
		}
		return nil
	}
	return errors.New("x5c could not be chained to any specified trust anchor")
}

// --- formats -------------------------------------------------------------------------------------------------------

func verifyAttestationPacked(input attestationInput) (bool, error) {
	sig := bytesMember(input.attStmt, "sig")
	alg, _ := input.attStmt.get("alg")
	x5c, hasX5c, err := x5cOf(input.attStmt)
	if !memberTruthy(input.attStmt, "sig") {
		return false, errors.New("No attestation signature provided in attestation statement (Packed)")
	}
	if !memberTruthy(input.attStmt, "alg") {
		return false, errors.New("Attestation statement did not contain alg (Packed)")
	}
	if !isCOSEAlg(alg) {
		return false, fmt.Errorf("Attestation statement contained invalid alg %v (Packed)", alg)
	}
	if err != nil {
		return false, err
	}
	signatureBase := concatBytes(input.authData, input.clientDataHash)
	if hasX5c {
		if len(x5c) == 0 {
			return false, errors.New("No certificate in x5c (Packed|Full)")
		}
		info, err := getCertificateInfo(x5c[0])
		if err != nil {
			return false, err
		}
		subject := info.subject
		switch {
		case subject["OU"] != "Authenticator Attestation":
			return false, errors.New(`Certificate OU was not "Authenticator Attestation" (Packed|Full)`)
		case subject["CN"] == "":
			return false, errors.New("Certificate CN was empty (Packed|Full)")
		case subject["O"] == "":
			return false, errors.New("Certificate O was empty (Packed|Full)")
		case core.UTF16Len(subject["C"]) != 2:
			return false, errors.New("Certificate C was not two-character ISO 3166 code (Packed|Full)")
		case info.basicConstraintsCA:
			return false, errors.New("Certificate basic constraints CA was not `false` (Packed|Full)")
		case info.version != 2:
			return false, errors.New("Certificate version was not `3` (ASN.1 value of 2) (Packed|Full)")
		case info.notBefore.After(time.Now()):
			return false, errors.New("Certificate not good before (Packed|Full)")
		case info.notAfter.Before(time.Now()):
			return false, errors.New("Certificate not good after (Packed|Full)")
		}
		if err := validateExtFIDOGenCEAAGUID(info.certificate, input.aaguid); err != nil {
			return false, fmt.Errorf("%v (Packed|Full)", err)
		}
		if err := validateCertificatePath(x5c, nil); err != nil {
			return false, err
		}
		return verifyWithCertificate(x5c[0], sig, signatureBase, alg)
	}
	decoded, err := cborDecodeFirst(input.credentialPublicKey)
	if err != nil {
		return false, err
	}
	key, ok := decoded.(*cborMap)
	if !ok {
		return false, errors.New("Credential public key is not a map")
	}
	return verifyCOSE(key, sig, signatureBase, alg)
}

func verifyAttestationFIDOU2F(input attestationInput) (bool, error) {
	publicKey, err := coseToPKCS(input.credentialPublicKey)
	if err != nil {
		return false, err
	}
	signatureBase := concatBytes([]byte{0}, input.rpIDHash, input.clientDataHash, input.credentialID, publicKey)
	sig := bytesMember(input.attStmt, "sig")
	x5c, hasX5c, err := x5cOf(input.attStmt)
	if !hasX5c {
		return false, errors.New("No attestation certificate provided in attestation statement (FIDOU2F)")
	}
	if !memberTruthy(input.attStmt, "sig") {
		return false, errors.New("No attestation signature provided in attestation statement (FIDOU2F)")
	}
	aaguidHex := hex.EncodeToString(input.aaguid)
	if aaguidHex == "" || strings.Trim(aaguidHex, "0") != "" {
		return false, errors.New("AAGUID was not expected value")
	}
	if err != nil {
		return false, err
	}
	if err := validateCertificatePath(x5c, nil); err != nil {
		return false, err
	}
	if len(x5c) == 0 {
		return false, errors.New("No certificate in x5c (FIDOU2F)")
	}
	return verifyWithCertificate(x5c[0], sig, signatureBase, float64(coseES256))
}

func verifyAttestationApple(input attestationInput) (bool, error) {
	x5c, hasX5c, err := x5cOf(input.attStmt)
	if !hasX5c {
		return false, errors.New("No attestation certificate provided in attestation statement (Apple)")
	}
	if err != nil {
		return false, err
	}
	if err := validateCertificatePath(x5c, input.rootCertificates); err != nil {
		return false, fmt.Errorf("%v (Apple)", err)
	}
	if len(x5c) == 0 {
		return false, errors.New("No certificate in x5c (Apple)")
	}
	certificate, err := x509.ParseCertificate(x5c[0])
	if err != nil {
		return false, err
	}
	if len(certificate.Extensions) == 0 {
		return false, errors.New("credCert missing extensions (Apple)")
	}
	value, ok := extensionValue(certificate, "1.2.840.113635.100.8.2")
	if !ok {
		return false, errors.New(`credCert missing "1.2.840.113635.100.8.2" extension (Apple)`)
	}
	nonce := sha256.Sum256(concatBytes(input.authData, input.clientDataHash))
	var extNonce []byte
	if len(value) > 6 {
		extNonce = value[6:]
	}
	if !bytes.Equal(nonce[:], extNonce) {
		return false, errors.New("credCert nonce was not expected value (Apple)")
	}
	credential, err := coseToPKCS(input.credentialPublicKey)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(credential, subjectPublicKeyBits(certificate)) {
		return false, errors.New("Credential public key does not equal credCert public key (Apple)")
	}
	return true, nil
}

// androidKeyDescription is the Android Key Attestation extension (KeyDescription), as far as the check reads it.
type androidKeyDescription struct {
	AttestationVersion       int
	AttestationSecurityLevel asn1.Enumerated
	KeymasterVersion         int
	KeymasterSecurityLevel   asn1.Enumerated
	AttestationChallenge     []byte
	UniqueID                 []byte
	SoftwareEnforced         asn1.RawValue
	TeeEnforced              asn1.RawValue
}

// androidAllApplications reports whether an AuthorizationList holds the allApplications [600] tag.
func androidAllApplications(list asn1.RawValue) bool {
	rest := list.Bytes
	for len(rest) > 0 {
		var element asn1.RawValue
		next, err := asn1.Unmarshal(rest, &element)
		if err != nil {
			return false
		}
		if element.Class == asn1.ClassContextSpecific && element.Tag == 600 {
			return true
		}
		rest = next
	}
	return false
}

func verifyAttestationAndroidKey(input attestationInput) (bool, error) {
	x5c, hasX5c, err := x5cOf(input.attStmt)
	sig := bytesMember(input.attStmt, "sig")
	alg, _ := input.attStmt.get("alg")
	if !hasX5c {
		return false, errors.New("No attestation certificate provided in attestation statement (Android Key)")
	}
	if !memberTruthy(input.attStmt, "sig") {
		return false, errors.New("No attestation signature provided in attestation statement (Android Key)")
	}
	if !memberTruthy(input.attStmt, "alg") {
		return false, errors.New("Attestation statement did not contain alg (Android Key)")
	}
	if !isCOSEAlg(alg) {
		return false, fmt.Errorf("Attestation statement contained invalid alg %v (Android Key)", alg)
	}
	if err != nil {
		return false, err
	}
	if len(x5c) == 0 {
		return false, errors.New("No certificate in x5c (Android Key)")
	}
	certificate, err := x509.ParseCertificate(x5c[0])
	if err != nil {
		return false, err
	}
	credential, err := coseToPKCS(input.credentialPublicKey)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(credential, subjectPublicKeyBits(certificate)) {
		return false, errors.New("Credential public key does not equal leaf cert public key (Android Key)")
	}
	value, ok := extensionValue(certificate, "1.3.6.1.4.1.11129.2.1.17")
	if !ok {
		return false, errors.New("Certificate did not contain extKeyStore (Android Key)")
	}
	var description androidKeyDescription
	if _, err := asn1.Unmarshal(value, &description); err != nil {
		return false, errors.New("Invalid key description (Android Key)")
	}
	if !bytes.Equal(description.AttestationChallenge, input.clientDataHash) {
		return false, errors.New("Attestation challenge was not equal to client data hash (Android Key)")
	}
	if androidAllApplications(description.TeeEnforced) || androidAllApplications(description.SoftwareEnforced) {
		return false, errors.New(`teeEnforced contained "allApplications [600]" tag (Android Key)`)
	}
	if err := validateCertificatePath(x5c[:len(x5c)-1], []string{pemOf(x5c[len(x5c)-1])}); err != nil {
		return false, fmt.Errorf("%v (Android Key)", err)
	}
	if len(input.rootCertificates) > 0 {
		root := pemOf(x5c[len(x5c)-1])
		known := false
		for _, candidate := range input.rootCertificates {
			if candidate == root {
				known = true
			}
		}
		if !known {
			return false, errors.New("x5c root certificate was not a known root certificate (Android Key)")
		}
	}
	return verifyWithCertificate(x5c[0], sig, concatBytes(input.authData, input.clientDataHash), alg)
}

func verifyAttestationAndroidSafetyNet(input attestationInput) (bool, error) {
	alg, _ := input.attStmt.get("alg")
	if !memberTruthy(input.attStmt, "ver") {
		return false, errors.New("No ver value in attestation (SafetyNet)")
	}
	if !memberTruthy(input.attStmt, "response") {
		return false, errors.New("No response was included in attStmt by authenticator (SafetyNet)")
	}
	response := bytesMember(input.attStmt, "response")
	if response == nil {
		return false, errors.New("response is not a byte string (SafetyNet)")
	}
	parts := strings.Split(decodeUTF8(response), ".")
	part := func(i int) string {
		if i < len(parts) {
			return parts[i]
		}
		return ""
	}
	parse := func(text string) (*core.Object, error) {
		parsed, err := core.ParseJSONString(decodeUTF8(hexagonDecode(text, true)))
		if err != nil {
			return nil, err
		}
		object, _ := parsed.(*core.Object)
		if object == nil {
			return core.NewObject(), nil
		}
		return object, nil
	}
	header, err := parse(part(0))
	if err != nil {
		return false, err
	}
	payload, err := parse(part(1))
	if err != nil {
		return false, err
	}
	timestamp := math.NaN()
	if value, ok := payload.Get("timestampMs").(float64); ok {
		timestamp = value
	}
	now := float64(time.Now().UnixMilli())
	if timestamp > now {
		return false, errors.New("Payload timestamp was later than now (SafetyNet)")
	}
	if timestamp+60*1000 < float64(time.Now().UnixMilli()) {
		return false, errors.New("Payload timestamp has expired (SafetyNet)")
	}
	nonce := sha256.Sum256(concatBytes(input.authData, input.clientDataHash))
	if !core.StrictEquals(payload.Get("nonce"), base64.StdEncoding.EncodeToString(nonce[:])) {
		return false, errors.New("Could not verify payload nonce (SafetyNet)")
	}
	if !truthy(payload.Get("ctsProfileMatch")) {
		return false, errors.New("Could not verify device integrity (SafetyNet)")
	}
	chainValue, ok := header.Get("x5c").([]any)
	if !ok || len(chainValue) == 0 {
		return false, errors.New("Header x5c is missing (SafetyNet)")
	}
	chain := make([][]byte, len(chainValue))
	for index, item := range chainValue {
		text, ok := item.(string)
		if !ok {
			return false, errors.New("Certificate is not a valid base64 or base64url string")
		}
		if isBase64URL(text) {
			chain[index] = hexagonDecode(text, true)
		} else {
			chain[index] = hexagonDecode(text, false)
		}
	}
	leaf := hexagonDecode(chainValue[0].(string), false)
	info, err := getCertificateInfo(leaf)
	if err != nil {
		return false, err
	}
	if info.subject["CN"] != "attest.android.com" {
		return false, errors.New(`Certificate common name was not "attest.android.com" (SafetyNet)`)
	}
	if err := validateCertificatePath(chain, input.rootCertificates); err != nil {
		return false, fmt.Errorf("%v (SafetyNet)", err)
	}
	signature := hexagonDecode(part(2), true)
	var override any
	if alg != nil && !isUndefinedCBOR(alg) {
		override = alg
	}
	return verifyWithCertificate(leaf, signature, utf8Bytes(part(0)+"."+part(1)), override)
}

func isUndefinedCBOR(value any) bool {
	_, ok := value.(cborUndefined)
	return ok
}

// --- tpm -------------------------------------------------------------------------------------------------------------

var tpmAlgorithms = map[uint16]string{
	0x0000: "TPM_ALG_ERROR", 0x0001: "TPM_ALG_RSA", 0x0004: "TPM_ALG_SHA1", 0x0005: "TPM_ALG_HMAC", 0x0006: "TPM_ALG_AES",
	0x0007: "TPM_ALG_MGF1", 0x0008: "TPM_ALG_KEYEDHASH", 0x000a: "TPM_ALG_XOR", 0x000b: "TPM_ALG_SHA256",
	0x000c: "TPM_ALG_SHA384", 0x000d: "TPM_ALG_SHA512", 0x0010: "TPM_ALG_NULL", 0x0012: "TPM_ALG_SM3_256",
	0x0013: "TPM_ALG_SM4", 0x0014: "TPM_ALG_RSASSA", 0x0015: "TPM_ALG_RSAES", 0x0016: "TPM_ALG_RSAPSS",
	0x0017: "TPM_ALG_OAEP", 0x0018: "TPM_ALG_ECDSA", 0x0019: "TPM_ALG_ECDH", 0x001a: "TPM_ALG_ECDAA",
	0x001b: "TPM_ALG_SM2", 0x001c: "TPM_ALG_ECSCHNORR", 0x001d: "TPM_ALG_ECMQV", 0x0020: "TPM_ALG_KDF1_SP800_56A",
	0x0021: "TPM_ALG_KDF2", 0x0022: "TPM_ALG_KDF1_SP800_108", 0x0023: "TPM_ALG_ECC", 0x0025: "TPM_ALG_SYMCIPHER",
	0x0026: "TPM_ALG_CAMELLIA", 0x0040: "TPM_ALG_CTR", 0x0041: "TPM_ALG_OFB", 0x0042: "TPM_ALG_CBC",
	0x0043: "TPM_ALG_CFB", 0x0044: "TPM_ALG_ECB",
}

var tpmCurves = map[uint16]string{
	0x0000: "TPM_ECC_NONE", 0x0001: "TPM_ECC_NIST_P192", 0x0002: "TPM_ECC_NIST_P224", 0x0003: "TPM_ECC_NIST_P256",
	0x0004: "TPM_ECC_NIST_P384", 0x0005: "TPM_ECC_NIST_P521", 0x0010: "TPM_ECC_BN_P256", 0x0011: "TPM_ECC_BN_P638",
	0x0020: "TPM_ECC_SM2_P256",
}

var tpmCurveCOSE = map[string]float64{
	"TPM_ECC_NIST_P256": 1, "TPM_ECC_NIST_P384": 2, "TPM_ECC_NIST_P521": 3, "TPM_ECC_BN_P256": 1, "TPM_ECC_SM2_P256": 1,
}

var tpmManufacturers = map[string]bool{
	"id:414D4400": true, "id:414E5400": true, "id:41544D4C": true, "id:4252434D": true, "id:4353434F": true,
	"id:464C5953": true, "id:524F4343": true, "id:474F4F47": true, "id:48504900": true, "id:48504500": true,
	"id:48495349": true, "id:49424d00": true, "id:49424D00": true, "id:49465800": true, "id:494E5443": true,
	"id:4C454E00": true, "id:4D534654": true, "id:4E534D20": true, "id:4E545A00": true, "id:4E534700": true,
	"id:4E544300": true, "id:51434F4D": true, "id:534D534E": true, "id:53454345": true, "id:534E5300": true,
	"id:534D5343": true, "id:53544D20": true, "id:54584E00": true, "id:57454300": true, "id:5345414C": true,
	"id:FFFFF1D0": true,
}

// tpmReader reads big-endian fields as a DataView does (out of bounds is an error) and slices as Uint8Array#slice
// does (clamped).
type tpmReader struct {
	data    []byte
	pointer int
	err     error
}

func (r *tpmReader) uint16() uint16 {
	if r.err != nil || r.pointer+2 > len(r.data) {
		r.err = errors.New("Offset is outside the bounds of the DataView")
		return 0
	}
	value := binary.BigEndian.Uint16(r.data[r.pointer:])
	r.pointer += 2
	return value
}

func (r *tpmReader) uint32() uint32 {
	if r.err != nil || r.pointer+4 > len(r.data) {
		r.err = errors.New("Offset is outside the bounds of the DataView")
		return 0
	}
	value := binary.BigEndian.Uint32(r.data[r.pointer:])
	r.pointer += 4
	return value
}

func (r *tpmReader) slice(n int) []byte {
	start, end := min(r.pointer, len(r.data)), min(r.pointer+n, len(r.data))
	r.pointer += n
	return append([]byte(nil), r.data[start:end]...)
}

type tpmPubArea struct {
	kind     string
	exponent uint32
	curveID  string
	unique   []byte
}

func parsePubArea(pubArea []byte) (*tpmPubArea, error) {
	r := &tpmReader{data: pubArea}
	area := &tpmPubArea{kind: tpmAlgorithms[r.uint16()]}
	r.uint16() // nameAlg
	r.uint32() // objectAttributes
	authPolicyLength := r.uint16()
	if r.err != nil {
		return nil, r.err
	}
	r.slice(int(authPolicyLength))
	switch area.kind {
	case "TPM_ALG_RSA":
		r.uint16()
		r.uint16()
		r.uint16()
		area.exponent = r.uint32()
		uniqueLength := r.uint16()
		if r.err != nil {
			return nil, r.err
		}
		area.unique = r.slice(int(uniqueLength))
	case "TPM_ALG_ECC":
		r.uint16()
		r.uint16()
		area.curveID = tpmCurves[r.uint16()]
		r.uint16()
		xLength := r.uint16()
		if r.err != nil {
			return nil, r.err
		}
		x := r.slice(int(xLength))
		yLength := r.uint16()
		if r.err != nil {
			return nil, r.err
		}
		area.unique = concatBytes(x, r.slice(int(yLength)))
	default:
		return nil, fmt.Errorf("Unexpected type %q (TPM)", area.kind)
	}
	return area, r.err
}

type tpmCertInfo struct {
	magic         uint32
	kind          string
	extraData     []byte
	nameAlg       string
	nameAlgBuffer []byte
	name          []byte
}

var tpmStructures = map[uint16]string{
	0x00c4: "TPM_ST_RSP_COMMAND", 0x8000: "TPM_ST_NULL", 0x8001: "TPM_ST_NO_SESSIONS", 0x8002: "TPM_ST_SESSIONS",
	0x8014: "TPM_ST_ATTEST_NV", 0x8015: "TPM_ST_ATTEST_COMMAND_AUDIT", 0x8016: "TPM_ST_ATTEST_SESSION_AUDIT",
	0x8017: "TPM_ST_ATTEST_CERTIFY", 0x8018: "TPM_ST_ATTEST_QUOTE", 0x8019: "TPM_ST_ATTEST_TIME",
	0x801a: "TPM_ST_ATTEST_CREATION", 0x8021: "TPM_ST_CREATION", 0x8022: "TPM_ST_VERIFIED",
	0x8023: "TPM_ST_AUTH_SECRET", 0x8024: "TPM_ST_HASHCHECK", 0x8025: "TPM_ST_AUTH_SIGNED", 0x8029: "TPM_ST_FU_MANIFEST",
}

func parseCertInfo(certInfo []byte) (*tpmCertInfo, error) {
	r := &tpmReader{data: certInfo}
	info := &tpmCertInfo{magic: r.uint32(), kind: tpmStructures[r.uint16()]}
	signerLength := r.uint16()
	if r.err != nil {
		return nil, r.err
	}
	r.slice(int(signerLength))
	extraLength := r.uint16()
	if r.err != nil {
		return nil, r.err
	}
	info.extraData = r.slice(int(extraLength))
	r.slice(8) // clock
	r.uint32() // resetCount
	r.uint32() // restartCount
	r.slice(1) // safe
	r.slice(8) // firmwareVersion
	nameLength := r.uint16()
	if r.err != nil {
		return nil, r.err
	}
	name := r.slice(int(nameLength))
	qualifiedLength := r.uint16()
	if r.err != nil {
		return nil, r.err
	}
	r.slice(int(qualifiedLength))
	if len(name) < 2 {
		return nil, errors.New("Offset is outside the bounds of the DataView")
	}
	info.nameAlg = tpmAlgorithms[binary.BigEndian.Uint16(name)]
	info.nameAlgBuffer = name[:2]
	info.name = name
	return info, nil
}

func tpmNameAlgCOSE(alg string) (any, error) {
	switch alg {
	case "TPM_ALG_SHA256":
		return float64(coseES256), nil
	case "TPM_ALG_SHA384":
		return float64(coseES384), nil
	case "TPM_ALG_SHA512":
		return float64(coseES512), nil
	}
	return nil, fmt.Errorf("Unexpected TPM attested name alg %s", alg)
}

// tpmSubjectAltName reads the TCG attributes from the first general name (it must be a non-empty directoryName).
func tpmSubjectAltName(value []byte) (manufacturer, model, version string, err error) {
	input := cryptobyte.String(value)
	var names cryptobyte.String
	if !input.ReadASN1(&names, cbasn1.SEQUENCE) {
		return "", "", "", errors.New("Invalid subjectAltName (TPM)")
	}
	var first cryptobyte.String
	var tag cbasn1.Tag
	if !names.ReadAnyASN1(&first, &tag) || tag != cbasn1.Tag(4).ContextSpecific().Constructed() {
		return "", "", "", errors.New("Certificate subjectAltName extension directoryName was empty (TPM)")
	}
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(first, &rdns); err != nil || len(rdns) == 0 || len(rdns[0]) == 0 {
		return "", "", "", errors.New("Certificate subjectAltName extension directoryName was empty (TPM)")
	}
	for _, rdn := range rdns {
		for _, attribute := range rdn {
			switch attribute.Type.String() {
			case "2.23.133.2.1":
				manufacturer = attributeString(attribute.Value)
			case "2.23.133.2.2":
				model = attributeString(attribute.Value)
			case "2.23.133.2.3":
				version = attributeString(attribute.Value)
			}
		}
	}
	return manufacturer, model, version, nil
}

func verifyAttestationTPM(input attestationInput) (bool, error) {
	statement := input.attStmt
	ver, _ := statement.get("ver")
	alg, _ := statement.get("alg")
	sig := bytesMember(statement, "sig")
	pubArea := bytesMember(statement, "pubArea")
	certInfo := bytesMember(statement, "certInfo")
	x5c, hasX5c, x5cErr := x5cOf(statement)
	switch {
	case ver != "2.0":
		return false, fmt.Errorf("Unexpected ver %q, expected \"2.0\" (TPM)", ver)
	case !memberTruthy(statement, "sig"):
		return false, errors.New("No attestation signature provided in attestation statement (TPM)")
	case !memberTruthy(statement, "alg"):
		return false, errors.New("Attestation statement did not contain alg (TPM)")
	case !isCOSEAlg(alg):
		return false, fmt.Errorf("Attestation statement contained invalid alg %v (TPM)", alg)
	case !hasX5c:
		return false, errors.New("No attestation certificate provided in attestation statement (TPM)")
	case !memberTruthy(statement, "pubArea"):
		return false, errors.New("Attestation statement did not contain pubArea (TPM)")
	case !memberTruthy(statement, "certInfo"):
		return false, errors.New("Attestation statement did not contain certInfo (TPM)")
	}
	if x5cErr != nil {
		return false, x5cErr
	}
	if pubArea == nil || certInfo == nil {
		return false, errors.New("pubArea and certInfo must be byte strings (TPM)")
	}
	area, err := parsePubArea(pubArea)
	if err != nil {
		return false, err
	}
	decoded, err := cborDecodeFirst(input.credentialPublicKey)
	if err != nil {
		return false, err
	}
	key, ok := decoded.(*cborMap)
	if !ok {
		return false, errors.New("Credential public key is not a map")
	}
	kty, _ := key.get(1.0)
	switch area.kind {
	case "TPM_ALG_RSA":
		if kty != 3.0 {
			return false, fmt.Errorf("Credential public key with kty %v did not match %s", kty, area.kind)
		}
		n, e := bytesMember(key, -1.0), bytesMember(key, -2.0)
		if n == nil {
			return false, errors.New("COSE public key missing n (TPM|RSA)")
		}
		if e == nil {
			return false, errors.New("COSE public key missing e (TPM|RSA)")
		}
		if !bytes.Equal(area.unique, n) {
			return false, errors.New("PubArea unique is not same as credentialPublicKey (TPM|RSA)")
		}
		expected := float64(area.exponent)
		if expected == 0 {
			expected = 65537
		}
		at := func(i int) float64 {
			if i < len(e) {
				return float64(e[i])
			}
			if i == 0 {
				return math.NaN()
			}
			return 0
		}
		if sum := at(0) + at(1)*256 + at(2)*65536; sum != expected {
			return false, fmt.Errorf("Unexpected public key exp %v, expected %v (TPM|RSA)", sum, expected)
		}
	case "TPM_ALG_ECC":
		if kty != 2.0 {
			return false, fmt.Errorf("Credential public key with kty %v did not match %s", kty, area.kind)
		}
		crv, _ := key.get(-1.0)
		x, y := bytesMember(key, -2.0), bytesMember(key, -3.0)
		if !memberTruthy(key, -1.0) {
			return false, errors.New("COSE public key missing crv (TPM|ECC)")
		}
		if x == nil {
			return false, errors.New("COSE public key missing x (TPM|ECC)")
		}
		if y == nil {
			return false, errors.New("COSE public key missing y (TPM|ECC)")
		}
		if !bytes.Equal(area.unique, concatBytes(x, y)) {
			return false, errors.New("PubArea unique is not same as public key x and y (TPM|ECC)")
		}
		mapped, ok := tpmCurveCOSE[area.curveID]
		if !ok || !core.StrictEquals(mapped, crv) {
			return false, fmt.Errorf("Public area key curve ID %q did not match public key crv of %v (TPM|ECC)", area.curveID, crv)
		}
	}
	info, err := parseCertInfo(certInfo)
	if err != nil {
		return false, err
	}
	if info.magic != 0xff544347 {
		return false, fmt.Errorf("Unexpected magic value \"%d\", expected \"0xff544347\" (TPM)", info.magic)
	}
	if info.kind != "TPM_ST_ATTEST_CERTIFY" {
		return false, fmt.Errorf("Unexpected type %q, expected \"TPM_ST_ATTEST_CERTIFY\" (TPM)", info.kind)
	}
	nameAlg, err := tpmNameAlgCOSE(info.nameAlg)
	if err != nil {
		return false, err
	}
	pubAreaHash, err := toHash(pubArea, nameAlg)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(info.name, concatBytes(info.nameAlgBuffer, pubAreaHash)) {
		return false, errors.New("Attested name comparison failed (TPM)")
	}
	signedHash, err := toHash(concatBytes(input.authData, input.clientDataHash), alg)
	if err != nil {
		return false, err
	}
	if !bytes.Equal(info.extraData, signedHash) {
		return false, errors.New("CertInfo extra data did not equal hashed attestation (TPM)")
	}
	if len(x5c) < 1 {
		return false, errors.New("No certificates present in x5c array (TPM)")
	}
	leaf, err := getCertificateInfo(x5c[0])
	if err != nil {
		return false, err
	}
	switch {
	case leaf.basicConstraintsCA:
		return false, errors.New("Certificate basic constraints CA was not `false` (TPM)")
	case leaf.version != 2:
		return false, errors.New("Certificate version was not `3` (ASN.1 value of 2) (TPM)")
	case leaf.combined != "":
		return false, errors.New("Certificate subject was not empty (TPM)")
	case leaf.notBefore.After(time.Now()):
		return false, errors.New("Certificate not good before (TPM)")
	case leaf.notAfter.Before(time.Now()):
		return false, errors.New("Certificate not good after (TPM)")
	}
	certificate := leaf.certificate
	if len(certificate.Extensions) == 0 {
		return false, errors.New("Certificate was missing extensions (TPM)")
	}
	altNames, hasAltNames := extensionValue(certificate, "2.5.29.17")
	if !hasAltNames {
		return false, errors.New("Certificate did not contain subjectAltName extension (TPM)")
	}
	manufacturer, model, version, err := tpmSubjectAltName(altNames)
	if err != nil {
		return false, err
	}
	if manufacturer == "" || model == "" || version == "" {
		return false, errors.New("Certificate contained incomplete subjectAltName data (TPM)")
	}
	usage, hasUsage := extensionValue(certificate, "2.5.29.37")
	if !hasUsage {
		return false, errors.New("Certificate did not contain ExtendedKeyUsage extension (TPM)")
	}
	if !tpmManufacturers[manufacturer] {
		return false, fmt.Errorf("Could not match TPM manufacturer %q (TPM)", manufacturer)
	}
	var usages []asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(usage, &usages); err != nil {
		return false, err
	}
	if len(usages) == 0 || usages[0].String() != "2.23.133.8.3" {
		return false, errors.New(`Unexpected extKeyUsage, expected "2.23.133.8.3" (TPM)`)
	}
	if err := validateExtFIDOGenCEAAGUID(certificate, input.aaguid); err != nil {
		return false, fmt.Errorf("%v (TPM)", err)
	}
	if err := validateCertificatePath(x5c, nil); err != nil {
		return false, err
	}
	return verifyWithCertificate(x5c[0], sig, certInfo, alg)
}
