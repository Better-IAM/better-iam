package saml

// XML signatures: node-saml's getVerifiedXml (signature wrapping defenses: exactly one enveloped signature as a
// direct child of the node, a unique referenced ID that is the signature's parent) over xml-crypto's SignedXml
// (loadSignature, checkSignature: every reference digest, then the SignedInfo signature with a trusted certificate),
// and SignedXml#computeSignature for the signatures this package creates (signed SP metadata).

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"hash"
	"regexp"
	"strings"
)

const (
	algRsaSha1   = "http://www.w3.org/2000/09/xmldsig#rsa-sha1"
	algRsaSha256 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
	algRsaSha512 = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512"
	algSha1      = "http://www.w3.org/2000/09/xmldsig#sha1"
	algSha256    = "http://www.w3.org/2001/04/xmlenc#sha256"
	algSha512    = "http://www.w3.org/2001/04/xmlenc#sha512"
)

func hashFor(name string) (crypto.Hash, func() hash.Hash, bool) {
	switch name {
	case algSha1:
		return crypto.SHA1, sha1.New, true
	case algSha256:
		return crypto.SHA256, sha256.New, true
	case algSha512:
		return crypto.SHA512, sha512.New, true
	}
	return 0, nil, false
}

func signatureHash(name string) (crypto.Hash, bool) {
	switch name {
	case algRsaSha1:
		return crypto.SHA1, true
	case algRsaSha256:
		return crypto.SHA256, true
	case algRsaSha512:
		return crypto.SHA512, true
	}
	return 0, false
}

// nodeBase64 is Buffer.from(value, 'base64'): characters outside the alphabet are skipped, decoding stops at the
// first padding character, and a dangling sextet is dropped.
func nodeBase64(value string) []byte {
	var clean []byte
	for i := 0; i < len(value); i++ {
		c := value[i]
		switch {
		case c >= 'A' && c <= 'Z', c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '+', c == '/':
			clean = append(clean, c)
		case c == '-':
			clean = append(clean, '+')
		case c == '_':
			clean = append(clean, '/')
		case c == '=':
			i = len(value)
		}
	}
	if len(clean)%4 == 1 {
		clean = clean[:len(clean)-1]
	}
	decoded, _ := base64.RawStdEncoding.DecodeString(string(clean))
	return decoded
}

var pemFormat = regexp.MustCompile(`(?s)^(-----BEGIN [A-Z ]{1,48}-----(\r\n|\r|\n){1}.*(\r\n|\r|\n){1}-----END [A-Z ]{1,48}-----(\r\n|\r|\n)?)$`)
var base64Format = regexp.MustCompile(`(?s)^(?:[A-Za-z0-9+/]{4}\n?)*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$`)

// normalizePemFile is node-saml's normalizePemFile.
func normalizePemFile(value string) string {
	value = strings.TrimSpace(value)
	value = strings.ReplaceAll(strings.ReplaceAll(value, "\r\n", "\n"), "\r", "\n")
	var lines []string
	for _, line := range strings.Split(value, "\n") {
		for len(line) > 64 {
			lines = append(lines, line[:64])
			line = line[64:]
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	return strings.Join(lines, "\n") + "\n"
}

// keyInfoToPem is node-saml's keyInfoToPem: a PEM is normalized, bare base64 wrapped in the label.
func keyInfoToPem(value, label, option string) (string, error) {
	if value == "" {
		return "", errors.New(option + " is not provided")
	}
	if pemFormat.MatchString(value) {
		return normalizePemFile(value), nil
	}
	if !base64Format.MatchString(value) {
		return "", errors.New(option + " is not in PEM format or in base64 format")
	}
	return normalizePemFile("-----BEGIN " + label + "-----\n" + value + "\n-----END " + label + "-----"), nil
}

// publicKeyOf reads the public key of a PEM certificate (or public key), as Node's crypto.verify accepts it.
func publicKeyOf(pemText string) (crypto.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemText))
	if block == nil {
		return nil, errors.New("Invalid PEM")
	}
	switch block.Type {
	case "CERTIFICATE":
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		return certificate.PublicKey, nil
	case "PUBLIC KEY":
		return x509.ParsePKIXPublicKey(block.Bytes)
	case "RSA PUBLIC KEY":
		return x509.ParsePKCS1PublicKey(block.Bytes)
	}
	signer, err := parsePrivateKey(pemText)
	if err != nil {
		return nil, err
	}
	return signer.Public(), nil
}

// parsePrivateKey reads a PEM (PKCS #8, PKCS #1 or SEC 1) private key, or bare base64 PKCS #8 DER.
func parsePrivateKey(value string) (crypto.Signer, error) {
	der := []byte(nil)
	if block, _ := pem.Decode([]byte(value)); block != nil {
		der = block.Bytes
		switch block.Type {
		case "RSA PRIVATE KEY":
			return x509.ParsePKCS1PrivateKey(der)
		case "EC PRIVATE KEY":
			return x509.ParseECPrivateKey(der)
		}
	} else {
		der = nodeBase64(value)
	}
	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("Unsupported private key")
	}
	return signer, nil
}

// signBytes is crypto.createSign(<hash>).sign(key): PKCS #1 v1.5 for RSA keys, DER ECDSA for EC keys.
func signBytes(key crypto.Signer, h crypto.Hash, data []byte) ([]byte, error) {
	digest := h.New()
	digest.Write(data)
	return key.Sign(rand.Reader, digest.Sum(nil), h)
}

// verifyBytes is crypto.createVerify(<hash>).verify(key, signature).
func verifyBytes(key crypto.PublicKey, h crypto.Hash, data, signature []byte) bool {
	digest := h.New()
	digest.Write(data)
	sum := digest.Sum(nil)
	switch public := key.(type) {
	case *rsa.PublicKey:
		return rsa.VerifyPKCS1v15(public, h, sum, signature) == nil
	case *ecdsa.PublicKey:
		return ecdsa.VerifyASN1(public, sum, signature)
	}
	return false
}

func digestOf(name, canon string) (string, error) {
	_, newHash, ok := hashFor(name)
	if !ok {
		return "", errors.New("hash algorithm '" + name + "' is not supported")
	}
	h := newHash()
	h.Write([]byte(canon))
	return base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

// reference is an xml-crypto Reference.
type reference struct {
	transforms        []string
	digestAlgorithm   string
	uri               *string
	digestValue       string
	inclusivePrefixes []string
	signedReference   string
}

// signedXML is the verification half of xml-crypto's SignedXml.
type signedXML struct {
	publicCert             string
	signatureNode          *Node
	canonicalization       string
	hasCanonicalization    bool
	signatureAlgorithm     string
	signatureValue         string
	references             []*reference
	signedReferences       []string
	canonicalizationIsNull bool
}

// loadSignature is SignedXml#loadSignature.
func (s *signedXML) loadSignature(signature *Node) error {
	s.signatureNode = signature
	methods := signature.Descendants(func(n *Node) bool { return n.Local == "CanonicalizationMethod" && n.HasAttribute("Algorithm") })
	if len(methods) == 0 {
		return errors.New("could not find CanonicalizationMethod/@Algorithm element")
	}
	s.canonicalization, s.hasCanonicalization = methods[0].Attribute("Algorithm"), true
	if algorithms := signature.Descendants(func(n *Node) bool { return n.Local == "SignatureMethod" && n.HasAttribute("Algorithm") }); len(algorithms) > 0 {
		s.signatureAlgorithm = algorithms[0].Attribute("Algorithm")
	}
	signedInfo := findChildren(signature, "SignedInfo")
	if len(signedInfo) == 0 {
		return errors.New("no signed info node found")
	}
	if len(signedInfo) > 1 {
		return errors.New("could not load signature that contains multiple SignedInfo nodes")
	}
	algorithm := s.canonicalization
	if algorithm == "" || algorithm == algC14n || algorithm == algC14nComment {
		algorithm = algExcC14n
	}
	temporary, err := s.canonXML([]string{algorithm}, signedInfo[0], c14nOptions{})
	if err != nil {
		return err
	}
	parsed, err := parseLenient(temporary)
	if err != nil {
		return err
	}
	s.references = nil
	references := findChildren(parsed, "Reference")
	if len(references) == 0 {
		return errors.New("could not find any Reference elements")
	}
	for _, ref := range references {
		if err := s.loadReference(ref); err != nil {
			return err
		}
	}
	if value, ok := firstTextUnder(signature, "SignatureValue"); ok {
		s.signatureValue = strings.NewReplacer("\r\n", "", "\n", "").Replace(value)
	}
	return nil
}

// parseLenient parses XML that xml-crypto reparses without an error handler (canonical output it produced).
func parseLenient(xml string) (*Node, error) { return ParseXML(xml) }

func (s *signedXML) canonXML(transforms []string, node *Node, options c14nOptions) (string, error) {
	options.signatureNode = s.signatureNode
	return canonXML(transforms, node, options)
}

// loadReference is SignedXml#loadReference.
func (s *signedXML) loadReference(node *Node) error {
	methods := findChildren(node, "DigestMethod")
	if len(methods) == 0 {
		return errors.New("could not find DigestMethod in reference " + node.String())
	}
	attr := findAttr(methods[0], "Algorithm")
	if attr == nil {
		return errors.New("could not find Algorithm attribute in node " + methods[0].String())
	}
	values := findChildren(node, "DigestValue")
	if len(values) == 0 {
		return errors.New("could not find DigestValue node in reference " + node.String())
	}
	if len(values) > 1 {
		return errors.New("could not load reference for a node that contains multiple DigestValue nodes: " + node.String())
	}
	digestValue := values[0].TextContent()
	if digestValue == "" {
		return errors.New("could not find the value of DigestValue in " + node.String())
	}
	var transforms []string
	var inclusive []string
	if groups := findChildren(node, "Transforms"); len(groups) > 0 {
		all := findChildren(groups[0], "Transform")
		for _, transform := range all {
			if algorithm := findAttr(transform, "Algorithm"); algorithm != nil {
				transforms = append(transforms, algorithm.Value)
			}
		}
		if len(all) == 0 {
			return errors.New("Cannot read properties of undefined (reading 'childNodes')")
		}
		for _, namespaces := range findChildren(all[len(all)-1], "InclusiveNamespaces") {
			for _, prefix := range strings.Split(namespaces.Attribute("PrefixList"), " ") {
				if prefix != "" {
					inclusive = append(inclusive, prefix)
				}
			}
		}
	}
	if len(transforms) == 0 || transforms[len(transforms)-1] == algEnveloped {
		transforms = append(transforms, algC14n)
	}
	ref := &reference{transforms: transforms, digestAlgorithm: attr.Value, digestValue: digestValue, inclusivePrefixes: inclusive}
	if value := node.Attribute("URI"); value != "" {
		ref.uri = &value
	}
	s.references = append(s.references, ref)
	return nil
}

var idAttributes = []string{"Id", "ID", "id"}

// validateReference is SignedXml#validateReference against the reparsed document.
func (s *signedXML) validateReference(ref *reference, doc *Node) (bool, error) {
	var elem *Node
	var uri *string
	if ref.uri != nil {
		value := strings.TrimPrefix(*ref.uri, "#")
		uri = &value
	}
	switch {
	case uri != nil && *uri == "":
		elem = doc.DocumentElement()
	case uri == nil || strings.Contains(*uri, "'"):
		return false, errors.New("Cannot validate a uri with quotes inside it")
	default:
		id := *uri
		count := 0
		for _, name := range idAttributes {
			matches := doc.Descendants(func(n *Node) bool {
				for _, attr := range n.Attrs {
					if attr.Local == name && attr.Value == id && attr.Prefix != "xmlns" && attr.Name != "xmlns" {
						return true
					}
				}
				return false
			})
			if len(matches) > 0 {
				count += len(matches)
				if count > 1 {
					return false, errors.New("Cannot validate a document which contains multiple elements with the same value for the ID / Id / Id attributes, in order to prevent signature wrapping attack.")
				}
				elem = matches[0]
			}
		}
	}
	if elem == nil {
		return false, nil
	}
	canon, err := s.canonXML(ref.transforms, elem, c14nOptions{inclusivePrefixes: ref.inclusivePrefixes, ancestorNamespaces: findAncestorNs(elem)})
	if err != nil {
		return false, err
	}
	digest, err := digestOf(ref.digestAlgorithm, canon)
	if err != nil {
		return false, err
	}
	if string(nodeBase64(digest)) != string(nodeBase64(ref.digestValue)) {
		return false, nil
	}
	s.signedReferences = append(s.signedReferences, canon)
	ref.signedReference = canon
	return true, nil
}

// checkSignature is SignedXml#checkSignature(xml).
func (s *signedXML) checkSignature(xml string) (bool, error) {
	doc, err := parseLenient(xml)
	if err != nil {
		return false, err
	}
	s.references = nil
	if s.signatureNode == nil {
		return false, errors.New("No signature found.")
	}
	if !s.hasCanonicalization {
		return false, errors.New("Missing canonicalizationAlgorithm when trying to get signed info for XML")
	}
	signedInfo := findChildren(s.signatureNode, "SignedInfo")
	if len(signedInfo) == 0 {
		return false, errors.New("could not find SignedInfo element in the message")
	}
	if len(signedInfo) > 1 {
		return false, errors.New("could not get canonicalized signed info for a signature that contains multiple SignedInfo nodes")
	}
	ancestors := findAncestorNs(firstElement(doc, func(n *Node) bool { return n.Local == "SignedInfo" }))
	canon, err := s.canonXML([]string{s.canonicalization}, signedInfo[0], c14nOptions{ancestorNamespaces: ancestors})
	if err != nil {
		return false, err
	}
	if canon == "" {
		return false, errors.New("Canonical signed info cannot be empty")
	}
	parsed, err := parseLenient(canon)
	if err != nil {
		return false, errors.New("Could not parse unverifiedSignedInfoCanon into a document")
	}
	references := findChildren(parsed, "Reference")
	if len(references) == 0 {
		return false, errors.New("could not find any Reference elements")
	}
	for _, ref := range references {
		if err := s.loadReference(ref); err != nil {
			return false, err
		}
	}
	for _, ref := range s.references {
		ok, err := s.validateReference(ref, doc)
		if err != nil {
			return false, err
		}
		if !ok {
			s.signedReferences = nil
			return false, nil
		}
	}
	h, ok := signatureHash(s.signatureAlgorithm)
	if s.signatureAlgorithm == "" {
		return false, errors.New("signatureAlgorithm is required")
	}
	if !ok {
		return false, errors.New("signature algorithm '" + s.signatureAlgorithm + "' is not supported")
	}
	key, err := publicKeyOf(s.publicCert)
	if err != nil {
		return false, err
	}
	if verifyBytes(key, h, []byte(canon), nodeBase64(s.signatureValue)) {
		return true, nil
	}
	s.signedReferences = nil
	return false, errors.New("invalid signature: the signature value " + s.signatureValue + " is incorrect")
}

// normalizeNewlines is node-saml's normalizeNewlines.
func normalizeNewlines(xml string) string {
	return strings.ReplaceAll(strings.ReplaceAll(xml, "\r\n", "\n"), "\r", "\n")
}

// getVerifiedXml is node-saml's getVerifiedXml: the canonical XML of the one reference of the single signature that
// is a direct child of currentNode, when it verifies with one of the trusted certificates ("" when it does not).
func getVerifiedXml(fullXml string, currentNode *Node, pemFiles []string) (string, error) {
	fullXml = normalizeNewlines(fullXml)
	signatures := currentNode.ChildElements(isSignature)
	if len(signatures) < 1 {
		return "", nil
	}
	if len(signatures) > 1 {
		return "", errors.New("Too many signatures found for this element")
	}
	signature := signatures[0]
	transforms := signature.Descendants(func(n *Node) bool { return n.Local == "Transform" && n.NamespaceURI == dsigNamespace })
	if len(transforms) > 2 {
		return "", errors.New("Invalid signature, too many transforms")
	}
	for _, pemFile := range pemFiles {
		sig := &signedXML{publicCert: pemFile}
		if err := sig.loadSignature(signature); err != nil {
			return "", err
		}
		if len(sig.references) != 1 {
			return "", nil
		}
		if signature.Parent == nil {
			return "", nil
		}
		ref := sig.references[0]
		if ref.uri == nil {
			return "", errors.New("Cannot read properties of undefined (reading '0')")
		}
		refID := *ref.uri
		if strings.HasPrefix(refID, "#") {
			refID = refID[1:]
		}
		if refID == "" {
			return "", errors.New("signature reference uri not found")
		}
		if strings.ContainsAny(refID, "'\"") {
			return "", errors.New("ref URI included quote character ' or \". Not a valid ID, and not allowed")
		}
		referenced := signature.OwnerDocument().Descendants(func(n *Node) bool {
			for _, attr := range n.Attrs {
				if attr.Name == "ID" && attr.Value == refID {
					return true
				}
			}
			return false
		})
		if len(referenced) != 1 {
			return "", errors.New("Invalid signature: ID cannot refer to more than one element")
		}
		if referenced[0] != signature.Parent {
			return "", errors.New("Invalid signature: Referenced node does not refer to it's parent element")
		}
		ok, err := sig.checkSignature(fullXml)
		if err != nil || !ok {
			continue
		}
		if len(sig.signedReferences) != 1 {
			continue
		}
		return sig.signedReferences[0], nil
	}
	return "", nil
}

// --- signing (SignedXml#computeSignature) -------------------------------------------------------------------------

// signOptions describe a signature to create: what to reference, where to put the signature, and the keys.
type signOptions struct {
	// references selects the nodes to reference in the parsed document (an xpath in xml-crypto).
	references func(doc *Node) []*Node
	// location selects the node the signature is placed relative to; action is append, prepend, before or after.
	location func(doc *Node) *Node
	action   string
	// privateKey signs; publicCert, when set, goes into KeyInfo.
	privateKey string
	publicCert string
	// signatureAlgorithm and digestAlgorithm are xmldsig algorithm URIs.
	signatureAlgorithm string
	digestAlgorithm    string
}

var x509Certs = regexp.MustCompile(`-----BEGIN CERTIFICATE-----[^-]*-----END CERTIFICATE-----`)
var pemBody = regexp.MustCompile(`(?s)^-----BEGIN [A-Z ]{1,48}-----([^-]*)-----END [A-Z ]{1,48}-----$`)

// pemToDer is xml-crypto utils.pemToDer.
func pemToDer(text string) ([]byte, error) {
	if !pemBody.MatchString(strings.TrimSpace(text)) {
		return nil, errors.New("Invalid PEM format.")
	}
	body := strings.NewReplacer("\r\n", "", "\r", "").Replace(text)
	body = regexp.MustCompile(`-----BEGIN [A-Z ]{1,48}-----\n?`).ReplaceAllString(body, "")
	body = regexp.MustCompile(`-----END [A-Z ]{1,48}-----\n?`).ReplaceAllString(body, "")
	return nodeBase64(body), nil
}

// ensureHasID is SignedXml#ensureHasId: the node's Id / ID / id, or a new Id.
func ensureHasID(node *Node, next *int) string {
	for _, name := range idAttributes {
		if attr := findAttr(node, name); attr != nil {
			return attr.Value
		}
	}
	id := "_" + itoa(*next)
	*next++
	node.SetAttributeNS("", "Id", id)
	return id
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	return string(digits)
}

// computeSignature is SignedXml#computeSignature(xml, { location }) with exclusive canonicalization, the enveloped
// signature and exclusive canonicalization transforms; it returns getSignedXml().
func computeSignature(xml string, options signOptions) (string, error) {
	doc, err := ParseXML(xml)
	if err != nil {
		return "", err
	}
	h, ok := signatureHash(options.signatureAlgorithm)
	if !ok {
		return "", errors.New("signature algorithm '" + options.signatureAlgorithm + "' is not supported")
	}
	if _, _, ok := hashFor(options.digestAlgorithm); !ok {
		return "", errors.New("hash algorithm '" + options.digestAlgorithm + "' is not supported")
	}
	var signedInfo strings.Builder
	signedInfo.WriteString("<SignedInfo><CanonicalizationMethod Algorithm=\"" + algExcC14n + "\" />")
	signedInfo.WriteString("<SignatureMethod Algorithm=\"" + options.signatureAlgorithm + "\" />")
	nodes := options.references(doc)
	if len(nodes) == 0 {
		return "", errors.New("the following xpath cannot be signed because it was not found")
	}
	next := 0
	for _, node := range nodes {
		id := ensureHasID(node, &next)
		signedInfo.WriteString("<Reference URI=\"#" + id + "\"><Transforms>")
		signedInfo.WriteString("<Transform Algorithm=\"" + algEnveloped + "\" />")
		signedInfo.WriteString("<Transform Algorithm=\"" + algExcC14n + "\" />")
		canon, err := canonXML([]string{algEnveloped, algExcC14n}, node, c14nOptions{ancestorNamespaces: findAncestorNs(nodes[0])})
		if err != nil {
			return "", err
		}
		digest, err := digestOf(options.digestAlgorithm, canon)
		if err != nil {
			return "", err
		}
		signedInfo.WriteString("</Transforms><DigestMethod Algorithm=\"" + options.digestAlgorithm + "\" /><DigestValue>" + digest + "</DigestValue></Reference>")
	}
	signedInfo.WriteString("</SignedInfo>")
	keyInfo := ""
	if options.publicCert != "" {
		var certificates strings.Builder
		for _, certificate := range x509Certs.FindAllString(options.publicCert, -1) {
			der, err := pemToDer(certificate)
			if err != nil {
				return "", err
			}
			certificates.WriteString("<X509Certificate>" + base64.StdEncoding.EncodeToString(der) + "</X509Certificate>")
		}
		keyInfo = "<KeyInfo><X509Data>" + certificates.String() + "</X509Data></KeyInfo>"
	}
	wrapper, err := ParseXML("<Dummy ><Signature xmlns=\"" + dsigNamespace + "\">" + signedInfo.String() + keyInfo + "</Signature></Dummy>")
	if err != nil {
		return "", err
	}
	signature := wrapper.DocumentElement().Children[0]
	target := options.location(doc)
	if target == nil {
		return "", errors.New("the following xpath cannot be used because it was not found")
	}
	switch options.action {
	case "append":
		target.AppendChild(signature)
	case "prepend":
		var first *Node
		if len(target.Children) > 0 {
			first = target.Children[0]
		}
		target.InsertBefore(signature, first)
	case "before":
		if target.Parent == nil {
			return "", errors.New("`location.reference` refers to the root node (by default), so we can't insert `before`")
		}
		target.Parent.InsertBefore(signature, target)
	case "after":
		if target.Parent == nil {
			return "", errors.New("`location.reference` refers to the root node (by default), so we can't insert `after`")
		}
		target.Parent.InsertBefore(signature, target.NextSibling())
	default:
		return "", errors.New("location.action option has an invalid action: " + options.action)
	}
	infoNodes := findChildren(signature, "SignedInfo")
	ancestors := findAncestorNs(firstElement(doc, func(n *Node) bool { return n.Local == "SignedInfo" }))
	canon, err := canonXML([]string{algExcC14n}, infoNodes[0], c14nOptions{ancestorNamespaces: ancestors, signatureNode: signature})
	if err != nil {
		return "", err
	}
	key, err := parsePrivateKey(options.privateKey)
	if err != nil {
		return "", err
	}
	raw, err := signBytes(key, h, []byte(canon))
	if err != nil {
		return "", err
	}
	valueDoc, err := ParseXML("<Signature xmlns=\"" + dsigNamespace + "\"><SignatureValue>" + base64.StdEncoding.EncodeToString(raw) + "</SignatureValue></Signature>")
	if err != nil {
		return "", err
	}
	signature.InsertBefore(valueDoc.DocumentElement().Children[0], infoNodes[0].NextSibling())
	return doc.String(), nil
}
