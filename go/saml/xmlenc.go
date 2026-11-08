package saml

// Port of xml-encryption 3.1.0's decrypt (the EncryptedAssertion decryption node-saml delegates to): the key transport
// (RSA-OAEP with MGF1, or RSA PKCS #1 v1.5) and the content encryption (AES-CBC, AES-GCM, 3DES-CBC) it supports.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"hash"
	"unicode/utf8"
)

const (
	algRsaOaep     = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	algRsa15       = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
	algAes128Cbc   = "http://www.w3.org/2001/04/xmlenc#aes128-cbc"
	algAes256Cbc   = "http://www.w3.org/2001/04/xmlenc#aes256-cbc"
	algTripleDes   = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc"
	algAes128Gcm   = "http://www.w3.org/2009/xmlenc11#aes128-gcm"
	algAes256Gcm   = "http://www.w3.org/2009/xmlenc11#aes256-gcm"
	xmldsigSha256  = "http://www.w3.org/2000/09/xmldsig#sha256"
	xmldsigSha512  = "http://www.w3.org/2000/09/xmldsig#sha512"
	errorDecryptGc = "Unsupported state or unable to authenticate data"
)

// localPath selects, in document order, the elements reached from every element named steps[0] (anywhere) through
// child elements named steps[1:] (xpath `//*[local-name(.)='a']/*[local-name(.)='b']/...`).
func localPath(doc *Node, steps ...string) []*Node {
	current := doc.Descendants(func(n *Node) bool { return n.Local == steps[0] })
	for _, step := range steps[1:] {
		var next []*Node
		seen := map[*Node]bool{}
		for _, node := range current {
			for _, child := range node.ChildElements(func(n *Node) bool { return n.Local == step }) {
				if !seen[child] {
					seen[child] = true
					next = append(next, child)
				}
			}
		}
		current = inDocumentOrder(doc, next)
	}
	return current
}

func inDocumentOrder(doc *Node, nodes []*Node) []*Node {
	if len(nodes) < 2 {
		return nodes
	}
	wanted := map[*Node]bool{}
	for _, node := range nodes {
		wanted[node] = true
	}
	return doc.Descendants(func(n *Node) bool { return wanted[n] })
}

// decryptXML is xml-encryption's decrypt(xml, { key }).
func decryptXML(xml, key string) (string, error) {
	doc, err := ParseXML(xml)
	if err != nil {
		return "", err
	}
	symmetricKey, err := decryptKeyInfo(doc, key)
	if err != nil {
		return "", err
	}
	methods := localPath(doc, "EncryptedData", "EncryptionMethod")
	if len(methods) == 0 {
		return "", errors.New("Cannot read properties of undefined (reading 'getAttribute')")
	}
	algorithm := methods[0].Attribute("Algorithm")
	values := localPath(doc, "EncryptedData", "CipherData", "CipherValue")
	if len(values) == 0 {
		return "", errors.New("Cannot read properties of undefined (reading 'textContent')")
	}
	encrypted := nodeBase64(values[0].TextContent())
	switch algorithm {
	case algAes128Cbc:
		return decryptCBC(symmetricKey, encrypted, 16, false)
	case algAes256Cbc:
		return decryptCBC(symmetricKey, encrypted, 32, false)
	case algTripleDes:
		return decryptCBC(symmetricKey, encrypted, 24, true)
	case algAes128Gcm, algAes256Gcm:
		size := 16
		if algorithm == algAes256Gcm {
			size = 32
		}
		return decryptGCM(symmetricKey, encrypted, size)
	}
	return "", errors.New("encryption algorithm " + algorithm + " not supported")
}

func decryptKeyInfo(doc *Node, key string) ([]byte, error) {
	keyInfos := doc.Descendants(func(n *Node) bool { return n.Local == "KeyInfo" && n.NamespaceURI == dsigNamespace })
	if len(keyInfos) == 0 {
		keyInfos = localPath(doc, "EncryptedData", "KeyInfo")
	}
	retrievalURI := ""
	hasRetrieval := false
	methods := localPath(doc, "KeyInfo", "EncryptedKey", "EncryptionMethod")
	if len(methods) == 0 {
		if retrievals := localPath(doc, "EncryptedData", "KeyInfo", "RetrievalMethod"); len(retrievals) > 0 {
			retrievalURI, hasRetrieval = retrievals[0].LookupAttribute("URI")
			hasRetrieval = hasRetrieval && retrievalURI != ""
		}
		if hasRetrieval {
			methods = byKeyID(doc, retrievalURI[1:], "EncryptionMethod")
		}
	}
	if len(methods) == 0 {
		return nil, errors.New("cant find encryption algorithm")
	}
	var oaepHash func() hash.Hash = sha1.New
	if digests := localPath(doc, "KeyInfo", "EncryptedKey", "EncryptionMethod", "DigestMethod"); len(digests) > 0 {
		switch digests[0].Attribute("Algorithm") {
		case xmldsigSha256:
			oaepHash = sha256.New
		case xmldsigSha512:
			oaepHash = sha512.New
		}
	}
	algorithm := methods[0].Attribute("Algorithm")
	if len(keyInfos) == 0 {
		return nil, errors.New("Context node is required")
	}
	var cipherValues []*Node
	if hasRetrieval {
		cipherValues = byKeyID(doc, retrievalURI[1:], "CipherData", "CipherValue")
	} else {
		cipherValues = doc.Descendants(func(n *Node) bool { return n.Local == "CipherValue" })
	}
	switch algorithm {
	case algRsaOaep, algRsa15:
	default:
		return nil, errors.New("key encryption algorithm " + algorithm + " not supported")
	}
	if len(cipherValues) == 0 {
		return nil, errors.New("Cannot read properties of undefined (reading 'textContent')")
	}
	encryptedKey := nodeBase64(cipherValues[0].TextContent())
	signer, err := parsePrivateKey(key)
	if err != nil {
		return nil, err
	}
	private, ok := signer.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("error:02000079:rsa routines::oaep decoding error")
	}
	if algorithm == algRsaOaep {
		return rsa.DecryptOAEP(oaepHash(), rand.Reader, private, encryptedKey, nil)
	}
	return rsa.DecryptPKCS1v15(rand.Reader, private, encryptedKey)
}

// byKeyID is xpath `//*[local-name(.)='EncryptedKey' and @Id='<id>']/*[...]/...`.
func byKeyID(doc *Node, id string, steps ...string) []*Node {
	current := doc.Descendants(func(n *Node) bool {
		return n.Local == "EncryptedKey" && n.Attribute("Id") == id && n.HasAttribute("Id")
	})
	for _, step := range steps {
		var next []*Node
		for _, node := range current {
			next = append(next, node.ChildElements(func(n *Node) bool { return n.Local == step })...)
		}
		current = inDocumentOrder(doc, next)
	}
	return current
}

func decryptCBC(key, content []byte, size int, tripleDes bool) (string, error) {
	if len(key) != size {
		return "", errors.New("Invalid key length")
	}
	var block cipher.Block
	var err error
	ivLength := 16
	if tripleDes {
		ivLength = 8
		block, err = des.NewTripleDESCipher(key)
	} else {
		block, err = aes.NewCipher(key)
	}
	if err != nil {
		return "", errors.New("Invalid key length")
	}
	if len(content) < ivLength {
		return "", errors.New("Invalid initialization vector")
	}
	data := append([]byte(nil), content[ivLength:]...)
	if len(data)%block.BlockSize() != 0 {
		return "", errors.New("wrong final block length")
	}
	cipher.NewCBCDecrypter(block, content[:ivLength]).CryptBlocks(data, data)
	// The padding is judged on the decrypted text read as Latin-1 characters.
	if len(data) == 0 {
		return "", errors.New("padding length invalid")
	}
	padding := int(data[len(data)-1])
	if padding < 1 || padding > ivLength {
		return "", errors.New("padding length invalid")
	}
	return decodeUTF8(data[:len(data)-padding]), nil
}

func decryptGCM(key, content []byte, size int) (string, error) {
	if len(key) != size {
		return "", errors.New("Invalid key length")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", errors.New("Invalid key length")
	}
	if len(content) < 12+16 {
		return "", errors.New(errorDecryptGc)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plain, err := aead.Open(nil, content[:12], content[12:], nil)
	if err != nil {
		return "", errors.New(errorDecryptGc)
	}
	return decodeUTF8(plain), nil
}

// decodeUTF8 is Buffer#toString('utf8'): invalid sequences become U+FFFD.
func decodeUTF8(data []byte) string {
	if utf8.Valid(data) {
		return string(data)
	}
	var out []rune
	for len(data) > 0 {
		r, size := utf8.DecodeRune(data)
		out = append(out, r)
		data = data[size:]
	}
	return string(out)
}
