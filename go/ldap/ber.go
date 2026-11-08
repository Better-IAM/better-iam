// Package ldap ports @better-iam/ldap: a read-only LDAPv3 directory gateway over Better IAM, so applications that
// only speak LDAP (VPNs, NAS devices, CI servers, wikis, printers) can look up people and groups and check passwords.
// Start it with CreateLdapServer; each organization publishes its directory under its own base DN
// (`ldap.updateSettings`). The BER codec, DN and filter helpers and message encoders are exported for tools and
// tests.
package ldap

// Port of packages/ldap/src/ber.ts: the subset of ASN.1 BER (X.690) that LDAPv3 (RFC 4511) uses: definite lengths,
// INTEGER/ENUMERATED, BOOLEAN, OCTET STRING, NULL, SEQUENCE/SET and context/application tags. Decoding is strict (no
// indefinite lengths, lengths at most four bytes) and bounds-checked; anything malformed fails with a BerError.

import (
	"math/big"
	"unicode/utf8"
)

// BerError is a malformed BER element.
type BerError struct{ Message string }

func (e *BerError) Error() string { return e.Message }

func berError(message string) error { return &BerError{Message: message} }

// BER universal tags.
const (
	TagBoolean     = 0x01
	TagInteger     = 0x02
	TagOctetString = 0x04
	TagNull        = 0x05
	TagEnumerated  = 0x0a
	TagSequence    = 0x30
	TagSet         = 0x31
)

// BerElement is a decoded element: its tag byte and raw content.
type BerElement struct {
	Tag int
	// Value is the content octets.
	Value []byte
	// Size is the total encoded size (tag + length + content).
	Size int
}

func lengthBytes(length int) ([]byte, error) {
	if length < 0x80 {
		return []byte{byte(length)}, nil
	}
	var bytes []byte
	for rest := length; rest > 0; rest /= 256 {
		bytes = append([]byte{byte(rest & 0xff)}, bytes...)
	}
	if len(bytes) > 4 {
		return nil, berError("Element too long")
	}
	return append([]byte{byte(0x80 | len(bytes))}, bytes...), nil
}

// Element is one TLV.
func Element(tag int, parts ...[]byte) []byte {
	var content []byte
	for _, part := range parts {
		content = append(content, part...)
	}
	length, err := lengthBytes(len(content))
	if err != nil {
		panic(err)
	}
	out := append([]byte{byte(tag)}, length...)
	return append(out, content...)
}

// IntegerBytes is the two's-complement content of an integer.
func IntegerBytes(value int64) []byte {
	var bytes []byte
	rest := value
	for {
		bytes = append([]byte{byte(rest & 0xff)}, bytes...)
		rest >>= 8
		if rest == 0 || rest == -1 {
			break
		}
	}
	// Keep the sign bit right: a positive value whose top bit is set needs a leading 0x00, a negative one 0xff.
	if value >= 0 && bytes[0]&0x80 != 0 {
		bytes = append([]byte{0}, bytes...)
	}
	if value < 0 && bytes[0]&0x80 == 0 {
		bytes = append([]byte{0xff}, bytes...)
	}
	return bytes
}

// Integer is an INTEGER (or the given tag).
func Integer(value int64, tag ...int) []byte {
	t := TagInteger
	if len(tag) > 0 {
		t = tag[0]
	}
	return Element(t, IntegerBytes(value))
}

// Enumerated is an ENUMERATED.
func Enumerated(value int64) []byte { return Element(TagEnumerated, IntegerBytes(value)) }

// Octets is an OCTET STRING (or the given tag).
func Octets(value []byte, tag ...int) []byte {
	t := TagOctetString
	if len(tag) > 0 {
		t = tag[0]
	}
	return Element(t, value)
}

// OctetString is an OCTET STRING holding text as UTF-8.
func OctetString(value string, tag ...int) []byte { return Octets([]byte(value), tag...) }

// Boolean is a BOOLEAN (or the given tag).
func Boolean(value bool, tag ...int) []byte {
	t := TagBoolean
	if len(tag) > 0 {
		t = tag[0]
	}
	b := byte(0)
	if value {
		b = 0xff
	}
	return Element(t, []byte{b})
}

// Sequence is a SEQUENCE (or the given tag).
func Sequence(items [][]byte, tag ...int) []byte {
	t := TagSequence
	if len(tag) > 0 {
		t = tag[0]
	}
	return Element(t, items...)
}

// Set is a SET (or the given tag).
func Set(items [][]byte, tag ...int) []byte {
	t := TagSet
	if len(tag) > 0 {
		t = tag[0]
	}
	return Element(t, items...)
}

// ReadElement reads one element at offset, or nil when buffer does not yet hold all of it (stream framing). maxSize
// bounds the content length a peer may announce.
func ReadElement(buffer []byte, offset int, maxSize int) (*BerElement, error) {
	if offset >= len(buffer) {
		return nil, nil
	}
	tag := int(buffer[offset])
	if tag&0x1f == 0x1f {
		return nil, berError("Multi-byte tags are not supported")
	}
	if offset+1 >= len(buffer) {
		return nil, nil
	}
	length := int(buffer[offset+1])
	header := 2
	if length&0x80 != 0 {
		count := length & 0x7f
		if count == 0 {
			return nil, berError("Indefinite lengths are not allowed")
		}
		if count > 4 {
			return nil, berError("Length too long")
		}
		if offset+2+count > len(buffer) {
			return nil, nil
		}
		length = 0
		for index := 0; index < count; index++ {
			length = length*256 + int(buffer[offset+2+index])
		}
		header += count
	}
	if length > maxSize {
		return nil, berError("Element exceeds the size limit")
	}
	if offset+header+length > len(buffer) {
		return nil, nil
	}
	return &BerElement{Tag: tag, Value: buffer[offset+header : offset+header+length], Size: header + length}, nil
}

// Children are the elements inside a constructed value.
func Children(value []byte) ([]*BerElement, error) {
	var result []*BerElement
	offset := 0
	for offset < len(value) {
		item, err := ReadElement(value, offset, 1<<20)
		if err != nil {
			return nil, err
		}
		if item == nil {
			return nil, berError("Truncated element")
		}
		result = append(result, item)
		offset += item.Size
	}
	return result, nil
}

func at(items []*BerElement, index int) *BerElement {
	if index < len(items) {
		return items[index]
	}
	return nil
}

// ReadInteger reads an INTEGER (or the given tag) of at most six bytes.
func ReadInteger(item *BerElement, tag ...int) (int64, error) {
	t := TagInteger
	if len(tag) > 0 {
		t = tag[0]
	}
	if item == nil || item.Tag != t || len(item.Value) == 0 || len(item.Value) > 6 {
		return 0, berError("Expected an integer")
	}
	value := big.NewInt(0)
	if item.Value[0]&0x80 != 0 {
		value.SetInt64(-1)
	}
	for _, b := range item.Value {
		value.Lsh(value, 8)
		value.Or(value, big.NewInt(int64(b)))
	}
	// BigInt.asIntN(48, value)
	modulus := new(big.Int).Lsh(big.NewInt(1), 48)
	value.Mod(value, modulus)
	if value.Cmp(new(big.Int).Lsh(big.NewInt(1), 47)) >= 0 {
		value.Sub(value, modulus)
	}
	return value.Int64(), nil
}

// ReadOctets reads an OCTET STRING (or the given tag).
func ReadOctets(item *BerElement, tag ...int) ([]byte, error) {
	t := TagOctetString
	if len(tag) > 0 {
		t = tag[0]
	}
	if item == nil || item.Tag != t {
		return nil, berError("Expected an octet string")
	}
	return item.Value, nil
}

// ReadString reads an OCTET STRING as UTF-8 text.
func ReadString(item *BerElement, tag ...int) (string, error) {
	value, err := ReadOctets(item, tag...)
	if err != nil {
		return "", err
	}
	return utf8Text(value), nil
}

// ReadBoolean reads a BOOLEAN (or the given tag).
func ReadBoolean(item *BerElement, tag ...int) (bool, error) {
	t := TagBoolean
	if len(tag) > 0 {
		t = tag[0]
	}
	if item == nil || item.Tag != t || len(item.Value) != 1 {
		return false, berError("Expected a boolean")
	}
	return item.Value[0] != 0, nil
}

// utf8Text is Buffer#toString('utf8'): invalid sequences become U+FFFD.
func utf8Text(data []byte) string {
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
