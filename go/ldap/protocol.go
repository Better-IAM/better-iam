package ldap

// Port of packages/ldap/src/protocol.ts: LDAPv3 messages (RFC 4511) as the gateway reads and writes them, and the
// client-side encoders for tests and for programs that talk to an LDAP server.

import (
	"strconv"
)

// Result codes (RFC 4511 §4.1.9).
const (
	ResultSuccess                     = 0
	ResultOperationsError             = 1
	ResultProtocolError               = 2
	ResultTimeLimitExceeded           = 3
	ResultSizeLimitExceeded           = 4
	ResultCompareFalse                = 5
	ResultCompareTrue                 = 6
	ResultAuthMethodNotSupported      = 7
	ResultConfidentialityRequired     = 13
	ResultNoSuchAttribute             = 16
	ResultNoSuchObject                = 32
	ResultInvalidDNSyntax             = 34
	ResultInappropriateAuthentication = 48
	ResultInvalidCredentials          = 49
	ResultInsufficientAccessRights    = 50
	ResultBusy                        = 51
	ResultUnavailable                 = 52
	ResultUnwillingToPerform          = 53
	ResultOther                       = 80
)

// Object identifiers the gateway knows.
const (
	OIDWhoAmI                = "1.3.6.1.4.1.4203.1.11.3"
	OIDStartTLS              = "1.3.6.1.4.1.1466.20037"
	OIDNoticeOfDisconnection = "1.3.6.1.4.1.1466.20036"
	OIDPagedResults          = "1.2.840.113556.1.4.319"
)

// SearchScope is base, one or sub.
type SearchScope string

var scopes = []SearchScope{"base", "one", "sub"}

// LdapRequest is a decoded protocol operation. Op is bind, unbind, search, compare, extended, abandon or
// unsupported (a write or other operation the gateway refuses; ResponseTag is the tag its answer needs).
type LdapRequest struct {
	Op string
	// Bind.
	Version     int64
	Name        string
	Password    []byte
	HasPassword bool
	Sasl        string
	// Search.
	Base       string
	Scope      SearchScope
	SizeLimit  int64
	TimeLimit  int64
	TypesOnly  bool
	Filter     *Filter
	Attributes []string
	// Compare.
	Entry     string
	Attribute string
	Value     string
	// Extended (Name is the request name).
	ExtendedValue    []byte
	HasExtendedValue bool
	// Abandon.
	ID int64
	// Unsupported.
	ResponseTag int
}

// LdapControl is a request or response control.
type LdapControl struct {
	Type     string
	Critical bool
	Value    []byte
	HasValue bool
}

// LdapMessage is one decoded LDAPMessage.
type LdapMessage struct {
	ID       int64
	Request  *LdapRequest
	Controls []LdapControl
}

var unsupportedOps = map[int]struct {
	name string
	tag  int
}{
	0x66: {"modify", 0x67},
	0x68: {"add", 0x69},
	0x4a: {"delete", 0x6b},
	0x6c: {"modifyDN", 0x6d},
}

func decodeControls(element *BerElement) ([]LdapControl, error) {
	controls := []LdapControl{}
	if element == nil || element.Tag != 0xa0 {
		return controls, nil
	}
	items, err := Children(element.Value)
	if err != nil {
		return nil, err
	}
	for _, control := range items {
		parts, err := Children(control.Value)
		if err != nil {
			return nil, err
		}
		kind, second, third := at(parts, 0), at(parts, 1), at(parts, 2)
		critical := false
		if second != nil && second.Tag == TagBoolean {
			if critical, err = ReadBoolean(second); err != nil {
				return nil, err
			}
		}
		valueItem := third
		if second != nil && second.Tag == TagOctetString {
			valueItem = second
		}
		name, err := ReadString(kind)
		if err != nil {
			return nil, err
		}
		decoded := LdapControl{Type: name, Critical: critical}
		if valueItem != nil && valueItem.Tag == TagOctetString {
			decoded.Value, decoded.HasValue = valueItem.Value, true
		}
		controls = append(controls, decoded)
	}
	return controls, nil
}

// DecodeMessage decodes one LDAPMessage element.
func DecodeMessage(message *BerElement) (*LdapMessage, error) {
	if message.Tag != TagSequence {
		return nil, berError("Expected an LDAPMessage")
	}
	parts, err := Children(message.Value)
	if err != nil {
		return nil, err
	}
	id, err := ReadInteger(at(parts, 0))
	if err != nil {
		return nil, err
	}
	if id < 0 || id > 2147483647 {
		return nil, berError("Invalid message ID")
	}
	op := at(parts, 1)
	if op == nil {
		return nil, berError("Missing protocol operation")
	}
	controls, err := decodeControls(at(parts, 2))
	if err != nil {
		return nil, err
	}
	request, err := decodeRequest(op)
	if err != nil {
		return nil, err
	}
	return &LdapMessage{ID: id, Request: request, Controls: controls}, nil
}

func decodeRequest(op *BerElement) (*LdapRequest, error) {
	switch op.Tag {
	case 0x60:
		parts, err := Children(op.Value)
		if err != nil {
			return nil, err
		}
		auth := at(parts, 2)
		if auth == nil {
			return nil, berError("Missing authentication")
		}
		if auth.Tag == 0x80 {
			version, err := ReadInteger(at(parts, 0))
			if err != nil {
				return nil, err
			}
			name, err := ReadString(at(parts, 1))
			if err != nil {
				return nil, err
			}
			return &LdapRequest{Op: "bind", Version: version, Name: name, Password: auth.Value, HasPassword: true}, nil
		}
		if auth.Tag == 0xa3 {
			mechanisms, err := Children(auth.Value)
			if err != nil {
				return nil, err
			}
			version, err := ReadInteger(at(parts, 0))
			if err != nil {
				return nil, err
			}
			name, err := ReadString(at(parts, 1))
			if err != nil {
				return nil, err
			}
			mechanism, err := ReadString(at(mechanisms, 0))
			if err != nil {
				return nil, err
			}
			return &LdapRequest{Op: "bind", Version: version, Name: name, Sasl: mechanism}, nil
		}
		return nil, berError("Unknown authentication choice")
	case 0x42:
		return &LdapRequest{Op: "unbind"}, nil
	case 0x63:
		parts, err := Children(op.Value)
		if err != nil {
			return nil, err
		}
		scope, err := ReadInteger(at(parts, 1), TagEnumerated)
		if err != nil {
			return nil, err
		}
		if scope < 0 || scope >= int64(len(scopes)) {
			return nil, berError("Invalid search scope")
		}
		filterElement := at(parts, 6)
		if filterElement == nil {
			return nil, berError("Missing filter")
		}
		base, err := ReadString(at(parts, 0))
		if err != nil {
			return nil, err
		}
		sizeLimit, err := ReadInteger(at(parts, 3))
		if err != nil {
			return nil, err
		}
		timeLimit, err := ReadInteger(at(parts, 4))
		if err != nil {
			return nil, err
		}
		typesOnly, err := ReadBoolean(at(parts, 5))
		if err != nil {
			return nil, err
		}
		filter, err := DecodeFilter(filterElement)
		if err != nil {
			return nil, err
		}
		attributes := []string{}
		if element := at(parts, 7); element != nil {
			items, err := Children(element.Value)
			if err != nil {
				return nil, err
			}
			for _, item := range items {
				name, err := ReadString(item)
				if err != nil {
					return nil, err
				}
				attributes = append(attributes, name)
			}
		}
		return &LdapRequest{Op: "search", Base: base, Scope: scopes[scope], SizeLimit: sizeLimit, TimeLimit: timeLimit,
			TypesOnly: typesOnly, Filter: filter, Attributes: attributes}, nil
	case 0x6e:
		parts, err := Children(op.Value)
		if err != nil {
			return nil, err
		}
		assertion := at(parts, 1)
		if assertion == nil {
			return nil, berError("Cannot read properties of undefined (reading 'value')")
		}
		pair, err := Children(assertion.Value)
		if err != nil {
			return nil, err
		}
		entry, err := ReadString(at(parts, 0))
		if err != nil {
			return nil, err
		}
		attribute, err := ReadString(at(pair, 0))
		if err != nil {
			return nil, err
		}
		value, err := ReadString(at(pair, 1))
		if err != nil {
			return nil, err
		}
		return &LdapRequest{Op: "compare", Entry: entry, Attribute: attribute, Value: value}, nil
	case 0x77:
		parts, err := Children(op.Value)
		if err != nil {
			return nil, err
		}
		var name, value *BerElement
		for _, part := range parts {
			if part.Tag == 0x80 && name == nil {
				name = part
			}
			if part.Tag == 0x81 && value == nil {
				value = part
			}
		}
		if name == nil {
			return nil, berError("Missing extended request name")
		}
		request := &LdapRequest{Op: "extended", Name: utf8Text(name.Value)}
		if value != nil {
			request.ExtendedValue, request.HasExtendedValue = value.Value, true
		}
		return request, nil
	case 0x50:
		id, err := ReadInteger(&BerElement{Tag: TagInteger, Value: op.Value, Size: op.Size})
		if err != nil {
			return nil, err
		}
		return &LdapRequest{Op: "abandon", ID: id}, nil
	}
	if known, ok := unsupportedOps[op.Tag]; ok {
		return &LdapRequest{Op: "unsupported", Name: known.name, ResponseTag: known.tag}, nil
	}
	return nil, berError("Unknown protocol operation 0x" + strconv.FormatInt(int64(op.Tag), 16))
}

func envelope(id int64, op []byte, controls []byte) []byte {
	items := [][]byte{Integer(id), op}
	if controls != nil {
		items = append(items, controls)
	}
	return Sequence(items)
}

func result(tag int, code int, matchedDn, message string, extra ...[]byte) []byte {
	items := [][]byte{Enumerated(int64(code)), OctetString(matchedDn), OctetString(message)}
	items = append(items, extra...)
	return Sequence(items, tag)
}

// BindResponse is a BindResponse.
func BindResponse(id int64, code int, message string) []byte {
	return envelope(id, result(0x61, code, "", message), nil)
}

// SearchDone is a SearchResultDone, with optional response controls.
func SearchDone(id int64, code int, message, matchedDn string, controls []byte) []byte {
	return envelope(id, result(0x65, code, matchedDn, message), controls)
}

// CompareResponse is a CompareResponse.
func CompareResponse(id int64, code int, message string) []byte {
	return envelope(id, result(0x6f, code, "", message), nil)
}

// GenericResponse is an LDAPResult with the given tag.
func GenericResponse(id int64, tag int, code int, message string) []byte {
	return envelope(id, result(tag, code, "", message), nil)
}

// ExtendedResponse is an ExtendedResponse with an optional name and value (nil: absent).
func ExtendedResponse(id int64, code int, message string, name string, value []byte) []byte {
	var extra [][]byte
	if name != "" {
		extra = append(extra, OctetString(name, 0x8a))
	}
	if value != nil {
		extra = append(extra, Octets(value, 0x8b))
	}
	return envelope(id, result(0x78, code, "", message, extra...), nil)
}

// NoticeOfDisconnection is the unsolicited notice sent before the server closes a connection (message ID 0).
func NoticeOfDisconnection(code int, message string) []byte {
	return ExtendedResponse(0, code, message, OIDNoticeOfDisconnection, nil)
}

// AttributeValues is one attribute of an entry: its name and values, in output order.
type AttributeValues struct {
	Name   string
	Values []string
}

// SearchEntry is one SearchResultEntry: attribute order kept, values as given (or types only).
func SearchEntry(id int64, dn string, attributes []AttributeValues, typesOnly bool) []byte {
	items := make([][]byte, len(attributes))
	for i, attribute := range attributes {
		var values [][]byte
		if !typesOnly {
			for _, value := range attribute.Values {
				values = append(values, OctetString(value))
			}
		}
		items[i] = Sequence([][]byte{OctetString(attribute.Name), Set(values)})
	}
	return envelope(id, Sequence([][]byte{OctetString(dn), Sequence(items)}, 0x64), nil)
}

// PagedResultsControl is the paged-results response control (RFC 2696): estimated size and the next page's cookie.
func PagedResultsControl(size int64, cookie []byte) []byte {
	return Sequence([][]byte{Sequence([][]byte{OctetString(OIDPagedResults), Octets(Sequence([][]byte{Integer(size), Octets(cookie)}))})}, 0xa0)
}

// PagedResults is a paged-results request control value: page size and cookie.
type PagedResults struct {
	Size   int64
	Cookie []byte
}

// ReadPagedResults reads a paged-results request control value (nil when there is none).
func ReadPagedResults(value []byte, present bool) (*PagedResults, error) {
	if !present {
		return nil, nil
	}
	outer, err := Children(value)
	if err != nil {
		return nil, err
	}
	if len(outer) == 0 {
		return nil, nil
	}
	parts, err := Children(outer[0].Value)
	if err != nil {
		return nil, err
	}
	size, err := ReadInteger(at(parts, 0))
	if err != nil {
		return nil, err
	}
	cookie, err := ReadOctets(at(parts, 1))
	if err != nil {
		return nil, err
	}
	return &PagedResults{Size: size, Cookie: cookie}, nil
}

// EncodeBind is a simple bind request.
func EncodeBind(id int64, name, password string) []byte {
	return envelope(id, Sequence([][]byte{Integer(3), OctetString(name), OctetString(password, 0x80)}, 0x60), nil)
}

// EncodeUnbind is an unbind request.
func EncodeUnbind(id int64) []byte { return envelope(id, []byte{0x42, 0x00}, nil) }

// SearchOptions describe a search request (Scope "" = sub).
type SearchOptions struct {
	Base       string
	Scope      SearchScope
	Filter     *Filter
	Attributes []string
	SizeLimit  int64
	TypesOnly  bool
}

// EncodeSearch is a search request with optional request controls.
func EncodeSearch(id int64, search SearchOptions, controls []byte) []byte {
	scope := int64(2)
	for i, value := range scopes {
		if value == search.Scope {
			scope = int64(i)
		}
	}
	typesOnly := byte(0)
	if search.TypesOnly {
		typesOnly = 0xff
	}
	attributes := make([][]byte, len(search.Attributes))
	for i, name := range search.Attributes {
		attributes[i] = OctetString(name)
	}
	return envelope(id, Sequence([][]byte{
		OctetString(search.Base),
		Enumerated(scope),
		Enumerated(0),
		Integer(search.SizeLimit),
		Integer(0),
		{TagBoolean, 1, typesOnly},
		EncodeFilter(search.Filter),
		Sequence(attributes),
	}, 0x63), controls)
}

// EncodeExtended is an extended request (value nil: none).
func EncodeExtended(id int64, name string, value []byte) []byte {
	items := [][]byte{OctetString(name, 0x80)}
	if value != nil {
		items = append(items, Octets(value, 0x81))
	}
	return envelope(id, Sequence(items, 0x77), nil)
}

// EncodeCompare is a compare request.
func EncodeCompare(id int64, entry, attribute, value string) []byte {
	return envelope(id, Sequence([][]byte{OctetString(entry), Sequence([][]byte{OctetString(attribute), OctetString(value)})}, 0x6e), nil)
}

// PagedResultsRequest is a paged-results request control.
func PagedResultsRequest(size int64, cookie []byte) []byte {
	return Sequence([][]byte{Sequence([][]byte{OctetString(OIDPagedResults), Octets(Sequence([][]byte{Integer(size), Octets(cookie)}))})}, 0xa0)
}

// LdapResponse is a decoded server answer (client side).
type LdapResponse struct {
	ID            int64
	Tag           int
	Code          int64
	Message       string
	Dn            string
	Attributes    map[string][]string
	AttributeList []string
	ResponseName  string
	ResponseValue []byte
	HasValue      bool
	Controls      []LdapControl
}

// DecodeResponse decodes a server answer.
func DecodeResponse(message *BerElement) (*LdapResponse, error) {
	parts, err := Children(message.Value)
	if err != nil {
		return nil, err
	}
	id, err := ReadInteger(at(parts, 0))
	if err != nil {
		return nil, err
	}
	op := at(parts, 1)
	if op == nil {
		return nil, berError("Missing protocol operation")
	}
	response := &LdapResponse{ID: id, Tag: op.Tag}
	items, err := Children(op.Value)
	if err != nil {
		return nil, err
	}
	if op.Tag == 0x64 {
		if response.Dn, err = ReadString(at(items, 0)); err != nil {
			return nil, err
		}
		response.Attributes = map[string][]string{}
		if second := at(items, 1); second != nil {
			attributes, err := Children(second.Value)
			if err != nil {
				return nil, err
			}
			for _, attribute := range attributes {
				pair, err := Children(attribute.Value)
				if err != nil {
					return nil, err
				}
				name, err := ReadString(at(pair, 0))
				if err != nil {
					return nil, err
				}
				var values []string
				if set := at(pair, 1); set != nil {
					elements, err := Children(set.Value)
					if err != nil {
						return nil, err
					}
					for _, value := range elements {
						values = append(values, utf8Text(value.Value))
					}
				}
				if values == nil {
					values = []string{}
				}
				response.Attributes[name] = values
				response.AttributeList = append(response.AttributeList, name)
			}
		}
	} else {
		if response.Code, err = ReadInteger(at(items, 0), TagEnumerated); err != nil {
			return nil, err
		}
		if response.Message, err = ReadString(at(items, 2)); err != nil {
			return nil, err
		}
		for _, part := range items {
			if part.Tag == 0x8a && response.ResponseName == "" {
				response.ResponseName = utf8Text(part.Value)
			}
			if part.Tag == 0x8b && !response.HasValue {
				response.ResponseValue, response.HasValue = part.Value, true
			}
		}
	}
	if controls := at(parts, 2); controls != nil && controls.Tag == 0xa0 {
		if response.Controls, err = decodeControls(controls); err != nil {
			return nil, err
		}
	}
	return response, nil
}
