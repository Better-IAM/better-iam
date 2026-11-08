package scim

// Port of packages/scim/src/attributes.ts: lenient attribute handling.

import (
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// readOnlyAttributes are the read-only attributes (RFC 7643 §3.1, §4): a client may send them back, and RFC 7644
// §3.3/§3.5.1 says to ignore them.
var readOnlyAttributes = map[ResourceType]map[string]bool{
	"Users":  {"id": true, "meta": true, "groups": true},
	"Groups": {"id": true, "meta": true},
}

// unsupportedUser are the core User attributes RFC 7643 §4.1 defines that this service provider does not store.
// Identity providers send several of them by default (Entra ID: addresses, phoneNumbers, preferredLanguage; Okta:
// locale, nickName, password with password sync), so with UnsupportedAttributes "ignore" they are accepted and dropped.
var unsupportedUser = map[string]bool{
	"nickname": true, "profileurl": true, "usertype": true, "preferredlanguage": true, "locale": true, "timezone": true,
	"password": true, "phonenumbers": true, "ims": true, "photos": true, "addresses": true, "entitlements": true,
	"roles": true, "x509certificates": true,
}

var corePrefixes = []string{core.JSLower(UserSchema) + ":", core.JSLower(GroupSchema) + ":"}

var enterpriseLower = core.JSLower(EnterpriseSchema)

// ignoredAttribute is whether an attribute (a top-level name such as `addresses`, or a PATCH path such as
// `phoneNumbers[type eq "work"].value` or `urn:…:core:2.0:User:preferredLanguage`) is dropped instead of applied:
// read-only attributes are (unless readOnly is false: a PATCH path that targets one is a `mutability` error, RFC 7644
// §3.5.2, while a POST/PUT body or a pathless PATCH value that carries one is not, §3.5.1); with lenient, so are core
// attributes this service does not store and anything in an extension schema other than the enterprise User
// extension. Everything else is validated as before.
func ignoredAttribute(path string, resourceType ResourceType, lenient bool, readOnly bool) bool {
	lower := core.JSLower(strings.SplitN(path, "[", 2)[0])
	for _, prefix := range corePrefixes {
		if strings.HasPrefix(lower, prefix) {
			lower = sliceUTF16(lower, utf16Len(prefix), utf16Len(lower))
			break
		}
	}
	if lower == enterpriseLower || strings.HasPrefix(lower, enterpriseLower+":") {
		return false
	}
	if strings.HasPrefix(lower, "urn:") {
		return lenient
	}
	name := strings.SplitN(lower, ".", 2)[0]
	if readOnlyAttributes[resourceType][name] {
		return readOnly
	}
	return lenient && resourceType == "Users" && unsupportedUser[name]
}

// withoutIgnored is a copy of a POST/PUT body without the attributes ignoredAttribute drops (and, when lenient,
// foreign schema URNs).
func withoutIgnored(data *core.Object, resourceType ResourceType, lenient bool) *core.Object {
	kept := core.NewObject()
	data.Entries(func(key string, value any) bool {
		if key == "schemas" || !ignoredAttribute(key, resourceType, lenient, true) {
			kept.SetRaw(key, value)
		}
		return true
	})
	if schemas, ok := kept.Get("schemas").([]any); lenient && ok {
		known := []string{GroupSchema}
		if resourceType == "Users" {
			known = []string{UserSchema, EnterpriseSchema}
		}
		// Extension schemas this service does not implement are listed by the IdP but their attributes were dropped above.
		filtered := make([]any, 0, len(schemas))
		for _, schema := range schemas {
			if text, isString := schema.(string); isString && strings.HasPrefix(text, "urn:") && !containsString(known, text) {
				continue
			}
			filtered = append(filtered, schema)
		}
		kept.SetRaw("schemas", filtered)
	}
	return kept
}
