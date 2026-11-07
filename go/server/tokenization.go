package server

// Skeleton of packages/server/src/tokenization.ts: every export another module or the API surface uses, with its final
// signature. Stubs return NOT_IMPLEMENTED (501) until the module is ported (see go/PORTING.md).

import (
	"github.com/Better-IAM/better-iam/go/core"
)

// TokenizationFingerprint (tokenization.ts fingerprint): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TokenizationFingerprint(key []byte, value string) (result string, err error) {
	err = notImplemented("tokenization.ts fingerprint")
	return
}

// FormatPreservingSpace (tokenization.ts formatPreservingSpace): Format-preserving generic tokens need enough random
// positions to be unguessable and unique.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func FormatPreservingSpace(typeValue string, value string) (result bool, err error) {
	err = notImplemented("tokenization.ts formatPreservingSpace")
	return
}

// LookupContext (tokenization.ts lookupContext): The encryption context of a profile's lookup key (batch data keys
// are bound to `{ protection }` alone).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func LookupContext(profileID string) (result *core.Object, err error) {
	err = notImplemented("tokenization.ts lookupContext")
	return
}

// MaskStyle (tokenization.ts maskStyle): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func MaskStyle(typeValue string, value any, name string) (result string, err error) {
	err = notImplemented("tokenization.ts maskStyle")
	return
}

// MaskValue (tokenization.ts maskValue): A masked form of a normalized value, for display. A mask never shows more
// than half of a value's letters and digits, except the first six and last four digits of a card number of 15 or
// more digits (what PCI DSS allows showing); on a shorter card number `first6last4` shows the last four only.
// Letters and digits of every script are hidden.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func MaskValue(typeValue string, style string, value string) (result string, err error) {
	err = notImplemented("tokenization.ts maskValue")
	return
}

// NeedsDeterministic (tokenization.ts needsDeterministic): Format-preserving `ssn` and `phone` tokens keep the last
// four digits, leaving few random ones (10,000 tokens per last four of a social security number): issuing a new
// token on every call would use them up, so these profiles are deterministic.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func NeedsDeterministic(typeValue string, format string) (result bool, err error) {
	err = notImplemented("tokenization.ts needsDeterministic")
	return
}

// NewToken (tokenization.ts newToken): A new token for a normalized value; never the value itself. Random tokens are
// `tok_` and 22 base62 characters (131 bits). Format-preserving tokens keep what systems validate or display: -
// card: the same length and last four digits, but failing the Luhn check, so a token is never a card number; - ssn:
// `9XX-`, group digits outside the ITIN ranges and the last four digits, so a token is never an SSN or ITIN; -
// email: a random local part at the same domain; - phone: the same length, leading `+` and last four digits; -
// generic: the same length in characters, each letter (of any script) replaced by an ASCII letter (capitals by
// capitals), each digit by a digit, the rest kept.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func NewToken(typeValue string, format string, value string) (result string, err error) {
	err = notImplemented("tokenization.ts newToken")
	return
}

// NormalizeValue (tokenization.ts normalizeValue): Validates and normalizes a value for its data type: card numbers
// to their digits (12 to 19, Luhn-valid), US social security numbers to `NNN-NN-NNNN`, email addresses to NFC
// lowercase, phone numbers to `+digits` or digits (7 to 15, compared as written, so give them in E.164), and
// anything else to NFC (up to 4096 characters of well-formed text without control or bidirectional formatting
// characters; tab and line feed are allowed).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func NormalizeValue(typeValue string, value any) (result string, err error) {
	err = notImplemented("tokenization.ts normalizeValue")
	return
}

// OpenValue (tokenization.ts openValue): Opens a stored value; a record that fails authentication was altered in
// storage.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func OpenValue(dataKey []byte, record *core.Object) (result string, err error) {
	err = notImplemented("tokenization.ts openValue")
	return
}

// ProfileName (tokenization.ts profileName): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func ProfileName(value any) (result string, err error) {
	err = notImplemented("tokenization.ts profileName")
	return
}

// SealValue (tokenization.ts sealValue): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SealValue(dataKey []byte, tenantID string, profileID string, token string, value string) (result string, err error) {
	err = notImplemented("tokenization.ts sealValue")
	return
}

// SummarizeProfile (tokenization.ts summarizeProfile): see the TypeScript source.
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func SummarizeProfile(profile *core.Object) (result *core.Object, err error) {
	err = notImplemented("tokenization.ts summarizeProfile")
	return
}

// TokenKey (tokenization.ts tokenKey): Where a token is unique: its profile, by hash (a format-preserving token can
// be long).
//
// STUB: returns NOT_IMPLEMENTED until the module is ported.
func TokenKey(profileID string, token string) (result string, err error) {
	err = notImplemented("tokenization.ts tokenKey")
	return
}

// MaxBatch is tokenization.ts MAX_BATCH.
const MaxBatch = 100

// MaxProfilesPerTenant is tokenization.ts MAX_PROFILES_PER_TENANT.
const MaxProfilesPerTenant = 100

// DataTypes is tokenization.ts dataTypes.
var DataTypes = []string{"card", "ssn", "email", "phone", "generic"}

// DefaultMask is tokenization.ts defaultMask.
var DefaultMask = struct {
	Card    string
	Ssn     string
	Email   string
	Phone   string
	Generic string
}{"last4", "last4", "email", "last4", "full"}

// ProtectionActions is tokenization.ts protectionActions.
var ProtectionActions = struct {
	Read       string
	Manage     string
	Tokenize   string
	Detokenize string
	Mask       string
	Delete     string
}{"iam:protection:read", "iam:protection:manage", "iam:protection:tokenize", "iam:protection:detokenize", "iam:protection:mask", "iam:protection:delete"}
