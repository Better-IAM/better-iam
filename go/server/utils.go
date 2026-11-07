package server

// Port of packages/server/src/utils.ts.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/Better-IAM/better-iam/go/core"
)

// ID is crypto.randomUUID(): a random (version 4) UUID in lowercase.
func ID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16])
}

// Token is 32 random bytes as unpadded base64url (43 characters).
func Token() string {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:])
}

// Hash is SHA-256 of the UTF-8 value, as lowercase hex.
func Hash(value string) string {
	digest := sha256.Sum256(utf8Bytes(value))
	return hex.EncodeToString(digest[:])
}

// SameHash compares two token hashes in constant time (for equal lengths). A stored value is typed as a string but
// read fail-closed: anything else, or a different byte length, never matches.
func SameHash(a, b any) bool {
	left, ok := a.(string)
	if !ok {
		return false
	}
	right, ok := b.(string)
	if !ok {
		return false
	}
	first, second := utf8Bytes(left), utf8Bytes(right)
	return len(first) == len(second) && subtle.ConstantTimeCompare(first, second) == 1
}

// All is the unrestricted policy used for root authorities, owner roles, and default ceilings. It returns a fresh
// copy (TypeScript shares one frozen-by-convention object).
func All() *core.Object {
	return core.NewObject(
		"version", 1.0,
		"statements", []any{core.NewObject("effect", "allow", "actions", []any{"*"}, "resources", []any{"*"})},
	)
}

// PublicIdentity strips credential material before an identity leaves the service layer.
func PublicIdentity(identity *core.Object) *core.Object {
	safe := identity.Spread()
	safe.Delete("passwordHash")
	return safe
}

// ByNewest is the deterministic newest-first ordering for records that carry a creation timestamp: createdAt
// descending, then id ascending (UTF-16 order).
func ByNewest(a, b *core.Object) int {
	left, _ := a.Number("createdAt")
	right, _ := b.Number("createdAt")
	if difference := right - left; difference != 0 && difference == difference {
		if difference < 0 {
			return -1
		}
		return 1
	}
	return ByID(a, b)
}

// ByID orders records by id (UTF-16 order).
func ByID(a, b *core.Object) int {
	left, _ := a.String("id")
	right, _ := b.String("id")
	return compareUTF16(left, right)
}
