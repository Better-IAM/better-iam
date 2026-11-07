package auth

// The password hashing of node-argon2 0.44, which the TypeScript service calls as argon2.hash(password, { type:
// argon2id }) and argon2.verify(hash, password): argon2id, version 19, m=65536 KiB, t=3, p=4, a 32-byte hash and a
// 16-byte random salt, serialized as a PHC string ($argon2id$v=19$m=65536,t=3,p=4$<salt>$<hash>, standard base64
// without padding). Verification reads the parameters from the PHC string, so hashes made by either implementation
// verify in the other.

import (
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2Params are the cost parameters of a password hash.
type Argon2Params struct {
	// Type is argon2id (the default) or argon2i. argon2d is not available in Go (golang.org/x/crypto).
	Type        string
	MemoryCost  uint32
	TimeCost    uint32
	Parallelism uint8
	HashLength  uint32
}

// DefaultArgon2Params are node-argon2's defaults with type argon2id.
var DefaultArgon2Params = Argon2Params{Type: "argon2id", MemoryCost: 1 << 16, TimeCost: 3, Parallelism: 4, HashLength: 32}

var phcBase64 = base64.RawStdEncoding

// HashPassword hashes a password as node-argon2 does with the default parameters.
func HashPassword(password string) (string, error) {
	return HashPasswordWith(password, DefaultArgon2Params, nil)
}

// HashPasswordWith hashes with explicit parameters and, when salt is nil, a 16-byte random salt.
func HashPasswordWith(password string, params Argon2Params, salt []byte) (string, error) {
	if salt == nil {
		salt = randomBytes(16)
	}
	hash, err := argon2Key(params.Type, utf8Bytes(password), salt, params.TimeCost, params.MemoryCost, params.Parallelism, params.HashLength)
	if err != nil {
		return "", err
	}
	return "$" + params.Type + "$v=19$m=" + strconv.FormatUint(uint64(params.MemoryCost), 10) + ",t=" +
		strconv.FormatUint(uint64(params.TimeCost), 10) + ",p=" + strconv.FormatUint(uint64(params.Parallelism), 10) +
		"$" + phcBase64.EncodeToString(salt) + "$" + phcBase64.EncodeToString(hash), nil
}

func argon2Key(kind string, password, salt []byte, t, m uint32, p uint8, length uint32) ([]byte, error) {
	if t < 1 || p < 1 || m < 8*uint32(p) || length < 4 {
		return nil, errors.New("argon2: invalid parameters")
	}
	switch kind {
	case "argon2id":
		return argon2.IDKey(password, salt, t, m, p, length), nil
	case "argon2i":
		return argon2.Key(password, salt, t, m, p, length), nil
	}
	return nil, errors.New("argon2: unsupported type " + kind)
}

// errMalformedHash is what verification fails with for a string that is not a PHC hash (node-argon2 throws a
// TypeError there).
var errMalformedHash = errors.New("pchstr must contain a $ as first char")

// VerifyPassword is argon2.verify(phc, password): false for a wrong password or an unknown type; an error for a
// malformed PHC string, a version other than 19 (only node-argon2 can compute version 16 hashes), argon2d, or
// associated data (golang.org/x/crypto supports neither).
func VerifyPassword(phc, password string) (bool, error) {
	if !strings.HasPrefix(phc, "$") {
		return false, errMalformedHash
	}
	fields := strings.Split(phc[1:], "$")
	if len(fields) < 1 || fields[0] == "" {
		return false, errMalformedHash
	}
	kind := fields[0]
	rest := fields[1:]
	version := uint64(0x10)
	if len(rest) > 0 && strings.HasPrefix(rest[0], "v=") {
		parsed, err := strconv.ParseUint(rest[0][2:], 10, 32)
		if err != nil {
			return false, errors.New("version must be a number")
		}
		version = parsed
		rest = rest[1:]
	}
	if len(rest) != 3 {
		return false, errMalformedHash
	}
	params := map[string]string{}
	for _, pair := range strings.Split(rest[0], ",") {
		name, value, ok := strings.Cut(pair, "=")
		if !ok {
			return false, errors.New("params must be in the format name=value")
		}
		params[name] = value
	}
	salt, err := phcBase64.DecodeString(rest[1])
	if err != nil {
		return false, errors.New("salt must be a valid B64 encoded string")
	}
	hash, err := phcBase64.DecodeString(rest[2])
	if err != nil {
		return false, errors.New("hash must be a valid B64 encoded string")
	}
	if kind != "argon2d" && kind != "argon2i" && kind != "argon2id" {
		return false, nil
	}
	if kind == "argon2d" {
		return false, errors.New("argon2d hashes are not supported")
	}
	if version != 0x13 {
		return false, errors.New("argon2 version " + strconv.FormatUint(version, 10) + " is not supported")
	}
	if data, ok := params["data"]; ok && data != "" {
		return false, errors.New("argon2 associated data is not supported")
	}
	number := func(name string) (uint64, error) {
		value, err := strconv.ParseUint(params[name], 10, 32)
		if err != nil {
			return 0, errors.New("invalid argon2 parameter " + name)
		}
		return value, nil
	}
	m, err := number("m")
	if err != nil {
		return false, err
	}
	t, err := number("t")
	if err != nil {
		return false, err
	}
	p, err := number("p")
	if err != nil {
		return false, err
	}
	if p > 255 {
		return false, errors.New("argon2 parallelism above 255 is not supported")
	}
	computed, err := argon2Key(kind, utf8Bytes(password), salt, uint32(t), uint32(m), uint8(p), uint32(len(hash)))
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(computed, hash) == 1, nil
}
