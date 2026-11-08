package server

// Port of tests/ssh-ca.test.ts (SSH certificate primitives), with tests/support/ssh.ts's key and ssh-keygen helpers.

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
)

// sshTestWrite is the support module's write: length-prefixed parts.
func sshTestWrite(parts ...[]byte) []byte {
	writer := new(SshWriter)
	for _, part := range parts {
		writer.String(part)
	}
	return writer.Bytes()
}

func sshTestMpint(value []byte) []byte {
	if value[0]&0x80 != 0 {
		return append([]byte{0}, value...)
	}
	return value
}

// sshTestPublicKey is sshPublicKey: a fresh OpenSSH public key line generated in-process.
func sshTestPublicKey(t *testing.T, keyType, comment string) string {
	t.Helper()
	if comment == "" {
		comment = "test@example"
	}
	switch keyType {
	case "", "ed25519", "sk-ed25519":
		publicKey, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		name := "ssh-ed25519"
		parts := [][]byte{[]byte(name), publicKey}
		if keyType == "sk-ed25519" {
			name = "sk-ssh-ed25519@openssh.com"
			parts = [][]byte{[]byte(name), publicKey, []byte("ssh:")}
		}
		return name + " " + base64.StdEncoding.EncodeToString(sshTestWrite(parts...)) + " " + comment
	case "ecdsa":
		key, err := ecdh.P256().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		blob := sshTestWrite([]byte("ecdsa-sha2-nistp256"), []byte("nistp256"), key.PublicKey().Bytes())
		return "ecdsa-sha2-nistp256 " + base64.StdEncoding.EncodeToString(blob) + " " + comment
	}
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	e := big.NewInt(int64(key.E)).Bytes()
	blob := sshTestWrite([]byte("ssh-rsa"), sshTestMpint(e), sshTestMpint(key.N.Bytes()))
	return "ssh-rsa " + base64.StdEncoding.EncodeToString(blob) + " " + comment
}

// sshTestKeygen is sshKeygen: the system's ssh-keygen, when installed.
func sshTestKeygen() string {
	for _, candidate := range []string{"ssh-keygen", `C:\Windows\System32\OpenSSH\ssh-keygen.exe`} {
		if path, err := exec.LookPath(candidate); err == nil {
			return path
		}
	}
	return ""
}

// sshTestRunKeygen is runKeygen: the exit status and stdout plus stderr.
func sshTestRunKeygen(binary string, args ...string) (int, string) {
	output, err := exec.Command(binary, args...).CombinedOutput()
	if err != nil {
		if exit, ok := err.(*exec.ExitError); ok {
			return exit.ExitCode(), string(output)
		}
		return 1, string(output) + err.Error()
	}
	return 0, string(output)
}

func sshTestAuthority(t *testing.T) *core.Object {
	t.Helper()
	generated := must(GenerateSshAuthorityKey())
	return must(SshSigningKey(generated.Get("publicBlob").([]byte), generated.Get("privatePkcs8").(string)))
}

func sshTestParse(t *testing.T, line string) *core.Object {
	t.Helper()
	key, err := ParseSshPublicKey(line, nil)
	if err != nil {
		t.Fatalf("parse %q: %v", line, err)
	}
	return key
}

func expectSshMessage(t *testing.T, err error, pattern string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error matching %q", pattern)
	}
	if !regexp.MustCompile(pattern).MatchString(err.Error()) {
		t.Fatalf("expected an error matching %q, got %v", pattern, err)
	}
}

func TestSshCaParsesEveryKeyTypeAndRefusesMalformedKeys(t *testing.T) {
	fingerprint := regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
	for _, keyType := range []string{"ed25519", "ecdsa", "rsa", "sk-ed25519"} {
		key := sshTestParse(t, sshTestPublicKey(t, keyType, "alice@laptop"))
		if !fingerprint.MatchString(key.Get("fingerprint").(string)) {
			t.Fatalf("fingerprint %v", key.Get("fingerprint"))
		}
		if key.Get("comment") != "alice@laptop" {
			t.Fatalf("comment %v", key.Get("comment"))
		}
		if key.Get("securityKey") != (keyType == "sk-ed25519") {
			t.Fatalf("securityKey %v for %s", key.Get("securityKey"), keyType)
		}
		if keyType == "rsa" && key.Get("bits") != 2048.0 {
			t.Fatalf("bits %v", key.Get("bits"))
		}
	}
	good := sshTestPublicKey(t, "", "")
	data := strings.Split(good, " ")[1]
	_, err := ParseSshPublicKey("ssh-dss AAAA", nil)
	expectSshMessage(t, err, "Unsupported key type")
	_, err = ParseSshPublicKey("ecdsa-sha2-nistp256 "+data, nil)
	expectSshMessage(t, err, "does not match")
	_, err = ParseSshPublicKey("ssh-ed25519 "+data+"AAAA", nil)
	expectSshMessage(t, err, ".")
	_, err = ParseSshPublicKey("ssh-ed25519-cert-v01@openssh.com AAAA", nil)
	expectSshMessage(t, err, "not a certificate")
	_, err = ParseSshPublicKey("ssh-ed25519", nil)
	expectError(t, err, "INVALID_INPUT", `Enter an OpenSSH public key such as "ssh-ed25519 AAAA..."`)
	// Beyond the TypeScript test: the refusals that guard what certificates embed.
	_, err = ParseSshPublicKey(42.0, nil)
	expectError(t, err, "INVALID_INPUT", `Enter an OpenSSH public key such as "ssh-ed25519 AAAA..."`)
	_, err = ParseSshPublicKey(sshTestPublicKey(t, "rsa", ""), core.NewObject("minRsaBits", 3072.0))
	expectError(t, err, "INVALID_INPUT", "RSA keys must have at least 3072 bits")
	padded := sshTestWrite([]byte("ssh-rsa"), []byte{0, 1}, append([]byte{0}, make([]byte, 256)...))
	_, err = ParseSshPublicKey("ssh-rsa "+base64.StdEncoding.EncodeToString(padded), nil)
	expectError(t, err, "INVALID_INPUT", "The RSA key is not canonically encoded")
	offCurve := append([]byte{4}, make([]byte, 64)...)
	offCurve[64] = 1
	_, err = ParseSshPublicKey("ecdsa-sha2-nistp256 "+base64.StdEncoding.EncodeToString(sshTestWrite([]byte("ecdsa-sha2-nistp256"), []byte("nistp256"), offCurve)), nil)
	expectError(t, err, "INVALID_INPUT", "The ECDSA point is not on its curve")
	_, err = ParseSshPublicKey("ecdsa-sha2-nistp256 "+base64.StdEncoding.EncodeToString(sshTestWrite([]byte("ecdsa-sha2-nistp256"), []byte("nistp384"), offCurve)), nil)
	expectError(t, err, "INVALID_INPUT", "The ECDSA curve does not match the key type")
	short := sshTestWrite([]byte("ssh-ed25519"), make([]byte, 31))
	_, err = ParseSshPublicKey("ssh-ed25519 "+base64.StdEncoding.EncodeToString(short), nil)
	expectError(t, err, "INVALID_INPUT", "Ed25519 keys are 32 bytes")
	trailing := append(sshTestWrite([]byte("ssh-ed25519"), make([]byte, 32)), 0)
	_, err = ParseSshPublicKey("ssh-ed25519 "+base64.StdEncoding.EncodeToString(trailing), nil)
	expectError(t, err, "INVALID_INPUT", "Unexpected data after the key")
	badApplication := sshTestWrite([]byte("sk-ssh-ed25519@openssh.com"), make([]byte, 32), []byte("web:"))
	_, err = ParseSshPublicKey("sk-ssh-ed25519@openssh.com "+base64.StdEncoding.EncodeToString(badApplication), nil)
	expectError(t, err, "INVALID_INPUT", "Security keys need an ssh: application")
	truncated := sshTestWrite([]byte("ssh-ed25519"))
	_, err = ParseSshPublicKey("ssh-ed25519 "+base64.StdEncoding.EncodeToString(truncated), nil)
	expectError(t, err, "INVALID_INPUT", "Truncated data")
}

func TestSshCaIssuesCertificatesThatVerifyDecodeAndRoundTrip(t *testing.T) {
	ca := sshTestAuthority(t)
	key := sshTestParse(t, sshTestPublicKey(t, "ecdsa", ""))
	serial := must(SshSerial()).(uint64)
	spec := sshRaw(
		"key", key, "serial", serial, "kind", float64(SshCertUser), "keyId", "alice@acme.test",
		"principals", []any{"deploy@web-01", "root@db-01"}, "validAfter", 1_700_000_000.0, "validBefore", 1_700_003_600.0,
		"criticalOptions", core.NewObject("source-address", "203.0.113.7/32"),
		"extensions", []any{"permit-pty", "permit-port-forwarding", "permit-X11-forwarding"},
	)
	signed := must(SignSshCertificate(ca, spec, ""))
	line := signed.Get("line").(string)
	if !strings.HasPrefix(line, "ecdsa-sha2-nistp256-cert-v01@openssh.com ") {
		t.Fatalf("line %s", line)
	}
	parsed := must(ParseSshCertificate(line))
	expect := map[string]any{
		"keyType":              "ecdsa-sha2-nistp256",
		"publicKeyFingerprint": key.Get("fingerprint"),
		"serial":               serial,
		"kind":                 float64(SshCertUser),
		"keyId":                "alice@acme.test",
		"principals":           []any{"deploy@web-01", "root@db-01"},
		"validAfter":           1_700_000_000.0,
		"validBefore":          1_700_003_600.0,
		// Lexical (byte) order: uppercase X sorts first.
		"extensions":     []any{"permit-X11-forwarding", "permit-port-forwarding", "permit-pty"},
		"signatureValid": true,
	}
	for name, value := range expect {
		if !reflect.DeepEqual(parsed.Get(name), value) {
			t.Fatalf("%s: %#v, want %#v", name, parsed.Get(name), value)
		}
	}
	if options := parsed.Get("criticalOptions").(*core.Object); options.Len() != 1 || options.Get("source-address") != "203.0.113.7/32" {
		t.Fatalf("criticalOptions %v", options)
	}
	if must(SshKeyLine(parsed.Get("signatureKey").([]byte), "")) != must(SshKeyLine(ca.Get("publicBlob").([]byte), "")) {
		t.Fatal("signature key differs from the authority")
	}
	// A flipped byte in the body breaks the signature.
	parts := strings.Split(line, " ")
	blob, _ := base64.StdEncoding.DecodeString(parts[1])
	blob[len(blob)-200] ^= 1
	tampered := must(ParseSshCertificate(parts[0] + " " + base64.StdEncoding.EncodeToString(blob)))
	if tampered.Get("signatureValid") != false {
		t.Fatal("a tampered certificate verified")
	}
	// A serial given as its decimal record form signs the same certificate fields.
	spec.SetRaw("serial", strconv.FormatUint(serial, 10))
	again := must(ParseSshCertificate(must(SignSshCertificate(ca, spec, "comment")).Get("line").(string)))
	if again.Get("serial") != serial {
		t.Fatalf("serial %v", again.Get("serial"))
	}
	_, err := ParseSshCertificate("ssh-ed25519 AAAA")
	expectError(t, err, "INVALID_INPUT", "Not an OpenSSH certificate")
}

func TestSshCaValidatesHostAddressesAndLogins(t *testing.T) {
	for input, want := range map[string]string{
		"Web-01.Prod.Example.com.": "web-01.prod.example.com",
		"10.0.0.5":                 "10.0.0.5",
		"2001:db8::1":              "2001:db8::1",
	} {
		if got := must(SshHostAddress(input)); got != want {
			t.Fatalf("SshHostAddress(%q) = %q", input, got)
		}
	}
	for _, bad := range []string{"*.example.com", "bad host", "fe80::1%eth0", "127.1", "10.0x1", "-web", strings.Repeat("a", 64)} {
		if _, err := SshHostAddress(bad); err == nil {
			t.Fatalf("SshHostAddress(%q) passed", bad)
		}
	}
	_, err := SshHostAddress("Bad Host")
	expectError(t, err, "INVALID_INPUT", "Invalid host address bad host")
	_, err = SshHostAddress(1.0)
	expectError(t, err, "INVALID_INPUT", "Invalid host address")
	if must(SshLogin("deploy")) != "deploy" || must(SshLogin("_svc.ci-1")) != "_svc.ci-1" {
		t.Fatal("valid logins refused")
	}
	for _, bad := range []any{"root@x", "1abc", "a b", "", strings.Repeat("x", 33), "dot.", "\u212a", nil} {
		_, err := SshLogin(bad)
		expectError(t, err, "INVALID_INPUT", `Logins are 1-32 letters, digits, "_", "." or "-" and start with a letter or "_"`)
	}
	if must(SshLoginPrincipal("deploy", "web-01")) != "deploy@web-01" {
		t.Fatal("login principal")
	}
}

func TestSshCaNodeIsIP(t *testing.T) {
	cases := map[string]int{
		"fe80::1%eth0": 6, "::1": 6, "::ffff:1.2.3.4": 6, "1.2.3.04": 0, "01.2.3.4": 0, "1.2.3.4": 4, "::": 6, "1::": 6,
		"2001:db8::1": 6, "::ffff:01.2.3.4": 0, "fe80::1%": 0, "1:2:3:4:5:6:7:8": 6, "1:2:3:4:5:6:7::": 6,
		"::1.2.3.4": 6, "1:2:3:4:5:6:1.2.3.4": 6, "a::b::c": 0, "FE80::1": 6, "web-01": 0,
	}
	for input, want := range cases {
		if got := nodeIsIP(input); got != want {
			t.Fatalf("nodeIsIP(%q) = %d, want %d", input, got, want)
		}
	}
}

func TestSshCaKrlLayout(t *testing.T) {
	ca := sshTestAuthority(t)
	blob := ca.Get("publicBlob").([]byte)
	krl := must(BuildSshKrl(sshRaw(
		"version", uint64(7), "generatedAt", 1_700_000_000_999.0, "comment", "test",
		"authorities", []any{
			sshRaw("authority", blob, "serials", []any{uint64(5), uint64(3), uint64(5), uint64(0)}, "keyIds", []any{"b", "a", "b"}),
			sshRaw("authority", blob, "serials", []any{}),
		},
		"keys", []any{[]byte{2}, []byte{1}, []byte{2}},
	)))
	reader := NewSshReader(krl)
	magic := must(reader.U64())
	if magic != krlMagic {
		t.Fatalf("magic %x", magic)
	}
	if must(reader.U32()) != 1 || must(reader.U64()) != 7 || must(reader.U64()) != 1_700_000_000 || must(reader.U64()) != 0 {
		t.Fatal("header")
	}
	if len(must(reader.String())) != 0 || must(reader.Text()) != "test" {
		t.Fatal("reserved or comment")
	}
	if must(reader.Byte()) != krlSectionCertificates {
		t.Fatal("certificate section")
	}
	section := NewSshReader(must(reader.String()))
	if string(must(section.String())) != string(blob) || len(must(section.String())) != 0 {
		t.Fatal("authority")
	}
	if must(section.Byte()) != krlSectionCertSerialList {
		t.Fatal("serial list")
	}
	serials := NewSshReader(must(section.String()))
	if must(serials.U64()) != 3 || must(serials.U64()) != 5 || !serials.Done() {
		t.Fatal("serials are deduplicated, sorted, and never 0")
	}
	if must(section.Byte()) != krlSectionCertKeyID {
		t.Fatal("key ID list")
	}
	keyIDs := NewSshReader(must(section.String()))
	if must(keyIDs.Text()) != "a" || must(keyIDs.Text()) != "b" || !keyIDs.Done() || !section.Done() {
		t.Fatal("key IDs")
	}
	if must(reader.Byte()) != krlSectionExplicitKey {
		t.Fatal("explicit keys (the empty authority section is skipped)")
	}
	keys := NewSshReader(must(reader.String()))
	if string(must(keys.String())) != "\x01" || string(must(keys.String())) != "\x02" || !keys.Done() || !reader.Done() {
		t.Fatal("keys are deduplicated and sorted")
	}
}

func TestSshCaCertificatesAndRevocationListsSshKeygenAccepts(t *testing.T) {
	keygen := sshTestKeygen()
	if keygen == "" {
		t.Skip("ssh-keygen is not installed")
	}
	ca := sshTestAuthority(t)
	for _, keyType := range []string{"ed25519", "ecdsa", "rsa"} {
		key := sshTestParse(t, sshTestPublicKey(t, keyType, ""))
		serial := must(SshSerial()).(uint64)
		kind := float64(SshCertUser)
		if keyType == "rsa" {
			kind = SshCertHost
		}
		critical := core.NewObject()
		if keyType == "ed25519" {
			critical.Set("force-command", "/usr/bin/true")
		}
		extensions := []any{"permit-pty", "permit-agent-forwarding"}
		if keyType == "rsa" {
			extensions = []any{}
		}
		line := must(SignSshCertificate(ca, sshRaw(
			"key", key, "serial", serial, "kind", kind, "keyId", "key-"+keyType, "principals", []any{"deploy@web-01"},
			"validAfter", 1_700_000_000.0, "validBefore", 4_100_000_000.0, "criticalOptions", critical, "extensions", extensions,
		), "")).Get("line").(string)
		other := must(SignSshCertificate(ca, sshRaw(
			"key", key, "serial", serial+1, "kind", float64(SshCertUser), "keyId", "other", "principals", []any{"x"},
			"validAfter", 0.0, "validBefore", 4_100_000_000.0,
		), "")).Get("line").(string)
		krl := must(BuildSshKrl(sshRaw(
			"version", uint64(7), "generatedAt", float64(time.Now().UnixMilli()), "comment", "test",
			"authorities", []any{sshRaw("authority", ca.Get("publicBlob"), "serials", []any{serial, uint64(99)}, "keyIds", []any{"nobody"})},
		)))
		directory := t.TempDir()
		path := func(name string) string { return filepath.Join(directory, name) }
		for name, content := range map[string][]byte{"cert.pub": []byte(line + "\n"), "other.pub": []byte(other + "\n"), "revoked.krl": krl} {
			if err := os.WriteFile(path(name), content, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		status, output := sshTestRunKeygen(keygen, "-L", "-f", path("cert.pub"))
		if status != 0 {
			t.Fatalf("%s: %s", keyType, output)
		}
		wantKind := "user certificate"
		if keyType == "rsa" {
			wantKind = "host certificate"
		}
		for _, fragment := range []string{`Key ID: "key-` + keyType + `"`, "Serial: " + strconv.FormatUint(serial, 10), "deploy@web-01", wantKind} {
			if !strings.Contains(output, fragment) {
				t.Fatalf("%s: %q not in %s", keyType, fragment, output)
			}
		}
		if keyType == "ed25519" && !strings.Contains(output, "force-command /usr/bin/true") {
			t.Fatalf("force-command missing: %s", output)
		}
		_, revoked := sshTestRunKeygen(keygen, "-Q", "-f", path("revoked.krl"), path("cert.pub"))
		if !strings.Contains(revoked, "REVOKED") {
			t.Fatalf("%s: not revoked: %s", keyType, revoked)
		}
		status, fine := sshTestRunKeygen(keygen, "-Q", "-f", path("revoked.krl"), path("other.pub"))
		if status != 0 || strings.Contains(fine, "REVOKED") {
			t.Fatalf("%s: other certificate refused: %d %s", keyType, status, fine)
		}
	}
}
