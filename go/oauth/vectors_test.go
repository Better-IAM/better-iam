package oauth

// The oauth vectors of spec/vectors: artifact sealing (oauth-artifacts.json) and the artifact id hash
// (derivations.json), reproduced from their inputs.

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

func loadVectorFile(t *testing.T, name string) []*core.Object {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "spec", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	parsed := mustParse(t, string(raw))
	var cases []*core.Object
	for _, item := range parsed.Get("cases").([]any) {
		cases = append(cases, item.(*core.Object))
	}
	return cases
}

func TestOAuthArtifactVectors(t *testing.T) {
	for _, vector := range loadVectorFile(t, "oauth-artifacts.json") {
		name := str(vector, "name")
		input := obj(vector, "input")
		output := vector.Get("output")
		t.Run(name, func(t *testing.T) {
			key, keyErr := EncryptionKey(str(input, "key"))
			switch {
			case strings.HasPrefix(name, "encryptionKey"):
				if failure := obj(obj(vector, "output"), "$error"); failure != nil {
					expectIamError(t, keyErr, 400, str(failure, "code"))
					if keyErr.Error() != str(failure, "message") {
						t.Fatalf("unexpected message %q", keyErr.Error())
					}
					return
				}
				if keyErr != nil || float64(len(key)) != output.(float64) {
					t.Fatalf("unexpected key length %d %v", len(key), keyErr)
				}
			case strings.HasPrefix(name, "seal"):
				crypt, _ := NewCipher(key)
				expected := obj(vector, "output")
				iv, _ := base64.StdEncoding.DecodeString(str(expected, "iv"))
				if sealed := crypt.sealWithIV(input.Get("value"), iv); sealed != str(expected, "sealed") {
					t.Fatalf("sealed %s, expected %s", sealed, str(expected, "sealed"))
				}
			case strings.HasPrefix(name, "open"):
				crypt, _ := NewCipher(key)
				opened, err := crypt.Open(str(input, "sealed"))
				if failure := obj(obj(vector, "output"), "$error"); failure != nil {
					if err == nil || err.Error() != str(failure, "message") {
						t.Fatalf("expected %q, got %v", str(failure, "message"), err)
					}
					return
				}
				if err != nil || stringify(opened) != stringify(output) {
					t.Fatalf("opened %s (%v), expected %s", stringify(opened), err, stringify(output))
				}
			}
		})
	}
}

func TestOAuthHashVectors(t *testing.T) {
	found := 0
	for _, vector := range loadVectorFile(t, "derivations.json") {
		if !strings.HasPrefix(str(vector, "name"), "oauth artifact id hash") {
			continue
		}
		found++
		if got := Hash(str(obj(vector, "input"), "value")); got != str(vector, "output") {
			t.Fatalf("%s: %s, expected %s", str(vector, "name"), got, str(vector, "output"))
		}
	}
	if found == 0 {
		t.Fatal("no oauth hash vectors")
	}
}
