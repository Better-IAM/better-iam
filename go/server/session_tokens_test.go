package server

// spec/vectors/session-jwt.json: the signer's configuration checks and public keys, EdDSA tokens byte for byte (ES256
// signatures are randomized: their header and payload, and the vector's token verifying), and every verify case of
// the signer and the offline verifier with the same claims or the same failure reason.

import (
	"context"
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/spectest"
)

// signingOptionsOf is the sts.jwt options of a vector input.
func signingOptionsOf(value *core.Object) *SessionTokenSigningOptions {
	options := &SessionTokenSigningOptions{}
	if list, ok := value.Get("signingKeys").([]any); ok {
		options.SigningKeys = []*core.Object{}
		for _, item := range list {
			key, _ := item.(*core.Object)
			options.SigningKeys = append(options.SigningKeys, key)
		}
	}
	if list, ok := value.Get("verificationKeys").([]any); ok {
		for _, item := range list {
			key, _ := item.(*core.Object)
			options.VerificationKeys = append(options.VerificationKeys, key)
		}
	}
	if text, ok := value.Get("activeKeyId").(string); ok {
		options.ActiveKeyID = &text
	}
	if text, ok := value.Get("issuer").(string); ok {
		options.Issuer = &text
	}
	if list, ok := value.Get("audiences").([]any); ok {
		for _, item := range list {
			options.Audiences = append(options.Audiences, item.(string))
		}
	}
	if number, ok := value.Get("maxLifetimeSeconds").(float64); ok {
		options.MaxLifetimeSeconds = &number
	}
	return options
}

// sessionOutcome is a result, or a SessionTokenError as the vectors write it.
func sessionOutcome(value any, err error) any {
	if known, ok := err.(*SessionTokenError); ok {
		return core.NewObject("$error", core.NewObject("name", "SessionTokenError", "code", known.Code(),
			"status", float64(known.Status()), "reason", known.Reason, "message", known.Error()))
	}
	return spectest.Outcome(value, err)
}

func TestSessionJwtVectors(t *testing.T) {
	file := spectest.Load(t, "session-jwt")
	ctx := context.Background()
	for _, c := range file.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if strings.HasPrefix(c.Name, "looksLikeJwt") {
				spectest.Check(t, c, LooksLikeJwt(c.Input.Get("value")))
				return
			}
			now, _ := c.Input.Get("now").(float64)
			clock := func() int64 { return int64(now) }
			if verifierInput, ok := c.Input.Object("verifier"); ok {
				options := &SessionTokenVerifierOptions{Issuer: jsString(verifierInput.Get("issuer")), Audience: verifierInput.Get("audience"),
					JWKS: verifierInput.Get("jwks"), Now: clock}
				if list, ok := verifierInput.Get("audience").([]any); ok {
					options.Audience = []string{}
					for _, item := range list {
						options.Audience = append(options.Audience.([]string), item.(string))
					}
				}
				for _, member := range []string{"kinds", "algorithms"} {
					if list, ok := verifierInput.Get(member).([]any); ok {
						values := []string{}
						for _, item := range list {
							values = append(values, item.(string))
						}
						if member == "kinds" {
							options.Kinds = values
						} else {
							options.Algorithms = values
						}
					}
				}
				if number, ok := verifierInput.Get("clockToleranceSeconds").(float64); ok {
					options.ClockToleranceSeconds = &number
				}
				verifier, err := CreateSessionTokenVerifier(options)
				if err != nil {
					t.Fatal(err)
				}
				result, err := verifier.Verify(ctx, jsString(c.Input.Get("token")))
				spectest.Check(t, c, sessionOutcome(result, err))
				return
			}
			optionsInput, _ := c.Input.Object("options")
			signer, err := CreateSessionTokenSigner(signingOptionsOf(optionsInput), jsString(c.Input.Get("issuer")), clock)
			if err != nil || strings.HasPrefix(c.Name, "config") {
				spectest.Check(t, c, sessionOutcome(nil, err))
				return
			}
			switch {
			case strings.HasPrefix(c.Name, "signer"):
				jwks, _ := signer.PublicJwks()
				spectest.Check(t, c, core.NewObject("issuer", signer.Issuer, "audiences", stringsOf(signer.Audiences),
					"maxLifetimeSeconds", signer.MaxLifetimeSeconds, "jwks", jwks))
			case strings.HasPrefix(c.Name, "sign"):
				claims, _ := c.Input.Object("claims")
				token, err := signer.Sign(ctx, claims)
				if err != nil {
					t.Fatal(err)
				}
				expected := c.Output.(*core.Object)
				parts := strings.Split(token, ".")
				header, payload := stsDecodeJwt(t, token)
				got := core.NewObject("token", token, "header", header, "payload", payload, "signature", parts[2])
				if strings.Contains(c.Name, "ES256") {
					// Randomized: the same header and payload, and both tokens verify.
					expectedParts := strings.Split(jsString(expected.Get("token")), ".")
					if parts[0] != expectedParts[0] || parts[1] != expectedParts[1] {
						t.Fatalf("got %s, want %s", token, expected.Get("token"))
					}
					for _, candidate := range []string{token, jsString(expected.Get("token"))} {
						if _, err := signer.Verify(ctx, candidate, ""); err != nil {
							t.Fatalf("%s does not verify: %v", candidate, err)
						}
					}
					return
				}
				spectest.Check(t, c, got)
			default:
				result, err := signer.Verify(ctx, jsString(c.Input.Get("token")), jsString(coalesce(c.Input.Get("audience"), "")))
				spectest.Check(t, c, sessionOutcome(result, err))
			}
		})
	}
}
