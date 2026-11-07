package auth

// Port of packages/auth/src/service/passwordless.ts: magic links and one-time codes over email or SMS. Passwordless
// sign-in never links accounts by matching email.

import (
	"context"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// StartPasswordless sends a magic link or code to a destination (and answers the same whether or not it belongs
// to anyone). input: { tenantId, destination, channel: 'email' | 'sms', kind: 'magic-link' | 'code' }.
func (s *Service) StartPasswordless(ctx context.Context, input *core.Object) (*core.Object, error) {
	input = body(input)
	channel, kind := input.Get("channel"), input.Get("kind")
	if (channel != "email" && channel != "sms") || (kind != "magic-link" && kind != "code") {
		return nil, core.NewIamError("INVALID_INPUT", "Invalid passwordless method")
	}
	if channel == "sms" && kind != "code" {
		return nil, core.NewIamError("INVALID_INPUT", "SMS authentication requires a code")
	}
	if (channel == "email" && !s.options.PasswordlessEmail) || (channel == "sms" && !s.options.PasswordlessSms) {
		return nil, core.NewIamError("FEATURE_DISABLED", "Passwordless method is disabled")
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	var destination string
	if channel == "email" {
		destination, err = Email(input.Get("destination"))
	} else {
		destination, err = Phone(input.Get("destination"))
	}
	if err != nil {
		return nil, err
	}
	channelName, kindName := channel.(string), kind.(string)
	if err := s.rate(ctx, tenantID, "passwordless-start:"+destination, "sensitive"); err != nil {
		return nil, err
	}
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		if err := s.AssertTenantActive(ctx, tx, tenantID); err != nil {
			return nil, err
		}
		if err := s.methodAllowed(ctx, tx, tenantID, "passwordless-"+channelName); err != nil {
			return nil, err
		}
		filter := core.NewObject("tenantId", tenantID, "kind", "user", "status", "active")
		if channelName == "email" {
			filter.Set("email", destination)
		} else {
			filter.Set("phone", destination).Set("phoneVerified", true)
		}
		matches, err := tx.Find(ctx, "identities", filter, nil)
		if err != nil {
			return nil, err
		}
		if len(matches) > 0 {
			identity := matches[0]
			// Only the newest code or link for a destination stays valid.
			earlier, err := tx.Find(ctx, "authChallenges", core.NewObject("tenantId", tenantID, "identityId", identity.Get("id"), "purpose", "passwordless"), nil)
			if err != nil {
				return nil, err
			}
			for _, challenge := range earlier {
				if core.StrictEquals(child(challenge, "payload").Get("destination"), destination) {
					if err := tx.Delete(ctx, "authChallenges", str(challenge, "id")); err != nil {
						return nil, err
					}
				}
			}
			token := NewToken()
			if kindName == "code" {
				token = sixDigitCode()
			}
			if _, err := s.challenge(ctx, tx, identity, "passwordless", core.NewObject("destination", destination, "channel", channelName), 5*60_000, token, ""); err != nil {
				return nil, err
			}
			if err := s.enqueue(ctx, tx, identity, channelName, destination, kindName, core.NewObject("token", token)); err != nil {
				return nil, err
			}
		}
		return success(), nil
	})
}

// FinishPasswordless redeems a magic link or code: a session or an MFA challenge. input: { tenantId, destination,
// token, deviceToken? }.
func (s *Service) FinishPasswordless(ctx context.Context, input *core.Object) (*core.Object, error) {
	input = body(input)
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return nil, err
	}
	deviceToken, err := optionalText(input, "deviceToken", "deviceToken", 512)
	if err != nil {
		return nil, err
	}
	var destination string
	if raw, ok := input.Get("destination").(string); ok && strings.HasPrefix(raw, "+") {
		destination, err = Phone(raw)
	} else {
		destination, err = Email(input.Get("destination"))
	}
	if err != nil {
		return nil, err
	}
	if err := s.rate(ctx, tenantID, "passwordless-finish:"+destination, "sensitive"); err != nil {
		return nil, err
	}
	return core.Transact(ctx, s.options.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		channel := "email"
		if strings.HasPrefix(destination, "+") {
			channel = "sms"
		}
		if err := s.methodAllowed(ctx, tx, tenantID, "passwordless-"+channel); err != nil {
			return nil, err
		}
		challenge, err := s.readChallenge(ctx, tx, tenantID, input.Get("token"), "passwordless", challengeMatch{destination: destination})
		if err != nil {
			return nil, err
		}
		payload := child(challenge, "payload")
		viaEmail := core.StrictEquals(payload.Get("channel"), "email")
		if (viaEmail && !s.options.PasswordlessEmail) || (!viaEmail && !s.options.PasswordlessSms) {
			return nil, core.NewIamError("FEATURE_DISABLED", "Passwordless method is disabled")
		}
		if !core.StrictEquals(payload.Get("destination"), destination) {
			return nil, core.NewIamError("INVALID_CHALLENGE", "Invalid verification code", 401)
		}
		identity, err := s.user(ctx, tx, str(challenge, "identityId"), tenantID)
		if err != nil {
			return nil, err
		}
		squatted := false
		if viaEmail {
			if !core.StrictEquals(identity.Get("email"), destination) {
				return nil, core.NewIamError("INVALID_CHALLENGE", "Email has changed", 401)
			}
			squatted = !flag(identity, "emailVerified") && isTrue(identity, "unprovenPassword")
			identity.Set("emailVerified", true)
			identity.Delete("unprovenPassword")
		} else if !core.StrictEquals(identity.Get("phone"), destination) || !flag(identity, "phoneVerified") {
			return nil, core.NewIamError("INVALID_CHALLENGE", "Phone has changed", 401)
		}
		if err := tx.Delete(ctx, "authChallenges", str(challenge, "id")); err != nil {
			return nil, err
		}
		if squatted {
			// The first proof that someone controls this address, on an account whose password was chosen at self
			// sign-up before anyone proved it: that password, and the sessions and remembered devices it produced,
			// go. The owner sets a password through reset. (Accounts an administrator created keep their password.)
			if err := s.RevokeIdentity(ctx, tx, str(identity, "id")); err != nil {
				return nil, err
			}
			if flag(identity, "passwordHash") {
				identity.Delete("passwordHash")
				if err := s.audit(ctx, tx, identity, "auth:password:clear", nil, nil); err != nil {
					return nil, err
				}
			}
		}
		if viaEmail {
			if _, err := tx.Put(ctx, "identities", identity); err != nil {
				return nil, err
			}
		}
		method := "passwordless-sms"
		if viaEmail {
			method = "passwordless-email"
		}
		return s.CompleteAuthentication(ctx, tx, identity, method, deviceToken)
	})
}
