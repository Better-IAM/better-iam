package auth

// Replays testdata/differential.json, recorded from the TypeScript implementation and its libraries by
// testdata/differential.mjs: templates, validators, password screening, user agents, SSRF URL rules, JavaScript
// number/date/URI/base64 semantics, the CBOR codec, and WebAuthn registration and authentication verification.

import (
	"encoding/hex"
	"errors"
	"math"
	"os"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/spectest"
)

var (
	differentialOnce sync.Once
	differentialData *core.Object
)

func differential(t *testing.T, key string) []any {
	t.Helper()
	differentialOnce.Do(func() {
		data, err := os.ReadFile("testdata/differential.json")
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := core.ParseJSON(data)
		if err != nil {
			t.Fatal(err)
		}
		differentialData = parsed.(*core.Object)
	})
	list, _ := differentialData.Get(key).([]any)
	if len(list) == 0 {
		t.Fatalf("no %s cases", key)
	}
	return list
}

func obj(value any) *core.Object {
	o, _ := value.(*core.Object)
	return o
}

// outcomeValue renders a Go result in the fixture's { value } / { error } shape.
func outcomeValue(value any, err error) *core.Object {
	if err != nil {
		var iam *core.IamError
		if errors.As(err, &iam) {
			return core.NewObject("error", core.NewObject("name", "IamError", "code", iam.Code, "status", iam.Status, "message", iam.Message))
		}
		return core.NewObject("error", core.NewObject("name", "Error"))
	}
	if value == nil || core.IsUndefined(value) {
		return core.NewObject("value", core.NewObject("$undefined", true))
	}
	return core.NewObject("value", spectest.Model(value))
}

// sameOutcome compares outcomes; for errors that are not IamErrors only the fact of the error counts.
func sameOutcome(got, want *core.Object) bool {
	if wantError := obj(want.Get("error")); wantError != nil {
		gotError := obj(got.Get("error"))
		if gotError == nil {
			return false
		}
		if str(wantError, "name") != "IamError" {
			return true
		}
		return str(gotError, "code") == str(wantError, "code") && str(gotError, "message") == str(wantError, "message") &&
			core.StrictEquals(gotError.Get("status"), wantError.Get("status"))
	}
	return got.Has("value") && spectest.Equal(got.Get("value"), want.Get("value"))
}

func decodeValue(value any) any {
	if o := obj(value); o != nil && o.Has("$undefined") {
		return core.Undefined
	}
	return value
}

func linkBuilder(name string) func(map[string]string) string {
	return func(values map[string]string) string {
		keys := make([]string, 0, len(values))
		for key := range values {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for index, key := range keys {
			parts[index] = key + "=" + values[key]
		}
		return "https://app.test/" + name + "?" + strings.Join(parts, "&")
	}
}

func withSite(values map[string]string, site string) map[string]string {
	if site != "" {
		values["signInUrl"] = site
	}
	return values
}

func optional(values map[string]string, key, value string) {
	if value != "" {
		values[key] = value
	}
}

func templateLinks(set string) *TemplateLinks {
	links := &TemplateLinks{}
	if set == "none" {
		return links
	}
	links.Account = func(i TenantLinkInput) string {
		return linkBuilder("account")(withSite(map[string]string{"tenantId": i.TenantID}, i.SignInURL))
	}
	if set == "account" {
		return links
	}
	token := func(name string) func(TokenLinkInput) string {
		return func(i TokenLinkInput) string {
			return linkBuilder(name)(withSite(map[string]string{"tenantId": i.TenantID, "token": i.Token}, i.SignInURL))
		}
	}
	links.PasswordReset, links.VerifyEmail, links.EmailChange, links.GuestInvitation =
		token("passwordReset"), token("verifyEmail"), token("emailChange"), token("guestInvitation")
	links.Invitation = func(i InvitationLinkInput) string {
		return linkBuilder("invitation")(withSite(map[string]string{"kind": i.Kind, "tenantId": i.TenantID, "token": i.Token}, i.SignInURL))
	}
	links.MagicLink = func(i MagicLinkInput) string {
		return linkBuilder("magicLink")(withSite(map[string]string{"tenantId": i.TenantID, "token": i.Token, "destination": i.Destination}, i.SignInURL))
	}
	links.Certification = func(i CertificationLinkInput) string {
		return linkBuilder("certification")(withSite(map[string]string{"tenantId": i.TenantID, "campaignId": i.CampaignID}, i.SignInURL))
	}
	links.Delegation = func(i DelegationLinkInput) string {
		return linkBuilder("delegation")(withSite(map[string]string{"tenantId": i.TenantID, "delegationId": i.DelegationID}, i.SignInURL))
	}
	links.Team = func(i TeamLinkInput) string {
		return linkBuilder("team")(withSite(map[string]string{"tenantId": i.TenantID, "teamId": i.TeamID}, i.SignInURL))
	}
	links.Billing = func(i BillingLinkInput) string {
		values := map[string]string{"tenantId": i.TenantID}
		optional(values, "statementId", i.StatementID)
		return linkBuilder("billing")(withSite(values, i.SignInURL))
	}
	links.Privacy = func(i PrivacyLinkInput) string {
		values := map[string]string{"tenantId": i.TenantID}
		optional(values, "requestId", i.RequestID)
		if i.HasToken {
			values["token"] = i.Token
		}
		if i.Handler {
			values["handler"] = "true"
		}
		return linkBuilder("privacy")(withSite(values, i.SignInURL))
	}
	links.Threats = func(i ThreatsLinkInput) string {
		values := map[string]string{"tenantId": i.TenantID}
		optional(values, "incidentId", i.IncidentID)
		return linkBuilder("threats")(withSite(values, i.SignInURL))
	}
	links.Guests = func(i GuestsLinkInput) string {
		values := map[string]string{"tenantId": i.TenantID}
		optional(values, "guestId", i.GuestID)
		return linkBuilder("guests")(withSite(values, i.SignInURL))
	}
	links.Clearances = func(i ClearancesLinkInput) string {
		values := map[string]string{"tenantId": i.TenantID}
		optional(values, "identityId", i.IdentityID)
		return linkBuilder("clearances")(withSite(values, i.SignInURL))
	}
	return links
}

func TestDifferentialTemplates(t *testing.T) {
	for index, item := range differential(t, "templates") {
		c := obj(item)
		message := obj(c.Get("message"))
		payload := map[string]string{}
		obj(message.Get("payload")).Entries(func(key string, value any) bool {
			payload[key] = value.(string)
			return true
		})
		input := TemplateMessage{
			Template: str(message, "template"), To: str(message, "to"), Payload: payload,
			TenantID: str(message, "tenantId"), SignInURL: str(message, "signInUrl"),
		}
		options := TemplateOptions{Links: templateLinks(str(c, "links"))}
		if name, ok := c.Get("appName").(string); ok {
			options.AppName = &name
		}
		rendered, err := RenderDeliveryMessage(input, options)
		var value any = core.Undefined
		if rendered != nil {
			value = core.NewObject("subject", rendered.Subject, "text", rendered.Text, "html", rendered.HTML)
		}
		got := outcomeValue(value, err)
		want := obj(c.Get("result"))
		if !sameOutcome(got, want) {
			t.Errorf("template case %d (%s, links %s):\n  message %s\n  ts %s\n  go %s", index, input.Template, str(c, "links"),
				spectest.Show(message), spectest.Show(want), spectest.Show(got))
		}
	}
}

func TestDifferentialValidators(t *testing.T) {
	for _, item := range differential(t, "validators") {
		c := obj(item)
		value := decodeValue(c.Get("value"))
		check := func(name string, result any, err error) {
			got := outcomeValue(result, err)
			if want := obj(c.Get(name)); !sameOutcome(got, want) {
				t.Errorf("%s(%s): ts %s, go %s", name, spectest.Show(c.Get("value")), spectest.Show(want), spectest.Show(got))
			}
		}
		result, err := Text(value, "field")
		check("text", result, err)
		result, err = Text(value, "code", 6)
		check("text6", result, err)
		result, err = Email(value)
		check("email", result, err)
		result, err = Phone(value)
		check("phone", result, err)
		result, err = Password(value)
		check("password", result, err)
		result, err = DisplayName(value)
		check("displayName", result, err)
	}
}

func TestDifferentialPasswordScreening(t *testing.T) {
	for _, item := range differential(t, "passwords") {
		c := obj(item)
		value := str(c, "value")
		if common := IsCommonPassword(value); common != c.Get("common") {
			t.Errorf("isCommonPassword(%q) = %v, ts %v", value, common, c.Get("common"))
		}
		if classes := CharacterClasses(value); float64(classes) != numOr(c, "classes", -1) {
			t.Errorf("characterClasses(%q) = %d, ts %v", value, classes, c.Get("classes"))
		}
	}
	for _, item := range differential(t, "rules") {
		c := obj(item)
		var options *PasswordPolicyOptions
		if block, ok := c.Get("block").(bool); ok {
			options = &PasswordPolicyOptions{BlockCommonPasswords: &block}
		}
		err := AssertPasswordRules(str(c, "value"), obj(c.Get("policy")), options, obj(c.Get("identity")))
		got := outcomeValue(core.Undefined, err)
		if want := obj(c.Get("result")); !sameOutcome(got, want) {
			t.Errorf("assertPasswordRules(%q, %s, %s): ts %s, go %s", str(c, "value"), spectest.Show(c.Get("policy")),
				spectest.Show(c.Get("identity")), spectest.Show(want), spectest.Show(got))
		}
	}
}

func TestDifferentialUserAgents(t *testing.T) {
	for _, item := range differential(t, "describeUserAgent") {
		c := obj(item)
		want, _ := c.Get("result").(string)
		if got := DescribeUserAgent(str(c, "value")); got != want {
			t.Errorf("describeUserAgent(%q) = %q, ts %q", str(c, "value"), got, want)
		}
	}
}

func TestDifferentialSafeFetchRules(t *testing.T) {
	for _, item := range differential(t, "publicAddresses") {
		c := obj(item)
		if got := IsPublicAddress(str(c, "value")); got != c.Get("result") {
			t.Errorf("isPublicAddress(%q) = %v, ts %v", str(c, "value"), got, c.Get("result"))
		}
	}
	for _, item := range differential(t, "fetchUrls") {
		c := obj(item)
		options := obj(c.Get("options"))
		u, err := CheckFetchURL(str(c, "value"), SafeFetchAddressOptions{
			AnyPort: isTrue(options, "anyPort"), AllowInsecureLocalhost: isTrue(options, "allowInsecureLocalhost"),
			AllowPrivateNetworks: isTrue(options, "allowPrivateNetworks"),
		})
		var got *core.Object
		if err != nil {
			var refused *SafeFetchError
			errors.As(err, &refused)
			got = core.NewObject("reason", refused.Reason, "message", refused.Message)
		} else {
			got = core.NewObject("href", u.Href, "hostname", u.Hostname, "port", u.Port, "protocol", u.Protocol)
		}
		if !spectest.Equal(got, c.Get("result")) {
			t.Errorf("checkFetchUrl(%q, %s): ts %s, go %s", str(c, "value"), spectest.Show(options), spectest.Show(c.Get("result")), spectest.Show(got))
		}
	}
}

func TestDifferentialJavaScriptSemantics(t *testing.T) {
	for _, item := range differential(t, "jsNumbers") {
		c := obj(item)
		n := jsNumber(str(c, "value"))
		got := core.NumberString(n)
		if n == 0 && math.Signbit(n) {
			got = "-0"
		}
		if got != str(c, "result") {
			t.Errorf("Number(%q) = %s, ts %s", str(c, "value"), got, str(c, "result"))
		}
	}
	for _, item := range differential(t, "jsDates") {
		c := obj(item)
		ms := parseDate(str(c, "value"))
		var got *core.Object
		if dateValid(ms) {
			got = core.NewObject("value", c.Get("value"), "time", ms, "utc", utcString(ms), "iso", isoString(ms))
		} else {
			got = core.NewObject("value", c.Get("value"), "time", nil, "utc", nil, "iso", nil)
		}
		if !spectest.Equal(got, c) {
			t.Errorf("new Date(%q): ts %s, go %s", str(c, "value"), spectest.Show(c), spectest.Show(got))
		}
	}
	for _, item := range differential(t, "encodeURIs") {
		c := obj(item)
		if got := encodeURIComponent(str(c, "value")); got != str(c, "result") {
			t.Errorf("encodeURIComponent(%q) = %q, ts %q", str(c, "value"), got, str(c, "result"))
		}
	}
	for _, item := range differential(t, "base64") {
		c := obj(item)
		value := str(c, "value")
		if got := hex.EncodeToString(nodeBase64Decode(value)); got != str(c, "node") {
			t.Errorf("Buffer.from(%q, 'base64url') = %s, ts %s", value, got, str(c, "node"))
		}
		if got := hex.EncodeToString(hexagonDecode(value, true)); got != str(c, "hexagonUrl") {
			t.Errorf("isoBase64URL.toBuffer(%q) = %s, ts %s", value, got, str(c, "hexagonUrl"))
		}
		if got := hex.EncodeToString(hexagonDecode(value, false)); got != str(c, "hexagon") {
			t.Errorf("isoBase64URL.toBuffer(%q, 'base64') = %s, ts %s", value, got, str(c, "hexagon"))
		}
	}
}

func TestDifferentialCBOR(t *testing.T) {
	for _, item := range differential(t, "cbor") {
		c := obj(item)
		data, _ := hex.DecodeString(str(c, "hex"))
		var got *core.Object
		if len(data) == 0 {
			got = core.NewObject("error", true)
		} else if value, consumed, err := cborDecodeNext(data, 0, 0); err != nil {
			got = core.NewObject("error", true)
		} else if encoded, err := cborEncode(value); err != nil {
			got = core.NewObject("error", true)
		} else {
			got = core.NewObject("value", core.NewObject("consumed", float64(consumed), "encoded", hex.EncodeToString(encoded)))
		}
		want := obj(c.Get("result"))
		if want.Has("error") != got.Has("error") || (!want.Has("error") && !spectest.Equal(got.Get("value"), want.Get("value"))) {
			t.Errorf("cbor %s: ts %s, go %s", str(c, "hex"), spectest.Show(want), spectest.Show(got))
		}
	}
}

func stringList(value any) []string {
	list, _ := value.([]any)
	out := make([]string, len(list))
	for index, item := range list {
		out[index], _ = item.(string)
	}
	return out
}

func TestDifferentialWebAuthn(t *testing.T) {
	registrations, assertions := 0, 0
	for _, item := range differential(t, "webauthn") {
		c := obj(item)
		options := obj(c.Get("options"))
		want := obj(c.Get("result"))
		var got *core.Object
		switch str(c, "kind") {
		case "registration":
			registrations++
			verified, info, err := VerifyRegistrationResponse(c.Get("response"), VerifyRegistrationOptions{
				ExpectedChallenge: str(options, "expectedChallenge"), ExpectedOrigins: stringList(options.Get("expectedOrigin")),
				ExpectedRPID: str(options, "expectedRPID"), RequireUserVerification: true,
			})
			switch {
			case err != nil:
				got = core.NewObject("error", err.Error())
			case !verified:
				got = core.NewObject("verified", false)
			default:
				transports := info.Transports
				if transports == nil || core.IsUndefined(transports) {
					transports = nil
				}
				got = core.NewObject("verified", true, "info", core.NewObject(
					"fmt", info.Fmt, "aaguid", info.AAGUID, "credentialID", info.CredentialID,
					"publicKey", base64url(info.CredentialPublicKey), "counter", float64(info.Counter), "transports", transports,
					"userVerified", info.UserVerified, "deviceType", info.CredentialDeviceType, "backedUp", info.CredentialBackedUp,
					"origin", info.Origin, "rpID", info.RPID,
				))
			}
		case "authentication":
			assertions++
			credential := obj(options.Get("credential"))
			verified, info, err := VerifyAuthenticationResponse(c.Get("response"), VerifyAuthenticationOptions{
				ExpectedChallenge: str(options, "expectedChallenge"), ExpectedOrigins: stringList(options.Get("expectedOrigin")),
				ExpectedRPID: str(options, "expectedRPID"), RequireUserVerification: true,
				Credential: WebAuthnCredential{ID: str(credential, "id"), PublicKey: nodeBase64Decode(str(credential, "publicKey")),
					Counter: numOr(credential, "counter", 0)},
			})
			if err != nil {
				got = core.NewObject("error", err.Error())
			} else {
				got = core.NewObject("verified", verified, "info", core.NewObject(
					"newCounter", float64(info.NewCounter), "userVerified", info.UserVerified, "deviceType", info.CredentialDeviceType,
					"backedUp", info.CredentialBackedUp, "origin", info.Origin, "rpID", info.RPID,
				))
			}
		}
		if want.Has("error") {
			if !got.Has("error") {
				t.Errorf("%s %q: ts refused (%s), go %s", str(c, "kind"), str(c, "name"), str(want, "error"), spectest.Show(got))
			}
			continue
		}
		if !spectest.Equal(got, want) {
			t.Errorf("%s %q:\n  ts %s\n  go %s", str(c, "kind"), str(c, "name"), spectest.Show(want), spectest.Show(got))
		}
	}
	if registrations == 0 || assertions == 0 {
		t.Fatal("no WebAuthn cases")
	}
}

func TestDifferentialWebAuthnOptions(t *testing.T) {
	differential(t, "webauthn")
	shapes := obj(differentialData.Get("shapes"))
	strip := func(o *core.Object) *core.Object {
		copy := o.Spread()
		copy.Delete("challenge")
		return copy
	}
	registration, err := GenerateRegistrationOptions(RegistrationOptionsInput{
		RPName: "Better IAM", RPID: "iam.example.com", UserName: "ada@example.com", UserID: []byte("usr_123"), UserDisplayName: "Ada",
		Exclude: []WebAuthnCredentialDescriptor{{ID: "AAAA", Transports: []any{"usb"}}, {ID: "BBBB"}, {ID: "CC=="}},
	})
	if err != nil {
		t.Fatal(err)
	}
	authentication, err := GenerateAuthenticationOptions("iam.example.com", []WebAuthnCredentialDescriptor{{ID: "AAAA", Transports: []any{"internal"}}, {ID: "BBBB"}})
	if err != nil {
		t.Fatal(err)
	}
	discovery, err := GenerateAuthenticationOptions("iam.example.com", nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, got := range map[string]*core.Object{"registration": registration, "authentication": authentication, "discovery": discovery} {
		want := obj(shapes.Get(name))
		if core.MustStringify(strip(got)) != core.MustStringify(strip(want)) {
			t.Errorf("%s options:\n  ts %s\n  go %s", name, core.MustStringify(strip(want)), core.MustStringify(strip(got)))
		}
		if len(str(got, "challenge")) != 43 {
			t.Errorf("%s challenge %q", name, str(got, "challenge"))
		}
	}
}
