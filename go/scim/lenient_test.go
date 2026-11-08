package scim

// Port of the "SCIM attributes the service does not store" part of tests/federation-import-gaps.test.ts (lenient
// attribute handling, attributes.go).

import (
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
)

const customSchema = "urn:ietf:params:scim:schemas:extension:acme:2.0:User"

func TestLenientIgnoresReadOnlyAndUnsupportedAttributesAndForeignExtensions(t *testing.T) {
	d := newDirectory(t, nil)
	// An Entra ID style create: defaults Better IAM has no place for, plus read-only attributes echoed back.
	created := d.request("Users", "POST", obj(
		"schemas", list(UserSchema, EnterpriseSchema, customSchema),
		"id", "client-chosen",
		"meta", obj("resourceType", "User"),
		"groups", list(obj("value", "g1")),
		"userName", "ada@acme.test",
		"active", true,
		"displayName", "Ada",
		"preferredLanguage", "en-US",
		"locale", "en-US",
		"password", "never stored",
		"addresses", list(obj("type", "work", "formatted", "1 Main St", "primary", true)),
		"phoneNumbers", list(obj("type", "work", "value", "+1 555 0100")),
		"emails", list(obj("value", "ada@acme.test", "type", "work", "primary", true)),
		EnterpriseSchema, obj("department", "Finance"),
		customSchema, obj("badge", "gold"),
	))
	if created.status != 201 {
		t.Fatalf("create: %d %s", created.status, show(created.body))
	}
	user := created.object()
	id := user.Get("id").(string)
	if id == "client-chosen" || user.Has("addresses") || user.Has("preferredLanguage") || strings.Contains(show(user.Get("schemas")), customSchema) {
		t.Fatalf("created: %s", show(user))
	}
	sameJSON(t, user.Get(EnterpriseSchema), obj("department", "Finance"))
	if strings.Contains(show(get(t, d.store, "scimUsers", id)), "never stored") {
		t.Fatal("stored the password")
	}

	// PUT with the full resource as the IdP last saw it (id and meta included).
	replaced := d.request("Users/"+id, "PUT", user.Spread(obj("displayName", "Ada Lovelace", "phoneNumbers", list(obj("type", "mobile", "value", "+1 555 0101")))))
	if replaced.status != 200 || replaced.get("displayName") != "Ada Lovelace" {
		t.Fatalf("put: %d %s", replaced.status, show(replaced.body))
	}

	// Entra PATCH: unsupported paths (value filters, core-qualified names, pathless values) are skipped, supported
	// ones in the same request still apply.
	patched := d.request("Users/"+id, "PATCH", patchOp(
		obj("op", "replace", "path", `phoneNumbers[type eq "work"].value`, "value", "+1 555 0199"),
		obj("op", "replace", "path", `addresses[type eq "work"].formatted`, "value", "2 Main St"),
		obj("op", "add", "path", UserSchema+":preferredLanguage", "value", "fr-FR"),
		obj("op", "replace", "path", customSchema+":badge", "value", "silver"),
		obj("op", "replace", "value", obj("title", "Controller", "locale", "fr-FR", "meta", obj())),
		obj("op", "replace", "path", EnterpriseSchema+":department", "value", "Treasury"),
		obj("op", "remove", "path", "addresses"),
	))
	if patched.status != 200 || patched.get("title") != "Controller" || patched.object().Has("locale") {
		t.Fatalf("patch: %d %s", patched.status, show(patched.body))
	}
	sameJSON(t, patched.get(EnterpriseSchema), obj("department", "Treasury"))

	// Attributes no supported schema defines are still errors, so typos are not silently dropped.
	for _, body := range []*core.Object{
		obj("userName", "ada@acme.test", "badge", "gold"),
		obj("userName", "ada@acme.test", EnterpriseSchema, obj("badge", "gold")),
		obj("userName", "ada@acme.test", "name", obj("nickname", "A")),
	} {
		refused := d.request("Users/"+id, "PUT", body)
		if refused.status != 400 || refused.get("scimType") != "mutability" {
			t.Fatalf("%s: %d %s", show(body), refused.status, show(refused.body))
		}
	}
	if bad := d.request("Users/"+id, "PATCH", patchOp(obj("op", "replace", "path", "badge", "value", "x"))); bad.status != 400 {
		t.Fatalf("bad path: %d", bad.status)
	}
}

func TestLenientRejectsUnsupportedAttributesWhenConfiguredStillIgnoringReadOnlyOnes(t *testing.T) {
	d := newDirectory(t, func(config *Config) { config.UnsupportedAttributes = "reject" })
	refused := d.request("Users", "POST", obj("userName", "ada@acme.test", "addresses", list(obj("formatted", "1 Main St"))))
	if refused.status != 400 || refused.get("scimType") != "mutability" {
		t.Fatalf("addresses: %d %s", refused.status, show(refused.body))
	}
	if foreign := d.request("Users", "POST", obj("schemas", list(UserSchema, customSchema), "userName", "ada@acme.test")); foreign.status != 400 {
		t.Fatalf("foreign schema: %d", foreign.status)
	}
	created := d.request("Users", "POST", obj("id", "ignored", "meta", obj("resourceType", "User"), "userName", "ada@acme.test"))
	if created.status != 201 {
		t.Fatalf("create: %d %s", created.status, show(created.body))
	}
	if patch := d.request("Users/"+created.get("id").(string), "PATCH", patchOp(obj("op", "replace", "path", "preferredLanguage", "value", "en"))); patch.status != 400 {
		t.Fatalf("patch: %d", patch.status)
	}
	config := hostConfig(d.iam)
	config.UnsupportedAttributes = "drop"
	if _, err := NewService(config); err == nil || !strings.Contains(err.Error(), "unsupportedAttributes") {
		t.Fatalf("drop: %v", err)
	}
}
