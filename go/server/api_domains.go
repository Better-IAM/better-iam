package server

// Port of packages/server/src/api/domains.ts: verified email domains and home-realm discovery. An organization claims
// a domain, publishes the TXT record it is given, and verifies it; a verified domain is owned by exactly one tenant,
// and `discover` maps an email address to that tenant (and its sign-in requirements) so login screens need neither a
// tenant ID nor a slug.

import (
	"context"
	"crypto/rand"
	"net"
	"regexp"
	"sort"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

var consumerDomains = []string{
	"gmail.com",
	"googlemail.com",
	"outlook.com",
	"hotmail.com",
	"live.com",
	"msn.com",
	"yahoo.com",
	"ymail.com",
	"aol.com",
	"icloud.com",
	"me.com",
	"mac.com",
	"proton.me",
	"protonmail.com",
	"pm.me",
	"gmx.com",
	"gmx.net",
	"mail.com",
	"yandex.com",
	"yandex.ru",
	"zoho.com",
	"fastmail.com",
	"hey.com",
	"qq.com",
	"163.com",
}

// topLevelDomain is /^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$/.
var topLevelDomain = regexp.MustCompile(`^(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$`)

// recordLabel is /^[a-z0-9_-]{1,63}$/i.
var recordLabel = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,63}$`)

// DomainName (api/domains.ts domainName): Normalizes and validates a registrable-looking DNS name: lowercase, no
// trailing dot, alphabetic TLD.
func DomainName(value any) (result string, err error) {
	raw, err := Text(value, "domain", 253)
	if err != nil {
		return "", err
	}
	domain := strings.TrimSuffix(core.JSLower(core.JSTrim(raw)), ".")
	labels := strings.Split(domain, ".")
	valid := len(labels) >= 2 && utf16Len(domain) <= 253
	if valid {
		for _, part := range labels {
			if !hostnameLabel(part) {
				valid = false
				break
			}
		}
	}
	if !valid || !topLevelDomain.MatchString(labels[len(labels)-1]) {
		return "", invalidInput("Enter a domain such as example.com")
	}
	return domain, nil
}

// PermittedAhead (api/domains.ts permittedAhead): The decision `operation` makes (`action` on `iam/{resourceId}`),
// taken ahead of work that must happen outside its transaction, such as a DNS query, so that work is done only for a
// caller the operation will admit. A refusal is not recorded here: the operation that follows refuses the caller
// again and records it.
func PermittedAhead(ctx context.Context, server *ServerContext, credential core.CredentialInput, tenantID string, action string, resourceID string) (result bool, err error) {
	authenticated, err := server.Principals.Authenticate(ctx, credential)
	if err != nil {
		return false, err
	}
	return core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (bool, error) {
		current, err := server.Principals.CurrentPrincipal(ctx, tx, authenticated)
		if err != nil {
			return false, err
		}
		decision, err := server.Decisions.Decide(ctx, tx, current, AuthorizationRequest{
			TenantID: tenantID, Action: action, Resource: ResourceTarget{Type: "iam", ID: resourceID},
		}, true)
		if err != nil {
			return false, err
		}
		return decision.Allowed, nil
	})
}

// txtLookup is the TXT lookup of the domain options (domains.resolveTxt), returning each record as its chunks.
type txtLookup func(ctx context.Context, hostname string) ([][]string, error)

// systemResolveTxt is the default TXT lookup (node:dns/promises resolveTxt): the system resolver joins each record's
// chunks, so every record is one chunk.
func systemResolveTxt(ctx context.Context, hostname string) ([][]string, error) {
	records, err := net.DefaultResolver.LookupTXT(ctx, hostname)
	if err != nil {
		return nil, err
	}
	chunks := make([][]string, len(records))
	for index, record := range records {
		chunks[index] = []string{record}
	}
	return chunks, nil
}

// domainSettings are the resolved domain options of createDomainsApi / createHostnamesApi.
type domainSettings struct {
	recordName string
	blocked    map[string]bool
	lookup     txtLookup
}

// domainSettingsOf resolves the `domains` option; a record name that is not a single DNS label fails with
// INVALID_CONFIG (createDomainsApi refuses it when the server is composed).
func domainSettingsOf(options *BetterIamOptions) (*domainSettings, error) {
	settings := &DomainOptions{}
	if options != nil && options.Domains != nil {
		settings = options.Domains
	}
	resolved := &domainSettings{recordName: "_better-iam-challenge", blocked: map[string]bool{}, lookup: systemResolveTxt}
	if settings.RecordName != nil {
		resolved.recordName = *settings.RecordName
	}
	blocked := consumerDomains
	if settings.BlockedDomains != nil {
		blocked = settings.BlockedDomains
	}
	for _, domain := range blocked {
		resolved.blocked[core.JSLower(domain)] = true
	}
	if settings.ResolveTxt != nil {
		resolved.lookup = settings.ResolveTxt
	}
	if !recordLabel.MatchString(resolved.recordName) {
		return resolved, invalidConfig("domains.recordName must be a single DNS label")
	}
	return resolved, nil
}

// CheckDomainOptions validates the `domains` option the way createDomainsApi does when the API is built.
func CheckDomainOptions(options *BetterIamOptions) error {
	_, err := domainSettingsOf(options)
	return err
}

// verificationToken is randomBytes(18).toString('base64url').
func verificationToken() string {
	bytes := make([]byte, 18)
	if _, err := rand.Read(bytes); err != nil {
		panic(err)
	}
	return base64url(bytes)
}

// txtMatches reports whether any TXT record (its chunks joined and trimmed) equals the expected value.
func txtMatches(records [][]string, expected string) bool {
	for _, chunks := range records {
		if core.JSTrim(strings.Join(chunks, "")) == expected {
			return true
		}
	}
	return false
}

// DomainsAPI is the `domains` API group (packages/server/src/api/domains.ts createDomainsApi): every method runs through the
// operation envelope; the router maps POST {basePath}/domains/{method} onto it.
type DomainsAPI struct {
	server   *ServerContext
	settings *domainSettings
}

// CreateDomainsAPI builds the `domains` API group. The `domains` option is validated by CheckDomainOptions when the
// server is composed.
func CreateDomainsAPI(server *ServerContext) *DomainsAPI {
	settings, _ := domainSettingsOf(server.Options)
	return &DomainsAPI{server: server, settings: settings}
}

func (api *DomainsAPI) instructions(record *core.Object) *core.Object {
	return core.NewObject(
		"type", "TXT",
		"name", api.settings.recordName+"."+jsString(record.Get("domain")),
		"value", "better-iam-verification="+jsString(record.Get("verificationToken")),
	)
}

func (api *DomainsAPI) present(record *core.Object) *core.Object {
	return core.NewObject(
		"id", record.Get("id"),
		"tenantId", record.Get("tenantId"),
		"domain", record.Get("domain"),
		"status", record.Get("status"),
		"createdAt", record.Get("createdAt"),
		"createdBy", record.Get("createdBy"),
		"verifiedAt", record.Get("verifiedAt"),
		"lastCheckedAt", record.Get("lastCheckedAt"),
		"dnsRecord", api.instructions(record),
	)
}

// claimResource picks the resource actions on a claim are authorized on: `domains/{domain}`, so a grant can name the
// domain. The claim is read ahead only to pick that resource: an ID that is not one of this tenant's claims is
// authorized as `domains/{id}` and reported missing inside the operation, after authorization, so a caller it
// refuses cannot tell whether it exists.
func (api *DomainsAPI) claimResource(ctx context.Context, tenantID, domainID string) (string, error) {
	record, err := api.server.Store.Get(ctx, "tenantDomains", domainID)
	if err != nil {
		return "", err
	}
	if record != nil && record.Get("tenantId") == tenantID {
		return "domains/" + jsString(record.Get("domain")), nil
	}
	return "domains/" + domainID, nil
}

// authorizedClaim is the claim inside an operation: this tenant's, and the one its authorized resource names.
func (api *DomainsAPI) authorizedClaim(ctx context.Context, tx core.IamStore, tenantID, domainID, resourceID string) (*core.Object, error) {
	record, err := api.server.Scoped(ctx, tx, "tenantDomains", domainID, tenantID)
	if err != nil {
		return nil, err
	}
	if "domains/"+jsString(record.Get("domain")) != resourceID {
		return nil, core.NewIamError("NOT_FOUND", "Resource not found", 404)
	}
	return record, nil
}

func domainTaken() *core.IamError {
	return core.NewIamError("DOMAIN_TAKEN", "Another organization verified this domain", 409)
}

// Add is POST {basePath}/domains/add. Claims a domain for the tenant and returns the TXT record the organization must publish to prove control.
// Requires iam:domains:create.
func (api *DomainsAPI) Add(ctx context.Context, credential core.CredentialInput, input In[apitypes.DomainsAddInput]) (Out[apitypes.DomainsAddOutput], error) {
	server := api.server
	domain, err := DomainName(input.Get("domain"))
	if err != nil {
		return Out[apitypes.DomainsAddOutput]{}, err
	}
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:domains:create", "domains/"+domain, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		if api.settings.blocked[domain] {
			return nil, core.NewIamError("DOMAIN_NOT_ALLOWED", "Shared mailbox providers cannot be claimed by an organization")
		}
		claimed, err := tx.Find(ctx, "tenantDomains", core.NewObject("tenantId", tenantID, "domain", domain), nil)
		if err != nil {
			return nil, err
		}
		if len(claimed) > 0 {
			return nil, core.NewIamError("CONFLICT", "This organization already claimed the domain", 409)
		}
		owner, err := tx.Get(ctx, "domainOwners", domain)
		if err != nil {
			return nil, err
		}
		if owner != nil && owner.Get("tenantId") != tenantID {
			return nil, domainTaken()
		}
		record, err := tx.Insert(ctx, "tenantDomains", core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"uniqueKey", domain,
			"domain", domain,
			"status", "pending",
			"verificationToken", verificationToken(),
			"createdAt", float64(server.Now()),
			"createdBy", call.Principal.Identity.Get("id"),
		))
		if err != nil {
			return nil, err
		}
		return api.present(record), nil
	}, false)
	return Out[apitypes.DomainsAddOutput]{Value: result}, err
}

// Delete is POST {basePath}/domains/delete. Releases a domain claim; a verified domain stops resolving to the tenant immediately.
// Requires iam:domains:delete.
func (api *DomainsAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.DomainsDeleteInput]) (Out[apitypes.DomainsDeleteOutput], error) {
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.DomainsDeleteOutput]{}, err
	}
	domainID, err := Text(input.Get("domainId"), "domainId")
	if err != nil {
		return Out[apitypes.DomainsDeleteOutput]{}, err
	}
	resourceID, err := api.claimResource(ctx, tenantID, domainID)
	if err != nil {
		return Out[apitypes.DomainsDeleteOutput]{}, err
	}
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:domains:delete", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		record, err := api.authorizedClaim(ctx, tx, tenantID, domainID, resourceID)
		if err != nil {
			return nil, err
		}
		domain := jsString(record.Get("domain"))
		owner, err := tx.Get(ctx, "domainOwners", domain)
		if err != nil {
			return nil, err
		}
		if owner != nil && owner.Get("tenantId") == tenantID {
			if err := tx.Delete(ctx, "domainOwners", domain); err != nil {
				return nil, err
			}
		}
		if err := tx.Delete(ctx, "tenantDomains", jsString(record.Get("id"))); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	return Out[apitypes.DomainsDeleteOutput]{Value: result}, err
}

// Discover is POST {basePath}/domains/discover (public: no request credential). Finds the organization that verified an email address's domain, with the sign-in rules it enforces.
// Unknown, unverified, and inactive domains are indistinguishable (404).
func (api *DomainsAPI) Discover(ctx context.Context, input In[apitypes.DomainsDiscoverInput]) (Out[apitypes.DomainsDiscoverOutput], error) {
	server := api.server
	email := input.Get("email")
	raw := input.Get("domain")
	if !isUndefined(email) {
		address, err := Text(email, "email", 320)
		if err != nil {
			return Out[apitypes.DomainsDiscoverOutput]{}, err
		}
		parts := strings.Split(core.JSTrim(address), "@")
		raw = parts[len(parts)-1]
		if !strings.Contains(address, "@") {
			return Out[apitypes.DomainsDiscoverOutput]{}, invalidInput("Enter an email address")
		}
	}
	domain, err := DomainName(raw)
	if err != nil {
		return Out[apitypes.DomainsDiscoverOutput]{}, err
	}
	result, err := core.Transact(ctx, server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		owner, err := tx.Get(ctx, "domainOwners", domain)
		if err != nil {
			return nil, err
		}
		var realm *core.Object
		if owner != nil {
			if realm, err = tx.Get(ctx, "tenants", jsString(owner.Get("tenantId"))); err != nil {
				return nil, err
			}
		}
		missing := realm == nil || realm.Get("status") != "active"
		if !missing {
			chain, err := server.Ancestry(ctx, tx, realm)
			if err != nil {
				return nil, err
			}
			for _, item := range chain {
				if item.Get("status") != "active" {
					missing = true
					break
				}
			}
		}
		if missing {
			return nil, core.NewIamError("NOT_FOUND", "No organization uses this domain", 404)
		}
		// In a multi-region deployment, people of an organization homed elsewhere are sent to its region.
		if err := server.Hosts.AssertServedHere(ctx, tx, realm, ""); err != nil {
			return nil, err
		}
		region, err := server.Hosts.RegionOf(ctx, tx, realm)
		if err != nil {
			return nil, err
		}
		signInURL, err := server.Hosts.SignInURL(ctx, realm, tx)
		if err != nil {
			return nil, err
		}
		discovery := core.NewObject(
			"domain", domain,
			"tenantId", realm.Get("id"),
			"name", realm.Get("name"),
			"type", realm.Get("type"),
		)
		if slug := realm.Get("slug"); truthy(slug) {
			discovery.Set("slug", slug)
		}
		discovery.Set("allowedMethods", coalesce(member(realm.Get("authPolicy"), "allowedMethods"), nil))
		discovery.Set("requireMfa", member(realm.Get("authPolicy"), "requireMfa") == true)
		if region != "" {
			discovery.Set("region", region)
		}
		if signInURL != "" {
			discovery.Set("signInUrl", signInURL)
		}
		return discovery, nil
	})
	if err != nil {
		return Out[apitypes.DomainsDiscoverOutput]{}, err
	}
	return Out[apitypes.DomainsDiscoverOutput]{Value: result}, nil
}

// List is POST {basePath}/domains/list. Lists the tenant's claimed domains, newest first, with their status and the TXT record each one needs.
func (api *DomainsAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.DomainsListInput]) (Out[apitypes.DomainsListOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:domains:read", "domains/*", func(ctx context.Context, call MutationContext) ([]any, error) {
		records, err := call.Tx.Find(ctx, "tenantDomains", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		sort.SliceStable(records, func(i, j int) bool { return ByNewest(records[i], records[j]) < 0 })
		list := make([]any, len(records))
		for index, record := range records {
			list[index] = api.present(record)
		}
		return list, nil
	}, false)
	return Out[apitypes.DomainsListOutput]{Value: result}, err
}

// Verify is POST {basePath}/domains/verify. Looks up the domain's TXT record and marks the claim verified when the record matches.
// DNS is queried before the transaction opens, and only for a caller allowed to verify the claim; the result reports
// `verified: false` (and the expected record) while it is not yet visible.
func (api *DomainsAPI) Verify(ctx context.Context, credential core.CredentialInput, input In[apitypes.DomainsVerifyInput]) (Out[apitypes.DomainsVerifyOutput], error) {
	server := api.server
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.DomainsVerifyOutput]{}, err
	}
	domainID, err := Text(input.Get("domainId"), "domainId")
	if err != nil {
		return Out[apitypes.DomainsVerifyOutput]{}, err
	}
	resourceID, err := api.claimResource(ctx, tenantID, domainID)
	if err != nil {
		return Out[apitypes.DomainsVerifyOutput]{}, err
	}
	found := false
	permitted, err := PermittedAhead(ctx, server, credential, tenantID, "iam:domains:update", resourceID)
	if err != nil {
		return Out[apitypes.DomainsVerifyOutput]{}, err
	}
	if permitted {
		claimed, err := server.Store.Get(ctx, "tenantDomains", domainID)
		if err != nil {
			return Out[apitypes.DomainsVerifyOutput]{}, err
		}
		if claimed != nil && claimed.Get("tenantId") == tenantID && claimed.Get("status") != "verified" {
			expected := api.instructions(claimed)
			records, err := api.settings.lookup(ctx, jsString(expected.Get("name")))
			found = err == nil && txtMatches(records, jsString(expected.Get("value")))
		}
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:domains:update", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		record, err := api.authorizedClaim(ctx, tx, tenantID, domainID, resourceID)
		if err != nil {
			return nil, err
		}
		if record.Get("status") == "verified" {
			return core.NewObject("verified", true, "domain", api.present(record)), nil
		}
		now := float64(server.Now())
		if !found {
			checked, err := tx.Put(ctx, "tenantDomains", record.Spread(core.NewObject("lastCheckedAt", now)))
			if err != nil {
				return nil, err
			}
			return core.NewObject("verified", false, "domain", api.present(checked)), nil
		}
		domain := jsString(record.Get("domain"))
		owner, err := tx.Get(ctx, "domainOwners", domain)
		if err != nil {
			return nil, err
		}
		if owner != nil && owner.Get("tenantId") != tenantID {
			return nil, domainTaken()
		}
		if owner == nil {
			if _, err := tx.Insert(ctx, "domainOwners", core.NewObject(
				"id", domain,
				"tenantId", tenantID,
				"domainId", record.Get("id"),
				"verifiedAt", now,
			)); err != nil {
				return nil, err
			}
		}
		verified, err := tx.Put(ctx, "tenantDomains", record.Spread(core.NewObject("status", "verified", "verifiedAt", now, "lastCheckedAt", now)))
		if err != nil {
			return nil, err
		}
		return core.NewObject("verified", true, "domain", api.present(verified)), nil
	}, false)
	return Out[apitypes.DomainsVerifyOutput]{Value: result}, err
}
