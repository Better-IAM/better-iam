package server

// Port of packages/server/src/api/hostnames.ts: custom sign-in hostnames. An organization claims a hostname it
// controls (`login.acme.com`), publishes the TXT record it is given, points the hostname at the deployment with a
// CNAME, and verifies it. From then on the hostname resolves to the organization like its subdomain does: requests
// there are pinned to it, its origin is trusted, and a primary hostname becomes the address in its sign-in URLs and
// email links. Needs `hosts.customHostnames`.

import (
	"context"
	"sort"
	"strconv"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

// maxHostnames is the most hostnames one organization may claim.
const maxHostnames = 20

// HostnamesAPI is the `hostnames` API group (packages/server/src/api/hostnames.ts createHostnamesApi): every method runs through the
// operation envelope; the router maps POST {basePath}/hostnames/{method} onto it.
type HostnamesAPI struct {
	server   *ServerContext
	settings *domainSettings
}

// CreateHostnamesAPI builds the `hostnames` API group.
func CreateHostnamesAPI(server *ServerContext) *HostnamesAPI {
	settings, _ := domainSettingsOf(server.Options)
	return &HostnamesAPI{server: server, settings: settings}
}

func (api *HostnamesAPI) enabled() error {
	if !api.server.Config.Hosts.CustomHostnames {
		return core.NewIamError("FEATURE_DISABLED", "Custom hostnames are not enabled on this deployment (hosts.customHostnames)")
	}
	return nil
}

// verification is the TXT record that proves the organization controls the hostname.
func (api *HostnamesAPI) verification(record *core.Object) *core.Object {
	hostname := jsString(record.Get("hostname"))
	return core.NewObject(
		"type", "TXT",
		"name", api.settings.recordName+"."+hostname,
		"value", "better-iam-hostname="+jsString(record.Get("verificationToken")),
	)
}

// present is a claimed hostname as the API returns it, with the DNS records that verify and route it.
func (api *HostnamesAPI) present(record *core.Object) *core.Object {
	config := api.server.Config
	hosts := config.Hosts
	hostname := jsString(record.Get("hostname"))
	public := core.NewObject(
		"id", record.Get("id"),
		"tenantId", record.Get("tenantId"),
		"hostname", record.Get("hostname"),
		"status", record.Get("status"),
		"primary", record.Get("primary") == true,
		"url", config.BaseURL.Protocol+"//"+hostname+hosts.SignInPath,
		"createdAt", record.Get("createdAt"),
		"createdBy", record.Get("createdBy"),
	)
	if value := record.Get("verifiedAt"); !isUndefined(value) {
		public.Set("verifiedAt", value)
	}
	if value := record.Get("lastCheckedAt"); !isUndefined(value) {
		public.Set("lastCheckedAt", value)
	}
	records := core.NewObject("verification", api.verification(record))
	if hosts.CnameTarget != "" {
		records.Set("routing", core.NewObject("type", "CNAME", "name", record.Get("hostname"), "value", hosts.CnameTarget))
	}
	public.Set("dnsRecords", records)
	return public
}

// claimResource picks the resource actions on a claim are authorized on: `hostnames/{hostname}`, so a grant can name
// the hostname. The claim is read ahead only to pick that resource: an ID that is not one of this tenant's claims is
// authorized as `hostnames/{id}` and reported missing inside the operation, after authorization, so a caller it
// refuses cannot tell whether it exists.
func (api *HostnamesAPI) claimResource(ctx context.Context, tenantID, hostnameID string) (string, error) {
	record, err := api.server.Store.Get(ctx, "tenantHostnames", hostnameID)
	if err != nil {
		return "", err
	}
	if record != nil && record.Get("tenantId") == tenantID {
		return "hostnames/" + jsString(record.Get("hostname")), nil
	}
	return "hostnames/" + hostnameID, nil
}

// authorizedClaim is the claim inside an operation: this tenant's, and the one its authorized resource names.
func (api *HostnamesAPI) authorizedClaim(ctx context.Context, tx core.IamStore, tenantID, hostnameID, resourceID string) (*core.Object, error) {
	record, err := api.server.Scoped(ctx, tx, "tenantHostnames", hostnameID, tenantID)
	if err != nil {
		return nil, err
	}
	if "hostnames/"+jsString(record.Get("hostname")) != resourceID {
		return nil, core.NewIamError("NOT_FOUND", "Resource not found", 404)
	}
	return record, nil
}

func hostnameTaken() *core.IamError {
	return core.NewIamError("HOSTNAME_TAKEN", "Another organization verified this hostname", 409)
}

// Add is POST {basePath}/hostnames/add. Claims a hostname for the organization and returns the DNS records that verify and route it.
// Requires iam:hostnames:create. Hostnames the deployment uses itself (its base URL and its subdomain space) are
// refused.
func (api *HostnamesAPI) Add(ctx context.Context, credential core.CredentialInput, input In[apitypes.HostnamesAddInput]) (Out[apitypes.HostnamesAddOutput], error) {
	server := api.server
	if err := api.enabled(); err != nil {
		return Out[apitypes.HostnamesAddOutput]{}, err
	}
	hostname, err := DomainName(input.Get("hostname"))
	if err != nil {
		return Out[apitypes.HostnamesAddOutput]{}, err
	}
	if err := server.Hosts.AssertClaimable(hostname); err != nil {
		return Out[apitypes.HostnamesAddOutput]{}, err
	}
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:hostnames:create", "hostnames/"+hostname, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		existing, err := tx.Find(ctx, "tenantHostnames", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		for _, record := range existing {
			if record.Get("hostname") == hostname {
				return nil, core.NewIamError("CONFLICT", "This organization already claimed the hostname", 409)
			}
		}
		if len(existing) >= maxHostnames {
			return nil, core.NewIamError("LIMIT_EXCEEDED", "An organization can claim at most "+strconv.Itoa(maxHostnames)+" hostnames", 409)
		}
		owner, err := tx.Get(ctx, "hostnameOwners", hostname)
		if err != nil {
			return nil, err
		}
		if owner != nil && owner.Get("tenantId") != tenantID {
			return nil, hostnameTaken()
		}
		record, err := tx.Insert(ctx, "tenantHostnames", core.NewObject(
			"id", ID(),
			"tenantId", tenantID,
			"uniqueKey", hostname,
			"hostname", hostname,
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
	return Out[apitypes.HostnamesAddOutput]{Value: result}, err
}

// Delete is POST {basePath}/hostnames/delete. Releases a hostname; a verified one stops resolving to the organization at once.
// Requires iam:hostnames:delete.
func (api *HostnamesAPI) Delete(ctx context.Context, credential core.CredentialInput, input In[apitypes.HostnamesDeleteInput]) (Out[apitypes.HostnamesDeleteOutput], error) {
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.HostnamesDeleteOutput]{}, err
	}
	hostnameID, err := Text(input.Get("hostnameId"), "hostnameId")
	if err != nil {
		return Out[apitypes.HostnamesDeleteOutput]{}, err
	}
	resourceID, err := api.claimResource(ctx, tenantID, hostnameID)
	if err != nil {
		return Out[apitypes.HostnamesDeleteOutput]{}, err
	}
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:hostnames:delete", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		current, err := api.authorizedClaim(ctx, tx, tenantID, hostnameID, resourceID)
		if err != nil {
			return nil, err
		}
		hostname := jsString(current.Get("hostname"))
		owner, err := tx.Get(ctx, "hostnameOwners", hostname)
		if err != nil {
			return nil, err
		}
		if owner != nil && owner.Get("tenantId") == tenantID {
			if err := tx.Delete(ctx, "hostnameOwners", hostname); err != nil {
				return nil, err
			}
		}
		if err := tx.Delete(ctx, "tenantHostnames", jsString(current.Get("id"))); err != nil {
			return nil, err
		}
		return core.NewObject("deleted", true), nil
	}, false)
	return Out[apitypes.HostnamesDeleteOutput]{Value: result}, err
}

// List is POST {basePath}/hostnames/list. Lists the organization's claimed hostnames, newest first, with their status and DNS records.
// Requires iam:hostnames:read.
func (api *HostnamesAPI) List(ctx context.Context, credential core.CredentialInput, input In[apitypes.HostnamesListInput]) (Out[apitypes.HostnamesListOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := Operate(ctx, api.server.Operations, credential, tenantID, "iam:hostnames:read", "hostnames/*", func(ctx context.Context, call MutationContext) ([]any, error) {
		records, err := call.Tx.Find(ctx, "tenantHostnames", core.NewObject("tenantId", tenantID), nil)
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
	return Out[apitypes.HostnamesListOutput]{Value: result}, err
}

// SetPrimary is POST {basePath}/hostnames/setPrimary. Makes a verified hostname the organization's canonical sign-in address, or goes back to its subdomain.
// Sign-in URLs and email links use the primary hostname; `hostnameId: null` goes back to the subdomain. Requires
// iam:hostnames:update.
func (api *HostnamesAPI) SetPrimary(ctx context.Context, credential core.CredentialInput, input In[apitypes.HostnamesSetPrimaryInput]) (Out[apitypes.HostnamesSetPrimaryOutput], error) {
	server := api.server
	if err := api.enabled(); err != nil {
		return Out[apitypes.HostnamesSetPrimaryOutput]{}, err
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.HostnamesSetPrimaryOutput]{}, err
	}
	hostnameID, hasHostname := "", false
	if raw := input.Get("hostnameId"); raw != nil {
		if hostnameID, err = Text(raw, "hostnameId"); err != nil {
			return Out[apitypes.HostnamesSetPrimaryOutput]{}, err
		}
		hasHostname = true
	}
	resourceID := "hostnames/*"
	if hasHostname {
		if resourceID, err = api.claimResource(ctx, tenantID, hostnameID); err != nil {
			return Out[apitypes.HostnamesSetPrimaryOutput]{}, err
		}
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:hostnames:update", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		var target *core.Object
		if hasHostname {
			claim, err := api.authorizedClaim(ctx, tx, tenantID, hostnameID, resourceID)
			if err != nil {
				return nil, err
			}
			target = claim
		}
		if target != nil && target.Get("status") != "verified" {
			return nil, invalidInput("Verify the hostname before making it primary")
		}
		records, err := tx.Find(ctx, "tenantHostnames", core.NewObject("tenantId", tenantID), nil)
		if err != nil {
			return nil, err
		}
		for _, record := range records {
			primary := target != nil && record.Get("id") == target.Get("id")
			if (record.Get("primary") == true) == primary {
				continue
			}
			rest := record.Spread()
			rest.Delete("primary")
			if primary {
				rest.Set("primary", primary)
			}
			if _, err := tx.Put(ctx, "tenantHostnames", rest); err != nil {
				return nil, err
			}
		}
		var primary any
		if target != nil {
			primary = api.present(target.Spread(core.NewObject("primary", true, "status", "verified")))
		}
		signInURL, err := server.Hosts.SignInURL(ctx, tenantID, tx)
		if err != nil {
			return nil, err
		}
		var signIn any
		if signInURL != "" {
			signIn = signInURL
		}
		return core.NewObject("primary", primary, "signInUrl", signIn), nil
	}, false)
	return Out[apitypes.HostnamesSetPrimaryOutput]{Value: result}, err
}

// Verify is POST {basePath}/hostnames/verify. Looks up the hostname's TXT record and, when it matches, marks the hostname verified so it starts resolving to the organization.
// DNS is queried before the transaction opens, and only for a caller allowed to verify the claim; `verified: false`
// means the record is not visible yet. Requires iam:hostnames:update.
func (api *HostnamesAPI) Verify(ctx context.Context, credential core.CredentialInput, input In[apitypes.HostnamesVerifyInput]) (Out[apitypes.HostnamesVerifyOutput], error) {
	server := api.server
	if err := api.enabled(); err != nil {
		return Out[apitypes.HostnamesVerifyOutput]{}, err
	}
	tenantID, err := Text(input.Get("tenantId"), "tenantId")
	if err != nil {
		return Out[apitypes.HostnamesVerifyOutput]{}, err
	}
	hostnameID, err := Text(input.Get("hostnameId"), "hostnameId")
	if err != nil {
		return Out[apitypes.HostnamesVerifyOutput]{}, err
	}
	resourceID, err := api.claimResource(ctx, tenantID, hostnameID)
	if err != nil {
		return Out[apitypes.HostnamesVerifyOutput]{}, err
	}
	found := false
	permitted, err := PermittedAhead(ctx, server, credential, tenantID, "iam:hostnames:update", resourceID)
	if err != nil {
		return Out[apitypes.HostnamesVerifyOutput]{}, err
	}
	if permitted {
		record, err := server.Store.Get(ctx, "tenantHostnames", hostnameID)
		if err != nil {
			return Out[apitypes.HostnamesVerifyOutput]{}, err
		}
		if record != nil && record.Get("tenantId") == tenantID && record.Get("status") != "verified" {
			if err := server.Hosts.AssertClaimable(jsString(record.Get("hostname"))); err != nil {
				return Out[apitypes.HostnamesVerifyOutput]{}, err
			}
			expected := api.verification(record)
			answers, err := api.settings.lookup(ctx, jsString(expected.Get("name")))
			found = err == nil && txtMatches(answers, jsString(expected.Get("value")))
		}
	}
	result, err := Operate(ctx, server.Operations, credential, tenantID, "iam:hostnames:update", resourceID, func(ctx context.Context, call MutationContext) (*core.Object, error) {
		tx := call.Tx
		current, err := api.authorizedClaim(ctx, tx, tenantID, hostnameID, resourceID)
		if err != nil {
			return nil, err
		}
		if current.Get("status") == "verified" {
			return core.NewObject("verified", true, "hostname", api.present(current)), nil
		}
		now := float64(server.Now())
		if !found {
			checked, err := tx.Put(ctx, "tenantHostnames", current.Spread(core.NewObject("lastCheckedAt", now)))
			if err != nil {
				return nil, err
			}
			return core.NewObject("verified", false, "hostname", api.present(checked)), nil
		}
		hostname := jsString(current.Get("hostname"))
		owner, err := tx.Get(ctx, "hostnameOwners", hostname)
		if err != nil {
			return nil, err
		}
		if owner != nil && owner.Get("tenantId") != tenantID {
			return nil, hostnameTaken()
		}
		if owner == nil {
			if _, err := tx.Insert(ctx, "hostnameOwners", core.NewObject(
				"id", hostname,
				"tenantId", tenantID,
				"hostnameId", current.Get("id"),
				"verifiedAt", now,
			)); err != nil {
				return nil, err
			}
		}
		verified, err := tx.Put(ctx, "tenantHostnames", current.Spread(core.NewObject("status", "verified", "verifiedAt", now, "lastCheckedAt", now)))
		if err != nil {
			return nil, err
		}
		return core.NewObject("verified", true, "hostname", api.present(verified)), nil
	}, false)
	return Out[apitypes.HostnamesVerifyOutput]{Value: result}, err
}
