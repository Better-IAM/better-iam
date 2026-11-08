package server

// Port of packages/server/src/api/pki.ts: the private certificate authority (pki.go). Authorities are
// `iam/pki/{authorityId}`; issuing decides `iam:pki:issue` once for every name on the certificate (the common name and
// each subject alternative name), with `resource.name` and `resource.nameType` (`commonName`, `dns`, `wildcard`,
// `uri`, `ip`, `email`) plus the authority's attributes and `resource.usage`, `resource.validitySeconds` and
// `resource.keyType`, so policies can say which names a caller may certify. Workload certificates
// (`requestCertificate`) name the caller's own identity as a SPIFFE ID and need `iam:pki:request`. Signing keys are
// KMS keys, pinned to one version per authority.

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"math"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/Better-IAM/better-iam/go/apitypes"
	"github.com/Better-IAM/better-iam/go/core"
)

const (
	pkiDayMs       = 86_400_000
	pkiClockSkewMs = 60_000
)

// pkiTarget is a guarded pki resource, with the authority it names once located.
type pkiTarget struct {
	GuardTarget
	authority *core.Object
}

// PkiAPI is the `pki` API group (packages/server/src/api/pki.ts createPkiApi): every method runs through the
// guard envelope; the router maps POST {basePath}/pki/{method} onto it.
type PkiAPI struct {
	server *ServerContext
	guard  *Guard[pkiTarget]
}

// CreatePkiAPI builds the `pki` API group.
func CreatePkiAPI(server *ServerContext) *PkiAPI {
	guard := CreateGuard(server, "pki", GuardOptions[pkiTarget]{
		Describe: func(target pkiTarget) *core.Object {
			if target.authority != nil {
				return core.NewObject("authorityId", target.authority.Get("id"))
			}
			return core.NewObject()
		},
		// Refusals after authorization are evidence too.
		RecordedFailures: map[string]string{
			"NAME_NOT_PERMITTED":    "name-not-permitted",
			"INVALID_CSR":           "invalid-csr",
			"INVALID_INPUT":         "invalid-input",
			"AUTHORITY_UNAVAILABLE": "authority-unavailable",
			"KEY_STATE_INVALID":     "key-state",
		},
	})
	return &PkiAPI{server: server, guard: guard}
}

// pkiValidityDays is api/pki.ts validityDays.
func pkiValidityDays(value any, fallback float64, max float64) (float64, error) {
	if isUndefined(value) {
		return fallback, nil
	}
	return Integer(value, "validityDays", 1, max)
}

// pkiNameEntry is one name a certificate carries, decided on its own.
type pkiNameEntry struct {
	nameType string
	name     string
}

func (entry pkiNameEntry) object() *core.Object {
	return core.NewObject("nameType", entry.nameType, "name", entry.name)
}

// pkiNameEntries is api/pki.ts nameEntries: the names a certificate carries, each decided on its own. A wildcard DNS
// name (`*.internal`) is its own name type, never `dns`: it covers hosts a policy may deny one by one, so policies
// allow wildcard certificates explicitly.
func pkiNameEntries(commonName string, names sanSet) []pkiNameEntry {
	entries := []pkiNameEntry{}
	if commonName != "" {
		entries = append(entries, pkiNameEntry{"commonName", commonName})
	}
	for _, name := range names.dnsNames {
		nameType := "dns"
		if strings.HasPrefix(name, "*.") {
			nameType = "wildcard"
		}
		entries = append(entries, pkiNameEntry{nameType, name})
	}
	for _, name := range names.uris {
		entries = append(entries, pkiNameEntry{"uri", name})
	}
	for _, name := range names.ipAddresses {
		entries = append(entries, pkiNameEntry{"ip", name})
	}
	for _, name := range names.emails {
		entries = append(entries, pkiNameEntry{"email", name})
	}
	return entries
}

// pkiUsageOf is api/pki.ts usageOf.
func pkiUsageOf(value any) (string, error) {
	if isUndefined(value) {
		return "both", nil
	}
	if value != "server" && value != "client" && value != "both" {
		return "", invalidInput("usage must be server, client or both")
	}
	return value.(string), nil
}

// pkiActsInOwnRight is kms.ts actsInOwnRight: a session that acts in its own right: a user session or an API key, not
// derived, not "view as".
func pkiActsInOwnRight(principal *Principal) bool {
	session := principal.Session
	kind := session.Get("kind")
	return (kind == "user" || kind == "api-key") && !truthy(session.Get("impersonatorId")) && isUndefined(session.Get("sourceSessionId"))
}

// authorityTarget locates a tenant's authority as the guarded target, with extra attributes.
func (api *PkiAPI) authorityTarget(tenantID any, authorityID any, extra *core.Object) func(ctx context.Context, tx core.IamStore, principal *Principal) (pkiTarget, error) {
	return func(ctx context.Context, tx core.IamStore, principal *Principal) (pkiTarget, error) {
		tenant, err := Text(tenantID, "tenantId")
		if err != nil {
			return pkiTarget{}, err
		}
		authority, err := FindAuthority(ctx, tx, tenant, authorityID)
		if err != nil {
			return pkiTarget{}, err
		}
		attributes := authorityAttributesOf(authority)
		if extra != nil {
			attributes.Assign(extra)
		}
		return pkiTarget{
			GuardTarget: GuardTarget{ResourceID: "pki/" + jsString(authority.Get("id")), Attributes: attributes},
			authority:   authority,
		}, nil
	}
}

// pkiIssueRequest is what issue signs.
type pkiIssueRequest struct {
	spki            []byte
	keyType         string
	commonName      string
	names           sanSet
	usage           string
	validitySeconds float64
	identityID      string
	spiffeID        string
	// notAfterCap is the latest the certificate may be valid until (the credential or identity it stands for ends
	// then); +Inf when nothing caps it.
	notAfterCap float64
	issuedBy    any
	principal   *Principal
}

// issue signs a leaf certificate for request.spki with request.names under an authority whose chain is usable.
func (api *PkiAPI) issue(ctx context.Context, tx core.IamStore, authority *core.Object, request pkiIssueRequest) (*core.Object, error) {
	server := api.server
	now := float64(server.Now())
	chain, err := AuthorityChain(ctx, tx, authority)
	if err != nil {
		return nil, err
	}
	if err := AssertAuthorityUsable(chain, int64(now)); err != nil {
		return nil, err
	}
	permitted, err := NamesPermitted(chain, request.names.object(), request.commonName)
	if err != nil {
		return nil, err
	}
	if !permitted {
		return nil, core.NewIamError("NAME_NOT_PERMITTED", "A requested name is outside the authority's name constraints", 403)
	}
	notAfter := math.Min(math.Min(now+request.validitySeconds*1000, jsNumber(authority.Get("notAfter"))), request.notAfterCap)
	if notAfter <= now+60_000 {
		return nil, invalidInput("The certificate would expire within a minute")
	}
	serialNumber, err := RandomSerial()
	if err != nil {
		return nil, err
	}
	subject := core.NewObject()
	if request.commonName != "" {
		subject.Set("commonName", request.commonName)
	}
	spec := core.NewObject("serialNumber", serialNumber)
	spec.SetRaw("issuer", nodeBase64Decode(jsString(authority.Get("subjectDer"))))
	spec.SetRaw("subject", subject)
	spec.SetRaw("spki", request.spki)
	spec.Set("notBefore", now-pkiClockSkewMs)
	spec.Set("notAfter", notAfter)
	spec.SetRaw("names", request.names.object())
	spec.Set("usage", request.usage)
	spec.SetRaw("authorityKeyId", nodeHexDecode(jsString(authority.Get("subjectKeyId"))))
	if crlURL := authority.Get("crlUrl"); truthy(crlURL) {
		spec.SetRaw("crlUrl", crlURL)
	}
	algorithm := jsString(authority.Get("algorithm"))
	tbs, err := TbsCertificate(spec, algorithm)
	if err != nil {
		return nil, err
	}
	signature, err := signWithAuthority(ctx, server, tx, authority, tbs, request.principal)
	if err != nil {
		return nil, err
	}
	der, err := SignedStructure(tbs, algorithm, signature)
	if err != nil {
		return nil, err
	}
	pemText, err := CertificatePem(der)
	if err != nil {
		return nil, err
	}
	fingerprint, err := Sha256Fingerprint(der)
	if err != nil {
		return nil, err
	}
	record := core.NewObject(
		"id", ID(),
		"tenantId", authority.Get("tenantId"),
		"uniqueKey", "serial:"+serialNumber,
		"authorityId", authority.Get("id"),
		"serialNumber", serialNumber,
		"names", request.names.object(),
		"keyType", request.keyType,
		"usage", request.usage,
		"notBefore", now-pkiClockSkewMs,
		"notAfter", notAfter,
		"certificatePem", pemText,
		"fingerprint", fingerprint,
		"status", "valid",
		"issuedAt", now,
		"issuedBy", request.issuedBy,
	)
	if request.commonName != "" {
		record.Set("commonName", request.commonName)
	}
	if request.identityID != "" {
		record.Set("identityId", request.identityID)
	}
	if request.spiffeID != "" {
		record.Set("spiffeId", request.spiffeID)
	}
	if _, err := tx.Insert(ctx, "pkiCertificates", record); err != nil {
		return nil, err
	}
	var chainPem strings.Builder
	for _, link := range chain {
		if link.Get("type") == "intermediate" {
			chainPem.WriteString(jsString(link.Get("certificatePem")))
		}
	}
	result := core.NewObject(
		"id", record.Get("id"),
		"serialNumber", serialNumber,
		"certificatePem", pemText,
		"chainPem", chainPem.String(),
		"rootPem", chain[len(chain)-1].Get("certificatePem"),
		"notBefore", record.Get("notBefore"),
		"notAfter", notAfter,
		"fingerprint", record.Get("fingerprint"),
	)
	if request.spiffeID != "" {
		result.Set("spiffeId", request.spiffeID)
	}
	return result, nil
}

// leafValidity is a leaf's validity in seconds: the authority's default, or one within 60 seconds and its maximum.
func leafValidity(authority *core.Object, value any) (float64, error) {
	if isUndefined(value) {
		return jsNumber(authority.Get("defaultValiditySeconds")), nil
	}
	return Integer(value, "validitySeconds", 60, jsNumber(authority.Get("maxValiditySeconds")))
}

// spiffeRules are the SPIFFE SVID rules: one URI per certificate, only in the authority's trust domain, and never in
// the paths `/user/`, `/service/` and `/agent/`, which name identities and are issued only to those identities
// themselves (`requestCertificate`).
func spiffeRules(authority *core.Object, names sanSet) error {
	spiffe := []string{}
	for _, uri := range names.uris {
		if strings.HasPrefix(core.JSLower(uri), "spiffe://") {
			spiffe = append(spiffe, uri)
		}
	}
	if len(spiffe) == 0 {
		return nil
	}
	if len(names.uris) != 1 {
		return invalidInput("A SPIFFE certificate carries exactly one URI")
	}
	parts := strings.Split(spiffe[0], "/")
	host, segment := "", ""
	if len(parts) > 2 {
		host = parts[2]
	}
	if len(parts) > 3 {
		segment = parts[3]
	}
	trustDomain := authority.Get("trustDomain")
	if !truthy(trustDomain) || host != trustDomain {
		named := "no trust domain"
		if !nullish(trustDomain) {
			named = jsString(trustDomain)
		}
		return core.NewIamError("NAME_NOT_PERMITTED", "This authority issues SPIFFE IDs only in "+named, 403)
	}
	if segment == "user" || segment == "service" || segment == "agent" {
		return core.NewIamError("NAME_NOT_PERMITTED", "spiffe://"+host+"/"+segment+"/… names an identity; it is issued only to that identity (requestCertificate)", 403)
	}
	return nil
}

// workloadID is the SPIFFE ID of an identity's own workload certificate.
func workloadID(authority *core.Object, identity *core.Object) string {
	return "spiffe://" + jsString(authority.Get("trustDomain")) + "/" + jsString(identity.Get("kind")) + "/" + jsString(identity.Get("id"))
}

// byCreatedThenID orders authorities oldest first, then by ID.
func byCreatedThenID(records []*core.Object) {
	sort.SliceStable(records, func(i, j int) bool {
		left, right := jsNumber(records[i].Get("createdAt")), jsNumber(records[j].Get("createdAt"))
		if left != right {
			return left < right
		}
		return jsLess(records[i].Get("id"), records[j].Get("id"))
	})
}

// CreateAuthority is POST {basePath}/pki/createAuthority. Creates a certificate authority: a self-signed root, or an
// intermediate signed by a `parentId` authority in the tenant (which needs iam:pki:update on the parent and respects
// its path length). The signing key is a new KMS key (`keySpec`, default `ecc-p256`) or an existing one the caller may
// sign with (`keyId`); its current version is pinned, so rotating the KMS key never changes the authority. Requires
// iam:pki:create on `iam/pki` and recent authentication.
func (api *PkiAPI) CreateAuthority(ctx context.Context, credential core.CredentialInput, input In[apitypes.PkiCreateAuthorityInput]) (Out[apitypes.PkiCreateAuthorityOutput], error) {
	server := api.server
	fail := func(err error) (Out[apitypes.PkiCreateAuthorityOutput], error) {
		return Out[apitypes.PkiCreateAuthorityOutput]{}, err
	}
	nameText, err := Text(input.Get("name"), "name", 128)
	if err != nil {
		return fail(err)
	}
	name := core.JSTrim(nameText)
	parentGiven := defined(input.Get("parentId"))
	typeValue := input.Get("type")
	if nullish(typeValue) {
		if parentGiven {
			typeValue = "intermediate"
		} else {
			typeValue = "root"
		}
	}
	if typeValue != "root" && typeValue != "intermediate" {
		return fail(invalidInput("type must be root or intermediate"))
	}
	kind := typeValue.(string)
	if (kind == "intermediate") != parentGiven {
		return fail(invalidInput("An intermediate authority needs a parentId; a root has none"))
	}
	subject, err := DistinguishedName(input.Get("subject"), true)
	if err != nil {
		return fail(err)
	}
	spec := ""
	if isUndefined(input.Get("keyId")) {
		if spec, err = KeySpec(coalesce(input.Get("keySpec"), "ecc-p256")); err != nil {
			return fail(err)
		}
	}
	if spec != "" {
		if _, err := AlgorithmForSpec(spec); err != nil {
			return fail(err)
		}
	}
	var pathLength *float64
	if defined(input.Get("pathLength")) {
		value, err := Integer(input.Get("pathLength"), "pathLength", 0, 10)
		if err != nil {
			return fail(err)
		}
		pathLength = &value
	}
	domain, err := TrustDomain(input.Get("trustDomain"))
	if err != nil {
		return fail(err)
	}
	crlURL, err := HttpURL(input.Get("crlUrl"), "crlUrl")
	if err != nil {
		return fail(err)
	}
	permitted, err := PermittedNames(input.Get("permitted"))
	if err != nil {
		return fail(err)
	}
	maxValiditySeconds := 90.0 * 86_400
	if defined(input.Get("maxValiditySeconds")) {
		if maxValiditySeconds, err = Integer(input.Get("maxValiditySeconds"), "maxValiditySeconds", 60, MaxLeafValiditySeconds); err != nil {
			return fail(err)
		}
	}
	defaultValiditySeconds := math.Min(86_400, maxValiditySeconds)
	if defined(input.Get("defaultValiditySeconds")) {
		if defaultValiditySeconds, err = Integer(input.Get("defaultValiditySeconds"), "defaultValiditySeconds", 60, maxValiditySeconds); err != nil {
			return fail(err)
		}
	}
	result, err := api.guard.Run(ctx, credential, guardTenantID(input.Get("tenantId")), GuardAction[pkiTarget]{Name: PkiActions.Create},
		func(ctx context.Context, tx core.IamStore, principal *Principal) (pkiTarget, error) {
			attributes := core.NewObject("authorityType", kind)
			if spec != "" {
				attributes.Set("keySpec", spec)
			}
			if domain != "" {
				attributes.Set("trustDomain", domain)
			}
			return pkiTarget{GuardTarget: GuardTarget{ResourceID: "pki", Attributes: attributes}}, nil
		},
		func(ctx context.Context, call GuardCall, target pkiTarget) (any, error) {
			tx, principal, tenant, metadata := call.Tx, call.Principal, call.Tenant, call.Metadata
			if err := server.Auth.RequireRecent(principal.Auth()); err != nil {
				return nil, err
			}
			existing, err := tx.Find(ctx, "pkiAuthorities", core.NewObject("tenantId", tenant.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			if len(existing) >= MaxAuthoritiesPerTenant {
				return nil, core.NewIamError("LIMIT_EXCEEDED", "A tenant keeps at most "+strconv.Itoa(MaxAuthoritiesPerTenant)+" certificate authorities", 409)
			}
			uniqueKey := "name:" + core.JSLower(name)
			same, err := tx.Find(ctx, "pkiAuthorities", core.NewObject("tenantId", tenant.Get("id"), "uniqueKey", uniqueKey), nil)
			if err != nil {
				return nil, err
			}
			if len(same) > 0 {
				return nil, core.NewIamError("CONFLICT", "A certificate authority with that name exists", 409)
			}
			// A SPIFFE trust domain names one organization's workloads: no other tenant may claim it.
			if domain != "" {
				claimed, err := tx.Find(ctx, "pkiAuthorities", core.NewObject("trustDomain", domain), nil)
				if err != nil {
					return nil, err
				}
				for _, other := range claimed {
					if !jsStrictEqual(other.Get("tenantId"), tenant.Get("id")) {
						return nil, core.NewIamError("CONFLICT", "Another organization uses that trust domain", 409)
					}
				}
			}
			tenantKey := jsString(tenant.Get("id"))
			now := float64(server.Now())
			authorityID := ID()
			var parent *core.Object
			childPathLength := pathLength
			if kind == "intermediate" {
				if parent, err = FindAuthority(ctx, tx, tenantKey, input.Get("parentId")); err != nil {
					return nil, err
				}
				parentChain, err := AuthorityChain(ctx, tx, parent)
				if err != nil {
					return nil, err
				}
				if err := AssertAuthorityUsable(parentChain, int64(now)); err != nil {
					return nil, err
				}
				// Every authority above bounds how many authorities may sit below it: the new one is the (i+1)-th below
				// the ancestor at index i, which leaves `pathLength - (i + 1)` levels for everything under it.
				remaining := infinity
				for index, ancestor := range parentChain {
					if limit := ancestor.Get("pathLength"); defined(limit) {
						remaining = math.Min(remaining, jsNumber(limit)-float64(index+1))
					}
				}
				if remaining < 0 {
					return nil, invalidInput("An authority above allows no more levels of subordinate authorities (path length)")
				}
				if pathLength != nil && *pathLength > remaining {
					return nil, invalidInput("pathLength exceeds what the authorities above allow")
				}
				if childPathLength == nil && remaining != infinity {
					value := remaining
					childPathLength = &value
				}
				allowed, err := call.Allowed(ctx, PkiActions.Update, GuardTarget{ResourceID: "pki/" + jsString(parent.Get("id")), Attributes: authorityAttributesOf(parent)})
				if err != nil {
					return nil, err
				}
				if !allowed {
					return nil, NewOperationDenied("You may not add authorities under that parent")
				}
			}
			// The signing key: a new KMS key, or an existing one the caller may sign with.
			var key *core.Object
			if keyRef := input.Get("keyId"); defined(keyRef) {
				if key, err = FindKey(ctx, tx, tenantKey, keyRef); err != nil {
					return nil, err
				}
				if err := AssertUsable(key, "sign"); err != nil {
					return nil, err
				}
				// One key, one authority; and a key others use cannot become a CA key without their knowing.
				if err := AssertUnmanaged(key); err != nil {
					return nil, err
				}
				algorithm, err := AlgorithmForSpec(jsString(key.Get("keySpec")))
				if err != nil {
					return nil, err
				}
				aliases, err := AliasNames(ctx, tx, key)
				if err != nil {
					return nil, err
				}
				attributes, err := KeyAttributes(key, aliases, core.NewObject("algorithm", algorithm))
				if err != nil {
					return nil, err
				}
				allowed, err := call.Allowed(ctx, jsString(KmsActions.Get("sign")), GuardTarget{ResourceID: "kms/" + jsString(key.Get("id")), Attributes: attributes})
				if err != nil {
					return nil, err
				}
				if !allowed {
					return nil, NewOperationDenied("You may not sign with that key")
				}
				// From now on the key signs only through this authority: raw KMS signatures could forge certificates.
				key = key.Spread(core.NewObject("managedBy", "pki", "managedId", authorityID, "updatedAt", now))
				if _, err := tx.Put(ctx, "kmsKeys", key); err != nil {
					return nil, err
				}
			} else if key, err = CreateServiceKey(ctx, server, tx, core.NewObject(
				"tenantId", tenantKey,
				"keySpec", spec,
				"keyUsage", "sign",
				// name is at most 128 UTF-16 units, within the description's 512 and the tag's 256.
				"description", "Certificate authority: "+name,
				"tags", core.NewObject("pki-authority", name),
				"createdBy", principal.Identity.Get("id"),
				"managedBy", "pki",
				"managedId", authorityID,
			)); err != nil {
				return nil, err
			}
			version, err := KeyVersion(ctx, tx, key, jsNumber(key.Get("currentVersion")))
			if err != nil {
				return nil, err
			}
			algorithm, err := AlgorithmForSpec(jsString(key.Get("keySpec")))
			if err != nil {
				return nil, err
			}
			spki, err := SpkiOf(jsString(version.Get("publicKeyPem")))
			if err != nil {
				return nil, err
			}
			subjectDer, err := EncodeName(subject)
			if err != nil {
				return nil, err
			}
			subjectKeyID, err := KeyIdentifier(spki)
			if err != nil {
				return nil, err
			}
			var days float64
			if kind == "root" {
				days, err = pkiValidityDays(input.Get("validityDays"), 3650, 10_950)
			} else {
				days, err = pkiValidityDays(input.Get("validityDays"), 1825, 10_950)
			}
			if err != nil {
				return nil, err
			}
			parentNotAfter := infinity
			if parent != nil {
				parentNotAfter = jsNumber(parent.Get("notAfter"))
			}
			notAfter := math.Min(now+days*pkiDayMs, parentNotAfter)
			serialNumber, err := RandomSerial()
			if err != nil {
				return nil, err
			}
			certificateSpec := core.NewObject("serialNumber", serialNumber)
			if parent != nil {
				certificateSpec.SetRaw("issuer", nodeBase64Decode(jsString(parent.Get("subjectDer"))))
			} else {
				certificateSpec.SetRaw("issuer", subjectDer)
			}
			certificateSpec.SetRaw("subject", subject)
			certificateSpec.SetRaw("spki", spki)
			certificateSpec.Set("notBefore", now-pkiClockSkewMs)
			certificateSpec.Set("notAfter", notAfter)
			ca := core.NewObject()
			if childPathLength != nil {
				ca.Set("pathLength", *childPathLength)
			}
			certificateSpec.SetRaw("ca", ca)
			if parent != nil {
				certificateSpec.SetRaw("authorityKeyId", nodeHexDecode(jsString(parent.Get("subjectKeyId"))))
				if parentCrl := parent.Get("crlUrl"); truthy(parentCrl) {
					certificateSpec.SetRaw("crlUrl", parentCrl)
				}
				if permitted != nil {
					certificateSpec.SetRaw("permitted", permitted)
				}
			}
			tbs, err := TbsCertificate(certificateSpec, algorithm)
			if err != nil {
				return nil, err
			}
			var signature []byte
			if parent != nil {
				signature, err = signWithAuthority(ctx, server, tx, parent, tbs, principal)
			} else {
				use := core.NewObject("via", "pki")
				use.SetRaw("principal", principal)
				signature, err = KmsSignFor(ctx, server, tx, tenantKey, jsString(key.Get("id")), jsNumber(version.Get("version")), algorithm, tbs, use)
			}
			if err != nil {
				return nil, err
			}
			der, err := SignedStructure(tbs, algorithm, signature)
			if err != nil {
				return nil, err
			}
			pemText, err := CertificatePem(der)
			if err != nil {
				return nil, err
			}
			// The certificate reads back, or the encoding is wrong: fail before storing anything.
			parsed, err := parseCertificatePem(pemText)
			if err != nil {
				return nil, err
			}
			if !parsed.ca() {
				return nil, core.NewIamError("INTERNAL_ERROR", "The CA certificate is malformed", 500)
			}
			authority := core.NewObject(
				"id", authorityID,
				"tenantId", tenant.Get("id"),
				"uniqueKey", uniqueKey,
				"name", name,
				"type", kind,
				"subject", subject,
				"subjectDer", encodeBase64(subjectDer),
				"subjectKeyId", hexOf(subjectKeyID),
				"keyId", key.Get("id"),
				"keyVersion", version.Get("version"),
				"algorithm", algorithm,
				"certificatePem", pemText,
				"serialNumber", serialNumber,
				"notBefore", now-pkiClockSkewMs,
				"notAfter", notAfter,
				"state", "active",
				"maxValiditySeconds", maxValiditySeconds,
				"defaultValiditySeconds", defaultValiditySeconds,
				"revision", 0.0,
				"crlNumber", 0.0,
				"createdAt", now,
				"createdBy", principal.Identity.Get("id"),
				"updatedAt", now,
			)
			if parent != nil {
				authority.Set("parentId", parent.Get("id"))
			}
			if childPathLength != nil {
				authority.Set("pathLength", *childPathLength)
			}
			if domain != "" {
				authority.Set("trustDomain", domain)
			}
			if crlURL != "" {
				authority.Set("crlUrl", crlURL)
			}
			if permitted != nil {
				authority.Set("permitted", permitted)
			}
			if _, err := tx.Insert(ctx, "pkiAuthorities", authority); err != nil {
				return nil, err
			}
			if parent != nil {
				fingerprint, err := Sha256Fingerprint(der)
				if err != nil {
					return nil, err
				}
				if _, err := tx.Insert(ctx, "pkiCertificates", core.NewObject(
					"id", ID(),
					"tenantId", tenant.Get("id"),
					"uniqueKey", "serial:"+serialNumber,
					"authorityId", parent.Get("id"),
					"serialNumber", serialNumber,
					"commonName", subject.Get("commonName"),
					"names", sanSet{}.object(),
					"keyType", key.Get("keySpec"),
					"usage", "ca",
					"notBefore", now-pkiClockSkewMs,
					"notAfter", notAfter,
					"certificatePem", pemText,
					"fingerprint", fingerprint,
					"subordinateId", authority.Get("id"),
					"status", "valid",
					"issuedAt", now,
					"issuedBy", principal.Identity.Get("id"),
				)); err != nil {
					return nil, err
				}
			}
			metadata.Assign(core.NewObject(
				"authorityId", authority.Get("id"),
				"name", name,
				"type", kind,
				"keyId", key.Get("id"),
				"serialNumber", serialNumber,
			))
			if parent != nil {
				metadata.Set("parentId", parent.Get("id"))
			}
			if childPathLength != nil {
				metadata.Set("pathLength", *childPathLength)
			}
			if domain != "" {
				metadata.Set("trustDomain", domain)
			}
			if crlURL != "" {
				metadata.Set("crlUrl", crlURL)
			}
			if permitted != nil {
				metadata.SetRaw("permitted", permitted.Clone())
			}
			return SummarizeAuthority(authority)
		})
	if err != nil {
		return fail(err)
	}
	return Out[apitypes.PkiCreateAuthorityOutput]{Value: result}, nil
}

// encodeBase64 is Buffer#toString('base64').
func encodeBase64(der []byte) string { return base64.StdEncoding.EncodeToString(der) }

// ListAuthorities is POST {basePath}/pki/listAuthorities. The tenant's certificate authorities the caller may read
// (`iam:pki:read`, per authority), oldest first.
func (api *PkiAPI) ListAuthorities(ctx context.Context, credential core.CredentialInput, input In[apitypes.PkiListAuthoritiesInput]) (Out[apitypes.PkiListAuthoritiesOutput], error) {
	listed, err := GuardVisible(ctx, api.guard, credential, guardTenantID(input.Get("tenantId")), PkiActions.Read, "pki",
		func(ctx context.Context, tx core.IamStore, tenant *core.Object) ([]VisibleItem[any], error) {
			authorities, err := tx.Find(ctx, "pkiAuthorities", core.NewObject("tenantId", tenant.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			byCreatedThenID(authorities)
			items := make([]VisibleItem[any], 0, len(authorities))
			for _, authority := range authorities {
				summary, err := SummarizeAuthority(authority)
				if err != nil {
					return nil, err
				}
				items = append(items, VisibleItem[any]{
					Item:   summary,
					Target: GuardTarget{ResourceID: "pki/" + jsString(authority.Get("id")), Attributes: authorityAttributesOf(authority)},
				})
			}
			return items, nil
		})
	if err != nil {
		return Out[apitypes.PkiListAuthoritiesOutput]{}, err
	}
	return Out[apitypes.PkiListAuthoritiesOutput]{Value: listed}, nil
}

// GetAuthority is POST {basePath}/pki/getAuthority. One certificate authority. Requires iam:pki:read.
func (api *PkiAPI) GetAuthority(ctx context.Context, credential core.CredentialInput, input In[apitypes.PkiGetAuthorityInput]) (Out[apitypes.PkiGetAuthorityOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := api.guard.Run(ctx, credential, guardTenantID(tenantID), GuardAction[pkiTarget]{Name: PkiActions.Read},
		api.authorityTarget(tenantID, input.Get("authorityId"), nil),
		func(ctx context.Context, call GuardCall, target pkiTarget) (any, error) {
			return SummarizeAuthority(target.authority)
		})
	if err != nil {
		return Out[apitypes.PkiGetAuthorityOutput]{}, err
	}
	return Out[apitypes.PkiGetAuthorityOutput]{Value: result}, nil
}

// UpdateAuthority is POST {basePath}/pki/updateAuthority. Disables or re-enables an authority (`state`; a disabled
// authority issues nothing and its certificates stop verifying), and changes the leaf validity limits or the CRL URL
// for future certificates (`crlUrl: null` clears it). Requires iam:pki:update.
func (api *PkiAPI) UpdateAuthority(ctx context.Context, credential core.CredentialInput, input In[apitypes.PkiUpdateAuthorityInput]) (Out[apitypes.PkiUpdateAuthorityOutput], error) {
	server := api.server
	state := input.Get("state")
	if defined(state) && state != "active" && state != "disabled" {
		return Out[apitypes.PkiUpdateAuthorityOutput]{}, invalidInput("state must be active or disabled")
	}
	tenantID := input.Get("tenantId")
	result, err := api.guard.Run(ctx, credential, guardTenantID(tenantID), GuardAction[pkiTarget]{Name: PkiActions.Update},
		api.authorityTarget(tenantID, input.Get("authorityId"), nil),
		func(ctx context.Context, call GuardCall, target pkiTarget) (any, error) {
			tx, metadata := call.Tx, call.Metadata
			current := target.authority
			if current.Get("state") == "revoked" {
				return nil, core.NewIamError("AUTHORITY_UNAVAILABLE", "A revoked authority cannot change", 409)
			}
			next := current.Spread(core.NewObject("updatedAt", float64(server.Now())))
			if defined(state) {
				next.Set("state", state)
			}
			if value := input.Get("maxValiditySeconds"); defined(value) {
				maxValidity, err := Integer(value, "maxValiditySeconds", 60, MaxLeafValiditySeconds)
				if err != nil {
					return nil, err
				}
				next.Set("maxValiditySeconds", maxValidity)
			}
			if value := input.Get("defaultValiditySeconds"); defined(value) {
				defaultValidity, err := Integer(value, "defaultValiditySeconds", 60, jsNumber(next.Get("maxValiditySeconds")))
				if err != nil {
					return nil, err
				}
				next.Set("defaultValiditySeconds", defaultValidity)
			}
			next.Set("defaultValiditySeconds", math.Min(jsNumber(next.Get("defaultValiditySeconds")), jsNumber(next.Get("maxValiditySeconds"))))
			crlURL := input.Get("crlUrl")
			if crlURL == nil {
				next.Delete("crlUrl")
			} else if defined(crlURL) {
				href, err := HttpURL(crlURL, "crlUrl")
				if err != nil {
					return nil, err
				}
				next.Set("crlUrl", href)
			}
			if _, err := tx.Put(ctx, "pkiAuthorities", next); err != nil {
				return nil, err
			}
			if truthy(state) {
				metadata.Set("state", state)
			}
			metadata.SetRaw("maxValiditySeconds", next.Get("maxValiditySeconds"))
			metadata.SetRaw("defaultValiditySeconds", next.Get("defaultValiditySeconds"))
			if defined(crlURL) {
				metadata.SetRaw("crlUrl", coalesce(next.Get("crlUrl"), nil))
			}
			return SummarizeAuthority(next)
		})
	if err != nil {
		return Out[apitypes.PkiUpdateAuthorityOutput]{}, err
	}
	return Out[apitypes.PkiUpdateAuthorityOutput]{Value: result}, nil
}

// IssueCertificate is POST {basePath}/pki/issueCertificate. Issues a certificate for the key in a PEM PKCS#10 request
// (`csr`, which proves possession of the key). Names come from the request unless `commonName`, `dnsNames`, `uris`,
// `ipAddresses` or `emails` are given. Every name is decided separately (`iam:pki:issue` with `resource.name` /
// `resource.nameType`), and must fit the name constraints of the authority chain; a `spiffe://` URI must be the only
// URI and in the authority's trust domain. Validity defaults to the authority's `defaultValiditySeconds`, is capped
// at its `maxValiditySeconds`, and never outlasts the authority. Audited as `iam:pki:issue` with the serial number and
// names.
func (api *PkiAPI) IssueCertificate(ctx context.Context, credential core.CredentialInput, input In[apitypes.PkiIssueCertificateInput]) (Out[apitypes.PkiIssueCertificateOutput], error) {
	usage, err := pkiUsageOf(input.Get("usage"))
	if err != nil {
		return Out[apitypes.PkiIssueCertificateOutput]{}, err
	}
	// Parsed once the caller is known to belong to the tenant (inside the envelope), never for anonymous callers.
	var request *core.Object
	var names sanSet
	var commonName string
	entries := []pkiNameEntry{}
	base := func(authority *core.Object, validitySeconds float64) *core.Object {
		attributes := authorityAttributesOf(authority)
		attributes.Set("usage", usage)
		attributes.Set("validitySeconds", validitySeconds)
		attributes.SetRaw("keyType", request.Get("keyType"))
		return attributes
	}
	tenantID := input.Get("tenantId")
	result, err := api.guard.Run(ctx, credential, guardTenantID(tenantID), GuardAction[pkiTarget]{Name: PkiActions.Issue},
		func(ctx context.Context, tx core.IamStore, principal *Principal) (pkiTarget, error) {
			target, err := api.authorityTarget(tenantID, input.Get("authorityId"), nil)(ctx, tx, principal)
			if err != nil {
				return pkiTarget{}, err
			}
			if request, err = ParseCertificateRequest(input.Get("csr")); err != nil {
				return pkiTarget{}, err
			}
			explicit := defined(input.Get("dnsNames")) || defined(input.Get("uris")) || defined(input.Get("ipAddresses")) || defined(input.Get("emails"))
			if explicit {
				if names, err = subjectAltNames(input.Body); err != nil {
					return pkiTarget{}, err
				}
			} else {
				names = sanSetOf(request.Get("names"))
			}
			if given := input.Get("commonName"); defined(given) {
				text, err := Text(given, "commonName", 64)
				if err != nil {
					return pkiTarget{}, err
				}
				commonName = core.JSTrim(text)
			} else if requested, ok := request.Get("commonName").(string); ok {
				commonName = requested
			}
			entries = pkiNameEntries(commonName, names)
			if len(entries) == 0 {
				return pkiTarget{}, invalidInput("A certificate needs a common name or at least one name")
			}
			// With alternative names, the common name must be one of them (clients may fall back to it).
			alternatives := append(append(append(append([]string{}, names.dnsNames...), names.uris...), names.ipAddresses...), names.emails...)
			if commonName != "" && len(alternatives) > 0 && !containsString(alternatives, core.JSLower(commonName)) && !containsString(alternatives, commonName) {
				return pkiTarget{}, invalidInput("The common name must be one of the subject alternative names")
			}
			validitySeconds, err := leafValidity(target.authority, input.Get("validitySeconds"))
			if err != nil {
				return pkiTarget{}, err
			}
			target.Attributes = base(target.authority, validitySeconds).Assign(entries[0].object())
			return target, nil
		},
		func(ctx context.Context, call GuardCall, target pkiTarget) (any, error) {
			authority := target.authority
			validitySeconds, err := leafValidity(authority, input.Get("validitySeconds"))
			if err != nil {
				return nil, err
			}
			for _, entry := range entries[1:] {
				allowed, err := call.Allowed(ctx, PkiActions.Issue, GuardTarget{
					ResourceID: "pki/" + jsString(authority.Get("id")),
					Attributes: base(authority, validitySeconds).Assign(entry.object()),
				})
				if err != nil {
					return nil, err
				}
				if !allowed {
					return nil, NewOperationDenied("You may not certify " + entry.name)
				}
			}
			if err := spiffeRules(authority, names); err != nil {
				return nil, err
			}
			spki, _ := request.Get("spki").([]byte)
			issued, err := api.issue(ctx, call.Tx, authority, pkiIssueRequest{
				spki:            spki,
				keyType:         jsString(request.Get("keyType")),
				commonName:      commonName,
				names:           names,
				usage:           usage,
				validitySeconds: validitySeconds,
				notAfterCap:     infinity,
				issuedBy:        call.Principal.Identity.Get("id"),
				principal:       call.Principal,
			})
			if err != nil {
				return nil, err
			}
			listed := make([]any, len(entries))
			for index, entry := range entries {
				listed[index] = entry.nameType + ":" + entry.name
			}
			call.Metadata.Assign(core.NewObject(
				"serialNumber", issued.Get("serialNumber"),
				"names", listed,
				"notAfter", issued.Get("notAfter"),
				"usage", usage,
			))
			return issued, nil
		})
	if err != nil {
		return Out[apitypes.PkiIssueCertificateOutput]{}, err
	}
	return Out[apitypes.PkiIssueCertificateOutput]{Value: result}, nil
}

// RequestCertificate is POST {basePath}/pki/requestCertificate. A workload certificate (SPIFFE X.509 SVID) for the
// caller's own identity: the only name is `spiffe://{trustDomain}/{user|service|agent}/{identityId}` (a critical
// subject alternative name, empty subject), valid for `validitySeconds` (default one hour, at most a day and the
// authority's maximum), and never past the end of the calling session or API key or of the identity itself. The
// authority needs a `trustDomain`. For user sessions and API keys acting in their own right; requires
// iam:pki:request on the authority, decided with `resource.name` (the SPIFFE ID), `resource.nameType` (`uri`) and
// `resource.identityKind`.
func (api *PkiAPI) RequestCertificate(ctx context.Context, credential core.CredentialInput, input In[apitypes.PkiRequestCertificateInput]) (Out[apitypes.PkiRequestCertificateOutput], error) {
	var request *core.Object
	spiffeID := ""
	validitySeconds := 0.0
	tenantID := input.Get("tenantId")
	result, err := api.guard.Run(ctx, credential, guardTenantID(tenantID), GuardAction[pkiTarget]{Name: PkiActions.Request},
		func(ctx context.Context, tx core.IamStore, principal *Principal) (pkiTarget, error) {
			target, err := api.authorityTarget(tenantID, input.Get("authorityId"), nil)(ctx, tx, principal)
			if err != nil {
				return pkiTarget{}, err
			}
			authority := target.authority
			if !pkiActsInOwnRight(principal) || !jsStrictEqual(principal.Identity.Get("tenantId"), authority.Get("tenantId")) {
				return pkiTarget{}, core.NewIamError("ACCESS_DENIED", "Workload certificates are issued to your own identity, from your own session or API key", 403)
			}
			if !truthy(authority.Get("trustDomain")) {
				return pkiTarget{}, invalidInput("This authority has no SPIFFE trust domain")
			}
			if request, err = ParseCertificateRequest(input.Get("csr")); err != nil {
				return pkiTarget{}, err
			}
			spiffeID = workloadID(authority, principal.Identity)
			ceiling := math.Min(86_400, jsNumber(authority.Get("maxValiditySeconds")))
			if given := input.Get("validitySeconds"); isUndefined(given) {
				validitySeconds = math.Min(3600, ceiling)
			} else if validitySeconds, err = Integer(given, "validitySeconds", 60, ceiling); err != nil {
				return pkiTarget{}, err
			}
			// The workload name is decided like any other: policies may narrow it by kind or trust domain.
			target.Attributes = target.Attributes.Spread(core.NewObject(
				"nameType", "uri",
				"name", spiffeID,
				"identityKind", principal.Identity.Get("kind"),
				"validitySeconds", validitySeconds,
				"keyType", request.Get("keyType"),
			))
			return target, nil
		},
		func(ctx context.Context, call GuardCall, target pkiTarget) (any, error) {
			principal := call.Principal
			names := sanSet{dnsNames: []string{}, uris: []string{spiffeID}, ipAddresses: []string{}, emails: []string{}}
			identityEnd := infinity
			if expiresAt, ok := principal.Identity.Get("expiresAt").(float64); ok {
				identityEnd = expiresAt
			}
			spki, _ := request.Get("spki").([]byte)
			issued, err := api.issue(ctx, call.Tx, target.authority, pkiIssueRequest{
				spki:            spki,
				keyType:         jsString(request.Get("keyType")),
				names:           names,
				usage:           "both",
				validitySeconds: validitySeconds,
				identityID:      jsString(principal.Identity.Get("id")),
				spiffeID:        spiffeID,
				// Never outlives the credential that asked for it, or the identity it names.
				notAfterCap: math.Min(jsNumber(principal.Session.Get("expiresAt")), identityEnd),
				issuedBy:    principal.Identity.Get("id"),
				principal:   principal,
			})
			if err != nil {
				return nil, err
			}
			call.Metadata.Assign(core.NewObject(
				"serialNumber", issued.Get("serialNumber"),
				"spiffeId", spiffeID,
				"notAfter", issued.Get("notAfter"),
			))
			return issued, nil
		})
	if err != nil {
		return Out[apitypes.PkiRequestCertificateOutput]{}, err
	}
	return Out[apitypes.PkiRequestCertificateOutput]{Value: result}, nil
}

// ListCertificates is POST {basePath}/pki/listCertificates. Certificates the caller may read (`iam:pki:read` on each
// one's authority), newest first; filter by `authorityId`, `status` (`valid`, `revoked`, `expired`) or `identityId`
// (workload certificates).
func (api *PkiAPI) ListCertificates(ctx context.Context, credential core.CredentialInput, input In[apitypes.PkiListCertificatesInput]) (Out[apitypes.PkiListCertificatesOutput], error) {
	server := api.server
	limit, err := Integer(coalesce(input.Get("limit"), 100.0), "limit", 1, 1000)
	if err != nil {
		return Out[apitypes.PkiListCertificatesOutput]{}, err
	}
	offset, err := Integer(coalesce(input.Get("offset"), 0.0), "offset", 0, 1_000_000)
	if err != nil {
		return Out[apitypes.PkiListCertificatesOutput]{}, err
	}
	status := input.Get("status")
	certificates, err := GuardVisible(ctx, api.guard, credential, guardTenantID(input.Get("tenantId")), PkiActions.Read, "pki",
		func(ctx context.Context, tx core.IamStore, tenant *core.Object) ([]VisibleItem[any], error) {
			found, err := tx.Find(ctx, "pkiAuthorities", core.NewObject("tenantId", tenant.Get("id")), nil)
			if err != nil {
				return nil, err
			}
			authorities := map[string]*core.Object{}
			for _, authority := range found {
				authorities[jsString(authority.Get("id"))] = authority
			}
			now := server.Now()
			filter := core.NewObject("tenantId", tenant.Get("id"))
			if value := input.Get("authorityId"); defined(value) {
				text, err := Text(value, "authorityId")
				if err != nil {
					return nil, err
				}
				filter.Set("authorityId", text)
			}
			if value := input.Get("identityId"); defined(value) {
				text, err := Text(value, "identityId")
				if err != nil {
					return nil, err
				}
				filter.Set("identityId", text)
			}
			records, err := tx.Find(ctx, "pkiCertificates", filter, nil)
			if err != nil {
				return nil, err
			}
			summaries := []*core.Object{}
			for _, certificate := range records {
				summary, err := SummarizeCertificate(certificate, now)
				if err != nil {
					return nil, err
				}
				if isUndefined(status) || summary.Get("status") == status {
					summaries = append(summaries, summary)
				}
			}
			sort.SliceStable(summaries, func(i, j int) bool {
				left, right := jsNumber(summaries[i].Get("issuedAt")), jsNumber(summaries[j].Get("issuedAt"))
				if left != right {
					return left > right
				}
				return jsLess(summaries[i].Get("id"), summaries[j].Get("id"))
			})
			items := []VisibleItem[any]{}
			for _, summary := range summaries {
				authority := authorities[jsString(summary.Get("authorityId"))]
				if authority == nil {
					continue
				}
				items = append(items, VisibleItem[any]{
					Item:   summary,
					Target: GuardTarget{ResourceID: "pki/" + jsString(authority.Get("id")), Attributes: authorityAttributesOf(authority)},
				})
			}
			return items, nil
		})
	if err != nil {
		return Out[apitypes.PkiListCertificatesOutput]{}, err
	}
	start := int(math.Min(offset, float64(len(certificates))))
	end := int(math.Min(offset+limit, float64(len(certificates))))
	page := append([]any{}, certificates[start:end]...)
	return Out[apitypes.PkiListCertificatesOutput]{Value: core.NewObject("certificates", page, "total", float64(len(certificates)))}, nil
}

var serialPattern = regexp.MustCompile(`^[0-9a-f]{1,40}$`)

// findCertificate is api/pki.ts findCertificate: a tenant's certificate by serial number (hex, colons allowed).
func findCertificate(ctx context.Context, tx core.IamStore, tenantID any, serialNumber any) (*core.Object, error) {
	text, err := Text(serialNumber, "serialNumber", 64)
	if err != nil {
		return nil, err
	}
	serial := strings.ReplaceAll(core.JSLower(text), ":", "")
	if !serialPattern.MatchString(serial) {
		return nil, invalidInput("serialNumber must be hexadecimal")
	}
	tenant, err := Text(tenantID, "tenantId")
	if err != nil {
		return nil, err
	}
	found, err := tx.Find(ctx, "pkiCertificates", core.NewObject("tenantId", tenant, "uniqueKey", "serial:"+stripLeadingZeros(serial)), nil)
	if err != nil {
		return nil, err
	}
	if len(found) == 0 {
		return nil, core.NewIamError("NOT_FOUND", "Certificate not found", 404)
	}
	return found[0], nil
}

// GetCertificate is POST {basePath}/pki/getCertificate. One certificate by serial number (hex). Requires iam:pki:read
// on its authority.
func (api *PkiAPI) GetCertificate(ctx context.Context, credential core.CredentialInput, input In[apitypes.PkiGetCertificateInput]) (Out[apitypes.PkiGetCertificateOutput], error) {
	var certificate *core.Object
	tenantID := input.Get("tenantId")
	result, err := api.guard.Run(ctx, credential, guardTenantID(tenantID), GuardAction[pkiTarget]{Name: PkiActions.Read},
		func(ctx context.Context, tx core.IamStore, principal *Principal) (pkiTarget, error) {
			var err error
			if certificate, err = findCertificate(ctx, tx, tenantID, input.Get("serialNumber")); err != nil {
				return pkiTarget{}, err
			}
			return api.authorityTarget(tenantID, certificate.Get("authorityId"), nil)(ctx, tx, principal)
		},
		func(ctx context.Context, call GuardCall, target pkiTarget) (any, error) {
			return SummarizeCertificate(certificate, api.server.Now())
		})
	if err != nil {
		return Out[apitypes.PkiGetCertificateOutput]{}, err
	}
	return Out[apitypes.PkiGetCertificateOutput]{Value: result}, nil
}

// RevokeCertificate is POST {basePath}/pki/revokeCertificate. Revokes a certificate (`reason`: `unspecified`,
// `keyCompromise`, `caCompromise`, `affiliationChanged`, `superseded`, `cessationOfOperation`, `privilegeWithdrawn`). It
// appears on the authority's next CRL and fails `iam.pki.verify` at once. Revoking a subordinate authority's
// certificate revokes the authority too. Requires iam:pki:revoke on the issuing authority.
func (api *PkiAPI) RevokeCertificate(ctx context.Context, credential core.CredentialInput, input In[apitypes.PkiRevokeCertificateInput]) (Out[apitypes.PkiRevokeCertificateOutput], error) {
	server := api.server
	reason := coalesce(input.Get("reason"), "unspecified")
	if _, known := revocationReasonCode(reason); !known || reason == "certificateHold" {
		return Out[apitypes.PkiRevokeCertificateOutput]{}, invalidInput("Unknown revocation reason")
	}
	var certificate *core.Object
	tenantID := input.Get("tenantId")
	result, err := api.guard.Run(ctx, credential, guardTenantID(tenantID), GuardAction[pkiTarget]{Name: PkiActions.Revoke},
		func(ctx context.Context, tx core.IamStore, principal *Principal) (pkiTarget, error) {
			var err error
			if certificate, err = findCertificate(ctx, tx, tenantID, input.Get("serialNumber")); err != nil {
				return pkiTarget{}, err
			}
			return api.authorityTarget(tenantID, certificate.Get("authorityId"), nil)(ctx, tx, principal)
		},
		func(ctx context.Context, call GuardCall, target pkiTarget) (any, error) {
			tx, principal, metadata := call.Tx, call.Principal, call.Metadata
			authority := target.authority
			if certificate.Get("status") == "revoked" {
				return nil, core.NewIamError("CONFLICT", "The certificate is already revoked", 409)
			}
			now := server.Now()
			revoked := certificate.Spread(core.NewObject("status", "revoked", "revokedAt", float64(now)))
			revoked.SetRaw("revocationReason", reason)
			revoked.SetRaw("revokedBy", principal.Identity.Get("id"))
			if _, err := tx.Put(ctx, "pkiCertificates", revoked); err != nil {
				return nil, err
			}
			if _, err := tx.Put(ctx, "pkiAuthorities", authority.Spread(core.NewObject(
				"revision", jsNumber(authority.Get("revision"))+1,
				"updatedAt", float64(now),
			))); err != nil {
				return nil, err
			}
			// A revoked authority certificate revokes the authority and every authority below it.
			cascaded := 0
			subordinateID := revoked.Get("subordinateId")
			if truthy(subordinateID) {
				all, err := tx.Find(ctx, "pkiAuthorities", core.NewObject("tenantId", authority.Get("tenantId")), nil)
				if err != nil {
					return nil, err
				}
				doomed := newOrderedSet(jsString(subordinateID))
				for grew := true; grew; {
					grew = false
					for _, candidate := range all {
						parentID := candidate.Get("parentId")
						if truthy(parentID) && doomed.Has(jsString(parentID)) && !doomed.Has(jsString(candidate.Get("id"))) {
							doomed.Add(jsString(candidate.Get("id")))
							grew = true
						}
					}
				}
				for _, candidate := range all {
					if doomed.Has(jsString(candidate.Get("id"))) && candidate.Get("state") != "revoked" {
						if _, err := tx.Put(ctx, "pkiAuthorities", candidate.Spread(core.NewObject("state", "revoked", "updatedAt", float64(now)))); err != nil {
							return nil, err
						}
						cascaded++
					}
				}
			}
			metadata.SetRaw("serialNumber", revoked.Get("serialNumber"))
			metadata.SetRaw("reason", reason)
			if truthy(subordinateID) {
				metadata.SetRaw("subordinateId", subordinateID)
				metadata.Set("authoritiesRevoked", float64(cascaded))
			}
			return SummarizeCertificate(revoked, now)
		})
	if err != nil {
		return Out[apitypes.PkiRevokeCertificateOutput]{}, err
	}
	return Out[apitypes.PkiRevokeCertificateOutput]{Value: result}, nil
}

// Crl is POST {basePath}/pki/crl. The authority's current certificate revocation list (PEM), rebuilt after
// revocations and at least twice a day. CRLs are public by design: serve them to relying parties with
// `iam.Pki.CrlResponse`. Requires iam:pki:read.
func (api *PkiAPI) Crl(ctx context.Context, credential core.CredentialInput, input In[apitypes.PkiCrlInput]) (Out[apitypes.PkiCrlOutput], error) {
	tenantID := input.Get("tenantId")
	result, err := api.guard.Run(ctx, credential, guardTenantID(tenantID), GuardAction[pkiTarget]{Name: PkiActions.Read},
		api.authorityTarget(tenantID, input.Get("authorityId"), nil),
		func(ctx context.Context, call GuardCall, target pkiTarget) (any, error) {
			crl, err := CurrentCrl(ctx, api.server, call.Tx, target.authority)
			if err != nil {
				return nil, err
			}
			der, _ := crl.Get("der").([]byte)
			pemText, err := CrlPem(der)
			if err != nil {
				return nil, err
			}
			return core.NewObject(
				"pem", pemText,
				"crlNumber", crl.Get("crlNumber"),
				"thisUpdate", crl.Get("thisUpdate"),
				"nextUpdate", crl.Get("nextUpdate"),
			), nil
		})
	if err != nil {
		return Out[apitypes.PkiCrlOutput]{}, err
	}
	return Out[apitypes.PkiCrlOutput]{Value: result}, nil
}

// Bundle is POST {basePath}/pki/bundle. The tenant's trust anchors: every active, unexpired root certificate as one
// PEM bundle, which is what relying parties trust. Intermediates are never in it (many TLS stacks treat any
// certificate in a trust store as an anchor); servers send them in their chain (`chainPem`).
func (api *PkiAPI) Bundle(ctx context.Context, credential core.CredentialInput, input In[apitypes.PkiBundleInput]) (Out[apitypes.PkiBundleOutput], error) {
	authorities, err := GuardVisible(ctx, api.guard, credential, guardTenantID(input.Get("tenantId")), PkiActions.Read, "pki",
		func(ctx context.Context, tx core.IamStore, tenant *core.Object) ([]VisibleItem[*core.Object], error) {
			anchors, err := trustAnchors(ctx, api.server, tx, jsString(tenant.Get("id")))
			if err != nil {
				return nil, err
			}
			items := make([]VisibleItem[*core.Object], 0, len(anchors))
			for _, authority := range anchors {
				items = append(items, VisibleItem[*core.Object]{
					Item:   authority,
					Target: GuardTarget{ResourceID: "pki/" + jsString(authority.Get("id")), Attributes: authorityAttributesOf(authority)},
				})
			}
			return items, nil
		})
	if err != nil {
		return Out[apitypes.PkiBundleOutput]{}, err
	}
	var bundle strings.Builder
	for _, authority := range authorities {
		bundle.WriteString(jsString(authority.Get("certificatePem")))
	}
	return Out[apitypes.PkiBundleOutput]{Value: core.NewObject("pem", bundle.String(), "authorities", float64(len(authorities)))}, nil
}

// trustAnchors is a tenant's active, unexpired roots, oldest first.
func trustAnchors(ctx context.Context, server *ServerContext, tx core.IamStore, tenantID string) ([]*core.Object, error) {
	found, err := tx.Find(ctx, "pkiAuthorities", core.NewObject("tenantId", tenantID, "state", "active", "type", "root"), nil)
	if err != nil {
		return nil, err
	}
	now := float64(server.Now())
	anchors := []*core.Object{}
	for _, authority := range found {
		if jsNumber(authority.Get("notAfter")) > now {
			anchors = append(anchors, authority)
		}
	}
	byCreatedThenID(anchors)
	return anchors, nil
}

// PkiRuntime is api/pki.ts createPkiRuntime(): `iam.Pki`, server side: public CRLs for relying parties, trust
// bundles, and certificate chain verification for servers that terminate mutual TLS.
type PkiRuntime struct {
	server *ServerContext
}

// Crl (api/pki.ts createPkiRuntime().crl): An authority's current CRL (DER and PEM), with no credential: CRLs are
// public.
func (s *PkiRuntime) Crl(ctx context.Context, authorityID string) (result *core.Object, err error) {
	return core.Transact(ctx, s.server.Store, func(ctx context.Context, tx core.IamStore) (*core.Object, error) {
		id, err := Text(authorityID, "authorityId")
		if err != nil {
			return nil, err
		}
		authority, err := tx.Get(ctx, "pkiAuthorities", id)
		if err != nil {
			return nil, err
		}
		if authority == nil {
			return nil, core.NewIamError("NOT_FOUND", "Certificate authority not found", 404)
		}
		current, err := CurrentCrl(ctx, s.server, tx, authority)
		if err != nil {
			return nil, err
		}
		der, _ := current.Get("der").([]byte)
		pemText, err := CrlPem(der)
		if err != nil {
			return nil, err
		}
		return current.Spread(core.NewObject("pem", pemText)), nil
	})
}

// textResponse is `new Response(text, { status })`.
func textResponse(status int, text string) *http.Response {
	header := http.Header{}
	header.Set("content-type", "text/plain;charset=UTF-8")
	return &http.Response{
		Status: strconv.Itoa(status) + " " + http.StatusText(status), StatusCode: status, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: header, Body: io.NopCloser(strings.NewReader(text)), ContentLength: int64(len(text)),
	}
}

// CrlResponse (api/pki.ts createPkiRuntime().crlResponse): An HTTP response for an authority's CRL distribution
// point (`application/pkix-crl`). When a fresh CRL cannot be signed (the authority's KMS key is disabled), the last
// one is served while it is still valid; otherwise 503.
func (s *PkiRuntime) CrlResponse(ctx context.Context, authorityID string) (result *http.Response, err error) {
	respond := func(der []byte, nextUpdate float64) *http.Response {
		header := http.Header{}
		header.Set("content-type", "application/pkix-crl")
		maxAge := math.Max(0, math.Floor((nextUpdate-float64(s.server.Now()))/2000))
		header.Set("cache-control", "public, max-age="+core.NumberString(maxAge))
		return &http.Response{
			Status: "200 OK", StatusCode: 200, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
			Header: header, Body: io.NopCloser(bytes.NewReader(der)), ContentLength: int64(len(der)),
		}
	}
	current, err := s.Crl(ctx, authorityID)
	if err == nil {
		der, _ := current.Get("der").([]byte)
		return respond(der, jsNumber(current.Get("nextUpdate"))), nil
	}
	known, ok := asIamError(err)
	if ok && known.Code == "NOT_FOUND" {
		return textResponse(404, "Not found"), nil
	}
	if ok {
		var cached *core.Object
		_ = s.server.Store.Transaction(ctx, func(ctx context.Context, tx core.IamStore) error {
			record, err := tx.Get(ctx, "pkiAuthorities", authorityID)
			cached = record
			return err
		})
		if cached != nil {
			if crl, isObject := cached.Get("crl").(*core.Object); isObject && crl != nil && jsNumber(crl.Get("nextUpdate")) > float64(s.server.Now()) {
				return respond(nodeBase64Decode(jsString(crl.Get("der"))), jsNumber(crl.Get("nextUpdate"))), nil
			}
		}
		return textResponse(503, "Revocation list unavailable"), nil
	}
	return nil, err
}

// Bundle (api/pki.ts createPkiRuntime().bundle): A tenant's trust anchors (active, unexpired roots) as one PEM
// bundle.
func (s *PkiRuntime) Bundle(ctx context.Context, tenantID string) (result string, err error) {
	return core.Transact(ctx, s.server.Store, func(ctx context.Context, tx core.IamStore) (string, error) {
		tenant, err := Text(tenantID, "tenantId")
		if err != nil {
			return "", err
		}
		anchors, err := trustAnchors(ctx, s.server, tx, tenant)
		if err != nil {
			return "", err
		}
		var bundle strings.Builder
		for _, authority := range anchors {
			bundle.WriteString(jsString(authority.Get("certificatePem")))
		}
		return bundle.String(), nil
	})
}

// Verify (api/pki.ts createPkiRuntime().verify): Verifies a presented certificate (leaf first; intermediates
// optional) against one tenant's stored chains: signatures, path lengths, validity, authority state and revocation,
// and for workload certificates the standing of the identity they name. Returns the SPIFFE ID and identity of
// workload certificates; throws `CERTIFICATE_INVALID` (401) otherwise. `tenantId` is required: trust is per
// organization.
func (s *PkiRuntime) Verify(ctx context.Context, chain any, options *core.Object) (result *core.Object, err error) {
	return VerifyCertificateChain(ctx, s.server, chain, options)
}

// CreatePkiRuntime builds the PkiRuntime (api/pki.ts createPkiRuntime).
func CreatePkiRuntime(server *ServerContext) *PkiRuntime {
	return &PkiRuntime{server: server}
}
