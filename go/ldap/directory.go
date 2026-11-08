package ldap

// Port of packages/ldap/src/directory.ts: the entries of a tenant's directory tree, built from the data the server's
// `ldap.directory` returns, and the attributes a search returns for an entry.

import (
	"regexp"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// DirectoryPerson is a person of DirectoryData.
type DirectoryPerson struct {
	ID            string
	UID           string
	Email         string
	HasEmail      bool
	Name          string
	HasName       bool
	EmailVerified bool
	// Attributes are the published identity attributes (model values).
	Attributes *core.Object
	GroupIDs   []string
}

// DirectoryGroup is a group of DirectoryData.
type DirectoryGroup struct {
	ID          string
	Name        string
	Description string
	MemberIDs   []string
}

// DirectoryService is a service account or agent of DirectoryData.
type DirectoryService struct {
	ID       string
	Name     string
	Kind     string
	GroupIDs []string
}

// DirectoryData is the directory data the server's `ldap.directory` returns (`LdapDirectory`).
type DirectoryData struct {
	TenantID   string
	TenantName string
	BaseDn     string
	// Scope is full or self.
	Scope    string
	People   []DirectoryPerson
	Groups   []DirectoryGroup
	Services []DirectoryService
}

func stringMember(object *core.Object, key string) string {
	text, _ := object.Get(key).(string)
	return text
}

func stringList(value any) []string {
	list, _ := value.([]any)
	out := make([]string, 0, len(list))
	for _, item := range list {
		if text, ok := item.(string); ok {
			out = append(out, text)
		}
	}
	return out
}

func objects(value any) []*core.Object {
	list, _ := value.([]any)
	out := make([]*core.Object, 0, len(list))
	for _, item := range list {
		if object, ok := item.(*core.Object); ok {
			out = append(out, object)
		}
	}
	return out
}

// DirectoryDataFrom reads the model value `ldap.directory` answers.
func DirectoryDataFrom(value any) DirectoryData {
	object, _ := value.(*core.Object)
	data := DirectoryData{TenantID: stringMember(object, "tenantId"), TenantName: stringMember(object, "tenantName"),
		BaseDn: stringMember(object, "baseDn"), Scope: stringMember(object, "scope")}
	for _, person := range objects(object.Get("people")) {
		attributes, _ := person.Get("attributes").(*core.Object)
		if attributes == nil {
			attributes = core.NewObject()
		}
		name, hasName := person.Get("name").(string)
		email, hasEmail := person.Get("email").(string)
		verified, _ := person.Get("emailVerified").(bool)
		data.People = append(data.People, DirectoryPerson{ID: stringMember(person, "id"), UID: stringMember(person, "uid"),
			Email: email, HasEmail: hasEmail, Name: name, HasName: hasName, EmailVerified: verified,
			Attributes: attributes, GroupIDs: stringList(person.Get("groupIds"))})
	}
	for _, group := range objects(object.Get("groups")) {
		data.Groups = append(data.Groups, DirectoryGroup{ID: stringMember(group, "id"), Name: stringMember(group, "name"),
			Description: stringMember(group, "description"), MemberIDs: stringList(group.Get("memberIds"))})
	}
	for _, service := range objects(object.Get("services")) {
		data.Services = append(data.Services, DirectoryService{ID: stringMember(service, "id"), Name: stringMember(service, "name"),
			Kind: stringMember(service, "kind"), GroupIDs: stringList(service.Get("groupIds"))})
	}
	return data
}

// DirectoryEntry is one entry of the tree: its DN, the normalized DN, and attributes (user and operational, in
// output order).
type DirectoryEntry struct {
	Dn           string
	NormalizedDn string
	Attributes   []AttributeValues
	Operational  []AttributeValues
	// Index maps lowercased attribute names to values, for filters (user and operational attributes).
	Index EntryAttributes
}

var standardAttributes = map[string]bool{}

func init() {
	for _, name := range []string{"objectClass", "uid", "cn", "sn", "givenName", "displayName", "mail", "memberOf", "member",
		"ou", "o", "dc", "description", "entryUUID", "entryDN"} {
		standardAttributes[strings.ToLower(name)] = true
	}
}

func entry(dn string, attributes []AttributeValues, operational []AttributeValues) (DirectoryEntry, error) {
	var kept []AttributeValues
	for _, attribute := range attributes {
		if len(attribute.Values) > 0 {
			kept = append(kept, attribute)
		}
	}
	extra := append(append([]AttributeValues(nil), operational...), AttributeValues{"entryDN", []string{dn}})
	index := EntryAttributes{}
	for _, attribute := range append(append([]AttributeValues(nil), kept...), extra...) {
		index[core.JSLower(attribute.Name)] = attribute.Values
	}
	normalized, err := NormalizeDn(dn)
	if err != nil {
		return DirectoryEntry{}, err
	}
	return DirectoryEntry{Dn: dn, NormalizedDn: normalized, Attributes: kept, Operational: extra, Index: index}, nil
}

// words is `(name ?? ”).trim().split(/\s+/).filter(Boolean)`.
func words(name string) []string {
	var out []string
	for _, word := range strings.FieldsFunc(name, isJSSpace) {
		if word != "" {
			out = append(out, word)
		}
	}
	return out
}

// text is `typeof value === 'string' ? value : JSON.stringify(value)`.
func text(value any) string {
	if s, ok := value.(string); ok {
		return s
	}
	encoded, ok, _ := core.Stringify(value)
	if !ok {
		return "undefined"
	}
	return encoded
}

var extraAttributeName = regexp.MustCompile(`^[a-zA-Z][a-zA-Z0-9-]{0,63}$`)

// BuildEntries is the tree under the tenant's base DN: the base entry, `ou=people` (inetOrgPerson entries named
// `uid={uid}`), `ou=groups` (groupOfNames named `cn={name}`, with `member` DNs) and `ou=services` (service accounts
// and agents, named `cn={name}`). People and services carry `memberOf`; `entryUUID` is the Better IAM ID.
func BuildEntries(data DirectoryData) ([]DirectoryEntry, error) {
	base := data.BaseDn
	rdns, err := ParseDn(base)
	if err != nil {
		return nil, err
	}
	var naming *Rdn
	if len(rdns) > 0 && len(rdns[0]) > 0 {
		naming = &rdns[0][0]
	}
	namingType := ""
	if naming != nil {
		namingType = core.JSLower(naming.Type)
	}
	baseClasses := []string{"top", "organization"}
	switch namingType {
	case "dc":
		baseClasses = []string{"top", "dcObject", "organization"}
	case "ou":
		baseClasses = []string{"top", "organizationalUnit"}
	}
	baseAttributes := []AttributeValues{{"objectClass", baseClasses}}
	if naming != nil {
		baseAttributes = append(baseAttributes, AttributeValues{naming.Type, []string{naming.Value}})
	}
	if namingType != "o" {
		baseAttributes = append(baseAttributes, AttributeValues{"o", []string{data.TenantName}})
	}
	var entries []DirectoryEntry
	add := func(dn string, attributes []AttributeValues, operational []AttributeValues) error {
		built, err := entry(dn, attributes, operational)
		if err != nil {
			return err
		}
		entries = append(entries, built)
		return nil
	}
	if err := add(base, baseAttributes, nil); err != nil {
		return nil, err
	}
	container := func(ou string) error {
		return add("ou="+ou+","+base, []AttributeValues{{"objectClass", []string{"top", "organizationalUnit"}}, {"ou", []string{ou}}}, nil)
	}
	if err := container("people"); err != nil {
		return nil, err
	}
	if err := container("groups"); err != nil {
		return nil, err
	}
	if len(data.Services) > 0 || data.Scope == "full" {
		if err := container("services"); err != nil {
			return nil, err
		}
	}
	personDn := map[string]string{}
	for _, person := range data.People {
		personDn[person.ID] = "uid=" + EscapeDnValue(person.UID) + ",ou=people," + base
	}
	// Names can collide (two service accounts called "ci"): the first keeps its name, later ones are named by ID.
	named := func(ids, names []string, ou string) map[string]string {
		taken := map[string]bool{}
		out := map[string]string{}
		for i, id := range ids {
			rdn := names[i]
			if taken[core.JSLower(names[i])] {
				rdn = id
			}
			taken[core.JSLower(rdn)] = true
			out[id] = "cn=" + EscapeDnValue(rdn) + ",ou=" + ou + "," + base
		}
		return out
	}
	var serviceIDs, serviceNames, groupIDs, groupNames []string
	for _, service := range data.Services {
		serviceIDs, serviceNames = append(serviceIDs, service.ID), append(serviceNames, service.Name)
	}
	for _, group := range data.Groups {
		groupIDs, groupNames = append(groupIDs, group.ID), append(groupNames, group.Name)
	}
	serviceDn := named(serviceIDs, serviceNames, "services")
	groupDn := named(groupIDs, groupNames, "groups")
	memberOf := func(ids []string) []string {
		out := []string{}
		for _, id := range ids {
			if dn, ok := groupDn[id]; ok {
				out = append(out, dn)
			}
		}
		return out
	}
	for _, person := range data.People {
		parts := words(person.Name)
		var extra []AttributeValues
		for _, name := range person.Attributes.Keys() {
			value := person.Attributes.Get(name)
			if !extraAttributeName.MatchString(name) || standardAttributes[core.JSLower(name)] || value == nil || core.IsUndefined(value) {
				continue
			}
			list, isList := value.([]any)
			if !isList {
				list = []any{value}
			}
			values := make([]string, len(list))
			for i, item := range list {
				values[i] = text(item)
			}
			extra = append(extra, AttributeValues{name, values})
		}
		cn := person.UID
		if person.HasName {
			cn = person.Name
		} else if person.HasEmail {
			cn = person.Email
		}
		sn := person.UID
		if len(parts) > 0 {
			sn = parts[len(parts)-1]
		}
		givenName := []string{}
		if len(parts) > 1 {
			givenName = []string{parts[0]}
		}
		displayName := []string{}
		if person.HasName && person.Name != "" {
			displayName = []string{person.Name}
		}
		mail := []string{}
		if person.Email != "" {
			mail = []string{person.Email}
		}
		attributes := []AttributeValues{
			{"objectClass", []string{"top", "person", "organizationalPerson", "inetOrgPerson"}},
			{"uid", []string{person.UID}},
			{"cn", []string{cn}},
			{"sn", []string{sn}},
			{"givenName", givenName},
			{"displayName", displayName},
			{"mail", mail},
			{"memberOf", memberOf(person.GroupIDs)},
		}
		if err := add(personDn[person.ID], append(attributes, extra...), []AttributeValues{{"entryUUID", []string{person.ID}}}); err != nil {
			return nil, err
		}
	}
	for _, service := range data.Services {
		dn := serviceDn[service.ID]
		parsed, err := ParseDn(dn)
		if err != nil {
			return nil, err
		}
		description := "Service account"
		if service.Kind == "agent" {
			description = "AI agent"
		}
		if err := add(dn, []AttributeValues{
			{"objectClass", []string{"top", "account", "applicationProcess"}},
			{"cn", []string{service.Name}},
			{"uid", []string{parsed[0][0].Value}},
			{"description", []string{description}},
			{"memberOf", memberOf(service.GroupIDs)},
		}, []AttributeValues{{"entryUUID", []string{service.ID}}}); err != nil {
			return nil, err
		}
	}
	for _, group := range data.Groups {
		members := []string{}
		for _, id := range group.MemberIDs {
			if dn, ok := personDn[id]; ok {
				members = append(members, dn)
			} else if dn, ok := serviceDn[id]; ok {
				members = append(members, dn)
			}
		}
		description := []string{}
		if group.Description != "" {
			description = []string{group.Description}
		}
		if err := add(groupDn[group.ID], []AttributeValues{
			{"objectClass", []string{"top", "groupOfNames"}},
			{"cn", []string{group.Name}},
			{"description", description},
			{"member", members},
		}, []AttributeValues{{"entryUUID", []string{group.ID}}}); err != nil {
			return nil, err
		}
	}
	return entries, nil
}

// SelectAttributes are the attributes a search returns for an entry: all user attributes for none or `*`,
// operational ones for `+` or by name, only the named ones otherwise, nothing for `1.1`.
func SelectAttributes(target DirectoryEntry, requested []string) []AttributeValues {
	wanted := make([]string, len(requested))
	for i, name := range requested {
		wanted[i] = core.JSLower(name)
	}
	if len(wanted) == 1 && wanted[0] == "1.1" {
		return []AttributeValues{}
	}
	all := len(wanted) == 0 || containsString(wanted, "*")
	operational := containsString(wanted, "+")
	out := []AttributeValues{}
	for _, attribute := range target.Attributes {
		if all || containsString(wanted, core.JSLower(attribute.Name)) {
			out = append(out, attribute)
		}
	}
	for _, attribute := range target.Operational {
		if operational || containsString(wanted, core.JSLower(attribute.Name)) {
			out = append(out, attribute)
		}
	}
	return out
}

func containsString(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}
