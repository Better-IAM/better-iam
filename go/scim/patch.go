package scim

// Port of packages/scim/src/patch.ts: RFC 7644 §3.5.2 PATCH operations, with value filters, sub-attributes,
// schema-qualified names and the Entra ID / Okta conventions.

import (
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// canonicalNames is the canonical casing of every attribute PATCH may address, by lowercase name.
var canonicalNames = func() map[string]string {
	names := []string{
		"userName", "displayName", "externalId", "active", "emails", "name", "title", "members", "formatted", "familyName",
		"givenName", "middleName", "honorificPrefix", "honorificSuffix", "value", "type", "primary", "display", "$ref",
		"employeeNumber", "costCenter", "organization", "division", "department", "manager", EnterpriseSchema,
	}
	out := make(map[string]string, len(names))
	for _, name := range names {
		out[core.JSLower(name)] = name
	}
	return out
}()

var topLevel = map[ResourceType][]string{
	"Users":  {"userName", "displayName", "externalId", "active", "emails", "name", "title", EnterpriseSchema},
	"Groups": {"displayName", "externalId", "members"},
}

var requiredAttributes = map[ResourceType][]string{
	"Users":  {"userName", "active"},
	"Groups": {"displayName"},
}

type patchPath struct {
	keys   []string
	filter *FilterNode
	sub    string
}

func invalidPath(message string) error { return core.NewIamError("invalidPath", message) }

func canonical(segments []string, resourceType ResourceType) ([]string, error) {
	keys := make([]string, len(segments))
	for index, segment := range segments {
		name, ok := canonicalNames[segment]
		if !ok {
			return nil, invalidPath(`Unsupported PATCH attribute "` + segment + `".`)
		}
		keys[index] = name
	}
	if !containsString(topLevel[resourceType], keys[0]) {
		return nil, invalidPath(`"` + keys[0] + `" is not a mutable ` + resourceType + ` attribute.`)
	}
	return keys, nil
}

var subAttributePattern = regexp.MustCompile(`^\.[A-Za-z$][A-Za-z0-9_$-]*$`)

// parsePatchPath parses `attrPath [ "[" valFilter "]" ] [ "." subAttr ]`, with schema-qualified names.
func parsePatchPath(path string, resourceType ResourceType) (*patchPath, error) {
	open := strings.Index(path, "[")
	segments := func(raw string) ([]string, error) {
		result, err := AttributePath(raw)
		if err != nil {
			return nil, invalidPath(`Invalid PATCH path "` + path + `".`)
		}
		return result, nil
	}
	if open == -1 {
		parsed, err := segments(path)
		if err != nil {
			return nil, err
		}
		keys, err := canonical(parsed, resourceType)
		if err != nil {
			return nil, err
		}
		return &patchPath{keys: keys}, nil
	}
	closing := strings.LastIndex(path, "]")
	rest := path[closing+1:]
	if closing < open || (rest != "" && !subAttributePattern.MatchString(rest)) {
		return nil, invalidPath(`Invalid PATCH path "` + path + `".`)
	}
	parsed, err := segments(path[:open])
	if err != nil {
		return nil, err
	}
	keys, err := canonical(parsed, resourceType)
	if err != nil {
		return nil, err
	}
	if len(keys) != 1 || (keys[0] != "emails" && keys[0] != "members") {
		return nil, invalidPath("Value filters apply only to multi-valued attributes.")
	}
	filter, err := ParseFilterExpression(path[open+1 : closing])
	if err != nil {
		return nil, err
	}
	result := &patchPath{keys: keys, filter: filter}
	if rest != "" {
		subKeys, err := canonical([]string{core.JSLower(keys[0]), core.JSLower(rest[1:])}, resourceType)
		if err != nil {
			return nil, err
		}
		result.sub = subKeys[1]
	}
	return result, nil
}

// asciiFold reports whether s equals word ignoring ASCII case only (a non-unicode /i regular expression).
func asciiFold(s, word string) bool {
	if len(s) != len(word) {
		return false
	}
	for i := 0; i < len(s); i++ {
		a, b := s[i], word[i]
		if a >= 'A' && a <= 'Z' {
			a += 'a' - 'A'
		}
		if a != b {
			return false
		}
	}
	return true
}

// coerce accepts Entra ID's "True"/"False" strings (exactly those spellings, any case) for boolean attributes.
func coerce(key string, value any) any {
	if text, ok := value.(string); ok && booleanAttributes[key] && (asciiFold(text, "true") || asciiFold(text, "false")) {
		return asciiFold(text, "true")
	}
	return value
}

// seed answers the attributes a simple `sub eq "x"` (optionally and-ed) filter pins, used to seed an added
// multi-valued entry; nil when the filter pins nothing.
func seed(filter *FilterNode) *core.Object {
	if filter.Kind == "compare" && filter.Op == "eq" && len(filter.Path) == 1 {
		if key, ok := canonicalNames[filter.Path[0]]; ok {
			return core.NewObject().SetRaw(key, filter.Value)
		}
		return nil
	}
	if filter.Kind == "and" {
		left, right := seed(filter.Left), seed(filter.Right)
		if left != nil && right != nil {
			return left.Spread(right)
		}
	}
	return nil
}

// typeError is a JavaScript TypeError (a 500 for the SCIM handler).
func typeError(message string) error { return &core.TypeError{Message: message} }

// setMember is `item[name] = value` in strict mode: objects take the member, arrays a named property JSON never
// shows (or an element for an index name), and anything else is a TypeError.
func setMember(item any, name string, value any) (any, error) {
	switch target := item.(type) {
	case *core.Object:
		if target != nil {
			target.SetRaw(name, value)
			return item, nil
		}
	case []any:
		return setArrayIndex(target, name, value), nil
	}
	if nullish(item) {
		return item, typeError("Cannot set properties of " + jsString(item))
	}
	return item, typeError("Cannot create property '" + name + "' on " + typeOf(item) + " '" + jsString(item) + "'")
}

// arrayIndexOf reports whether name is a canonical array index.
func arrayIndexOf(name string) (int, bool) {
	n, err := strconv.ParseUint(name, 10, 32)
	if err != nil || strconv.FormatUint(n, 10) != name || n >= math.MaxUint32 || n > 1<<20 {
		return 0, false
	}
	return int(n), true
}

func setArrayIndex(list []any, name string, value any) []any {
	index, ok := arrayIndexOf(name)
	if !ok {
		return list
	}
	for len(list) <= index {
		list = append(list, core.Undefined)
	}
	list[index] = value
	return list
}

// deleteMember is `delete item[name]` in strict mode.
func deleteMember(item any, name string) error {
	switch target := item.(type) {
	case *core.Object:
		if target != nil {
			target.Delete(name)
			return nil
		}
	case []any:
		if index, ok := arrayIndexOf(name); ok && index < len(target) {
			target[index] = core.Undefined
		}
		return nil
	case string:
		if index, ok := arrayIndexOf(name); ok && index < utf16Len(target) {
			return typeError("Cannot delete property '" + name + "' of [object String]")
		}
		return nil
	}
	if nullish(item) {
		return typeError("Cannot convert undefined or null to object")
	}
	return nil
}

// ownKeys is Object.keys(item) for a matched multi-valued entry; null and undefined are a TypeError.
func ownKeys(item any) ([]string, error) {
	switch target := item.(type) {
	case *core.Object:
		if target != nil {
			return target.Keys(), nil
		}
	case []any:
		keys := make([]string, 0, len(target))
		for index, element := range target {
			if !core.IsUndefined(element) {
				keys = append(keys, strconv.Itoa(index))
			}
		}
		return keys, nil
	case string:
		keys := make([]string, utf16Len(target))
		for index := range keys {
			keys[index] = strconv.Itoa(index)
		}
		return keys, nil
	}
	if nullish(item) {
		return nil, typeError("Cannot convert undefined or null to object")
	}
	return nil, nil
}

func applyFiltered(document *core.Object, operation string, path *patchPath, value any) error {
	key := path.keys[0]
	items, _ := document.Get(key).([]any)
	if items == nil {
		items = []any{}
	}
	prefix := []string{core.JSLower(key)}
	matched := make([]int, 0, len(items))
	for index, item := range items {
		if EvaluateFilter(path.filter, item, prefix) {
			matched = append(matched, index)
		}
	}
	if operation == "remove" {
		if path.sub == "" {
			isMatched := make(map[int]bool, len(matched))
			for _, index := range matched {
				isMatched[index] = true
			}
			kept := make([]any, 0, len(items))
			for index, item := range items {
				if !isMatched[index] {
					kept = append(kept, item)
				}
			}
			document.SetRaw(key, kept)
			return nil
		}
		for _, index := range matched {
			if err := deleteMember(items[index], path.sub); err != nil {
				return err
			}
		}
		return nil
	}
	if len(matched) == 0 {
		initial := seed(path.filter)
		if operation == "replace" || initial == nil {
			return core.NewIamError("noTarget", "The value filter matched no values.")
		}
		var entry *core.Object
		if path.sub != "" {
			entry = initial.Spread(core.NewObject().SetRaw(path.sub, coerce(path.sub, value)))
		} else if record, ok := value.(*core.Object); ok && record != nil {
			entry = initial.Spread(record)
		} else {
			entry = initial.Spread()
		}
		document.SetRaw(key, append(append([]any{}, items...), entry))
		return nil
	}
	for _, index := range matched {
		item := items[index]
		if path.sub != "" {
			updated, err := setMember(item, path.sub, coerce(path.sub, value))
			if err != nil {
				return err
			}
			items[index] = updated
			continue
		}
		record, ok := value.(*core.Object)
		if !ok || record == nil {
			return core.NewIamError("invalidValue", "Expected an object value.")
		}
		if operation == "replace" {
			names, err := ownKeys(item)
			if err != nil {
				return err
			}
			for _, name := range names {
				if err := deleteMember(item, name); err != nil {
					return err
				}
			}
		}
		switch target := item.(type) {
		case *core.Object:
			target.Assign(record)
		case []any:
			record.Entries(func(name string, member any) bool {
				target = setArrayIndex(target, name, member)
				return true
			})
			items[index] = target
		default:
			if nullish(item) {
				return typeError("Cannot convert undefined or null to object")
			}
		}
	}
	return nil
}

// sameValueZero is the SameValueZero comparison (Set#has).
func sameValueZero(a, b any) bool {
	x, xNumber := a.(float64)
	y, yNumber := b.(float64)
	if xNumber && yNumber && math.IsNaN(x) && math.IsNaN(y) {
		return true
	}
	return strictEqual(a, b)
}

func applyAt(document *core.Object, resourceType ResourceType, operation string, keys []string, input any) error {
	leaf := keys[len(keys)-1]
	value := coerce(leaf, input)
	parent := document
	for _, key := range keys[:len(keys)-1] {
		child := parent.Get(key)
		if _, isArray := child.([]any); isArray {
			return invalidPath("Use a value filter to modify one value of " + key + ".")
		}
		if !isObject(child) {
			if operation == "remove" {
				return nil
			}
			parent.SetRaw(key, core.NewObject())
		}
		parent = parent.Get(key).(*core.Object)
	}
	current := parent.Get(leaf)
	if operation == "remove" {
		if len(keys) == 1 && containsString(requiredAttributes[resourceType], leaf) {
			return core.NewIamError("mutability", "Required attribute cannot be removed.")
		}
		// Entra ID removes individual members as `{ op: "remove", path: "members", value: [{ value }] }`.
		currentList, currentIsArray := current.([]any)
		valueList, valueIsArray := value.([]any)
		if currentIsArray && valueIsArray {
			valueOf := func(item any) any {
				if isObject(item) {
					return item.(*core.Object).Get("value")
				}
				return item
			}
			removed := make([]any, len(valueList))
			for index, item := range valueList {
				removed[index] = valueOf(item)
			}
			kept := make([]any, 0, len(currentList))
			for _, item := range currentList {
				candidate := valueOf(item)
				drop := false
				for _, gone := range removed {
					if sameValueZero(candidate, gone) {
						drop = true
						break
					}
				}
				if !drop {
					kept = append(kept, item)
				}
			}
			parent.SetRaw(leaf, kept)
		} else {
			parent.Delete(leaf)
		}
		return nil
	}
	if currentList, ok := current.([]any); operation == "add" && ok {
		parent.SetRaw(leaf, append(append([]any{}, currentList...), flat1(value)...))
	} else if currentObject, ok := current.(*core.Object); operation == "add" && ok && currentObject != nil && isObject(value) {
		parent.SetRaw(leaf, currentObject.Spread(value.(*core.Object)))
	} else {
		parent.SetRaw(leaf, value)
	}
	return nil
}

// applyPatchOperation applies one PatchOp operation in place to a resource's writable document. ignored names
// attributes the service drops instead of applying: a key of a pathless value (explicitPath false) or a whole path
// (explicitPath true). An operation on one of them is skipped. A nil path is an operation without a path.
func applyPatchOperation(document *core.Object, resourceType ResourceType, operation string, path *string, value any, ignored func(attribute string, explicitPath bool) bool) error {
	if ignored == nil {
		ignored = func(string, bool) bool { return false }
	}
	if path == nil {
		if operation == "remove" {
			return core.NewIamError("noTarget", "remove requires a path.")
		}
		record, ok := value.(*core.Object)
		if !ok || record == nil {
			return core.NewIamError("invalidValue", "A PATCH without a path requires an object value.")
		}
		for _, name := range record.Keys() {
			item := record.Get(name)
			if name == "schemas" || ignored(name, false) {
				continue
			}
			segments, err := AttributePath(name)
			if err != nil {
				return invalidPath(`Invalid attribute "` + name + `".`)
			}
			keys, err := canonical(segments, resourceType)
			if err != nil {
				return err
			}
			// A whole extension object merges key by key so schema-qualified and nested forms behave alike.
			if extension, ok := item.(*core.Object); ok && extension != nil && len(keys) == 1 && keys[0] == EnterpriseSchema {
				for _, sub := range extension.Keys() {
					subKeys, err := canonical(append(append([]string{}, segments...), core.JSLower(sub)), resourceType)
					if err != nil {
						return err
					}
					if err := applyAt(document, resourceType, operation, subKeys, extension.Get(sub)); err != nil {
						return err
					}
				}
			} else if err := applyAt(document, resourceType, operation, keys, item); err != nil {
				return err
			}
		}
		return nil
	}
	if ignored(*path, true) {
		return nil
	}
	parsed, err := parsePatchPath(*path, resourceType)
	if err != nil {
		return err
	}
	if parsed.filter != nil {
		return applyFiltered(document, operation, parsed, value)
	}
	return applyAt(document, resourceType, operation, parsed.keys, value)
}
