package core

import (
	"regexp"
	"sort"
)

// Security classification: the pure lattice behind clearances and mandatory access control. A party may read a
// labeled resource only when its adjudicated clearance dominates the label (no read up).

// ClassificationLevel is one level of a scheme. Ranks order levels; the lowest (rank 0) is the public level.
type ClassificationLevel struct {
	ID           string  `json:"id"`
	Name         string  `json:"name"`
	Rank         float64 `json:"rank"`
	Abbreviation string  `json:"abbreviation,omitempty"`
}

// Compartment is a control system or special access program.
type Compartment struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// ClassificationSchemeDefinition is a tenant's classification scheme.
type ClassificationSchemeDefinition struct {
	Levels         []ClassificationLevel `json:"levels"`
	Compartments   []Compartment         `json:"compartments"`
	OwnerCountries []string              `json:"ownerCountries"`
	Caveats        []string              `json:"caveats"`
}

// ClassificationLabel is the classification of one resource. A nil ReleasableTo means unrestricted releasability; an
// empty (non-nil) list means releasable to citizens of the owner countries only.
type ClassificationLabel struct {
	Level        string   `json:"level"`
	Compartments []string `json:"compartments,omitempty"`
	Noforn       bool     `json:"noforn,omitempty"`
	ReleasableTo []string `json:"releasableTo"`
}

// MarshalJSON writes the label as TypeScript builds it (absent members left out, an empty releasableTo kept).
func (l ClassificationLabel) MarshalJSON() ([]byte, error) { return l.ToValue().MarshalJSON() }

// ToValue is the label as a model value.
func (l ClassificationLabel) ToValue() *Object {
	o := NewObject("level", l.Level)
	if len(l.Compartments) > 0 {
		o.Set("compartments", l.Compartments)
	}
	if l.Noforn {
		o.Set("noforn", true)
	}
	if l.ReleasableTo != nil {
		o.Set("releasableTo", l.ReleasableTo)
	}
	return o
}

// ClearanceParty is one person or agent taking part in a decision, as their adjudicated clearance stands.
type ClearanceParty struct {
	IdentityID string
	// Rank of the cleared level; -1 = no clearance.
	Rank float64
	// Compartments the party is read into.
	Compartments map[string]bool
	// Citizenship: alpha-3 codes from the adjudicated clearance record.
	Citizenship map[string]bool
}

// DominanceFailure is level, compartment, noforn, releasability or invalid-label ("" when the party dominates).
type DominanceFailure = string

// ClassificationIDPattern matches level and compartment ids.
var ClassificationIDPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$`)
var countryPattern = regexp.MustCompile(`^[A-Z]{3}$`)

// ClassificationLimits are the bounds ValidateScheme and ValidateLabel enforce.
var ClassificationLimits = struct {
	MinLevels, MaxLevels, MaxRank, MaxCompartments, MaxOwnerCountries, MaxReleasableTo int
	MaxLevelNameLength, MaxCompartmentNameLength, MaxAbbreviationLength                int
}{2, 20, 999, 200, 64, 300, 64, 128, 16}

var caveatNames = map[string]bool{"NOFORN": true, "RELTO": true}

func invalidInput(message string) error { return NewIamError("INVALID_INPUT", message) }

// objectPrototypeNames are the properties of Object.prototype an identifier must not be.
var objectPrototypeNames = map[string]bool{
	"constructor": true, "hasOwnProperty": true, "isPrototypeOf": true, "propertyIsEnumerable": true,
	"toLocaleString": true, "toString": true, "valueOf": true, "__proto__": true, "__defineGetter__": true,
	"__defineSetter__": true, "__lookupGetter__": true, "__lookupSetter__": true,
}

func classificationIdentifier(value any) bool {
	text, ok := value.(string)
	return ok && ClassificationIDPattern.MatchString(text) && !objectPrototypeNames[text]
}

// classificationText is display text: trimmed and non-empty, without control, separator, bidirectional override,
// zero-width-no-break or unpaired surrogate characters.
func classificationText(value any, max int) bool {
	text, ok := value.(string)
	if !ok {
		return false
	}
	length := UTF16Len(text)
	if length == 0 || length > max || JSTrim(text) != text {
		return false
	}
	units := ToUTF16(text)
	for index := 0; index < len(units); index++ {
		code := units[index]
		if code < 0x20 || (code >= 0x7f && code <= 0x9f) || code == 0x061c || code == 0x200e || code == 0x200f ||
			(code >= 0x2028 && code <= 0x202e) || (code >= 0x2066 && code <= 0x2069) || code == 0xfeff {
			return false
		}
		if code >= 0xd800 && code <= 0xdbff {
			if index+1 >= len(units) || !(units[index+1] >= 0xdc00 && units[index+1] <= 0xdfff) {
				return false
			}
			index++
		} else if code >= 0xdc00 && code <= 0xdfff {
			return false
		}
	}
	return true
}

func distinctIgnoringCase(values []string) bool {
	seen := map[string]bool{}
	for _, value := range values {
		seen[JSLower(value)] = true
	}
	return len(seen) == len(values)
}

func listOrEmpty(o *Object, key string) (any, bool) {
	value := o.Get(key)
	if IsUndefined(value) {
		return []any{}, true
	}
	return value, false
}

func itoa(n int) string { return NumberString(float64(n)) }

// ValidateScheme validates a scheme definition (any model value or a ClassificationSchemeDefinition) and returns a
// fresh copy (absent compartments, ownerCountries and caveats read as empty). Fails with INVALID_INPUT.
func ValidateScheme(input any) (*ClassificationSchemeDefinition, error) {
	limits := ClassificationLimits
	o, ok := Normalize(input).(*Object)
	if !ok || o == nil {
		return nil, invalidInput("The classification scheme must be an object")
	}
	if !onlyKeys(o, "levels", "compartments", "ownerCountries", "caveats") {
		return nil, invalidInput("Unknown classification scheme field")
	}
	levels, isList := o.Get("levels").([]any)
	if !isList || len(levels) < limits.MinLevels || len(levels) > limits.MaxLevels {
		return nil, invalidInput("A classification scheme needs " + itoa(limits.MinLevels) + " to " + itoa(limits.MaxLevels) + " levels")
	}
	out := &ClassificationSchemeDefinition{Levels: []ClassificationLevel{}, Compartments: []Compartment{}, OwnerCountries: []string{}, Caveats: []string{}}
	for index, item := range levels {
		at := "levels[" + itoa(index) + "]"
		level, ok := item.(*Object)
		if !ok || level == nil {
			return nil, invalidInput(at + " must be an object")
		}
		if !onlyKeys(level, "id", "name", "rank", "abbreviation") {
			return nil, invalidInput(at + " has an unknown field")
		}
		if !classificationIdentifier(level.Get("id")) {
			return nil, invalidInput(at + ".id is not a valid identifier")
		}
		if !classificationText(level.Get("name"), limits.MaxLevelNameLength) {
			return nil, invalidInput(at + ".name must be 1 to " + itoa(limits.MaxLevelNameLength) + " printable characters")
		}
		rank, isNumber := level.Get("rank").(float64)
		if !isNumber || !IsSafeInteger(rank) || rank > float64(limits.MaxRank) {
			return nil, invalidInput(at + ".rank must be an integer from 0 to " + itoa(limits.MaxRank))
		}
		if index > 0 {
			if rank <= out.Levels[index-1].Rank {
				return nil, invalidInput("Level ranks must start at 0 and strictly increase in the order the levels are listed")
			}
		} else if rank != 0 {
			return nil, invalidInput("Level ranks must start at 0 and strictly increase in the order the levels are listed")
		}
		abbreviation := level.Get("abbreviation")
		if !IsUndefined(abbreviation) && !classificationText(abbreviation, limits.MaxAbbreviationLength) {
			return nil, invalidInput(at + ".abbreviation must be 1 to " + itoa(limits.MaxAbbreviationLength) + " printable characters")
		}
		entry := ClassificationLevel{ID: level.Get("id").(string), Name: level.Get("name").(string), Rank: rank}
		if text, ok := abbreviation.(string); ok {
			entry.Abbreviation = text
		}
		out.Levels = append(out.Levels, entry)
	}
	var ids, names, abbreviations []string
	for _, level := range out.Levels {
		ids = append(ids, level.ID)
		names = append(names, level.Name)
		if level.Abbreviation != "" {
			abbreviations = append(abbreviations, level.Abbreviation)
		}
	}
	if !distinctIgnoringCase(ids) {
		return nil, invalidInput("Level ids must be unique, ignoring case")
	}
	if !distinctIgnoringCase(names) {
		return nil, invalidInput("Level names must be unique, ignoring case")
	}
	if !distinctIgnoringCase(abbreviations) {
		return nil, invalidInput("Level abbreviations must be unique, ignoring case")
	}

	compartmentsValue, _ := listOrEmpty(o, "compartments")
	compartments, isList := compartmentsValue.([]any)
	if !isList || len(compartments) > limits.MaxCompartments {
		return nil, invalidInput("A classification scheme has at most " + itoa(limits.MaxCompartments) + " compartments")
	}
	for index, item := range compartments {
		at := "compartments[" + itoa(index) + "]"
		compartment, ok := item.(*Object)
		if !ok || compartment == nil {
			return nil, invalidInput(at + " must be an object")
		}
		if !onlyKeys(compartment, "id", "name") {
			return nil, invalidInput(at + " has an unknown field")
		}
		if !classificationIdentifier(compartment.Get("id")) {
			return nil, invalidInput(at + ".id is not a valid identifier")
		}
		if !classificationText(compartment.Get("name"), limits.MaxCompartmentNameLength) {
			return nil, invalidInput(at + ".name must be 1 to " + itoa(limits.MaxCompartmentNameLength) + " printable characters")
		}
		out.Compartments = append(out.Compartments, Compartment{ID: compartment.Get("id").(string), Name: compartment.Get("name").(string)})
	}
	ids, names = nil, nil
	for _, compartment := range out.Compartments {
		ids = append(ids, compartment.ID)
		names = append(names, compartment.Name)
	}
	if !distinctIgnoringCase(ids) {
		return nil, invalidInput("Compartment ids must be unique, ignoring case")
	}
	if !distinctIgnoringCase(names) {
		return nil, invalidInput("Compartment names must be unique, ignoring case")
	}

	ownersValue, _ := listOrEmpty(o, "ownerCountries")
	owners, isList := ownersValue.([]any)
	if !isList || len(owners) > limits.MaxOwnerCountries {
		return nil, invalidInput("ownerCountries must list at most " + itoa(limits.MaxOwnerCountries) + " countries")
	}
	seen := map[string]bool{}
	for _, item := range owners {
		country, ok := item.(string)
		if !ok || !countryPattern.MatchString(country) {
			return nil, invalidInput("ownerCountries must be ISO 3166-1 alpha-3 codes in upper case")
		}
		out.OwnerCountries = append(out.OwnerCountries, country)
		seen[country] = true
	}
	if len(seen) != len(out.OwnerCountries) {
		return nil, invalidInput("ownerCountries must not repeat a country")
	}

	caveatsValue, _ := listOrEmpty(o, "caveats")
	caveats, isList := caveatsValue.([]any)
	if !isList {
		return nil, invalidInput("caveats must be a list")
	}
	seen = map[string]bool{}
	for _, item := range caveats {
		caveat, ok := item.(string)
		if !ok || !caveatNames[caveat] {
			return nil, invalidInput("caveats may be NOFORN and RELTO only")
		}
		out.Caveats = append(out.Caveats, caveat)
		seen[caveat] = true
	}
	if len(seen) != len(out.Caveats) {
		return nil, invalidInput("caveats must not repeat a caveat")
	}
	if seen["NOFORN"] && len(out.OwnerCountries) == 0 {
		return nil, invalidInput("The NOFORN caveat needs at least one owner country")
	}
	return out, nil
}

func schemeHasCaveat(scheme *ClassificationSchemeDefinition, caveat string) bool {
	for _, item := range scheme.Caveats {
		if item == caveat {
			return true
		}
	}
	return false
}

func sortedUnique(values []string) []string {
	// A non-nil empty list stays non-nil: an empty releasableTo means owner countries only, not unrestricted.
	out := append(make([]string, 0, len(values)), values...)
	sort.SliceStable(out, func(i, j int) bool { return compareUTF16(out[i], out[j]) < 0 })
	return out
}

// labelValue converts a label argument (ClassificationLabel, *ClassificationLabel or a model value) to a model value.
func labelValue(label any) any {
	switch v := label.(type) {
	case ClassificationLabel:
		return v.ToValue()
	case *ClassificationLabel:
		if v == nil {
			return nil
		}
		return v.ToValue()
	}
	return Normalize(label)
}

// checkLabel returns the checked, normalized label, or why it is invalid for the scheme.
func checkLabel(label any, scheme *ClassificationSchemeDefinition) (*ClassificationLabel, string) {
	o, ok := labelValue(label).(*Object)
	if !ok || o == nil {
		return nil, "A classification label must be an object"
	}
	if !onlyKeys(o, "level", "compartments", "noforn", "releasableTo") {
		return nil, "Unknown classification label field"
	}
	level, ok := o.Get("level").(string)
	known := false
	for _, item := range scheme.Levels {
		if item.ID == level {
			known = true
			break
		}
	}
	if !ok || !known {
		return nil, "The label names a level the scheme does not define"
	}
	out := &ClassificationLabel{Level: level}
	if compartments := o.Get("compartments"); !IsUndefined(compartments) {
		list, isList := compartments.([]any)
		if !isList || len(list) > ClassificationLimits.MaxCompartments {
			return nil, "Label compartments must be a list of compartment ids"
		}
		knownIDs := map[string]bool{}
		for _, compartment := range scheme.Compartments {
			knownIDs[compartment.ID] = true
		}
		seen := map[string]bool{}
		var ordered []string
		for _, item := range list {
			compartment, ok := item.(string)
			if !ok || !knownIDs[compartment] {
				return nil, "The label names a compartment the scheme does not define"
			}
			if seen[compartment] {
				return nil, "Label compartments must not repeat"
			}
			seen[compartment] = true
			ordered = append(ordered, compartment)
		}
		out.Compartments = sortedUnique(ordered)
	}
	noforn := o.Get("noforn")
	if _, isBool := noforn.(bool); !IsUndefined(noforn) && !isBool {
		return nil, "Label noforn must be a boolean"
	}
	if noforn == true && !schemeHasCaveat(scheme, "NOFORN") {
		return nil, "The scheme does not use the NOFORN caveat"
	}
	out.Noforn = noforn == true
	if releasable := o.Get("releasableTo"); !IsUndefined(releasable) {
		if !schemeHasCaveat(scheme, "RELTO") {
			return nil, "The scheme does not use the RELTO caveat"
		}
		list, isList := releasable.([]any)
		if !isList || len(list) > ClassificationLimits.MaxReleasableTo {
			return nil, "Label releasableTo must list at most " + itoa(ClassificationLimits.MaxReleasableTo) + " countries"
		}
		seen := map[string]bool{}
		ordered := []string{}
		for _, item := range list {
			country, ok := item.(string)
			if !ok || !countryPattern.MatchString(country) {
				return nil, "Label releasableTo must hold ISO 3166-1 alpha-3 codes in upper case"
			}
			if seen[country] {
				return nil, "Label releasableTo must not repeat a country"
			}
			seen[country] = true
			ordered = append(ordered, country)
		}
		out.ReleasableTo = sortedUnique(ordered)
	}
	if len(out.Compartments) == 0 {
		out.Compartments = nil
	}
	return out, ""
}

// ValidateLabel validates a label against a scheme and returns it normalized: compartments and countries sorted, an
// empty compartment list and noforn false dropped, an empty releasableTo kept. Fails with INVALID_INPUT.
func ValidateLabel(label any, scheme *ClassificationSchemeDefinition) (*ClassificationLabel, error) {
	checked, problem := checkLabel(label, scheme)
	if problem != "" {
		return nil, invalidInput(problem)
	}
	return checked, nil
}

// IsValidClassificationLabel is the non-throwing form of ValidateLabel.
func IsValidClassificationLabel(label any, scheme *ClassificationSchemeDefinition) bool {
	_, problem := checkLabel(label, scheme)
	return problem == ""
}

// LabelRank is the rank of the label's level in the scheme; ok is false when the level is unknown.
func LabelRank(label any, scheme *ClassificationSchemeDefinition) (float64, bool) {
	o, ok := labelValue(label).(*Object)
	if !ok || o == nil {
		return 0, false
	}
	level, ok := o.Get("level").(string)
	if !ok {
		return 0, false
	}
	for _, item := range scheme.Levels {
		if item.ID == level {
			return item.Rank, true
		}
	}
	return 0, false
}

// JoinLabels is the least restrictive label at least as restrictive as both: the higher level, the union of
// compartments, NOFORN when either has it, and the intersection of releasableTo lists. A nil input is ignored; both
// nil gives nil. An input that is not a valid label of the scheme makes the result that input unchanged (as a model
// value), so it stays invalid and Dominates refuses every party.
func JoinLabels(a, b any, scheme *ClassificationSchemeDefinition) any {
	absent := func(value any) bool { return value == nil || IsUndefined(value) || isNilLabel(value) }
	var left, right *ClassificationLabel
	if !absent(a) {
		checked, problem := checkLabel(a, scheme)
		if problem != "" {
			return labelValue(a)
		}
		left = checked
	}
	if !absent(b) {
		checked, problem := checkLabel(b, scheme)
		if problem != "" {
			return labelValue(b)
		}
		right = checked
	}
	if left == nil || right == nil {
		if left != nil {
			return left
		}
		if right != nil {
			return right
		}
		return nil
	}
	leftRank, _ := LabelRank(left, scheme)
	rightRank, _ := LabelRank(right, scheme)
	level := right.Level
	if leftRank >= rightRank {
		level = left.Level
	}
	union := map[string]bool{}
	var compartments []string
	for _, item := range append(append([]string(nil), left.Compartments...), right.Compartments...) {
		if !union[item] {
			union[item] = true
			compartments = append(compartments, item)
		}
	}
	compartments = sortedUnique(compartments)
	var releasable []string
	switch {
	case left.ReleasableTo != nil && right.ReleasableTo != nil:
		other := map[string]bool{}
		for _, country := range right.ReleasableTo {
			other[country] = true
		}
		releasable = []string{}
		for _, country := range left.ReleasableTo {
			if other[country] {
				releasable = append(releasable, country)
			}
		}
	case left.ReleasableTo != nil:
		releasable = append([]string{}, left.ReleasableTo...)
	case right.ReleasableTo != nil:
		releasable = append([]string{}, right.ReleasableTo...)
	}
	out := &ClassificationLabel{Level: level, Noforn: left.Noforn || right.Noforn, ReleasableTo: releasable}
	if len(compartments) > 0 {
		out.Compartments = compartments
	}
	return out
}

func isNilLabel(value any) bool {
	label, ok := value.(*ClassificationLabel)
	return ok && label == nil
}

// Dominates reports whether a party may read a resource carrying label (no read up): "" when it may, or the first
// dimension it fails: invalid-label, level, compartment, noforn or releasability.
func Dominates(party *ClearanceParty, label any, scheme *ClassificationSchemeDefinition) DominanceFailure {
	checked, problem := checkLabel(label, scheme)
	if problem != "" {
		return "invalid-label"
	}
	required, ok := LabelRank(checked, scheme)
	if !ok || party == nil || !IsSafeInteger(party.Rank) || party.Rank < required {
		return "level"
	}
	for _, compartment := range checked.Compartments {
		if !party.Compartments[compartment] {
			return "compartment"
		}
	}
	citizen := func(countries []string) bool {
		for _, country := range countries {
			if party.Citizenship[country] {
				return true
			}
		}
		return false
	}
	if checked.Noforn && !citizen(scheme.OwnerCountries) {
		return "noforn"
	}
	if checked.ReleasableTo != nil && !citizen(append(append([]string(nil), checked.ReleasableTo...), scheme.OwnerCountries...)) {
		return "releasability"
	}
	return ""
}

// releasableSet is the countries whose citizens may read a valid label, or nil when releasability is unrestricted.
func releasableSet(label *ClassificationLabel, scheme *ClassificationSchemeDefinition) map[string]bool {
	if label.Noforn {
		out := map[string]bool{}
		for _, country := range scheme.OwnerCountries {
			out[country] = true
		}
		return out
	}
	if label.ReleasableTo != nil {
		out := map[string]bool{}
		for _, country := range append(append([]string(nil), label.ReleasableTo...), scheme.OwnerCountries...) {
			out[country] = true
		}
		return out
	}
	return nil
}

// LabelCovers reports whether replacing lower with upper never declassifies.
func LabelCovers(upper, lower any, scheme *ClassificationSchemeDefinition) bool {
	high, problem := checkLabel(upper, scheme)
	if problem != "" {
		return false
	}
	low, problem := checkLabel(lower, scheme)
	if problem != "" {
		return false
	}
	highRank, ok := LabelRank(high, scheme)
	if !ok {
		highRank = -1
	}
	lowRank, _ := LabelRank(low, scheme)
	if highRank < lowRank {
		return false
	}
	compartments := map[string]bool{}
	for _, item := range high.Compartments {
		compartments[item] = true
	}
	for _, item := range low.Compartments {
		if !compartments[item] {
			return false
		}
	}
	if low.Noforn && !high.Noforn {
		return false
	}
	highReach := releasableSet(high, scheme)
	lowReach := releasableSet(low, scheme)
	if lowReach == nil {
		return true
	}
	if highReach == nil {
		return false
	}
	for country := range highReach {
		if !lowReach[country] {
			return false
		}
	}
	return true
}

// ClassificationTemplates are the starting points for clearances.defineScheme({ template }). Copy with
// ValidateScheme before changing.
var ClassificationTemplates = map[string]ClassificationSchemeDefinition{
	"us": {
		Levels: []ClassificationLevel{
			{ID: "U", Name: "UNCLASSIFIED", Rank: 0, Abbreviation: "U"},
			{ID: "C", Name: "CONFIDENTIAL", Rank: 1, Abbreviation: "C"},
			{ID: "S", Name: "SECRET", Rank: 2, Abbreviation: "S"},
			{ID: "TS", Name: "TOP SECRET", Rank: 3, Abbreviation: "TS"},
		},
		Compartments: []Compartment{}, OwnerCountries: []string{"USA"}, Caveats: []string{"NOFORN", "RELTO"},
	},
	"uk": {
		Levels: []ClassificationLevel{
			{ID: "OFFICIAL", Name: "OFFICIAL", Rank: 0, Abbreviation: "O"},
			{ID: "SECRET", Name: "SECRET", Rank: 1, Abbreviation: "S"},
			{ID: "TOP-SECRET", Name: "TOP SECRET", Rank: 2, Abbreviation: "TS"},
		},
		Compartments: []Compartment{}, OwnerCountries: []string{"GBR"}, Caveats: []string{"NOFORN", "RELTO"},
	},
	"nato": {
		Levels: []ClassificationLevel{
			{ID: "NU", Name: "NATO UNCLASSIFIED", Rank: 0, Abbreviation: "NU"},
			{ID: "NR", Name: "NATO RESTRICTED", Rank: 1, Abbreviation: "NR"},
			{ID: "NC", Name: "NATO CONFIDENTIAL", Rank: 2, Abbreviation: "NC"},
			{ID: "NS", Name: "NATO SECRET", Rank: 3, Abbreviation: "NS"},
			{ID: "CTS", Name: "COSMIC TOP SECRET", Rank: 4, Abbreviation: "CTS"},
		},
		Compartments: []Compartment{}, OwnerCountries: []string{}, Caveats: []string{"RELTO"},
	},
	"corporate": {
		Levels: []ClassificationLevel{
			{ID: "public", Name: "Public", Rank: 0},
			{ID: "internal", Name: "Internal", Rank: 1},
			{ID: "confidential", Name: "Confidential", Rank: 2},
			{ID: "restricted", Name: "Restricted", Rank: 3},
		},
		Compartments: []Compartment{}, OwnerCountries: []string{}, Caveats: []string{},
	},
}

// ClassificationTemplateNames lists the template names in TypeScript order.
var ClassificationTemplateNames = []string{"us", "uk", "nato", "corporate"}
