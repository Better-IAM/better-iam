package server

// Port of packages/server/src/validation.ts. The validators take model values (see jsutil.go) and fail with
// INVALID_INPUT exactly as the TypeScript ones do.

import (
	"regexp"

	"github.com/Better-IAM/better-iam/go/core"
)

// Text validates a non-blank string of at most max UTF-16 units (default 256) without control characters.
func Text(value any, name string, max ...int) (string, error) {
	limit := 256
	if len(max) > 0 {
		limit = max[0]
	}
	s, ok := value.(string)
	if !ok || core.JSTrim(s) == "" || utf16Len(s) > limit || hasControl(s) {
		return "", invalidInput("Invalid " + name)
	}
	return s, nil
}

// jsWhitespace is the JavaScript \s class (without the u flag), as a character-class body.
const jsWhitespace = `\t\n\x{0B}\f\r \x{00A0}\x{1680}\x{2000}-\x{200A}\x{2028}\x{2029}\x{202F}\x{205F}\x{3000}\x{FEFF}`

var emailPattern = regexp.MustCompile(`^[^` + jsWhitespace + `@]+@[^` + jsWhitespace + `@]+\.[^` + jsWhitespace + `@]+$`)

// Email validates and normalizes (trim, lowercase) an email address.
func Email(value any) (string, error) {
	text, err := Text(value, "email", 254)
	if err != nil {
		return "", err
	}
	result := core.JSLower(core.JSTrim(text))
	if !emailPattern.MatchString(result) {
		return "", invalidInput("Invalid email")
	}
	return result, nil
}

// Object requires a plain object (not null, not an array).
func Object(value any) (*core.Object, error) {
	o, ok := value.(*core.Object)
	if !ok || o == nil {
		return nil, invalidInput("Expected an object")
	}
	return o, nil
}

// Integer requires a safe integer within [min, max]. Go integers are accepted as numbers.
func Integer(value any, name string, min, max float64) (float64, error) {
	number, ok := core.Normalize(value).(float64)
	if !ok || !core.IsSafeInteger(number) || number < min || number > max {
		return 0, invalidInput("Invalid " + name)
	}
	return number, nil
}

// Strings requires an array of at most 100 valid texts.
func Strings(value any, name string) ([]string, error) {
	switch v := value.(type) {
	case []string:
		value = stringsOf(v)
	}
	list, ok := value.([]any)
	if !ok || len(list) > 100 {
		return nil, invalidInput("Invalid " + name)
	}
	out := make([]string, len(list))
	for index, item := range list {
		text, err := Text(item, name)
		if err != nil {
			return nil, err
		}
		out[index] = text
	}
	return out, nil
}
