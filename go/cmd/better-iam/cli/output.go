package cli

// Port of packages/cli/src/output.ts.

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/Better-IAM/better-iam/go/core"
)

// OutputFormat is how a command prints its result: "json" (indented, the default), "compact" (one line), or
// "table".
type OutputFormat = string

// outputFormats are the values of --format.
var outputFormats = []string{"json", "compact", "table"}

var unsafeKeys = map[string]bool{"__proto__": true, "constructor": true, "prototype": true}

var (
	segmentPiece = regexp.MustCompile(`^([^\[\]]*)((?:\[\d*\])*)$`)
	indexPiece   = regexp.MustCompile(`\[\d*\]`)
	digitsOnly   = regexp.MustCompile(`^\d+$`)
)

// segments splits `a.b[0].c` / `items[].id` into segments; `[]` maps the rest of the path over an array.
func segments(path string) ([]string, error) {
	var parts []string
	for _, piece := range strings.Split(path, ".") {
		match := segmentPiece.FindStringSubmatch(piece)
		if match == nil {
			return nil, UsageError("--query " + path + " is not a path like findings[].kind or roles.0.name")
		}
		if match[1] != "" {
			parts = append(parts, match[1])
		}
		for _, index := range indexPiece.FindAllString(match[2], -1) {
			inner := index[1 : len(index)-1]
			if inner == "" {
				inner = "[]"
			}
			parts = append(parts, inner)
		}
	}
	unusable := len(parts) == 0
	for _, part := range parts {
		if unsafeKeys[part] {
			unusable = true
		}
	}
	if unusable {
		return nil, UsageError("--query " + path + " is not a usable path")
	}
	return parts, nil
}

// jsonValue is the value as JSON.parse(JSON.stringify(value)) gives it back (Undefined when it has no JSON form):
// what a command result looks like on the wire.
func jsonValue(value any) any {
	text, ok, err := core.Stringify(value)
	if err != nil || !ok {
		return core.Undefined
	}
	parsed, err := core.ParseJSONString(text)
	if err != nil {
		return core.Undefined
	}
	return parsed
}

// SelectPath selects part of a result for --query: dotted keys (summary.create), array indexes (roles.0 or
// roles[0]), and [] to map over an array (findings[].kind). A missing key selects null rather than failing, like jq.
func SelectPath(value any, path string) (any, error) {
	parts, err := segments(path)
	if err != nil {
		return nil, err
	}
	var walk func(current any, parts []string) any
	walk = func(current any, parts []string) any {
		if len(parts) == 0 {
			return current
		}
		head, rest := parts[0], parts[1:]
		if head == "[]" {
			list, ok := current.([]any)
			if !ok {
				return nil
			}
			mapped := make([]any, len(list))
			for index, item := range list {
				mapped[index] = walk(item, rest)
			}
			return mapped
		}
		switch typed := current.(type) {
		case []any:
			if digitsOnly.MatchString(head) {
				index, err := strconv.Atoi(head)
				if err != nil || index >= len(typed) || typed[index] == nil || core.IsUndefined(typed[index]) {
					return walk(nil, rest)
				}
				return walk(typed[index], rest)
			}
			if head == "length" {
				return walk(float64(len(typed)), rest)
			}
			return nil
		case *core.Object:
			if typed == nil {
				return nil
			}
			if typed.Has(head) {
				return walk(typed.Get(head), rest)
			}
			return nil
		}
		return nil
	}
	return walk(jsonValue(value), parts), nil
}

// printable shows terminal control sequences in server data (escape codes that rewrite the screen or set the
// clipboard) as U+FFFD. Line breaks and tabs survive only where keepLines.
func printable(text string, keepLines bool) string {
	var b strings.Builder
	for i := 0; i < len(text); i++ {
		c := text[i]
		if c < 0x20 || c == 0x7f {
			if keepLines && (c == '\t' || c == '\n') {
				b.WriteByte(c)
			} else {
				b.WriteString("�")
			}
			continue
		}
		// U+0080-U+009F (C1 controls) are encoded as C2 80 - C2 9F.
		if c == 0xC2 && i+1 < len(text) && text[i+1] >= 0x80 && text[i+1] <= 0x9F {
			b.WriteString("�")
			i++
			continue
		}
		b.WriteByte(c)
	}
	return b.String()
}

// sliceUnits is String.prototype.slice(0, end) in UTF-16 units.
func sliceUnits(text string, end int) string {
	units := core.ToUTF16(text)
	if end >= len(units) {
		return text
	}
	return core.FromUTF16(units[:end])
}

// padEnd is String.prototype.padEnd with spaces (UTF-16 length).
func padEnd(text string, width int) string {
	length := core.UTF16Len(text)
	if length >= width {
		return text
	}
	return text + strings.Repeat(" ", width-length)
}

func jsString(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case float64:
		return core.NumberString(typed)
	case bool:
		if typed {
			return "true"
		}
		return "false"
	case nil:
		return "null"
	}
	if core.IsUndefined(value) {
		return "undefined"
	}
	return core.MustStringify(value)
}

func cell(value any) string {
	if value == nil || core.IsUndefined(value) {
		return ""
	}
	switch typed := value.(type) {
	case string:
		return printable(typed, false)
	case float64, bool:
		return jsString(typed)
	}
	text := core.MustStringify(value)
	if core.UTF16Len(text) > 60 {
		return sliceUnits(text, 57) + "..."
	}
	return text
}

func isRecordValue(value any) bool {
	object, ok := value.(*core.Object)
	return ok && object != nil
}

// tableRows are the rows a table shows: an array as it is, or the one array inside a result object
// ({ findings: [...] }).
func tableRows(value any) ([]any, bool) {
	if list, ok := value.([]any); ok {
		return list, true
	}
	object, ok := value.(*core.Object)
	if !ok || object == nil {
		return nil, false
	}
	var arrays [][]any
	for _, key := range object.Keys() {
		if list, ok := object.Get(key).([]any); ok {
			arrays = append(arrays, list)
		}
	}
	if len(arrays) == 1 {
		return arrays[0], true
	}
	return nil, false
}

// RenderTable renders rows of objects as aligned columns (keys in first-seen order), or an object as key/value
// lines.
func RenderTable(value any) string {
	value = jsonValue(value)
	rows, ok := tableRows(value)
	if !ok {
		if object, isObject := value.(*core.Object); isObject && object != nil {
			keys := object.Keys()
			width := 0
			for _, key := range keys {
				width = max(width, core.UTF16Len(key))
			}
			lines := make([]string, len(keys))
			for index, key := range keys {
				lines[index] = padEnd(printable(key, false), width) + "  " + cell(object.Get(key))
			}
			return strings.Join(lines, "\n")
		}
		return cell(value)
	}
	if len(rows) == 0 {
		return "(no rows)"
	}
	allScalar := true
	for _, row := range rows {
		if isRecordValue(row) {
			allScalar = false
			break
		}
	}
	if allScalar {
		cells := make([]string, len(rows))
		for index, row := range rows {
			cells[index] = cell(row)
		}
		return strings.Join(cells, "\n")
	}
	var columns []string
	known := map[string]bool{}
	for _, row := range rows {
		if object, ok := row.(*core.Object); ok && object != nil {
			for _, key := range object.Keys() {
				if !known[key] {
					known[key] = true
					columns = append(columns, key)
				}
			}
		}
	}
	shown := columns
	if len(shown) > 8 {
		shown = shown[:8]
	}
	header := make([]string, len(shown))
	for index, column := range shown {
		header[index] = strings.ToUpper(printable(column, false))
	}
	grid := [][]string{header}
	for _, row := range rows {
		line := make([]string, len(shown))
		object, _ := row.(*core.Object)
		for index, column := range shown {
			if object != nil {
				line[index] = cell(object.Get(column))
			} else {
				line[index] = cell(core.Undefined)
			}
		}
		grid = append(grid, line)
	}
	widths := make([]int, len(shown))
	for index := range shown {
		for _, line := range grid {
			widths[index] = max(widths[index], core.UTF16Len(line[index]))
		}
	}
	lines := make([]string, len(grid))
	for row, line := range grid {
		parts := make([]string, len(line))
		for index, text := range line {
			if index == len(line)-1 {
				parts[index] = text
			} else {
				parts[index] = padEnd(text, widths[index])
			}
		}
		lines[row] = strings.TrimRight(strings.Join(parts, "  "), " \t\n\r\v\f")
	}
	if len(columns) > len(shown) {
		lines = append(lines, "("+strconv.Itoa(len(columns)-len(shown))+" more column(s); use --format json to see them)")
	}
	return strings.Join(lines, "\n")
}

// FormatResult turns a command result into the text printed on stdout. Strings are printed as they are; format
// "" is json.
func FormatResult(value any, format OutputFormat, query string, hasQuery bool) (string, error) {
	selected := jsonValue(value)
	if hasQuery {
		var err error
		if selected, err = SelectPath(value, query); err != nil {
			return "", err
		}
	}
	if text, ok := selected.(string); ok {
		return printable(text, true), nil
	}
	if format == "table" {
		return RenderTable(selected), nil
	}
	if core.IsUndefined(selected) {
		return "null", nil
	}
	if format == "compact" {
		return core.MustStringify(selected), nil
	}
	return stringifyIndented(selected, "  ", ""), nil
}

// stringifyIndented is JSON.stringify(value, null, 2) of a JSON value (as jsonValue returns it).
func stringifyIndented(value any, gap, indent string) string {
	switch typed := value.(type) {
	case []any:
		if len(typed) == 0 {
			return "[]"
		}
		inner := indent + gap
		parts := make([]string, len(typed))
		for index, item := range typed {
			if core.IsUndefined(item) {
				parts[index] = "null"
			} else {
				parts[index] = stringifyIndented(item, gap, inner)
			}
		}
		return "[\n" + inner + strings.Join(parts, ",\n"+inner) + "\n" + indent + "]"
	case *core.Object:
		if typed == nil {
			return "null"
		}
		inner := indent + gap
		var parts []string
		for _, key := range typed.Keys() {
			item := typed.Get(key)
			if core.IsUndefined(item) {
				continue
			}
			parts = append(parts, core.QuoteJSON(key)+": "+stringifyIndented(item, gap, inner))
		}
		if len(parts) == 0 {
			return "{}"
		}
		return "{\n" + inner + strings.Join(parts, ",\n"+inner) + "\n" + indent + "}"
	}
	return core.MustStringify(value)
}
