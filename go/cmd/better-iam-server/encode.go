package main

// The tagged value encoding of control-plane values (spec/conformance/FORMAT.md "Value encoding";
// scripts/conformance/lib/encode.mjs encodeValue/decodeValue), between Go values and JSON model values.

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"reflect"
	"sort"
	"time"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/server"
)

// encodeValue is encodeValue: plain JSON where possible, tags for what JSON cannot carry.
func encodeValue(value any) any {
	switch typed := value.(type) {
	case nil:
		return nil
	case core.UndefinedType:
		return core.NewObject("$undefined", true)
	case string, bool:
		return typed
	case float64:
		if math.IsNaN(typed) || math.IsInf(typed, 0) {
			return core.NewObject("$number", core.NumberString(typed))
		}
		return typed
	case int, int64, int32, uint32, uint64, float32:
		return core.Normalize(typed)
	case []byte:
		return core.NewObject("$bytes", base64.StdEncoding.EncodeToString(typed))
	case time.Time:
		return core.NewObject("$date", typed.UTC().Format("2006-01-02T15:04:05.000Z"))
	case *http.Response:
		// A fetch Response is recorded by its class name, as encodeValue does for objects JSON cannot carry.
		return core.NewObject("$object", "Response")
	case http.Header:
		out := core.NewObject()
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			out.Set(http.CanonicalHeaderKey(key), joinHeader(key, typed.Values(key)))
		}
		return core.NewObject("$headers", out)
	case *core.Object:
		if typed == nil {
			return nil
		}
		out := core.NewObject()
		typed.Entries(func(key string, item any) bool {
			if !core.IsUndefined(item) {
				out.Set(key, encodeValue(item))
			}
			return true
		})
		return out
	case []any:
		out := make([]any, len(typed))
		for index, item := range typed {
			out[index] = encodeValue(item)
		}
		return out
	case error:
		shape := core.NewObject("name", errorName(typed), "message", typed.Error())
		var known *core.IamError
		if errors.As(typed, &known) {
			shape.Set("code", known.Code).Set("status", float64(known.Status))
		}
		return core.NewObject("$error", shape)
	}
	reflected := reflect.ValueOf(value)
	switch reflected.Kind() {
	case reflect.Func:
		return core.NewObject("$function", "anonymous")
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice:
		if reflected.IsNil() {
			if reflected.Kind() == reflect.Slice {
				return []any{}
			}
			return nil
		}
	}
	if reflected.Kind() == reflect.Slice {
		out := make([]any, reflected.Len())
		for index := range out {
			out[index] = encodeValue(reflected.Index(index).Interface())
		}
		return out
	}
	model, err := server.ToModel(value)
	if err != nil {
		return core.NewObject("$object", reflected.Type().String())
	}
	return encodeValue(model)
}

func joinHeader(key string, values []string) string {
	separator := ", "
	if http.CanonicalHeaderKey(key) == "Cookie" {
		separator = "; "
	}
	out := ""
	for index, value := range values {
		if index > 0 {
			out += separator
		}
		out += value
	}
	return out
}

// decodeValue is decodeValue: tags back to values (bytes, dates, numbers, maps and sets as model values, headers as
// http.Header).
func decodeValue(value any) any {
	switch typed := value.(type) {
	case []any:
		out := make([]any, len(typed))
		for index, item := range typed {
			out[index] = decodeValue(item)
		}
		return out
	case *core.Object:
		if typed == nil {
			return nil
		}
		if typed.Len() == 1 {
			key := typed.Keys()[0]
			inner := typed.Get(key)
			switch key {
			case "$bytes":
				decoded, _ := base64.StdEncoding.DecodeString(jsonString(inner))
				return decoded
			case "$date":
				parsed, err := time.Parse(time.RFC3339Nano, jsonString(inner))
				if err != nil {
					return inner
				}
				return parsed
			case "$bigint":
				return inner
			case "$undefined":
				return core.Undefined
			case "$number":
				switch jsonString(inner) {
				case "NaN":
					return math.NaN()
				case "Infinity":
					return math.Inf(1)
				case "-Infinity":
					return math.Inf(-1)
				}
				return inner
			case "$map":
				out := core.NewObject()
				pairs, _ := inner.([]any)
				for _, pair := range pairs {
					items, _ := pair.([]any)
					if len(items) == 2 {
						out.Set(core.MustStringify(decodeValue(items[0])), decodeValue(items[1]))
					}
				}
				return out
			case "$set":
				return decodeValue(inner)
			case "$headers":
				header := http.Header{}
				if object, ok := inner.(*core.Object); ok {
					object.Entries(func(name string, item any) bool {
						header.Add(name, jsonString(item))
						return true
					})
				}
				return header
			}
		}
		out := core.NewObject()
		typed.Entries(func(key string, item any) bool {
			out.Set(key, decodeValue(item))
			return true
		})
		return out
	}
	return value
}

func jsonString(value any) string {
	text, _ := value.(string)
	return text
}

// errorName is the JavaScript error name of an error (Name() when it has one).
func errorName(err error) string {
	var named interface{ Name() string }
	if errors.As(err, &named) {
		return named.Name()
	}
	return "Error"
}

// errorShape is the error shape a step records: IamError code/status/message (and retryAfterMs), anything else
// INTERNAL_ERROR 500 with the thrown name and message.
func errorShape(err error) *core.Object {
	var known *core.IamError
	if errors.As(err, &known) {
		shape := core.NewObject("code", known.Code, "status", float64(known.Status), "message", known.Message)
		var hinted interface{ RetryAfter() float64 }
		if errors.As(err, &hinted) && hinted.RetryAfter() > 0 {
			shape.Set("retryAfterMs", hinted.RetryAfter())
		}
		return shape
	}
	return core.NewObject("code", "INTERNAL_ERROR", "status", 500.0, "message", "Internal server error",
		"thrown", core.NewObject("name", errorName(err), "message", err.Error()))
}

// sameValue compares two model values as JSON with member order ignored.
func sameValue(left, right any) bool {
	return core.CanonicalJSON(left) == core.CanonicalJSON(right)
}

var _ = json.Marshal
