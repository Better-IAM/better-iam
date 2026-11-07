package core

import (
	"math"
	"strings"
	"testing"
)

// Expected values are what Node.js prints for the same expressions.

func TestNumberString(t *testing.T) {
	sum := 0.1
	sum += 0.2
	for _, item := range []struct {
		value float64
		want  string
	}{
		{0, "0"}, {math.Copysign(0, -1), "0"}, {1, "1"}, {-1.5, "-1.5"}, {100, "100"}, {sum, "0.30000000000000004"},
		{1e21, "1e+21"}, {1e20, "100000000000000000000"}, {1e-7, "1e-7"}, {0.000001, "0.000001"},
		{123456789012345680000, "123456789012345680000"}, {5e-324, "5e-324"}, {math.MaxFloat64, "1.7976931348623157e+308"},
		{math.Pow(2, 53) + 2, "9007199254740994"}, {1.5e-10, "1.5e-10"}, {123e-20, "1.23e-18"}, {-1e21, "-1e+21"},
		{4611686018427389000, "4611686018427389000"}, {1.7125808327557952e177, "1.7125808327557952e+177"},
		{math.NaN(), "NaN"}, {math.Inf(1), "Infinity"}, {math.Inf(-1), "-Infinity"},
	} {
		if got := NumberString(item.value); got != item.want {
			t.Errorf("NumberString(%v) = %s, want %s", item.value, got, item.want)
		}
	}
}

func TestObjectKeyOrder(t *testing.T) {
	o := NewObject()
	for _, key := range []string{"b", "10", "a", "2", "01", "4294967295", "4294967294", "-1", "1.5"} {
		o.Set(key, 1)
	}
	if got := strings.Join(o.Keys(), ","); got != "2,10,4294967294,b,a,01,4294967295,-1,1.5" {
		t.Errorf("key order %s", got)
	}
	o.Delete("10")
	o.Set("10", 2)
	if got := strings.Join(o.Keys(), ","); got != "2,10,4294967294,b,a,01,4294967295,-1,1.5" {
		t.Errorf("key order after re-adding an index %s", got)
	}
	o.Delete("b")
	o.Set("b", 3)
	if got := strings.Join(o.Keys(), ","); got != "2,10,4294967294,a,01,4294967295,-1,1.5,b" {
		t.Errorf("key order after re-adding a string key %s", got)
	}
}

func TestParseAndStringify(t *testing.T) {
	for _, item := range []struct{ input, want string }{
		{`{"a":1,"b":2,"a":3}`, `{"a":3,"b":2}`},
		{`"\ud800"`, `"\ud800"`},
		{`"😀"`, `"😀"`},
		{`"😀x\uDC00"`, `"😀x\udc00"`},
		{`"  <>&\u007f"`, "\"  <>&\u007f\""},
		{`"\u0000\u001f\b\f\n\r\t\"\\\/"`, `"\u0000\u001f\b\f\n\r\t\"\\/"`},
		{`[1e400,-1e400,1E2,-0,0.5e-400]`, `[null,null,100,0,0]`},
		{`{"10":1,"2":2,"x":3}`, `{"2":2,"10":1,"x":3}`},
		{` { "a" : [ true , false , null ] } `, `{"a":[true,false,null]}`},
	} {
		value, err := ParseJSONString(item.input)
		if err != nil {
			t.Errorf("parse %s: %v", item.input, err)
			continue
		}
		got, ok, err := Stringify(value)
		if err != nil || !ok || got != item.want {
			t.Errorf("stringify(parse(%s)) = %s, want %s (%v)", item.input, got, item.want, err)
		}
	}
	for _, bad := range []string{`{`, `[1,]`, `{"a":1,}`, `01`, `1.`, `.5`, `"a`, "\"\x01\"", `tru`, `"\x"`, `1 2`, `'a'`, `"\u12"`} {
		if _, err := ParseJSONString(bad); err == nil {
			t.Errorf("parse %q should fail", bad)
		}
	}
	if _, ok, _ := Stringify(Undefined); ok {
		t.Error("undefined has no JSON form")
	}
	if got := MustStringify([]any{Undefined, func() {}, math.NaN()}); got != "[null,null,null]" {
		t.Errorf("array entries without JSON form: %s", got)
	}
	if got := MustStringify(NewObject("a", Undefined, "b", 1).SetRaw("c", func() {})); got != `{"b":1}` {
		t.Errorf("members without JSON form: %s", got)
	}
	cycle := NewObject()
	cycle.SetRaw("self", cycle)
	if _, _, err := Stringify(cycle); err == nil {
		t.Error("cycles must fail")
	}
}

func TestUTF16Helpers(t *testing.T) {
	text := "a😀" + FromUTF16([]uint16{0xd800}) + "é"
	if UTF16Len(text) != 5 {
		t.Errorf("UTF16Len = %d", UTF16Len(text))
	}
	if got := ToUTF16(text); len(got) != 5 || got[1] != 0xd83d || got[3] != 0xd800 {
		t.Errorf("ToUTF16 = %x", got)
	}
	if FromUTF16(ToUTF16(text)) != text {
		t.Error("UTF-16 round trip")
	}
	if points := CodePoints(text); len(points) != 4 {
		t.Errorf("CodePoints = %q", points)
	}
	if StorableString(text) || !StorableString("a😀é") || StorableString("a\u0000") {
		t.Error("StorableString")
	}
}

func TestJSLower(t *testing.T) {
	for _, item := range []struct{ input, want string }{
		{"ABC", "abc"}, {"İ", "i̇"}, {"ΑΣ", "ας"}, {"Σ", "σ"}, {"ΑΣΑ", "ασα"}, {"ÉCOLE", "école"}, {"ǅ", "ǆ"},
	} {
		if got := JSLower(item.input); got != item.want {
			t.Errorf("JSLower(%q) = %q, want %q", item.input, got, item.want)
		}
	}
	if JSTrim(string([]rune{0xa0, 0xfeff, 0x20})+"a "+string(rune(0x2028))) != "a" {
		t.Error("JSTrim")
	}
}

func TestNormalize(t *testing.T) {
	type inner struct {
		Z int    `json:"z"`
		A string `json:"a,omitempty"`
	}
	type outer struct {
		Name  string            `json:"name"`
		Inner inner             `json:"inner"`
		Tags  []string          `json:"tags"`
		Map   map[string]int    `json:"map"`
		HTML  string            `json:"html"`
		Extra map[string]string `json:"extra,omitempty"`
	}
	value := Normalize(outer{Name: "x", Inner: inner{Z: 2}, Tags: []string{"b"}, Map: map[string]int{"b": 1, "a": 2}, HTML: "<&>"})
	if got := MustStringify(value); got != `{"name":"x","inner":{"z":2},"tags":["b"],"map":{"a":2,"b":1},"html":"<&>"}` {
		t.Errorf("Normalize(struct) = %s", got)
	}
	if got := MustStringify(NewObject("n", 3, "u", uint8(4), "f", float32(0.5), "l", []int{1, 2})); got != `{"n":3,"u":4,"f":0.5,"l":[1,2]}` {
		t.Errorf("Normalize(numbers) = %s", got)
	}
	var back outer
	if err := FromRecord(value, &back); err != nil || back.Inner.Z != 2 || back.Map["a"] != 2 {
		t.Errorf("FromRecord = %+v %v", back, err)
	}
}
