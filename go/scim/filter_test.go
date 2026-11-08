package scim

import (
	"strings"
	"testing"

	"github.com/Better-IAM/better-iam/go/core"
	"github.com/Better-IAM/better-iam/go/spectest"
)

// TestScimFilterVectors replays spec/vectors/scim-filter.json: parsing, evaluation against three rendered users,
// attribute paths, sorting, projection and attribute lists.
func TestScimFilterVectors(t *testing.T) {
	file := spectest.Load(t, "scim-filter")
	resources, _ := file.Notes.Array("resources")
	users := make([]*core.Object, len(resources))
	for index, item := range resources {
		users[index] = spectest.Decode(item).(*core.Object)
	}
	for _, c := range file.Cases {
		input := c.Input
		var got any
		switch {
		case strings.HasPrefix(c.Name, "parse "):
			node, err := ParseFilterExpression(input.Get("filter").(string))
			if err != nil {
				got = spectest.ErrorValue(err)
			} else {
				got = node.ToValue()
			}
		case strings.HasPrefix(c.Name, "matches "):
			node, err := ParseFilterExpression(input.Get("filter").(string))
			if err != nil {
				got = spectest.ErrorValue(err)
			} else {
				ids := []any{}
				for _, user := range users {
					if EvaluateFilter(node, user, nil) {
						ids = append(ids, user.Get("id"))
					}
				}
				got = ids
			}
		case strings.HasPrefix(c.Name, "attributePath "):
			path, err := AttributePath(input.Get("raw").(string))
			got = spectest.Outcome(stringList(path), err)
			if err == nil {
				got = stringList(path)
			}
		case strings.HasPrefix(c.Name, "sort "):
			sortBy, _ := input.Get("sortBy").(string)
			sortOrder, _ := input.Get("sortOrder").(string)
			sorted, err := SortResources(append([]*core.Object{}, users...), sortBy, sortOrder)
			if err != nil {
				got = spectest.ErrorValue(err)
			} else {
				ids := []any{}
				for _, user := range sorted {
					ids = append(ids, user.Get("id"))
				}
				got = ids
			}
		case strings.HasPrefix(c.Name, "project "):
			var attributes, excluded []string
			if list, ok := input.Get("attributes").([]any); ok {
				for _, item := range list {
					attributes = append(attributes, item.(string))
				}
			}
			if list, ok := input.Get("excluded").([]any); ok {
				for _, item := range list {
					excluded = append(excluded, item.(string))
				}
			}
			projected, err := ProjectResource(input.Get("resource").(*core.Object).Clone(), attributes, excluded)
			if err != nil {
				got = spectest.ErrorValue(err)
			} else {
				got = projected
			}
		case strings.HasPrefix(c.Name, "attributeList "):
			list, ok, err := AttributeList(input.Get("value"))
			switch {
			case err != nil:
				got = spectest.ErrorValue(err)
			case !ok:
				got = core.Undefined
			default:
				got = stringList(list)
			}
		default:
			t.Fatalf("unknown case %s", c.Name)
		}
		if spectest.IsError(c.Output) {
			if !spectest.IsError(got) || !spectest.Equal(got.(*core.Object).Get("$error"), spectest.Decode(c.Output.(*core.Object).Get("$error"))) {
				t.Errorf("%s:\n  expected %s\n  received %s", c.Name, spectest.Show(c.Output), spectest.Show(got))
			}
			continue
		}
		spectest.Check(t, c, got)
	}
}

func TestFilterQuirks(t *testing.T) {
	user := core.NewObject("id", "u1", "userName", "a")
	// `constructor` is found through the prototype chain, as `'constructor' in record` is in JavaScript.
	node, err := ParseFilterExpression("constructor pr")
	if err != nil || !EvaluateFilter(node, user, nil) {
		t.Fatalf("constructor pr should match: %v", err)
	}
	node, _ = ParseFilterExpression(`constructor eq "x"`)
	if EvaluateFilter(node, user, nil) {
		t.Fatal("constructor eq should not match")
	}
	projected, err := ProjectResource(user, []string{"constructor.x"}, nil)
	if err != nil || core.MustStringify(projected) != `{"id":"u1","constructor":{}}` {
		t.Fatalf("projection: %v %s", err, core.MustStringify(projected))
	}
	if _, err := ParseFilterExpression("userName eq \"\\\n\""); err == nil {
		t.Fatal("an escaped line terminator is not a string")
	}
	if _, err := ParseFilterExpression("userName eq \"😀\" and x eq 😀"); err == nil || !strings.Contains(err.Error(), "Unexpected character") {
		t.Fatalf("astral character: %v", err)
	}
}
