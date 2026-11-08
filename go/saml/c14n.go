package saml

// Port of xml-crypto 6.1.2's canonicalization and transforms (exclusive-canonicalization.js, c14n-canonicalization.js,
// enveloped-signature.js and the namespace helpers of utils.js), the algorithms the TypeScript package validates and
// creates XML signatures with. Their quirks are kept: what an identity provider signed with xml-crypto (or with a
// standard implementation on ordinary documents) canonicalizes to the same octets here.

import (
	"errors"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

const (
	dsigNamespace     = "http://www.w3.org/2000/09/xmldsig#"
	algExcC14n        = "http://www.w3.org/2001/10/xml-exc-c14n#"
	algExcC14nComment = "http://www.w3.org/2001/10/xml-exc-c14n#WithComments"
	algC14n           = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
	algC14nComment    = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"
	algEnveloped      = "http://www.w3.org/2000/09/xmldsig#enveloped-signature"
)

// nsDecl is a namespace declaration: a prefix and its URI.
type nsDecl struct{ prefix, uri string }

// c14nOptions are the transform options xml-crypto passes along.
type c14nOptions struct {
	inclusivePrefixes  []string
	ancestorNamespaces []nsDecl
	defaultNsForPrefix map[string]string
	signatureNode      *Node
}

var defaultNsForPrefix = map[string]string{"ds": dsigNamespace}

func encodeC14nAttr(value string) string {
	if !strings.ContainsAny(value, "&<\"\r\n\t") {
		return value
	}
	var out strings.Builder
	for _, r := range value {
		switch r {
		case '&':
			out.WriteString("&amp;")
		case '<':
			out.WriteString("&lt;")
		case '"':
			out.WriteString("&quot;")
		case '\r':
			out.WriteString("&#xD;")
		case '\n':
			out.WriteString("&#xA;")
		case '\t':
			out.WriteString("&#x9;")
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}

func encodeC14nText(value string) string {
	if !strings.ContainsAny(value, "&<>\r") {
		return value
	}
	var out strings.Builder
	for _, r := range value {
		switch r {
		case '&':
			out.WriteString("&amp;")
		case '<':
			out.WriteString("&lt;")
		case '>':
			out.WriteString("&gt;")
		case '\r':
			out.WriteString("&#xD;")
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}

// compareUTF16 is JavaScript's `<` on strings.
func compareUTF16(a, b string) int {
	x, y := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(x) && i < len(y); i++ {
		if x[i] != y[i] {
			if x[i] < y[i] {
				return -1
			}
			return 1
		}
	}
	return len(x) - len(y)
}

// attrCompare is xml-crypto's attribute order: attributes without a namespace first, then by namespace + local name.
func attrCompare(a, b *Attr) int {
	if a.NamespaceURI == "" && b.NamespaceURI != "" {
		return -1
	}
	if b.NamespaceURI == "" && a.NamespaceURI != "" {
		return 1
	}
	left, right := a.NamespaceURI+a.Local, b.NamespaceURI+b.Local
	if a.NamespaceURI == "" {
		left, right = "null"+a.Local, "null"+b.Local
	}
	return compareUTF16(left, right)
}

// collationWeight approximates the ICU root collation String#localeCompare uses for namespace prefixes (NCNames):
// punctuation before digits before letters, letters case-insensitively first.
func collationWeight(r rune) int {
	switch {
	case r == '_':
		return 1
	case r == '-':
		return 2
	case r == '.':
		return 3
	case r >= '0' && r <= '9':
		return 10 + int(r-'0')
	case r >= 'a' && r <= 'z':
		return 100 + int(r-'a')*2
	case r >= 'A' && r <= 'Z':
		return 100 + int(r-'A')*2
	}
	return 1000 + int(r)
}

// localeCompare is String#localeCompare for namespace prefixes.
func localeCompare(a, b string) int {
	x, y := []rune(a), []rune(b)
	for i := 0; i < len(x) && i < len(y); i++ {
		if wx, wy := collationWeight(x[i]), collationWeight(y[i]); wx != wy {
			return wx - wy
		}
	}
	if len(x) != len(y) {
		return len(x) - len(y)
	}
	// Tertiary difference: lowercase sorts before uppercase.
	for i := range x {
		lx, ly := x[i] >= 'a' && x[i] <= 'z', y[i] >= 'a' && y[i] <= 'z'
		if lx != ly {
			if lx {
				return -1
			}
			return 1
		}
	}
	return 0
}

func sortNs(list []nsDecl) {
	sort.SliceStable(list, func(i, j int) bool {
		if list[i].prefix == list[j].prefix {
			return false
		}
		return localeCompare(list[i].prefix, list[j].prefix) < 0
	})
}

func renderAttrs(node *Node) string {
	var list []*Attr
	for _, attr := range node.Attrs {
		if strings.HasPrefix(attr.Name, "xmlns") {
			continue
		}
		list = append(list, attr)
	}
	sort.SliceStable(list, func(i, j int) bool { return attrCompare(list[i], list[j]) < 0 })
	var out strings.Builder
	for _, attr := range list {
		out.WriteString(" " + attr.Name + "=\"" + encodeC14nAttr(attr.Value) + "\"")
	}
	return out.String()
}

func renderComment(node *Node, withComments bool) string {
	if !withComments {
		return ""
	}
	before, after := "", ""
	if parent := node.Parent; parent != nil && parent.Type == DocumentNode {
		root := parent.DocumentElement()
		seenRoot := false
		for _, sibling := range parent.Children {
			if sibling == root {
				seenRoot = true
			}
			if sibling == node {
				if seenRoot {
					after = "\n"
				} else {
					before = "\n"
				}
			}
		}
	}
	return after + "<!--" + encodeC14nText(node.Data) + "-->" + before
}

// excC14n is ExclusiveCanonicalization(.WithComments).process.
func excC14n(elem *Node, options c14nOptions, withComments bool) (string, error) {
	inclusive := options.inclusivePrefixes
	if len(inclusive) == 0 {
		if methods := findChildren(elem, "CanonicalizationMethod"); len(methods) > 0 {
			if namespaces := findChildren(methods[0], "InclusiveNamespaces"); len(namespaces) > 0 {
				inclusive = strings.Split(namespaces[0].Attribute("PrefixList"), " ")
			}
		}
	}
	if len(inclusive) > 0 {
		for _, prefix := range inclusive {
			for _, ancestor := range options.ancestorNamespaces {
				if prefix == ancestor.prefix {
					elem.SetAttributeNS(xmlnsNamespace, "xmlns:"+prefix, ancestor.uri)
				}
			}
		}
	}
	nsForPrefix := options.defaultNsForPrefix
	var out strings.Builder
	err := excInner(elem, nil, "", nsForPrefix, inclusive, withComments, &out)
	return out.String(), err
}

func inScope(scope []nsDecl, prefix, uri string) bool {
	for _, entry := range scope {
		if entry.prefix == prefix && entry.uri == uri {
			return true
		}
	}
	return false
}

func contains(list []string, value string) bool {
	for _, item := range list {
		if item == value {
			return true
		}
	}
	return false
}

func excInner(node *Node, scope []nsDecl, defaultNs string, nsForPrefix map[string]string, inclusive []string, withComments bool, out *strings.Builder) error {
	if node.Type == CommentNode {
		out.WriteString(renderComment(node, withComments))
		return nil
	}
	if (node.Type == TextNode || node.Type == CDATANode || node.Type == PINode) && node.Data != "" {
		out.WriteString(encodeC14nText(node.Data))
		return nil
	}
	if node.Type != ElementNode {
		return errors.New("Unable to exclusive canonicalize node type: " + strconv.Itoa(int(node.Type)))
	}
	// renderNs
	var rendered strings.Builder
	newDefault := defaultNs
	var list []nsDecl
	if node.Prefix != "" {
		uri := node.NamespaceURI
		if uri == "" {
			uri = nsForPrefix[node.Prefix]
		}
		if !inScope(scope, node.Prefix, uri) {
			list = append(list, nsDecl{node.Prefix, uri})
			scope = append(scope, nsDecl{node.Prefix, uri})
		}
	} else if defaultNs != node.NamespaceURI {
		newDefault = node.NamespaceURI
		rendered.WriteString(" xmlns=\"" + newDefault + "\"")
	}
	for _, attr := range node.Attrs {
		if attr.Prefix != "" && !inScope(scope, attr.Local, attr.Value) && contains(inclusive, attr.Local) {
			list = append(list, nsDecl{attr.Local, attr.Value})
			scope = append(scope, nsDecl{attr.Local, attr.Value})
		}
		if attr.Prefix != "" && !inScope(scope, attr.Prefix, attr.NamespaceURI) && attr.Prefix != "xmlns" && attr.Prefix != "xml" {
			list = append(list, nsDecl{attr.Prefix, attr.NamespaceURI})
			scope = append(scope, nsDecl{attr.Prefix, attr.NamespaceURI})
		}
	}
	sortNs(list)
	for _, decl := range list {
		rendered.WriteString(" xmlns:" + decl.prefix + "=\"" + decl.uri + "\"")
	}
	out.WriteString("<" + node.TagName + rendered.String() + renderAttrs(node) + ">")
	for _, child := range node.Children {
		copied := append([]nsDecl(nil), scope...)
		if err := excInner(child, copied, newDefault, nsForPrefix, inclusive, withComments, out); err != nil {
			return err
		}
	}
	out.WriteString("</" + node.TagName + ">")
	return nil
}

// incC14n is C14nCanonicalization(.WithComments).process.
func incC14n(node *Node, options c14nOptions, withComments bool) (string, error) {
	var scope []string
	for _, ancestor := range options.ancestorNamespaces {
		scope = append(scope, ancestor.prefix)
	}
	var out strings.Builder
	err := incInner(node, scope, "", options.defaultNsForPrefix, options.ancestorNamespaces, withComments, &out)
	return out.String(), err
}

func incInner(node *Node, scope []string, defaultNs string, nsForPrefix map[string]string, ancestors []nsDecl, withComments bool, out *strings.Builder) error {
	if node.Type == CommentNode {
		out.WriteString(renderComment(node, withComments))
		return nil
	}
	if (node.Type == TextNode || node.Type == CDATANode || node.Type == PINode) && node.Data != "" {
		out.WriteString(encodeC14nText(node.Data))
		return nil
	}
	if node.Type != ElementNode {
		return errors.New("Unable to canonicalize node type: " + strconv.Itoa(int(node.Type)))
	}
	var rendered strings.Builder
	newDefault := defaultNs
	var list []nsDecl
	if node.Prefix != "" {
		if !contains(scope, node.Prefix) {
			uri := node.NamespaceURI
			if uri == "" {
				uri = nsForPrefix[node.Prefix]
			}
			list = append(list, nsDecl{node.Prefix, uri})
			scope = append(scope, node.Prefix)
		}
	} else if defaultNs != node.NamespaceURI {
		newDefault = node.NamespaceURI
		rendered.WriteString(" xmlns=\"" + newDefault + "\"")
	}
	for _, attr := range node.Attrs {
		if attr.Prefix == "xmlns" && !contains(scope, attr.Local) {
			list = append(list, nsDecl{attr.Local, attr.Value})
			scope = append(scope, attr.Local)
		}
		if attr.Prefix != "" && !contains(scope, attr.Prefix) && attr.Prefix != "xmlns" && attr.Prefix != "xml" {
			list = append(list, nsDecl{attr.Prefix, attr.NamespaceURI})
			scope = append(scope, attr.Prefix)
		}
	}
	for _, ancestor := range ancestors {
		listed := false
		for _, entry := range list {
			if entry.prefix == ancestor.prefix && entry.uri == ancestor.uri {
				listed = true
			}
		}
		if !listed {
			list = append(list, ancestor)
		}
	}
	sortNs(list)
	for _, decl := range list {
		if decl.prefix != "" {
			rendered.WriteString(" xmlns:" + decl.prefix + "=\"" + decl.uri + "\"")
		} else {
			rendered.WriteString(" xmlns=\"" + decl.uri + "\"")
		}
	}
	out.WriteString("<" + node.TagName + rendered.String() + renderAttrs(node) + ">")
	for _, child := range node.Children {
		copied := append([]string(nil), scope...)
		if err := incInner(child, copied, newDefault, nsForPrefix, nil, withComments, out); err != nil {
			return err
		}
	}
	out.WriteString("</" + node.TagName + ">")
	return nil
}

// firstTextUnder is xpath `.//*[local-name(.)='<local>']/text()` select1 followed by isTextNode: the first text or
// CDATA child of a matching descendant, in document order; ok is false when there is none or it is CDATA.
func firstTextUnder(node *Node, local string) (string, bool) {
	for _, element := range node.Descendants(func(n *Node) bool { return n.Local == local }) {
		for _, child := range element.Children {
			if child.Type == TextNode {
				return child.Data, true
			}
			if child.Type == CDATANode {
				return "", false
			}
		}
	}
	return "", false
}

func isSignature(n *Node) bool { return n.Local == "Signature" && n.NamespaceURI == dsigNamespace }

// envelopedSignature is EnvelopedSignature.process.
func envelopedSignature(node *Node, options c14nOptions) *Node {
	if options.signatureNode == nil {
		if signatures := node.ChildElements(isSignature); len(signatures) > 0 && signatures[0].Parent != nil {
			signatures[0].Parent.RemoveChild(signatures[0])
		}
		return node
	}
	expected, ok := firstTextUnder(options.signatureNode, "SignatureValue")
	if !ok {
		return node
	}
	for _, signature := range node.Descendants(isSignature) {
		if value, ok := firstTextUnder(signature, "SignatureValue"); ok && value == expected && signature.Parent != nil {
			signature.Parent.RemoveChild(signature)
		}
	}
	return node
}

// supportedTransform reports whether xml-crypto knows a canonicalization or transform algorithm.
func supportedTransform(name string) bool {
	switch name {
	case algExcC14n, algExcC14nComment, algC14n, algC14nComment, algEnveloped:
		return true
	}
	return false
}

// canonXML is SignedXml#getCanonXml: the transforms applied in order to a deep clone of node while the result is
// still a node; a node result is serialized.
func canonXML(transforms []string, node *Node, options c14nOptions) (string, error) {
	if options.defaultNsForPrefix == nil {
		options.defaultNsForPrefix = defaultNsForPrefix
	}
	current := node.Clone()
	for _, name := range transforms {
		if !supportedTransform(name) {
			return "", errors.New("canonicalization algorithm '" + name + "' is not supported")
		}
		var result string
		var err error
		switch name {
		case algEnveloped:
			current = envelopedSignature(current, options)
			continue
		case algExcC14n:
			result, err = excC14n(current, options, false)
		case algExcC14nComment:
			result, err = excC14n(current, options, true)
		case algC14n:
			result, err = incC14n(current, options, false)
		case algC14nComment:
			result, err = incC14n(current, options, true)
		}
		return result, err
	}
	return current.String(), nil
}

// findChildren is xml-crypto utils.findChildren (any namespace).
func findChildren(node *Node, local string) []*Node {
	if node == nil {
		return nil
	}
	if node.Type == DocumentNode {
		node = node.DocumentElement()
		if node == nil {
			return nil
		}
	}
	return node.ChildElements(func(n *Node) bool { return n.Local == local })
}

// findAttr is xml-crypto utils.findAttr without a namespace: the first attribute with this local name.
func findAttr(node *Node, local string) *Attr {
	for _, attr := range node.Attrs {
		if attr.Local == local {
			return attr
		}
	}
	return nil
}

func xmlnsPrefixOf(name string) (string, bool) {
	if !strings.HasPrefix(name, "xmlns") {
		return "", false
	}
	return strings.TrimPrefix(strings.TrimPrefix(name, "xmlns"), ":"), true
}

// findAncestorNs is xml-crypto utils.findAncestorNs for the first node of the subset (nil: none).
func findAncestorNs(subset *Node) []nsDecl {
	if subset == nil {
		return nil
	}
	var collected []nsDecl
	for parent := subset.Parent; parent != nil && parent.Type == ElementNode; parent = parent.Parent {
		for _, attr := range parent.Attrs {
			if prefix, ok := xmlnsPrefixOf(attr.Name); ok {
				collected = append(collected, nsDecl{prefix, attr.Value})
			}
		}
	}
	var unique []nsDecl
	for _, decl := range collected {
		seen := false
		for _, kept := range unique {
			if kept.prefix == decl.prefix {
				seen = true
				break
			}
		}
		if !seen {
			unique = append(unique, decl)
		}
	}
	subsetPrefix := subset.Prefix
	for _, attr := range subset.Attrs {
		if prefix, ok := xmlnsPrefixOf(attr.Name); ok {
			subsetPrefix = prefix
			break
		}
	}
	var result []nsDecl
	for _, decl := range unique {
		if decl.prefix != subsetPrefix {
			result = append(result, decl)
		}
	}
	return result
}

// firstElement returns the first element of the document (document order, the document element included) that keep
// accepts.
func firstElement(doc *Node, keep func(*Node) bool) *Node {
	found := doc.Descendants(keep)
	if len(found) == 0 {
		return nil
	}
	return found[0]
}
