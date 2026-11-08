package saml

// A small namespace-aware XML DOM with the parsing and serialization behavior of @xmldom/xmldom 0.8 (the parser the
// TypeScript package and its libraries use): line endings normalized before parsing, attribute whitespace folded to
// spaces, only the five XML entities and character references expanded, and xmldom's serializer output. Parse
// problems that xmldom reports (warnings, errors and fatal errors) are returned as an error; xmldom's silent
// leniencies (an unbound prefix, a bare `&`, `]]>` in text) are kept.

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// NodeType is the DOM node type.
type NodeType int

const (
	ElementNode  NodeType = 1
	TextNode     NodeType = 3
	CDATANode    NodeType = 4
	PINode       NodeType = 7
	CommentNode  NodeType = 8
	DocumentNode NodeType = 9
	DoctypeNode  NodeType = 10
)

const (
	xmlnsNamespace = "http://www.w3.org/2000/xmlns/"
	xmlNamespace   = "http://www.w3.org/XML/1998/namespace"
)

// Attr is an attribute: its qualified name, prefix ("" when none), local name, namespace ("" when none) and value.
type Attr struct {
	Name         string
	Prefix       string
	Local        string
	NamespaceURI string
	Value        string
}

// Node is a DOM node.
type Node struct {
	Type     NodeType
	Parent   *Node
	Children []*Node
	Owner    *Node

	// Elements.
	TagName      string
	Prefix       string
	Local        string
	NamespaceURI string
	Attrs        []*Attr

	// Text, CDATA, comments and processing instructions (Target is the PI target, Data its content).
	Data   string
	Target string
}

// ParseError is a problem xmldom reports while parsing.
type ParseError struct{ Message string }

func (e *ParseError) Error() string { return e.Message }

// DocumentElement is the document's root element (nil when there is none).
func (n *Node) DocumentElement() *Node {
	for _, child := range n.Children {
		if child.Type == ElementNode {
			return child
		}
	}
	return nil
}

// Attribute is getAttribute: the value of the attribute with this qualified name ("" when absent).
func (n *Node) Attribute(name string) string {
	value, _ := n.LookupAttribute(name)
	return value
}

// LookupAttribute is getAttribute with presence.
func (n *Node) LookupAttribute(name string) (string, bool) {
	if n == nil {
		return "", false
	}
	for _, attr := range n.Attrs {
		if attr.Name == name {
			return attr.Value, true
		}
	}
	return "", false
}

// HasAttribute is hasAttribute.
func (n *Node) HasAttribute(name string) bool {
	_, ok := n.LookupAttribute(name)
	return ok
}

// SetAttributeNS sets (or replaces) an attribute by namespace and qualified name.
func (n *Node) SetAttributeNS(namespace, name, value string) {
	prefix, local := splitName(name)
	for _, attr := range n.Attrs {
		if attr.NamespaceURI == namespace && attr.Local == local {
			attr.Value = value
			attr.Name = name
			attr.Prefix = prefix
			return
		}
	}
	n.Attrs = append(n.Attrs, &Attr{Name: name, Prefix: prefix, Local: local, NamespaceURI: namespace, Value: value})
}

// ElementsByTagNameNS is getElementsByTagNameNS: descendant elements in document order ("*" matches any).
func (n *Node) ElementsByTagNameNS(namespace, local string) []*Node {
	var found []*Node
	var walk func(node *Node)
	walk = func(node *Node) {
		for _, child := range node.Children {
			if child.Type != ElementNode {
				continue
			}
			if (namespace == "*" || child.NamespaceURI == namespace) && (local == "*" || child.Local == local) {
				found = append(found, child)
			}
			walk(child)
		}
	}
	walk(n)
	return found
}

// Descendants are the descendant elements in document order matching keep.
func (n *Node) Descendants(keep func(*Node) bool) []*Node {
	var found []*Node
	var walk func(node *Node)
	walk = func(node *Node) {
		for _, child := range node.Children {
			if child.Type != ElementNode {
				continue
			}
			if keep(child) {
				found = append(found, child)
			}
			walk(child)
		}
	}
	walk(n)
	return found
}

// ChildElements are the element children matching keep (nil keeps all).
func (n *Node) ChildElements(keep func(*Node) bool) []*Node {
	var found []*Node
	for _, child := range n.Children {
		if child.Type == ElementNode && (keep == nil || keep(child)) {
			found = append(found, child)
		}
	}
	return found
}

// TextContent is textContent: the concatenated text and CDATA of the subtree (a text node's own data).
func (n *Node) TextContent() string {
	switch n.Type {
	case TextNode, CDATANode, CommentNode, PINode:
		return n.Data
	}
	var out strings.Builder
	var walk func(node *Node)
	walk = func(node *Node) {
		for _, child := range node.Children {
			switch child.Type {
			case TextNode, CDATANode:
				out.WriteString(child.Data)
			case ElementNode:
				walk(child)
			}
		}
	}
	walk(n)
	return out.String()
}

// Root is the top of the node's tree (its document when attached).
func (n *Node) Root() *Node {
	for n.Parent != nil {
		n = n.Parent
	}
	return n
}

// OwnerDocument is the node's document.
func (n *Node) OwnerDocument() *Node {
	if n.Type == DocumentNode {
		return n
	}
	if n.Owner != nil {
		return n.Owner
	}
	return n.Root()
}

// Clone is cloneNode(true): a deep copy that keeps the owner document and has no parent.
func (n *Node) Clone() *Node {
	copied := &Node{Type: n.Type, Owner: n.Owner, TagName: n.TagName, Prefix: n.Prefix, Local: n.Local,
		NamespaceURI: n.NamespaceURI, Data: n.Data, Target: n.Target}
	for _, attr := range n.Attrs {
		value := *attr
		copied.Attrs = append(copied.Attrs, &value)
	}
	for _, child := range n.Children {
		c := child.Clone()
		c.Parent = copied
		copied.Children = append(copied.Children, c)
	}
	return copied
}

// RemoveChild detaches a child.
func (n *Node) RemoveChild(child *Node) {
	for i, c := range n.Children {
		if c == child {
			n.Children = append(n.Children[:i:i], n.Children[i+1:]...)
			child.Parent = nil
			return
		}
	}
}

// InsertBefore inserts child before ref (appends when ref is nil).
func (n *Node) InsertBefore(child, ref *Node) {
	if child.Parent != nil {
		child.Parent.RemoveChild(child)
	}
	child.Parent = n
	setOwner(child, n.OwnerDocument())
	if ref == nil {
		n.Children = append(n.Children, child)
		return
	}
	for i, c := range n.Children {
		if c == ref {
			n.Children = append(n.Children[:i], append([]*Node{child}, n.Children[i:]...)...)
			return
		}
	}
	n.Children = append(n.Children, child)
}

// AppendChild appends a child.
func (n *Node) AppendChild(child *Node) { n.InsertBefore(child, nil) }

// NextSibling is the following sibling (nil at the end).
func (n *Node) NextSibling() *Node {
	if n.Parent == nil {
		return nil
	}
	for i, c := range n.Parent.Children {
		if c == n && i+1 < len(n.Parent.Children) {
			return n.Parent.Children[i+1]
		}
	}
	return nil
}

func setOwner(node, owner *Node) {
	node.Owner = owner
	for _, child := range node.Children {
		setOwner(child, owner)
	}
}

func splitName(name string) (string, string) {
	if index := strings.IndexByte(name, ':'); index >= 0 {
		return name[:index], name[index+1:]
	}
	return "", name
}

// normalizeLineEndings is xmldom's normalizeLineEndings.
func normalizeLineEndings(input string) string {
	if !strings.ContainsAny(input, "\r\u0085 ") {
		return input
	}
	var out strings.Builder
	for i := 0; i < len(input); {
		r, size := utf8.DecodeRuneInString(input[i:])
		switch r {
		case '\r':
			out.WriteByte('\n')
			i += size
			if i < len(input) {
				next, nextSize := utf8.DecodeRuneInString(input[i:])
				if next == '\n' || next == '\u0085' {
					i += nextSize
				}
			}
			continue
		case '\u0085', ' ':
			out.WriteByte('\n')
		default:
			out.WriteString(input[i : i+size])
		}
		i += size
	}
	return out.String()
}

// ParseXML is `new DOMParser().parseFromString(xml, 'text/xml')` with every reported problem turned into an error.
func ParseXML(xml string) (*Node, error) {
	if xml == "" {
		return nil, &ParseError{Message: "invalid doc source"}
	}
	p := &parser{src: normalizeLineEndings(xml)}
	p.doc = &Node{Type: DocumentNode}
	if err := p.parse(); err != nil {
		return nil, err
	}
	return p.doc, nil
}

type parser struct {
	src   string
	pos   int
	doc   *Node
	stack []*element
}

type element struct {
	node *Node
	ns   map[string]string
}

var xmlEntities = map[string]string{"amp": "&", "apos": "'", "gt": ">", "lt": "<", "quot": "\""}

func (p *parser) fail(message string) error { return &ParseError{Message: message} }

func isWordByte(c byte) bool {
	return c == '_' || c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

// decodeEntities is xmldom's `replace(/&#?\w+;/g, entityReplacer)`.
func decodeEntities(text string) (string, error) {
	if !strings.Contains(text, "&") {
		return text, nil
	}
	var out strings.Builder
	for i := 0; i < len(text); {
		if text[i] != '&' {
			out.WriteByte(text[i])
			i++
			continue
		}
		j := i + 1
		if j < len(text) && text[j] == '#' {
			j++
		}
		start := j
		for j < len(text) && isWordByte(text[j]) {
			j++
		}
		if j == start || j >= len(text) || text[j] != ';' {
			out.WriteByte('&')
			i++
			continue
		}
		key := text[i+1 : j]
		if value, ok := xmlEntities[key]; ok {
			out.WriteString(value)
		} else if key[0] == '#' {
			out.WriteString(fromCharCode(jsParseInt(strings.Replace(key[1:], "x", "0x", 1))))
		} else {
			return "", &ParseError{Message: "entity not found:&" + key + ";"}
		}
		i = j + 1
	}
	return out.String(), nil
}

// jsParseInt is parseInt(value) without a radix: leading digits, "0x" for hexadecimal, NaN as -1.
func jsParseInt(value string) int64 {
	value = strings.TrimLeft(value, " \t\n\r")
	negative := false
	if strings.HasPrefix(value, "-") || strings.HasPrefix(value, "+") {
		negative = value[0] == '-'
		value = value[1:]
	}
	base := int64(10)
	if len(value) >= 2 && value[0] == '0' && (value[1] == 'x' || value[1] == 'X') {
		base = 16
		value = value[2:]
	}
	var result int64
	digits := 0
	for _, c := range []byte(value) {
		var d int64
		switch {
		case c >= '0' && c <= '9':
			d = int64(c - '0')
		case base == 16 && c >= 'a' && c <= 'f':
			d = int64(c-'a') + 10
		case base == 16 && c >= 'A' && c <= 'F':
			d = int64(c-'A') + 10
		default:
			d = -1
		}
		if d < 0 {
			break
		}
		if result < 1<<40 {
			result = result*base + d
		}
		digits++
	}
	if digits == 0 {
		return -1
	}
	if negative {
		return -result
	}
	return result
}

// fromCharCode is xmldom's fixedFromCharCode (NaN reads as U+0000).
func fromCharCode(code int64) string {
	if code < 0 {
		code = 0
	}
	if code > 0x10ffff {
		code &= 0xffff
	}
	if code >= 0xd800 && code <= 0xdfff {
		return string(utf8.RuneError)
	}
	return string(rune(code))
}

func isNameStart(r rune) bool {
	return r == ':' || r == '_' || r >= 'A' && r <= 'Z' || r >= 'a' && r <= 'z' || r >= 0xc0 && r <= 0xd6 ||
		r >= 0xd8 && r <= 0xf6 || r >= 0xf8 && r <= 0x2ff || r >= 0x370 && r <= 0x37d || r >= 0x37f && r <= 0x1fff ||
		r >= 0x200c && r <= 0x200d || r >= 0x2070 && r <= 0x218f || r >= 0x2c00 && r <= 0x2fef ||
		r >= 0x3001 && r <= 0xd7ff || r >= 0xf900 && r <= 0xfdcf || r >= 0xfdf0 && r <= 0xfffd || r >= 0x10000 && r <= 0xeffff
}

func isNameChar(r rune) bool {
	return isNameStart(r) || r == '-' || r == '.' || r >= '0' && r <= '9' || r == 0xb7 ||
		r >= 0x300 && r <= 0x36f || r >= 0x203f && r <= 0x2040
}

func validName(name string) bool {
	if name == "" {
		return false
	}
	for i, r := range name {
		if i == 0 && !isNameStart(r) || i > 0 && !isNameChar(r) {
			return false
		}
	}
	return true
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

func (p *parser) current() *element {
	if len(p.stack) == 0 {
		return nil
	}
	return p.stack[len(p.stack)-1]
}

func (p *parser) appendNode(node *Node) {
	node.Owner = p.doc
	if top := p.current(); top != nil {
		node.Parent = top.node
		top.node.Children = append(top.node.Children, node)
		return
	}
	node.Parent = p.doc
	p.doc.Children = append(p.doc.Children, node)
}

func (p *parser) text(raw string, last bool) error {
	if raw == "" {
		return nil
	}
	value, err := decodeEntities(raw)
	if err != nil {
		return err
	}
	if p.current() == nil {
		// Document-level text: whitespace is kept, other text is dropped (kept when it trails the last tag).
		if !isJSWhitespace(value) && !last {
			return nil
		}
		if last && isJSWhitespace(raw) {
			return nil
		}
	}
	p.appendNode(&Node{Type: TextNode, Data: value})
	return nil
}

// isJSWhitespace is /^\s*$/.test(value).
func isJSWhitespace(value string) bool {
	for _, r := range value {
		switch r {
		case ' ', '\t', '\n', '\r', '\f', '\v', 0xa0, 0x1680, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff:
			continue
		}
		if r >= 0x2000 && r <= 0x200a {
			continue
		}
		return false
	}
	return true
}

func (p *parser) parse() error {
	src := p.src
	for {
		lt := strings.IndexByte(src[p.pos:], '<')
		if lt < 0 {
			if err := p.text(src[p.pos:], true); err != nil {
				return err
			}
			break
		}
		lt += p.pos
		if err := p.text(src[p.pos:lt], false); err != nil {
			return err
		}
		p.pos = lt
		rest := src[lt:]
		switch {
		case strings.HasPrefix(rest, "</"):
			if err := p.endTag(); err != nil {
				return err
			}
		case strings.HasPrefix(rest, "<!--"):
			end := strings.Index(src[lt+4:], "-->")
			if end < 0 {
				return p.fail("Unclosed comment")
			}
			p.appendNode(&Node{Type: CommentNode, Data: src[lt+4 : lt+4+end]})
			p.pos = lt + 4 + end + 3
		case strings.HasPrefix(rest, "<![CDATA["):
			end := strings.Index(src[lt+9:], "]]>")
			if end < 0 {
				return p.fail("Unclosed CDATA")
			}
			if p.current() == nil {
				return p.fail("CDATA outside the document element")
			}
			p.appendNode(&Node{Type: CDATANode, Data: src[lt+9 : lt+9+end]})
			p.pos = lt + 9 + end + 3
		case strings.HasPrefix(rest, "<!DOCTYPE") || strings.HasPrefix(rest, "<!doctype"):
			if err := p.doctype(); err != nil {
				return err
			}
		case strings.HasPrefix(rest, "<?"):
			end := strings.Index(src[lt+2:], "?>")
			if end < 0 {
				return p.fail("Unclosed processing instruction")
			}
			body := src[lt+2 : lt+2+end]
			target, data := body, ""
			if index := strings.IndexAny(body, " \t\n\r"); index >= 0 {
				target = body[:index]
				data = strings.TrimLeft(body[index:], " \t\n\r")
			}
			if !validName(target) {
				return p.fail("Invalid processing instruction")
			}
			p.appendNode(&Node{Type: PINode, Target: target, Data: data})
			p.pos = lt + 2 + end + 2
		case strings.HasPrefix(rest, "<!"):
			return p.fail("Unsupported markup declaration")
		default:
			if err := p.startTag(); err != nil {
				return err
			}
		}
	}
	if len(p.stack) > 0 {
		return p.fail("unclosed xml attribute")
	}
	if p.doc.DocumentElement() == nil {
		return p.fail("No document element")
	}
	return nil
}

func (p *parser) doctype() error {
	if p.current() != nil || p.doc.DocumentElement() != nil {
		return p.fail("Misplaced DOCTYPE")
	}
	depth := 0
	for i := p.pos + 2; i < len(p.src); i++ {
		switch p.src[i] {
		case '[':
			depth++
		case ']':
			depth--
		case '>':
			if depth <= 0 {
				p.appendNode(&Node{Type: DoctypeNode, Data: p.src[p.pos : i+1]})
				p.pos = i + 1
				return nil
			}
		}
	}
	return p.fail("Unclosed DOCTYPE")
}

func (p *parser) readName() string {
	start := p.pos
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if isSpace(c) || c == '>' || c == '/' || c == '=' || c == '<' || c == '"' || c == '\'' {
			break
		}
		p.pos++
	}
	return p.src[start:p.pos]
}

func (p *parser) skipSpace() {
	for p.pos < len(p.src) && isSpace(p.src[p.pos]) {
		p.pos++
	}
}

func (p *parser) endTag() error {
	end := strings.IndexByte(p.src[p.pos:], '>')
	if end < 0 {
		return p.fail("end tag is not complete")
	}
	name := strings.TrimRight(p.src[p.pos+2:p.pos+end], " \t\n\r")
	p.pos += end + 1
	top := p.current()
	if top == nil || top.node.TagName != name {
		return p.fail("end tag name: " + name + " is not match the current start tagName")
	}
	p.stack = p.stack[:len(p.stack)-1]
	return nil
}

type rawAttr struct{ name, value string }

func (p *parser) startTag() error {
	p.pos++
	name := p.readName()
	if !validName(name) {
		return p.fail("invalid tagName:" + name)
	}
	var attrs []rawAttr
	seen := map[string]bool{}
	selfClosing := false
	for {
		p.skipSpace()
		if p.pos >= len(p.src) {
			return p.fail("unexpected end of input")
		}
		c := p.src[p.pos]
		if c == '>' {
			p.pos++
			break
		}
		if c == '/' {
			if p.pos+1 < len(p.src) && p.src[p.pos+1] == '>' {
				p.pos += 2
				selfClosing = true
				break
			}
			return p.fail("Invalid character in tag")
		}
		before := p.pos
		attrName := p.readName()
		if attrName == "" || !validName(attrName) {
			if p.pos == before {
				p.pos++
			}
			return p.fail("invalid attribute:" + attrName)
		}
		p.skipSpace()
		if p.pos >= len(p.src) || p.src[p.pos] != '=' {
			return p.fail("attribute " + attrName + " missed value")
		}
		p.pos++
		p.skipSpace()
		if p.pos >= len(p.src) || (p.src[p.pos] != '"' && p.src[p.pos] != '\'') {
			return p.fail("attribute value missed quot")
		}
		quote := p.src[p.pos]
		end := strings.IndexByte(p.src[p.pos+1:], quote)
		if end < 0 {
			return p.fail("attribute value no end '" + string(quote) + "' match")
		}
		raw := p.src[p.pos+1 : p.pos+1+end]
		p.pos += end + 2
		folded := strings.Map(func(r rune) rune {
			if r == '\t' || r == '\n' || r == '\r' {
				return ' '
			}
			return r
		}, raw)
		value, err := decodeEntities(folded)
		if err != nil {
			return err
		}
		if seen[attrName] {
			return p.fail("Attribute " + attrName + " redefined")
		}
		seen[attrName] = true
		attrs = append(attrs, rawAttr{attrName, value})
		if p.pos < len(p.src) && !isSpace(p.src[p.pos]) && p.src[p.pos] != '>' && p.src[p.pos] != '/' {
			return p.fail("attribute space is required")
		}
	}
	if p.current() == nil && p.doc.DocumentElement() != nil {
		return p.fail("Only one element can be added and only after doctype")
	}
	// Namespaces in scope.
	parentNs := map[string]string{"xml": xmlNamespace}
	if top := p.current(); top != nil {
		parentNs = top.ns
	}
	ns := parentNs
	copied := false
	for _, attr := range attrs {
		if attr.name == "xmlns" || strings.HasPrefix(attr.name, "xmlns:") {
			if !copied {
				ns = make(map[string]string, len(parentNs)+2)
				for k, v := range parentNs {
					ns[k] = v
				}
				copied = true
			}
			if attr.name == "xmlns" {
				ns[""] = attr.value
			} else {
				ns[attr.name[6:]] = attr.value
			}
		}
	}
	node := &Node{Type: ElementNode, TagName: name}
	node.Prefix, node.Local = splitName(name)
	node.NamespaceURI = ns[node.Prefix]
	for _, attr := range attrs {
		a := &Attr{Name: attr.name, Value: attr.value}
		a.Prefix, a.Local = splitName(attr.name)
		switch {
		case attr.name == "xmlns":
			a.NamespaceURI = xmlnsNamespace
		case a.Prefix == "xmlns":
			a.NamespaceURI = xmlnsNamespace
		case a.Prefix != "":
			a.NamespaceURI = ns[a.Prefix]
		}
		node.Attrs = append(node.Attrs, a)
	}
	p.appendNode(node)
	if !selfClosing {
		p.stack = append(p.stack, &element{node: node, ns: ns})
	}
	return nil
}

// --- serialization (xmldom XMLSerializer) -----------------------------------------------------------------------

type nsEntry struct{ prefix, namespace string }

func encodeXMLAttr(value string) string {
	if !strings.ContainsAny(value, "<>&\"\t\n\r") {
		return value
	}
	var out strings.Builder
	for _, r := range value {
		switch r {
		case '<':
			out.WriteString("&lt;")
		case '>':
			out.WriteString("&gt;")
		case '&':
			out.WriteString("&amp;")
		case '"':
			out.WriteString("&quot;")
		case '\t', '\n', '\r':
			out.WriteString("&#" + strconv.Itoa(int(r)) + ";")
		default:
			out.WriteRune(r)
		}
	}
	return out.String()
}

func encodeXMLText(value string) string {
	if !strings.ContainsAny(value, "<>&") {
		return value
	}
	replacer := strings.NewReplacer("<", "&lt;", ">", "&gt;", "&", "&amp;")
	return replacer.Replace(value)
}

func needNamespaceDefine(prefix, namespace string, visible []nsEntry) bool {
	if namespace == "" {
		return false
	}
	if prefix == "xml" && namespace == xmlNamespace || namespace == xmlnsNamespace {
		return false
	}
	for i := len(visible) - 1; i >= 0; i-- {
		if visible[i].prefix == prefix {
			return visible[i].namespace != namespace
		}
	}
	return true
}

// String is node.toString(): xmldom's serialization.
func (n *Node) String() string {
	var out strings.Builder
	serialize(n, &out, nil)
	return out.String()
}

func serialize(n *Node, out *strings.Builder, visible []nsEntry) {
	switch n.Type {
	case DocumentNode:
		for _, child := range n.Children {
			serialize(child, out, visible)
		}
	case ElementNode:
		nodeName := n.TagName
		prefixed := nodeName
		if n.Prefix == "" && n.NamespaceURI != "" {
			defaultNS := ""
			hasDefault := false
			for _, attr := range n.Attrs {
				if attr.Name == "xmlns" {
					defaultNS, hasDefault = attr.Value, true
					break
				}
			}
			if !hasDefault || defaultNS == "" {
				for i := len(visible) - 1; i >= 0; i-- {
					if visible[i].prefix == "" && visible[i].namespace == n.NamespaceURI {
						defaultNS, hasDefault = visible[i].namespace, true
						break
					}
				}
			}
			if defaultNS != n.NamespaceURI {
				for i := len(visible) - 1; i >= 0; i-- {
					if visible[i].namespace == n.NamespaceURI {
						if visible[i].prefix != "" {
							prefixed = visible[i].prefix + ":" + nodeName
						}
						break
					}
				}
			}
		}
		out.WriteString("<" + prefixed)
		child := append([]nsEntry(nil), visible...)
		for _, attr := range n.Attrs {
			if attr.Prefix == "xmlns" {
				child = append(child, nsEntry{attr.Local, attr.Value})
			} else if attr.Name == "xmlns" {
				child = append(child, nsEntry{"", attr.Value})
			}
		}
		for _, attr := range n.Attrs {
			if attr.Prefix != "xmlns" && attr.Name != "xmlns" && needNamespaceDefine(attr.Prefix, attr.NamespaceURI, child) && attr.Prefix != "" {
				out.WriteString(" xmlns:" + attr.Prefix + "=\"" + encodeXMLAttr(attr.NamespaceURI) + "\"")
				child = append(child, nsEntry{attr.Prefix, attr.NamespaceURI})
			}
			out.WriteString(" " + attr.Name + "=\"" + encodeXMLAttr(attr.Value) + "\"")
		}
		if nodeName == prefixed && needNamespaceDefine(n.Prefix, n.NamespaceURI, child) {
			name := "xmlns"
			if n.Prefix != "" {
				name = "xmlns:" + n.Prefix
			}
			out.WriteString(" " + name + "=\"" + encodeXMLAttr(n.NamespaceURI) + "\"")
			child = append(child, nsEntry{n.Prefix, n.NamespaceURI})
		}
		if len(n.Children) == 0 {
			out.WriteString("/>")
			return
		}
		out.WriteString(">")
		for _, c := range n.Children {
			serialize(c, out, child)
		}
		out.WriteString("</" + prefixed + ">")
	case TextNode:
		out.WriteString(encodeXMLText(n.Data))
	case CDATANode:
		out.WriteString("<![CDATA[" + strings.ReplaceAll(n.Data, "]]>", "]]]]><![CDATA[>") + "]]>")
	case CommentNode:
		out.WriteString("<!--" + n.Data + "-->")
	case PINode:
		out.WriteString("<?" + n.Target + " " + n.Data + "?>")
	case DoctypeNode:
		out.WriteString(n.Data)
	}
}
