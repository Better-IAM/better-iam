//! A namespace-aware XML DOM with the parsing and serialization behavior of `@xmldom/xmldom` 0.8 (which the
//! TypeScript implementation, `xml-crypto` and `xml-encryption` parse with): line endings normalized (`\r\n`, `\r`,
//! U+0085 and U+2028 become `\n`), attribute values whitespace-normalized before entity references are expanded,
//! only the five predefined entities and character references, DOCTYPEs kept but never expanded, and
//! `toString()`'s serialization. No libxml2.
//!
//! Malformed markup that xmldom reports as a warning or error is an [`XmlError`] here.

use std::fmt;

pub const XML_NS: &str = "http://www.w3.org/XML/1998/namespace";
pub const XMLNS_NS: &str = "http://www.w3.org/2000/xmlns/";

/// A node of a [`Document`].
pub type NodeId = usize;

/// A malformed document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XmlError(pub String);

impl fmt::Display for XmlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for XmlError {}

fn error(message: impl Into<String>) -> XmlError {
    XmlError(message.into())
}

/// An attribute (namespace declarations included, as in the DOM).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attr {
    /// The qualified name (`nodeName`).
    pub name: String,
    pub prefix: Option<String>,
    pub local: String,
    pub namespace: Option<String>,
    pub value: String,
}

/// An element.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Element {
    /// The qualified name (`tagName`).
    pub name: String,
    pub prefix: Option<String>,
    pub local: String,
    pub namespace: Option<String>,
    pub attrs: Vec<Attr>,
}

impl Element {
    /// `getAttribute(name)`: the first attribute whose qualified name is `name`.
    pub fn attr(&self, name: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|attr| attr.name == name)
            .map(|attr| attr.value.as_str())
    }
}

/// A node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    Document,
    Element(Element),
    Text(String),
    CData(String),
    Comment(String),
    Pi { target: String, data: String },
    DocType { raw: String },
}

#[derive(Debug, Clone)]
struct Entry {
    kind: Kind,
    parent: Option<NodeId>,
    children: Vec<NodeId>,
}

/// A document: an arena of nodes whose node 0 is the document node.
#[derive(Debug, Clone)]
pub struct Document {
    nodes: Vec<Entry>,
}

impl Default for Document {
    fn default() -> Self {
        Self::new()
    }
}

/// `normalizeLineEndings`.
pub fn normalize_line_endings(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\r' => {
                if matches!(chars.peek(), Some('\n') | Some('\u{85}')) {
                    chars.next();
                }
                out.push('\n');
            }
            '\u{85}' | '\u{2028}' => out.push('\n'),
            other => out.push(other),
        }
    }
    out
}

/// `/\s/` of JavaScript.
pub fn is_js_space(c: char) -> bool {
    better_iam_core::js::is_js_whitespace(c)
}

impl Document {
    pub fn new() -> Self {
        Document {
            nodes: vec![Entry {
                kind: Kind::Document,
                parent: None,
                children: Vec::new(),
            }],
        }
    }

    /// The document node.
    pub const ROOT: NodeId = 0;

    /// `new DOMParser().parseFromString(text, 'text/xml')`, failing on anything xmldom warns about.
    pub fn parse(text: &str) -> Result<Document, XmlError> {
        Parser::new(&normalize_line_endings(text)).parse()
    }

    fn push(&mut self, kind: Kind, parent: Option<NodeId>) -> NodeId {
        let id = self.nodes.len();
        self.nodes.push(Entry {
            kind,
            parent,
            children: Vec::new(),
        });
        if let Some(parent) = parent {
            self.nodes[parent].children.push(id);
        }
        id
    }

    /// A detached node of this document.
    pub fn create(&mut self, kind: Kind) -> NodeId {
        self.push(kind, None)
    }

    /// `documentElement`.
    pub fn document_element(&self) -> Option<NodeId> {
        self.nodes[Self::ROOT]
            .children
            .iter()
            .copied()
            .find(|id| self.element(*id).is_some())
    }

    pub fn kind(&self, id: NodeId) -> &Kind {
        &self.nodes[id].kind
    }

    pub fn element(&self, id: NodeId) -> Option<&Element> {
        match &self.nodes[id].kind {
            Kind::Element(element) => Some(element),
            _ => None,
        }
    }

    pub fn element_mut(&mut self, id: NodeId) -> Option<&mut Element> {
        match &mut self.nodes[id].kind {
            Kind::Element(element) => Some(element),
            _ => None,
        }
    }

    pub fn parent(&self, id: NodeId) -> Option<NodeId> {
        self.nodes[id].parent
    }

    pub fn children(&self, id: NodeId) -> &[NodeId] {
        &self.nodes[id].children
    }

    /// The element children of a node.
    pub fn child_elements(&self, id: NodeId) -> Vec<NodeId> {
        self.nodes[id]
            .children
            .iter()
            .copied()
            .filter(|child| self.element(*child).is_some())
            .collect()
    }

    pub fn local_name(&self, id: NodeId) -> Option<&str> {
        self.element(id).map(|element| element.local.as_str())
    }

    pub fn namespace(&self, id: NodeId) -> Option<&str> {
        self.element(id)
            .and_then(|element| element.namespace.as_deref())
    }

    /// `getAttribute(name)`.
    pub fn attr(&self, id: NodeId, name: &str) -> Option<&str> {
        self.element(id).and_then(|element| element.attr(name))
    }

    /// `hasAttribute(name)`.
    pub fn has_attr(&self, id: NodeId, name: &str) -> bool {
        self.attr(id, name).is_some()
    }

    /// Whether `id` is an element with this local name (and namespace, when given).
    pub fn is(&self, id: NodeId, namespace: Option<&str>, local: &str) -> bool {
        self.element(id).is_some_and(|element| {
            element.local == local
                && namespace.is_none_or(|namespace| element.namespace.as_deref() == Some(namespace))
        })
    }

    /// The descendants of a node in document order (the node itself excluded).
    pub fn descendants(&self, id: NodeId) -> Vec<NodeId> {
        let mut out = Vec::new();
        let mut stack: Vec<NodeId> = self.nodes[id].children.iter().rev().copied().collect();
        while let Some(next) = stack.pop() {
            out.push(next);
            stack.extend(self.nodes[next].children.iter().rev().copied());
        }
        out
    }

    /// The node and its descendants in document order.
    pub fn self_and_descendants(&self, id: NodeId) -> Vec<NodeId> {
        let mut out = vec![id];
        out.extend(self.descendants(id));
        out
    }

    /// The descendant elements with a local name (and namespace, when given), in document order
    /// (`getElementsByTagNameNS` for a namespace; `.//*[local-name()=...]` without).
    pub fn find_descendants(
        &self,
        id: NodeId,
        namespace: Option<&str>,
        local: &str,
    ) -> Vec<NodeId> {
        self.descendants(id)
            .into_iter()
            .filter(|node| self.is(*node, namespace, local))
            .collect()
    }

    /// The element children with a local name (and namespace, when given).
    pub fn find_children(&self, id: NodeId, namespace: Option<&str>, local: &str) -> Vec<NodeId> {
        self.child_elements(id)
            .into_iter()
            .filter(|node| self.is(*node, namespace, local))
            .collect()
    }

    /// `textContent`: the text of every text and CDATA descendant (comments and processing instructions skipped).
    pub fn text_content(&self, id: NodeId) -> String {
        match &self.nodes[id].kind {
            Kind::Text(text) | Kind::CData(text) | Kind::Comment(text) => text.clone(),
            Kind::Pi { data, .. } => data.clone(),
            _ => {
                let mut out = String::new();
                for node in self.descendants(id) {
                    if let Kind::Text(text) | Kind::CData(text) = &self.nodes[node].kind {
                        out.push_str(text);
                    }
                }
                out
            }
        }
    }

    /// The first text node child of the first matching descendant (`.//*[local-name(.)=name]/text()`, `select1`).
    pub fn first_descendant_text(&self, id: NodeId, local: &str) -> Option<String> {
        for node in self.find_descendants(id, None, local) {
            for child in &self.nodes[node].children {
                if let Kind::Text(text) = &self.nodes[*child].kind {
                    return Some(text.clone());
                }
            }
        }
        None
    }

    /// Detaches a node from its parent (`removeChild`).
    pub fn detach(&mut self, id: NodeId) {
        if let Some(parent) = self.nodes[id].parent.take() {
            self.nodes[parent].children.retain(|child| *child != id);
        }
    }

    /// `parent.insertBefore(node, reference)` (`reference` None appends).
    pub fn insert_before(&mut self, parent: NodeId, node: NodeId, reference: Option<NodeId>) {
        self.detach(node);
        let position = reference
            .and_then(|reference| {
                self.nodes[parent]
                    .children
                    .iter()
                    .position(|child| *child == reference)
            })
            .unwrap_or(self.nodes[parent].children.len());
        self.nodes[parent].children.insert(position, node);
        self.nodes[node].parent = Some(parent);
    }

    /// `parent.appendChild(node)`.
    pub fn append_child(&mut self, parent: NodeId, node: NodeId) {
        self.insert_before(parent, node, None);
    }

    /// `parent.replaceChild(node, old)`.
    pub fn replace_child(&mut self, parent: NodeId, node: NodeId, old: NodeId) {
        self.insert_before(parent, node, Some(old));
        self.detach(old);
    }

    /// The next sibling of a node.
    pub fn next_sibling(&self, id: NodeId) -> Option<NodeId> {
        let parent = self.nodes[id].parent?;
        let siblings = &self.nodes[parent].children;
        let position = siblings.iter().position(|child| *child == id)?;
        siblings.get(position + 1).copied()
    }

    /// Copies a subtree of another document into this one, detached (`importNode(node, true)` / `cloneNode(true)`).
    pub fn import(&mut self, other: &Document, id: NodeId) -> NodeId {
        let copy = self.push(other.nodes[id].kind.clone(), None);
        for child in other.nodes[id].children.clone() {
            let child = self.import(other, child);
            self.nodes[child].parent = Some(copy);
            self.nodes[copy].children.push(child);
        }
        copy
    }

    /// A deep clone of a subtree as the only child of a new document.
    pub fn clone_subtree(&self, id: NodeId) -> (Document, NodeId) {
        let mut document = Document::new();
        let copy = document.import(self, id);
        document.append_child(Document::ROOT, copy);
        (document, copy)
    }

    /// `setAttributeNS(namespace, qualifiedName, value)`: replaces the attribute with the same namespace and local
    /// name in place, or appends one.
    pub fn set_attribute_ns(
        &mut self,
        id: NodeId,
        namespace: Option<&str>,
        name: &str,
        value: &str,
    ) {
        let (prefix, local) = split_name(name);
        let Some(element) = self.element_mut(id) else {
            return;
        };
        let attr = Attr {
            name: name.to_owned(),
            prefix: prefix.map(str::to_owned),
            local: local.to_owned(),
            namespace: namespace.map(str::to_owned),
            value: value.to_owned(),
        };
        match element.attrs.iter().position(|existing| {
            existing.namespace.as_deref() == namespace && existing.local == local
        }) {
            Some(position) => element.attrs[position] = attr,
            None => element.attrs.push(attr),
        }
    }

    /// `setAttribute(name, value)` (no namespace).
    pub fn set_attribute(&mut self, id: NodeId, name: &str, value: &str) {
        let Some(element) = self.element_mut(id) else {
            return;
        };
        match element.attrs.iter_mut().find(|attr| attr.name == name) {
            Some(attr) => attr.value = value.to_owned(),
            None => element.attrs.push(Attr {
                name: name.to_owned(),
                prefix: None,
                local: name.to_owned(),
                namespace: None,
                value: value.to_owned(),
            }),
        }
    }

    /// The namespace a prefix resolves to at a node (`lookupNamespaceURI`), from the declarations in scope.
    pub fn lookup_namespace(&self, id: NodeId, prefix: Option<&str>) -> Option<String> {
        let mut current = Some(id);
        while let Some(node) = current {
            if let Some(element) = self.element(node) {
                for attr in &element.attrs {
                    let declares = match prefix {
                        Some(prefix) => {
                            attr.prefix.as_deref() == Some("xmlns") && attr.local == prefix
                        }
                        None => attr.name == "xmlns",
                    };
                    if declares {
                        return (!attr.value.is_empty()).then(|| attr.value.clone());
                    }
                }
            }
            current = self.nodes[node].parent;
        }
        None
    }

    /// `node.toString()`: xmldom's serialization of a node and its subtree.
    pub fn serialize(&self, id: NodeId) -> String {
        let mut out = String::new();
        self.serialize_into(id, &mut out, &[]);
        out
    }

    fn serialize_into(&self, id: NodeId, out: &mut String, visible: &[(String, String)]) {
        match &self.nodes[id].kind {
            Kind::Document => {
                for child in &self.nodes[id].children {
                    self.serialize_into(*child, out, visible);
                }
            }
            Kind::Element(element) => {
                let mut prefixed = element.name.clone();
                if element.prefix.is_none()
                    && let Some(namespace) = &element.namespace
                {
                    let mut default = element
                        .attrs
                        .iter()
                        .find(|attr| attr.name == "xmlns")
                        .map(|attr| attr.value.clone());
                    if default.as_deref().is_none_or(str::is_empty) {
                        default = visible
                            .iter()
                            .rev()
                            .find(|(prefix, uri)| prefix.is_empty() && uri == namespace)
                            .map(|(_, uri)| uri.clone());
                    }
                    if default.as_deref() != Some(namespace.as_str())
                        && let Some((prefix, _)) =
                            visible.iter().rev().find(|(_, uri)| uri == namespace)
                        && !prefix.is_empty()
                    {
                        prefixed = format!("{prefix}:{}", element.name);
                    }
                }
                out.push('<');
                out.push_str(&prefixed);
                let mut scope: Vec<(String, String)> = visible.to_vec();
                for attr in &element.attrs {
                    if attr.prefix.as_deref() == Some("xmlns") {
                        scope.push((attr.local.clone(), attr.value.clone()));
                    } else if attr.name == "xmlns" {
                        scope.push((String::new(), attr.value.clone()));
                    }
                }
                for attr in &element.attrs {
                    if need_namespace_define(
                        attr.prefix.as_deref(),
                        attr.namespace.as_deref(),
                        &scope,
                    ) {
                        let prefix = attr.prefix.clone().unwrap_or_default();
                        let namespace = attr.namespace.clone().unwrap_or_default();
                        let name = if prefix.is_empty() {
                            "xmlns".to_owned()
                        } else {
                            format!("xmlns:{prefix}")
                        };
                        serialize_attribute(out, &name, &namespace);
                        scope.push((prefix, namespace));
                    }
                    serialize_attribute(out, &attr.name, &attr.value);
                }
                if element.name == prefixed
                    && need_namespace_define(
                        element.prefix.as_deref(),
                        element.namespace.as_deref(),
                        &scope,
                    )
                {
                    let prefix = element.prefix.clone().unwrap_or_default();
                    let namespace = element.namespace.clone().unwrap_or_default();
                    let name = if prefix.is_empty() {
                        "xmlns".to_owned()
                    } else {
                        format!("xmlns:{prefix}")
                    };
                    serialize_attribute(out, &name, &namespace);
                    scope.push((prefix, namespace));
                }
                let children = &self.nodes[id].children;
                if children.is_empty() {
                    out.push_str("/>");
                } else {
                    out.push('>');
                    for child in children {
                        self.serialize_into(*child, out, &scope);
                    }
                    out.push_str("</");
                    out.push_str(&prefixed);
                    out.push('>');
                }
            }
            Kind::Text(text) => push_escaped(out, text, &['<', '&', '>']),
            Kind::CData(text) => {
                out.push_str("<![CDATA[");
                out.push_str(&text.replace("]]>", "]]]]><![CDATA[>"));
                out.push_str("]]>");
            }
            Kind::Comment(text) => {
                out.push_str("<!--");
                out.push_str(text);
                out.push_str("-->");
            }
            Kind::Pi { target, data } => {
                out.push_str("<?");
                out.push_str(target);
                out.push(' ');
                out.push_str(data);
                out.push_str("?>");
            }
            Kind::DocType { raw } => out.push_str(raw),
        }
    }
}

fn need_namespace_define(
    prefix: Option<&str>,
    namespace: Option<&str>,
    scope: &[(String, String)],
) -> bool {
    let prefix = prefix.unwrap_or_default();
    let Some(uri) = namespace.filter(|uri| !uri.is_empty()) else {
        return false;
    };
    if (prefix == "xml" && uri == XML_NS) || uri == XMLNS_NS {
        return false;
    }
    match scope.iter().rev().find(|(declared, _)| declared == prefix) {
        Some((_, declared)) => declared != uri,
        None => true,
    }
}

/// `_xmlEncoder`.
fn push_escaped(out: &mut String, text: &str, special: &[char]) {
    for c in text.chars() {
        if special.contains(&c) {
            match c {
                '<' => out.push_str("&lt;"),
                '>' => out.push_str("&gt;"),
                '&' => out.push_str("&amp;"),
                '"' => out.push_str("&quot;"),
                other => {
                    out.push_str("&#");
                    out.push_str(&(other as u32).to_string());
                    out.push(';');
                }
            }
        } else {
            out.push(c);
        }
    }
}

fn serialize_attribute(out: &mut String, name: &str, value: &str) {
    out.push(' ');
    out.push_str(name);
    out.push_str("=\"");
    push_escaped(out, value, &['<', '>', '&', '"', '\t', '\n', '\r']);
    out.push('"');
}

/// `prefix:local` → (prefix, local).
pub fn split_name(name: &str) -> (Option<&str>, &str) {
    match name.find(':') {
        Some(index) => (Some(&name[..index]), &name[index + 1..]),
        None => (None, name),
    }
}

/// `String.fromCharCode` of a code point (`fixedFromCharCode`); invalid code points become U+FFFD.
fn from_code(code: f64) -> String {
    if !code.is_finite() {
        return "\u{0}".to_owned();
    }
    let code = code as i64;
    let unit = |value: i64| -> u16 { (value.rem_euclid(65536)) as u16 };
    let units: Vec<u16> = if code > 0xffff {
        let rest = code - 0x10000;
        vec![unit(0xd800 + (rest >> 10)), unit(0xdc00 + (rest & 0x3ff))]
    } else {
        vec![unit(code)]
    };
    String::from_utf16_lossy(&units)
}

/// `parseInt(text)` for xmldom's character references (`&#12;`, `&#x1f;`).
fn parse_reference(text: &str) -> f64 {
    let (digits, radix) = match text.strip_prefix("0x").or_else(|| text.strip_prefix("0X")) {
        Some(hex) => (hex, 16),
        None => (text, 10),
    };
    let leading: String = digits.chars().take_while(|c| c.is_digit(radix)).collect();
    if leading.is_empty() {
        return f64::NAN;
    }
    i64::from_str_radix(&leading, radix)
        .map(|value| value as f64)
        .unwrap_or(f64::INFINITY)
}

/// xmldom's `entityReplacer` over `/&#?\w+;/g`: the five predefined entities and character references; anything else
/// matching the pattern is an error, and an `&` that does not start a reference stays as it is.
fn replace_entities(text: &str) -> Result<String, XmlError> {
    if !text.contains('&') {
        return Ok(text.to_owned());
    }
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::with_capacity(text.len());
    let mut index = 0;
    while index < chars.len() {
        if chars[index] == '&' {
            let mut end = index + 1;
            if chars.get(end) == Some(&'#') {
                end += 1;
            }
            let start = end;
            while end < chars.len() && (chars[end].is_ascii_alphanumeric() || chars[end] == '_') {
                end += 1;
            }
            if end > start && chars.get(end) == Some(&';') {
                let name: String = chars[index + 1..end].iter().collect();
                match name.as_str() {
                    "amp" => out.push('&'),
                    "lt" => out.push('<'),
                    "gt" => out.push('>'),
                    "quot" => out.push('"'),
                    "apos" => out.push('\''),
                    reference if reference.starts_with('#') => {
                        out.push_str(&from_code(parse_reference(
                            &reference[1..].replacen('x', "0x", 1),
                        )));
                    }
                    other => return Err(error(format!("entity not found:&{other};"))),
                }
                index = end + 1;
                continue;
            }
        }
        out.push(chars[index]);
        index += 1;
    }
    Ok(out)
}

struct Parser<'a> {
    source: &'a str,
    position: usize,
    document: Document,
    /// The open elements, innermost last, with the namespace declarations in scope at each.
    stack: Vec<(NodeId, Vec<(String, String)>)>,
}

impl<'a> Parser<'a> {
    fn new(source: &'a str) -> Self {
        Parser {
            source,
            position: 0,
            document: Document::new(),
            stack: Vec::new(),
        }
    }

    fn rest(&self) -> &'a str {
        &self.source[self.position..]
    }

    fn current(&self) -> NodeId {
        self.stack
            .last()
            .map(|(id, _)| *id)
            .unwrap_or(Document::ROOT)
    }

    fn scope(&self) -> &[(String, String)] {
        self.stack
            .last()
            .map(|(_, scope)| scope.as_slice())
            .unwrap_or(&[])
    }

    fn parse(mut self) -> Result<Document, XmlError> {
        loop {
            let Some(offset) = self.rest().find('<') else {
                let text = self.rest();
                if !self.stack.is_empty() {
                    return Err(error("unexpected end of input"));
                }
                if !text.chars().all(is_js_space) {
                    let text = text.to_owned();
                    self.document.push(Kind::Text(text), Some(Document::ROOT));
                }
                break;
            };
            if offset > 0 {
                let text = self.rest()[..offset].to_owned();
                self.position += offset;
                self.text(&text)?;
            }
            let rest = self.rest();
            if rest.starts_with("</") {
                self.end_tag()?;
            } else if let Some(body) = rest.strip_prefix("<!--") {
                let Some(end) = body.find("-->") else {
                    return Err(error("Unclosed comment"));
                };
                let data = body[..end].to_owned();
                self.position += 4 + end + 3;
                let parent = self.current();
                self.document.push(Kind::Comment(data), Some(parent));
            } else if let Some(body) = rest.strip_prefix("<![CDATA[") {
                let Some(end) = body.find("]]>") else {
                    return Err(error("Unclosed CDATA"));
                };
                if self.stack.is_empty() {
                    return Err(error("CDATA outside of the document element"));
                }
                let data = body[..end].to_owned();
                self.position += 9 + end + 3;
                let parent = self.current();
                self.document.push(Kind::CData(data), Some(parent));
            } else if rest.starts_with("<!DOCTYPE") {
                self.doctype()?;
            } else if rest.starts_with("<?") {
                let Some(end) = rest.find("?>") else {
                    return Err(error("Unclosed processing instruction"));
                };
                let body = &rest[2..end];
                let target_end = body.find(|c: char| is_js_space(c)).unwrap_or(body.len());
                let target = body[..target_end].to_owned();
                if target.is_empty() {
                    return Err(error("Invalid processing instruction"));
                }
                let data = body[target_end..].trim_matches(is_js_space).to_owned();
                self.position += end + 2;
                let parent = self.current();
                self.document.push(Kind::Pi { target, data }, Some(parent));
            } else if rest.starts_with("<!") {
                return Err(error("Invalid markup declaration"));
            } else {
                self.start_tag()?;
            }
        }
        if self.document.document_element().is_none() {
            return Err(error("Not a valid XML document"));
        }
        Ok(self.document)
    }

    fn text(&mut self, raw: &str) -> Result<(), XmlError> {
        let text = replace_entities(raw)?;
        if text.is_empty() {
            return Ok(());
        }
        if self.stack.is_empty() {
            // Before the document element only whitespace is kept; after it xmldom keeps any text.
            let after_root = self.document.document_element().is_some();
            if after_root || text.chars().all(is_js_space) {
                self.document.push(Kind::Text(text), Some(Document::ROOT));
            }
            return Ok(());
        }
        let parent = self.current();
        if let Some(last) = self.document.nodes[parent].children.last().copied()
            && let Kind::Text(existing) = &mut self.document.nodes[last].kind
        {
            existing.push_str(&text);
            return Ok(());
        }
        self.document.push(Kind::Text(text), Some(parent));
        Ok(())
    }

    fn doctype(&mut self) -> Result<(), XmlError> {
        let rest = self.rest();
        let mut depth = 0usize;
        let mut quote: Option<char> = None;
        let mut end = None;
        for (index, c) in rest.char_indices().skip(2) {
            match quote {
                Some(q) if c == q => quote = None,
                Some(_) => {}
                None => match c {
                    '"' | '\'' => quote = Some(c),
                    '[' => depth += 1,
                    ']' => depth = depth.saturating_sub(1),
                    '>' if depth == 0 => {
                        end = Some(index);
                        break;
                    }
                    _ => {}
                },
            }
        }
        let Some(end) = end else {
            return Err(error("Unclosed DOCTYPE"));
        };
        if !self.stack.is_empty() || self.document.document_element().is_some() {
            return Err(error("Misplaced DOCTYPE"));
        }
        let raw = rest[..=end].to_owned();
        self.position += end + 1;
        self.document
            .push(Kind::DocType { raw }, Some(Document::ROOT));
        Ok(())
    }

    fn end_tag(&mut self) -> Result<(), XmlError> {
        let rest = self.rest();
        let Some(end) = rest.find('>') else {
            return Err(error("end tag name is not complete"));
        };
        let name = rest[2..end].trim_end_matches([' ', '\t', '\n', '\r']);
        let Some((open, _)) = self.stack.last() else {
            return Err(error(format!(
                "end tag name: {name} is not match the current start tagName"
            )));
        };
        let open_name = self
            .document
            .element(*open)
            .map(|element| element.name.clone())
            .unwrap_or_default();
        if open_name != name {
            return Err(error(format!(
                "end tag name: {name} is not match the current start tagName:{open_name}"
            )));
        }
        self.position += end + 1;
        self.stack.pop();
        Ok(())
    }

    fn start_tag(&mut self) -> Result<(), XmlError> {
        let source = self.source;
        let mut index = self.position + 1;
        let bytes = source.as_bytes();
        let name_end = source[index..]
            .find(|c: char| is_js_space(c) || c == '/' || c == '>')
            .map(|offset| index + offset)
            .ok_or_else(|| error("unexpected end of input"))?;
        let name = &source[index..name_end];
        if name.is_empty() || name.contains(['<', '=', '"', '\'']) {
            return Err(error(format!("invalid tagName:{name}")));
        }
        index = name_end;
        let mut raw_attrs: Vec<(String, String)> = Vec::new();
        let self_closing;
        loop {
            let had_space = index < bytes.len() && source[index..].starts_with(is_js_space);
            while index < bytes.len() && source[index..].starts_with(is_js_space) {
                index += source[index..]
                    .chars()
                    .next()
                    .map(char::len_utf8)
                    .unwrap_or(1);
            }
            if index >= bytes.len() {
                return Err(error("unexpected end of input"));
            }
            if source[index..].starts_with("/>") {
                self_closing = true;
                index += 2;
                break;
            }
            if source[index..].starts_with('>') {
                self_closing = false;
                index += 1;
                break;
            }
            if source[index..].starts_with('/') {
                return Err(error(
                    "elements closed character '/' and '>' must be connected to",
                ));
            }
            if !had_space {
                return Err(error("attribute space is required"));
            }
            let attr_end = source[index..]
                .find(|c: char| is_js_space(c) || c == '=' || c == '/' || c == '>')
                .map(|offset| index + offset)
                .ok_or_else(|| error("unexpected end of input"))?;
            let attr_name = &source[index..attr_end];
            if attr_name.is_empty() || attr_name.contains(['<', '"', '\'']) {
                return Err(error(format!("invalid attribute:{attr_name}")));
            }
            index = attr_end;
            while index < bytes.len() && source[index..].starts_with(is_js_space) {
                index += source[index..]
                    .chars()
                    .next()
                    .map(char::len_utf8)
                    .unwrap_or(1);
            }
            if !source[index..].starts_with('=') {
                return Err(error(format!("attribute \"{attr_name}\" missed value")));
            }
            index += 1;
            while index < bytes.len() && source[index..].starts_with(is_js_space) {
                index += source[index..]
                    .chars()
                    .next()
                    .map(char::len_utf8)
                    .unwrap_or(1);
            }
            let quote = source[index..]
                .chars()
                .next()
                .ok_or_else(|| error("unexpected end of input"))?;
            if quote != '"' && quote != '\'' {
                return Err(error(format!(
                    "attribute \"{attr_name}\" missed start quot"
                )));
            }
            index += 1;
            let value_end = source[index..]
                .find(quote)
                .map(|offset| index + offset)
                .ok_or_else(|| error("unclosed xml attribute"))?;
            let raw_value = &source[index..value_end];
            if raw_value.contains('<') {
                return Err(error(format!("attribute \"{attr_name}\" contains <")));
            }
            let normalized: String = raw_value
                .chars()
                .map(|c| {
                    if matches!(c, '\t' | '\n' | '\r') {
                        ' '
                    } else {
                        c
                    }
                })
                .collect();
            let value = replace_entities(&normalized)?;
            if raw_attrs.iter().any(|(existing, _)| existing == attr_name) {
                return Err(error(format!("Attribute {attr_name} redefined")));
            }
            raw_attrs.push((attr_name.to_owned(), value));
            index = value_end + 1;
            if index < bytes.len()
                && !source[index..].starts_with(is_js_space)
                && !source[index..].starts_with('>')
                && !source[index..].starts_with("/>")
            {
                return Err(error("attribute invalid close char"));
            }
        }
        if self.stack.is_empty() && self.document.document_element().is_some() {
            return Err(error("element parse error: Only one element can be added"));
        }
        // Namespace declarations of this element first, then the names they resolve.
        let mut scope: Vec<(String, String)> = self.scope().to_vec();
        for (attr_name, value) in &raw_attrs {
            if attr_name == "xmlns" {
                scope.push((String::new(), value.clone()));
            } else if let Some(prefix) = attr_name.strip_prefix("xmlns:") {
                scope.push((prefix.to_owned(), value.clone()));
            }
        }
        let resolve = |prefix: &str| -> Option<String> {
            if prefix == "xml" {
                return Some(XML_NS.to_owned());
            }
            if prefix == "xmlns" {
                return Some(XMLNS_NS.to_owned());
            }
            scope
                .iter()
                .rev()
                .find(|(declared, _)| declared == prefix)
                .map(|(_, uri)| uri.clone())
                .filter(|uri| !uri.is_empty())
        };
        let attrs: Vec<Attr> = raw_attrs
            .iter()
            .map(|(attr_name, value)| {
                let (prefix, local) = split_name(attr_name);
                let namespace = match prefix {
                    Some(prefix) => resolve(prefix),
                    None if attr_name == "xmlns" => Some(XMLNS_NS.to_owned()),
                    None => None,
                };
                Attr {
                    name: attr_name.clone(),
                    prefix: prefix.map(str::to_owned),
                    local: local.to_owned(),
                    namespace,
                    value: value.clone(),
                }
            })
            .collect();
        let (prefix, local) = split_name(name);
        let namespace = resolve(prefix.unwrap_or(""));
        let element = Element {
            name: name.to_owned(),
            prefix: prefix.map(str::to_owned),
            local: local.to_owned(),
            namespace,
            attrs,
        };
        let parent = self.current();
        let id = self.document.push(Kind::Element(element), Some(parent));
        self.position = index;
        if !self_closing {
            self.stack.push((id, scope));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_namespaces_and_entities() {
        let document = Document::parse(
            "<?xml version=\"1.0\"?>\r\n<a:root xmlns:a=\"urn:a\" xmlns=\"urn:d\" x=\"1&amp;2&#x41;\tz\"><child>t&lt;&#65;<!--c--><![CDATA[<x>]]></child></a:root>",
        )
        .unwrap();
        let root = document.document_element().unwrap();
        assert_eq!(document.namespace(root), Some("urn:a"));
        assert_eq!(document.attr(root, "x"), Some("1&2A z"));
        let child = document.child_elements(root)[0];
        assert_eq!(document.namespace(child), Some("urn:d"));
        assert_eq!(document.text_content(child), "t<A<x>");
        assert_eq!(
            document.serialize(Document::ROOT),
            "<?xml version=\"1.0\"?>\n<a:root xmlns:a=\"urn:a\" xmlns=\"urn:d\" x=\"1&amp;2A z\"><child>t&lt;A<!--c--><![CDATA[<x>]]></child></a:root>"
        );
    }

    #[test]
    fn refuses_malformed_documents() {
        for bad in [
            "<a><b></a>",
            "<a x=1/>",
            "<a x=\"1\" x=\"2\"/>",
            "<a>&nope;</a>",
            "<a/><b/>",
            "<a>",
            "text",
        ] {
            assert!(Document::parse(bad).is_err(), "{bad}");
        }
        assert!(Document::parse("<a>x & y</a>").is_ok());
    }

    #[test]
    fn serializes_subtrees_with_their_namespaces() {
        let document = Document::parse("<p:a xmlns:p=\"urn:p\"><p:b q=\"1\"/></p:a>").unwrap();
        let root = document.document_element().unwrap();
        let child = document.child_elements(root)[0];
        assert_eq!(
            document.serialize(child),
            "<p:b q=\"1\" xmlns:p=\"urn:p\"/>"
        );
    }
}
